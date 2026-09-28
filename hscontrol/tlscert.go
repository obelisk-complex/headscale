package hscontrol

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/libdns/libdns"
	"github.com/rs/zerolog/log"
	"tailscale.com/tailcfg"
)

const (
	dnsCertRecordRetention = 10 * time.Minute

	dnsCertCleanupTimeout = 30 * time.Second

	// A failed cleanup write is retried after dnsCertCleanupRetryBase,
	// doubling per consecutive failure up to dnsCertCleanupRetryMax, until
	// it succeeds, so a provider outage does not orphan stale records.
	dnsCertCleanupRetryBase = 30 * time.Second
	dnsCertCleanupRetryMax  = 10 * time.Minute

	dnsPropagationPollInterval = 2 * time.Second
	dnsPropagationQueryTimeout = 5 * time.Second

	// acmeDNS01ValueLength is the length of an unpadded base64url SHA-256
	// digest, the only value an ACME DNS-01 TXT record carries.
	acmeDNS01ValueLength = 43

	// dnsCertMaxValuesPerName caps the TXT values Headscale keeps published
	// for one challenge name. tailscaled validates at most two authorisations
	// under one name at once (<fqdn> and *.<fqdn>); when a third value arrives
	// the one expiring soonest is dropped, so a retrying client always gets
	// its newest value published and a looping client cannot grow the RRset.
	dnsCertMaxValuesPerName = 2

	// untrustedLogLimit caps how many bytes of a client-supplied string are
	// formatted into an error. Those errors are logged, and a node can send
	// a string as large as the request body limit.
	untrustedLogLimit = 256

	// setDNSRateBurst and setDNSRateInterval bound /machine/set-dns per node:
	// a burst of setDNSRateBurst requests, refilled at one per interval.
	// A certificate order needs one request per name, two with a wildcard.
	setDNSRateBurst    = 6
	setDNSRateInterval = 10 * time.Second
)

var (
	errDNSCertProviderExists = errors.New("DNS certificate provider already registered")
	errDNSCertProviderUnset  = errors.New("DNS certificate provider is not registered")
	errDNSCertRecordType     = errors.New("only TXT records are supported")
	errDNSCertRecordName     = errors.New("DNS record name is not allowed")
	errDNSCertRecordValue    = errors.New("invalid TXT record value")
	errDNSCertPropagation    = errors.New("DNS record not visible on authoritative name servers")
	errDNSCertRateLimited    = errors.New("too many DNS record updates")
)

// DNSCertificateProviderFactory constructs a libdns RecordSetter from the
// provider_config map in config.yaml.
type DNSCertificateProviderFactory func(map[string]string) (libdns.RecordSetter, error)

var (
	dnsCertProviderMu        sync.RWMutex
	dnsCertProviderFactories = map[string]DNSCertificateProviderFactory{}
)

// RegisterDNSCertificateProvider registers a provider-neutral libdns factory.
// Concrete provider packages should call this from init and return a
// libdns.RecordSetter built from providerConfig.
func RegisterDNSCertificateProvider(
	name string,
	factory DNSCertificateProviderFactory,
) error {
	name = strings.TrimSpace(strings.ToLower(name))
	if name == "" {
		return fmt.Errorf("provider name is empty")
	}
	if factory == nil {
		return fmt.Errorf("provider factory is nil")
	}

	dnsCertProviderMu.Lock()
	defer dnsCertProviderMu.Unlock()

	if _, ok := dnsCertProviderFactories[name]; ok {
		return fmt.Errorf("%w: %s", errDNSCertProviderExists, name)
	}

	dnsCertProviderFactories[name] = factory

	return nil
}

func newDNSCertificateManager(
	cfg types.DNSCertificatesConfig,
) (*dnsCertificateManager, error) {
	providerName := strings.TrimSpace(strings.ToLower(cfg.Provider))

	dnsCertProviderMu.RLock()
	factory := dnsCertProviderFactories[providerName]
	dnsCertProviderMu.RUnlock()

	if factory == nil {
		return nil, fmt.Errorf("%w: %s", errDNSCertProviderUnset, providerName)
	}

	setter, err := factory(cfg.ProviderConfig)
	if err != nil {
		return nil, fmt.Errorf("creating DNS certificate provider %q: %w", providerName, err)
	}
	if setter == nil {
		return nil, fmt.Errorf("creating DNS certificate provider %q: nil provider", providerName)
	}

	return newDNSCertificateManagerForSetter(cfg, setter), nil
}

func newDNSCertificateManagerForSetter(
	cfg types.DNSCertificatesConfig,
	setter libdns.RecordSetter,
) *dnsCertificateManager {
	m := &dnsCertificateManager{
		zone:            strings.TrimSuffix(strings.ToLower(cfg.Zone), "."),
		ttl:             cfg.TTL,
		propagationWait: cfg.PropagationWait,
		retention:       max(dnsCertRecordRetention, cfg.TTL),
		setter:          setter,
		records:         make(map[string]map[string]time.Time),
		cleanupTimers:   make(map[string]*time.Timer),
		cleanupFailures: make(map[string]int),
		cleanupRetry:    dnsCertCleanupRetryBase,
		cleanupRetryMax: dnsCertCleanupRetryMax,
		nameLocks:       make(map[string]*dnsNameLock),
		limiter:         newNodeRateLimiter(setDNSRateBurst, setDNSRateInterval),
	}

	// Deleting is optional for providers: without it the RRset is still
	// trimmed on the next write to the same name, but the last values for a
	// name stay published until they are overwritten.
	if deleter, ok := setter.(libdns.RecordDeleter); ok {
		m.deleter = deleter
	}

	if cfg.PropagationCheck {
		m.propagation = &dnsPropagationChecker{
			resolver:     netPropagationResolver{},
			timeout:      cfg.PropagationTimeout,
			pollInterval: dnsPropagationPollInterval,
		}
	}

	return m
}

type dnsCertificateManager struct {
	zone            string
	ttl             time.Duration
	propagationWait time.Duration
	setter          libdns.RecordSetter
	deleter         libdns.RecordDeleter // nil when the provider cannot delete

	// retention is how long a challenge value stays published. It outlives
	// the ACME validation that needs it; the CA does not look again.
	retention time.Duration

	// propagation, when set, holds SetDNS responses until the record is
	// served by every authoritative name server of its zone.
	propagation *dnsPropagationChecker

	// mu guards the maps below. It is never held across a provider call.
	mu sync.Mutex
	// records is the TXT RRset Headscale owns per challenge name (canonical,
	// fully qualified), as value -> expiry. An entry is only changed by the
	// holder of that name's lock.
	// A value is only removed from records once a provider write without
	// it has succeeded, so a failed write never loses track of a value
	// that is still published.
	records       map[string]map[string]time.Time
	cleanupTimers map[string]*time.Timer
	// cleanupFailures counts consecutive failed cleanup writes per name.
	cleanupFailures map[string]int
	cleanupRetry    time.Duration
	cleanupRetryMax time.Duration
	// nameLocks serialises the read-modify-write of one name's RRset,
	// including the provider write, so each write carries the complete
	// RRset and no two writes for a name race to replace it. Writes for
	// different names proceed in parallel.
	nameLocks map[string]*dnsNameLock

	limiter *nodeRateLimiter
}

type dnsNameLock struct {
	mu   sync.Mutex
	refs int // goroutines holding or waiting for mu; guarded by manager mu
}

// lockName takes the lock for name and returns its release function.
func (m *dnsCertificateManager) lockName(name string) func() {
	m.mu.Lock()

	l := m.nameLocks[name]
	if l == nil {
		l = &dnsNameLock{}
		m.nameLocks[name] = l
	}

	l.refs++
	m.mu.Unlock()

	l.mu.Lock()

	return func() {
		l.mu.Unlock()

		m.mu.Lock()
		defer m.mu.Unlock()

		l.refs--
		if l.refs == 0 {
			delete(m.nameLocks, name)
		}
	}
}

// allowRequest reports whether node may make another SetDNS request now.
func (m *dnsCertificateManager) allowRequest(node types.NodeID) bool {
	return m.limiter.allow(node, time.Now())
}

// setDNS publishes the node's ACME DNS-01 TXT value and returns once the
// record can be expected to be visible to the ACME server: tailscaled asks
// the CA to validate as soon as this call returns.
func (m *dnsCertificateManager) setDNS(
	ctx context.Context,
	node types.NodeView,
	baseDomain string,
	extraRecords []tailcfg.DNSRecord,
	req tailcfg.SetDNSRequest,
) error {
	if m == nil {
		return errDNSCertProviderUnset
	}

	if err := validateSetDNSRequest(node, baseDomain, extraRecords, req); err != nil {
		return err
	}

	name, _ := parseDNSName(req.Name)
	value := req.Value

	if !isInZone(name, m.zone) {
		return fmt.Errorf("challenge name %q is outside the configured zone %q", name, m.zone)
	}

	if err := m.publish(ctx, name, value); err != nil {
		return err
	}

	written := time.Now()

	if m.propagation != nil {
		if err := m.propagation.wait(ctx, name, m.zone, value); err != nil {
			return err
		}
	}

	return sleepCtx(ctx, m.propagationWait-time.Since(written))
}

// publish adds value to the TXT RRset for name and writes the whole RRset,
// so concurrent authorisations for the same name (tailscaled requests a
// certificate for both <fqdn> and *.<fqdn> under one challenge name) all
// stay valid. At most [dnsCertMaxValuesPerName] values are kept; the one
// expiring soonest makes room for a new one. Only name's lock is held
// across the provider write, and nothing is held while waiting for
// propagation, so a slow provider or zone does not stall other nodes.
func (m *dnsCertificateManager) publish(ctx context.Context, name, value string) error {
	unlock := m.lockName(name)
	defer unlock()

	m.mu.Lock()

	// Snapshot the RRset before dropping expired values, so a failed write
	// restores them too: they are still published until a write succeeds.
	before := maps.Clone(m.records[name])

	now := time.Now()
	m.forgetLocked(name, m.expiredLocked(name, now))

	values := m.records[name]
	if values == nil {
		values = make(map[string]time.Time)
		m.records[name] = values
	}

	if _, existed := values[value]; !existed && len(values) >= dnsCertMaxValuesPerName {
		delete(values, oldestValue(values))
	}

	values[value] = now.Add(m.retention)
	rrset := m.rrsetLocked(name)

	m.mu.Unlock()

	_, err := m.setter.SetRecords(ctx, m.zone, rrset)

	m.mu.Lock()
	defer m.mu.Unlock()

	if err != nil {
		if len(before) == 0 {
			delete(m.records, name)
		} else {
			m.records[name] = before
		}

		m.scheduleCleanupLocked(name)

		return fmt.Errorf("setting ACME DNS-01 TXT record: %w", err)
	}

	// This write carried no expired values, so it also did any cleanup a
	// failed cleanup write left pending.
	delete(m.cleanupFailures, name)
	m.scheduleCleanupLocked(name)

	return nil
}

// oldestValue returns the value in values that expires first, breaking
// ties by value so the choice is deterministic.
func oldestValue(values map[string]time.Time) string {
	var (
		oldest  string
		expires time.Time
	)

	for v, exp := range values {
		if oldest == "" || exp.Before(expires) || (exp.Equal(expires) && v < oldest) {
			oldest, expires = v, exp
		}
	}

	return oldest
}

// rrsetLocked returns the libdns records for every value held for name,
// leaving out those in exclude.
func (m *dnsCertificateManager) rrsetLocked(name string, exclude ...string) []libdns.Record {
	values := make([]string, 0, len(m.records[name]))

	for _, txt := range slices.Sorted(maps.Keys(m.records[name])) {
		if !slices.Contains(exclude, txt) {
			values = append(values, txt)
		}
	}

	return m.txtRecords(name, values)
}

func (m *dnsCertificateManager) txtRecords(name string, values []string) []libdns.Record {
	relative := m.relativeRecordName(name)

	records := make([]libdns.Record, 0, len(values))
	for _, txt := range values {
		records = append(records, libdns.TXT{Name: relative, TTL: m.ttl, Text: txt})
	}

	return records
}

// expiredLocked returns the values for name that have expired by now,
// without forgetting them.
func (m *dnsCertificateManager) expiredLocked(name string, now time.Time) []string {
	var expired []string

	for value, expires := range m.records[name] {
		if !now.Before(expires) {
			expired = append(expired, value)
		}
	}

	slices.Sort(expired)

	return expired
}

// forgetLocked removes values from the RRset held for name.
func (m *dnsCertificateManager) forgetLocked(name string, values []string) {
	for _, value := range values {
		delete(m.records[name], value)
	}

	if len(m.records[name]) == 0 {
		delete(m.records, name)
	}
}

// scheduleCleanupLocked arms the cleanup timer for name to fire when its
// earliest value expires. An armed timer already fires no later than that.
func (m *dnsCertificateManager) scheduleCleanupLocked(name string) {
	if _, armed := m.cleanupTimers[name]; armed {
		return
	}

	values := m.records[name]
	if len(values) == 0 {
		return
	}

	earliest := slices.MinFunc(slices.Collect(maps.Values(values)), time.Time.Compare)

	m.cleanupTimers[name] = time.AfterFunc(time.Until(earliest), func() {
		m.cleanup(name)
	})
}

// cleanup removes expired challenge values for name from DNS. Values that
// are still live are rewritten as the RRset; when none remain the records
// are deleted if the provider supports it. Expired values are forgotten
// only once that write succeeds; a failed write is retried with backoff.
func (m *dnsCertificateManager) cleanup(name string) {
	unlock := m.lockName(name)
	defer unlock()

	m.mu.Lock()

	if t := m.cleanupTimers[name]; t != nil {
		t.Stop() // no-op when this call is the timer firing
		delete(m.cleanupTimers, name)
	}

	expired := m.expiredLocked(name, time.Now())
	if len(expired) == 0 {
		m.scheduleCleanupLocked(name)
		m.mu.Unlock()

		return
	}

	live := len(m.records[name]) > len(expired)
	rrset := m.rrsetLocked(name, expired...)

	m.mu.Unlock()

	err := m.removeExpired(name, live, rrset, expired)

	m.mu.Lock()
	defer m.mu.Unlock()

	if err != nil {
		m.cleanupFailures[name]++
		delay := m.cleanupBackoffLocked(name)

		log.Warn().Err(err).Str("dns.name", name).Dur("retry_in", delay).
			Msg("failed to remove expired ACME DNS-01 TXT values, will retry")

		m.cleanupTimers[name] = time.AfterFunc(delay, func() {
			m.cleanup(name)
		})

		return
	}

	delete(m.cleanupFailures, name)
	m.forgetLocked(name, expired)
	m.scheduleCleanupLocked(name)
}

// removeExpired makes the provider stop serving expired: by rewriting the
// RRset as rrset while other values are live, otherwise by deleting them.
func (m *dnsCertificateManager) removeExpired(
	name string,
	live bool,
	rrset []libdns.Record,
	expired []string,
) error {
	ctx, cancel := context.WithTimeout(context.Background(), dnsCertCleanupTimeout)
	defer cancel()

	if live {
		_, err := m.setter.SetRecords(ctx, m.zone, rrset)

		return err
	}

	if m.deleter == nil {
		log.Debug().Str("dns.name", name).
			Msg("DNS certificate provider cannot delete records; expired ACME DNS-01 TXT record left in place")

		return nil
	}

	_, err := m.deleter.DeleteRecords(ctx, m.zone, m.txtRecords(name, expired))

	return err
}

// cleanupBackoffLocked returns the delay before retrying a failed cleanup
// of name: cleanupRetry, doubled per further consecutive failure, capped at
// cleanupRetryMax.
func (m *dnsCertificateManager) cleanupBackoffLocked(name string) time.Duration {
	delay := m.cleanupRetry
	for i := 1; i < m.cleanupFailures[name] && delay < m.cleanupRetryMax; i++ {
		delay *= 2
	}

	return min(delay, m.cleanupRetryMax)
}

// nodeRateLimiter is a per-node token bucket.
type nodeRateLimiter struct {
	burst    float64
	interval time.Duration

	mu        sync.Mutex
	buckets   map[types.NodeID]*tokenBucket
	lastSweep time.Time
}

type tokenBucket struct {
	tokens float64
	last   time.Time
}

func newNodeRateLimiter(burst int, interval time.Duration) *nodeRateLimiter {
	return &nodeRateLimiter{
		burst:    float64(burst),
		interval: interval,
		buckets:  make(map[types.NodeID]*tokenBucket),
	}
}

func (l *nodeRateLimiter) refill(b *tokenBucket, now time.Time) {
	b.tokens = min(l.burst, b.tokens+float64(now.Sub(b.last))/float64(l.interval))
	b.last = now
}

// allow takes a token from node's bucket, reporting false when it is empty.
func (l *nodeRateLimiter) allow(node types.NodeID, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	// A full bucket is the same as no bucket, so forget those now and then
	// to keep the map bounded by recently active nodes.
	if now.Sub(l.lastSweep) > time.Duration(l.burst)*l.interval {
		for id, b := range l.buckets {
			if l.refill(b, now); b.tokens >= l.burst {
				delete(l.buckets, id)
			}
		}

		l.lastSweep = now
	}

	b := l.buckets[node]
	if b == nil {
		b = &tokenBucket{tokens: l.burst, last: now}
		l.buckets[node] = b
	}

	l.refill(b, now)

	if b.tokens < 1 {
		return false
	}

	b.tokens--

	return true
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}

	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// dnsPropagationResolver is the view of DNS used to confirm that a TXT
// record is published. It exists so tests can run without a network.
type dnsPropagationResolver interface {
	// LookupNS returns the name server host names delegated for name.
	LookupNS(ctx context.Context, name string) ([]string, error)
	// LookupHost returns the IP addresses of host.
	LookupHost(ctx context.Context, host string) ([]string, error)
	// LookupTXTAt queries the name server at addr (host:port) directly,
	// bypassing any caching resolver.
	LookupTXTAt(ctx context.Context, addr, name string) ([]string, error)
}

type netPropagationResolver struct{}

func (netPropagationResolver) LookupNS(ctx context.Context, name string) ([]string, error) {
	nss, err := net.DefaultResolver.LookupNS(ctx, name)
	if err != nil {
		return nil, err
	}

	hosts := make([]string, 0, len(nss))
	for _, ns := range nss {
		hosts = append(hosts, ns.Host)
	}

	return hosts, nil
}

func (netPropagationResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	return net.DefaultResolver.LookupHost(ctx, host)
}

func (netPropagationResolver) LookupTXTAt(
	ctx context.Context,
	addr, name string,
) ([]string, error) {
	// The pure Go resolver sends every query through Dial, so pinning the
	// dial target makes it talk to exactly this server. It keeps no cache.
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer

			return d.DialContext(ctx, network, addr)
		},
	}

	return r.LookupTXT(ctx, name)
}

// dnsPropagationChecker polls a zone's authoritative name servers until
// each serves an expected TXT value.
type dnsPropagationChecker struct {
	resolver     dnsPropagationResolver
	timeout      time.Duration
	pollInterval time.Duration
}

// wait blocks until every authoritative name server for name (as found by
// walking from name up to zone) serves value, the timeout passes, or ctx
// ends. A name server counts as serving the value when any one of its
// addresses answers with it; addresses that cannot be reached from here
// are not waited on individually.
func (c *dnsPropagationChecker) wait(ctx context.Context, name, zone, value string) error {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	var (
		servers   map[string][]string
		confirmed = make(map[string]bool)
		lastErr   error
	)

	for {
		if servers == nil {
			servers, lastErr = c.authoritativeServers(ctx, name, zone)
		}

		for host, addrs := range servers {
			if confirmed[host] {
				continue
			}

			for _, addr := range addrs {
				qctx, qcancel := context.WithTimeout(ctx, dnsPropagationQueryTimeout)
				txts, err := c.resolver.LookupTXTAt(qctx, net.JoinHostPort(addr, "53"), name)
				qcancel()

				if slices.Contains(txts, value) {
					confirmed[host] = true

					break
				}

				lastErr = fmt.Errorf("%s (%s): %w", host, addr, err)
				if err == nil {
					lastErr = fmt.Errorf("%s (%s): value not served yet", host, addr)
				}
			}
		}

		if servers != nil && len(confirmed) == len(servers) {
			return nil
		}

		select {
		case <-ctx.Done():
			pending := make([]string, 0, len(servers))
			for host := range servers {
				if !confirmed[host] {
					pending = append(pending, host)
				}
			}
			slices.Sort(pending)

			return fmt.Errorf(
				"%w: %s not served by %v within %s: %w",
				errDNSCertPropagation, name, pending, c.timeout, errors.Join(lastErr, ctx.Err()),
			)
		case <-time.After(c.pollInterval):
		}
	}
}

// authoritativeServers finds the zone cut for name by walking up from name
// to zone until an NS RRset is found, then resolves each name server's
// addresses. Name servers without addresses are left out, since the ACME
// server cannot query them either.
func (c *dnsPropagationChecker) authoritativeServers(
	ctx context.Context,
	name, zone string,
) (map[string][]string, error) {
	zone = canonicalDNSName(zone)

	var hosts []string

	for candidate := name; ; {
		found, err := c.resolver.LookupNS(ctx, candidate)
		if err == nil && len(found) > 0 {
			hosts = found

			break
		}

		if candidate == zone || ctx.Err() != nil {
			return nil, fmt.Errorf("no NS records found for %s up to zone %s: %w", name, zone, err)
		}

		_, candidate, _ = strings.Cut(candidate, ".")
		if candidate == "" {
			return nil, fmt.Errorf("%s is not inside zone %s", name, zone)
		}
	}

	servers := make(map[string][]string, len(hosts))

	var errs []error

	for _, host := range hosts {
		addrs, err := c.resolver.LookupHost(ctx, host)
		if err != nil || len(addrs) == 0 {
			errs = append(errs, fmt.Errorf("resolving name server %s: %w", host, err))

			continue
		}

		servers[canonicalDNSName(host)] = addrs
	}

	if len(servers) == 0 {
		return nil, errors.Join(errs...)
	}

	return servers, nil
}

func (m *dnsCertificateManager) relativeRecordName(name string) string {
	zone := canonicalDNSName(m.zone)
	if name == zone {
		return "@"
	}

	return strings.TrimSuffix(strings.TrimSuffix(name, "."), "."+strings.TrimSuffix(zone, "."))
}

// isSetDNSRequestError reports whether err was caused by the client's
// request rather than by the provider or server configuration.
func isSetDNSRequestError(err error) bool {
	return errors.Is(err, errDNSCertRecordType) ||
		errors.Is(err, errDNSCertRecordName) ||
		errors.Is(err, errDNSCertRecordValue)
}

// validateSetDNSRequest restricts a SetDNS request to the single record a
// node may legitimately need: the ACME DNS-01 TXT record for its own FQDN,
// and only while that FQDN does not collide with a dns.extra_records name.
func validateSetDNSRequest(
	node types.NodeView,
	baseDomain string,
	extraRecords []tailcfg.DNSRecord,
	req tailcfg.SetDNSRequest,
) error {
	if req.Type != "TXT" {
		return fmt.Errorf("%w: got %q", errDNSCertRecordType, truncateUntrusted(req.Type))
	}

	if !isACMEDNS01Value(req.Value) {
		return fmt.Errorf(
			"%w: want a %d character base64url ACME key authorisation digest",
			errDNSCertRecordValue,
			acmeDNS01ValueLength,
		)
	}

	want, err := acmeChallengeName(node, baseDomain)
	if err != nil {
		return err
	}

	got, ok := parseDNSName(req.Name)
	if !ok || got != want {
		return fmt.Errorf("%w: got %q, want %q", errDNSCertRecordName, truncateUntrusted(req.Name), want)
	}

	if types.GivenNameShadowsExtraRecord(node.GivenName(), baseDomain, extraRecords) {
		return fmt.Errorf(
			"%w: node name %q collides with a DNS extra record",
			errDNSCertRecordName, node.GivenName(),
		)
	}

	return nil
}

// truncateUntrusted bounds a client-supplied string before it is formatted
// into an error or log line.
func truncateUntrusted(s string) string {
	if len(s) <= untrustedLogLimit {
		return s
	}

	return s[:untrustedLogLimit] + "...(truncated)"
}

// acmeChallengeName returns the canonical DNS-01 challenge name for node.
func acmeChallengeName(node types.NodeView, baseDomain string) (string, error) {
	fqdn, err := node.GetFQDN(baseDomain)
	if err != nil {
		return "", fmt.Errorf("determining node FQDN: %w", err)
	}

	name, ok := parseDNSName("_acme-challenge." + fqdn)
	if !ok {
		return "", fmt.Errorf("node FQDN %q is not a valid DNS name", fqdn)
	}

	return name, nil
}

// isACMEDNS01Value reports whether value has the shape RFC 8555 section 8.4
// mandates for a DNS-01 TXT record: unpadded base64url of a SHA-256 digest.
// Holding clients to that shape keeps quotes, whitespace and other
// provider-specific syntax out of the records written on their behalf.
func isACMEDNS01Value(value string) bool {
	if len(value) != acmeDNS01ValueLength {
		return false
	}

	for _, c := range value {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '-', c == '_':
		default:
			return false
		}
	}

	return true
}

// parseDNSName validates name as a hostname-style DNS name (letters, digits,
// '-' and '_', non-empty labels of at most 63 octets, one optional trailing
// dot) and returns it lower-cased and fully qualified. Anything else,
// including wildcards, empty labels and surrounding whitespace, is refused.
func parseDNSName(name string) (string, bool) {
	name = strings.TrimSuffix(name, ".")
	if name == "" || len(name) > 253 {
		return "", false
	}

	for label := range strings.SplitSeq(name, ".") {
		if label == "" || len(label) > 63 {
			return "", false
		}

		for _, c := range label {
			switch {
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
				c == '-', c == '_':
			default:
				return "", false
			}
		}
	}

	return strings.ToLower(name) + ".", true
}

// isInZone reports whether the canonical name is zone or lies below it.
func isInZone(name, zone string) bool {
	zone = canonicalDNSName(zone)

	return name == zone || strings.HasSuffix(name, "."+zone)
}

func canonicalDNSName(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), ".") + ".")
}
