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

	dnsPropagationPollInterval = 2 * time.Second
	dnsPropagationQueryTimeout = 5 * time.Second

	// acmeDNS01ValueLength is the length of an unpadded base64url SHA-256
	// digest, the only value an ACME DNS-01 TXT record carries.
	acmeDNS01ValueLength = 43
)

var (
	errDNSCertProviderExists = errors.New("DNS certificate provider already registered")
	errDNSCertProviderUnset  = errors.New("DNS certificate provider is not registered")
	errDNSCertRecordType     = errors.New("only TXT records are supported")
	errDNSCertRecordName     = errors.New("DNS record name is not allowed")
	errDNSCertRecordValue    = errors.New("invalid TXT record value")
	errDNSCertPropagation    = errors.New("DNS record not visible on authoritative name servers")
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

	// mu serialises every provider write, so each write carries the
	// complete RRset for its name and no two writes race to replace it.
	mu sync.Mutex
	// records is the TXT RRset Headscale owns per challenge name (canonical,
	// fully qualified), as value -> expiry.
	records       map[string]map[string]time.Time
	cleanupTimers map[string]*time.Timer
}

// setDNS publishes the node's ACME DNS-01 TXT value and returns once the
// record can be expected to be visible to the ACME server: tailscaled asks
// the CA to validate as soon as this call returns.
func (m *dnsCertificateManager) setDNS(
	ctx context.Context,
	node types.NodeView,
	baseDomain string,
	req tailcfg.SetDNSRequest,
) error {
	if m == nil {
		return errDNSCertProviderUnset
	}

	if err := validateSetDNSRequest(node, baseDomain, req); err != nil {
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
// stay valid. The lock is held only for the provider write, never while
// waiting for propagation, so a slow zone does not stall other nodes.
func (m *dnsCertificateManager) publish(ctx context.Context, name, value string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	m.dropExpiredLocked(name, now)

	values := m.records[name]
	if values == nil {
		values = make(map[string]time.Time)
		m.records[name] = values
	}

	previous, existed := values[value]
	values[value] = now.Add(m.retention)

	if _, err := m.setter.SetRecords(ctx, m.zone, m.rrsetLocked(name)); err != nil {
		if existed {
			values[value] = previous
		} else {
			delete(values, value)
		}

		if len(values) == 0 {
			delete(m.records, name)
		}

		return fmt.Errorf("setting ACME DNS-01 TXT record: %w", err)
	}

	m.scheduleCleanupLocked(name)

	return nil
}

// rrsetLocked returns the libdns records for every value held for name.
func (m *dnsCertificateManager) rrsetLocked(name string) []libdns.Record {
	relative := m.relativeRecordName(name)
	values := m.records[name]

	records := make([]libdns.Record, 0, len(values))
	for _, txt := range slices.Sorted(maps.Keys(values)) {
		records = append(records, libdns.TXT{Name: relative, TTL: m.ttl, Text: txt})
	}

	return records
}

// dropExpiredLocked forgets expired values for name and returns them.
func (m *dnsCertificateManager) dropExpiredLocked(name string, now time.Time) []string {
	var expired []string

	for value, expires := range m.records[name] {
		if !now.Before(expires) {
			expired = append(expired, value)
			delete(m.records[name], value)
		}
	}

	if len(m.records[name]) == 0 {
		delete(m.records, name)
	}

	return expired
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
// are deleted if the provider supports it.
func (m *dnsCertificateManager) cleanup(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.cleanupTimers, name)

	expired := m.dropExpiredLocked(name, time.Now())
	if len(expired) == 0 {
		m.scheduleCleanupLocked(name)

		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), dnsCertCleanupTimeout)
	defer cancel()

	if _, live := m.records[name]; live {
		_, err := m.setter.SetRecords(ctx, m.zone, m.rrsetLocked(name))
		if err != nil {
			log.Warn().Err(err).Str("dns.name", name).
				Msg("failed to remove expired ACME DNS-01 values from TXT RRset")
		}

		m.scheduleCleanupLocked(name)

		return
	}

	if m.deleter == nil {
		log.Debug().Str("dns.name", name).
			Msg("DNS certificate provider cannot delete records; expired ACME DNS-01 TXT record left in place")

		return
	}

	relative := m.relativeRecordName(name)
	records := make([]libdns.Record, 0, len(expired))

	for _, txt := range expired {
		records = append(records, libdns.TXT{Name: relative, TTL: m.ttl, Text: txt})
	}

	if _, err := m.deleter.DeleteRecords(ctx, m.zone, records); err != nil {
		log.Warn().Err(err).Str("dns.name", name).
			Msg("failed to delete expired ACME DNS-01 TXT record")
	}
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
// node may legitimately need: the ACME DNS-01 TXT record for its own FQDN.
func validateSetDNSRequest(
	node types.NodeView,
	baseDomain string,
	req tailcfg.SetDNSRequest,
) error {
	if req.Type != "TXT" {
		return fmt.Errorf("%w: got %q", errDNSCertRecordType, req.Type)
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
		return fmt.Errorf("%w: got %q, want %q", errDNSCertRecordName, req.Name, want)
	}

	return nil
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
