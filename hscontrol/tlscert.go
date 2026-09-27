package hscontrol

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/libdns/libdns"
	"tailscale.com/tailcfg"
)

const (
	dnsCertRecordRetention = 10 * time.Minute

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
	return &dnsCertificateManager{
		zone:            strings.TrimSuffix(strings.ToLower(cfg.Zone), "."),
		ttl:             cfg.TTL,
		propagationWait: cfg.PropagationWait,
		setter:          setter,
		records:         make(map[string]map[string]time.Time),
	}
}

type dnsCertificateManager struct {
	zone            string
	ttl             time.Duration
	propagationWait time.Duration
	setter          libdns.RecordSetter

	mu      sync.Mutex
	records map[string]map[string]time.Time
}

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

	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	m.purgeExpiredLocked(now)

	values := m.records[name]
	if values == nil {
		values = make(map[string]time.Time)
		m.records[name] = values
	}

	retention := dnsCertRecordRetention
	if m.ttl > retention {
		retention = m.ttl
	}
	expires := now.Add(retention)
	values[value] = expires

	records := make([]libdns.Record, 0, len(values))
	for txt := range values {
		records = append(records, libdns.TXT{
			Name: m.relativeRecordName(name),
			TTL:  m.ttl,
			Text: txt,
		})
	}

	if _, err := m.setter.SetRecords(ctx, m.zone, records); err != nil {
		return fmt.Errorf("setting ACME DNS-01 TXT record: %w", err)
	}

	if m.propagationWait > 0 {
		timer := time.NewTimer(m.propagationWait)
		defer timer.Stop()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}

	return nil
}

func (m *dnsCertificateManager) purgeExpiredLocked(now time.Time) {
	for name, values := range m.records {
		for value, expires := range values {
			if !expires.IsZero() && now.After(expires) {
				delete(values, value)
			}
		}

		if len(values) == 0 {
			delete(m.records, name)
		}
	}
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
