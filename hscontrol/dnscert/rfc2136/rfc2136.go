// Package rfc2136 registers a Headscale DNS certificate provider ("rfc2136")
// that publishes ACME DNS-01 TXT records via RFC 2136 TSIG-signed dynamic DNS
// updates. It targets any authoritative name server that supports RFC 2136
// dynamic updates with an update-policy grant for a TSIG key, such as BIND or
// PowerDNS.
package rfc2136

import (
	"encoding/base64"
	"fmt"
	"net"
	"strings"

	"github.com/juanfont/headscale/hscontrol"
	"github.com/libdns/libdns"
	rfc2136provider "github.com/libdns/rfc2136"
)

// Supported TSIG algorithms. github.com/libdns/rfc2136 (via miekg/dns)
// accepts any TSIG algorithm the server understands, but Headscale only
// advertises the two current, secure choices.
const (
	algorithmHMACSHA256 = "hmac-sha256"
	algorithmHMACSHA512 = "hmac-sha512"
)

func init() {
	if err := hscontrol.RegisterDNSCertificateProvider("rfc2136", newProvider); err != nil {
		panic(err)
	}
}

// newProvider builds a libdns.RecordSetter (also implementing
// libdns.RecordDeleter) from dns.certificates.provider_config. The DNS zone
// itself comes from dns.certificates.zone, not from provider_config: it is
// passed by the caller on every SetRecords/DeleteRecords call.
//
// Expected provider_config keys:
//
//	nameserver:    the RFC 2136 server's address, "host:port"
//	key_name:      the TSIG key name
//	key_algorithm: "hmac-sha256" (default) or "hmac-sha512"
//	key_secret:    the TSIG secret, base64 (supports "_path"/"_env" indirection)
func newProvider(cfg map[string]string) (libdns.RecordSetter, error) {
	nameserver := strings.TrimSpace(cfg["nameserver"])
	if nameserver == "" {
		return nil, fmt.Errorf("rfc2136: %q is required", "nameserver")
	}

	if _, _, err := net.SplitHostPort(nameserver); err != nil {
		return nil, fmt.Errorf("rfc2136: %q must be \"host:port\": %w", "nameserver", err)
	}

	keyName := strings.TrimSpace(cfg["key_name"])
	if keyName == "" {
		return nil, fmt.Errorf("rfc2136: %q is required", "key_name")
	}

	algorithm := strings.ToLower(strings.TrimSpace(cfg["key_algorithm"]))
	if algorithm == "" {
		algorithm = algorithmHMACSHA256
	}

	switch algorithm {
	case algorithmHMACSHA256, algorithmHMACSHA512:
	default:
		return nil, fmt.Errorf(
			"rfc2136: %q must be %q or %q, got %q",
			"key_algorithm", algorithmHMACSHA256, algorithmHMACSHA512, algorithm,
		)
	}

	secret := strings.TrimSpace(cfg["key_secret"])
	if secret == "" {
		return nil, fmt.Errorf("rfc2136: %q is required", "key_secret")
	}

	if _, err := base64.StdEncoding.DecodeString(secret); err != nil {
		return nil, fmt.Errorf("rfc2136: %q must be base64: %w", "key_secret", err)
	}

	return &rfc2136provider.Provider{
		Server:  nameserver,
		KeyName: keyName,
		KeyAlg:  algorithm,
		Key:     secret,
	}, nil
}
