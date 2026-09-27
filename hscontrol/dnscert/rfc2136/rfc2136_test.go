package rfc2136

import (
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libdns/libdns"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

const (
	testZone      = "example.com."
	testKeyName   = "headscale-key"
	testKeySecret = "pRZgBrBvI4NAHZYhxmhs/Q==" // 128-bit HMAC secret, base64
)

// fakeUpdateServer is a minimal RFC 2136 dynamic update server used to test
// the rfc2136 provider without any real DNS infrastructure. It runs over TCP
// because github.com/libdns/rfc2136 always sends updates over TCP.
type fakeUpdateServer struct {
	mu      sync.Mutex
	zone    string              // fqdn; empty accepts any zone
	records map[string][]string // "name|TYPE" -> rdata values currently stored

	srv  *dns.Server
	addr string
}

// startFakeUpdateServer starts a server that authenticates requests against
// keyName/keySecret and, once authenticated, only accepts updates for zone
// (empty zone accepts any).
func startFakeUpdateServer(t *testing.T, zone, keyName, keySecret string) *fakeUpdateServer {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	f := &fakeUpdateServer{
		records: make(map[string][]string),
		addr:    ln.Addr().String(),
	}
	if zone != "" {
		f.zone = dns.Fqdn(zone)
	}

	mux := dns.NewServeMux()
	mux.HandleFunc(".", f.handle)

	f.srv = &dns.Server{
		Listener:   ln,
		Handler:    mux,
		TsigSecret: map[string]string{dns.Fqdn(keyName): keySecret},
		// The default MsgAcceptFunc refuses every dynamic update with
		// NOTIMP before the handler ever runs; RFC 2136 updates are exactly
		// what this test double exists to accept.
		MsgAcceptFunc: acceptUpdates,
	}

	ready := make(chan struct{})
	f.srv.NotifyStartedFunc = func() { close(ready) }
	go f.srv.ActivateAndServe() //nolint:errcheck
	<-ready

	t.Cleanup(func() { _ = f.srv.Shutdown() })

	return f
}

func acceptUpdates(dh dns.Header) dns.MsgAcceptAction {
	opcode := int(dh.Bits>>11) & 0xF
	if opcode == dns.OpcodeUpdate {
		return dns.MsgAccept
	}

	return dns.DefaultMsgAcceptFunc(dh)
}

func (f *fakeUpdateServer) handle(w dns.ResponseWriter, r *dns.Msg) {
	reply := new(dns.Msg)
	reply.SetReply(r)

	if r.Opcode != dns.OpcodeUpdate || len(r.Question) != 1 {
		reply.Rcode = dns.RcodeFormatError
		_ = w.WriteMsg(reply)

		return
	}

	// RFC 2845: a signed request that fails verification (unknown key or bad
	// MAC) must be rejected with NOTAUTH.
	if r.IsTsig() == nil || w.TsigStatus() != nil {
		reply.Rcode = dns.RcodeNotAuth
		_ = w.WriteMsg(reply)

		return
	}

	zone := r.Question[0].Name

	f.mu.Lock()
	defer f.mu.Unlock()

	if f.zone != "" && !strings.EqualFold(zone, f.zone) {
		reply.Rcode = dns.RcodeNotZone
		_ = w.WriteMsg(reply)

		return
	}

	for _, rr := range r.Ns {
		hdr := rr.Header()
		key := strings.ToLower(hdr.Name) + "|" + dns.TypeToString[hdr.Rrtype]

		switch hdr.Class {
		case dns.ClassANY:
			// RemoveRRset: delete every value held for name+type.
			delete(f.records, key)
		case dns.ClassNONE:
			// Remove: delete one exact value.
			value := txtValue(rr)
			f.records[key] = deleteValue(f.records[key], value)
		default:
			// Insert.
			f.records[key] = append(f.records[key], txtValue(rr))
		}
	}

	reply.Rcode = dns.RcodeSuccess
	_ = w.WriteMsg(reply)
}

func (f *fakeUpdateServer) rrset(name string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()

	key := strings.ToLower(dns.Fqdn(name)) + "|TXT"

	return append([]string(nil), f.records[key]...)
}

func txtValue(rr dns.RR) string {
	txt, ok := rr.(*dns.TXT)
	if !ok || len(txt.Txt) == 0 {
		return ""
	}

	return strings.Join(txt.Txt, "")
}

func deleteValue(values []string, value string) []string {
	out := values[:0]

	for _, v := range values {
		if v != value {
			out = append(out, v)
		}
	}

	return out
}

func validConfig(addr string) map[string]string {
	return map[string]string{
		"nameserver":    addr,
		"key_name":      testKeyName,
		"key_algorithm": algorithmHMACSHA256,
		"key_secret":    testKeySecret,
	}
}

func TestNewProviderValidatesConfig(t *testing.T) {
	t.Parallel()

	base := validConfig("127.0.0.1:53")

	tests := []struct {
		name    string
		mutate  func(map[string]string)
		wantErr string
	}{
		{name: "valid", mutate: func(map[string]string) {}},
		{
			name:    "missing-nameserver",
			mutate:  func(c map[string]string) { delete(c, "nameserver") },
			wantErr: "nameserver",
		},
		{
			name:    "nameserver-without-port",
			mutate:  func(c map[string]string) { c["nameserver"] = "127.0.0.1" },
			wantErr: "nameserver",
		},
		{
			name:    "missing-key-name",
			mutate:  func(c map[string]string) { delete(c, "key_name") },
			wantErr: "key_name",
		},
		{
			name:    "unsupported-algorithm",
			mutate:  func(c map[string]string) { c["key_algorithm"] = "hmac-md5" },
			wantErr: "key_algorithm",
		},
		{
			name:    "missing-secret",
			mutate:  func(c map[string]string) { delete(c, "key_secret") },
			wantErr: "key_secret",
		},
		{
			name:    "secret-not-base64",
			mutate:  func(c map[string]string) { c["key_secret"] = "not base64!!" },
			wantErr: "key_secret",
		},
		{
			name:   "algorithm-defaults-to-sha256",
			mutate: func(c map[string]string) { delete(c, "key_algorithm") },
		},
		{
			name:   "sha512-accepted",
			mutate: func(c map[string]string) { c["key_algorithm"] = algorithmHMACSHA512 },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := make(map[string]string, len(base))
			for k, v := range base {
				cfg[k] = v
			}
			tt.mutate(cfg)

			setter, err := newProvider(cfg)
			if tt.wantErr == "" {
				require.NoError(t, err)
				require.NotNil(t, setter)

				return
			}

			require.Error(t, err)
			require.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestProviderSetRecordsWritesTXT(t *testing.T) {
	t.Parallel()

	server := startFakeUpdateServer(t, testZone, testKeyName, testKeySecret)

	setter, err := newProvider(validConfig(server.addr))
	require.NoError(t, err)

	_, err = setter.SetRecords(t.Context(), testZone, []libdns.Record{
		libdns.TXT{Name: "_acme-challenge.node1", TTL: time.Minute, Text: "challenge-value"},
	})
	require.NoError(t, err)

	require.Equal(t, []string{"challenge-value"}, server.rrset("_acme-challenge.node1.example.com."))
}

func TestProviderDeleteRecordsRemovesExactValue(t *testing.T) {
	t.Parallel()

	server := startFakeUpdateServer(t, testZone, testKeyName, testKeySecret)

	setter, err := newProvider(validConfig(server.addr))
	require.NoError(t, err)

	_, err = setter.SetRecords(t.Context(), testZone, []libdns.Record{
		libdns.TXT{Name: "_acme-challenge.node1", TTL: time.Minute, Text: "value-1"},
		libdns.TXT{Name: "_acme-challenge.node1", TTL: time.Minute, Text: "value-2"},
	})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"value-1", "value-2"}, server.rrset("_acme-challenge.node1.example.com."))

	deleter, ok := setter.(libdns.RecordDeleter)
	require.True(t, ok, "provider must implement libdns.RecordDeleter so expired challenges can be removed")

	_, err = deleter.DeleteRecords(t.Context(), testZone, []libdns.Record{
		libdns.TXT{Name: "_acme-challenge.node1", TTL: time.Minute, Text: "value-1"},
	})
	require.NoError(t, err)

	require.Equal(t, []string{"value-2"}, server.rrset("_acme-challenge.node1.example.com."))
}

func TestProviderRejectsWrongTSIGSecret(t *testing.T) {
	t.Parallel()

	server := startFakeUpdateServer(t, testZone, testKeyName, testKeySecret)

	cfg := validConfig(server.addr)
	cfg["key_secret"] = "d0Zn21p3xv0F9WCEz5FUFg==" // different, valid-shaped secret

	setter, err := newProvider(cfg)
	require.NoError(t, err)

	_, err = setter.SetRecords(t.Context(), testZone, []libdns.Record{
		libdns.TXT{Name: "_acme-challenge.node1", TTL: time.Minute, Text: "challenge-value"},
	})
	require.Error(t, err)

	require.Empty(t, server.rrset("_acme-challenge.node1.example.com."))
}

func TestProviderRejectsZoneMismatch(t *testing.T) {
	t.Parallel()

	// The server only accepts updates for example.com.
	server := startFakeUpdateServer(t, testZone, testKeyName, testKeySecret)

	setter, err := newProvider(validConfig(server.addr))
	require.NoError(t, err)

	_, err = setter.SetRecords(t.Context(), "example.org", []libdns.Record{
		libdns.TXT{Name: "_acme-challenge.node1", TTL: time.Minute, Text: "challenge-value"},
	})
	require.Error(t, err)

	require.Empty(t, server.rrset("_acme-challenge.node1.example.org."))
}
