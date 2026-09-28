package hscontrol

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"maps"
	"net"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/libdns/libdns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

type fakeRecordSetter struct {
	err     error
	zone    string
	records []libdns.Record
}

func (f *fakeRecordSetter) SetRecords(
	_ context.Context,
	zone string,
	records []libdns.Record,
) ([]libdns.Record, error) {
	if f.err != nil {
		return nil, f.err
	}

	f.zone = zone
	f.records = append([]libdns.Record(nil), records...)

	return records, nil
}

// testACMEValue returns a well-formed DNS-01 TXT value derived from seed.
func testACMEValue(seed string) string {
	sum := sha256.Sum256([]byte(seed))

	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func testCertNode() types.NodeView {
	nodeKey := key.NewNode()
	machineKey := key.NewMachine()

	return (&types.Node{
		ID:         1,
		Hostname:   "node1",
		GivenName:  "node1",
		NodeKey:    nodeKey.Public(),
		MachineKey: machineKey.Public(),
	}).View()
}

func TestDNSCertificateManagerSetDNS(t *testing.T) {
	t.Parallel()

	setter := &fakeRecordSetter{}
	manager := newDNSCertificateManagerForSetter(types.DNSCertificatesConfig{
		Zone: "example.com",
		TTL:  time.Minute,
	}, setter)

	req := tailcfg.SetDNSRequest{
		NodeKey: testCertNode().NodeKey(),
		Name:    "_acme-challenge.node1.example.com",
		Type:    "TXT",
		Value:   testACMEValue("challenge"),
	}

	require.NoError(t, manager.setDNS(t.Context(), testCertNode(), "example.com", nil, req))
	require.Equal(t, "example.com", setter.zone)
	require.Len(t, setter.records, 1)

	txt, ok := setter.records[0].(libdns.TXT)
	require.True(t, ok, "record = %T, want libdns.TXT", setter.records[0])
	require.Equal(t, "_acme-challenge.node1", txt.Name)
	require.Equal(t, testACMEValue("challenge"), txt.Text)
	require.Equal(t, time.Minute, txt.TTL)
}

func TestDNSCertificateManagerKeepsConcurrentTXTValues(t *testing.T) {
	t.Parallel()

	setter := &fakeRecordSetter{}
	manager := newDNSCertificateManagerForSetter(types.DNSCertificatesConfig{
		Zone: "example.com",
		TTL:  time.Minute,
	}, setter)
	node := testCertNode()

	req := tailcfg.SetDNSRequest{
		NodeKey: node.NodeKey(),
		Name:    "_acme-challenge.node1.example.com",
		Type:    "TXT",
		Value:   testACMEValue("token-1"),
	}
	require.NoError(t, manager.setDNS(t.Context(), node, "example.com", nil, req))

	req.Value = testACMEValue("token-2")
	require.NoError(t, manager.setDNS(t.Context(), node, "example.com", nil, req))

	require.Len(t, setter.records, 2)
}

func TestValidateSetDNSRequest(t *testing.T) {
	t.Parallel()

	node := testCertNode()
	value := testACMEValue("challenge")

	tests := []struct {
		name    string
		reqName string
		reqType string
		value   string
		wantErr error
	}{
		{name: "own-record", reqName: "_acme-challenge.node1.example.com", reqType: "TXT", value: value},
		{name: "own-record-trailing-dot", reqName: "_acme-challenge.node1.example.com.", reqType: "TXT", value: value},
		{name: "own-record-mixed-case", reqName: "_ACME-Challenge.Node1.Example.COM", reqType: "TXT", value: value},

		{name: "type-a", reqName: "_acme-challenge.node1.example.com", reqType: "A", value: value, wantErr: errDNSCertRecordType},
		{name: "type-cname", reqName: "_acme-challenge.node1.example.com", reqType: "CNAME", value: value, wantErr: errDNSCertRecordType},
		{name: "type-lowercase", reqName: "_acme-challenge.node1.example.com", reqType: "txt", value: value, wantErr: errDNSCertRecordType},
		{name: "type-empty", reqName: "_acme-challenge.node1.example.com", reqType: "", value: value, wantErr: errDNSCertRecordType},

		{name: "other-node", reqName: "_acme-challenge.other.example.com", reqType: "TXT", value: value, wantErr: errDNSCertRecordName},
		{name: "node-prefix-of-other", reqName: "_acme-challenge.node10.example.com", reqType: "TXT", value: value, wantErr: errDNSCertRecordName},
		{name: "node-fqdn-itself", reqName: "node1.example.com", reqType: "TXT", value: value, wantErr: errDNSCertRecordName},
		{name: "parent-zone", reqName: "_acme-challenge.example.com", reqType: "TXT", value: value, wantErr: errDNSCertRecordName},
		{name: "zone-apex", reqName: "example.com", reqType: "TXT", value: value, wantErr: errDNSCertRecordName},
		{name: "subdomain-of-node", reqName: "_acme-challenge.sub.node1.example.com", reqType: "TXT", value: value, wantErr: errDNSCertRecordName},
		{name: "label-under-challenge", reqName: "x._acme-challenge.node1.example.com", reqType: "TXT", value: value, wantErr: errDNSCertRecordName},
		{name: "wildcard", reqName: "*.node1.example.com", reqType: "TXT", value: value, wantErr: errDNSCertRecordName},
		{name: "wildcard-challenge", reqName: "_acme-challenge.*.example.com", reqType: "TXT", value: value, wantErr: errDNSCertRecordName},
		{name: "other-base-domain", reqName: "_acme-challenge.node1.example.org", reqType: "TXT", value: value, wantErr: errDNSCertRecordName},
		{name: "suffix-appended", reqName: "_acme-challenge.node1.example.com.evil.com", reqType: "TXT", value: value, wantErr: errDNSCertRecordName},
		{name: "double-trailing-dot", reqName: "_acme-challenge.node1.example.com..", reqType: "TXT", value: value, wantErr: errDNSCertRecordName},
		{name: "empty-label", reqName: "_acme-challenge..node1.example.com", reqType: "TXT", value: value, wantErr: errDNSCertRecordName},
		{name: "leading-dot", reqName: "._acme-challenge.node1.example.com", reqType: "TXT", value: value, wantErr: errDNSCertRecordName},
		{name: "traversal", reqName: "_acme-challenge.other.example.com/../node1.example.com", reqType: "TXT", value: value, wantErr: errDNSCertRecordName},
		{name: "leading-space", reqName: " _acme-challenge.node1.example.com", reqType: "TXT", value: value, wantErr: errDNSCertRecordName},
		{name: "trailing-newline", reqName: "_acme-challenge.node1.example.com\n", reqType: "TXT", value: value, wantErr: errDNSCertRecordName},
		{name: "nul-byte", reqName: "_acme-challenge.node1.example.com\x00.other.example.com", reqType: "TXT", value: value, wantErr: errDNSCertRecordName},
		{name: "escaped-dot", reqName: "_acme-challenge\\.node1.example.com", reqType: "TXT", value: value, wantErr: errDNSCertRecordName},
		{name: "unicode-lookalike", reqName: "_acme-challenge.node\u0131.example.com", reqType: "TXT", value: value, wantErr: errDNSCertRecordName},
		{name: "empty-name", reqName: "", reqType: "TXT", value: value, wantErr: errDNSCertRecordName},
		{name: "root", reqName: ".", reqType: "TXT", value: value, wantErr: errDNSCertRecordName},

		{name: "value-empty", reqName: "_acme-challenge.node1.example.com", reqType: "TXT", value: "", wantErr: errDNSCertRecordValue},
		{name: "value-short", reqName: "_acme-challenge.node1.example.com", reqType: "TXT", value: value[:42], wantErr: errDNSCertRecordValue},
		{name: "value-long", reqName: "_acme-challenge.node1.example.com", reqType: "TXT", value: value + "A", wantErr: errDNSCertRecordValue},
		{name: "value-quote", reqName: "_acme-challenge.node1.example.com", reqType: "TXT", value: `"` + value[1:], wantErr: errDNSCertRecordValue},
		{name: "value-space", reqName: "_acme-challenge.node1.example.com", reqType: "TXT", value: " " + value[1:], wantErr: errDNSCertRecordValue},
		{name: "value-std-base64", reqName: "_acme-challenge.node1.example.com", reqType: "TXT", value: "+" + value[1:], wantErr: errDNSCertRecordValue},
		{name: "value-spf", reqName: "_acme-challenge.node1.example.com", reqType: "TXT", value: "v=spf1 include:evil.example -all", wantErr: errDNSCertRecordValue},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := validateSetDNSRequest(node, "example.com", nil, tailcfg.SetDNSRequest{
				NodeKey: node.NodeKey(),
				Name:    tt.reqName,
				Type:    tt.reqType,
				Value:   tt.value,
			})
			if tt.wantErr == nil {
				require.NoError(t, err)

				return
			}

			require.ErrorIs(t, err, tt.wantErr)
			require.True(t, isSetDNSRequestError(err))
		})
	}
}

// TestValidateSetDNSRequestRefusesExtraRecordCollision checks that a node
// named after a dns.extra_records entry cannot publish a challenge for it.
func TestValidateSetDNSRequestRefusesExtraRecordCollision(t *testing.T) {
	t.Parallel()

	node := (&types.Node{ID: 1, GivenName: "www", NodeKey: key.NewNode().Public()}).View()
	req := tailcfg.SetDNSRequest{
		NodeKey: node.NodeKey(),
		Name:    "_acme-challenge.www.example.com",
		Type:    "TXT",
		Value:   testACMEValue("challenge"),
	}

	for _, record := range []string{"www.example.com", "WWW.Example.com.", "api.www.example.com"} {
		err := validateSetDNSRequest(node, "example.com", []tailcfg.DNSRecord{
			{Name: record, Type: "A", Value: "192.0.2.1"},
		}, req)
		require.ErrorIs(t, err, errDNSCertRecordName, "record %q", record)
		require.True(t, isSetDNSRequestError(err))
	}

	require.NoError(t, validateSetDNSRequest(node, "example.com", []tailcfg.DNSRecord{
		{Name: "www.example.org", Type: "A", Value: "192.0.2.1"},
		{Name: "example.com", Type: "A", Value: "192.0.2.1"},
	}, req))
}

func TestDNSCertificateManagerWritesCanonicalName(t *testing.T) {
	t.Parallel()

	setter := &fakeRecordSetter{}
	manager := newDNSCertificateManagerForSetter(types.DNSCertificatesConfig{
		Zone: "Example.COM.",
	}, setter)
	node := testCertNode()

	require.NoError(t, manager.setDNS(t.Context(), node, "example.com", nil, tailcfg.SetDNSRequest{
		NodeKey: node.NodeKey(),
		Name:    "_ACME-Challenge.NODE1.example.com.",
		Type:    "TXT",
		Value:   testACMEValue("challenge"),
	}))

	require.Equal(t, "example.com", setter.zone)
	require.Len(t, setter.records, 1)
	require.Equal(t, "_acme-challenge.node1", setter.records[0].RR().Name)
}

func TestDNSCertificateManagerRejectsNameOutsideZone(t *testing.T) {
	t.Parallel()

	setter := &fakeRecordSetter{}
	manager := newDNSCertificateManagerForSetter(types.DNSCertificatesConfig{
		Zone: "example.org",
	}, setter)
	node := testCertNode()

	err := manager.setDNS(t.Context(), node, "example.com", nil, tailcfg.SetDNSRequest{
		NodeKey: node.NodeKey(),
		Name:    "_acme-challenge.node1.example.com",
		Type:    "TXT",
		Value:   testACMEValue("challenge"),
	})
	require.Error(t, err)
	require.False(t, isSetDNSRequestError(err), "zone mismatch is a server misconfiguration")
	require.Nil(t, setter.records)
}

// fakePropagationResolver models a small DNS hierarchy. ns maps a name to
// its NS host names, hosts maps a host to its addresses, and served maps
// "addr|name" to the TXT values that server answers with. unreachable
// addresses fail every query. visibleAfter delays a server's answers by a
// number of queries to model a zone still propagating.
type fakePropagationResolver struct {
	mu           sync.Mutex
	ns           map[string][]string
	hosts        map[string][]string
	served       map[string][]string
	unreachable  map[string]bool
	visibleAfter map[string]int
	queries      map[string]int
}

func (f *fakePropagationResolver) LookupNS(_ context.Context, name string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if hosts, ok := f.ns[name]; ok {
		return hosts, nil
	}

	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func (f *fakePropagationResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if addrs, ok := f.hosts[host]; ok {
		return addrs, nil
	}

	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func (f *fakePropagationResolver) LookupTXTAt(
	_ context.Context,
	addr, name string,
) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.queries == nil {
		f.queries = make(map[string]int)
	}
	f.queries[addr]++

	if f.unreachable[addr] {
		return nil, errors.New("connect: network is unreachable")
	}

	if f.queries[addr] <= f.visibleAfter[addr] {
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}

	return f.served[addr+"|"+name], nil
}

func (f *fakePropagationResolver) queryCount(addr string) int {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.queries[addr]
}

const testChallengeFQDN = "_acme-challenge.node1.example.com."

func testPropagationManager(
	resolver dnsPropagationResolver,
	timeout time.Duration,
) (*dnsCertificateManager, *fakeRecordSetter) {
	setter := &fakeRecordSetter{}
	manager := newDNSCertificateManagerForSetter(types.DNSCertificatesConfig{
		Zone: "example.com",
	}, setter)
	manager.propagation = &dnsPropagationChecker{
		resolver:     resolver,
		timeout:      timeout,
		pollInterval: time.Millisecond,
	}

	return manager, setter
}

func testChallengeRequest(node types.NodeView, value string) tailcfg.SetDNSRequest {
	return tailcfg.SetDNSRequest{
		NodeKey: node.NodeKey(),
		Name:    testChallengeFQDN,
		Type:    "TXT",
		Value:   value,
	}
}

func TestDNSPropagationWaitsForEveryAuthoritativeServer(t *testing.T) {
	t.Parallel()

	value := testACMEValue("challenge")
	resolver := &fakePropagationResolver{
		ns: map[string][]string{"example.com.": {"ns1.example.net.", "ns2.example.net."}},
		hosts: map[string][]string{
			"ns1.example.net.": {"192.0.2.1"},
			"ns2.example.net.": {"192.0.2.2"},
		},
		served: map[string][]string{
			"192.0.2.1:53|" + testChallengeFQDN: {"unrelated", value},
			"192.0.2.2:53|" + testChallengeFQDN: {value},
		},
		// ns2 lags behind ns1.
		visibleAfter: map[string]int{"192.0.2.2:53": 3},
	}
	manager, _ := testPropagationManager(resolver, time.Minute)
	node := testCertNode()

	require.NoError(t, manager.setDNS(t.Context(), node, "example.com", nil, testChallengeRequest(node, value)))

	require.Equal(t, 1, resolver.queryCount("192.0.2.1:53"), "confirmed server is not polled again")
	require.Equal(t, 4, resolver.queryCount("192.0.2.2:53"), "lagging server is polled until it serves the value")
}

func TestDNSPropagationFindsDelegatedZoneCut(t *testing.T) {
	t.Parallel()

	value := testACMEValue("challenge")
	resolver := &fakePropagationResolver{
		// node1.example.com is delegated away from example.com; only the
		// delegated servers are authoritative for the challenge name.
		ns: map[string][]string{
			"example.com.":       {"parent.example.net."},
			"node1.example.com.": {"child.example.net."},
		},
		hosts: map[string][]string{
			"parent.example.net.": {"192.0.2.1"},
			"child.example.net.":  {"192.0.2.9"},
		},
		served: map[string][]string{
			"192.0.2.9:53|" + testChallengeFQDN: {value},
		},
	}
	manager, _ := testPropagationManager(resolver, time.Minute)
	node := testCertNode()

	require.NoError(t, manager.setDNS(t.Context(), node, "example.com", nil, testChallengeRequest(node, value)))
	require.Zero(t, resolver.queryCount("192.0.2.1:53"), "parent zone servers are not authoritative")
}

func TestDNSPropagationToleratesUnreachableAddress(t *testing.T) {
	t.Parallel()

	value := testACMEValue("challenge")
	resolver := &fakePropagationResolver{
		ns: map[string][]string{"example.com.": {"ns1.example.net."}},
		hosts: map[string][]string{
			"ns1.example.net.": {"2001:db8::1", "192.0.2.1"},
		},
		served: map[string][]string{
			"192.0.2.1:53|" + testChallengeFQDN: {value},
		},
		unreachable: map[string]bool{"[2001:db8::1]:53": true},
	}
	manager, _ := testPropagationManager(resolver, time.Minute)
	node := testCertNode()

	require.NoError(t, manager.setDNS(t.Context(), node, "example.com", nil, testChallengeRequest(node, value)))
}

func TestDNSPropagationTimesOut(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		resolver *fakePropagationResolver
	}{
		{
			name: "value-never-served",
			resolver: &fakePropagationResolver{
				ns:    map[string][]string{"example.com.": {"ns1.example.net.", "ns2.example.net."}},
				hosts: map[string][]string{"ns1.example.net.": {"192.0.2.1"}, "ns2.example.net.": {"192.0.2.2"}},
				served: map[string][]string{
					"192.0.2.1:53|" + testChallengeFQDN: {testACMEValue("challenge")},
					"192.0.2.2:53|" + testChallengeFQDN: {testACMEValue("stale")},
				},
			},
		},
		{
			name:     "no-ns-records",
			resolver: &fakePropagationResolver{},
		},
		{
			name: "ns-without-addresses",
			resolver: &fakePropagationResolver{
				ns: map[string][]string{"example.com.": {"ns1.example.net."}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			manager, _ := testPropagationManager(tt.resolver, 50*time.Millisecond)
			node := testCertNode()

			err := manager.setDNS(
				t.Context(), node, "example.com", nil,
				testChallengeRequest(node, testACMEValue("challenge")),
			)
			require.ErrorIs(t, err, errDNSCertPropagation)
			require.False(t, isSetDNSRequestError(err))
		})
	}
}

func TestDNSPropagationRespectsRequestContext(t *testing.T) {
	t.Parallel()

	manager, _ := testPropagationManager(&fakePropagationResolver{}, time.Hour)
	node := testCertNode()

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := manager.setDNS(ctx, node, "example.com", nil, testChallengeRequest(node, testACMEValue("challenge")))
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Less(t, time.Since(start), 5*time.Second)
}

// TestDNSPropagationDoesNotBlockOtherNodes guards against holding the
// manager lock while one node's record propagates.
func TestDNSPropagationDoesNotBlockOtherNodes(t *testing.T) {
	t.Parallel()

	slowValue := testACMEValue("slow")
	fastValue := testACMEValue("fast")
	resolver := &fakePropagationResolver{
		ns:    map[string][]string{"example.com.": {"ns1.example.net."}},
		hosts: map[string][]string{"ns1.example.net.": {"192.0.2.1"}},
		served: map[string][]string{
			"192.0.2.1:53|_acme-challenge.node2.example.com.": {fastValue},
		},
	}
	manager, _ := testPropagationManager(resolver, time.Hour)

	slowNode := testCertNode()
	fastNode := (&types.Node{
		ID:        2,
		GivenName: "node2",
		NodeKey:   key.NewNode().Public(),
	}).View()

	ctx, cancel := context.WithCancel(t.Context())
	slowDone := make(chan error, 1)

	go func() {
		slowDone <- manager.setDNS(ctx, slowNode, "example.com", nil, testChallengeRequest(slowNode, slowValue))
	}()

	require.Eventually(t, func() bool {
		return resolver.queryCount("192.0.2.1:53") > 0
	}, 5*time.Second, time.Millisecond, "slow node is polling")

	require.NoError(t, manager.setDNS(t.Context(), fastNode, "example.com", nil, tailcfg.SetDNSRequest{
		NodeKey: fastNode.NodeKey(),
		Name:    "_acme-challenge.node2.example.com",
		Type:    "TXT",
		Value:   fastValue,
	}))

	cancel()
	require.ErrorIs(t, <-slowDone, context.Canceled)
}

func TestDNSPropagationWaitIsMinimum(t *testing.T) {
	t.Parallel()

	setter := &fakeRecordSetter{}
	manager := newDNSCertificateManagerForSetter(types.DNSCertificatesConfig{
		Zone:            "example.com",
		PropagationWait: 50 * time.Millisecond,
	}, setter)
	require.Nil(t, manager.propagation, "check is off unless configured")

	node := testCertNode()
	start := time.Now()
	require.NoError(t, manager.setDNS(t.Context(), node, "example.com", nil, testChallengeRequest(node, testACMEValue("challenge"))))
	require.GreaterOrEqual(t, time.Since(start), 50*time.Millisecond)
}

// TestNetPropagationResolverQueriesPinnedServer checks that LookupTXTAt
// sends its query to the given server rather than the system resolver.
func TestNetPropagationResolverQueriesPinnedServer(t *testing.T) {
	t.Parallel()

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })

	value := testACMEValue("challenge")
	queries := make(chan string, 16)

	go func() {
		buf := make([]byte, 1500)

		for {
			n, from, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}

			var p dnsmessage.Parser

			hdr, err := p.Start(buf[:n])
			if err != nil {
				continue
			}

			q, err := p.Question()
			if err != nil {
				continue
			}
			queries <- q.Name.String()

			b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
				ID: hdr.ID, Response: true, Authoritative: true,
			})
			b.EnableCompression()
			_ = b.StartQuestions()
			_ = b.Question(q)
			_ = b.StartAnswers()

			if q.Type == dnsmessage.TypeTXT {
				_ = b.TXTResource(
					dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 60},
					dnsmessage.TXTResource{TXT: []string{value}},
				)
			}

			msg, err := b.Finish()
			if err != nil {
				continue
			}

			_, _ = conn.WriteTo(msg, from)
		}
	}()

	txts, err := netPropagationResolver{}.LookupTXTAt(
		t.Context(), conn.LocalAddr().String(), testChallengeFQDN,
	)
	require.NoError(t, err)
	require.Equal(t, []string{value}, txts)
	require.Equal(t, testChallengeFQDN, <-queries)
}

// fakeRecordStore is a concurrency-safe provider that keeps one zone's TXT
// records and optionally implements libdns.RecordDeleter.
type fakeRecordStore struct {
	mu      sync.Mutex
	failSet bool
	rrsets  map[string][]string // relative name -> values
	deleted []string
}

func (f *fakeRecordStore) SetRecords(
	_ context.Context,
	_ string,
	records []libdns.Record,
) ([]libdns.Record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.failSet {
		return nil, errors.New("provider down")
	}

	if f.rrsets == nil {
		f.rrsets = make(map[string][]string)
	}

	// libdns SetRecords semantics: the input replaces each (name, type) RRset.
	byName := make(map[string][]string)
	for _, r := range records {
		rr := r.RR()
		byName[rr.Name] = append(byName[rr.Name], rr.Data)
	}
	maps.Copy(f.rrsets, byName)

	return records, nil
}

func (f *fakeRecordStore) rrset(name string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()

	return slices.Clone(f.rrsets[name])
}

func (f *fakeRecordStore) setFail(fail bool) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.failSet = fail
}

type fakeDeletingRecordStore struct {
	fakeRecordStore

	// failDeletes is how many upcoming DeleteRecords calls fail.
	failDeletes    int
	deleteAttempts int
}

func (f *fakeDeletingRecordStore) DeleteRecords(
	_ context.Context,
	_ string,
	records []libdns.Record,
) ([]libdns.Record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.deleteAttempts++

	if f.failDeletes > 0 {
		f.failDeletes--

		return nil, errors.New("provider down")
	}

	for _, r := range records {
		rr := r.RR()
		f.rrsets[rr.Name] = slices.DeleteFunc(f.rrsets[rr.Name], func(v string) bool {
			return v == rr.Data
		})
		f.deleted = append(f.deleted, rr.Data)
	}

	return records, nil
}

func (f *fakeDeletingRecordStore) deletedValues() []string {
	f.mu.Lock()
	defer f.mu.Unlock()

	return slices.Clone(f.deleted)
}

func setTestChallenge(t *testing.T, m *dnsCertificateManager, value string) {
	t.Helper()

	node := testCertNode()
	require.NoError(t, m.setDNS(t.Context(), node, "example.com", nil, testChallengeRequest(node, value)))
}

// expireValue backdates value so the next cleanup treats it as expired.
func expireValue(m *dnsCertificateManager, value string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.records[testChallengeFQDN][value] = time.Now().Add(-time.Second)
}

func TestDNSCertificateManagerMergesRRset(t *testing.T) {
	t.Parallel()

	store := &fakeRecordStore{}
	manager := newDNSCertificateManagerForSetter(types.DNSCertificatesConfig{Zone: "example.com"}, store)
	v1, v2, v3 := testACMEValue("1"), testACMEValue("2"), testACMEValue("3")

	setTestChallenge(t, manager, v1)
	setTestChallenge(t, manager, v2)
	require.ElementsMatch(t, []string{v1, v2}, store.rrset("_acme-challenge.node1"))

	// Re-sending a value does not duplicate it.
	setTestChallenge(t, manager, v1)
	require.ElementsMatch(t, []string{v1, v2}, store.rrset("_acme-challenge.node1"))

	// A value the provider rejected is not carried into later writes, and
	// the value it would have evicted is kept.
	store.setFail(true)

	node := testCertNode()
	require.Error(t, manager.setDNS(t.Context(), node, "example.com", nil, testChallengeRequest(node, v3)))
	store.setFail(false)

	// A third value evicts the one expiring first: v2, since v1 was re-sent.
	v4 := testACMEValue("4")
	setTestChallenge(t, manager, v4)
	require.ElementsMatch(t, []string{v1, v4}, store.rrset("_acme-challenge.node1"))
}

// TestDNSCertificateManagerCapsValuesPerName checks that a client looping
// with fresh values cannot grow the RRset past dnsCertMaxValuesPerName,
// and that its newest values are the ones published.
func TestDNSCertificateManagerCapsValuesPerName(t *testing.T) {
	t.Parallel()

	store := &fakeRecordStore{}
	manager := newDNSCertificateManagerForSetter(types.DNSCertificatesConfig{Zone: "example.com"}, store)

	var values []string

	for i := range 20 {
		v := testACMEValue(strconv.Itoa(i))
		values = append(values, v)
		setTestChallenge(t, manager, v)
		require.LessOrEqual(t, len(store.rrset("_acme-challenge.node1")), dnsCertMaxValuesPerName)
	}

	require.ElementsMatch(t, values[len(values)-dnsCertMaxValuesPerName:], store.rrset("_acme-challenge.node1"))

	manager.mu.Lock()
	defer manager.mu.Unlock()

	require.Len(t, manager.records[testChallengeFQDN], dnsCertMaxValuesPerName)
}

// slowRecordStore is a fakeRecordStore whose writes take a while and which
// records whether two writes for the same name ever overlapped.
type slowRecordStore struct {
	fakeRecordStore

	delay time.Duration
	// block, when set, holds writes for blockName until it is closed.
	block     chan struct{}
	blockName string

	inflightMu sync.Mutex
	inflight   map[string]int
	overlapped bool
}

func (f *slowRecordStore) SetRecords(
	ctx context.Context,
	zone string,
	records []libdns.Record,
) ([]libdns.Record, error) {
	name := records[0].RR().Name

	f.inflightMu.Lock()
	if f.inflight == nil {
		f.inflight = make(map[string]int)
	}
	f.inflight[name]++
	if f.inflight[name] > 1 {
		f.overlapped = true
	}
	f.inflightMu.Unlock()

	defer func() {
		f.inflightMu.Lock()
		f.inflight[name]--
		f.inflightMu.Unlock()
	}()

	if f.block != nil && name == f.blockName {
		<-f.block
	}

	time.Sleep(f.delay)

	return f.fakeRecordStore.SetRecords(ctx, zone, records)
}

// TestDNSCertificateManagerConcurrentSameNameKeepsBothValues runs pairs of
// concurrent requests for one name, as tailscaled does for <fqdn> and
// *.<fqdn>, against a slow provider. Each pair must end up published in
// full: neither write may drop the other's value.
func TestDNSCertificateManagerConcurrentSameNameKeepsBothValues(t *testing.T) {
	t.Parallel()

	store := &slowRecordStore{delay: time.Millisecond}
	manager := newDNSCertificateManagerForSetter(types.DNSCertificatesConfig{Zone: "example.com"}, store)
	node := testCertNode()

	for i := range 50 {
		a, b := testACMEValue("a"+strconv.Itoa(i)), testACMEValue("b"+strconv.Itoa(i))

		var wg sync.WaitGroup
		for _, v := range []string{a, b} {
			wg.Go(func() {
				assert.NoError(t, manager.setDNS(t.Context(), node, "example.com", nil, testChallengeRequest(node, v)))
			})
		}
		wg.Wait()

		require.ElementsMatch(t, []string{a, b}, store.rrset("_acme-challenge.node1"), "pair %d", i)
	}

	store.inflightMu.Lock()
	defer store.inflightMu.Unlock()

	require.False(t, store.overlapped, "writes for one name must not overlap")
}

// TestDNSCertificateManagerSlowNameDoesNotBlockOthers guards against one
// node's slow provider write stalling every other node's issuance.
func TestDNSCertificateManagerSlowNameDoesNotBlockOthers(t *testing.T) {
	t.Parallel()

	store := &slowRecordStore{block: make(chan struct{}), blockName: "_acme-challenge.node1"}
	manager := newDNSCertificateManagerForSetter(types.DNSCertificatesConfig{Zone: "example.com"}, store)

	slowNode := testCertNode()
	fastNode := (&types.Node{ID: 2, GivenName: "node2", NodeKey: key.NewNode().Public()}).View()

	slowDone := make(chan error, 1)

	go func() {
		slowDone <- manager.setDNS(t.Context(), slowNode, "example.com", nil,
			testChallengeRequest(slowNode, testACMEValue("slow")))
	}()

	require.Eventually(t, func() bool {
		store.inflightMu.Lock()
		defer store.inflightMu.Unlock()

		return store.inflight["_acme-challenge.node1"] == 1
	}, 5*time.Second, time.Millisecond, "slow write is in flight")

	require.NoError(t, manager.setDNS(t.Context(), fastNode, "example.com", nil, tailcfg.SetDNSRequest{
		NodeKey: fastNode.NodeKey(),
		Name:    "_acme-challenge.node2.example.com",
		Type:    "TXT",
		Value:   testACMEValue("fast"),
	}))

	close(store.block)
	require.NoError(t, <-slowDone)

	manager.mu.Lock()
	defer manager.mu.Unlock()

	require.Empty(t, manager.nameLocks, "name locks are released")
}

func TestNodeRateLimiter(t *testing.T) {
	t.Parallel()

	l := newNodeRateLimiter(3, 10*time.Second)
	now := time.Now()

	for range 3 {
		require.True(t, l.allow(1, now))
	}

	require.False(t, l.allow(1, now), "burst exhausted")
	require.True(t, l.allow(2, now), "other nodes have their own bucket")

	require.False(t, l.allow(1, now.Add(9*time.Second)))
	require.True(t, l.allow(1, now.Add(10*time.Second)), "one token back per interval")
	require.False(t, l.allow(1, now.Add(10*time.Second)))

	// Idle, full buckets are forgotten.
	l.allow(3, now.Add(time.Hour))
	require.Len(t, l.buckets, 1)
}

func TestDNSCertificateManagerCleanup(t *testing.T) {
	t.Parallel()

	store := &fakeDeletingRecordStore{}
	manager := newDNSCertificateManagerForSetter(types.DNSCertificatesConfig{Zone: "example.com"}, store)
	require.NotNil(t, manager.deleter)

	v1, v2 := testACMEValue("1"), testACMEValue("2")
	setTestChallenge(t, manager, v1)
	setTestChallenge(t, manager, v2)

	// One value expired: the RRset is rewritten without it.
	expireValue(manager, v1)
	manager.cleanup(testChallengeFQDN)
	require.Equal(t, []string{v2}, store.rrset("_acme-challenge.node1"))
	require.Empty(t, store.deletedValues())

	// Last value expired: the record is deleted.
	expireValue(manager, v2)
	manager.cleanup(testChallengeFQDN)
	require.Empty(t, store.rrset("_acme-challenge.node1"))
	require.Equal(t, []string{v2}, store.deletedValues())

	manager.mu.Lock()
	defer manager.mu.Unlock()

	require.Empty(t, manager.records)
	require.Empty(t, manager.cleanupTimers)
}

func TestDNSCertificateManagerCleanupWithoutDeleter(t *testing.T) {
	t.Parallel()

	store := &fakeRecordStore{}
	manager := newDNSCertificateManagerForSetter(types.DNSCertificatesConfig{Zone: "example.com"}, store)
	require.Nil(t, manager.deleter)

	v1 := testACMEValue("1")
	setTestChallenge(t, manager, v1)

	expireValue(manager, v1)
	manager.cleanup(testChallengeFQDN)

	// Nothing to delete with, so the record stays; the manager forgets it.
	require.Equal(t, []string{v1}, store.rrset("_acme-challenge.node1"))

	manager.mu.Lock()
	defer manager.mu.Unlock()

	require.Empty(t, manager.records)
}

func TestDNSCertificateManagerCleanupTimerFires(t *testing.T) {
	t.Parallel()

	store := &fakeDeletingRecordStore{}
	manager := newDNSCertificateManagerForSetter(types.DNSCertificatesConfig{Zone: "example.com"}, store)
	manager.retention = 20 * time.Millisecond

	v1 := testACMEValue("1")
	setTestChallenge(t, manager, v1)

	require.Eventually(t, func() bool {
		return slices.Equal([]string{v1}, store.deletedValues())
	}, 5*time.Second, 5*time.Millisecond)
	require.Empty(t, store.rrset("_acme-challenge.node1"))
}

// heldValues returns the values the manager holds for the test challenge.
func heldValues(m *dnsCertificateManager) []string {
	m.mu.Lock()
	defer m.mu.Unlock()

	return slices.Sorted(maps.Keys(m.records[testChallengeFQDN]))
}

// TestDNSCertificateManagerCleanupRetriesFailedDelete checks that a failed
// delete of the last expired value keeps the value tracked and retries,
// rather than forgetting a record that is still published.
func TestDNSCertificateManagerCleanupRetriesFailedDelete(t *testing.T) {
	t.Parallel()

	store := &fakeDeletingRecordStore{failDeletes: 1}
	manager := newDNSCertificateManagerForSetter(types.DNSCertificatesConfig{Zone: "example.com"}, store)
	manager.cleanupRetry = time.Hour // the test drives the retry itself

	v1 := testACMEValue("1")
	setTestChallenge(t, manager, v1)

	expireValue(manager, v1)
	manager.cleanup(testChallengeFQDN)

	require.Equal(t, []string{v1}, store.rrset("_acme-challenge.node1"), "the delete failed")
	require.Equal(t, []string{v1}, heldValues(manager), "a value is not forgotten before it is removed")

	manager.mu.Lock()
	require.Contains(t, manager.cleanupTimers, testChallengeFQDN, "a retry is scheduled")
	require.Equal(t, 1, manager.cleanupFailures[testChallengeFQDN])
	manager.mu.Unlock()

	manager.cleanup(testChallengeFQDN)

	require.Equal(t, []string{v1}, store.deletedValues())
	require.Empty(t, store.rrset("_acme-challenge.node1"))

	manager.mu.Lock()
	defer manager.mu.Unlock()

	require.Empty(t, manager.records)
	require.Empty(t, manager.cleanupTimers)
	require.Empty(t, manager.cleanupFailures)
}

// TestDNSCertificateManagerCleanupRetryTimerFires checks the retry end to
// end: a cleanup whose first delete fails still removes the record.
func TestDNSCertificateManagerCleanupRetryTimerFires(t *testing.T) {
	t.Parallel()

	store := &fakeDeletingRecordStore{failDeletes: 1}
	manager := newDNSCertificateManagerForSetter(types.DNSCertificatesConfig{Zone: "example.com"}, store)
	manager.retention = 20 * time.Millisecond
	manager.cleanupRetry = 20 * time.Millisecond

	v1 := testACMEValue("1")
	setTestChallenge(t, manager, v1)

	require.Eventually(t, func() bool {
		return slices.Equal([]string{v1}, store.deletedValues())
	}, 5*time.Second, 5*time.Millisecond)
	require.Empty(t, store.rrset("_acme-challenge.node1"))
	require.Empty(t, heldValues(manager))

	store.mu.Lock()
	defer store.mu.Unlock()

	require.Equal(t, 2, store.deleteAttempts)
}

// TestDNSCertificateManagerCleanupRetriesFailedRewrite covers the rewrite
// path, where other values are still live, and a publish that fails while
// an expired value is pending removal.
func TestDNSCertificateManagerCleanupRetriesFailedRewrite(t *testing.T) {
	t.Parallel()

	store := &fakeDeletingRecordStore{}
	manager := newDNSCertificateManagerForSetter(types.DNSCertificatesConfig{Zone: "example.com"}, store)
	manager.cleanupRetry = time.Hour

	v1, v2, v3 := testACMEValue("1"), testACMEValue("2"), testACMEValue("3")
	setTestChallenge(t, manager, v1)
	setTestChallenge(t, manager, v2)
	expireValue(manager, v1)

	store.setFail(true)
	manager.cleanup(testChallengeFQDN)
	require.ElementsMatch(t, []string{v1, v2}, heldValues(manager), "the rewrite failed")

	// A failed publish must not drop the expired value either: the provider
	// still serves it.
	node := testCertNode()
	require.Error(t, manager.setDNS(t.Context(), node, "example.com", nil, testChallengeRequest(node, v3)))
	require.ElementsMatch(t, []string{v1, v2}, heldValues(manager))

	store.setFail(false)
	manager.cleanup(testChallengeFQDN)
	require.Equal(t, []string{v2}, store.rrset("_acme-challenge.node1"))
	require.Equal(t, []string{v2}, heldValues(manager))
	require.Empty(t, store.deletedValues())
}

func TestDNSCertificateManagerCleanupBackoff(t *testing.T) {
	t.Parallel()

	manager := newDNSCertificateManagerForSetter(types.DNSCertificatesConfig{Zone: "example.com"}, &fakeRecordStore{})

	var got []time.Duration

	for failures := 1; failures <= 7; failures++ {
		manager.cleanupFailures["x"] = failures
		got = append(got, manager.cleanupBackoffLocked("x"))
	}

	require.Equal(t, []time.Duration{
		30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute,
		8 * time.Minute, 10 * time.Minute, 10 * time.Minute,
	}, got)
}
