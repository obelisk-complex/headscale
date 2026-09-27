package hscontrol

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"maps"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/libdns/libdns"
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

	require.NoError(t, manager.setDNS(t.Context(), testCertNode(), "example.com", req))
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
	require.NoError(t, manager.setDNS(t.Context(), node, "example.com", req))

	req.Value = testACMEValue("token-2")
	require.NoError(t, manager.setDNS(t.Context(), node, "example.com", req))

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

			err := validateSetDNSRequest(node, "example.com", tailcfg.SetDNSRequest{
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

func TestDNSCertificateManagerWritesCanonicalName(t *testing.T) {
	t.Parallel()

	setter := &fakeRecordSetter{}
	manager := newDNSCertificateManagerForSetter(types.DNSCertificatesConfig{
		Zone: "Example.COM.",
	}, setter)
	node := testCertNode()

	require.NoError(t, manager.setDNS(t.Context(), node, "example.com", tailcfg.SetDNSRequest{
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

	err := manager.setDNS(t.Context(), node, "example.com", tailcfg.SetDNSRequest{
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

	require.NoError(t, manager.setDNS(t.Context(), node, "example.com", testChallengeRequest(node, value)))

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

	require.NoError(t, manager.setDNS(t.Context(), node, "example.com", testChallengeRequest(node, value)))
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

	require.NoError(t, manager.setDNS(t.Context(), node, "example.com", testChallengeRequest(node, value)))
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
				t.Context(), node, "example.com",
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
	err := manager.setDNS(ctx, node, "example.com", testChallengeRequest(node, testACMEValue("challenge")))
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
		slowDone <- manager.setDNS(ctx, slowNode, "example.com", testChallengeRequest(slowNode, slowValue))
	}()

	require.Eventually(t, func() bool {
		return resolver.queryCount("192.0.2.1:53") > 0
	}, 5*time.Second, time.Millisecond, "slow node is polling")

	require.NoError(t, manager.setDNS(t.Context(), fastNode, "example.com", tailcfg.SetDNSRequest{
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
	require.NoError(t, manager.setDNS(t.Context(), node, "example.com", testChallengeRequest(node, testACMEValue("challenge"))))
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
}

func (f *fakeDeletingRecordStore) DeleteRecords(
	_ context.Context,
	_ string,
	records []libdns.Record,
) ([]libdns.Record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

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
	require.NoError(t, m.setDNS(t.Context(), node, "example.com", testChallengeRequest(node, value)))
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

	// A value the provider rejected is not carried into later writes.
	store.setFail(true)

	node := testCertNode()
	require.Error(t, manager.setDNS(t.Context(), node, "example.com", testChallengeRequest(node, v3)))
	store.setFail(false)

	v4 := testACMEValue("4")
	setTestChallenge(t, manager, v4)
	require.ElementsMatch(t, []string{v1, v2, v4}, store.rrset("_acme-challenge.node1"))
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
