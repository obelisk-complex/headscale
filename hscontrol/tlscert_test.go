package hscontrol

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/libdns/libdns"
	"github.com/stretchr/testify/require"
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
