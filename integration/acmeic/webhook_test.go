package acmeic

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testToken  = "test-token"
	testSecret = "test-secret"
	testZone   = "headscale.net"
	testHost   = "_acme-challenge.node1.headscale.net."
)

// fakeChallTestSrv mimics pebble-challtestsrv's TXT API: /set-txt appends
// a value to a host, /clear-txt drops every value of a host.
type fakeChallTestSrv struct {
	mu   sync.Mutex
	txt  map[string][]string
	ops  []string
	fail bool
}

func (f *fakeChallTestSrv) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Host  string `json:"host"`
		Value string `json:"value"`
	}

	if err := json.NewDecoder(r.Body).Decode(&body); err != nil { //nolint:noinlineerr
		http.Error(w, err.Error(), http.StatusBadRequest)

		return
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	if f.fail {
		http.Error(w, "injected failure", http.StatusInternalServerError)

		return
	}

	switch r.URL.Path {
	case "/set-txt":
		f.txt[body.Host] = append(f.txt[body.Host], body.Value)
		f.ops = append(f.ops, "set "+body.Value)
	case "/clear-txt":
		delete(f.txt, body.Host)
		f.ops = append(f.ops, "clear")
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeChallTestSrv) state(host string) ([]string, []string) {
	f.mu.Lock()
	defer f.mu.Unlock()

	ops := f.ops
	f.ops = nil

	return f.txt[host], ops
}

func newTestAdapter(t *testing.T) (*WebhookAdapter, *fakeChallTestSrv) {
	t.Helper()

	fake := &fakeChallTestSrv{txt: make(map[string][]string)}
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)

	adapter, err := NewWebhookAdapter(srv.URL, testToken, testSecret)
	require.NoError(t, err)
	t.Cleanup(func() { _ = adapter.Close() })

	return adapter, fake
}

func post(t *testing.T, a *WebhookAdapter, action string, values ...string) int {
	t.Helper()

	req := WebhookRequest{Action: action, Zone: testZone, Type: "TXT"}
	for _, v := range values {
		req.Records = append(req.Records, WebhookRecord{
			Name: "_acme-challenge.node1", Type: "TXT", Value: v, TTL: 60,
		})
	}

	body, err := json.Marshal(req)
	require.NoError(t, err)

	return postRaw(t, a, "/"+action, body, "Bearer "+testToken, sign(body, testSecret))
}

func postRaw(t *testing.T, a *WebhookAdapter, path string, body []byte, auth, sig string) int {
	t.Helper()

	url := fmt.Sprintf("http://127.0.0.1:%d%s", a.Port(), path)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, url, bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", auth)
	req.Header.Set("X-Headscale-Signature", sig)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	return resp.StatusCode
}

func sign(body []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)

	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func TestWebhookAdapterSetGrowsWithoutClearing(t *testing.T) {
	a, fake := newTestAdapter(t)

	require.Equal(t, http.StatusNoContent, post(t, a, "set", "v1"))
	txt, ops := fake.state(testHost)
	assert.Equal(t, []string{"v1"}, txt)
	assert.Equal(t, []string{"set v1"}, ops)

	// The full RRset {v1, v2}: only v2 is new, v1 must never disappear.
	require.Equal(t, http.StatusNoContent, post(t, a, "set", "v1", "v2"))
	txt, ops = fake.state(testHost)
	assert.ElementsMatch(t, []string{"v1", "v2"}, txt)
	assert.Equal(t, []string{"set v2"}, ops)

	// Repeating a set is a no-op (Headscale retries on 5xx).
	require.Equal(t, http.StatusNoContent, post(t, a, "set", "v1", "v2"))
	_, ops = fake.state(testHost)
	assert.Empty(t, ops)

	assert.ElementsMatch(t, []string{"v1", "v2"}, a.TXT("_acme-challenge.node1.headscale.net"))
	assert.Len(t, a.Calls(), 3)
}

func TestWebhookAdapterSetShrinkReplaces(t *testing.T) {
	a, fake := newTestAdapter(t)

	require.Equal(t, http.StatusNoContent, post(t, a, "set", "v1", "v2"))
	_, _ = fake.state(testHost)

	require.Equal(t, http.StatusNoContent, post(t, a, "set", "v3"))
	txt, ops := fake.state(testHost)
	assert.Equal(t, []string{"v3"}, txt)
	assert.Equal(t, []string{"clear", "set v3"}, ops)
}

func TestWebhookAdapterDelete(t *testing.T) {
	a, fake := newTestAdapter(t)

	require.Equal(t, http.StatusNoContent, post(t, a, "set", "v1", "v2"))
	_, _ = fake.state(testHost)

	// delete carries only the values to remove.
	require.Equal(t, http.StatusNoContent, post(t, a, "delete", "v1"))
	txt, ops := fake.state(testHost)
	assert.Equal(t, []string{"v2"}, txt)
	assert.Equal(t, []string{"clear", "set v2"}, ops)

	require.Equal(t, http.StatusNoContent, post(t, a, "delete", "v2"))
	txt, ops = fake.state(testHost)
	assert.Empty(t, txt)
	assert.Equal(t, []string{"clear"}, ops)
	assert.Empty(t, a.TXT(testHost))
}

func TestWebhookAdapterRecoversAfterBackendFailure(t *testing.T) {
	a, fake := newTestAdapter(t)

	require.Equal(t, http.StatusNoContent, post(t, a, "set", "v1"))

	fake.mu.Lock()
	fake.fail = true
	fake.mu.Unlock()

	require.Equal(t, http.StatusBadGateway, post(t, a, "set", "v1", "v2"))

	fake.mu.Lock()
	fake.fail = false
	fake.mu.Unlock()
	_, _ = fake.state(testHost)

	// The failed call left the name in an unknown state, so the retry
	// rewrites it from scratch instead of appending.
	require.Equal(t, http.StatusNoContent, post(t, a, "set", "v1", "v2"))
	txt, ops := fake.state(testHost)
	assert.ElementsMatch(t, []string{"v1", "v2"}, txt)
	assert.Equal(t, []string{"clear", "set v1", "set v2"}, ops)
}

func TestWebhookAdapterRejects(t *testing.T) {
	a, fake := newTestAdapter(t)

	valid, err := json.Marshal(WebhookRequest{
		Action: "set", Zone: testZone, Type: "TXT",
		Records: []WebhookRecord{{Name: "_acme-challenge.node1", Type: "TXT", Value: "v1"}},
	})
	require.NoError(t, err)

	tests := []struct {
		name string
		path string
		body []byte
		auth string
		sig  string
		want int
	}{
		{"wrong token", "/set", valid, "Bearer nope", sign(valid, testSecret), http.StatusUnauthorized},
		{"no token", "/set", valid, "", sign(valid, testSecret), http.StatusUnauthorized},
		{"wrong signature", "/set", valid, "Bearer " + testToken, sign(valid, "nope"), http.StatusUnauthorized},
		{"no signature", "/set", valid, "Bearer " + testToken, "", http.StatusUnauthorized},
		{"action mismatch", "/delete", valid, "Bearer " + testToken, sign(valid, testSecret), http.StatusBadRequest},
		{"unknown path", "/other", valid, "Bearer " + testToken, sign(valid, testSecret), http.StatusNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, postRaw(t, a, tt.path, tt.body, tt.auth, tt.sig))
		})
	}

	txt, ops := fake.state(testHost)
	assert.Empty(t, txt)
	assert.Empty(t, ops)
	assert.Empty(t, a.Calls())
}

func TestWebhookAdapterZoneApex(t *testing.T) {
	a, fake := newTestAdapter(t)

	body, err := json.Marshal(WebhookRequest{
		Action: "set", Zone: "Example.COM", Type: "TXT",
		Records: []WebhookRecord{{Name: "@", Type: "TXT", Value: "apex"}},
	})
	require.NoError(t, err)

	require.Equal(t, http.StatusNoContent,
		postRaw(t, a, "/set", body, "Bearer "+testToken, sign(body, testSecret)))

	txt, _ := fake.state("example.com.")
	assert.Equal(t, []string{"apex"}, txt)
}
