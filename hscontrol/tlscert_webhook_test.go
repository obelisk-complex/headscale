package hscontrol

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libdns/libdns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// webhookTestRecords returns a single-value TXT RRset like the manager
// builds in tlscert.go's rrsetLocked.
func webhookTestRecords() []libdns.Record {
	return []libdns.Record{
		libdns.TXT{Name: "_acme-challenge.node1", TTL: 2 * time.Minute, Text: "challenge-value"},
	}
}

func newTestWebhookProvider(t *testing.T, setURL string, extra map[string]string) libdns.RecordSetter {
	t.Helper()

	raw := map[string]string{
		"set_url":       setURL,
		"insecure_http": "true",
		"timeout":       "2s",
		"max_retries":   "0",
	}
	for k, v := range extra {
		raw[k] = v
	}

	setter, err := newWebhookDNSProvider(raw)
	require.NoError(t, err)

	return setter
}

func TestWebhookSetRecordsRequestShape(t *testing.T) {
	t.Parallel()

	var gotBody webhookRequest

	var gotContentType string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotContentType = r.Header.Get("Content-Type")
		// assert, not require: t.FailNow (which require calls on failure) is
		// documented as unsafe from a goroutine other than the test's own,
		// and would abort this handler without writing a response.
		assert.NoError(t, json.NewDecoder(r.Body).Decode(&gotBody))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	setter := newTestWebhookProvider(t, server.URL, nil)

	records, err := setter.SetRecords(t.Context(), "example.com", webhookTestRecords())
	require.NoError(t, err)
	require.Equal(t, webhookTestRecords(), records)

	require.Equal(t, "application/json; charset=utf-8", gotContentType)
	require.Equal(t, "set", gotBody.Action)
	require.Equal(t, "example.com", gotBody.Zone)
	require.Equal(t, "TXT", gotBody.Type)
	require.Len(t, gotBody.Records, 1)
	require.Equal(t, "_acme-challenge.node1", gotBody.Records[0].Name)
	require.Equal(t, "TXT", gotBody.Records[0].Type)
	require.Equal(t, "challenge-value", gotBody.Records[0].Value)
	require.Equal(t, int64(120), gotBody.Records[0].TTL)
}

func TestWebhookAuthToken(t *testing.T) {
	t.Parallel()

	var gotAuth string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	setter := newTestWebhookProvider(t, server.URL, map[string]string{"auth_token": "s3cr3t"})

	_, err := setter.SetRecords(t.Context(), "example.com", webhookTestRecords())
	require.NoError(t, err)
	require.Equal(t, "Bearer s3cr3t", gotAuth)
}

func TestWebhookHMACSignature(t *testing.T) {
	t.Parallel()

	var gotSignature string

	var gotBody []byte

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSignature = r.Header.Get("X-Headscale-Signature")

		var err error
		gotBody, err = io.ReadAll(r.Body)
		assert.NoError(t, err)

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	setter := newTestWebhookProvider(t, server.URL, map[string]string{"hmac_secret": "shared-secret"})

	_, err := setter.SetRecords(t.Context(), "example.com", webhookTestRecords())
	require.NoError(t, err)

	mac := hmac.New(sha256.New, []byte("shared-secret"))
	mac.Write(gotBody)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	require.Equal(t, want, gotSignature)
}

func TestWebhookNon2xxReturnsError(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"zone not found"}`))
	}))
	defer server.Close()

	setter := newTestWebhookProvider(t, server.URL, nil)

	_, err := setter.SetRecords(t.Context(), "example.com", webhookTestRecords())
	require.Error(t, err)
	require.ErrorContains(t, err, "400")
	require.ErrorContains(t, err, "zone not found")
}

func TestWebhookErrorBodyIsTruncated(t *testing.T) {
	t.Parallel()

	huge := make([]byte, dnsWebhookErrorBodyLimit*4)
	for i := range huge {
		huge[i] = 'x'
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write(huge)
	}))
	defer server.Close()

	setter := newTestWebhookProvider(t, server.URL, nil)

	_, err := setter.SetRecords(t.Context(), "example.com", webhookTestRecords())
	require.Error(t, err)
	require.Less(t, len(err.Error()), len(huge))
	require.ErrorContains(t, err, "...(truncated)")
}

func TestWebhookRetriesOn5xxNotOn4xx(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		status       int
		wantAttempts int32
	}{
		{name: "server-error-retried", status: http.StatusInternalServerError, wantAttempts: 3},
		{name: "too-many-requests-retried", status: http.StatusTooManyRequests, wantAttempts: 3},
		{name: "bad-request-not-retried", status: http.StatusBadRequest, wantAttempts: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var attempts int32

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				atomic.AddInt32(&attempts, 1)
				w.WriteHeader(tt.status)
			}))
			defer server.Close()

			raw := map[string]string{
				"set_url":       server.URL,
				"insecure_http": "true",
				"timeout":       "2s",
				"max_retries":   "2",
			}

			setter, err := newWebhookDNSProvider(raw)
			require.NoError(t, err)

			_, err = setter.SetRecords(t.Context(), "example.com", webhookTestRecords())
			require.Error(t, err)
			require.Equal(t, tt.wantAttempts, atomic.LoadInt32(&attempts))
		})
	}
}

func TestWebhookTimeout(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	setter := newTestWebhookProvider(t, server.URL, map[string]string{"timeout": "20ms"})

	_, err := setter.SetRecords(t.Context(), "example.com", webhookTestRecords())
	require.Error(t, err)
}

func TestWebhookMalformedResponseBodyIgnoredOnSuccess(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not json at all {{{"))
	}))
	defer server.Close()

	setter := newTestWebhookProvider(t, server.URL, nil)

	_, err := setter.SetRecords(t.Context(), "example.com", webhookTestRecords())
	require.NoError(t, err)
}

func TestWebhookDeleteRecordsOptIn(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	t.Run("without delete_url", func(t *testing.T) {
		t.Parallel()

		setter := newTestWebhookProvider(t, server.URL, nil)
		_, ok := setter.(libdns.RecordDeleter)
		require.False(t, ok, "delete must not be advertised without delete_url")
	})

	t.Run("with delete_url", func(t *testing.T) {
		t.Parallel()

		var gotAction string

		deleteServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var body webhookRequest
			assert.NoError(t, json.NewDecoder(r.Body).Decode(&body))
			gotAction = body.Action
			w.WriteHeader(http.StatusOK)
		}))
		defer deleteServer.Close()

		setter := newTestWebhookProvider(t, server.URL, map[string]string{"delete_url": deleteServer.URL})

		deleter, ok := setter.(libdns.RecordDeleter)
		require.True(t, ok, "delete must be advertised when delete_url is set")

		_, err := deleter.DeleteRecords(t.Context(), "example.com", webhookTestRecords())
		require.NoError(t, err)
		require.Equal(t, "delete", gotAction)
	})
}

func TestWebhookURLValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		raw     map[string]string
		wantErr string
	}{
		{
			name:    "missing set_url",
			raw:     map[string]string{},
			wantErr: "set_url is required",
		},
		{
			name:    "http rejected by default",
			raw:     map[string]string{"set_url": "http://example.com/set"},
			wantErr: "insecure_http",
		},
		{
			name: "http allowed with insecure_http",
			raw: map[string]string{
				"set_url":       "http://example.com/set",
				"insecure_http": "true",
			},
		},
		{
			name:    "unsupported scheme",
			raw:     map[string]string{"set_url": "ftp://example.com/set"},
			wantErr: "unsupported scheme",
		},
		{
			name:    "invalid max_retries",
			raw:     map[string]string{"set_url": "https://example.com/set", "max_retries": "-1"},
			wantErr: "must not be negative",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := newWebhookDNSProvider(tt.raw)
			if tt.wantErr == "" {
				require.NoError(t, err)

				return
			}

			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestWebhookRefusesRedirectToDifferentHost(t *testing.T) {
	t.Parallel()

	var otherHits int32

	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&otherHits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer other.Close()

	redirecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/set", http.StatusTemporaryRedirect)
	}))
	defer redirecting.Close()

	setter := newTestWebhookProvider(t, redirecting.URL, map[string]string{"max_retries": "0"})

	_, err := setter.SetRecords(t.Context(), "example.com", webhookTestRecords())
	require.Error(t, err)
	require.ErrorContains(t, err, "different host")
	require.Zero(t, atomic.LoadInt32(&otherHits))
}

// TestWebhookRefusesMethodChangingRedirect checks that a 301/302/303, which
// Go's client would follow as a bodyless GET, fails the write instead of
// counting the GET's 2xx as the record having been set, and is not retried.
func TestWebhookRefusesMethodChangingRedirect(t *testing.T) {
	t.Parallel()

	for _, code := range []int{http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther} {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			t.Parallel()

			var redirects, targetHits int32

			var mux http.ServeMux

			mux.HandleFunc("/old", func(w http.ResponseWriter, r *http.Request) {
				atomic.AddInt32(&redirects, 1)
				http.Redirect(w, r, "/new", code)
			})
			mux.HandleFunc("/new", func(w http.ResponseWriter, r *http.Request) {
				atomic.AddInt32(&targetHits, 1)
				w.WriteHeader(http.StatusOK)
			})

			server := httptest.NewServer(&mux)
			defer server.Close()

			setter := newTestWebhookProvider(t, server.URL+"/old", map[string]string{"max_retries": "2"})

			_, err := setter.SetRecords(t.Context(), "example.com", webhookTestRecords())
			require.ErrorIs(t, err, errWebhookRedirect)
			require.ErrorContains(t, err, strconv.Itoa(code))
			require.Zero(t, atomic.LoadInt32(&targetHits), "redirect target must not be requested")
			require.Equal(t, int32(1), atomic.LoadInt32(&redirects), "a refused redirect is not retried")
		})
	}
}

func TestWebhookAllowsRedirectToSameHost(t *testing.T) {
	t.Parallel()

	var gotAction string

	var mux http.ServeMux

	mux.HandleFunc("/old", func(w http.ResponseWriter, r *http.Request) {
		// 307 preserves method and body, unlike 301/302/303 which would
		// downgrade this POST to a bodyless GET.
		http.Redirect(w, r, "/new", http.StatusTemporaryRedirect)
	})
	mux.HandleFunc("/new", func(w http.ResponseWriter, r *http.Request) {
		var body webhookRequest
		assert.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		gotAction = body.Action
		w.WriteHeader(http.StatusOK)
	})

	server := httptest.NewServer(&mux)
	defer server.Close()

	setter := newTestWebhookProvider(t, server.URL+"/old", nil)

	_, err := setter.SetRecords(t.Context(), "example.com", webhookTestRecords())
	require.NoError(t, err)
	require.Equal(t, "set", gotAction)
}

// TestWebhookRetryBackoffDoesNotExceedBudget guards against an unbounded or
// runaway backoff schedule.
func TestWebhookRetryBackoffDoesNotExceedBudget(t *testing.T) {
	t.Parallel()

	var attempts int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	raw := map[string]string{
		"set_url":       server.URL,
		"insecure_http": "true",
		"timeout":       "2s",
		"max_retries":   "3",
	}

	setter, err := newWebhookDNSProvider(raw)
	require.NoError(t, err)

	start := time.Now()
	_, err = setter.SetRecords(t.Context(), "example.com", webhookTestRecords())
	elapsed := time.Since(start)

	require.Error(t, err)
	require.Equal(t, int32(4), atomic.LoadInt32(&attempts))
	// Backoff schedule is 200ms, 400ms, 800ms = 1.4s; allow generous slack.
	require.Less(t, elapsed, 5*time.Second)
}
