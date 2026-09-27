package acmeic

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"
)

const webhookMaxBodyBytes = 64 * 1024

// WebhookRecord is one TXT record in a Headscale webhook request.
type WebhookRecord struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
	TTL   int64  `json:"ttl"`
}

// WebhookRequest is the body Headscale's "webhook" DNS provider POSTs, as
// documented in docs/ref/serve.md.
type WebhookRequest struct {
	Action  string          `json:"action"`
	Zone    string          `json:"zone"`
	Type    string          `json:"type"`
	Records []WebhookRecord `json:"records"`
}

// WebhookAdapter serves Headscale's webhook DNS provider contract and
// applies each call to pebble-challtestsrv.
//
// The contract and pebble-challtestsrv disagree on granularity: a "set"
// carries the complete TXT RRset for a name (libdns SetRecords semantics)
// and a "delete" carries only the values to remove, while
// pebble-challtestsrv can only append one value to a name (/set-txt) or
// drop every value of a name (/clear-txt). The adapter therefore keeps the
// RRset it last wrote per name. A set that only adds values appends them,
// so the values already published never disappear; any change that removes
// a value clears the name and writes back what remains, leaving the name
// briefly empty. Calls are serialised, so the adapter's view and
// pebble-challtestsrv never diverge while no call fails.
type WebhookAdapter struct {
	challTestSrvURL string
	authToken       string
	hmacSecret      string

	client   *http.Client
	listener net.Listener
	server   *http.Server

	mu sync.Mutex
	// rrsets is the TXT RRset last written per fully qualified name.
	rrsets map[string][]string
	// unknown holds names whose pebble-challtestsrv state is uncertain
	// after a failed call; the next write clears them first.
	unknown map[string]bool
	calls   []WebhookRequest
}

// NewWebhookAdapter listens on a free port on all interfaces. Requests
// must carry authToken as a bearer token and, when hmacSecret is set, a
// valid X-Headscale-Signature.
func NewWebhookAdapter(challTestSrvURL, authToken, hmacSecret string) (*WebhookAdapter, error) {
	listener, err := net.Listen("tcp", ":0") //nolint:gosec // must be reachable from the Headscale container
	if err != nil {
		return nil, fmt.Errorf("listening for webhook: %w", err)
	}

	a := &WebhookAdapter{
		challTestSrvURL: strings.TrimSuffix(challTestSrvURL, "/"),
		authToken:       authToken,
		hmacSecret:      hmacSecret,
		client:          &http.Client{Timeout: 5 * time.Second},
		listener:        listener,
		rrsets:          make(map[string][]string),
		unknown:         make(map[string]bool),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /set", a.handle("set"))
	mux.HandleFunc("POST /delete", a.handle("delete"))

	a.server = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		err := a.server.Serve(listener)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("webhook adapter stopped: %s", err)
		}
	}()

	return a, nil
}

// Port is the TCP port the adapter listens on.
func (a *WebhookAdapter) Port() int {
	return a.listener.Addr().(*net.TCPAddr).Port //nolint:forcetypeassert // net.Listen("tcp") always yields a TCPAddr
}

// Close stops the adapter.
func (a *WebhookAdapter) Close() error {
	return a.server.Close()
}

// Calls returns every request the adapter accepted, in order.
func (a *WebhookAdapter) Calls() []WebhookRequest {
	a.mu.Lock()
	defer a.mu.Unlock()

	return slices.Clone(a.calls)
}

// TXT returns the values the adapter last published for the fully
// qualified name (with or without a trailing dot).
func (a *WebhookAdapter) TXT(name string) []string {
	a.mu.Lock()
	defer a.mu.Unlock()

	return slices.Clone(a.rrsets[fqdn(name)])
}

func (a *WebhookAdapter) handle(action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, webhookMaxBodyBytes))
		if err != nil {
			http.Error(w, "reading body: "+err.Error(), http.StatusBadRequest)

			return
		}

		if !a.authorised(r, body) {
			http.Error(w, "unauthorised", http.StatusUnauthorized)

			return
		}

		var req WebhookRequest

		err = json.Unmarshal(body, &req)
		if err != nil {
			http.Error(w, "decoding body: "+err.Error(), http.StatusBadRequest)

			return
		}

		want, err := validate(action, req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)

			return
		}

		a.mu.Lock()
		defer a.mu.Unlock()

		for _, name := range slices.Sorted(maps.Keys(want)) {
			err := a.apply(r.Context(), action, name, want[name])
			if err != nil {
				log.Printf("webhook adapter: %s %s: %s", action, name, err)
				http.Error(w, err.Error(), http.StatusBadGateway)

				return
			}
		}

		a.calls = append(a.calls, req)
		w.WriteHeader(http.StatusNoContent)
	}
}

// authorised checks the bearer token and the HMAC signature of body.
func (a *WebhookAdapter) authorised(r *http.Request, body []byte) bool {
	if a.authToken != "" {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(got), []byte(a.authToken)) != 1 {
			return false
		}
	}

	if a.hmacSecret != "" {
		got, ok := strings.CutPrefix(r.Header.Get("X-Headscale-Signature"), "sha256=")
		if !ok {
			return false
		}

		sig, err := hex.DecodeString(got)
		if err != nil {
			return false
		}

		mac := hmac.New(sha256.New, []byte(a.hmacSecret))
		mac.Write(body)

		if !hmac.Equal(sig, mac.Sum(nil)) {
			return false
		}
	}

	return true
}

// validate checks req against the contract and returns its values grouped
// by fully qualified record name.
func validate(action string, req WebhookRequest) (map[string][]string, error) {
	if req.Action != action {
		return nil, fmt.Errorf("action %q sent to the %s endpoint", req.Action, action) //nolint:err113
	}

	if req.Type != "TXT" {
		return nil, fmt.Errorf("unsupported type %q", req.Type) //nolint:err113
	}

	if req.Zone == "" || strings.HasSuffix(req.Zone, ".") {
		return nil, fmt.Errorf("zone %q must be set and not end in a dot", req.Zone) //nolint:err113
	}

	if len(req.Records) == 0 {
		return nil, errors.New("no records") //nolint:err113
	}

	want := make(map[string][]string)

	for _, rec := range req.Records {
		if rec.Type != "TXT" || rec.Name == "" || rec.Value == "" {
			return nil, fmt.Errorf("invalid record %+v", rec) //nolint:err113
		}

		name := rec.Name + "." + req.Zone
		if rec.Name == "@" {
			name = req.Zone
		}

		name = fqdn(name)
		if !slices.Contains(want[name], rec.Value) {
			want[name] = append(want[name], rec.Value)
		}
	}

	return want, nil
}

// apply makes pebble-challtestsrv serve the RRset for name that results
// from action with values. The caller holds a.mu.
func (a *WebhookAdapter) apply(ctx context.Context, action, name string, values []string) error {
	have := a.rrsets[name]

	var next []string

	switch action {
	case "set":
		next = values
	case "delete":
		next = slices.DeleteFunc(slices.Clone(have), func(v string) bool {
			return slices.Contains(values, v)
		})
	}

	// pebble-challtestsrv cannot drop a single value, so removing any
	// value means starting the name over.
	clearFirst := a.unknown[name] ||
		slices.ContainsFunc(have, func(v string) bool { return !slices.Contains(next, v) })

	add := next

	if !clearFirst {
		add = slices.DeleteFunc(slices.Clone(next), func(v string) bool {
			return slices.Contains(have, v)
		})

		if len(add) == 0 {
			return nil
		}
	}

	// From here pebble-challtestsrv may be left part-way; if so the next
	// write for name starts from a clear.
	a.unknown[name] = true

	if clearFirst {
		err := a.challTestSrv(ctx, "/clear-txt", map[string]string{"host": name})
		if err != nil {
			return err
		}
	}

	for _, value := range add {
		err := a.challTestSrv(ctx, "/set-txt", map[string]string{"host": name, "value": value})
		if err != nil {
			return err
		}
	}

	delete(a.unknown, name)

	if len(next) == 0 {
		delete(a.rrsets, name)
	} else {
		a.rrsets[name] = slices.Clone(next)
	}

	return nil
}

func (a *WebhookAdapter) challTestSrv(ctx context.Context, path string, body map[string]string) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.challTestSrvURL+path, bytes.NewReader(payload))
	if err != nil {
		return err
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("pebble-challtestsrv %s: %w", path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))

		return fmt.Errorf("pebble-challtestsrv %s: %s: %s", path, resp.Status, msg) //nolint:err113
	}

	return nil
}

func fqdn(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, ".")) + "."
}
