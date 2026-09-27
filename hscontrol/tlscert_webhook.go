package hscontrol

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/libdns/libdns"
)

// webhookProviderName is the DNS certificate provider name operators set as
// dns.certificates.provider to use this package. See docs/ref/serve.md for
// the full request/response contract.
const webhookProviderName = "webhook"

const (
	dnsWebhookDefaultTimeout    = 10 * time.Second
	dnsWebhookDefaultMaxRetries = 2
	dnsWebhookRetryBackoff      = 200 * time.Millisecond
	dnsWebhookMaxRetryBackoff   = 2 * time.Second

	// dnsWebhookMaxResponseBytes bounds how much of a webhook response body
	// is ever read into memory, regardless of what the response declares.
	dnsWebhookMaxResponseBytes = 8 * 1024

	// dnsWebhookErrorBodyLimit further truncates the response body embedded
	// in an error: the error is logged server-side only (see
	// noiseServer.SetDNSHandler, which never returns provider error detail
	// to the calling node), but an operator's webhook is arbitrary code and
	// a runaway or secret-echoing error page should not grow the log
	// without bound.
	dnsWebhookErrorBodyLimit = 512

	// dnsWebhookMaxRedirects bounds how many redirects the client follows.
	dnsWebhookMaxRedirects = 3
)

func init() {
	if err := RegisterDNSCertificateProvider(webhookProviderName, newWebhookDNSProvider); err != nil {
		// Only reachable if something else already registered "webhook",
		// which is a build-time programming error, not a runtime condition.
		panic("hscontrol: " + err.Error())
	}
}

// webhookConfig is dns.certificates.provider_config parsed for the "webhook"
// provider.
type webhookConfig struct {
	setURL     *url.URL
	deleteURL  *url.URL // nil when delete_url is not configured
	authToken  string
	hmacSecret string
	timeout    time.Duration
	maxRetries int
}

// newWebhookDNSProvider builds the generic HTTP webhook DNS provider: it
// lets an operator (or an integration test) point Headscale at any DNS
// backend that speaks the small JSON contract documented in
// docs/ref/serve.md, without Headscale needing a built-in client for that
// backend.
func newWebhookDNSProvider(raw map[string]string) (libdns.RecordSetter, error) {
	cfg, err := parseWebhookConfig(raw)
	if err != nil {
		return nil, fmt.Errorf("webhook DNS provider: %w", err)
	}

	client := &http.Client{
		Timeout:       cfg.timeout,
		CheckRedirect: webhookCheckRedirect,
	}

	provider := &webhookProvider{cfg: cfg, client: client}

	// DeleteRecords is opt-in: only expose it (so the manager's
	// setter.(libdns.RecordDeleter) type assertion succeeds) when the
	// operator configured a delete_url.
	if cfg.deleteURL == nil {
		return provider, nil
	}

	return &webhookDeleterProvider{webhookProvider: provider}, nil
}

func parseWebhookConfig(raw map[string]string) (webhookConfig, error) {
	insecureHTTP, err := webhookConfigBool(raw, "insecure_http", false)
	if err != nil {
		return webhookConfig{}, err
	}

	setURLRaw := raw["set_url"]
	if setURLRaw == "" {
		return webhookConfig{}, errors.New("set_url is required")
	}

	setURL, err := validateWebhookURL("set_url", setURLRaw, insecureHTTP)
	if err != nil {
		return webhookConfig{}, err
	}

	var deleteURL *url.URL

	if deleteURLRaw := raw["delete_url"]; deleteURLRaw != "" {
		deleteURL, err = validateWebhookURL("delete_url", deleteURLRaw, insecureHTTP)
		if err != nil {
			return webhookConfig{}, err
		}
	}

	timeout, err := webhookConfigDuration(raw, "timeout", dnsWebhookDefaultTimeout)
	if err != nil {
		return webhookConfig{}, err
	}

	maxRetries, err := webhookConfigInt(raw, "max_retries", dnsWebhookDefaultMaxRetries)
	if err != nil {
		return webhookConfig{}, err
	}

	if maxRetries < 0 {
		return webhookConfig{}, errors.New("max_retries must not be negative")
	}

	return webhookConfig{
		setURL:     setURL,
		deleteURL:  deleteURL,
		authToken:  raw["auth_token"],
		hmacSecret: raw["hmac_secret"],
		timeout:    timeout,
		maxRetries: maxRetries,
	}, nil
}

// validateWebhookURL restricts a configured webhook URL to https, unless
// insecureHTTP allows http for local or test use. This is the operator's own
// configuration, not attacker-controlled input, but a sane default still
// avoids sending challenge values in the clear by accident.
func validateWebhookURL(key, raw string, insecureHTTP bool) (*url.URL, error) {
	target, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", key, err)
	}

	switch target.Scheme {
	case "https":
	case "http":
		if !insecureHTTP {
			return nil, fmt.Errorf(
				"%s: %q uses http, set insecure_http: \"true\" to allow this (local/test use only)",
				key, raw,
			)
		}
	default:
		return nil, fmt.Errorf("%s: unsupported scheme %q, want https", key, target.Scheme)
	}

	if target.Host == "" {
		return nil, fmt.Errorf("%s: missing host: %s", key, raw)
	}

	return target, nil
}

func webhookConfigBool(raw map[string]string, key string, def bool) (bool, error) {
	value, ok := raw[key]
	if !ok || value == "" {
		return def, nil
	}

	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("%s: %w", key, err)
	}

	return parsed, nil
}

func webhookConfigDuration(raw map[string]string, key string, def time.Duration) (time.Duration, error) {
	value, ok := raw[key]
	if !ok || value == "" {
		return def, nil
	}

	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}

	if parsed <= 0 {
		return 0, fmt.Errorf("%s must be positive", key)
	}

	return parsed, nil
}

func webhookConfigInt(raw map[string]string, key string, def int) (int, error) {
	value, ok := raw[key]
	if !ok || value == "" {
		return def, nil
	}

	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}

	return parsed, nil
}

// webhookProvider implements libdns.RecordSetter by POSTing the RRset to a
// configured HTTP endpoint.
type webhookProvider struct {
	cfg    webhookConfig
	client *http.Client
}

// webhookCheckRedirect allows a webhook to redirect only to the same host it
// was called on, and never downgrades https to http. The webhook target is
// operator-configured rather than attacker-controlled, but a redirect
// followed blindly would let a compromised or misconfigured webhook send
// Headscale's auth token or HMAC-signed body to an arbitrary host.
func webhookCheckRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= dnsWebhookMaxRedirects {
		return fmt.Errorf("webhook: stopped after %d redirects", dnsWebhookMaxRedirects)
	}

	first := via[0].URL
	if req.URL.Host != first.Host {
		return fmt.Errorf("webhook: refusing to follow redirect to different host %q", req.URL.Host)
	}

	if first.Scheme == "https" && req.URL.Scheme != "https" {
		return errors.New("webhook: refusing to follow redirect from https to a non-https URL")
	}

	return nil
}

func (p *webhookProvider) SetRecords(
	ctx context.Context,
	zone string,
	records []libdns.Record,
) ([]libdns.Record, error) {
	if err := p.send(ctx, "set", p.cfg.setURL, zone, records); err != nil {
		return nil, err
	}

	return records, nil
}

// webhookDeleterProvider adds DeleteRecords. It is a distinct type, rather
// than webhookProvider always implementing the method, so the manager's
// setter.(libdns.RecordDeleter) assertion only succeeds when the operator
// configured delete_url: a webhook backend that cannot delete is not forced
// to implement one.
type webhookDeleterProvider struct {
	*webhookProvider
}

func (p *webhookDeleterProvider) DeleteRecords(
	ctx context.Context,
	zone string,
	records []libdns.Record,
) ([]libdns.Record, error) {
	if err := p.send(ctx, "delete", p.cfg.deleteURL, zone, records); err != nil {
		return nil, err
	}

	return records, nil
}

// send posts action's records to target. Transient failures (transport
// errors, HTTP 429, and 5xx) are retried with exponential backoff up to
// cfg.maxRetries times; any other non-2xx response is returned immediately.
func (p *webhookProvider) send(
	ctx context.Context,
	action string,
	target *url.URL,
	zone string,
	records []libdns.Record,
) error {
	body, err := webhookEncodeRequest(action, zone, records)
	if err != nil {
		return fmt.Errorf("webhook %s: encoding request: %w", action, err)
	}

	var lastErr error

	backoff := dnsWebhookRetryBackoff

	for attempt := 0; attempt <= p.cfg.maxRetries; attempt++ {
		if attempt > 0 {
			if err := sleepCtx(ctx, backoff); err != nil {
				return err
			}

			backoff = min(backoff*2, dnsWebhookMaxRetryBackoff)
		}

		lastErr = p.attempt(ctx, action, target, body)
		if lastErr == nil {
			return nil
		}

		if !isWebhookRetryable(lastErr) {
			return lastErr
		}
	}

	return fmt.Errorf(
		"webhook %s: giving up after %d attempts: %w",
		action, p.cfg.maxRetries+1, lastErr,
	)
}

func (p *webhookProvider) attempt(
	ctx context.Context,
	action string,
	target *url.URL,
	body []byte,
) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("webhook %s: building request: %w", action, err)
	}

	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	if p.cfg.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+p.cfg.authToken)
	}

	if p.cfg.hmacSecret != "" {
		mac := hmac.New(sha256.New, []byte(p.cfg.hmacSecret))
		mac.Write(body)
		req.Header.Set("X-Headscale-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook %s: %w", action, err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, dnsWebhookMaxResponseBytes))

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &webhookStatusError{
			action: action,
			code:   resp.StatusCode,
			body:   truncateWebhookBody(respBody),
		}
	}

	return nil
}

// webhookStatusError is a non-2xx webhook response.
type webhookStatusError struct {
	action string
	code   int
	body   string
}

func (e *webhookStatusError) Error() string {
	if e.body == "" {
		return fmt.Sprintf("webhook %s returned %d", e.action, e.code)
	}

	return fmt.Sprintf("webhook %s returned %d: %s", e.action, e.code, e.body)
}

func (e *webhookStatusError) retryable() bool {
	return e.code == http.StatusTooManyRequests || e.code >= http.StatusInternalServerError
}

func isWebhookRetryable(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	var statusErr *webhookStatusError
	if errors.As(err, &statusErr) {
		return statusErr.retryable()
	}

	// Anything else here is a transport-level failure (dial, TLS, connection
	// reset); those are transient by nature.
	return true
}

// truncateWebhookBody bounds how much of a response body is embedded in an
// error, on top of the dnsWebhookMaxResponseBytes cap already applied when
// reading it.
func truncateWebhookBody(body []byte) string {
	text := strings.TrimSpace(string(body))
	if len(text) > dnsWebhookErrorBodyLimit {
		text = text[:dnsWebhookErrorBodyLimit] + "...(truncated)"
	}

	return text
}

// webhookRecord is one TXT record in the JSON request body. See
// docs/ref/serve.md for the full contract.
type webhookRecord struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
	TTL   int64  `json:"ttl"`
}

// webhookRequest is the JSON body POSTed to set_url/delete_url.
type webhookRequest struct {
	Action  string          `json:"action"`
	Zone    string          `json:"zone"`
	Type    string          `json:"type"`
	Records []webhookRecord `json:"records"`
}

func webhookEncodeRequest(action, zone string, records []libdns.Record) ([]byte, error) {
	req := webhookRequest{
		Action:  action,
		Zone:    zone,
		Type:    "TXT",
		Records: make([]webhookRecord, 0, len(records)),
	}

	for _, record := range records {
		rr := record.RR()
		req.Records = append(req.Records, webhookRecord{
			Name:  rr.Name,
			Type:  rr.Type,
			Value: rr.Data,
			TTL:   int64(rr.TTL.Round(time.Second).Seconds()),
		})
	}

	return json.Marshal(req)
}
