// Package acmeic runs a test ACME CA for integration tests: Pebble, Let's
// Encrypt's test CA, validating DNS-01 challenges against
// pebble-challtestsrv, a test DNS server whose records are set over HTTP.
//
// Headscale writes challenge records through its "webhook" DNS provider;
// [WebhookAdapter] translates those calls into pebble-challtestsrv's API.
//
// ACME clients do not talk to Pebble directly but to a TLS proxy in the
// test process; see [ACMEInContainer.ExtraHost].
package acmeic

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/juanfont/headscale/integration/dockertestutil"
	"github.com/juanfont/headscale/integration/integrationutil"
	"github.com/ory/dockertest/v3"
	"tailscale.com/util/rands"
)

const (
	pebbleRepository       = "ghcr.io/letsencrypt/pebble"
	challTestSrvRepository = "ghcr.io/letsencrypt/pebble-challtestsrv"
	pebbleVersion          = "2.10.1"

	// PebbleHostname is the name Pebble's bundled TLS certificate is
	// issued for. ACME clients must reach Pebble by this name; see
	// [ACMEInContainer.ExtraHost].
	PebbleHostname = "pebble"

	pebbleACMEPort       = 14000
	pebbleManagementPort = 15000
	challTestSrvDNSPort  = 8053
	challTestSrvAPIPort  = 8055

	// pebbleTLSRootPath is the root that signs Pebble's own HTTPS
	// certificate, shipped in the image. It is not the root of the
	// certificates Pebble issues; see [ACMEInContainer.IssuerRoot].
	pebbleTLSRootPath = "/test/certs/pebble.minica.pem"

	// Pebble's own HTTPS certificate and key, issued for [PebbleHostname];
	// the proxy presents them so clients see the same server identity.
	pebbleTLSCertPath = "/test/certs/localhost/cert.pem"
	pebbleTLSKeyPath  = "/test/certs/localhost/key.pem"

	pebbleOrderPath    = "/my-order/"
	pebbleFinalizePath = "/finalize-order/"

	acmeicHashLength = 6
	logDir           = "/tmp/control"
)

var errNotReady = errors.New("not ready")

// ACMEInContainer is a Pebble ACME server and the pebble-challtestsrv DNS
// server it validates DNS-01 challenges against.
type ACMEInContainer struct {
	pool         *dockertest.Pool
	pebble       *dockertest.Resource
	challTestSrv *dockertest.Resource

	pebbleIP       string
	challTestSrvIP string
	tlsRoot        []byte

	suiteIP string
	proxy   *http.Server
	proxyLn net.Listener
}

// New starts pebble-challtestsrv and Pebble on network, and the proxy in
// front of Pebble, and waits until they answer.
func New(pool *dockertest.Pool, network *dockertest.Network) (*ACMEInContainer, error) {
	hash := rands.HexString(acmeicHashLength)
	a := &ACMEInContainer{pool: pool}

	for _, repo := range []string{challTestSrvRepository, pebbleRepository} {
		err := dockertestutil.PullWithAuth(pool, repo+":"+pebbleVersion)
		if err != nil {
			log.Printf("pull failed for %s:%s, relying on a local image: %s", repo, pebbleVersion, err)
		}
	}

	challOpts := &dockertest.RunOptions{
		Name:       "challtestsrv-" + hash,
		Repository: challTestSrvRepository,
		Tag:        pebbleVersion,
		Networks:   []*dockertest.Network{network},
		// Only DNS and the management API; the HTTP-01, TLS-ALPN-01 and
		// DoH listeners are not needed. A queries for unknown names get
		// no answer rather than challtestsrv's 127.0.0.1 default.
		Cmd: []string{
			"-dnsserver", ":" + strconv.Itoa(challTestSrvDNSPort),
			"-management", ":" + strconv.Itoa(challTestSrvAPIPort),
			"-http01", "",
			"-https01", "",
			"-tlsalpn01", "",
			"-doh", "",
			"-defaultIPv4", "",
			"-defaultIPv6", "",
		},
	}
	dockertestutil.DockerAddIntegrationLabels(challOpts, "challtestsrv")

	var err error

	a.challTestSrv, err = pool.RunWithOptions(challOpts, dockertestutil.DockerRestartPolicy)
	if err != nil {
		return nil, fmt.Errorf("starting pebble-challtestsrv: %w", err)
	}

	a.challTestSrvIP = a.challTestSrv.GetIPInNetwork(network)

	err = pool.Retry(func() error {
		return a.challTestSrvReady()
	})
	if err != nil {
		_ = a.Shutdown()

		return nil, fmt.Errorf("waiting for pebble-challtestsrv: %w", err)
	}

	pebbleOpts := &dockertest.RunOptions{
		Name:       "pebble-" + hash,
		Repository: pebbleRepository,
		Tag:        pebbleVersion,
		Networks:   []*dockertest.Network{network},
		Cmd: []string{
			"-config", "/test/config/pebble-config.json",
			"-dnsserver", net.JoinHostPort(a.challTestSrvIP, strconv.Itoa(challTestSrvDNSPort)),
		},
		Env: []string{
			// Validate as soon as the client asks instead of after a
			// random delay of up to 15s.
			"PEBBLE_VA_NOSLEEP=1",
			// Pebble rejects 5% of valid nonces by default to exercise
			// client retries; the client is not under test here.
			"PEBBLE_WFE_NONCEREJECT=0",
		},
	}
	dockertestutil.DockerAddIntegrationLabels(pebbleOpts, "pebble")

	a.pebble, err = pool.RunWithOptions(pebbleOpts, dockertestutil.DockerRestartPolicy)
	if err != nil {
		_ = a.Shutdown()

		return nil, fmt.Errorf("starting pebble: %w", err)
	}

	a.pebbleIP = a.pebble.GetIPInNetwork(network)

	a.tlsRoot, err = readFileFromContainer(pool, a.pebble, pebbleTLSRootPath)
	if err != nil {
		_ = a.Shutdown()

		return nil, fmt.Errorf("reading pebble TLS root: %w", err)
	}

	err = pool.Retry(func() error {
		_, err := a.pebbleGet(pebbleACMEPort, "/dir")

		return err
	})
	if err != nil {
		_ = a.Shutdown()

		return nil, fmt.Errorf("waiting for pebble: %w", err)
	}

	err = a.startProxy(network)
	if err != nil {
		_ = a.Shutdown()

		return nil, fmt.Errorf("starting pebble proxy: %w", err)
	}

	log.Printf("pebble ACME server ready at %s (pebble %s, proxy %s), challtestsrv at %s",
		a.DirectoryURL(), a.pebbleIP, a.suiteIP, a.ChallTestSrvURL())

	return a, nil
}

// DirectoryURL is the ACME directory URL, for TS_DEBUG_ACME_DIRECTORY_URL.
// It points at the proxy.
func (a *ACMEInContainer) DirectoryURL() string {
	return "https://" + net.JoinHostPort(PebbleHostname, strconv.Itoa(a.proxyPort())) + "/dir"
}

// ExtraHost maps [PebbleHostname] to the proxy's address, in the "name:ip"
// form of a container's extra /etc/hosts entries.
func (a *ACMEInContainer) ExtraHost() string {
	return PebbleHostname + ":" + a.suiteIP
}

func (a *ACMEInContainer) proxyPort() int {
	return a.proxyLn.Addr().(*net.TCPAddr).Port //nolint:forcetypeassert // net.Listen("tcp") always yields a TCPAddr
}

// startProxy serves Pebble's ACME API from the test process, adding the
// Location header Pebble leaves off finalize responses.
//
// Pebble always answers finalize with status "processing" and issues the
// certificate in the background. RFC 8555 section 7.4 has the client poll
// the order URL until it is "valid", and Pebble sends no Location header
// with the finalize response. Tailscale's ACME client
// (tailscale.com/tempfork/acme, CreateOrderCert) takes the order URL to
// poll from that header only, so it polls "" and fails with
// `Post "": unsupported protocol scheme ""`.
//
// The proxy keeps the client's Host header so the URLs Pebble puts in its
// responses lead back through the proxy.
func (a *ACMEInContainer) startProxy(network *dockertest.Network) error {
	var err error

	a.suiteIP, err = dockertestutil.TestSuiteIPInNetwork(a.pool, network)
	if err != nil {
		return err
	}

	certPEM, err := readFileFromContainer(a.pool, a.pebble, pebbleTLSCertPath)
	if err != nil {
		return err
	}

	keyPEM, err := readFileFromContainer(a.pool, a.pebble, pebbleTLSKeyPath)
	if err != nil {
		return err
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("loading pebble TLS certificate: %w", err)
	}

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(a.tlsRoot) {
		return errors.New("pebble TLS root is not a PEM certificate") //nolint:err113
	}

	target := &url.URL{
		Scheme: "https",
		Host:   net.JoinHostPort(a.pebbleIP, strconv.Itoa(pebbleACMEPort)),
	}

	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)
			r.Out.Host = r.In.Host
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    roots,
				ServerName: PebbleHostname,
				MinVersion: tls.VersionTLS12,
			},
		},
		ModifyResponse: func(resp *http.Response) error {
			id, ok := strings.CutPrefix(resp.Request.URL.Path, pebbleFinalizePath)
			if ok && resp.StatusCode == http.StatusOK && resp.Header.Get("Location") == "" {
				resp.Header.Set("Location", "https://"+resp.Request.Host+pebbleOrderPath+id)
			}

			return nil
		},
	}

	a.proxyLn, err = net.Listen("tcp", ":0") //nolint:gosec // must be reachable from the Tailscale containers
	if err != nil {
		return err
	}

	a.proxy = &http.Server{
		Handler:           proxy,
		ReadHeaderTimeout: 5 * time.Second,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		},
	}

	go func() {
		err := a.proxy.ServeTLS(a.proxyLn, "", "")
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("pebble proxy stopped: %s", err)
		}
	}()

	return nil
}

// TLSRoot returns the PEM root an ACME client must trust to talk to
// Pebble over HTTPS.
func (a *ACMEInContainer) TLSRoot() []byte {
	return a.tlsRoot
}

// ChallTestSrvURL is the base URL of pebble-challtestsrv's management API.
func (a *ACMEInContainer) ChallTestSrvURL() string {
	return "http://" + net.JoinHostPort(a.challTestSrvIP, strconv.Itoa(challTestSrvAPIPort))
}

// IssuerRoot returns the PEM root of the certificates Pebble issues. Pebble
// generates it at startup, so it differs on every run.
func (a *ACMEInContainer) IssuerRoot() ([]byte, error) {
	return a.pebbleGet(pebbleManagementPort, "/roots/0")
}

// Shutdown stops the proxy, saves both containers' logs and removes them.
func (a *ACMEInContainer) Shutdown() error {
	var errs []error

	if a.proxy != nil {
		errs = append(errs, a.proxy.Close())
	} else if a.proxyLn != nil {
		errs = append(errs, a.proxyLn.Close())
	}

	for _, r := range []*dockertest.Resource{a.pebble, a.challTestSrv} {
		if r == nil {
			continue
		}

		_, _, err := dockertestutil.SaveLog(a.pool, r, logDir)
		if err != nil {
			log.Printf("saving log from %s: %s", r.Container.Name, err)
		}

		errs = append(errs, a.pool.Purge(r))
	}

	return errors.Join(errs...)
}

func (a *ACMEInContainer) challTestSrvReady() error {
	// The management API has no health endpoint; any HTTP answer means
	// it is listening.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.ChallTestSrvURL()+"/", nil)
	if err != nil {
		return err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}

	return resp.Body.Close()
}

// pebbleGet fetches path from one of Pebble's HTTPS listeners, verifying
// its certificate against the bundled TLS root.
func (a *ACMEInContainer) pebbleGet(port int, path string) ([]byte, error) {
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(a.tlsRoot) {
		return nil, errors.New("pebble TLS root is not a PEM certificate") //nolint:err113
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    roots,
				ServerName: PebbleHostname,
				MinVersion: tls.VersionTLS12,
			},
		},
	}
	defer client.CloseIdleConnections()

	url := "https://" + net.JoinHostPort(a.pebbleIP, strconv.Itoa(port)) + path

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: GET %s: %s", errNotReady, url, resp.Status)
	}

	return body, nil
}

// readFileFromContainer copies one file out of a container. It works on
// images without a shell, which Pebble's are.
func readFileFromContainer(
	pool *dockertest.Pool,
	resource *dockertest.Resource,
	path string,
) ([]byte, error) {
	tarBytes, err := integrationutil.FetchPathFromContainer(pool, resource, path)
	if err != nil {
		return nil, err
	}

	tr := tar.NewReader(bytes.NewReader(tarBytes))

	_, err = tr.Next()
	if err != nil {
		return nil, fmt.Errorf("reading %s from tar: %w", path, err)
	}

	return io.ReadAll(tr)
}
