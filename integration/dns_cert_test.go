package integration

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/juanfont/headscale/integration/acmeic"
	"github.com/juanfont/headscale/integration/dockertestutil"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/integrationutil"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/util/rands"
)

// TestDNSCertificatesServeHTTPS runs the whole `tailscale cert` /
// `tailscale serve --https` flow against Headscale: each node's tailscaled
// orders a certificate from Pebble, Headscale publishes the DNS-01 TXT record
// through its webhook provider into pebble-challtestsrv (via
// [acmeic.WebhookAdapter]), Pebble validates it and issues the certificate,
// and the other node fetches the served page over HTTPS, verifying the chain
// against Pebble's issuing root.
func TestDNSCertificatesServeHTTPS(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		NodesPerUser: 2,
		Users:        []string{"user1"},
	}

	scenario, err := NewScenario(spec)
	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	network := scenario.Networks()[0]

	acme, err := acmeic.New(scenario.Pool(), network)
	require.NoError(t, err)

	defer func() {
		if err := acme.Shutdown(); err != nil { //nolint:noinlineerr
			t.Logf("shutting down pebble: %s", err)
		}
	}()

	authToken := rands.HexString(32)
	hmacSecret := rands.HexString(32)

	adapter, err := acmeic.NewWebhookAdapter(acme.ChallTestSrvURL(), authToken, hmacSecret)
	require.NoError(t, err)

	defer func() { _ = adapter.Close() }()

	// The adapter runs in this process; Headscale reaches it through the
	// test suite container's address on the scenario network.
	suiteIP, err := dockertestutil.TestSuiteIPInNetwork(scenario.Pool(), network)
	require.NoError(t, err)

	webhookURL := "http://" + net.JoinHostPort(suiteIP, strconv.Itoa(adapter.Port()))

	// propagation_check is off: it looks up the zone's NS records in public
	// DNS, and pebble-challtestsrv is not delegated there. It serves a
	// record as soon as the webhook call returns, so no wait is needed.
	certConfig := fmt.Sprintf(`
dns:
  certificates:
    enabled: true
    provider: webhook
    ttl: 60s
    propagation_check: false
    propagation_wait: 0s
    provider_config:
      set_url: %[1]s/set
      delete_url: %[1]s/delete
      insecure_http: "true"
      auth_token_env: DNS_WEBHOOK_AUTH_TOKEN
      hmac_secret: %[2]s
      timeout: 5s
`, webhookURL, hmacSecret)

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{
			tsic.WithEnv("TS_DEBUG_ACME_DIRECTORY_URL=" + acme.DirectoryURL()),
			tsic.WithCACert(acme.TLSRoot()),
			tsic.WithExtraHosts([]string{acme.ExtraHost()}),
			// The tailscale images ship without curl.
			tsic.WithPackages("curl"),
		},
		hsic.WithTestName("dnscert"),
		hsic.WithConfigYAML(certConfig),
		hsic.WithConfigEnv(map[string]string{"DNS_WEBHOOK_AUTH_TOKEN": authToken}),
	)
	requireNoErrHeadscaleEnv(t, err)

	allClients, err := scenario.ListTailscaleClients()
	requireNoErrListClients(t, err)
	require.Len(t, allClients, 2)

	err = scenario.WaitForTailscaleSync()
	requireNoErrSync(t, err)

	issuerRootPEM, err := acme.IssuerRoot()
	require.NoError(t, err)

	issuerRoots := x509.NewCertPool()
	require.True(t, issuerRoots.AppendCertsFromPEM(issuerRootPEM), "pebble issuer root is not PEM")

	const issuerRootPath = "/tmp/pebble-issuer-root.pem"

	type served struct {
		fqdn string
		ip   string
		body string
	}

	var servers []served

	for _, client := range allClients {
		fqdn := strings.TrimSuffix(client.MustFQDN(), ".")

		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			status, err := client.Status()
			assert.NoError(c, err)
			assert.Contains(c, status.CertDomains, fqdn, "node should be offered a certificate for its FQDN")
			assert.True(c, status.Self.HasCap(nodecap.HTTPS), "node should carry the https capability")
		}, integrationutil.StatusReadyTimeout, 1*time.Second, "waiting for %s to see certificate support", fqdn)

		// Issue the certificate explicitly first: serve would otherwise
		// order it during the first TLS handshake, which curl would time
		// out on.
		certPath := "/tmp/" + fqdn + ".crt"
		_, stderr, err := client.Execute(
			[]string{
				"tailscale", "cert",
				"--cert-file", certPath,
				"--key-file", "/tmp/" + fqdn + ".key",
				fqdn,
			},
			dockertestutil.ExecuteCommandTimeout(integrationutil.ScaledTimeout(2*time.Minute)),
		)
		require.NoError(t, err, "tailscale cert %s failed: %s", fqdn, stderr)

		certPEM, err := client.ReadFile(certPath)
		require.NoError(t, err)
		requireCertIssuedFor(t, certPEM, fqdn, issuerRoots)

		challengeName := "_acme-challenge." + strings.TrimSuffix(fqdn, ".headscale.net")
		assert.True(t, slices.ContainsFunc(adapter.Calls(), func(req acmeic.WebhookRequest) bool {
			return req.Action == "set" && req.Zone == "headscale.net" &&
				slices.ContainsFunc(req.Records, func(r acmeic.WebhookRecord) bool {
					return r.Name == challengeName && r.TTL == 60
				})
		}), "webhook should have received a set for %s", challengeName)
		assert.NotEmpty(t, adapter.TXT("_acme-challenge."+fqdn),
			"challenge record should stay published until its retention expires")

		body := "hello-from-" + client.Hostname()
		_, stderr, err = client.Execute([]string{
			"tailscale", "serve", "--bg", "--yes", "--https=443", "text:" + body,
		})
		require.NoError(t, err, "tailscale serve on %s failed: %s", fqdn, stderr)

		servers = append(servers, served{fqdn: fqdn, ip: client.MustIPv4().String(), body: body})
	}

	for i, client := range allClients {
		target := servers[(i+1)%len(servers)]

		// TailscaleClient has no WriteFile; PEM holds no single quotes.
		_, stderr, err := client.Execute([]string{
			"sh", "-c", fmt.Sprintf("printf '%%s' '%s' > %s", issuerRootPEM, issuerRootPath),
		})
		require.NoError(t, err, "writing issuer root on %s: %s", client.Hostname(), stderr)

		// --resolve pins the tailnet address so the check does not depend
		// on MagicDNS; the certificate is still verified for the FQDN.
		curl := []string{
			"curl", "--silent", "--show-error", "--fail", "--max-time", "5",
			"--resolve", target.fqdn + ":443:" + target.ip,
			"https://" + target.fqdn + "/",
		}

		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			out, stderr, err := client.Execute(slices.Insert(slices.Clone(curl), 1, "--cacert", issuerRootPath))
			assert.NoError(c, err, "curl stderr: %s", stderr)
			assert.Equal(c, target.body, strings.TrimSpace(out))
		}, integrationutil.ScaledTimeout(60*time.Second), 2*time.Second,
			"%s should fetch https://%s/ with a certificate chaining to Pebble's root", client.Hostname(), target.fqdn)

		// Negative control: without Pebble's issuing root the same request
		// must fail verification, so the success above was a real check.
		_, stderr, err = client.Execute(curl)
		require.Error(t, err, "curl without the issuer root should fail certificate verification")
		assert.Contains(t, stderr, "certificate", "curl should fail on the certificate, not on connectivity")
	}
}

// requireCertIssuedFor checks that certPEM is a chain for fqdn that
// verifies against roots.
func requireCertIssuedFor(t *testing.T, certPEM []byte, fqdn string, roots *x509.CertPool) {
	t.Helper()

	var chain []*x509.Certificate

	for rest := certPEM; ; {
		var block *pem.Block

		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		require.NoError(t, err)

		chain = append(chain, cert)
	}

	require.NotEmpty(t, chain, "certificate file holds no certificates")

	intermediates := x509.NewCertPool()
	for _, cert := range chain[1:] {
		intermediates.AddCert(cert)
	}

	_, err := chain[0].Verify(x509.VerifyOptions{
		DNSName:       fqdn,
		Roots:         roots,
		Intermediates: intermediates,
	})
	require.NoError(t, err, "certificate for %s does not verify against Pebble's issuer root", fqdn)
}
