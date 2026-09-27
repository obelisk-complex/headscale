# Tailscale Serve and certificates

[Tailscale Serve](https://tailscale.com/docs/features/tailscale-serve) is a
client-side feature: the Serve configuration and TLS private keys live on the
node, not on Headscale.

Plain HTTP Serve works with MagicDNS. HTTPS Serve and `tailscale cert` require
Headscale to advertise the node's MagicDNS name as certificate-eligible and to
publish ACME DNS-01 TXT challenge records for the node.

## Certificate flow

1. Headscale advertises the node's FQDN in `DNSConfig.CertDomains`.
   This is the client signal that avoids:

   ```console
   HTTPS cert support is not enabled/configured for your tailnet.
   ```

2. The node runs `tailscale cert <node>.<base_domain>` or
   `tailscale serve --https`.
3. The node starts an ACME order locally. Headscale never sees the ACME account
   key, certificate private key, or issued certificate.
4. The node calls Headscale's Noise endpoint `/machine/set-dns` with a
   `TXT` record for `_acme-challenge.<node>.<base_domain>`.
5. Headscale validates that the Noise machine key owns the node key and that
   the requested TXT name belongs to that node's own FQDN.
6. Headscale publishes the TXT RRset through the configured `libdns`
   `RecordSetter`.
7. Headscale waits until every authoritative name server of the zone serves
   the new value (see [Propagation](#propagation)), then answers the node.
8. The client asks the ACME CA to validate DNS-01 and stores the issued
   certificate locally.

## Configuration

```yaml
dns:
  magic_dns: true
  base_domain: example.com

  certificates:
    enabled: true
    provider: "provider-name"
    zone: "example.com"
    ttl: 2m
    propagation_check: true
    propagation_timeout: 90s
    propagation_wait: 0s
    provider_config:
      token_path: /run/secrets/dns_provider_token
```

`dns.certificates.enabled` requires:

- `dns.magic_dns: true`
- `dns.base_domain` set
- `dns.certificates.provider` set
- a Headscale build that registers a matching `libdns` provider factory

`zone` defaults to `dns.base_domain` when empty, and must contain
`dns.base_domain`.

`provider_config` usually carries API credentials. Rather than writing them
into the configuration file, give any key as:

- `<key>_path`: a file holding the value (for example a systemd credential or
  container secret). Environment variables in the path are expanded and
  surrounding whitespace is trimmed, as for `oidc.client_secret_path`.
- `<key>_env`: the name of an environment variable holding the value.

Headscale resolves these at startup and hands the provider `<key>`; setting a
key in more than one form is a configuration error. As a consequence a provider
cannot receive a key that itself ends in `_path` or `_env`. `provider_config`
values are omitted from JSON output and redacted from
`HEADSCALE_DEBUG_DUMP_CONFIG` dumps.

## Propagation

tailscaled asks the ACME CA to validate the challenge as soon as
`/machine/set-dns` returns. If the CA queries a name server that has not yet
received the record, validation fails and the certificate is not issued.

With `propagation_check: true` (the default) Headscale:

1. finds the zone cut for `_acme-challenge.<node>.<base_domain>` by looking up
   NS records from that name upwards until `zone`;
2. resolves every name server's addresses;
3. queries each name server directly on port 53, bypassing caching resolvers,
   until each serves the new TXT value. A name server counts once any one of
   its addresses answers with the value.

If that does not happen within `propagation_timeout` (default `90s`), the node
receives `504 Gateway Timeout` and retries later. tailscaled's background
renewal gives the whole ACME order two minutes, so keep the timeout below that.

Headscale needs outbound DNS (UDP and TCP port 53) to the zone's authoritative
servers for this. Where that is not possible, set `propagation_check: false`
and use `propagation_wait` as a fixed delay instead. `propagation_wait` is also
honoured as a minimum when the check is on.

## Provider registration

Headscale's core implementation is provider-neutral. It imports only
`github.com/libdns/libdns`; it does not import Cloudflare, Hetzner, Route53, or
any other provider package directly.

A concrete provider package must be included in the build and register a
factory with:

```go
hscontrol.RegisterDNSCertificateProvider("provider-name", func(config map[string]string) (libdns.RecordSetter, error) {
    // Construct and return the provider-specific libdns RecordSetter.
})
```

If the returned value also implements `libdns.RecordDeleter`, Headscale uses
it to delete expired challenge records (see [Record cleanup](#record-cleanup)).

The factory receives `dns.certificates.provider_config`.

### RFC 2136 provider

Headscale ships an `rfc2136` provider for DNS servers that support
[RFC 2136](https://www.rfc-editor.org/rfc/rfc2136) dynamic updates
authenticated with TSIG, such as BIND or PowerDNS. It uses
[`github.com/libdns/rfc2136`](https://github.com/libdns/rfc2136) and supports
both `SetRecords` and `DeleteRecords`, so expired challenge records are
deleted outright rather than left in the zone (see
[Record cleanup](#record-cleanup)).

You need:

- A DNS server authoritative for `dns.certificates.zone` (or `dns.base_domain`
  if `zone` is empty) that accepts dynamic updates for the
  `_acme-challenge.*` names under it.
- A TSIG key. Generate one with, for example:

  ```console
  tsig-keygen -a hmac-sha256 headscale.
  ```

  This prints a `key "headscale." { algorithm hmac-sha256; secret "..."; };`
  block. Add it to the server's configuration together with an update-policy
  grant limited to `_acme-challenge` records, for example in BIND:

  ```
  zone "example.com" {
      type primary;
      file "example.com.zone";
      update-policy {
          grant headscale. name _acme-challenge.example.com. txt;
          grant headscale. wildcard *._acme-challenge.example.com. txt;
      };
  };
  ```

Configure it under `dns.certificates.provider_config`:

```yaml
dns:
  certificates:
    enabled: true
    provider: "rfc2136"
    zone: "example.com"
    provider_config:
      # The RFC 2136 server's address, host:port.
      nameserver: "ns1.example.com:53"
      # The TSIG key name from tsig-keygen.
      key_name: "headscale."
      # "hmac-sha256" (default) or "hmac-sha512".
      key_algorithm: "hmac-sha256"
      # The TSIG secret from tsig-keygen, base64. Prefer key_secret_path or
      # key_secret_env over writing it into this file directly.
      key_secret_path: /run/secrets/rfc2136_tsig_secret
```

`nameserver`, `key_name` and `key_secret` are required; `key_algorithm`
defaults to `hmac-sha256`. `key_secret` follows the same `_path`/`_env`
indirection as any other `provider_config` value.

## Security properties

- Nodes can only publish `TXT` records.
- Nodes can only publish `_acme-challenge.<their-node-fqdn>`.
- The Noise machine key must match the node key in the request.
- Nodes can only publish a value shaped like an ACME DNS-01 digest (43
  base64url characters), and expired nodes cannot publish at all.
- Concurrent TXT values for the same challenge name are preserved in the RRset
  so overlapping ACME validations (for example `<node>` and `*.<node>`) do not
  replace each other.

## Record cleanup

Each challenge value stays published for 10 minutes, or for `ttl` if that is
longer. When it expires Headscale rewrites the RRset without it; when the last
value for a name expires, Headscale deletes the record if the provider
implements `libdns.RecordDeleter`.

If the provider only implements `libdns.RecordSetter`, the last value for each
name stays in the zone until the node's next certificate request replaces it.
It is harmless (ACME challenge values are single-use), but set a low `ttl` so
resolvers do not hold it. Pending cleanups are not persisted: values still
published when Headscale stops are left in the zone and replaced by the next
request for the same name.

## Usage

After enabling the config and restarting Headscale, clients need a fresh netmap
containing `DNSConfig.CertDomains`. This normally happens automatically; if a
client still says certificate support is not enabled, restart or reconnect the
client and check that the node's map response contains its FQDN in
`CertDomains`.

Then run:

```console
tailscale cert <node>.<base_domain>
tailscale serve --https=443 localhost:8080
```

Funnel remains unsupported because it depends on Tailscale's public ingress
infrastructure.
