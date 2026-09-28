# Tailscale Serve and certificates

[Tailscale Serve](https://tailscale.com/docs/features/tailscale-serve) is a
client-side feature: the Serve configuration and TLS private keys live on the
node, not on Headscale.

Plain HTTP Serve works with MagicDNS. HTTPS Serve and `tailscale cert` require
Headscale to advertise the node's MagicDNS name as certificate-eligible and to
publish ACME DNS-01 TXT challenge records for the node.

## Certificate flow

1. Headscale advertises the node's FQDN in `DNSConfig.CertDomains` and gives
   the node the `https` capability. The first is the client signal that
   avoids:

   ```console
   HTTPS cert support is not enabled/configured for your tailnet.
   ```

   The second lets `tailscale serve --https` start without asking the
   control server to enable HTTPS, which Headscale does not implement.

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
  base_domain: ts.example.com

  certificates:
    enabled: true
    provider: "provider-name"
    zone: "ts.example.com"
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

!!! warning "Use a dedicated subdomain for `base_domain`"

    Every label under `dns.base_domain` is certifiable by any node that can
    register or rename itself to it. Node names come from the client's
    hostname, so a node can become `www.<base_domain>` with
    `tailscale set --hostname=www`, obtain a publicly trusted certificate for
    that name, and MagicDNS already routes the name to the node inside the
    tailnet. Never point `dns.base_domain` at a zone or apex you also use for
    real hostnames. Use a subdomain that serves nothing else, such as
    `ts.example.com`, delegated to its own zone (see
    [RFC 2136 provider](#rfc-2136-provider)).

    Headscale refuses node names that collide with a `dns.extra_records` entry
    and never offers such a node a certificate, but it cannot know about
    hostnames that exist only in your public DNS.

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

## Webhook provider

Headscale ships one provider built in: `webhook`. It posts the TXT RRset as
JSON to an HTTP(S) endpoint you run, so any DNS backend — a small script, a
cloud API shim, a test double — can be plugged in without a Headscale build
that imports that vendor's SDK. It is the escape hatch instead of a built-in
client per DNS vendor, and it is also what Headscale's own integration tests
use, fronting [pebble-challtestsrv](https://github.com/letsencrypt/pebble)'s
`/set-txt`/`/clear-txt` HTTP API with a thin adapter (pebble-challtestsrv
takes one `(host, value)` pair per call; the adapter fans a `records` array
out to it).

```yaml
dns:
  certificates:
    provider: webhook
    provider_config:
      set_url: https://dns-shim.internal/set
      delete_url: https://dns-shim.internal/delete # optional
      auth_token_path: /run/secrets/dns_webhook_token
      hmac_secret_env: DNS_WEBHOOK_HMAC_SECRET
      timeout: 10s
      max_retries: "2"
      insecure_http: "false"
```

`provider_config` keys:

| Key             | Required | Default | Meaning                                                                          |
| --------------- | -------- | ------- | --------------------------------------------------------------------------------- |
| `set_url`       | yes      | -       | Endpoint called for every `SetRecords`.                                           |
| `delete_url`    | no       | unset   | Endpoint called for record deletion. Unset = the provider does not implement `libdns.RecordDeleter`, matching every other optional-delete provider (see [Record cleanup](#record-cleanup)). |
| `auth_token`    | no       | unset   | Sent as `Authorization: Bearer <auth_token>`. Give it as `auth_token_path` or `auth_token_env` to keep it out of the config file (see [Configuration](#configuration)). |
| `hmac_secret`   | no       | unset   | Signs the raw request body with HMAC-SHA256, sent as `X-Headscale-Signature: sha256=<hex>`. Also resolvable via `_path`/`_env`. |
| `timeout`       | no       | `10s`   | Per-HTTP-request timeout, as a Go duration.                                       |
| `max_retries`   | no       | `2`     | Extra attempts, with exponential backoff (200ms, 400ms, 800ms, capped at 2s), on a transport error, HTTP 429, or HTTP 5xx. Any other non-2xx response is not retried. |
| `insecure_http` | no       | `false` | Set to `"true"` to allow `set_url`/`delete_url` to use `http://` instead of `https://`. Local/test use only. |

Both URLs must use `https://` unless `insecure_http` is `"true"`. Headscale
does not follow a redirect to a different host, or a redirect from `https` to
`http`, so a compromised or misconfigured webhook cannot be used to leak the
auth token or HMAC-signed body elsewhere.

### Request

`POST` to `set_url` (or `delete_url` for a deletion), `Content-Type:
application/json; charset=utf-8`:

```json
{
  "action": "set",
  "zone": "example.com",
  "type": "TXT",
  "records": [
    {
      "name": "_acme-challenge.node1",
      "type": "TXT",
      "value": "gfj9Xq...Rg85nM",
      "ttl": 120
    }
  ]
}
```

- `action` is `"set"` for `set_url`, `"delete"` for `delete_url`. It is
  informational — which endpoint was called already says which operation
  this is — useful if one backend fronts both URLs.
- `zone` is `dns.certificates.zone` (or `dns.base_domain`), never trailing-dot
  qualified.
- `type` is always `"TXT"`; Headscale never asks this provider for another
  record type.
- `records` is the **complete current RRset** for `name`, matching libdns
  `SetRecords` semantics: it replaces whatever the backend holds for that
  name, it is not a diff. It normally holds one record; it holds more than
  one only while two ACME orders for the same node (for example `<node>` and
  `*.<node>`) are validating concurrently. `name` is relative to `zone`
  (`"_acme-challenge.node1"`, not the FQDN). `ttl` is whole seconds, `0` when
  unset.
- On `delete_url`, `records` holds only the values Headscale is removing
  (expired challenge values), not the rest of the RRset.

### Response

- Any `2xx` status is success. The response body is ignored.
- Any other status is a failure. Up to 8 KiB of the response body is read
  (bounding memory against a runaway backend), and up to 512 bytes of that is
  kept in the server-side error log. This error is never sent back to the
  Tailscale client: `SetDNSHandler` (`hscontrol/noise.go`) already returns
  only a fixed, generic message over the wire and logs full detail
  server-side only, and the webhook provider's truncation exists so that
  detail cannot itself balloon the log or echo back a secret from the
  request.

## Security properties

- Nodes can only publish `TXT` records.
- Nodes can only publish `_acme-challenge.<their-node-fqdn>`.
- A node cannot take a name used by a `dns.extra_records` entry (registration
  and hostname changes pick the next free `<name>-N`, admin renames are
  refused), and a node that already holds one gets no `CertDomains` and
  cannot publish challenges for it.
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
