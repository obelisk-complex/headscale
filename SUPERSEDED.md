# Superseded

This branch (`tailscale-cert-poc`) is an early Hetzner-only proof of concept
for DNS-01 ACME certificate support. It has been superseded by the
`dns-01-certs` branch, which ports upstream PR #3321 as a baseline and adds
hardened authorization, real DNS propagation verification, RRset
merge/cleanup, secret redaction, RFC2136 + generic webhook providers, and an
end-to-end integration test against Pebble/pebble-challtestsrv.

This branch is left as-is for reference; no further work is planned here.
