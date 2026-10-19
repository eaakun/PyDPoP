# Twelve Token Thefts, One Missing Control

## The incident

Vanus 0.8.0 through 0.9.0 ships a **hardcoded admin Bearer <redacted> (`vanus-admin`)**
(CVE-2026-111998, CRITICAL, CWE-1392, published 2026-10-18). An unauthenticated
remote attacker sends the fixed token string to the gateway gRPC proxy port
and gets **cluster-admin**: manage namespaces, eventbuses, users, tokens, role
bindings, read and publish events. The "credential" is a public string —
literally committed in `internal/primitive/constants.go` (v0.9.0, line 37) and
referenced in `internal/controller/tenant/controller.go` (L449–L500).

- Affected: Vanus (vanus-labs/vanus, Go, serverless messaging / event
  streaming, marketed for AI agents), versions 0.8.0–0.9.0.
- Sources: NVD record (CVE-2026-111998);
  VulnCheck advisory
  https://www.vulncheck.com/advisories/vanus-0.8.0-through-0.9.0-default-admin-credentials-via-gateway;
  upstream issue https://github.com/vanus-labs/vanus/issues/647.

## Why it's DPoP-shaped

This is the purest specimen yet of the series thesis: **the gateway
authenticates a string, not a holder.** No theft was even needed — the token
is public source. Any replayable bearer credential is this vulnerability
wearing different clothes: the Mattermost OAuth-bearer <redacted> (Ten Token Thefts),
the Open WebUI cookie-jar (Seven), the Open WebUI postMessage tokens (Five).
Vanus just skips the stealing step.

DPoP (RFC 9449) closes the *class*, not the bug: the real fix is to stop
shipping a static bearer string and issue sender-constrained tokens instead.
A DPoP-bound access token is useless without the private key that produced the
proof — so even a hardcoded, leaked, or dumped token string cannot be replayed
by a stranger's hand. The honest sentence to print: the fix rotates one
secret; sender-constrained issuance makes every secret of this shape
unstealable.

## Notes / honesty checks

- Default/hardcoded-credential CVEs are adjacent to the DataBuff
  CVE-2026-111692/93 pair (filtered 10-17: hardcoded HMAC secret allowed token
  *minting* — DPoP no help, obscure project). Vanus differs on both axes:
  the attacker cannot mint, only replay the public string — and DPoP-bound
  issuance genuinely neutralizes that replay; the project is a real
  open-source streaming platform (event-native infra for AI agents, MCP
  ecosystem-adjacent).
- DPoP does not fix the hardcoded credential itself; it neutralizes the
  replayability of any bearer string of this shape. Say so explicitly.
- Vanus is Go; pydpop is Python. No product plug — "shape of the fix"
  narrative only, consistent with the mcp-remote #377 approach.
