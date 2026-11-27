# Sixty-One Token Thefts, One Missing Control

## The incident

HKUDS nanobot's OpenAI Codex provider retried authenticated API
requests without TLS certificate or hostname verification after a
certificate verification failure (CVE-2026-137463, HIGH 7.4,
published 2026-11-26). An attacker able to intercept the connection
could trigger a certificate failure, impersonate the endpoint, and
steal the bearer token — the ChatGPT OAuth access token the provider
sends as `Authorization: Bearer` on every Codex request — along with
request contents, or alter responses.

- Affected: nanobot 0.1.4 before 0.4.1; fixed in 0.4.1 (TLS
  verification stays enabled; no automatic retry with verification
  disabled).
- Sources: NVD record (CVE-2026-137463); GitHub Security Advisory
  GHSA-mxwj-93g9-cc5r
  https://github.com/HKUDS/nanobot/security/advisories/GHSA-mxwj-93g9-cc5r;
  VulnCheck advisory
  https://www.vulncheck.com/advisories/hkuds-nanobot-0.1.4-before-0.4.1-tls-verification-bypass-in-openai-codex-provider.
  Token type confirmed against the provider source: the Codex
  provider authenticates by PKCE OAuth (`oauth_cli_kit`) and sends
  the ChatGPT OAuth access token as the bearer token — not a static
  API key.

## Why it's DPoP-shaped

The misdelivery family's tenth outing — and the closest cousin of
agentjido's `verify_none` WebSocket bearer theft (#18), Camel's
redirect re-attaching `Authorization: Bearer` (#13), and
mcp-remote's cleartext device-code flow (#6). In each, the token
crosses a channel the attacker can stand in, and the string is the
whole credential. A DPoP-bound Codex access token would be inert in
the attacker's hands: replaying it against the Codex backend without
the proof key fails, even after a perfect man-in-the-middle. The
stolen token buys nothing.

## Notes / honesty checks

- DPoP does not fix TLS validation — the provider must verify
  certificates, and 0.4.1 does. The honest claim is narrower:
  sender binding contains the blast radius when verification
  fails, which is exactly the failure mode this CVE is.
- The angle holds for the OAuth (ChatGPT-login) token path. A
  deployment authenticating to Codex with a static API key instead
  gets no protection from DPoP; that key is a bearer string too,
  and DPoP cannot bind what the issuer never bound.
- No exploitation in the wild is reported; the advisory is a
  responsible disclosure by @dajiaohuang.
