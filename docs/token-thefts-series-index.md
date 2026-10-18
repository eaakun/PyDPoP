# Eleven Token Thefts, One Missing Control — series index

Bearer tokens are strings; strings can be copied. This running series documents real,
independently-verified token-theft and token-forgery incidents in the OAuth / MCP /
AI-tooling ecosystem — each checked against primary sources (NVD, vendor advisories) —
and shows, for each one, exactly where sender-constrained tokens (RFC 9449 DPoP) would
and would not have changed the outcome.

The honest boundary, stated once: **DPoP does not fix the underlying bug** — a missing
origin check, a cleartext device-code flow, or a hardcoded signing key still needs its
patch. What DPoP changes is the *economics of the stolen token*: a token that only its
holder can present turns every "the string is the identity" failure into one that
requires stealing an actual private key. The patch closes this door; DPoP makes the
next theft a non-event.

1. [The MCP OAuth Credential Theft, and the DPoP Backstop Nobody Mentions](mcp-oauth-theft-dpop-analysis.md)
   — CVE-2026-104850: a malicious MCP server could steal a client's OAuth credentials
   (client secret, auth code, PKCE verifier) through unvalidated issuer discovery.
2. [Two Token Thefts in One Week, One Missing Control](two-token-thefts-one-missing-control.md)
   — the MCP SDK flaw (CVE-2026-104850, HIGH 7.5), plus CVE-2026-76286: Splunk MCP
   Server <1.2.1 sent the platform auth token to an attacker-configured URL.
3. [Three Token Thefts, One Missing Control](ditto-oauth-theft-dpop-analysis.md)
   — CVE-2026-107503: Ditto Explorer OAuth token theft (HIGH).
4. [Four Token Thefts, One Missing Control](wpo365-oauth-theft-dpop-analysis.md)
   — CVE-2026-104759: WPO365 OIDC nonce replay → `id_token` replay (HIGH 8.1) — the
   biggest blast radius of the series.
5. [Five Token Thefts, One Missing Control](openwebui-session-token-theft-dpop-analysis.md)
   — GHSA-vpq8-f445-hcq7: Open WebUI's message listener never checked `event.origin`,
   so any website the victim visited could harvest their session token (HIGH 8.1).
6. [Six Token Thefts, One Missing Control](mcp-remote-oauth-theft-dpop-analysis.md)
   — CVE-2026-108716: mcp-remote 0.8.0–0.14.3 transmitted device-code OAuth tokens in
   cleartext (MEDIUM 5.3).
7. [Seven Token Thefts, One Missing Control](openwebui-cookie-jar-disclosure-dpop-analysis.md)
   — CVE-2026-109292: Open WebUI OAuth-mode connections forwarded the full browser
   cookie jar to destination servers (MEDIUM).
8. [Eight Token Thefts, One Missing Control](hitachi-remotops-jwt-forgery-dpop-analysis.md)
   — CVE-2026-108336: Hitachi RemotOps Agent hardcoded JWT key (CWE-321, CRITICAL 9.1)
   — admin tokens mintable from the public repository.
9. [Nine Token Thefts, One Missing Control](mcp-context-forge-forged-admin-token-dpop-analysis.md)
   — CVE-2026-53709: IBM mcp-context-forge hardcoded `JWT_SECRET_KEY` plus a
   platform-admin bootstrap (CRITICAL), and CVE-2026-110612: vlife's hardcoded HS256
   key signing `superUser=true` tokens — three minted-admin CVEs in two days.
10. [Ten Token Thefts, One Missing Control](mattermost-oauth-session-switch-dpop-analysis.md)
    — CVE-2026-19076: Mattermost's `POST /api/v4/users/login/switch` never rejected
    OAuth app sessions, so a stolen OAuth bearer token meant permanent SSO account
    takeover (MEDIUM 4.4, CWE-863); the sibling CVE-2026-19600 (authentication tokens
    written into server logs) was the ready-made theft channel — the purest
    stolen-bearer-replay shape of the series.
11. [Eleven Token Thefts, One Missing Control](vikunja-websocket-revocation-bypass-dpop-analysis.md)
    — CVE-2026-111917: Vikunja's WebSocket `handleAuth` never checks the JWT `sid`
    against the sessions table, so a stolen access token keeps the victim's
    `notification.created` pushes flowing in real time after session deletion or
    TOTP enrollment — revocation simply never reaches the endpoint (MEDIUM 6.5,
    CWE-613, fixed in 2.7.0).

Written in the "雪中送炭" spirit: expert analysis first, the library second. If this
month sent you rotating secrets, the control that makes the next theft a non-event is
[pydpop](https://github.com/eaakun/PyDPoP) (`pip install pydpop`) — pure-RFC 9449 DPoP
for Python, with post-quantum hybrid proofs, seven framework integrations, and
[Keycloak-verified interop](interop-keycloak.md).
