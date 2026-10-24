# Nineteen Token Thefts, One Missing Control — series index

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
11. [Vikunja's WebSocket Revocation Bypass](vikunja-websocket-revocation-bypass-dpop-analysis.md)
    — CVE-2026-111917: Vikunja's WebSocket `handleAuth` never checks the JWT `sid`
    against the sessions table, so a stolen access token keeps the victim's
    `notification.created` pushes flowing in real time after session deletion or
    TOTP enrollment — revocation simply never reaches the endpoint (MEDIUM 6.5,
    CWE-613, fixed in 2.7.0).


12. [Twelve Token Thefts, One Missing Control](vanus-default-admin-token-dpop-analysis.md)
    — CVE-2026-111998: Vanus 0.8.0–0.9.0 ships a hardcoded default admin Bearer <redacted>;
    unauthenticated remote attackers replay the public string to the gateway gRPC
    proxy port for cluster-admin (CRITICAL 9.3/9.8, CWE-1392). The purest specimen
    of the series thesis — no theft needed, the token is public source; DPoP-bound
    issuance neutralizes the entire replay class.

13. [Thirteen Token Thefts, One Missing Control](camel-http-redirect-credential-disclosure-dpop-analysis.md)
    — CVE-2026-85251: Apache Camel `camel-http` re-attached `Authorization: Bearer`
    to every redirect target and registered basic/digest credentials against an
    any-host `AuthScope` (HIGH 7.5, `followRedirects=true`, fixed in 4.18.5 / 4.22.1 /
    4.23.0) — one `Location:` header is all a remote endpoint needs to harvest
    your tokens.

14. [Fourteen Token Thefts, One Missing Control](cloud-shell-cswh-oauth-exfiltration-dpop-analysis.md)
    — CVE-2026-85267: Google Cloud Shell Cross-Site WebSocket Hijacking — an
    unauthenticated attacker could hijack an active session and exfiltrate the
    user’s OAuth access token from a cross-origin WebSocket (no CVSS; patched
    2026-07-22, NVD-published 2026-10-20). Retrospective write-up, not a live
    fire — but the highest-profile bearer-string casualty so far: exfiltrating
    the string would no longer exfiltrate access under DPoP.

15. [Fifteen Token Thefts, One Missing Control](litellm-supply-chain-stolen-github-tokens-dpop-analysis.md)
    — 2026-10-21: attackers published a malicious `litellm==1.107.0` (PyPI +
    Docker, ~23M weekly downloads) using stolen GitHub CLI OAuth tokens from
    three engineers' accounts; a credential stealer ("privcollect") plus a
    backdoor rode the poisoned `latest` tag for ~2 hours. The string was the
    identity: bearer-token replay turned stolen CLI tokens into
    release-pipeline authority — DPoP-bound tokens would have been inert in
    the attacker's hands.

16. [Sixteen Token Thefts, One Missing Control](better-auth-magiclink-state-confusion-dpop-analysis.md)
    — CVE-2026-114607: better-auth OAuth sign-in `state` redeemable as a Magic
    Link token (cross-protocol state confusion, unauthenticated session takeover,
    CRITICAL 9.1, fixed in 1.7.7) — a session issued to the wrong holder is only
    useful if it can be replayed.

17. [Seventeen Token Thefts, One Missing Control](authlib-octkey-token-forgery-batch-dpop-analysis.md)
    — the library that inspired pydpop had a token-forgery week: Authlib 1.9.0/1.9.1
    batch, OctKey key-validation bypasses forging arbitrary claims (HIGH 7.4 ×2)
    plus captured-token replay shapes (MEDIUM ×2) — DPoP is the last line of
    "a forged token still needs a real key".

18. [Eighteen Token Thefts, One Missing Control](reqllm-websocket-bearer-theft-dpop-analysis.md)
    — CVE-2026-107685: agentjido req_llm ≥1.9.0 <1.29.0 started WebSockex
    with `verify: :verify_none` (and dropped callers' `cacerts`/`ssl_options`),
    so an on-path attacker read the `authorization` bearer header of every
    OpenAI Responses/Realtime/Codex WebSocket session — the captured OAuth
    access token is replayable from anywhere unless it is sender-bound.

19. [Nineteen Token Thefts, One Missing Control](kruize-autotune-credential-disclosure-dpop-analysis.md)
    — CVE-2026-110975: Kruize Autotune's unauthenticated REST API serialized
    datasource configs with default Gson — basic-auth passwords, bearer tokens,
    API keys, and OAuth2 client secrets returned in cleartext to any network
    client (HIGH 7.4). The bearer-token portion dies on contact with DPoP;
    static secrets need their own fix.

Written in the "雪中送炭" spirit: expert analysis first, the library second. If this
month sent you rotating secrets, the control that makes the next theft a non-event is
[pydpop](https://github.com/eaakun/PyDPoP) (`pip install pydpop`) — pure-RFC 9449 DPoP
for Python, with post-quantum hybrid proofs, seven framework integrations, and
[Keycloak-verified interop](interop-keycloak.md).
