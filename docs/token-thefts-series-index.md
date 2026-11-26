# Fifty-Eight Token Thefts, One Missing Control — series index

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
    — CVE-2026-111998: Vanus 0.8.0–0.9.0 ships a hardcoded default admin Bearer token;
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

20. [Twenty Token Thefts, One Missing Control](kener-dummy-secret-session-forgery-dpop-analysis.md)
    — CVE-2026-116747: Kener 3.0.0 through before 4.1.10 falls back to a
    hardcoded `DUMMY_SECRET` when `KENER_SECRET_KEY` is unset (HIGH 8.1,
    CWE-321) — an unauthenticated attacker knowing one admin email forges a
    `kener-user` cookie straight into `/manage/api`. The forgery family, at
    its purest: nothing is stolen, the token is minted on demand — and a
    sender-constrained token is exactly what a minted string cannot redeem.

21. [Twenty-One Token Thefts, One Missing Control](nest-admin-hardcoded-jwt-secret-dpop-analysis.md)
    — CVE-2026-117564: nest-admin before 1.0.1 committed a hardcoded
    `JWT_SECRET` in `.env.production` (CRITICAL 9.8, CWE-321) — an
    unauthenticated attacker self-signs a JWT that `JwtStrategy` and
    `RbacGuard` accept for any user ID or the admin role. The forgery
    family, fourth occurrence — and this time the forged object is a
    standard JWT access token itself, squarely on DPoP's home ground.
    Upgrade to 1.0.1 is not enough alone: deployed instances must also
    rotate the key.

22. [Twenty-Two Token Thefts, One Missing Control](redaxo-predictable-secret-login-forgery-dpop-analysis.md)
    — CVE-2026-117532: REDAXO core 5.3.0 through 5.21.3 (patched in
    5.21.4) — the `structure/history` plugin's session-tied secret could
    be pushed into a predictable state unauthenticated, letting an
    attacker forge a temporary login token for any account including
    admin (CRITICAL 9.8); outside live mode the admin session escalates
    to code execution. The twist the series had not seen: the key was
    never leaked, only made guessable. Retrospective disclosure — the
    patch shipped 2026-08-03, the CVE published 2026-10-27.

23. [Twenty-Three Token Thefts, One Missing Control](triggerdev-cli-auth-code-pat-takeover-dpop-analysis.md)
    — CVE-2026-114089: Trigger.dev before 4.5.2 minted a Personal Access
    Token with no consent step when a logged-in victim was lured to
    `/account/authorization-code/<code>`, and the victim's PAT could
    then be collected from the unauthenticated `/api/v1/token`
    endpoint (HIGH 8.8, CWE-352, fixed in 4.5.2) — full account
    takeover from one lured click, and the closest sibling of #16's
    cross-protocol state confusion: a token in the wrong hands through
    a flow confusion, not a break-in.

24. [Twenty-Four Token Thefts, One Missing Control](kafka-oauthbearer-jwks-fallback-dpop-analysis.md)
    — CVE-2026-110985: Kafka brokers on SASL/OAUTHBEARER with the
    default validator and no JWKS endpoint URL silently fell back to a
    non-verifying validator, accepting any structurally valid JWT —
    including `alg:none` — and letting an unauthenticated remote
    attacker forge any principal, superusers included (fixed 4.2.2,
    4.3.1, 4.4.0, fail-closed) — the series' purest "the verifier does
    not verify" specimen, and its thinnest DPoP angle yet: a verifier
    that verifies nothing cannot be fixed by sender-constrained tokens.

25. [Twenty-Five Token Thefts, One Missing Control](openam-cdsso-session-token-exposure-dpop-analysis.md)
    — CVE-2026-45049: OpenAM's CDSSO servlet let a logged-in user's raw
    session token be POSTed to an attacker-controlled URL when the
    victim visited a crafted link (HIGH 8.3, through 16.0.6, patched
    16.1.1) — a bearer credential replayable across every domain the
    session logged into, gated on CDSSO being enabled, user
    interaction, and an absent non-default configuration; the
    vendor's own restricted-token binding is the same idea DPoP
    applies to OAuth access tokens.

26. [Twenty-Six Token Thefts, One Missing Control](hardcoded-jwt-secrets-opendeepwiki-ngantdadmin-dpop-analysis.md)
    — Two hardcoded-JWT-secret forgeries published the same day:
    CVE-2026-119597 (OpenDeepWiki through 2.0.6, CRITICAL 9.3 — the
    fix commit is on main but no release carries it) and
    CVE-2026-61737 (ng-antd-admin before 22.0, CRITICAL 9.8 — the fix
    shipped in v22.0 but old deployments never upgraded) — one
    lesson in both directions: "patched" and "protected" are
    different states, and the gap between them is where forged
    tokens keep working.

27. [Twenty-Seven Token Thefts, One Missing Control](aj-report-hardcoded-jwt-share-token-dpop-analysis.md)
    — CVE-2026-120209: AJ-Report through 1.7.1 signs Share-Tokens with a
    hardcoded JWT secret (CWE-321, CRITICAL 9.8) — an unauthenticated
    attacker forges a Share-Token with reportCode 'dataSet' and reaches
    the testTransform endpoint, which hands scripts to GroovyClassLoader
    for unauthenticated RCE. No fixed version is marked in the CVE
    record as of publication.
28. [Twenty-Eight Token Thefts, One Missing Control](kaniko-azure-token-misdelivery-dpop-analysis.md)
    — CVE-2026-105769: kaniko before 1.25.20 (CRITICAL 9.3) — the ACR
    credential helper's unanchored regex treats any hostname containing
    .azurecr.io as an ACR registry, so a Dockerfile FROM
    x.azurecr.io.attacker.com/img sends the build's Azure AD ARM access
    token to the attacker's /oauth2/exchange — the token is replayable
    against ARM and exchangeable for ACR credentials (fixed in 1.25.20).
29. [Twenty-Nine Token Thefts, One Missing Control](mcp-client-resource-confusion-dpop-analysis.md)
    — Two MCP clients, one missing check, published the same day:
    CVE-2026-123272 (mcp-go < 1.2.1) and CVE-2026-123271 (ChatCLI <
    v1.215.2), both HIGH 8.0 — each took the resource indicator straight
    from the server's Protected Resource Metadata, letting a malicious
    MCP server claim another resource and walk away with the user's
    bearer token (fixed in 1.2.1 / v1.215.2).
30. [Thirty Token Thefts, One Missing Control](ofbiz-hardcoded-jwt-forgery-dpop-analysis.md)
    — CVE-2026-105330: Apache OFBiz 24.09.06/07 (CWE-321, no CVSS yet)
    — the factory-default security.token.key signs JWT SSO tokens, and
    deployments upgraded from pre-CVE-2026-31986 versions with old
    security.properties and internal SSO enabled let an unauthenticated
    remote attacker forge any JWT for full admin access. Upgrading to
    24.09.08 is not enough alone: the key must also be rotated
    (./gradlew rotateSecretKeys).
31. [Thirty-One Token Thefts, One Missing Control](vikunja-token-misdelivery-dpop-analysis.md)
    — Two Vikunja token-misdelivery CVEs published the same day, both fixed
    in 2.7.1: CVE-2026-123513 (MEDIUM 6.8) — the frontend sends the stored
    bearer token and desktop OAuth refresh token to an attacker-chosen API
    URL; and CVE-2026-123499 (MEDIUM 5.9) — veans sends VEANS_TOKEN as a
    Bearer header to a server named in a repo-controlled .veans.yml. The
    project's second appearance in the series (#11 was the WebSocket
    revocation bypass) — the token string keeps being treated as the
    identity, one endpoint at a time.
32. [Thirty-Two Token Thefts, One Missing Control](mittwald-mcp-session-token-theft-dpop-analysis.md)
    — Mittwald's MCP server flaw (exploited 2026-10-27, disclosed
    2026-11-07, no CVE yet): the attacker read the session tokens of
    customers who used the server, and each token opened mStudio with
    the customer's rights — 56 customer projects compromised, eight
    days undetected. The series' first real-world MCP-server token
    theft with customer impact; the proof-key-hands test passes (the
    tokens were stolen from the holder's store, not minted to the
    attacker), with the honest boundary that these are session tokens,
    not RFC 9449 OAuth access tokens, and the flaw itself is still
    undisclosed.
33. [Thirty-Three Token Thefts, One Missing Control](thunderbird-oauth-token-cleartext-dpop-analysis.md)
    — CVE-2026-126136: Thunderbird sent the user's OAuth2 access token
    over unencrypted HTTP for Exchange accounts (EWS / Microsoft
    Graph) — a network observer could take the token and walk into
    the mailbox until it expired (Mozilla impact moderate, fixed in
    160 / 153.7). The cleartext-theft shape, met for the first time
    in a mainstream end-user client rather than a library or server.
34. [Thirty-Four Token Thefts, One Missing Control](hardcoded-secrets-whms-versa-forgery-dpop-analysis.md)
    — Two hardcoded-secret forgeries published within an hour of each
    other: CVE-2026-125383 (INDOTALENT WHMS, CRITICAL 9.3 — a
    hard-coded JWT signing key, issuer, and audience in
    appsettings.json lets an unauthenticated remote attacker forge
    tokens for any user ID or role) and CVE-2026-107244 (Versa VOS,
    HIGH 7.6 — a hardcoded key and IV let an unauthenticated
    attacker compute a valid token for the ZTP service's /decryptTest
    endpoint and obtain a fully authenticated session; gated on the
    service being left enabled after provisioning). The forgery
    family, eighth occurrence — rotate the secret first, then make
    the token worthless without its key.
35. [Thirty-Five Token Thefts, One Missing Control](nextscan-woocommerce-token-forgery-dpop-analysis.md)
    — Two CRITICAL 9.8s published the same day, one forging and one
    asking: CVE-2026-126797 (NextScan ns-admin 1.1.0–1.2.0, CWE-321
    — a hardcoded JWT signing key lets an unauthenticated attacker
    sign HS256 X-Access-Tokens with the public super administrator
    role ID; no fixed version named yet) and CVE-2026-123695
    (Security For WooCommerce through 1.0.16, CWE-269 — unrestricted
    REST API routes let an unauthenticated user generate and retrieve
    login tokens for any user, including administrators; no known
    fix, PoC due 2026-12-09). The forgery family's ninth occurrence,
    and its mirror image — with the binding caveat that a
    token-generation endpoint must bind to the account owner's key,
    not the caller's.
36. [Thirty-Six Token Thefts, One Missing Control](mongodb-node-driver-oidc-token-disclosure-dpop-analysis.md)
    — CVE-2026-126835: the MongoDB Node.js driver 6.7.0–7.8.x did
    not consistently enforce its permitted-host restriction during
    OIDC authentication, so a bearer token from the embedding
    application's own login callback could be sent to a host
    outside the allowlisted set (MEDIUM 6.5, CWE-923, fixed in
    7.9.0). The misdelivery family's fifth outing — the connection
    string is becoming the new redirect URI.
37. [Thirty-Seven Token Thefts, One Missing Control](nodepress-tensei-hardcoded-jwt-forgery-dpop-analysis.md)
    — Two CRITICAL 9.8 hardcoded-JWT-secret forgeries published the
    same day: CVE-2026-129952 (NodePress through 8.5.1 — the
    `'nodepress-secret'` fallback key lets an unauthenticated
    attacker sign HS256 admin bearer tokens) and CVE-2026-129552
    (Tensei through 0.11.5 — `@tensei/auth` falls back to
    `'auth-secret-key'` when `JWT_SECRET` is unset, so tokens with
    arbitrary user IDs are signable; no fixed version named for
    either). The forgery family's tenth occurrence.
38. [Thirty-Eight Token Thefts, One Missing Control](deepaudit-aws-mcp-token-exfiltration-dpop-analysis.md)
    — Three tokens that walked out the door, published the same
    day: CVE-2026-129877 (DeepAudit 2.0.0-beta.1–3.8.0, HIGH 7.5 —
    an unauthenticated `GET /api/v1/config/defaults` returns the
    operator's LLM keys and GitHub/GitLab tokens) and
    CVE-2026-129880 (DeepAudit 2.0.0-beta.5–3.8.0, HIGH 7.7 — SSRF
    via `repository_url` delivers the server-wide GitLab/Gitea
    token to an attacker host), plus CVE-2026-126681 (AWS Labs
    Timestream for InfluxDB MCP Server before 0.0.19, MEDIUM 5.5 —
    prompt injection sends the configured InfluxDB API token to a
    crafted endpoint; fixed in 0.0.19, rotate tokens). The
    misdelivery family's sixth and seventh outings — and the first
    to arrive through a prompt.
39. [Thirty-Nine Token Thefts, One Missing Control](shiro-session-fixation-dpop-analysis.md)
    — CVE-2026-74762: Apache Shiro through 3.0.0 never rotates the
    session when a subject is restored from a "Remember me" cookie,
    and accepts session IDs from the request URL even with URL
    rewriting disabled (MEDIUM 5.9, CWE-384, fixed in 3.0.1) — the
    oldest trick in the series' book, in the framework that guards
    half of Java. One of seventeen Apache flaws published
    2026-11-13/14; the 9.1 LDAP headliner stays out as issuance-class.
40. [Forty Token Thefts, One Missing Control](bisheng-greaterwms-hardcoded-jwt-forgery-dpop-analysis.md)
    — Two forgeries published within minutes of each other:
    CVE-2026-130840 (BISHENG before 3.0.0, CRITICAL 9.8 — a
    hard-coded default `jwt_secret` lets an unauthenticated attacker
    forge HS256 admin tokens; fixed in 3.0.0) and CVE-2026-130868
    (GreaterWMS through 2.1.54, HIGH 7.4 — the `openid` token is an
    unsalted MD5 of username and registration timestamp,
    brute-forceable offline; no fixed version named). The forgery
    family's eleventh occurrence — and the second time the secret
    was never leaked at all, only never secret.
41. [Forty-One Token Thefts, One Missing Control](flowise-mcp-server-token-disclosure-dpop-analysis.md)
    — CVE-2026-130796: Flowise 3.1.3–3.1.4 returns the MCP server
    bearer token in the unauthenticated public-chatflow response
    (HIGH 8.2), and the leaked token invokes chatflows past the
    API-key check, consuming the owner's model quota — the
    disclosure family's MCP-native outing; no fixed version named
    yet.
42. [Forty-Two Token Thefts, One Missing Control](rucio-ssh-challenge-token-confusion-dpop-analysis.md)
    — CVE-2026-100397: Rucio's token validator could not tell an
    SSH challenge nonce from an auth token (CRITICAL 10.0), so an
    unauthenticated attacker requested a challenge token for any
    account and presented it as the auth token — admin included
    (fixed in 35.9.1 / 38.6.1 / 40.4.2 / 41.1.1). The first
    type-confusion case in the series: the string was never issued
    as an auth token at all.
43. [Forty-Three Token Thefts, One Missing Control](obot-resource-confusion-token-theft-dpop-analysis.md)
    — CVE-2026-130766: Obot 0.26.0–before 0.27.0 took the resource
    identifier straight from a remote MCP server's Protected
    Resource Metadata, letting a malicious server claim another
    service and walk away with the victim's access token (HIGH
    8.0, fixed in 0.27.0) — the resource-confusion shape's third
    outing, the misdelivery family's eighth. The same-release
    sibling CVE-2026-130764 (SSRF token-endpoint hijack) is
    recorded in the piece as endpoint-hijack class, not
    DPoP-shaped.
44. [Forty-Four Token Thefts, One Missing Control](ansibleforms-openondemand-hardcoded-secret-forgery-dpop-analysis.md)
    — Two CRITICAL forgeries published one minute apart:
    CVE-2026-73969 (AnsibleForms before 6.2.1, 9.8 — a public
    hard-coded fallback JWT secret mints admin tokens when
    ACCESS_TOKEN_SECRET is unset; fixed in 6.2.1) and
    CVE-2026-55171 (Open OnDemand before 4.1.6 / 4.2.3, 9.1 —
    OIDCCryptoPassphrase defaults to SHA1(servername), so an
    unauthenticated attacker derives the key and forges another
    user's session cookie; fixed in 4.1.6 / 4.2.3 and
    ood-ansible 4.2.1). The forgery family's twelfth
    occurrence — and the second time the secret was never
    leaked at all, only never secret.
45. [Forty-Five Token Thefts, One Missing Control](flowintel-predictable-session-id-dpop-analysis.md)
    — CVE-2026-133652: FlowIntel before 4.1.0 used a bare
    numeric user ID as the browser session identifier, so
    an unauthenticated attacker presents any user's number
    — `1` is the administrator — and is logged in as them
    (HIGH 7.2, fixed in 4.1.0). The forgery family's
    thirteenth occurrence, and its purest specimen: no
    secret was leaked, derived, or guessed, because there
    was no secret at all. The bundled lifecycle failures
    (remember-me surviving password change, no rotation,
    no current-password check) are recorded in the piece
    as revocation semantics DPoP does not fix.

46. [Forty-Six Token Thefts, One Missing Control](xo-token-confusion-login-token-theft-dpop-analysis.md)
    — CVE-2026-133469: Xen Orchestra before 6.9.2 / 6.10.1
    turned `authenticationToken=j:{}` into an empty object,
    and the token collection treated it as an unfiltered
    lookup — returning its first token and authenticating
    as that token's owner, then handing out reusable login
    token IDs (CRITICAL 9.8, actively exploited in the
    wild, fixed in 6.9.2 / 6.10.1). The second
    type-confusion case in the series, after Rucio #100397.
47. [Forty-Seven Token Thefts, One Missing Control](autogpt-hardcoded-secrets-token-forgery-dpop-analysis.md)
    — Two AutoGPT Platform CVEs, one shipped default file:
    CVE-2026-130169 (CRITICAL 10.0 — a publicly known
    hardcoded JWT verification key in `.env.default` forges
    tokens for any user or admin) and CVE-2026-132257
    (HIGH 8.2 — a hardcoded Fernet key encrypts every
    user's stored OAuth tokens, decryptable by anyone with
    database read access), both fixed in 0.8.0. The
    forgery family's fourteenth occurrence, and the
    stored-token disclosure family's return.
48. [Forty-Eight Token Thefts, One Missing Control](kerberos-agent-hardcoded-jwt-forgery-dpop-analysis.md)
    — CVE-2026-135208: Kerberos Agent before 3.14.4 fell
    back to the hard-coded JWT key `TOBECHANGED`, so an
    unauthenticated attacker signs HS256 admin tokens with
    arbitrary username and role claims (CRITICAL 9.8,
    fixed in 3.14.4) — the forgery family's fifteenth
    occurrence, and its most literal: the secret announces
    itself as a to-do item.
49. [Forty-Nine Token Thefts, One Missing Control](pomerium-mcp-token-endpoint-refresh-redemption-dpop-analysis.md)
    — CVE-2026-135300: Pomerium 0.30.0–before 0.34.0
    skipped client secret verification at its MCP token
    endpoint, so an intercepted authorization code or
    refresh token redeemed with any secret yields the
    victim's access tokens (HIGH 7.4, fixed in 0.34.0).
    The misdelivery family's ninth outing — and the first
    to arrive at a token endpoint itself.
50. [Fifty Token Thefts, One Missing Control](wingftp-predictable-session-id-dpop-analysis.md)
    — CVE-2026-135171: Wing FTP Server before 8.2.8
    derived session identifiers from process, time,
    ServerID, and client IP state, and offered a validity
    oracle to enumerate them — replay a live session and
    you are the administrator, Lua console included
    (HIGH 8.1, fixed in 8.2.8). The forgery family's
    sixteenth occurrence, and the second
    predictable-session-identifier specimen after FlowIntel.
51. [Fifty-One Token Thefts, One Missing Control](dreamehome-idor-token-theft-dpop-analysis.md)
    — Three DreameHome CVEs from one research batch, all
    the same missing ownership check: CVE-2026-49964
    (HIGH 7.1 — an Agora RTC token for another user's
    device, joining its live-video channel), CVE-2026-49960
    (MEDIUM 6.5 — another user's Meari camera-platform
    session credentials, live video, microphone, and stored
    recordings), and CVE-2026-49961 (MEDIUM 6.5 — another
    device's MQTT status topic, including the session key
    for encrypted video). Retrospective disclosure: the
    cloud API was fixed 2026-10-14 and the MQTT broker
    2026-10-26, six weeks before the CVEs published.
52. [Fifty-Two Token Thefts, One Missing Control](redvector-hardcoded-api-token-dpop-analysis.md)
    — CVE-2026-136168: RedVector before 8.1.0 ships the hard-coded default
    bearer token `redvector-dev-token`; unauthenticated attackers replay the
    public string to `/api/python/execute` for remote code execution as the
    server user — and permissive CORS lets a malicious web page drive a
    loopback instance the same way (HIGH 8.8, CWE-1392, fixed in 8.1.0).
    The Vanus #12 shape, with a nastier delivery channel.
53. [Fifty-Three Token Thefts, One Missing Control](webmin-cleartext-session-id-dpop-analysis.md)
    — CVE-2026-134647: Webmin through 2.670 sends cluster RPC traffic
    over raw TCP despite SSL configuration, so a network-positioned
    attacker reads the session ID — and the `remote_eval` payloads
    riding with it — or alters calls to execute code as root on managed
    servers (HIGH 7.5, fixed by commits `63666bd6` / `aca80423`). The
    cleartext-theft family's fourth outing.
54. [Fifty-Four Token Thefts, One Missing Control](jspwiki-session-fixation-dpop-analysis.md)
    — CVE-2026-78114: Apache JSPWiki 2.10–3.0.0 never replaced the
    session identifier on login, so an attacker who set a known session
    ID in a victim's browser kept it after the victim logged in
    (CRITICAL 10.0, CWE-384, fixed in 3.0.1 / 2.12.6). Session
    fixation, second outing after Shiro #39.
55. [Fifty-Five Token Thefts, One Missing Control](openimis-jwt-signing-key-disclosure-dpop-analysis.md)
    — Two openIMIS CVEs, one flaw class: CVE-2026-82491 and
    CVE-2026-82492 (HIGH 8.8 ×2) let an authenticated user with a
    single ordinary read right traverse dotted relation paths to
    another user's JWT signing key (`user_created.i_user.private_key`)
    and forge valid sessions for any account, administrators included
    — surviving password reset, with no failed-login event (fixed in
    Release 2026-10). The forgery family's seventeenth occurrence.
56. [Fifty-Six Token Thefts, One Missing Control](gitlab-session-cookie-disclosure-dpop-analysis.md)
    — CVE-2026-119452: GitLab CE/EE 13.7.0–19.4.11 / 19.5.9 / 19.6.2
    let a Maintainer obtain another user's authenticated session cookie
    through improper session storage in the dependency proxy
    authentication flow (MEDIUM 6.7, fixed in 19.4.11 / 19.5.9 /
    19.6.2). The session-cookie replay shape, in its most ordinary
    clothes — an insider flaw, but a stolen cookie is still an
    account.
57. [Fifty-Seven Token Thefts, One Missing Control](equinox-hardcoded-jwt-secret-dpop-analysis.md)
    — CVE-2026-136733: EduardoPires/EquinoxProject ships its JWT
    signing key (`fmFGn5agHZkuG2N0e1zaEJIQtGVoNN5P`) in
    `appsettings.Development.json` — and Staging and Testing — with no
    startup warning, so anyone who reads the repo forges any user's
    JWT (HIGH 7.3, CWE-259). Retrospective disclosure: issue #219 was
    filed 2026-06-16, still unanswered, and the secret is still in
    the repository. The forgery family's eighteenth occurrence.
58. [Fifty-Eight Token Thefts, One Missing Control](teracom-predictable-session-cookie-dpop-analysis.md)
    — CVE-2026-137086: Teracom TCW122B-CM firmware before 4.07 derives
    its 32-bit session cookie from a tick counter, so an unauthenticated
    remote attacker predicts or brute-forces it from uptime and login
    timing and hijacks administrator sessions (HIGH 8.1, fixed in
    4.07). The forgery family's nineteenth occurrence, and its third
    predictable-session-identifier specimen after FlowIntel #45 and
    Wing FTP #50.

Written in the "雪中送炭" spirit: expert analysis first, the library second. If this
month sent you rotating secrets, the control that makes the next theft a non-event is
[pydpop](https://github.com/eaakun/PyDPoP) (`pip install pydpop`) — pure-RFC 9449 DPoP
for Python, with post-quantum hybrid proofs, seven framework integrations, and
[Keycloak-verified interop](interop-keycloak.md).
