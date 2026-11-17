# Thirty-Nine Token Thefts, One Missing Control

## The incident

Apache Shiro, all versions through 3.0.0 —
CVE-2026-74762, **MEDIUM 5.9** (CVSS 4.0), CWE-384, published
2026-11-16T14:17Z:

- When a subject is restored from a **"Remember me" cookie**,
  the existing session is **not invalidated, and no new session
  is created with a new ID**.
- Additionally, **session IDs are accepted from the request URL
  even when session ID URL rewriting is disabled**.
- The combination is session fixation: an attacker fixes the
  session ID a victim's browser will use — for example by getting
  the victim to follow a link carrying the ID — and once the
  victim authenticates, the attacker presents the same session ID
  and inherits the authenticated session.
- The issue affects all Shiro versions through 3.0.0, only when
  RememberMe functionality is enabled. Fixed in **3.0.1**, which
  invalidates the existing session and creates a new session with
  a new ID when a subject is restored from a "Remember me" cookie,
  and ignores session IDs in the URL when URL rewriting is
  disabled.

Sources: NVD CVE-2026-74762; Apache oss-security advisory
(2026-11-14); Apache Shiro security advisories (2026-11-14).

The fixation arrived as one of seventeen Apache flaws published
on 2026-11-13/14 across Shiro, APISIX, and DataSketches, led by
CVE-2026-129349 — a CVSS 9.1 LDAP authentication bypass in
Shiro's `DefaultLdapRealm`. That headliner stays out of this
series on purpose: an attacker logging in with any password is
an authentication bypass, and the tokens are then issued *to the
attacker* — the issuance class, where the proof key is the
attacker's own. The fixation is the one member of the batch that
is a token theft: the session belongs to the victim, and the
attacker rides it.

## Why it's DPoP-shaped

Session fixation is the oldest trick in the series' book, and
it is the same trick as ever: the session ID is a bearer string,
and whoever holds the string holds the session. The attacker
does not need the victim's password, does not need to intercept
anything, and does not need the victim to make a mistake beyond
clicking a link. He chooses the session ID in advance, the
victim's login attaches the victim's identity to it, and the
attacker — who already knows the string — walks in.

The proof-key-hands test passes. The session belongs to the
victim, and the attacker holds no proof key for it — he never
completed the login, never registered a key, never touched the
victim's browser. A sender-constrained session token presented
without its holder's private key is a string the server will not
honour, however perfectly it matches the session table. That is
the same answer the series gave for the Open WebUI session-token
theft in #5 and the cookie-jar disclosure in #7: the session
token is a token, and a token that only its holder can present
cannot be fixed, stolen, or replayed into someone else's
browser.

The honest boundary, as ever: DPoP does not fix the underlying
bug. Upgrade to Shiro 3.0.1 — rotate the session on every
authentication event, and never accept a session ID from the
URL. One further limit, specific to this case: Shiro sessions
are server-side opaque IDs, not RFC 9449 OAuth access tokens,
so DPoP as written does not drop into Shiro unchanged — the
control here is the same idea applied to session tokens, binding
the session to a key the holder established at login and
re-binding it whenever the session is restored. And Shiro is
Java, so this is analysis only. What the case gives the series
is the reminder that the bearer-string problem predates OAuth,
predates MCP, and predates the series itself — a session ID from
a URL is still a token, and a token that anyone can present is
still the identity.
