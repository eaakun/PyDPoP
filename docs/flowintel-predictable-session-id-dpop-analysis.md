# Forty-Five Token Thefts, One Missing Control

## The incident

**FlowIntel**, before 4.1.0 — CVE-2026-133652, **HIGH 7.2**
(CVSS 3.1), published 2026-11-20T11:18Z:

- The browser session identifier is a **bare numeric user
  ID**, not a credential-bound token. There is no secret in
  the credential at all: the value that proves who you are
  is the number that names you.
- An unauthenticated attacker can present any user's ID as
  their session — `1` is, as usual, the first account — and
  be logged in as that user, administrator included. No
  theft is required, because there is nothing to steal; the
  credential is public by construction.
- The same advisory bundles the session-lifecycle failures
  that make the forged session permanent: remember-me
  cookies remain valid after a password change; session
  identifiers are not rotated on login (local, SSO, or
  remembered), enabling fixation; self-service email and
  password changes do not require the current password, so
  an attacker holding any valid session can re-point the
  account's email and lock the real owner out; and
  administrator-initiated password resets do not revoke
  other browser sessions, invalidate remembered logins, or
  rotate the affected user's API key.
- Fixed in FlowIntel 4.1.0. Upstream: flowintel/flowintel,
  commit `a7f025e`.

FlowIntel is a threat-intelligence case-management platform,
and this CVE arrived as part of a large single-audit batch
of FlowIntel <4.1.0 disclosures published on 2026-11-20 —
seventeen CVEs in one day, from TLS verification disabled
on MISP connections (CVE-2026-133648) to connector
credentials exposed to non-admin users (CVE-2026-133665)
to a shared MCP session applying one user's API key to
another user's tool invocation (CVE-2026-133853). Of the
whole batch, this is the one that passes the DPoP test.
The rest are authorization confusion, static-credential
disclosure, CSRF, XSS, and SSRF classes — real bugs, but
bugs where the token is either the attacker's own, a
static key DPoP cannot bind, or never involved at all.

Sources: NVD CVE-2026-133652; the fix commit linked in
the NVD record.

## Why it's DPoP-shaped

The forgery family's thirteenth occurrence — and its
purest specimen yet. Every earlier member of the family
had a secret that turned out to be public: a hard-coded
fallback (AnsibleForms, nest-admin, BISHENG), a
predictable derivation (Open OnDemand's SHA1(servername),
GreaterWMS's MD5 token), a default nobody replaced
(Kener, OpenDeepWiki). FlowIntel skips the secret
entirely. The session identifier *is* the user ID. The
attacker does not need to find, derive, or guess a key;
the credential is the primary key of the users table,
and the first row is the administrator.

The proof-key-hands test passes. The forger holds no
proof key for the victim — he holds a number. A
sender-constrained credential is two objects, not one:
the string and the key that must present it. A session
issued as a bound token would fail the moment it is
presented without its holder's private key, and no
amount of enumerating user IDs would mint a working
session. That is the same answer the series gave for
Kener, nest-admin, and OpenDeepWiki: the forged string
is unredeemable without the holder's private key.

The honest boundary, as ever: DPoP does not fix the
underlying bug, and here the underlying bug is wider
than the forgery. A random, credential-bound session
token is the primary fix; rotation on login and
revocation on password change are the rest of it. Sender
binding does not cure the lifecycle failures bundled
into this CVE — a remember-me cookie that survives a
password change, a session that is never rotated, a
password reset that leaves other sessions and the API
key alive — because those are failures of revocation,
and DPoP has never claimed to fix revocation. Two
further limits, specific to this case: the forged object
is a browser session identifier, not an OAuth access
token, so the DPoP angle is the sender-bound-credential
shape rather than RFC 9449 itself (the same boundary
the series drew for Open OnDemand #55171 and OpenAM
#45049); and the attacker must pick a victim user ID,
which is trivially enumerable rather than secret —
which is precisely the point. Thirteen times now, the
credential that proved identity was public by design or
by arithmetic, and thirteen times the fix has been
"make the token random, bind it to its holder, and
revoke it when the password changes."
