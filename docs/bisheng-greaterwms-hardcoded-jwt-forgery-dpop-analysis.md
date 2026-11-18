# Forty Token Thefts, One Missing Control

## The incident

Two forgeries, published within minutes of each other on
2026-11-17, with the same shape in two different codebases: the
token is a bearer string whose only protection is a secret, and
the secret is public — or was never secret at all.

**BISHENG**, before 3.0.0 —
CVE-2026-130840, **CRITICAL 9.8** (CVSS 3.1), CWE-321, published
2026-11-17T20:17Z:

- The application signs its auth JWTs with a **hard-coded
  default `jwt_secret`** used by `AuthJwt` (visible in the
  published source, `src/backend/bisheng/core/config/settings.py`).
- An unauthenticated remote attacker can forge an HS256 token
  **offline**, naming `user_id` 1 with the admin role, send it as
  the `access_token_cookie`, and gain full administrative access
  to users, workspaces, knowledge bases, and workflows.
- Fixed in **3.0.0** (released 2026-11-04; 3.0.1 and 3.0.2 have
  followed since). Deployments still on 2.x must upgrade — and
  replace the shipped secret, since every copy of it ever
  published is now a signing key in the attacker's hands.

Sources: NVD CVE-2026-130840; VulnCheck advisory
(bisheng-before-3.0.0-authentication-bypass-via-hard-coded-jwt-signing-secret);
dataelement/bisheng commit b98e2bc.

**GreaterWMS**, through 2.1.54 —
CVE-2026-130868, **HIGH 7.4** (CVSS 3.1, AC:H), CWE-341,
published 2026-11-17T20:17Z:

- The `openid` authentication token is an **unsalted MD5 hash of
  the username and the registration timestamp** — two values the
  attacker can know or bound.
- An unauthenticated attacker who knows a username and can bound
  its registration time can **brute-force candidate `openid`
  values** offline and present them in the `Token` header to gain
  full read and write access to warehouse, staff, customer,
  supplier, and order data.
- No fixed version is named in the NVD record or the VulnCheck
  advisory as of this writing; the upstream issue is
  GreaterWMS/GreaterWMS#411.

Sources: NVD CVE-2026-130868; VulnCheck advisory
(greaterwms-through-2.1.54-predictable-openid-authentication-token-generation);
GreaterWMS/GreaterWMS issue #411.

## Why it's DPoP-shaped

This is the forgery family's eleventh occurrence in the series —
#8 Hitachi, #9 mcp-context-forge, #20 Kener, #21 nest-admin,
#26 OpenDeepWiki and ng-antd-admin, #27 AJ-Report, #30 OFBiz,
#34 WHMS and Versa, #35 NextScan, #37 NodePress and Tensei —
and the second same-day pair. The shape never changes: the
token is a bearer string whose only protection is a shared
secret, and the secret is public. The attacker does not steal
anything. He reads the repository — or the registration page —
computes a token, and the server, which trusts its own key,
welcomes him as an administrator.

The proof-key-hands test passes for both. Neither attacker holds
a proof key for the account he impersonates: the BISHENG
attacker mints a string with a published secret, and the
GreaterWMS attacker computes a string from public facts. A
sender-constrained token presented without its holder's private
key is a string the server will not honour, however perfectly
it matches the session table. That is the whole of the series'
thesis, stated for the eleventh time.

The pair also shows the family's two mechanisms side by side.
BISHENG is the familiar one: a shipped default secret that was
never rotated. GreaterWMS is the rarer one: the token was never
secret at all — it is a deterministic function of observable
state, and the only thing standing between the attacker and a
working token is the size of the brute-force window. The series
has seen this second mechanism once before, in #22 REDAXO,
where the session-tied secret was pushed into a predictable
state rather than leaked. The lesson is the same in both
directions: a token is only as unforgeable as the entropy
behind it, and "computable from public facts" is not entropy.

The honest boundary, as ever: DPoP does not fix either bug.
BISHENG deployments must upgrade to 3.0.0 or later and replace
the shipped secret; GreaterWMS must generate its tokens from a
server-side secret with a CSPRNG and invalidate every token
minted under the old scheme. Two further limits, specific to
these cases: GreaterWMS is gated on AC:H — the attacker must
know a username and bound its registration time, so the window
is real but narrow — and GreaterWMS is not an OAuth system, so
DPoP as written does not drop into it unchanged; the control
here is the same idea applied to its `Token`-header credential.
What the pair gives the series is the count: eleven
occurrences, and the family is still the most reliable producer
of criticals in the whole watch.
