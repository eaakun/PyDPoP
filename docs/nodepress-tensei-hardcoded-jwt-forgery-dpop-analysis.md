# Thirty-Seven Token Thefts, One Missing Control

## The incident

Two CRITICAL 9.8s, published on the same day, with the same
vulnerability written in two different codebases: the JWT signing
key is a string constant in the source, and anyone who reads the
source can sign a token for anyone.

**NodePress**, through 8.5.1 —
CVE-2026-129952, **CRITICAL 9.8** (CVSS 3.1; 9.3 under CVSS 4.0),
CWE-1394, published 2026-11-16T15:17Z:

- The application falls back to a **hardcoded JWT signing key,
  `'nodepress-secret'`**, when no secret is configured.
- An unauthenticated remote attacker can sign HS256 bearer tokens
  with the default issuer, audience, and role `'admin'` and gain
  administrator access to the article, comment, options, and file
  management APIs.
- No fixed version is named in the NVD record or the VulnCheck
  advisory as of this writing; the upstream issue is
  surmon-china/nodepress#143, and the fallback is visible in the
  published source (`src/app.config.ts`, `src/core/auth/auth.module.ts`).

Sources: NVD CVE-2026-129952; VulnCheck advisory
(nodepress-through-8.5.1-authentication-bypass-via-default-jwt-signing-secret);
surmon-china/nodepress issue #143.

**Tensei** (`@tensei/auth`), through 0.11.5 —
CVE-2026-129552, **CRITICAL 9.8** (CVSS 3.1; 9.3 under CVSS 4.0),
CWE-1394, published 2026-11-16T12:17Z:

- The auth package falls back to the **hard-coded JWT signing key
  `'auth-secret-key'`** when `JWT_SECRET` is unset.
- An unauthenticated attacker can sign tokens carrying **arbitrary
  user IDs**, which `populateContextFromToken` accepts, and
  impersonate any user — including administrators.
- No fixed version is named in the NVD record or the VulnCheck
  advisory as of this writing; the upstream issue is
  tenseijs/tensei#398, and the fallback is visible in the
  published source (`packages/auth/src/index.ts`).

Sources: NVD CVE-2026-129552; VulnCheck advisory
(tensei-through-0.11.5-authentication-bypass-via-hard-coded-jwt-secret-in-tensei-auth);
tenseijs/tensei issue #398.

## Why it's DPoP-shaped

This is the forgery family's tenth occurrence in the series —
#8 Hitachi, #9 mcp-context-forge, #20 Kener, #21 nest-admin,
#26 OpenDeepWiki and ng-antd-admin, #27 AJ-Report, #30 OFBiz,
#34 WHMS and Versa, #35 NextScan — and the first time two of
them have landed in a single day from two unrelated projects.
The shape never changes: the token is a bearer string whose only
protection is a shared secret, and the secret is public. The
attacker does not steal anything. He reads the repository,
signs a token, and the server — which trusts its own key —
welcomes him as an administrator.

The proof-key-hands test passes for both, and the pair shows
the same two halves #35 showed. In NodePress, the attacker mints
the token himself but holds no legitimate holder's proof key —
the forged string has no key behind it. In Tensei, the same:
the token is minted by the attacker, for a victim's user ID,
with no key the victim ever held. A sender-constrained token
presented without its holder's private key is a string the
resource server will not honour, however perfectly formed it is.

The honest boundary, as ever: DPoP does not fix either
underlying bug. Both projects must replace the hardcoded
fallback with a required, deployment-generated secret — and
deployed instances must rotate the key, because the old one is
in the public source and will keep signing valid tokens until
it is retired. One further limit, specific to the forgery
family: the binding has to be to the *account owner's* key at
issuance. If a server let the caller supply the binding key,
the attacker would simply bind his own — the control only works
when the server binds the token to the key of the account the
token is for, not to whoever asked for it. And neither project
is Python, so this is analysis only: no pydpop plug, no
upstream patch to write from here. What the pair gives the
series is the count: ten forgery occurrences, and the lesson
has not changed since #8 — a hardcoded signing key is not a
secret, and a bearer token signed with a public key is a
permission slip anyone can print.
