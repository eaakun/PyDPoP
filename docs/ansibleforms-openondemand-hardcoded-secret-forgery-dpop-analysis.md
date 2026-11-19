# Forty-Four Token Thefts, One Missing Control

## The incident

Two forgeries published one minute apart, both CRITICAL, both
with the same root cause — the secret was never secret:

**AnsibleForms**, before 6.2.1 —
CVE-2026-73969, **CRITICAL 9.8** (CVSS 3.1), CWE-321,
published 2026-11-18T21:18Z:

- When `ACCESS_TOKEN_SECRET` is unset, the server falls back
  to a **public hard-coded JWT signing secret** shipped in
  `server/config/auth.config.js`.
- An unauthenticated attacker can sign a self-contained token
  with privileged claims, because `auth_jwt.js` verifies the
  signature without reloading the user from the database, and
  the middleware trusts the token's roles and options for
  authorization. A forged token is accepted as an
  administrator session, with full privileged API access.
- Fixed in 6.2.1. The advisory is GHSA-g27f-cjvv-42rf
  (ansibleforms/ansibleforms).

**Open OnDemand**, before 4.1.6 and 4.2.3 (and ood-ansible
before 4.2.1) — CVE-2026-55171, **CRITICAL 9.1** (CVSS 3.1),
published 2026-11-18T21:17Z:

- The portal generator defaults `OIDCCryptoPassphrase` to
  `SHA1(servername)` — an attacker-derivable value. Worse,
  the `ood_portal.yml.j2` role checks a *different* variable
  from the documented passphrase setting, so an administrator
  who sets `ood_oidc_crypto_passphrase` can believe a strong
  secret is configured while the deployment keeps using the
  derivable one.
- In `OIDCSessionType` client-cookie deployments, an
  unauthenticated remote attacker can derive the encryption
  key and **forge a `mod_auth_openidc_session` cookie for
  another user**. Server-cache deployments permit
  lower-impact tampering with protected OIDC state and nonce
  cookies.
- Fixed in Open OnDemand 4.1.6 and 4.2.3, and ood-ansible
  4.2.1. Upstream: OSC/ondemand, PR #5559.

Sources: NVD CVE-2026-73969 and CVE-2026-55171; the two
advisories linked in the NVD records.

## Why it's DPoP-shaped

The forgery family's twelfth occurrence — and its most
honest pair. Neither secret was leaked. AnsibleForms shipped
its fallback in the source tree, in the open, as a
convenience for deployments that never set the variable.
Open OnDemand computed its passphrase from the server name,
a value any remote attacker can know or guess, and then
hid the fact behind a template that reads a different
variable from the one the documentation names. In both
cases the attacker mints the credential on demand, from
public information, without touching the victim at all.
There is no theft to detect and no revocation to race: the
string is valid because the key that signed it is public.

The proof-key-hands test passes for both. The forger holds
no proof key for the victim — he holds the *signing* key,
which is a different thing, and the difference is the whole
point. A sender-constrained token is two objects, not one:
the string and the key that must present it. Forging the
string without the key buys the attacker a token no
resource server will honour. That is the same answer the
series gave for Kener, nest-admin, OpenDeepWiki, and
BISHENG: the forged string is unredeemable without the
holder's private key.

The honest boundary, as ever: DPoP does not fix the
underlying bug. AnsibleForms deployments must set
`ACCESS_TOKEN_SECRET` and upgrade to 6.2.1; Open OnDemand
deployments must upgrade and confirm the passphrase
actually took effect — the template mismatch means
"configured" and "protected" were different states, and
the gap between them is where forged cookies kept
working. Two further limits, specific to these cases:
the Open OnDemand object is an OIDC session cookie, not
an OAuth access token, so the DPoP angle is the
sender-bound-credential shape rather than RFC 9449
itself (the same boundary the series drew for OpenAM
#45049); and server-cache deployments of Open OnDemand
were never exposed to full session forgery, only to
state and nonce tampering — the blast radius tracks the
deployment mode. What the pair gives the series is the
count: twelve times now, the secret that signed the token
was public by design or by arithmetic, and twelve times
the fix has been "rotate the secret, then make the token
worthless without its key."
