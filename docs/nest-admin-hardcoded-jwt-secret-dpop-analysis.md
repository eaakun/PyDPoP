# Twenty-One Token Thefts, One Missing Control

## The incident

**CVE-2026-117564** (CRITICAL, CVSS 3.1 9.8, `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`,
NVD-published 2026-10-27) in **nest-admin** (a NestJS admin-panel scaffold,
GitHub `buqiyuan/nest-admin`), versions before 1.0.1:

- The repository's `.env.production` shipped a **hardcoded `JWT_SECRET`**
  (CWE-321, use of hardcoded cryptographic key), committed in the open.
- An **unauthenticated** attacker signs their own JWT with the public key,
  and the server's `JwtStrategy` and `RbacGuard` accept it as-is — any
  user ID, or the admin role directly, for full administrative access.
- The fix is in **1.0.1** (commit `f2cec8cb`, "remove hardcoded JWT key
  and reject weak keys at startup", fixing issues #92 and #93): the
  committed env files are gone, replaced by `.example` templates, and the
  server now refuses to boot on a weak key. But upgrading alone is not
  enough for already-deployed instances — tokens signed with the old key
  stay valid until the key is **rotated**.
- Sources: NVD record for CVE-2026-117564; nest-admin issues #92/#93;
  fix commit `f2cec8cb`.

## Why it's DPoP-shaped

Another "the string is the identity" forgery — and the fourth occurrence
of the same mistake in this series' forgery family (#8 Hitachi, #9
mcp-context-forge, #20 Kener). The difference here is the forged object:
not a session cookie, but a **standard JWT access token itself**, which
puts it squarely on DPoP's home ground. A sender-constrained token
changes the deal: the string alone is not sufficient, because presenting
it requires the client's proof key, which the forger never had. The
forged JWT would still be *issued* — DPoP does not police issuance —
but it could not be *redeemed* against a resource server that checks
the binding.

## Notes / honesty checks

- DPoP does **not** fix the hardcoded key, and it is not a substitute
  for the actual remediation — delete the committed key, rotate it, and
  upgrade to 1.0.1. What it changes is only the post-forgery half: a
  minted string that cannot be presented without a proof key.
- Scope, stated plainly: only deployments still running on the
  repository's bundled `.env.production` key are exploitable. A
  deployment that replaced it with its own strong key is not affected.
- Scale, stated plainly: nest-admin is a small scaffold, not a large
  platform — the CRITICAL score describes the weakness, not the blast
  radius. Its value in this series is as the fourth data point that the
  same error keeps shipping.
