# Fifty-Five Token Thefts, One Missing Control

## The incident

openIMIS before 2026-10 lets an authenticated user with a single
ordinary read right walk out with another user's JWT signing key — and
then mint that user's session. Two CVEs, one flaw class, published the
same day:

- CVE-2026-82491 (HIGH 8.8): the core export mixin rewrites
  caller-controlled dotted field paths into Django ORM syntax without an
  allow-list, so a path such as `user_created.i_user.private_key`
  exports another user's JWT signing key.
- CVE-2026-82492 (HIGH 8.8): the deduplication service checks only the
  first segment of a dotted column path before using the full
  unvalidated path in the query — `user_created__i_user__private_key`
  retrieves an administrator's JWT signing key the same way.

With the key, the attacker forges valid authenticated sessions for other
accounts, including administrators — no password, no failed-login event,
and no invalidation by password reset.

- Affected: openIMIS (openimis-be-core_py / openimis-be-deduplication_py)
  before 2026-10; fixed in Release 2026-10.
- Sources: NVD records (CVE-2026-82491, CVE-2026-82492); VulnCheck
  advisories
  https://www.vulncheck.com/advisories/openimis-2026-10-core-export-mixin-information-disclosure-via-dotted-field-paths
  and
  https://www.vulncheck.com/advisories/openimis-2026-10-deduplication-service-dotted-path-validation-bypass;
  release notes
  https://openimis.atlassian.net/wiki/spaces/OP/pages/5166989313/Release+2026-10.

## Why it's DPoP-shaped

The forgery family's seventeenth occurrence — and its purest
key-disclosure variant. In the hardcoded-secret cases (#8, #9, #20,
#21, #26, #27, #34, #35, #37, #40, #44, #47, #48) the key was never
secret; here the key *was* secret, and an allow-list omission handed
it to any authenticated user with one read right. The economics are
identical: the string is the identity, so whoever holds the signing
key mints whoever they want. Sender-constrained issuance changes what
a stolen *token string* is worth — a DPoP-bound access token issued to
the victim cannot be presented by the attacker's hand — and it is the
reason the forgery has to mint a fresh token rather than replay a
captured one. A fresh token minted under the victim's signing key is
exactly what key rotation kills.

## Notes / honesty checks

- DPoP does not fix the dotted-path traversal or the key disclosure;
  the patch is Release 2026-10, and every exposed signing key must be
  rotated — password resets do not invalidate forged sessions.
- The attacker is authenticated, with one ordinary read right — a low
  bar, but a bar: this is not an unauthenticated forgery.
- openIMIS is a health-insurance management system deployed by
  governments and NGOs; the blast radius of a forged administrator
  session is enrollee and claims data, not just the application itself.
