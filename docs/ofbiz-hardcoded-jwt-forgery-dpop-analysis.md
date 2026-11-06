# Thirty Token Thefts, One Missing Control

## The incident

**CVE-2026-105330, Apache OFBiz 24.09.06 / 24.09.07** (CWE-321,
no CVSS yet — NVD Awaiting Analysis; Apache oss-security
announcement 2026-11-04 lists it in the 24.09.08 batch of 46
defects, "some critical issues"):

- The factory-default `security.token.key` signs JWT SSO tokens.
  Deployments that upgraded from a release predating the
  CVE-2026-31986 fix while retaining their existing
  `security.properties`, with `security.internal.sso.enabled` set
  to true, let an unauthenticated, network-reachable attacker forge
  any JWT with the publicly known default key — and walk straight
  into full administrative access. Fresh installs are unaffected:
  CVE-2026-31986 already removed the default from newly generated
  configurations.
- The detail that makes this entry worth writing: upgrading to
  24.09.08 is not enough. An already-configured key is not replaced
  by the upgrade — deployments that carried
  `framework/security/config/security.properties` forward must also
  run `./gradlew rotateSecretKeys` afterwards, because the existing
  `generateSecretKeys` task leaves an already-set value untouched.
  "Upgraded" and "fixed" are different states, and the gap between
  them is a live forgery window.
- The sibling in the same batch, CVE-2026-97356, is the same lesson
  from the other side: an authenticated user holding only
  `LABEL_MANAGER_VIEW` can read arbitrary properties and XML files
  through the ViewFile component — including the generated JWT
  signing key — and forge an administrator session. The signing key
  is a single point of failure, and this batch attacks it twice.
- Sources: NVD record for CVE-2026-105330; Apache oss-security
  announcement 2026-11-04 (46 defects, fixed in 24.09.08).

## Why it's DPoP-shaped

The forgery family, now at its most mainstream: #8 (Hitachi), #9
(mcp-context-forge), #20 (Kener), #21 (nest-admin), #26
(OpenDeepWiki / ng-antd-admin), and #27 (AJ-Report) all turned on
a hardcoded or default signing key — and OFBiz is the Apache
project in that line, the one with the longest upgrade tail. A
sender-constrained token changes that deal: the string alone is not
sufficient without the holder's private key, so a forged string
minted from a known secret fails presentation. The honest boundary,
as ever: DPoP does not fix the key. The fix is upgrading to
24.09.08 *and* rotating the key; what DPoP changes is whether the
forged string is worth anything afterwards.

OFBiz is a Java project; per the series' rule, this is analysis
only, no pydpop plug.
