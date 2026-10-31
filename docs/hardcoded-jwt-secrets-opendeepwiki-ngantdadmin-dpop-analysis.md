# Twenty-Six Token Thefts, One Missing Control

## The incident

Two hardcoded-JWT-secret forgeries, published the same day
(2026-10-30), make one entry — because together they show both halves
of the same delivery failure.

**CVE-2026-119597, OpenDeepWiki through 2.0.6** (CRITICAL 9.3,
CWE-321, AIDotNet/OpenDeepWiki, ~3.6k stars):

- `appsettings.json` carries a publicly known `Jwt:SecretKey`. An
  unauthenticated attacker can mint HS256 bearer <redacted> with an Admin
  role claim and walk into `/api/admin` endpoints, controlling users,
  roles, repositories, settings, and API keys.
- A fix commit (2026-10-22) is on main, but the CVE record lists no
  fixed version and the latest release is still 2.0.6 (2026-09-08):
  the patch exists and has not shipped. Existing deployments stay
  exposed until a release carries it.
- Sources: NVD record for CVE-2026-119597; the OpenDeepWiki fix
  commit and issue #403.

**CVE-2026-61737, ng-antd-admin before 22.0** (CRITICAL 9.8,
GHSA-qphq-m2hv-wj5h):

- The project shipped a hardcoded default JWT secret. A deployment
  that never replaced the default — with no startup warning triggered
  — lets an attacker trivially forge valid JWT tokens, impersonate any
  user including administrators, and reach protected API endpoints:
  complete account takeover.
- This is a retrospective disclosure: the fix shipped in v22.0 (the
  default secret removed, the secret required to be injected via
  environment variables, the application refusing to start without
  one). Old deployments that never upgraded stay exposed anyway.
- Sources: GitHub Security Advisory GHSA-qphq-m2hv-wj5h (verified
  against the advisory record at publish time).

## Why it's DPoP-shaped

Both are the same family the series has tracked since #20 and #21 —
"the string is the identity" — with the key not stolen but shipped.
When the signing secret is public or default, anyone can mint the
string, and the string alone opens the door. A sender-constrained
token changes that deal: the string is not sufficient without the
holder's private key, so a forged string minted from a known secret
fails presentation. The honest boundary, as ever: DPoP does not fix a
hardcoded secret. The secret still has to be replaced; what DPoP
changes is whether the forged string is worth anything afterwards.

The pair is worth one entry rather than two because the contrast is
the lesson, and it runs in both directions. OpenDeepWiki fixed the
code and has not shipped the fix; ng-antd-admin shipped the fix and
deployments have not followed it. "Patched" and "protected" are
different states, and the gap between them — unreleased fix on one
side, unupgraded deployment on the other — is where these tokens keep
getting forged. Shipping the patch and landing the patch are two
different jobs, and both have to happen.

Both projects are non-Python (OpenDeepWiki .NET, ng-antd-admin
Angular + NestJS); per the series' rule, this is analysis only, no
pydpop plug.
