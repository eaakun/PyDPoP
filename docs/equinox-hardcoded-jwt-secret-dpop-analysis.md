# Fifty-Seven Token Thefts, One Missing Control

## The incident

EduardoPires/EquinoxProject — a .NET DDD sample with 6,785 stars —
ships its JWT signing key in the repository (CVE-2026-136733, HIGH 7.3,
CWE-259, published 2026-11-25). `AppSettings.SecretKey` is
`fmFGn5agHZkuG2N0e1zaEJIQtGVoNN5P`, committed in
`appsettings.Development.json` (and the same value in Staging and
Testing), with no warning on startup when the default is in use. Anyone
who reads the repo can forge any user's JWT — administrators included —
and walk past authentication and authorization entirely.

- Affected: EquinoxProject (all versions shipping the default secret);
  no fix as of publication. Issue #219, opened 2026-06-16, is still
  unanswered, and the repository's last push was 2026-04-14.
- Sources: NVD record (CVE-2026-136733); upstream issue
  https://github.com/EduardoPires/EquinoxProject/issues/219; the secret
  is visible in the repository at
  `src/Equinox.Services.Api/appsettings.Development.json`
  (verified 2026-11-26, default branch `master`).

## Why it's DPoP-shaped

The forgery family's eighteenth occurrence — and its most literal
since Kerberos Agent's `TOBECHANGED` (#48). The comment above the key
reads "Always use strong keys like that": the key *is* strong, and
that is precisely the point — a strong secret that is public is not a
secret. The fix is environment-variable secrets and refusing to start
on defaults; sender-constrained issuance is what makes the forged
string unredeemable even while the secret is still public, because a
DPoP-bound token is useless without the private key that produced the
proof.

## Notes / honesty checks

- Retrospective disclosure: the issue was filed in June 2026 and the
  CVE published in November. The exposure is live, not historical —
  the secret is still in the repository today.
- Only deployments running the shipped default are affected; a
  deployment that replaced the secret is safe from this exact string.
  The series documents the class, and the class here is "the sample
  became the deployment".
- DPoP does not fix the hardcoded secret; it neutralizes the
  replayability of any bearer token of this shape. Say so explicitly.
