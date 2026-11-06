# Twenty-Seven Token Thefts, One Missing Control

## The incident

**CVE-2026-120209, AJ-Report through 1.7.1** (CRITICAL 9.8 CVSS 3.1 /
9.3 CVSS 4.0, CWE-321, published 2026-10-31):

- AJ-Report signs its Share-Tokens with a hardcoded JWT secret, the
  same on every install. An unauthenticated attacker can forge a valid
  Share-Token offline — no account, no password, no interaction with
  the victim at all.
- The forged token, minted with reportCode `dataSet`, passes a
  substring check on the request path and reaches the `testTransform`
  endpoint without authentication. That endpoint hands scripts to
  `GroovyClassLoader` — so a forged token is not a forged session,
  it is unauthenticated remote code execution.
- The public issue report names V1.4.2 through V1.7.1 as affected.
  As of publication, the CVE record names no fixed version — checked
  at publish time against the NVD record and secondary trackers, which
  agree: no fixed release is listed. Do not read that as "never
  fixed"; it means no fix had been published when this went out.
- Sources: NVD record for CVE-2026-120209; VulnCheck advisory
  "AJ-Report through 1.7.1 Authentication Bypass leading to RCE
  via Share-Token".

## Why it's DPoP-shaped

This is the forgery family the series has tracked since #8
(Hitachi), #9 (mcp-context-forge), #20 (Kener), #21 (nest-admin),
and #26 (OpenDeepWiki / ng-antd-admin) — "the string is the
identity", with the key not stolen but shipped. The difference here
is the ceiling: the forged token's endpoint is not an admin panel,
it is a Groovy code-execution endpoint. The same failure, one notch
higher on the harm scale.

A sender-constrained token changes that deal: the string alone is
not sufficient without the holder's private key, so a forged string
minted from a known secret fails presentation. The honest boundary,
as ever: DPoP does not fix a hardcoded secret. The secret still has
to be removed, rotated, and the release upgraded when one exists;
what DPoP changes is whether the forged string is worth anything
afterwards.

AJ-Report is a Java project; per the series' rule, this is analysis
only, no pydpop plug.
