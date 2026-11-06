# Twenty-Eight Token Thefts, One Missing Control

## The incident

**CVE-2026-105769, kaniko before 1.25.20** (CRITICAL 9.3, CVSS
3.1 AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H, published 2026-11-02,
GHSA-5q7h-w9jf-cx97):

- kaniko builds container images from Dockerfiles, and its Azure
  Container Registry credential helper,
  `docker-credential-acr-env`, decides whether a host is an ACR
  registry with an unanchored regular expression: any hostname
  containing `.azurecr.io`, `.azurecr.cn`, `.azurecr.de`, or
  `.azurecr.us` is accepted.
- A Dockerfile that references an image on a lookalike host — `FROM
  x.azurecr.io.attacker.com/img`, or `COPY --from=` the same —
  causes the helper to obtain a token from the build's Azure identity
  (service principal environment variables, federated workload
  identity token, or managed identity) and POST it to
  `https://<host>/oauth2/exchange`. The attacker can then use the
  token against Azure Resource Manager with the identity's role
  assignments until it expires, and exchange it for credentials to
  any ACR registry the identity can access.
- No RUN instruction or push is required. The trigger needs user
  interaction — the victim has to build a Dockerfile that references
  the lookalike host — but once triggered, nothing else is needed.
- Fixed in 1.25.20 (Chainguard fork).
- Sources: NVD record for CVE-2026-105769; GitHub Security Advisory
  GHSA-5q7h-w9jf-cx97.

## Why it's DPoP-shaped

Same family as #13 (Camel re-attaching `Authorization: Bearer` to
redirect targets) and #6 (mcp-remote transmitting tokens in
cleartext): a bearer token delivered to the wrong party, replayed
as-is. The difference is the delivery layer — not a redirect, not
cleartext, but a credential helper that recognizes kin by hostname
suffix. The token itself never had to be stolen; it was handed over
by the victim's own tooling, to a host that merely *contained* the
right string.

A sender-constrained token changes that deal: the string alone is
not sufficient without the holder's private key, so a token that
arrives at the wrong host is dead on arrival. The honest boundary,
as ever: DPoP does not fix the regex. The fix is upgrading to
1.25.20 and anchoring the host match — and Entra ID issues plain
bearer tokens in this exchange flow today, so the DPoP angle is
conditional on sender-bound issuance. The upgrade is the cure;
DPoP is the depth.

kaniko is a Go project; per the series' rule, this is analysis
only, no pydpop plug.
