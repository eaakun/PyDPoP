# Nineteen Token Thefts, One Missing Control

## The incident

**CVE-2026-110975** (HIGH, CVSS 3.1 7.4, `AV:A/AC:L/PR:N/UI:N/S:C/C:H`,
published 2026-10-23) in **Kruize Autotune** (Red Hat's container
right-sizing / OpenShift monitoring tooling):

- The REST API **ships without an authentication layer**, and the
  endpoints that return datasource configuration — `GET /datasources`
  and the datasource-metadata endpoint — serialize datasource objects
  with a **default Gson configuration and no field-exclusion
  strategy**.
- As a result, the authentication secrets stored for each configured
  monitoring datasource — basic-auth passwords, **bearer tokens**,
  API keys, and OAuth2 client secrets — are returned **in cleartext to
  any client able to reach the service**. An attacker with network
  access harvests them and reuses them to authenticate to the backing
  monitoring stack (CWE-256, plaintext storage of a password… here
  plaintext disclosure of everything).
- Sources: NVD record (published 2026-10-23); Red Hat CVE page and
  Bugzilla 2512012; fix in kruize/autotune PR #2038 (field exclusion
  on serialization).

## Why it's DPoP-shaped

This is the stolen-string class again, one drawer down from the pure
"token theft" specimens: the harvested bearer tokens are meant to be
presented to the backing monitoring stack, and today the string alone
is sufficient. If those tokens were sender-constrained (RFC 9449
DPoP), the disclosed strings would be **unreplayable without the
client's proof key** — the exfiltration still happens, but the
harvested bearer material is inert. Same family as the series'
stored-token-replay case (CVE-2026-63160, Omnispace Agora
remember-me token replay from a DB dump): the store leaks, the
binding survives the leak.

## Notes / honesty checks

- The honest boundary is narrower here than usual: DPoP neutralizes
  only the **bearer-token portion** of the disclosure. Static
  basic-auth passwords, API keys, and OAuth2 client secrets are not
  OAuth access tokens — DPoP does not bind them, and nothing about
  this write-up should imply otherwise.
- The primary fixes are an authentication layer on the REST API and
  the serialization field exclusion (PR #2038) — both server-side,
  both first. DPoP is defense-in-depth against the next store-or-API
  disclosure, not a substitute.
- Attack vector is `AV:A` (adjacent network), so the exposure
  requires network reach to Autotune — scope the blast radius honestly;
  it is not an internet-remote grab.
- Java project; pydpop is Python. No product plug — "shape of the
  fix" narrative only.
