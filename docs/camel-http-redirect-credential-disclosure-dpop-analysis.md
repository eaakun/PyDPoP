# Thirteen Token Thefts, One Missing Control

## The incident

Apache Camel's October 2026 security batch (38 CVEs, disclosed ~2026-10-19;
fixes in 4.23.0 / 4.18.5 / 4.22.1) includes **CVE-2026-85251** (HIGH, CVSS
7.5), in the `camel-http` component:

- Affected: Apache Camel from 4.0.0 before 4.18.5, from 4.19.0 before
  4.22.1 (`camel-http`, with `followRedirects=true`).
- Two paths handed credentials to a redirect target chosen by the remote
  server: `OAuth2ClientConfigurer` registered its interceptor with
  `addRequestInterceptorFirst`, and HttpClient runs protocol-level request
  interceptors inside `ProtocolExec`, which sits below `RedirectExec` in
  the exec chain — so the interceptor ran again for every redirect hop and
  re-attached `Authorization: Bearer <token>` to whatever host the
  `Location:` header named. Separately, basic/digest credentials were
  registered against an `AuthScope` matching any host.
- Consequence: a remote endpoint — or anyone who can influence its
  responses — could collect the bearer token or the configured credentials
  simply by answering with a redirect to an attacker-controlled host.
- Sources: https://camel.apache.org/security/CVE-2026-85251.html (official
  advisory); NVD record (published 2026-10-19); coverage of the 38-CVE
  batch: https://trustlist.uk/security-advisories/apache-camel-38-cves-fixed-4-18-5-4-22-1-4-23-0-jgroups-deserialization-4-14-end-of-life

## Why it's DPoP-shaped

This is bearer-string theft in its purest network form: the attacker's
reward for issuing one redirect is a token that **any holder can spend**.
The vendor fix (credentials only to the configured authority) closes this
door; DPoP (RFC 9449) closes the *class*: a DPoP-bound access token
captured at a malicious redirect target is unreplayable without the
client's proof-of-possession private key. The redirect still leaks a
string; the string no longer buys access. Series thesis, again:
**the server authenticates a string, not a holder**.

## Notes / honesty checks

- DPoP neutralizes the *stolen bearer token* but does not prevent the leak
  itself — basic/digest credentials exfiltrated the same way are still
  stolen. Say both explicitly.
- This is the same enabling condition as CVE-2026-89111 (SAP Cloud SDK,
  OAuth2 SSRF): the server sends the credential to an attacker-chosen
  destination. Different component, same "trust the destination" failure.
- Apache Camel is Java; pydpop is Python. No product plug — "shape of the
  fix" narrative only, consistent with the mcp-remote #377 approach.
