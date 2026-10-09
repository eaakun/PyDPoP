# Three Token Thefts, One Missing Control

This week gave the ecosystem its third data point.

**Case 3: Eclipse Ditto Explorer (CVE-2026-107503, HIGH, published October 8).** Ditto Explorer 3.6.0–3.9.7 accepted a crafted link that injected an attacker-controlled OIDC authority while auto-SSO was on. The victim logged in at the *real* identity provider, but the authorization code and the PKCE verifier were delivered to the *attacker's* token endpoint. The attacker then redeemed the victim's access and refresh tokens directly; a second variant of the same flaw leaked Bearer and Basic credentials outright.

This is the same failure mode as the two cases from last week — the MCP SDKs (CVE-2026-104850) and the Splunk MCP Server (CVE-2026-76286): a bearer artifact ends up in the wrong hands, and because possession equals access, the theft is already the exploit. There are now three independent codebases, three weeks apart, all teaching the same lesson.

The missing control is still sender-constrained tokens. RFC 9449 (DPoP) binds the token request itself to a keypair the client holds: redeeming a stolen authorization code + PKCE verifier requires a DPoP proof signed by the victim's private key, which the attacker never has. Even if a token were exfiltrated, presenting it without the matching proof gets rejected at the resource server. In this case, the attacker's entire redemption chain dies at step one.

The MCP authorization spec already mandates DPoP for exactly this reason. Ditto is not an MCP project, but the lesson travels: wherever an OAuth client can be tricked into talking to the wrong endpoint, DPoP is the backstop that turns stolen artifacts into dead paper.

I maintain pydpop ([github.com/eaakun/PyDPoP](https://github.com/eaakun/PyDPoP), `pip install pydpop`): a pure-RFC 9449 DPoP library for Python — ES256 proof generation plus full server-side verification, one dependency, 37 tests, [live demo](https://huggingface.co/spaces/tatkuen/pydpop-demo). If this week sent you rotating secrets, DPoP is the control that makes the next theft a non-event.

---

**Sources**

- CVE-2026-107503 (Eclipse Ditto Explorer): https://nvd.nist.gov/vuln/detail/CVE-2026-107503
- Eclipse Ditto security advisory (GitHub): https://github.com/eclipse-ditto/ditto/security/advisories
- CVE-2026-104850 (MCP TypeScript SDK): https://nvd.nist.gov/vuln/detail/CVE-2026-104850
- CVE-2026-76286 (Splunk MCP Server): https://nvd.nist.gov/vuln/detail/CVE-2026-76286
