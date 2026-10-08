# Two Token Thefts in One Week, One Missing Control

The MCP ecosystem learned the same lesson twice this week.

**Case 1: the MCP SDKs (CVE-2026-104850, HIGH 7.5).** A malicious MCP server could name its own authorization server during OAuth discovery. The SDK never validated the issuer it ended up talking to, so clients handed over refresh tokens, client secrets, authorization codes — even PKCE verifiers. No user interaction required.

**Case 2: Splunk MCP Server (CVE-2026-76286, MEDIUM, advisory SVD-2026-1004, published October 7).** Running someone else's custom API tool sent your Splunk platform authentication token to whatever URL that tool had configured. Attacker-controlled URL, attacker-held token, full impersonation.

Different products, different codebases, identical failure mode: a bearer token ends up where it shouldn't be, and because it is a bearer token, possession equals access. The attacker never has to break crypto. They just have to be handed the key.

The missing control in both cases is sender-constrained tokens. RFC 9449 (DPoP) binds each token to a keypair the client holds; a stolen token presented without the matching proof JWT is rejected at the authorization server. In case 1, the thief's loot could never have been redeemed. In case 2, the exfiltrated platform token would have been dead on arrival. The MCP authorization spec already mandates DPoP for exactly this reason — the ecosystem has now demonstrated, twice in seven days, why the requirement exists.

I maintain pydpop ([github.com/eaakun/PyDPoP](https://github.com/eaakun/PyDPoP), `pip install pydpop`): a pure-RFC 9449 DPoP library for Python — ES256 proof generation plus full server-side verification, one dependency, 37 tests, [live demo](https://huggingface.co/spaces/tatkuen/pydpop-demo). If this week sent you rotating secrets, DPoP is the control that makes the next theft a non-event.

---

**Sources**

- CVE-2026-104850 (MCP TypeScript SDK): https://nvd.nist.gov/vuln/detail/CVE-2026-104850
- CVE-2026-76286 (Splunk MCP Server): https://nvd.nist.gov/vuln/detail/CVE-2026-76286
- Splunk advisory SVD-2026-1004: https://advisory.splunk.com/advisories/SVD-2026-1004
