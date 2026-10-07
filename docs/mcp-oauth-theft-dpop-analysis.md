# The MCP OAuth Credential Theft, and the DPoP Backstop Nobody Mentions

On September 28, the MCP Python SDK maintainers published a GitHub security advisory for a high-severity OAuth flaw, found by Cycode's researcher (reported late July, fixed mid-September). A malicious or compromised MCP server could steal a client's OAuth credentials — client secret, authorization code, even the PKCE verifier — with the victim seeing nothing but a genuine login page before the server "failed." CVE-2026-104850, covering the same flaw class in the TypeScript SDK, was published October 6. CVSS 7.5 for unattended (machine-to-machine) flows, 6.5 for interactive sign-in. No in-the-wild exploitation has been reported.

## How the theft works

The SDK asks the MCP server where its authorization server lives, then never consistently checks that the issuer it ends up talking to is the issuer it expected. A rogue server publishes metadata naming its own token endpoint, and the client hands over everything it stored from a legitimate earlier sign-in.

Two details make it worse than a garden-variety token leak. First, the stolen PKCE verifier defeats PKCE itself — the mechanism whose entire job is stopping a stolen authorization code from being reused. Second, the client secret outlives the session: the attacker can keep minting fresh tokens with the client's full permissions until someone manually rotates the secret. Bearer credentials, once exfiltrated, are fully reusable. That reusability is the whole ballgame.

## The official fix — and what it admits

Upgrade to 1.30.0/2.2.0, explicitly pin `issuer=` on the unattended providers, clear stored dynamic registrations, rotate secrets, revoke tokens. Note the advisory's own caveat: upgrading alone is insufficient. Every step after the patch is manual cleanup, and every credential already leaked stays valid until a human intervenes. The remediation is "stop the bleeding, then mop up by hand" — which is an honest description of where bearer-token architectures leave you.

## The layer nobody mentions

RFC 9449 (DPoP) binds tokens to a keypair the client holds: each request carries a proof JWT signed with the client's private key, and the authorization server rejects tokens presented without a matching proof. Be precise about what changes:

- DPoP would **not** have prevented the misdirected send. The client still posts to the attacker's endpoint. It is not an issuer-validation mechanism, and claiming otherwise would be dishonest.
- DPoP **would** have made the stolen tokens worthless. Refresh and access tokens bound to the client's key can't be redeemed by the thief at the real authorization server — the proof check fails without the private key, and unlike the PKCE verifier, the private key never leaves the client. There is nothing to steal.

That's the defense-in-depth point the coverage skipped: issuer validation is the primary fix; DPoP is the backstop for the day validation fails. The MCP authorization spec mandates DPoP sender-constrained tokens for exactly this reason — and the ecosystem's own reference SDK just demonstrated, in production, the failure mode the requirement was written for.

## Why I'm writing this

I maintain pydpop ([github.com/eaakun/PyDPoP](https://github.com/eaakun/PyDPoP), `pip install pydpop`): a pure-RFC 9449 DPoP library for Python — ES256 proof generation plus full server-side verification, one dependency, 37 tests, [live demo](https://huggingface.co/spaces/tatkuen/pydpop-demo). Python had no spec-compliant DPoP library (Authlib's DPoP issue has been open since 2021), so I wrote one. If this advisory sent you rotating secrets last week, DPoP is the control that makes the next theft a non-event.

Every SDK will have a bug eventually. Bearer tokens make every bug a skeleton key. DPoP exists, the spec requires it, and the tooling is finally here.

---

**Sources**

- CVE-2026-104850 (TypeScript SDK): https://nvd.nist.gov/vuln/detail/CVE-2026-104850
- Advisory summary (Python SDK, Sept 28): https://www.isec.news/2026/09/29/mcp-python-sdk-oauth-credential-theft/
- Attack mechanics: https://expertinsights.com/news/python-sdk-flaw-lets-rogue-mcp-servers-hijack-oauth-accounts
