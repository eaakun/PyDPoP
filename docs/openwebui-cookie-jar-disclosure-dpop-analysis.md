# Seven Token Thefts, One Missing Control

Open WebUI is the self-hosted ChatGPT-style interface a large share of the local-AI world runs in front of Ollama — including teams who chose it precisely to keep proprietary chats off third-party servers. Two days ago this series covered its fifth theft: an unchecked `postMessage` origin handing session tokens to any website the victim visited (GHSA-vpq8-f445-hcq7). That analysis mentioned, almost in passing, a sibling issue: session tokens leaking through OAuth-mode connections. It now has its own CVE number — CVE-2026-109292, published October 12, Medium — and it deserves the full treatment, because the failure mode is even more brazen.

The bug: when Open WebUI talks to a third-party server over an OAuth-mode connection — an OpenAI-compatible endpoint, an OpenAPI tool server, a terminal server — it forwards the user's **entire browser cookie jar** with the request. Not the credential that connection needs. Everything. The operator of that destination server can lift the victim's session cookies out of routine traffic and replay them to hijack the account, administrators included. No exploit chain, no phishing, no attacker account: the victim's own configured integration does the exfiltration.

Two details make this one sting. First, the fifth analysis in this series already flagged OAuth-mode leaks as an un-CVE'd sibling on October 11; twenty-four hours later it is CVE-2026-109292. The same codebase was handing out session tokens through two different doors at once. Second, both doors were closed by the same release — 0.11.4. One patch version, two session-token thefts, thirty days. If you run anything before 0.11.4, both advisories apply to you.

Different app, different bug, identical failure mode — the seventh time in this series: a Bearer token ends up in the wrong hands, and because it is a Bearer token, possession equals access. The attacker never breaks crypto; the application mails them the key.

To be precise about what DPoP can and cannot do here: RFC 9449 would not have fixed the forwarding — shipping the ambient cookie jar to third parties is an application bug, and the patch (stop forwarding it, 0.11.4) is the fix, full stop. What sender-constrained tokens change is the economics of the theft. A DPoP-bound token is useless without the client-held proof key: the destination server collects a session cookie it cannot redeem anywhere else. The patch closes this hole; the control makes the next theft a non-event. These are session cookies rather than OAuth access tokens, but the principle generalizes — anywhere a Bearer token is the whole of authentication, binding it to the holder is the missing control.

I maintain pydpop ([github.com/eaakun/PyDPoP](https://github.com/eaakun/PyDPoP), `pip install pydpop`): a pure-RFC 9449 DPoP library for Python — ES256 proof generation plus full server-side verification, drop-in integrations for httpx/requests/aiohttp and FastAPI/Django/Flask/Starlette, post-quantum hybrid algs, v0.2.1 on PyPI, [live demo](https://huggingface.co/spaces/tatkuen/pydpop-demo). If this month sent you rotating secrets, DPoP is the control that makes the next theft a non-event.

---

**Sources**

- CVE-2026-109292 (NVD): https://nvd.nist.gov/vuln/detail/CVE-2026-109292
- GHSA-gqfh-jxvw-74rp (Open WebUI): https://github.com/open-webui/open-webui/security/advisories/GHSA-gqfh-jxvw-74rp
- VulnCheck advisory "open-webui 0.6.27 before 0.11.4 session token disclosure via OAuth-mode connections": https://www.vulncheck.com/advisories/open-webui-0.6.27-before-0.11.4-session-token-disclosure-via-oauth-mode-connections
