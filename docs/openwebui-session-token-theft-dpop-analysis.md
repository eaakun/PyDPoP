# Five Token Thefts, One Missing Control

Open WebUI is the self-hosted ChatGPT-style interface a large share of the local-AI world runs in front of Ollama — including teams who chose it precisely to keep proprietary chats off third-party servers. On September 27–28 it published a batch of security advisories, all fixed in 0.11.4. The worst of them is GHSA-vpq8-f445-hcq7: High, CVSS 8.1, affecting every version from 0.7.0 up.

The bug: the community-stats feature's message listener never checked `event.origin`. Any website visited by a signed-in user — in the same browser — could open Open WebUI in a popup and receive that user's session token. No attacker account needed, no admin action. The token grants full API access as the victim: private chats, everything the role can do. And because the attack runs entirely in the user's own browser, keeping the server on the LAN or behind a VPN doesn't help.

Two details make this one sting. First, the precondition is `ENABLE_COMMUNITY_SHARING`, which is on by default — the vulnerable configuration is the out-of-box one. Second, none of the advisories in this batch has a CVE ID, and as of October 11 they are in neither the GitHub Advisory Database nor OSV. Dependency scanners that read those feeds will report a 0.11.1–0.11.3 install as clean. Your scanner won't tell you; check Settings > About yourself.

The batch's siblings are the same story in miniature: viewer token theft through `javascript:` links in chat messages (GHSA-wf9m-46cp-c6h6), through shared chats' citations (GHSA-qpqv-xwg8-cqpj, High), and other users' session tokens leaking through OAuth-mode connections.

Different app, different bug, identical failure mode — the fifth time in this series: a bearer credential ends up in the wrong hands, and because it is a bearer token, possession equals access. The attacker never breaks crypto; they just get handed the key.

To be precise about what DPoP can and cannot do here: RFC 9449 would not have fixed the missing origin check — that is an application bug, and the patch (0.11.4, then 0.12.0 on October 10) is the fix. What sender-constrained tokens change is the economics of the theft. A DPoP-bound token is useless without the client-held proof key: the attacker's popup receives a token it cannot redeem. The patch closes this hole; the control makes the next theft a non-event. These are session tokens rather than OAuth access tokens, but the principle generalizes — anywhere a bearer credential is the whole of authentication, binding it to the holder is the missing control.

I maintain pydpop ([github.com/eaakun/PyDPoP](https://github.com/eaakun/PyDPoP), `pip install pydpop`): a pure-RFC 9449 DPoP library for Python — ES256 proof generation plus full server-side verification, one dependency, 39 tests, [live demo](https://huggingface.co/spaces/tatkuen/pydpop-demo). If this month sent you rotating secrets, DPoP is the control that makes the next theft a non-event.

---

**Sources**

- GHSA-vpq8-f445-hcq7 (Open WebUI): https://github.com/open-webui/open-webui/security/advisories/GHSA-vpq8-f445-hcq7
- "Open WebUI before 0.11.4…" writeup, 2026-10-11 (checked its claims against the advisory on 2026-10-11): https://dev.to/munimv2/open-webui-before-0114-any-website-you-visit-could-take-your-session-token-and-your-scanner-30dd
