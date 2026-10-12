# Six Token Thefts, One Missing Control

mcp-remote is the bridge half the MCP world quietly depends on: Claude Desktop and other stdio-only clients use it to talk to remote MCP servers. Version 0.8.0 through 0.14.3 (1,624 stars, punkpeye/mcp-remote) shipped a flaw in its device-code OAuth flow — CVE-2026-108716, published October 11, 2026, Medium 5.3.

The bug: `authorizeWithDeviceCode` never enforces HTTPS. When the discovered device-authorization and token endpoints are non-loopback plain-HTTP URLs, the client sends its client secret and receives the issued access and refresh tokens over the wire in cleartext. Any on-path network attacker — a rogue proxy, a compromised middlebox, anyone on the same hostile network segment — can sit there and collect them: client secret plus live tokens, no exploit chain required. The vulnerable code is in `client-credentials.ts` and `device-authorization.ts`; VulnCheck published an advisory the same day.

Two details make this one sting. First, the device-code flow exists precisely for input-constrained clients that can't do a browser dance — exactly the MCP client case — so the broken path is the one most of its users walk. Second, the captured goods are the long-lived kind: refresh tokens and client secrets keep working until someone rotates them, which means a passive listener gets persistent access to whatever the victim's MCP connection could reach.

Different app, different bug, identical failure mode — the sixth time in this series: a bearer credential ends up in the wrong hands, and because it is a bearer token, possession equals access. The attacker never breaks crypto; they just read the wire.

To be precise about what DPoP can and cannot do here: RFC 9449 would not have fixed the cleartext transport — enforcing HTTPS on non-loopback endpoints is the patch, full stop. Nor would it protect the client secret captured on the wire. What sender-constrained tokens change is the economics of the theft. A DPoP-bound access token is useless without the client-held proof key: the on-path attacker collects a token they cannot redeem. The TLS fix closes this hole; the control makes the next theft a non-event. Anywhere a bearer credential is the whole of authentication, binding it to the holder is the missing control.

I maintain pydpop ([github.com/eaakun/PyDPoP](https://github.com/eaakun/PyDPoP), `pip install pydpop`): a pure-RFC 9449 DPoP library for Python — ES256 proof generation plus full server-side verification, optional httpx/FastAPI integrations, post-quantum hybrid algs in v0.2.0, [live demo](https://huggingface.co/spaces/tatkuen/pydpop-demo). If this month sent you rotating secrets, DPoP is the control that makes the next theft a non-event.

---

**Sources**

- CVE-2026-108716 (NVD): https://nvd.nist.gov/vuln/detail/CVE-2026-108716
- VulnCheck advisory "mcp-remote 0.8.0 through 0.14.3 cleartext credential transmission via device code OAuth grant": https://www.vulncheck.com/advisories/mcp-remote-0.8.0-through-0.14.3-cleartext-credential-transmission-via-device-code-oauth-grant
- Technical writeup (hackmd.io/@haind03, "punkpeye-mcp-remote-device-code-cleartext-oauth-transport"): https://hackmd.io/@haind03/punkpeye-mcp-remote-device-code-cleartext-oauth-transport
- mcp-remote repo: https://github.com/punkpeye/mcp-remote
