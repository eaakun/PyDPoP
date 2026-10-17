# Ten Token Thefts, One Missing Control

Mattermost is the open-source team-chat platform that enterprises deploy when they want Slack without the SaaS. Its October 2026 security update ships MMSA-2026-00758 / CVE-2026-19076, rated MEDIUM (4.4), CWE-863 — and it is the purest illustration yet of this series' thesis.

The bug: the `POST /api/v4/users/login/switch` endpoint — the one that lets a user change their account's authentication type — fails to reject OAuth application sessions. An attacker holding a valid OAuth bearer token for a target user can call it to permanently take over that user's SSO-backed account: set an attacker-controlled password, detach the account from its identity provider. No further interaction, irreversible. The victim's SSO login simply stops working; the attacker's password works. Affected: 11.7.x through 11.10.0; fixed in 11.11.0.

Two details make this one sting. First, the attack requires no vulnerability in the usual sense — no injection, no crypto break, no misconfiguration. The endpoint works exactly as coded; it just never asks "is this session allowed to do this?" The entire security boundary was one missing check on session type. Second, the same security update ships a sibling, CVE-2026-19600: Mattermost writes authentication tokens, including OAuth access tokens, into server log entries. Read the two advisories together and the kill chain assembles itself: logs leak the bearer token, the bearer token walks through `login/switch`, the SSO account is gone. The theft channel and the takeover primitive shipped in the same product, fixed in the same release.

Different app, different bug, identical failure mode — the tenth time in this series: a bearer credential that anyone can produce or copy, and a server that cannot tell the holder from the thief. The attacker never breaks crypto; they just paste a string.

To be precise about what DPoP can and cannot do here: RFC 9449 would not have fixed the missing session-type check — rejecting OAuth app sessions at the switch endpoint (11.11.0) is the patch, full stop. But notice what the vulnerability really is. Authentication here reduces to "present a correctly-signed string," and the stolen string is byte-for-byte indistinguishable from the legitimate user's. That indistinguishability is the whole disease: theft, leak, and session confusion are all the same event to a bearer-token server. Sender-constrained tokens break the equivalence. With DPoP, possession of the token string is never sufficient — the proof key never leaves the client, so a token copied from a log file is unredeemable at `login/switch`. The endpoint check closes this hole; the control converts the entire class of "the string is the identity" failures into failures that require stealing an actual private key. Anywhere a bearer credential is the whole of authentication, binding it to the holder is the missing control.

I maintain pydpop ([github.com/eaakun/PyDPoP](https://github.com/eaakun/PyDPoP), `pip install pydpop`): a pure-RFC 9449 DPoP library for Python — ES256 proof generation plus full server-side verification, drop-in integrations for httpx/requests/aiohttp and FastAPI/Django/Flask/Starlette, post-quantum hybrid algs, v0.2.1 on PyPI, [live demo](https://huggingface.co/spaces/tatkuen/pydpop-demo). If this month sent you rotating secrets, DPoP is the control that makes the next theft a non-event.

---

**Sources**

- CVE-2026-19076 (NVD): https://nvd.nist.gov/vuln/detail/CVE-2026-19076
- Mattermost security updates (MMSA-2026-00758): https://mattermost.com/security-updates
- CVE-2026-19600 (NVD): https://nvd.nist.gov/vuln/detail/CVE-2026-19600
