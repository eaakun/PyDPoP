# Eleven Token Thefts, One Missing Control

Vikunja is the self-hosted kanban and project-management app — Trello you run yourself. Its October 2026 security update ships GHSA-4hv6-xc92-j86g / CVE-2026-111917, rated MEDIUM (6.5), CWE-613, and the CVE's own description names the enabling condition outright: "attackers holding a stolen access token."

The bug: the WebSocket auth handler (`handleAuth` on `/api/v2/ws`) never checks the JWT `sid` claim against the sessions table. An attacker holding a stolen access token can open — or keep — a WebSocket connection after the session was deleted or after TOTP was enrolled. Revocation simply doesn't reach this endpoint. The payoff is a live feed: the attacker keeps receiving the victim's `notification.created` pushes in real time — comments, tasks, project content — indefinitely. Affected: 2.3.0 before 2.7.0; fixed in 2.7.0.

Two details make this one sting. First, the victim did everything right. They deleted the session. They enrolled TOTP. Every revocation ritual the product offers was performed — and the attacker's connection stayed up, because token validation and WebSocket upgrade are two code paths, and the `sid` lookup fell through the crack between them. Revocation that doesn't reach every endpoint is a universal operational reality, not a Vikunja-specific lapse. Second, this is the same stolen-token-replay shape as two earlier entries in this series — the Open WebUI postMessage theft and the Open WebUI cookie-jar disclosure. Bearer-string indistinguishability, not a new class. The industry keeps relearning that a token that can be copied is a token that can't be revoked, one product at a time.

Different app, different bug, identical failure mode — the eleventh time in this series: a bearer credential that anyone can produce or copy, and a server that cannot tell the holder from the thief. The attacker never breaks crypto; they just hold the string.

To be precise about what DPoP can and cannot do here: RFC 9449 would not have fixed the missing `sid` check — looking up the session in `handleAuth` (2.7.0) is the patch, full stop. But notice what the vulnerability really is. Authentication here reduces to "present a correctly-signed string," and the stolen string is byte-for-byte indistinguishable from the legitimate user's. That indistinguishability is the whole disease: theft, leak, and revocation gaps are all the same event to a bearer-token server. Sender-constrained tokens break the equivalence. With DPoP, possession of the token string is never sufficient — the proof key never leaves the client, so the thief holding the stolen string gets a 401 instead of a live feed of the victim's tasks and comments. The `sid` check closes this hole; the control converts the entire class of "the string is the identity" failures into failures that require stealing an actual private key. Anywhere a bearer credential is the whole of authentication, binding it to the holder is the missing control.

I maintain pydpop ([github.com/eaakun/PyDPoP](https://github.com/eaakun/PyDPoP), `pip install pydpop`): a pure-RFC 9449 DPoP library for Python — ES256 proof generation plus full server-side verification, drop-in integrations for httpx/requests/aiohttp and FastAPI/Django/Flask/Starlette, post-quantum hybrid algs, v0.2.1 on PyPI, [live demo](https://huggingface.co/spaces/tatkuen/pydpop-demo). If this month sent you rotating secrets, DPoP is the control that makes the next theft a non-event.

---

**Sources**

- CVE-2026-111917 (NVD): https://nvd.nist.gov/vuln/detail/CVE-2026-111917
- GHSA-4hv6-xc92-j86g (go-vikunja/vikunja security advisory): https://github.com/go-vikunja/vikunja/security/advisories/GHSA-4hv6-xc92-j86g
- VulnCheck advisory: https://www.vulncheck.com/advisories/vikunja-2.3.0-before-2.7.0-websocket-authentication-ignores-session-revocation
