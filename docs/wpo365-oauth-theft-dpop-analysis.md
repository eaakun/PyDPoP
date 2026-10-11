# Four Token Thefts, One Missing Control

This week gave the ecosystem its fourth data point — and the biggest blast radius yet.

**Case 4: WPO365 Login (CVE-2026-104759, HIGH 8.1, published October 10).** WPO365 | LOGIN ≤ 44.1, the WordPress + Microsoft 365 integration plugin, shipped a deprecated OIDC parser that validated its login nonce with the wrong function: it checked a 64-hex-character nonce using WordPress core's `wp_verify_nonce()`, a check that nonce could never pass. So the nonce verification **silently failed on every login** — and the flow carried on regardless, authenticating whoever presented an `id_token`. Attackers who got hold of any previously issued, still-valid `id_token` for a target account could simply replay it and log in as that user, administrators included. Full site takeover from one stolen token. (Only installations with the `use_id_token_parser_v2` option enabled took this code path; 45.0 fixes it.)

This is the same failure mode as the three cases before it — the MCP SDKs (CVE-2026-104850), the Splunk MCP Server (CVE-2026-76286), and Eclipse Ditto Explorer (CVE-2026-107503): a Bearer <redacted> ends up in the wrong hands, and because possession equals access, the theft is already the exploit. Four independent codebases, four weeks, one lesson.

The missing control is still sender-constrained tokens. An honest note first: DPoP (RFC 9449) binds *access* tokens, and this case replays an *id* token — the mechanism differs, but the enemy is identical: a replayable Bearer <redacted> WPO365's broken nonce check was, in effect, a poor man's sender-constraint: a string comparison standing between the attacker and the account. When it failed silently, there was nothing left. DPoP replaces that fragile string check with a public-key binding — the token is useless without the holder's private key, so a stolen token is dead paper instead of a master key.

I maintain pydpop ([github.com/eaakun/PyDPoP](https://github.com/eaakun/PyDPoP), `pip install pydpop`): a pure-RFC 9449 DPoP library for Python — ES256 proof generation plus full server-side verification, one dependency, 39 tests, fuzz-hardened, RFC test vectors and Node `jose` interop verified, [live demo](https://huggingface.co/spaces/tatkuen/pydpop-demo). If this week sent you rotating secrets, DPoP is the control that makes the next theft a non-event.

---

**Sources**

- CVE-2026-104759 (WPO365): https://nvd.nist.gov/vuln/detail/CVE-2026-104759
- Wordfence threat intel: https://www.wordfence.com/threat-intel/vulnerabilities/id/3dee7f76-bd66-4e54-8ef6-bbf581ebcc11?source=cve
- CVE-2026-104850 (MCP TypeScript SDK): https://nvd.nist.gov/vuln/detail/CVE-2026-104850
- CVE-2026-76286 (Splunk MCP Server): https://nvd.nist.gov/vuln/detail/CVE-2026-76286
- CVE-2026-107503 (Eclipse Ditto Explorer): https://nvd.nist.gov/vuln/detail/CVE-2026-107503
