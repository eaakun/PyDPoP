# Fifty-Two Token Thefts, One Missing Control

## The incident

RedVector before 8.1.0 ships a **hard-coded default API bearer token
(`redvector-dev-token`)** (CVE-2026-136168, HIGH 8.8, CWE-1392, published
2026-11-24). An unauthenticated remote attacker supplies the fixed token
string to `/api/python/execute` or `/api/process/execute-async` and runs
Python scripts and shell commands **as the server user** — unauthenticated
remote code execution, no login at all. The server's permissive CORS makes it
worse: a malicious web page can drive a loopback RedVector instance with the
same public string, no network position required.

- Affected: RedVector (0x7AK7/RedVector, Python, AI-powered penetration-testing
  automation framework), all versions before 8.1.0; fixed in 8.1.0.
- Sources: NVD record (CVE-2026-136168);
  VulnCheck advisory
  https://www.vulncheck.com/advisories/redvector-before-8.1.0-hard-coded-api-token-rce-via-rest-backend;
  upstream issue https://github.com/0x7AK7/RedVector/issues/3; fix commit
  https://github.com/0x7AK7/RedVector/commit/5270e2db9e1109e63e399f3f2c087faf92c3a9e5;
  release https://github.com/0x7AK7/RedVector/releases/tag/v8.1.0. The
  hard-coded token sat in `redvector_server.py` (pre-fix line 113).

## Why it's DPoP-shaped

This is the Vanus specimen (#12) again, with a nastier delivery channel: the
backend authenticates **a string, not a holder**. No theft was even needed —
the token is public source. Vanus needed a network path to the gateway port;
RedVector's permissive CORS hands that path to any web page the victim visits,
against a loopback instance. Any replayable bearer token is this vulnerability
wearing different clothes.

DPoP (RFC 9449) closes the *class*, not the bug: the real fix is to stop
shipping a static bearer token and issue sender-constrained tokens instead. A
DPoP-bound access token is useless without the private key that produced the
proof — so even a hardcoded, leaked, or dumped token string cannot be replayed
by a stranger's hand, or a stranger's web page. The honest sentence to print:
the fix rotates one secret (upgrade to 8.1.0); sender-constrained issuance
makes every secret of this shape unstealable.

## Notes / honesty checks

- RedVector is young (created 2026-10-20, ~47 stars) — smaller than Vanus,
  but the vulnerability class is identical, the severity is HIGH 8.8, and the
  fix (8.1.0) is already out. The series documents the class; the project's
  size is not the story.
- DPoP does not fix the hardcoded credential itself; it neutralizes the
  replayability of any bearer token of this shape. Say so explicitly.
- The token is a RedVector API token, not an OAuth access token — the angle
  is sender-bound issuance as the shape of the fix, not a pydpop plug.
  RedVector is Python, so the "shape of the fix" narrative applies directly.
