# Fifty-Three Token Thefts, One Missing Control

## The incident

Webmin through 2.670 sends its cluster RPC traffic over raw TCP **despite
SSL being configured** (CVE-2026-134647, HIGH 7.5, published 2026-11-25).
The cluster RPC path (`fastrpc.cgi` / `web-lib-funcs.pl`) carries the
session ID in cleartext, so a network-positioned attacker can read the
session ID — and the `remote_eval` payloads riding alongside it — or alter
calls in transit to execute code as root on managed servers.

- Affected: Webmin through 2.670 (cluster RPC / managed-servers feature);
  fixed by commits `63666bd6` and `aca80423`.
- Sources: NVD record (CVE-2026-134647); VulnCheck disclosure
  https://doi.org/10.5281/zenodo.24396540; fix commits
  https://github.com/webmin/webmin/commit/63666bd623241607321f0621d6010e0b0c9bdcf0
  and
  https://github.com/webmin/webmin/commit/aca804236eef565d8f6f61ad50951b34359f579c.

## Why it's DPoP-shaped

The session ID is a bearer credential, and it crossed the wire in
cleartext. The cleartext-theft shape, fourth outing in this series — after
mcp-remote's cleartext device-code flow (#6), req_llm's unverified
WebSocket bearer header (#18), and Thunderbird's cleartext OAuth token
(#33). In each case the fix for the transport is TLS (or verification),
and in each case the theft itself only works because the string *is* the
identity. A sender-constrained token is useless in a stranger's hands:
the attacker can read the string off the wire and still cannot present
it, because the proof key never crossed the wire with it.

## Notes / honesty checks

- The stolen credential is a Webmin session ID, not an OAuth access token
  — the angle is sender-bound issuance as the shape of the fix, not a
  pydpop plug.
- DPoP does not fix the cleartext transport, and it does not stop the
  second half of this CVE: an attacker who alters calls in transit gets
  code execution as root without ever replaying a session. The
  cleartext-theft angle covers the session-replay half only; TLS is the
  patch for both.
- Gating: the attacker needs a network position on the cluster RPC path
  and a deployment with cluster RPC in use — the same network-observer
  gating as #33.
