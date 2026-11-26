# Fifty-Four Token Thefts, One Missing Control

## The incident

Apache JSPWiki 2.10 through 3.0.0 never replaced the session identifier
when a user authenticated (CVE-2026-78114, CRITICAL 10.0, CWE-384,
published 2026-11-25). An attacker who could set a known session
identifier in a victim's browser could keep using that same identifier
after the victim logged in — the victim's authenticated session, on the
attacker's chosen ID.

- Affected: Apache JSPWiki 2.10–3.0.0, all platforms; fixed in 3.0.1
  (3.x) and 2.12.6 (2.x).
- Sources: NVD record (CVE-2026-78114); Apache security list
  https://lists.apache.org/thread.html/n43zhkpnphlksm12w7ndx4d87s7wdffv.

## Why it's DPoP-shaped

Session fixation, the second outing in this series after Apache Shiro's
Remember-Me fixation (#39) — the oldest trick in the book, in the second
Apache framework to ship it this month. The fixation only works because
the session identifier *is* the session: whoever presents the string is
the user. A sender-constrained session token breaks exactly that link —
the proof key lives in the victim's browser, so the identifier the
attacker fixed is unusable from the attacker's browser, authenticated
or not.

## Notes / honesty checks

- JSPWiki sessions are not OAuth access tokens — the angle is
  sender-bound issuance as the shape of the fix, not a pydpop plug.
- The patch is session rotation on authentication (upgrade to 3.0.1 /
  2.12.6); DPoP is the control that makes the next fixation a
  non-event, not the fix for this one.
- Gating: the attacker must be able to set a session identifier in the
  victim's browser first (the usual fixation precondition); the CVE
  itself is silent on the delivery channel.
