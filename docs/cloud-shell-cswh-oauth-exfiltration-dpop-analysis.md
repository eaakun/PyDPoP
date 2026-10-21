# Fourteen Token Thefts, One Missing Control

## The incident

Google Cloud Platform's Cloud Shell disclosed **CVE-2026-85267**
(NVD published 2026-10-20; no CVSS assigned in the NVD record):

- Affected: Google Cloud Shell prior to 2026-07-22 (WebSocket session
  channel).
- A **Cross-Site WebSocket Hijacking (CSWH)** vulnerability allowed an
  unauthenticated attacker to hijack an active Cloud Shell session and
  **exfiltrate the user's OAuth access token using a cross-origin
  WebSocket request**. Classic CSWH shape: the attacker lures the victim's
  browser into opening a WebSocket to Cloud Shell from an attacker origin;
  the session's messages — including the OAuth access token — land on a
  socket the attacker's page owns and can read. The victim's browser did
  the attacker's reading for them.
- Source: NVD record (published 2026-10-20).

## Why it's DPoP-shaped

The attack ends the moment the exfiltrated token is *spendable*: a stolen
bearer string replays against Google APIs exactly like the victim's. The
hijack itself is a browser-origin-validation bug, but the *blast radius*
is a token-format bug — the OAuth access token authenticates its holder,
not its owner. A DPoP-bound (RFC 9449) access token exfiltrated the same
way is inert: replaying it requires a proof-of-possession signature from
the victim client's private key, which never crossed the WebSocket. The
server fix (validate the WebSocket origin) closes this door; DPoP closes
the *class*: **exfiltrating the string no longer exfiltrates access**.
Series thesis, again: the server authenticates a string, not a holder —
Google Cloud Shell is the highest-profile bearer-string casualty so far.

## Notes / honesty checks

- **Timing caveat**: Google patched this on 2026-07-22 ("no customer
  action is needed"); the CVE was only *published* on 2026-10-20. This is
  a retrospective write-up, not a live fire — say so explicitly; the value
  is the Google-scale demonstration of the bearer-string problem, not
  urgency.
- DPoP mitigates the *replay of the exfiltrated token*, not the session
  hijack itself — the WebSocket session could still be abused in real
  time while the victim's page holds it open. Say both.
- No CVSS on the NVD record; do not invent one. Impact is described by
  the vendor as session hijack + OAuth access-token exfiltration.
