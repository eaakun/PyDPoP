# Fifty-Eight Token Thefts, One Missing Control

## The incident

Teracom TCW122B-CM firmware before 4.07 uses a predictable session
cookie (CVE-2026-137086, HIGH 8.1, published 2026-11-25). The 32-bit
cookie is derived from a tick counter, so an unauthenticated remote
attacker can predict or brute-force it from device uptime and login
timing — and hijack administrator sessions, taking control of relays,
settings, and administrator credentials.

- Affected: Teracom TCW122B-CM (remote I/O monitoring controller)
  firmware before 4.07; fixed in 4.07.
- Sources: NVD record (CVE-2026-137086); vendor security advisory
  SEC-2026-001
  https://www.teracomsystems.com/security-advisory/sec-2026-001.pdf;
  VulnCheck advisory
  https://www.vulncheck.com/advisories/teracom-tcw122b-cm-before-4.07-predictable-session-cookie-session-hijacking.

## Why it's DPoP-shaped

The forgery family's nineteenth occurrence — and its third
predictable-session-identifier specimen, after FlowIntel's bare
numeric user ID (#45) and Wing FTP's derived session IDs (#50). No
secret was leaked, derived, or guessed, because there was no secret
at all: the session identifier is a counter. A sender-constrained
session token cannot be produced from a counter — it needs the
holder's private key, which the attacker does not have and cannot
compute from uptime.

## Notes / honesty checks

- The stolen credential is a device session cookie, not an OAuth
  access token — the angle is sender-bound issuance as the shape of
  the fix, not a pydpop plug.
- The device is a niche industrial controller, and the attack needs
  network reachability to it; the series documents the class, and the
  class here is the purest form of the thesis — the string was never
  the identity, because there was nothing behind the string at all.
- The patch is firmware 4.07, and the cookie needs real entropy; a
  longer counter is the same bug with a longer fuse.
