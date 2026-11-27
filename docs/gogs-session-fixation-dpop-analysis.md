# Fifty-Nine Token Thefts, One Missing Control

## The incident

Gogs, the self-hosted Git service, does not regenerate the session ID
after successful authentication (CVE-2026-52803, HIGH 7.6, published
2026-11-26). An attacker who forces a victim to use a known session
ID — via a crafted link, a subdomain XSS, a network position, or
physical access — hijacks the session the moment the victim logs in
and takes over the account, including administrator accounts with
access to private repositories.

- Affected: Gogs before 0.15.0; fixed in 0.15.0.
- Sources: NVD record (CVE-2026-52803); GitHub Security Advisory
  GHSA-h48f-pxp7-c4mj
  https://github.com/gogs/gogs/security/advisories/GHSA-h48f-pxp7-c4mj
  (with a working proof of concept: attacker session
  `i_like_gogs=c9af1981d493dc56` survives the victim's login unchanged).

## Why it's DPoP-shaped

The session-fixation family's third outing, after Shiro's RememberMe
fixation (#39) and JSPWiki's never-rotated login session (#54). The
attack works because the session identifier is a bare string whose
only qualification is knowing it: the attacker picks the string, the
victim's login authenticates it, and the server cannot tell the two
presentations apart. A session credential bound to the holder's key
at authentication time breaks the chain at its only link — the
attacker's copy of the fixed ID is inert, because the proof key
stayed with the victim's browser. Rotation on login is the patch
(Gogs 0.15.0 adds it); binding is what makes the next rotation bug
a non-event.

## Notes / honesty checks

- The stolen credential is a web session ID, not an OAuth access
  token — the angle is sender-bound issuance as the shape of the
  fix, not a pydpop plug.
- Fixation needs a delivery channel for the fixed ID (link, XSS,
  network position); the vulnerability is the missing rotation, and
  the patch is one line — `RegenerateID` on successful sign-in.
- DPoP does not fix the rotation bug itself; it makes a fixed
  identifier unredeemable by anyone except the holder who logged in
  with it.
