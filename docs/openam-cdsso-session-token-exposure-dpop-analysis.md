# Twenty-Five Token Thefts, One Missing Control

## The incident

**CVE-2026-45049** (HIGH 8.3, NVD-published 2026-10-29,
GHSA-r9pv-5rpp-vm8g) in **OpenAM Community Edition**
(`org.openidentityplatform.openam:openam-federation`):

- An Information Exposure Through Sent Data (CWE-201) issue in
  OpenAM's Cross-Domain Single Sign-On (CDSSO) servlet allows a
  logged-in user's raw OpenAM session token to be POSTed to an
  attacker-controlled URL. An attacker who can induce a logged-in
  victim to visit a crafted URL may receive the victim's session
  credential, which could enable session hijacking.
- Affected versions: through 16.0.6. Patched in 16.1.1.
- The exposure is gated, and the gates matter: exploitation requires
  user interaction (an authenticated user must be induced to visit an
  attacker-crafted URL) and is further gated on a non-default
  configuration being absent. OpenAM deployments through 16.0.6 that
  have CDSSO enabled are potentially affected; the CDSSO component is
  commonly enabled in multi-domain deployments.
- The blast radius is what makes a CDSSO token worse than an ordinary
  session cookie: a CDSSO cookie is valid across several domains, so a
  stolen one can potentially reach any realm the session has logged
  into, across every protected domain in the deployment — not just the
  one it was stolen from.
- Sources: GitHub Security Advisory GHSA-r9pv-5rpp-vm8g (verified
  against the advisory record at publish time); NVD record for
  CVE-2026-45049.

## Why it's DPoP-shaped

A stolen CDSSO token is a bearer credential replayed across domains —
the same shape as every other entry in this series, with a
cross-domain amplifier attached. The vendor's own mitigation points the
same way as DPoP: OpenAM's restricted tokens and cookie hijacking
protection bind the credential to the fully qualified domain name
where it was issued, so a token lifted from one host does not work
from another. DPoP does the same thing one layer down, for OAuth
access tokens: the string alone is not sufficient, because presenting
it requires the holder's private key.

The honest boundary, stated plainly: OpenAM is a Java project and the
stolen thing is a session token, not an OAuth access token, so this is
analysis only, no pydpop plug. DPoP does not fix an information
exposure in a CDSSO servlet; the fix is the 16.1.1 patch plus the
binding configuration. What generalizes is the control: a credential
that works from anywhere, presented by anyone, is a string waiting to
be copied — and binding it to its holder or its host is what turns
the next theft into a non-event.
