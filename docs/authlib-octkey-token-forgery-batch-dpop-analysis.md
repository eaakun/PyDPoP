# Seventeen Token Thefts, One Missing Control

## The incident

On 2026-10-22, Authlib — the mainstream OAuth/OIDC library for Python,
and the library whose open DPoP issue (#315) is why pydpop exists —
published a 7-CVE security batch (1.9.0/1.9.1). Four of them are
"token forgery / replay" class:

- **CVE-2026-114615** (HIGH 7.4): `OctKey.import_key()` only checked
  the asymmetric-key marker at byte 0, while the PEM loader accepted
  leading whitespace/comments/BOM → an attacker can use **the same
  public public-key bytes as an HMAC secret** and forge HS256 tokens
  with arbitrary claims (bypass of the CVE-2024-37568 fix). Fixed in
  1.9.0.
- **CVE-2026-114616** (HIGH 7.4): `OctKey.import_key()` and the HMAC
  path accepted **zero-length keys**; if an application's secret lookup
  can return an empty string, the attacker computes deterministic
  HS256/384/512 signatures and forges tokens that verify as genuine.
  Fixed in 1.9.1.
- **CVE-2026-114617** (MEDIUM 4.2): `parse_id_token()` read the
  `nonce_supported` decision **from the ID token being verified
  itself** → with `nonce=false` the expected nonce is emptied; an
  attacker holding **a captured valid ID token** replays it in
  implicit/hybrid flows. Pure "stolen bearer string" shape.
- **CVE-2026-114618** (MEDIUM 6.8): `JWTBearerGrant.get_audiences()`
  defaulted to an empty list, requiring `aud` to exist but never
  matching the current AS → an attacker holding **another service's
  valid assertion** replays it cross-service in deployments sharing
  the signing key. Cross-service assertion replay shape.
- Filtered from the same batch (no token angle, not covered here):
  CVE-2026-114614 (LOW), CVE-2026-114619 (MEDIUM), CVE-2026-114620
  (MEDIUM).

## Why it's DPoP-shaped

114617/114618 are textbook DPoP shape: a stolen or misappropriated
bearer string, sender-constrained, is waste paper in the attacker's
hands. 114615/114616 are the "forgery" class — when a verifier's
signature check is bypassed, **a token bound to proof-of-possession**
is the last line of "a forged token still needs a real key". DPoP
(RFC 9449) doesn't fix "the verifier accepted a forged signature"
itself — but it changes what the forged token can buy. Series
thesis, in the most fitting place of all: the library that inspired
pydpop had a token-forgery week, and the missing control is the one
pydpop implements.

## Notes / honesty checks

- The root cause of 114615/114616 is Authlib's key-validation bug;
  the real fix is upgrading to 1.9.0/1.9.1. DPoP cannot repair "the
  verifier accepted a forged signature" — an attacker who can forge
  arbitrary claims could in theory also stuff a `cnf` and hold the
  matching key. Say this explicitly; no exaggeration.
- The DPoP angle on 114617/114618 (replay class) is solid.
- No new issue/PR filed against Authlib: everything is already fixed
  (1.9.0/1.9.1), and the #315 follow-up line is already being watched
  by the feedback loop. This analysis does not disturb lepture.
