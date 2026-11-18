# Forty-Two Token Thefts, One Missing Control

## The incident

**Rucio**, 1.14.0 until 35.9.1, 38.6.1, 40.4.2, and 41.1.1 —
CVE-2026-100397, **CRITICAL 10.0** (CVSS 3.1), CWE-287,
published 2026-11-17T20:17Z:

- `validate_auth_token` in `lib/rucio/core/authentication.py`
  **does not distinguish short-lived SSH challenge nonces from
  authentication tokens** stored in the same token table.
- An unauthenticated attacker can request
  `/auth/ssh_challenge_token` for an arbitrary account by
  supplying `X-Rucio-Account`, then present the returned
  `X-Rucio-SSH-Challenge-Token` as `X-Rucio-Auth-Token` to
  authenticate to other API endpoints **as that account —
  including an administrative account**.
- Fixed in **35.9.1, 38.6.1, 40.4.2, and 41.1.1**. The fix
  separates the two token types at validation time.

Sources: NVD CVE-2026-100397; GHSA-x585-4vv8-2mh2;
rucio/rucio fix commits (4d4a585, 4df924f, d7a3c2c, 2ef8cdf).

## Why it's DPoP-shaped

This is the first type-confusion case in the series, and it is
worth stating precisely what makes it different from the
issuance class the series keeps filtering out. In the issuance
cases — Lago #119420, WSO2 #4052, IBM API Connect #16720 — the
server mints a genuine token *to the attacker's own flow*, and
the attacker holds the proof key for it: DPoP binds the token
to the attacker, and nothing is gained. Here the server never
issued an auth token to the attacker at all. It issued an SSH
challenge nonce — a short-lived value for a different purpose —
and the validator mistook it for an auth token. The attacker
holds no proof key for the victim account, never completed the
victim's login, never touched the victim's credentials. He
holds a string that was never an auth token, and the server
accepted it as one.

The proof-key-hands test passes, in the direction that
matters: the string the attacker presents carries no binding
to any key, because it was never issued as a holder-bound
credential. A sender-constrained auth token carries its
holder's key binding (`jkt`); a challenge nonce carries none.
Presenting the nonce as an auth token fails a DPoP verifier
for the same reason a forged token fails — there is no key
behind the string. That is the control the validator was
missing, expressed as a property of the token rather than as
a branch in the code.

The honest boundary, as ever: DPoP does not fix the underlying
bug. The shipped fix — distinguishing token types at
validation — is the patch, and it is the whole of the fix for
the confusion itself. Two further limits, specific to this
case: Rucio tokens are API bearer tokens, not RFC 9449 OAuth
access tokens, so DPoP as written does not drop into Rucio
unchanged — the control here is the same idea applied to its
auth tokens, binding each one to the holder's key and refusing
any unbound string as an auth token. And Rucio is scientific
data management, not an OAuth identity provider, so this is
analysis only. What the case gives the series is the
distinction: a token that was never issued as an auth token is
not the attacker's token, and a verifier that cannot tell its
token types apart will accept anything that fits the table.
