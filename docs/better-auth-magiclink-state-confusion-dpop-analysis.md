# Sixteen Token Thefts, One Missing Control

## The incident

**CVE-2026-114607** (CRITICAL, CVSS 9.1, published 2026-10-22) in
better-auth (the mainstream auth library for the TypeScript ecosystem),
fixed in v1.7.7:

- Affected: better-auth from 1.4.0-beta.18 through 1.7.7.
- Four configuration conditions coincide — (1) Magic Link enabled with
  `storeToken=plain` (or `storeToken=hashed` with
  `verification.storeIdentifier=hashed`), (2) a built-in social / Generic
  OAuth provider enabled, (3) `account.storeStateStrategy=database` —
  and the OAuth sign-in `state` value becomes redeemable **as a Magic
  Link token**.
- Root cause: Magic Link verification records and OAuth state resolve
  to the same identifier in the storage layer. An **unauthenticated
  attacker** only needs to start an OAuth sign-in for a known email
  address, take the `state` returned by the callback, and redeem it at
  the Magic Link exchange endpoint — obtaining that email's existing
  user's normal session. No control of the mailbox, no provider
  callback involved; with sign-up enabled, an "email-verified" account
  can be registered the same way.
- Sources: NVD record (published 2026-10-22); GHSA
  (better-auth/security/advisories/GHSA-965c-763c-88jm); fix in
  better-auth v1.7.7 (PR #11494).

## Why it's DPoP-shaped

What the attacker walks away with is a **standard bearer session** —
the same shape as every "stolen token" in this series. If the session
were sender-bound (tied to a DPoP key held by the party redeeming it),
the step that mints the wrongly-issued session would produce a token
unusable on the attacker's machine. The server fix (isolating the
Magic Link and OAuth state namespaces, v1.7.7) closes this door; DPoP
(RFC 9449) closes the *class*: **a session issued to the wrong holder
is only useful if it can be replayed**. Series thesis, again: the
server authenticates a string, not a holder.

## Notes / honesty checks

- DPoP fixes "the token can be replayed", not "the server handed the
  session to the wrong person": the root cause is an identifier
  collision in the storage layer (cross-protocol state confusion); the
  real fix is the v1.7.7 isolation logic.
- This angle is weaker than the pure "token theft" class — the same
  shape as the queued Trigger.dev CVE-2026-114089 (PAT issued without
  authorization). Say the real-fix-first framing up front: proper
  protocol isolation first, DPoP as defense-in-depth.
- better-auth is a JavaScript project; pydpop is Python. No product
  plug — "shape of the fix" narrative only.
