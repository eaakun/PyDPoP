# Twenty Token Thefts, One Missing Control

## The incident

**CVE-2026-116747** (HIGH, CVSS 3.1 8.1, `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H`,
NVD-published 2026-10-26) in **Kener** (the open-source status-page tool,
GitHub `rajnandan1/kener`, ~5.2k stars), versions 3.0.0 through before 4.1.10:

- When the environment variable `KENER_SECRET_KEY` is empty or unset, the
  server falls back to a **hardcoded `DUMMY_SECRET`** to sign session tokens
  (CWE-321, use of hardcoded cryptographic key). The fallback lives in
  `src/lib/server/controllers/commonController.ts` (v4.1.9, lines 44–55).
- An **unauthenticated** attacker who knows one administrator email address
  can sign their own `kener-user` cookie with the public fallback key and
  walk straight into `/manage/api` with full administrative privileges.
  The same forged-key trick also mints password-reset tokens.
- The fix is in **v4.1.10** (commit `ff636483544c926eab5b5e3e26b811c0f52bcaf8`,
  which removes the fallback key) — or, immediately, setting a strong
  `KENER_SECRET_KEY`.
- Sources: NVD record for CVE-2026-116747; Kener issue #871; the v4.1.10
  release notes.

## Why it's DPoP-shaped

Another "the string is the identity" forgery — and the purest of the
forgery family so far, because the attacker steals nothing at all. With
the fallback key public, an admin token is minted on demand, no breach
required. A sender-constrained token changes the shape of that deal: the
string alone is not sufficient, because presenting it requires the
client's proof key, which the forger never had. The forged cookie would
still be *issued* — DPoP does not police issuance — but it could not be
*redeemed* against a resource server that checks the binding.

Same family as the series' earlier forgery specimens: #8 (Hitachi
RemotOps' hardcoded JWT key) and #9 (mcp-context-forge's hardcoded
`JWT_SECRET_KEY`). The difference here is the trigger: a fail-open
default. The vulnerability is not "someone leaked the key" but "the
software ships a key for you when you forget to bring one."

## Notes / honesty checks

- DPoP does **not** fix the hardcoded key, and it is not a substitute
  for the actual remediation — set a strong `KENER_SECRET_KEY` and
  upgrade to v4.1.10. What it changes is only the post-forgery half:
  a minted string that cannot be presented without a proof key.
- Scope, stated plainly: only deployments that never set
  `KENER_SECRET_KEY` are exploitable. A deployment with a strong key
  configured is not affected — this is not "every Kener instance falls."
- Form matters: Kener's token is a **session cookie**, not an OAuth
  access token, so the right framing is the general principle —
  sender-constrained session tokens — not a forced fit to the OAuth
  DPoP flow. And Kener is a TypeScript project, so per the series'
  "雪中送炭" rule this one is analysis only: no pydpop plug.
