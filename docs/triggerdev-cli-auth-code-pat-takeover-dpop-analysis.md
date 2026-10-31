# Twenty-Three Token Thefts, One Missing Control

## The incident

**CVE-2026-114089** (HIGH, CVSS 3.1 8.8,
`AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H`, CWE-352, NVD-published
2026-10-21, GHSA-58mc-m3qq-6qrh) in **Trigger.dev before 4.5.2**:

- The CLI authorization-code flow contains a cross-site request
  forgery flaw: loading `/account/authorization-code/<code>` **mints a
  Personal Access Token without any consent step**.
- An attacker mints an unauthenticated authorization code, lures a
  logged-in victim to that URL, and then retrieves the victim's PAT
  from the **unauthenticated `/api/v1/token` endpoint** — full account
  takeover from one lured click.
- Fixed in **4.5.2** (GHSA range <= 4.5.1, patched >= 4.5.2).
- Sources: NVD record for CVE-2026-114089; GitHub Security Advisory
  GHSA-58mc-m3qq-6qrh.

## Why it's DPoP-shaped

A stolen-bearer-string story with the theft step built into the
protocol flow itself: the attacker never breaks into anything, they
just arrange for the victim's own session to mint a token and then
collect it from an unauthenticated endpoint. The collected PAT is a
plain string, and a plain string is redeemable from anywhere. A
sender-constrained token changes that deal: the PAT would be bound to
the CLI's proof key at issuance, so the string retrieved from
`/api/v1/token` could not be presented by the attacker's client —
the takeover chain breaks at the redemption step, even though the
CSRF minting flaw itself still needs its patch.

Same family as the series' earlier minted-token specimens, and the
closest sibling is #16 (Better Auth's cross-protocol state confusion):
in both, a token ends up in the wrong hands through a flow confusion,
not a break-in — and in both, binding the token to its holder is the
control that makes the mis-issued string inert.

## Notes / honesty checks

- DPoP does **not** fix the missing consent step or the
  unauthenticated token endpoint, and it is not a substitute for the
  actual remediation — upgrade to 4.5.2 and rotate any PAT that may
  have been minted this way. What it changes is only the post-theft
  half: a collected string that cannot be presented without a proof
  key.
- Scope, stated plainly: exploitation requires luring a logged-in
  victim to the crafted URL (UI:R) — this is not unauthenticated
  remote takeover with no user interaction.
- Form matters: a Trigger.dev PAT is a long-lived API credential, not
  an OAuth access token, so the right framing is the general
  principle — sender-constrained credentials — not a forced fit to the
  OAuth DPoP flow. And Trigger.dev is a TypeScript project, so per the
  series' "雪中送炭" rule this one is analysis only: no pydpop plug.
