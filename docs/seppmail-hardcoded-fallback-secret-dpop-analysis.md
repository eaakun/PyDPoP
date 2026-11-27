# Sixty Token Thefts, One Missing Control

## The incident

SEPPmail Secure Email Gateway before 15.1.2 uses a source-visible
hard-coded fallback secret for legacy GINA token and Large File
Transfer cryptographic operations whenever the appliance-specific key
material cannot be loaded (CVE-2026-124843, CRITICAL 9.2, published
2026-11-26). While the fallback path is active, a remote attacker
can forge accepted GINA account tokens — and decrypt Large File
Transfer content protected with the shared fallback — without any
credential at all.

- Affected: SEPPmail Secure Email Gateway before 15.1.2; fixed in
  15.1.2 (released 2026-11-24).
- Sources: NVD record (CVE-2026-124843); vendor release notes
  15.1.2, "Hard-Coded Cryptographic Fallback Secret Enables Token
  Forgery"
  https://downloads.seppmail.com/extrelnotes/151/ERN15.1.html —
  "Large File Transfer encryption no longer falls back to the
  hard-coded secret and is refused if the required key is not
  available."

## Why it's DPoP-shaped

The forgery family's twentieth occurrence — the same shape as
Hitachi (#8), mcp-context-forge (#9), Kener (#20), nest-admin
(#21), OpenDeepWiki (#26), AnsibleForms (#44), Kerberos Agent
(#48), and openIMIS (#55): the signing secret is public knowledge,
so the token is whoever holds the string. A sender-constrained
account token cannot be minted from a published secret, because
minting one needs the holder's private key, which the attacker does
not have and cannot derive from the fallback. The patch removes
the fallback; DPoP makes the next hardcoded secret a non-event,
because a forged string still fails the proof check.

## Notes / honesty checks

- DPoP does not fix the hardcoded secret — the fallback must go,
  and 15.1.2 removes it. The honest claim is narrower: with
  sender-bound tokens, the forged string is unredeemable.
- The fallback only activates when appliance key material fails to
  load, so not every deployment was exposed — but any deployment
  that hit the fallback was silently issuing forgeable tokens.
- This CVE arrived in a batch: the same 15.1.2 release fixes a
  pre-auth template injection (CVE-2026-130637, CRITICAL 9.3), a
  recovery-session purpose confusion (CVE-2026-124840), and an
  unauthenticated credential reset (CVE-2026-124842) — all recorded
  in the watch log; only the token-forgery member is DPoP-shaped.
