# Fifteen Token Thefts, One Missing Control

## The incident

On 2026-10-21, the `litellm` Python package (~23M weekly downloads per
Datadog Security Labs) was compromised in a supply-chain attack that
published a malicious `1.107.0` to PyPI and Docker Hub:

- Affected: `litellm==1.107.0` — seven wheels + sdist on PyPI, and the
  `v1.107.0` / `latest` / `main-latest` / `main-stable` tags on GHCR and
  Docker Hub. Malicious for roughly two hours on PyPI (uploaded ~11:39
  UTC, quarantined early afternoon) before removal; last clean release
  `1.106.2`.
- Payload: `cook.pth` / `cook.py` / `sitecustomize.py` — executes on
  interpreter startup *before* LiteLLM is imported. A credential stealer
  ("privcollect") harvesting cloud credentials, private keys, browser
  data, environment variables, and LiteLLM proxy credentials, plus a
  backdoor polling a GitHub dead drop (`domain.txt`) hourly for
  second-stage Python.
- Attack vector (per LiteLLM director of security Oliver Jensen): the
  threat actor acted through **three engineers' GitHub accounts,
  "appearing to be by way of stolen GitHub CLI OAuth tokens"** — one
  account triggered the project-releaser run, another approved it. The
  malicious fork `Berri-AI/litellm` (note the hyphen, vs. the real
  `BerriAI/litellm`) was built through LiteLLM's own legitimate
  pipeline, with faithful build provenance — a human-review-evading
  detail.
- How the tokens were acquired is still unknown. LiteLLM revoked all
  involved tokens and temporarily removed all but one unaffected user
  from its GitHub organization.
- Sources: The Hacker News (Oct 21, 2026), Datadog Security Labs, Kodem,
  Security Boulevard; original reports from SafeDep, Socket,
  StepSecurity, Upwind. Second LiteLLM supply-chain compromise of 2026
  (earlier: 1.82.7/1.82.8, attributed to TeamPCP activity — no
  established connection to this one).

## Why it's DPoP-shaped

The hinge of the whole attack is *replay*: stolen GitHub CLI OAuth
tokens are bearer strings, and GitHub's API authenticates the string, not
the machine holding it. The attacker needed no laptop, no SSH agent, no
2FA — the token strings alone were enough to trigger a release run and
approve it from the attacker's own infrastructure.

A DPoP-bound (RFC 9449) token would have been inert in the attacker's
hands: every API call would require a proof-of-possession signature from
the private key the engineer's CLI holds, and the stolen string alone
proves nothing. Revocation still happened after the fact; DPoP would have
made the reuse *impossible before the fact*. Series thesis, sharpened:
the release pipeline's weakest link wasn't the code — it was that three
bearer strings were indistinguishable from three engineers.

## Notes / honesty checks

- No CVE; this is a malicious release, not a software vulnerability.
  DPoP applies to the *authentication layer* of the incident (GitHub CLI
  OAuth tokens), not to detecting the malicious package.
- The initial token-acquisition channel is unknown. If the attacker had
  also exfiltrated the proof-of-possession keys, DPoP would not help —
  say both. The observed shape (tokens replayed from attacker
  infrastructure) is exactly the shape DPoP defeats.
- GitHub CLI OAuth flows do not currently issue sender-constrained
  tokens; this is a "what-if" analysis, not a product claim.
- The ~2-hour exposure window and the poisoned `latest` tag mean any
  environment that installed or pulled 1.107.0 in the window must be
  treated as fully compromised — the payload targets exactly the
  credentials (cloud tokens, keys, cookies) that enable the *next*
  supply-chain attack.
