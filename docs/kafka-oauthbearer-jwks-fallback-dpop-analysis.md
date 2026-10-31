# Twenty-Four Token Thefts, One Missing Control

## The incident

**CVE-2026-110985** (NVD-published 2026-10-28, Kafka official
announcement 2026-10-28) in **Apache Kafka**:

- A broker using SASL/OAUTHBEARER with the default validator
  (`sasl.oauthbearer.jwt.validator.class=DefaultJwtValidator`) selects
  its implementation from configuration. When
  `sasl.oauthbearer.jwks.endpoint.url` is set, the validator verifies
  the JWT signature. When that URL is unset (the default) and no
  verification key resolver is supplied, `DefaultJwtValidator` silently
  falls back to `ClientJwtValidator`, which does not verify the JWT
  signature, algorithm, or issuer — and the broker starts with no
  warning or error.
- An unauthenticated remote attacker who can reach the listener can
  therefore forge a token asserting any principal — including configured
  superusers — and gain full access to the cluster. Any structurally
  valid JWT is accepted, including `"alg":"none"` tokens.
- This is the residual of CVE-2026-33557, whose fix restored signature
  verification only on the path where the JWKS endpoint URL is set.
- Versions affected: 4.1.0 through 4.1.2, 4.2.0 through 4.2.1, 4.3.0.
  Only brokers that enable SASL/OAUTHBEARER without a JWKS endpoint URL
  (and without a custom verification key resolver) are affected;
  brokers that set the URL verify signatures and are not affected.
- Fixed versions: 4.2.2, 4.3.1, 4.4.0 — from these releases, a broker
  that would fall back to the non-verifying validator fails to start
  with a `ConfigException` instead of running without signature
  verification (secure by default). Mitigation without upgrade: set
  `sasl.oauthbearer.jwks.endpoint.url` for every listener/mechanism
  that uses `OAuthBearerValidatorCallbackHandler`, or configure a
  signature-verifying `sasl.oauthbearer.jwt.validator.class`.
- Sources: NVD record for CVE-2026-110985; Apache Kafka official CVE
  list (re-verified against the official list at publish time, entry
  unchanged; NVD had assigned no CVSS score at publish time, so none
  is claimed here).

## Why it's DPoP-shaped

This one has the thinnest DPoP angle in the series so far — and that
is exactly why it belongs here. A verifier that verifies nothing cannot
be fixed by sender-constrained tokens: a validator that skips signature
checks will skip DPoP proof checks with the same indifference. The
honest statement is that DPoP changes nothing for this broker; the fix
is fail-closed configuration and upgrade. What the incident teaches, and
what generalizes to every other entry in this series, is the ordering:
before a token can be bound to its holder, the verifier must actually
verify. A misconfiguration that should have refused to start instead
ran silently — the fail-open default is the vulnerability, and
fail-closed is the lesson.

The scope stays narrow on purpose: only SASL/OAUTHBEARER with the
default validator and no JWKS endpoint URL is affected. Brokers that
set the URL, or that use a custom signature-verifying resolver, were
never exposed. This is not "all of Kafka falls over"; it is one
configuration path where the verification step itself was silently
skipped — the purest "the verifier does not verify" specimen in the
series, beside #8 (Hitachi), #9 (mcp-context-forge), #20 (Kener), and
#21 (nest-admin), where the failure was a leaked or predictable key
rather than a skipped check.

Kafka is a Java project; per the series' rule, this is analysis only,
no pydpop plug.
