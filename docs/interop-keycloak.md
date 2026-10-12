# Interop: Keycloak 26.8.0 (DPoP-bound access tokens)

**Status: PASS** — pydpop's DPoP proofs are accepted by a real Keycloak
authorization server, and the issued access token's `cnf.jkt` exactly
matches pydpop's JWK thumbprint.

Tested 2026-10-12 against a throwaway local Keycloak (loopback only,
destroyed after the test). No public exposure, no persistent state.

## Environment

- Keycloak **26.8.0** (latest stable 26.x at the time), `start-dev`,
  bound to `127.0.0.1:8080`, H2 dev database
- OpenJDK Temurin 21.0.12.1
- pydpop from source (`generate_proof`, `generate_key`,
  `jwk_thumbprint`, ES256)

## Server configuration (via Admin REST API)

- Realm: `pydpop-test`
- Client: `pydpop-client`
  - `publicClient: true`
  - `directAccessGrantsEnabled: true` (password grant, test-only)
  - `attributes["dpop.bound.access.tokens"] = "true"` — the
    "Require DPoP bound tokens" switch; this is what makes the token
    endpoint **reject requests without a DPoP proof**
- Test user with password (see gotcha below)

## Positive test

Password-grant token request to
`/realms/pydpop-test/protocol/openid-connect/token` with a `DPoP` header
containing `pydpop.generate_proof(private_key=key, htm="POST",
htu=<token endpoint URL>)`:

- **HTTP 200**, `token_type: "DPoP"`
- Access token `cnf.jkt` **==** `pydpop.jwk_thumbprint(public_jwk(key))`
  (exact string match)

## Negative tests

| Case | Result |
|---|---|
| No `DPoP` header | `400 invalid_request` — `DPoP proof is missing` |
| Tampered proof (corrupted signature) | `400 invalid_request` — `DPoP verification failure: TokenSignatureInvalidException: Invalid token signature` |

The tampered-proof case proves Keycloak cryptographically validated
pydpop's proof structure and ES256 signature — it parsed the JWS,
checked the signature, and rejected the forgery. The valid-proof case
proves the full happy path including `htm`/`htu` binding and `cnf.jkt`
propagation into the access token.

## Limitations (honest)

- Password grant was used for simplicity; the DPoP mechanics (proof
  validation, `cnf.jkt` binding) are identical for the authorization-code
  flow, but the code-exchange path was not exercised here.
- ES256 only (what Keycloak advertises). pydpop's PQC hybrid algs were
  not tested against Keycloak — Keycloak 26.x does not support them.
- `DPoP-Nonce` rotation was not exercised (Keycloak did not issue a
  nonce challenge in this setup).

## Gotcha: "Account is not fully set up"

Users created via the Admin API **with inline credentials and no
`firstName`/`lastName`** failed the password grant with
`400 invalid_grant: Account is not fully set up` — even with a valid
DPoP proof (the DPoP layer had already passed; the failure was in
Keycloak's account-resolution step). Creating the user first, then
setting the password via `reset-password`, with `firstName`/`lastName`
populated, worked. This is a Keycloak 26.x account-provisioning quirk,
unrelated to DPoP.
