# Interop verification

pydpop's correctness is verified against independent implementations,
not just its own test suite.

## RFC 9449 official examples

- The DPoP proof in **Figure 5** (token request, `POST https://server.example.com/token`)
  verifies cleanly with `pydpop.verify_proof` — signature over the exact
  signing input plus all claim checks (`htm`/`htu`/`iat`/`jti`).
- The **JWK SHA-256 thumbprint** of the Figure 5 example key computed by
  `pydpop.jwk_thumbprint` equals the `jkt` value published in **Figures 8/9**
  (`0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I`).

## Cross-language: Node.js `jose`

- A proof minted by `pydpop.generate_proof` verifies with the [`jose`](https://github.com/panva/jose)
  JavaScript library (independent implementation, different crypto backend).
- A proof minted by `jose` verifies with `pydpop.verify_proof`.

Test scripts: `interop/` in the pydpop workspace (RFC vector test, fuzz/property
tests, and the node interop harness).

## Robustness

The verification path is fuzz-tested: 300+ malformed, bit-flipped, and hostile-JWK
inputs are all rejected with a clean `DPoPError` — the verifier never raises an
unhandled exception on adversarial input.
