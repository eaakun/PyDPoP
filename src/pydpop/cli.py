"""The ``dpop`` command: mint, verify, and inspect DPoP proofs from the shell.

Handy for debugging your OAuth flow without writing a script:

    $ dpop keygen --alg ML-DSA-44-ES256 > key.json   # keep key.json secret!
    $ dpop mint --key key.json --htm POST --htu https://auth.example.com/token
    $ dpop verify --proof <proof> --htm POST --htu https://auth.example.com/token
"""
from __future__ import annotations

import argparse
import json
import sys

from .jwk import (
    generate_key,
    jwk_thumbprint,
    private_jwk,
    private_key_from_jwk,
    public_jwk,
)
from .proof import generate_proof
from .verifier import DPoPError, verify_proof


def _load_key(path: str | None, alg: str):
    if path:
        with open(path) as f:
            return private_key_from_jwk(json.load(f))
    return generate_key(alg=alg)


def cmd_keygen(args: argparse.Namespace) -> int:
    key = generate_key(alg=args.alg)
    print(json.dumps(private_jwk(key), indent=2))
    print("WARNING: this is a PRIVATE key — store it securely, never share it.",
          file=sys.stderr)
    return 0


def cmd_mint(args: argparse.Namespace) -> int:
    key = _load_key(args.key, args.alg)
    print(generate_proof(
        private_key=key, htm=args.htm, htu=args.htu,
        access_token=args.access_token, nonce=args.nonce,
    ))
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    try:
        result = verify_proof(
            proof=args.proof, htm=args.htm, htu=args.htu,
            access_token=args.access_token, expected_nonce=args.nonce,
        )
    except DPoPError as exc:
        print(f"INVALID: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({
        "jwk_thumbprint": result["jwk_thumbprint"],
        "alg": result["jwk"].get("alg", "ES256"),
        "claims": result["claims"],
    }, indent=2))
    return 0


def cmd_thumbprint(args: argparse.Namespace) -> int:
    key = _load_key(args.key, args.alg)
    print(jwk_thumbprint(public_jwk(key)))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="dpop", description="Mint and verify RFC 9449 DPoP proofs.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("keygen", help="Generate a key (prints private JWK).")
    p.add_argument("--alg", default="ES256",
                   choices=["ES256", "ML-DSA-44-ES256", "ML-DSA-65-ES256"])
    p.set_defaults(func=cmd_keygen)

    p = sub.add_parser("mint", help="Mint a DPoP proof JWT.")
    p.add_argument("--key", help="Private JWK JSON file (else ephemeral key).")
    p.add_argument("--alg", default="ES256",
                   choices=["ES256", "ML-DSA-44-ES256", "ML-DSA-65-ES256"])
    p.add_argument("--htm", required=True, help="HTTP method, e.g. POST.")
    p.add_argument("--htu", required=True, help="Request URI, e.g. https://auth.example.com/token.")
    p.add_argument("--access-token", default=None)
    p.add_argument("--nonce", default=None)
    p.set_defaults(func=cmd_mint)

    p = sub.add_parser("verify", help="Verify a DPoP proof JWT.")
    p.add_argument("--proof", required=True)
    p.add_argument("--htm", required=True)
    p.add_argument("--htu", required=True)
    p.add_argument("--access-token", default=None)
    p.add_argument("--nonce", default=None)
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("thumbprint", help="Print the RFC 7638 JWK thumbprint (cnf.jkt).")
    p.add_argument("--key", help="Private JWK JSON file (else ephemeral key).")
    p.add_argument("--alg", default="ES256",
                   choices=["ES256", "ML-DSA-44-ES256", "ML-DSA-65-ES256"])
    p.set_defaults(func=cmd_thumbprint)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
