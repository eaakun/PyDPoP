"""The ``dpop`` command: mint, verify, and inspect DPoP proofs from the shell.

Handy for debugging your OAuth flow without writing a script:

    $ dpop keygen --alg ML-DSA-44-ES256 > key.json   # keep key.json secret!
    $ dpop mint --key key.json --htm POST --htu https://auth.example.com/token
    $ dpop verify --proof <proof> --htm POST --htu https://auth.example.com/token

``dpop serve --conformance`` starts a minimal oracle for
cross-language interop tests: other languages' clients POST proofs
to ``/verify`` and compare the structured result; other languages'
servers fetch the 28-case fixture vectors from ``/vectors`` and the
live compliance matrix from ``/matrix``.
"""
from __future__ import annotations

import argparse
import base64
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files as _res_files

from .jwk import (
    b64u_decode,
    generate_key,
    jwk_thumbprint,
    private_jwk,
    private_key_from_jwk,
    public_jwk,
)
from .proof import generate_proof
from .verifier import DPoPError, MemoryJtiStore, verify_proof, verify_proof_result


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


# --- conformance oracle (pydpop serve --conformance) ------------------------

def _load_vectors(path: str | None) -> dict:
    """Load the fixture vectors: an explicit path, else the copy
    embedded in the installed package (kept byte-identical to
    conformance/vectors/vectors.json; see tests/test_conformance_serve.py).
    The embedded key is TEST ONLY and labelled as such in the file."""
    if path:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    text = _res_files("pydpop").joinpath("vectors.json").read_text(
        encoding="utf-8")
    return json.loads(text)


def _subset_match(expected, actual) -> bool:
    if isinstance(expected, dict):
        return isinstance(actual, dict) and all(
            k in actual and _subset_match(v, actual[k])
            for k, v in expected.items()
        )
    return expected == actual


def _eval_vector_step(step: dict, ref: int, store) -> tuple[bool, str]:
    """Evaluate one vector step; returns (passed, note). Mirrors
    conformance/run.py semantics for the /matrix endpoint."""
    proof = step["proof"]
    expect = step["expect"]
    if expect == "structure":
        try:
            head = json.loads(b64u_decode(proof.split(".")[0]))
            claims = json.loads(b64u_decode(proof.split(".")[1]))
        except Exception as exc:  # noqa: BLE001 - malformed fixture
            return False, f"cannot decode proof: {exc}"
        if "expect_header" in step and not _subset_match(
                step["expect_header"], head):
            return False, f"header mismatch: {head}"
        if "expect_claims" in step and not _subset_match(
                step["expect_claims"], claims):
            return False, f"claims mismatch: {claims}"
        return True, ""
    kwargs = {
        "proof": proof,
        "htm": step["htm"],
        "htu": step["htu"],
        "now": ref,
        "clock_skew": step.get("clock_skew", 300),
        "jti_store": store,
    }
    if "access_token" in step:
        kwargs["access_token"] = step["access_token"]
    if "expected_nonce" in step:
        kwargs["expected_nonce"] = step["expected_nonce"]
    result = verify_proof_result(**kwargs)
    if expect == "accept":
        if not result.valid:
            return False, f"expected accept, got {result.reason}"
        if ("expect_cnf_jkt" in step
                and result.jwk_thumbprint != step["expect_cnf_jkt"]):
            return False, "cnf.jkt mismatch"
        return True, ""
    if expect == "reject":
        if result.valid:
            return False, "expected rejection, proof was accepted"
        if ("reason_contains" in step
                and step["reason_contains"] not in (result.detail or "")):
            return False, f"wrong reason: {result.detail}"
        if "expect_reason" in step:
            got = result.reason.name if result.reason else None
            if got != step["expect_reason"]:
                return False, (
                    f"wrong VerificationFailure: expected "
                    f"{step['expect_reason']}, got {got}")
        return True, ""
    return False, f"unknown step expectation: {expect}"


def _build_matrix(doc: dict) -> dict:
    """Run the embedded vectors against the local verifier and return
    the compliance matrix (same shape as
    conformance/compliance-matrix.json)."""
    ref = doc["reference_time"]
    cases = []
    for case in doc["cases"]:
        store = MemoryJtiStore()
        status, note = "PASS", ""
        for step in case["steps"]:
            ok, step_note = _eval_vector_step(step, ref, store)
            if not ok:
                status, note = "FAIL", step_note
                break
        cases.append({
            "id": case["id"],
            "title": case["title"],
            "spec": case["spec"],
            "category": case["category"],
            "expected": case["expected"],
            "steps": [
                {"expect": s["expect"],
                 **({"expect_reason": s["expect_reason"]}
                    if "expect_reason" in s else {})}
                for s in case["steps"]
            ],
            "result": status,
            "note": note,
        })
    return {
        "format": "pydpop-compliance-matrix/1",
        "implementation": "pydpop",
        "corpus": doc["corpus"],
        "vectors": doc["format"],
        "reference_time": doc["reference_time_iso"],
        "cases": cases,
        "summary": {
            "passed": sum(1 for c in cases if c["result"] == "PASS"),
            "skipped": 0,
            "failed": sum(1 for c in cases if c["result"] == "FAIL"),
            "total": len(cases),
        },
    }


def _make_conformance_handler(doc: dict, store):
    """HTTP handler for the oracle. State: one shared jti store for
    the server lifetime (stateful, like a real deployment); POST
    /reset clears it — test-only. Verification outcomes are always
    HTTP 200 with the structured result in the body."""
    holder = [store]  # rebindable so /reset can swap in a fresh store

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):  # keep stdout clean
            pass

        def _send_json(self, payload, status=200):
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path == "/health":
                self._send_json({
                    "status": "ok",
                    "service": "pydpop-conformance",
                    "vectors": len(doc["cases"]),
                    "format": doc["format"],
                })
            elif self.path == "/vectors":
                self._send_json(doc)
            elif self.path == "/matrix":
                self._send_json(_build_matrix(doc))
            else:
                self._send_json({"error": "not found"}, status=404)

        def do_POST(self):
            length = int(self.headers.get("Content-Length") or 0)
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
            except json.JSONDecodeError:
                self._send_json({"error": "invalid JSON"}, status=400)
                return
            if self.path == "/reset":
                holder[0] = MemoryJtiStore()
                self._send_json({"status": "ok", "reset": True})
                return
            if self.path != "/verify":
                self._send_json({"error": "not found"}, status=404)
                return
            proof = body.get("proof")
            htm = body.get("htm")
            htu = body.get("htu")
            if not isinstance(proof, str) or not htm or not htu:
                self._send_json(
                    {"error": "proof, htm and htu are required"},
                    status=400)
                return
            result = verify_proof_result(
                proof=proof, htm=htm, htu=htu,
                access_token=body.get("access_token"),
                expected_nonce=body.get("expected_nonce"),
                clock_skew=body.get("clock_skew", 60),
                now=body.get("now"),
                jti_store=holder[0],
            )
            self._send_json({
                "valid": result.valid,
                "reason": result.reason.name if result.reason else None,
                "detail": result.detail,
                "jwk_thumbprint": result.jwk_thumbprint,
                "claims": result.claims,
            })

    return Handler


def cmd_serve(args: argparse.Namespace) -> int:
    doc = _load_vectors(args.vectors)
    store = MemoryJtiStore()
    handler = _make_conformance_handler(doc, store)
    server = ThreadingHTTPServer((args.host, args.port), handler)
    host, port = server.server_address
    print(f"pydpop conformance oracle on http://{host}:{port} "
          f"({len(doc['cases'])} cases, {doc['format']})", file=sys.stderr)
    print("endpoints: GET /health /vectors /matrix, POST /verify /reset",
          file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


# --- release audit (dpop audit-release) -------------------------------------

def _read_pyproject(path: str) -> tuple[str, list[str]]:
    """Minimal reader for this repo's pyproject.toml: returns
    (version, runtime dependency specs). Regex-based on purpose —
    no TOML parser is a runtime dependency; the layout is pinned by
    tests/test_audit_release.py."""
    import re

    with open(path, encoding="utf-8") as f:
        text = f.read()
    version = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE).group(1)
    deps_block = re.search(r"^dependencies\s*=\s*\[(.*?)\]", text,
                           re.MULTILINE | re.DOTALL).group(1)
    deps = re.findall(r'"([^"]+)"', deps_block)
    return version, deps


def _ver_tuple(version: str) -> tuple[int, ...]:
    return tuple(int(p) for p in version.split(".") if p.isdigit())


def _audit_checks(args: argparse.Namespace) -> list[dict]:
    """Run every consistency check; each returns a dict with
    (name, ok, detail). No network, no trust in the artifacts
    themselves — this is a consistency check, not a signature
    verification (verify Sigstore bundles with `sigstore verify`)."""
    import hashlib
    import os

    checks: list[dict] = []

    def check(name: str, ok: bool, detail: str) -> None:
        checks.append({"name": name, "ok": ok, "detail": detail})

    version, deps = _read_pyproject(args.pyproject)
    tag = args.tag.lstrip("v")
    check("tag_matches_pyproject_version", tag == version,
          f"tag {args.tag} vs pyproject version {version}")

    artifacts = sorted(
        p for p in os.listdir(args.artifacts)
        if p.endswith((".whl", ".tar.gz")))
    check("artifacts_present", bool(artifacts),
          f"{len(artifacts)} distribution file(s) in {args.artifacts}")

    prov_paths = sorted(
        os.path.join(args.artifacts, p)
        for p in os.listdir(args.artifacts)
        if p.endswith(".intoto.jsonl"))
    if args.provenance:
        prov_paths = [args.provenance]
    check("provenance_present", bool(prov_paths),
          "no .intoto.jsonl provenance found" if not prov_paths
          else f"{len(prov_paths)} provenance file(s)")
    subjects: dict[str, str] = {}
    builder_ok, commit_ok = False, args.commit is None
    for path in prov_paths:
        try:
            with open(path, encoding="utf-8") as f:
                envelope = json.loads(f.readline())
            payload = json.loads(
                base64.b64decode(envelope["payload"]).decode("utf-8"))
        except Exception as exc:  # noqa: BLE001 - malformed fixture
            check("provenance_parseable", False, f"{path}: {exc}")
            continue
        predicate = payload.get("predicate", {})
        builder = predicate.get("runDetails", {}).get("builder", {})
        if "slsa" in builder.get("id", ""):
            builder_ok = True
        config = predicate.get("invocation", {}).get("configSource", {})
        digest = config.get("digest", {})
        if args.commit and digest.get("sha1") == args.commit:
            commit_ok = True
        for subject in payload.get("subject", []):
            subjects[subject["name"]] = subject["digest"].get("sha256", "")
    if prov_paths:
        check("provenance_parseable", True, "all provenance files parse")
        check("provenance_builder_is_slsa", builder_ok,
              "builder id does not mention slsa" if not builder_ok
              else "SLSA generator builder id")
        if args.commit:
            check("provenance_commit_matches_tag", commit_ok,
                  f"no provenance configSource sha1 == {args.commit}")
        mismatches = []
        for name in artifacts:
            with open(os.path.join(args.artifacts, name), "rb") as f:
                actual = hashlib.sha256(f.read()).hexdigest()
            if subjects.get(name) != actual:
                mismatches.append(name)
        check("provenance_subjects_match_files", not mismatches,
              ("digests differ for: " + ", ".join(mismatches)) if mismatches
              else f"{len(artifacts)} subject digest(s) match")

    sbom_path = args.sbom
    if not sbom_path:
        candidates = sorted(
            os.path.join(args.artifacts, p)
            for p in os.listdir(args.artifacts)
            if p.endswith(".cyclonedx.json"))
        sbom_path = candidates[0] if candidates else None
    check("sbom_present", sbom_path is not None,
          "no CycloneDX SBOM found" if not sbom_path else sbom_path)
    if sbom_path:
        with open(sbom_path, encoding="utf-8") as f:
            sbom = json.load(f)
        components = {c.get("name", "").lower(): c.get("version", "")
                      for c in sbom.get("components", [])}
        dep_names = [d.split(">", 1)[0].split("<", 1)[0].split("=", 1)[0]
                     .strip().lower() for d in deps]
        missing = [d for d in dep_names if d not in components]
        check("sbom_covers_pyproject_dependencies", not missing,
              ("missing from SBOM: " + ", ".join(missing)) if missing
              else f"{len(dep_names)} runtime dep(s) in SBOM")
        crypto = components.get("cryptography")
        crypto_ok = bool(crypto) and _ver_tuple(crypto) >= (41,)
        check("sbom_cryptography_version", crypto_ok,
              f"cryptography in SBOM: {crypto}")
    return checks


def cmd_audit_release(args: argparse.Namespace) -> int:
    checks = _audit_checks(args)
    failed = [c for c in checks if not c["ok"]]
    if args.json:
        print(json.dumps({"passed": not failed, "checks": checks}, indent=2))
    else:
        for c in checks:
            print(f"[{'PASS' if c['ok'] else 'FAIL'}] {c['name']}: "
                  f"{c['detail']}")
        print(f"\n{len(checks) - len(failed)}/{len(checks)} checks passed")
        if failed:
            print("NOTE: this is a consistency check only — verify "
                  "Sigstore signatures separately with `sigstore verify`.")
    return 0 if not failed else 1


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

    p = sub.add_parser("serve", help="Run the conformance oracle HTTP server.")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8931)
    p.add_argument("--vectors", default=None,
                   help="Vectors JSON path (default: the copy embedded in "
                        "the installed package).")
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("audit-release",
                       help="Consistency-check a release directory "
                            "(provenance, tag, SBOM).")
    p.add_argument("--tag", required=True, help="Release tag, e.g. v0.2.2.")
    p.add_argument("--artifacts", required=True,
                   help="Directory holding the wheel/sdist, provenance "
                        "(.intoto.jsonl) and SBOM (.cyclonedx.json).")
    p.add_argument("--commit", default=None,
                   help="Expected source commit (provenance configSource "
                        "sha1).")
    p.add_argument("--provenance", default=None,
                   help="Provenance file (default: auto-find in "
                        "--artifacts).")
    p.add_argument("--sbom", default=None,
                   help="SBOM file (default: auto-find in --artifacts).")
    p.add_argument("--pyproject", default="pyproject.toml")
    p.add_argument("--json", action="store_true",
                   help="Print the report as JSON.")
    p.set_defaults(func=cmd_audit_release)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
