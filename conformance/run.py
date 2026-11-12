#!/usr/bin/env python3
"""Run the DPoP conformance corpus against the local pydpop checkout.

Usage (from the repo root, with the dev venv):

    python conformance/run.py [--dump-corpus] [--vectors [PATH]] [--json PATH]

Without flags it prints a per-case PASS/FAIL/SKIP table and a summary,
and writes conformance/conformance-report.json next to this file.
Exit code is 0 only when every runnable case passes (skips do not fail).

--dump-corpus prints the implementation-agnostic corpus (id, title,
spec, category, expected outcome) as JSON, for other implementations
to implement the same runner interface against. It is metadata only;
the full fixture vectors (proof strings + verifier inputs + expected
outcomes) live in conformance/vectors/vectors.json.

--vectors [PATH] runs the committed fixture vectors in
conformance/vectors/vectors.json (default) against the local
verifier instead of generating proofs live. Every step is evaluated
at the file's fixed reference_time with its stated clock_skew; each
case gets one fresh jti store shared across its steps (R07 replay
and N01 nonce retry depend on that). Reject steps are checked
twice: the human-readable ``reason_contains`` substring and the
machine-readable ``expect_reason`` (a ``VerificationFailure``
member), both against ``verify_proof_result``.

--vectors --matrix PATH additionally writes
conformance/compliance-matrix.json: the machine-readable export of
the corpus (per case: RFC/SEP reference, category, expected
outcome, and the VerificationFailure each rejection must return),
for other implementations to calibrate against.
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.dirname(__file__))

from cases import CASES, SkipCase, make_ctx

from pydpop.composite import mldsa_available
from pydpop.jwk import b64u_decode
from pydpop.verifier import (
    MemoryJtiStore,
    verify_proof_result,
)

VECTORS_DEFAULT = os.path.join(os.path.dirname(__file__), "vectors",
                               "vectors.json")


def run_all():
    ctx = make_ctx()
    results = []
    for case_id, title, spec, category, fn in CASES:
        try:
            fn(ctx)
        except SkipCase as exc:
            results.append((case_id, "SKIP", title, spec, category, str(exc)))
        except AssertionError as exc:
            results.append((case_id, "FAIL", title, spec, category, str(exc)))
        except Exception as exc:  # noqa: BLE001 - harness must report, not crash
            results.append((case_id, "FAIL", title, spec, category,
                            f"unexpected {type(exc).__name__}: {exc}"))
        else:
            results.append((case_id, "PASS", title, spec, category, ""))
    return results


def _subset_match(expected, actual):
    if isinstance(expected, dict):
        return isinstance(actual, dict) and all(
            k in actual and _subset_match(v, actual[k])
            for k, v in expected.items()
        )
    return expected == actual


def _decode_part(proof, index):
    return json.loads(b64u_decode(proof.split(".")[index]))


def _run_vector_step(step, ref, store):
    proof = step["proof"]
    expect = step["expect"]
    try:
        head = _decode_part(proof, 0)
    except Exception:  # noqa: BLE001 - malformed proofs have no header
        head = {}
    if head.get("alg", "").startswith("ML-DSA") and not mldsa_available():
        raise SkipCase("ML-DSA backend unavailable")
    if expect == "structure":
        claims = _decode_part(proof, 1)
        if "expect_header" in step and not _subset_match(
                step["expect_header"], head):
            raise AssertionError(f"header mismatch: {head}")
        if "expect_claims" in step and not _subset_match(
                step["expect_claims"], claims):
            raise AssertionError(f"claims mismatch: {claims}")
        return
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
    if expect == "accept":
        result = verify_proof_result(**kwargs)
        if not result.valid:
            raise AssertionError(
                f"expected accept, got {result.reason}: {result.detail}")
        if ("expect_cnf_jkt" in step
                and result.jwk_thumbprint != step["expect_cnf_jkt"]):
            raise AssertionError(
                f"cnf.jkt mismatch: {result.jwk_thumbprint}")
    elif expect == "reject":
        result = verify_proof_result(**kwargs)
        if result.valid:
            raise AssertionError("expected DPoPError, proof was accepted")
        if ("reason_contains" in step
                and step["reason_contains"] not in (result.detail or "")):
            raise AssertionError(
                f"rejected, but wrong reason: {result.detail}")
        if "expect_reason" in step:
            got = result.reason.name if result.reason else None
            if got != step["expect_reason"]:
                raise AssertionError(
                    f"rejected, but wrong VerificationFailure: "
                    f"expected {step['expect_reason']}, got {got}")
        return
    else:
        raise AssertionError(f"unknown step expectation: {expect}")


def run_vectors(path):
    """Run the committed fixture vectors; returns (doc, results)."""
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    ref = doc["reference_time"]
    results = []
    for case in doc["cases"]:
        store = MemoryJtiStore()
        try:
            for step in case["steps"]:
                _run_vector_step(step, ref, store)
        except SkipCase as exc:
            results.append((case["id"], "SKIP", case["title"], case["spec"],
                            case["category"], str(exc)))
        except AssertionError as exc:
            results.append((case["id"], "FAIL", case["title"], case["spec"],
                            case["category"], str(exc)))
        except Exception as exc:  # noqa: BLE001 - harness must report, not crash
            results.append((case["id"], "FAIL", case["title"], case["spec"],
                            case["category"],
                            f"unexpected {type(exc).__name__}: {exc}"))
        else:
            results.append((case["id"], "PASS", case["title"], case["spec"],
                            case["category"], ""))
    return doc, results


def build_matrix(doc, results):
    """Machine-readable compliance matrix for the vector suite.

    Per case: RFC/SEP reference, category, expected outcome, and
    (for rejections) the VerificationFailure the verifier must
    return — plus the outcome of this run, so another implementation
    can compare its own matrix against pydpop's cell by cell.
    """
    by_id = {cid: (status, note)
             for cid, status, _t, _s, _c, note in results}
    return {
        "format": "pydpop-compliance-matrix/1",
        "implementation": "pydpop",
        "corpus": doc["corpus"],
        "vectors": doc["format"],
        "reference_time": doc["reference_time_iso"],
        "cases": [
            {
                "id": case["id"],
                "title": case["title"],
                "spec": case["spec"],
                "category": case["category"],
                "expected": case["expected"],
                "steps": [
                    {
                        "expect": step["expect"],
                        **({"expect_reason": step["expect_reason"]}
                           if "expect_reason" in step else {}),
                    }
                    for step in case["steps"]
                ],
                "result": by_id[case["id"]][0],
                "note": by_id[case["id"]][1],
            }
            for case in doc["cases"]
        ],
        "summary": {
            "passed": sum(1 for r in results if r[1] == "PASS"),
            "skipped": sum(1 for r in results if r[1] == "SKIP"),
            "failed": sum(1 for r in results if r[1] == "FAIL"),
            "total": len(results),
        },
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dump-corpus", action="store_true")
    ap.add_argument("--vectors", nargs="?", const=VECTORS_DEFAULT, default=None)
    ap.add_argument("--json", default=None)
    ap.add_argument("--matrix", default=None,
                    help="with --vectors: also write the compliance matrix "
                         "JSON to this path")
    args = ap.parse_args()

    if args.dump_corpus:
        corpus = [
            {
                "id": cid,
                "title": title,
                "spec": spec,
                "category": category,
                "expected": "reject" if category == "reject" else "accept",
            }
            for cid, title, spec, category, _ in CASES
        ]
        print(json.dumps(corpus, indent=2, ensure_ascii=False))
        return 0

    if args.vectors is not None:
        doc, results = run_vectors(args.vectors)
        for cid, status, title, spec, category, note in results:
            line = f"[{status:4}] {cid} {title} ({spec})"
            print(line if not note else f"{line} -- {note}")
        passed = sum(1 for r in results if r[1] == "PASS")
        skipped = sum(1 for r in results if r[1] == "SKIP")
        failed = sum(1 for r in results if r[1] == "FAIL")
        print(f"\n{passed} passed, {skipped} skipped, {failed} failed "
              f"out of {len(results)} cases "
              f"(vectors {doc['format']}, ref {doc['reference_time_iso']})")
        report = {
            "implementation": "pydpop",
            "corpus": doc["corpus"],
            "vectors": doc["format"],
            "reference_time": doc["reference_time_iso"],
            "cases": [
                {
                    "id": cid,
                    "title": title,
                    "spec": spec,
                    "category": category,
                    "result": status,
                    "note": note,
                }
                for cid, status, title, spec, category, note in results
            ],
            "summary": {
                "passed": passed,
                "skipped": skipped,
                "failed": failed,
                "total": len(results),
            },
        }
        out = args.json or os.path.join(os.path.dirname(__file__),
                                        "vectors-report.json")
        with open(out, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"report written to {out}")
        if args.matrix:
            with open(args.matrix, "w", encoding="utf-8") as f:
                json.dump(build_matrix(doc, results), f, indent=2,
                          ensure_ascii=False)
            print(f"compliance matrix written to {args.matrix}")
        return 0 if failed == 0 else 1

    results = run_all()
    for cid, status, title, spec, category, note in results:
        line = f"[{status:4}] {cid} {title} ({spec})"
        print(line if not note else f"{line} -- {note}")
    passed = sum(1 for r in results if r[1] == "PASS")
    skipped = sum(1 for r in results if r[1] == "SKIP")
    failed = sum(1 for r in results if r[1] == "FAIL")
    print(f"\n{passed} passed, {skipped} skipped, {failed} failed "
          f"out of {len(results)} cases")

    report = {
        "implementation": "pydpop",
        "corpus": "RFC 9449 + SEP-1932 (DPoP Profile for MCP)",
        "cases": [
            {
                "id": cid,
                "title": title,
                "spec": spec,
                "category": category,
                "result": status,
                "note": note,
            }
            for cid, status, title, spec, category, note in results
        ],
        "summary": {
            "passed": passed,
            "skipped": skipped,
            "failed": failed,
            "total": len(results),
        },
    }
    out = args.json or os.path.join(os.path.dirname(__file__),
                                    "conformance-report.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"report written to {out}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
