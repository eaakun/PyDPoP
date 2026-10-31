#!/usr/bin/env python3
"""Run the DPoP conformance corpus against the local pydpop checkout.

Usage (from the repo root, with the dev venv):

    python conformance/run.py [--dump-corpus] [--json PATH]

Without flags it prints a per-case PASS/FAIL/SKIP table and a summary,
and writes conformance/conformance-report.json next to this file.
Exit code is 0 only when every runnable case passes (skips do not fail).

--dump-corpus prints the implementation-agnostic corpus (id, title,
spec, category, expected outcome) as JSON, for other implementations
to implement the same runner interface against.
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from cases import CASES, SkipCase, make_ctx  # noqa: E402


def run_all():
    ctx = make_ctx()
    results = []
    for case_id, title, spec, category, fn in CASES:
        expected = "reject" if category == "reject" else "accept"
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dump-corpus", action="store_true")
    ap.add_argument("--json", default=None)
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
