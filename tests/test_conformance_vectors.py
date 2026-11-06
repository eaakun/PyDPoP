"""The committed fixture vectors must pass against the current verifier.

Loads conformance/vectors/vectors.json through the conformance
runner's own vector mode, so the vectors are a living artifact:
any verifier change that breaks a vector fails the suite.
Skips are allowed only for the hybrid cases (G05, A06) when the
ML-DSA backend is unavailable.
"""

import importlib.util
import os

from pydpop.composite import mldsa_available

_RUN = os.path.join(os.path.dirname(__file__), "..", "conformance", "run.py")
_VECTORS = os.path.join(
    os.path.dirname(__file__), "..", "conformance", "vectors", "vectors.json"
)


def _load_runner():
    spec = importlib.util.spec_from_file_location("conformance_run", _RUN)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_committed_vectors_pass():
    runner = _load_runner()
    doc, results = runner.run_vectors(_VECTORS)
    assert len(results) == 28
    assert doc["format"] == "pydpop-conformance-vectors/1"
    failed = [r for r in results if r[1] == "FAIL"]
    assert not failed, failed
    skipped = [r for r in results if r[1] == "SKIP"]
    if not mldsa_available():
        assert {r[0] for r in skipped} <= {"G05", "A06"}
    else:
        assert not skipped
