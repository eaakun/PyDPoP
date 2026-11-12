"""Tests for `pydpop serve --conformance` (cross-language oracle).

The server is started on an ephemeral port in a background thread;
tests exercise every endpoint with http.client. Also pins the sync
rule: the vectors embedded in the installed package
(src/pydpop/vectors.json) must be byte-identical to
conformance/vectors/vectors.json, so the oracle never serves a
stale fixture set.
"""
from __future__ import annotations

import http.client
import json
import os
import threading

import pytest

from pydpop import generate_key, generate_proof
from pydpop.cli import _load_vectors, _make_conformance_handler
from pydpop.verifier import MemoryJtiStore

HTM = "POST"
HTU = "https://server.example.com/token"


def test_embedded_vectors_match_repo_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "..", "src", "pydpop", "vectors.json"),
              "rb") as f:
        embedded = f.read()
    with open(os.path.join(here, "..", "conformance", "vectors",
                           "vectors.json"), "rb") as f:
        repo = f.read()
    assert embedded == repo, (
        "src/pydpop/vectors.json drifted from "
        "conformance/vectors/vectors.json — copy it after regenerating")


class _Server:
    def __init__(self):
        from http.server import ThreadingHTTPServer

        doc = _load_vectors(None)
        self.handler = _make_conformance_handler(doc, MemoryJtiStore())
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), self.handler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever,
                                       daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()

    def request(self, method, path, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        payload = json.dumps(body) if body is not None else None
        headers = {"Content-Type": "application/json"} if payload else {}
        conn.request(method, path, body=payload, headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp.status, json.loads(data) if data else {}


@pytest.fixture(scope="module")
def server():
    with _Server() as srv:
        yield srv


def test_health_and_vectors(server):
    status, body = server.request("GET", "/health")
    assert status == 200
    assert body["status"] == "ok"
    assert body["vectors"] == 28
    assert body["format"] == "pydpop-conformance-vectors/1"

    status, body = server.request("GET", "/vectors")
    assert status == 200
    assert len(body["cases"]) == 28
    assert body["cases"][0]["id"] == "G01"


def test_verify_accept_then_replay(server):
    key = generate_key()
    proof = generate_proof(private_key=key, htm=HTM, htu=HTU)
    status, body = server.request("POST", "/verify", {
        "proof": proof, "htm": HTM, "htu": HTU,
    })
    assert status == 200
    assert body["valid"] is True
    assert body["reason"] is None
    assert body["jwk_thumbprint"]

    # Same proof again: the shared store sees the replay.
    status, body = server.request("POST", "/verify", {
        "proof": proof, "htm": HTM, "htu": HTU,
    })
    assert body["valid"] is False
    assert body["reason"] == "REPLAY_DETECTED"

    # Reset clears the store: the proof verifies again.
    status, _ = server.request("POST", "/reset")
    assert status == 200
    status, body = server.request("POST", "/verify", {
        "proof": proof, "htm": HTM, "htu": HTU,
    })
    assert body["valid"] is True


def test_verify_rejects_tampered_proof(server):
    key = generate_key()
    proof = generate_proof(private_key=key, htm=HTM, htu=HTU)
    head, payload, sig = proof.split(".")
    tampered = f"{head}.{payload}.{'A' * len(sig)}"
    status, body = server.request("POST", "/verify", {
        "proof": tampered, "htm": HTM, "htu": HTU,
    })
    assert status == 200
    assert body["valid"] is False
    assert body["reason"] == "BAD_SIGNATURE"


def test_verify_bad_request(server):
    status, _ = server.request("POST", "/verify", {"htm": HTM})
    assert status == 400
    status, _ = server.request("GET", "/nope")
    assert status == 404


def test_matrix_is_all_pass(server):
    status, body = server.request("GET", "/matrix")
    assert status == 200
    assert body["format"] == "pydpop-compliance-matrix/1"
    assert body["summary"] == {
        "passed": 28, "skipped": 0, "failed": 0, "total": 28,
    }
    r07 = next(c for c in body["cases"] if c["id"] == "R07")
    assert r07["steps"][1]["expect_reason"] == "REPLAY_DETECTED"


# --- evaluator failure branches (coverage of the oracle internals) ---------

def test_load_vectors_explicit_path(tmp_path):
    from pydpop.cli import _load_vectors

    src = _load_vectors(None)
    path = tmp_path / "vectors.json"
    path.write_text(json.dumps(src), encoding="utf-8")
    assert _load_vectors(str(path)) == src


def test_eval_step_failure_branches():
    from pydpop.cli import _eval_vector_step

    key = generate_key()
    store = MemoryJtiStore()
    good = generate_proof(private_key=key, htm=HTM, htu=HTU, iat=1_700_000_000)
    head, payload, sig = good.split(".")
    tampered = f"{head}.{payload}.{'A' * len(sig)}"

    def step(proof, expect, **kw):
        d = {"proof": proof, "htm": HTM, "htu": HTU, "clock_skew": 60,
             "expect": expect}
        d.update(kw)
        return d

    # structure: undecodable proof
    ok, note = _eval_vector_step(step("not.a.jwt", "structure"), 0, store)
    assert ok is False and "cannot decode" in note
    # structure: header / claims mismatch
    ok, note = _eval_vector_step(
        step(good, "structure", expect_header={"typ": "nope"}), 0, store)
    assert ok is False and "header mismatch" in note
    ok, note = _eval_vector_step(
        step(good, "structure", expect_claims={"htm": "GET"}), 0, store)
    assert ok is False and "claims mismatch" in note
    # accept: proof that fails verification
    ok, note = _eval_vector_step(
        step(tampered, "accept"), 1_700_000_000, store)
    assert ok is False and "expected accept" in note
    # accept: wrong cnf.jkt
    ok, note = _eval_vector_step(
        step(good, "accept", expect_cnf_jkt="wrong"), 1_700_000_000, store)
    assert ok is False and "cnf.jkt mismatch" in note
    # reject: proof that verifies (fresh proof — the earlier `good`
    # proof already consumed its jti in the cnf step above, so
    # re-verifying it would be a replay, not an acceptance)
    fresh = generate_proof(private_key=key, htm=HTM, htu=HTU,
                           iat=1_700_000_000, jti="fresh-reject-1")
    ok, note = _eval_vector_step(
        step(fresh, "reject"), 1_700_000_000, store)
    assert ok is False and "expected rejection" in note
    # reject: wrong reason_contains / wrong expect_reason
    ok, note = _eval_vector_step(
        step(tampered, "reject", reason_contains="htm mismatch"),
        1_700_000_000, store)
    assert ok is False and "wrong reason" in note
    ok, note = _eval_vector_step(
        step(tampered, "reject", reason_contains="bad signature",
             expect_reason="ATH_MISMATCH"), 1_700_000_000, store)
    assert ok is False and "wrong VerificationFailure" in note
    # unknown expectation
    ok, note = _eval_vector_step(step(good, "sideways"), 0, store)
    assert ok is False and "unknown step expectation" in note


def test_post_invalid_json_and_unknown_path(server):
    conn = http.client.HTTPConnection("127.0.0.1", server.port, timeout=5)
    conn.request("POST", "/verify", body="{not json",
                 headers={"Content-Type": "application/json"})
    resp = conn.getresponse()
    assert resp.status == 400
    resp.read()
    conn.request("POST", "/nope", body="{}",
                 headers={"Content-Type": "application/json"})
    resp = conn.getresponse()
    assert resp.status == 404
    resp.read()
    conn.close()


def test_cmd_serve_starts_and_handles_keyboard_interrupt(monkeypatch):
    import argparse

    from pydpop import cli as cli_mod

    class _FakeServer:
        def __init__(self, addr, handler):
            self.server_address = addr

        def serve_forever(self):
            raise KeyboardInterrupt

    monkeypatch.setattr(cli_mod, "ThreadingHTTPServer", _FakeServer)
    args = argparse.Namespace(host="127.0.0.1", port=0, vectors=None)
    assert cli_mod.cmd_serve(args) == 0
