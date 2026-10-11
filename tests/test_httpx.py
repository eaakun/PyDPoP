"""Tests for the httpx DPoP integration (requires the httpx extra)."""
import pytest

httpx = pytest.importorskip("httpx")

from pydpop import generate_key, verify_proof
from pydpop.integrations.httpx import DPoPAuth


def _client(handler, key, **kw):
    return httpx.Client(transport=httpx.MockTransport(handler), auth=DPoPAuth(key, **kw))


def test_proof_attached_and_verifies():
    key = generate_key()
    seen = {}

    def handler(request):
        seen["dpop"] = request.headers["DPoP"]
        return httpx.Response(200, json={"ok": True})

    r = _client(handler, key).post("https://auth.example.com/token", data={"a": "b"})
    assert r.status_code == 200
    result = verify_proof(proof=seen["dpop"], htm="POST", htu="https://auth.example.com/token")
    assert result["claims"]["htm"] == "POST"


def test_nonce_challenge_retried_once():
    key = generate_key()
    calls = []

    def handler(request):
        calls.append(request.headers["DPoP"])
        if len(calls) == 1:
            return httpx.Response(400, headers={"DPoP-Nonce": "srv-nonce-1"}, json={"error": "use_dpop_nonce"})
        return httpx.Response(200, json={"ok": True})

    client = _client(handler, key)
    r = client.post("https://auth.example.com/token")
    assert r.status_code == 200
    assert len(calls) == 2
    assert client.auth.nonce == "srv-nonce-1"
    # second proof carries the nonce claim
    result = verify_proof(proof=calls[1], htm="POST", htu="https://auth.example.com/token", expected_nonce="srv-nonce-1")
    assert result["claims"]["nonce"] == "srv-nonce-1"


def test_nonce_cached_for_later_requests():
    key = generate_key()

    def handler(request):
        return httpx.Response(200, json={"ok": True})

    client = _client(handler, key)
    client.auth._nonce = "cached-nonce"
    r = client.get("https://api.example.com/data")
    assert r.status_code == 200


def test_hybrid_key_over_httpx():
    key = generate_key(alg="ML-DSA-44-ES256")
    seen = {}

    def handler(request):
        seen["dpop"] = request.headers["DPoP"]
        return httpx.Response(200, json={"ok": True})

    _client(handler, key).get("https://api.example.com/data")
    result = verify_proof(proof=seen["dpop"], htm="GET", htu="https://api.example.com/data")
    assert result["jwk"]["alg"] == "ML-DSA-44-ES256"


def test_access_token_binds_ath():
    key = generate_key()
    seen = {}

    def handler(request):
        seen["dpop"] = request.headers["DPoP"]
        return httpx.Response(200, json={"ok": True})

    _client(handler, key, access_token="tok123").get("https://api.example.com/data")
    verify_proof(proof=seen["dpop"], htm="GET", htu="https://api.example.com/data", access_token="tok123")
