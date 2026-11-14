"""Tests for the FastAPI DPoP integration (requires the fastapi extra)."""
import pytest

fastapi = pytest.importorskip("fastapi")
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from pydpop import generate_key, generate_proof
from pydpop.integrations.fastapi import DPoPVerifier


def _app(**kw):
    app = FastAPI()
    verify_dpop = DPoPVerifier(**kw)

    @app.get("/data")
    def read_data(bound=Depends(verify_dpop)):
        return {"jkt": bound["jwk_thumbprint"]}

    return app


def test_valid_proof_reaches_endpoint():
    key = generate_key()
    client = TestClient(_app())
    proof = generate_proof(private_key=key, htm="GET", htu="http://testserver/data")
    r = client.get("/data", headers={"DPoP": proof})
    assert r.status_code == 200
    assert len(r.json()["jkt"]) == 43


def test_missing_proof_401():
    client = TestClient(_app())
    r = client.get("/data")
    assert r.status_code == 401
    assert r.headers["WWW-Authenticate"].startswith("DPoP")


def test_tampered_proof_401():
    key = generate_key()
    client = TestClient(_app())
    proof = generate_proof(private_key=key, htm="GET", htu="http://testserver/data")
    r = client.get("/data", headers={"DPoP": proof[:-4] + "AAAA"})
    assert r.status_code == 401


def test_replay_rejected():
    key = generate_key()
    client = TestClient(_app())
    proof = generate_proof(private_key=key, htm="GET", htu="http://testserver/data")
    assert client.get("/data", headers={"DPoP": proof}).status_code == 200
    assert client.get("/data", headers={"DPoP": proof}).status_code == 401


def test_access_token_ath_binding():
    key = generate_key()
    client = TestClient(_app())
    proof = generate_proof(
        private_key=key, htm="GET", htu="http://testserver/data", access_token="tok123"
    )
    r = client.get(
        "/data",
        headers={"DPoP": proof, "Authorization": "DPoP tok123"},
    )
    assert r.status_code == 200
    r2 = client.get(
        "/data",
        headers={"DPoP": proof, "Authorization": "DPoP wrong"},
    )
    assert r2.status_code == 401


def test_hybrid_proof_over_fastapi():
    key = generate_key(alg="ML-DSA-44-ES256")
    client = TestClient(_app())
    proof = generate_proof(private_key=key, htm="GET", htu="http://testserver/data")
    r = client.get("/data", headers={"DPoP": proof})
    assert r.status_code == 200
