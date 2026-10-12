"""Tests for the Flask DPoP integration (requires the flask extra)."""
import pytest

flask = pytest.importorskip("flask")
from flask import Flask, g, jsonify  # noqa: E402

from pydpop import generate_key, generate_proof  # noqa: E402
from pydpop.integrations.flask import DPoPVerifier, dpop_exempt  # noqa: E402


@pytest.fixture()
def app():
    app = Flask(__name__)
    DPoPVerifier(app)

    @app.get("/data")
    def data():
        return jsonify(jkt=g.dpop["jwk_thumbprint"])

    @app.get("/health")
    @dpop_exempt
    def health():
        return jsonify(ok=True)

    return app


@pytest.fixture()
def client(app):
    return app.test_client()


def _proof(key, token=None):
    return generate_proof(
        private_key=key, htm="GET", htu="http://localhost/data", access_token=token
    )


def test_valid_proof_reaches_view(client):
    key = generate_key()
    r = client.get("/data", headers={"DPoP": _proof(key)})
    assert r.status_code == 200
    assert len(r.json["jkt"]) == 43


def test_missing_proof_401(client):
    r = client.get("/data")
    assert r.status_code == 401
    assert r.headers["WWW-Authenticate"].startswith("DPoP")


def test_tampered_proof_401(client):
    key = generate_key()
    r = client.get("/data", headers={"DPoP": _proof(key)[:-4] + "AAAA"})
    assert r.status_code == 401


def test_replay_rejected(client):
    key = generate_key()
    proof = _proof(key)
    assert client.get("/data", headers={"DPoP": proof}).status_code == 200
    assert client.get("/data", headers={"DPoP": proof}).status_code == 401


def test_exempt_view_skips_verification(client):
    assert client.get("/health").status_code == 200


def test_ath_binding(client):
    key = generate_key()
    proof = _proof(key, token="tok123")
    h = {"DPoP": proof, "Authorization": "DPoP tok123"}
    assert client.get("/data", headers=h).status_code == 200
    h2 = {"DPoP": proof, "Authorization": "DPoP wrong"}
    assert client.get("/data", headers=h2).status_code == 401
