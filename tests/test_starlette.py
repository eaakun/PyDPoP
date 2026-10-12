"""Tests for the Starlette DPoP middleware (requires the starlette extra)."""
import pytest

starlette = pytest.importorskip("starlette")
from starlette.applications import Starlette  # noqa: E402
from starlette.responses import JSONResponse  # noqa: E402
from starlette.routing import Route  # noqa: E402
from starlette.testclient import TestClient  # noqa: E402

from pydpop import generate_key, generate_proof  # noqa: E402
from pydpop.integrations.starlette import DPoPMiddleware  # noqa: E402


async def data(request):
    return JSONResponse({"jkt": request.scope["dpop"]["jwk_thumbprint"]})


@pytest.fixture()
def client():
    app = Starlette(routes=[Route("/data", data)])
    app.add_middleware(DPoPMiddleware)
    return TestClient(app)


def _proof(key, token=None):
    return generate_proof(
        private_key=key, htm="GET", htu="http://testserver/data", access_token=token
    )


def test_valid_proof_reaches_endpoint(client):
    key = generate_key()
    r = client.get("/data", headers={"DPoP": _proof(key)})
    assert r.status_code == 200
    assert len(r.json()["jkt"]) == 43


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


def test_ath_binding(client):
    key = generate_key()
    proof = _proof(key, token="tok123")
    h = {"DPoP": proof, "Authorization": "DPoP tok123"}
    assert client.get("/data", headers=h).status_code == 200
    h2 = {"DPoP": proof, "Authorization": "DPoP wrong"}
    assert client.get("/data", headers=h2).status_code == 401


def test_hybrid_proof(client):
    key = generate_key(alg="ML-DSA-44-ES256")
    r = client.get("/data", headers={"DPoP": _proof(key)})
    assert r.status_code == 200
