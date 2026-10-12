"""Tests for the Django DPoP middleware (requires the django extra)."""
import pytest

django = pytest.importorskip("django")
from django.conf import settings  # noqa: E402

if not settings.configured:
    settings.configure(
        DEBUG=True,
        ALLOWED_HOSTS=["*"],
        ROOT_URLCONF=__name__,
        MIDDLEWARE=["pydpop.integrations.django.DPoPMiddleware"],
        PYDPOP_DPOP={},
    )
    django.setup()

from django.http import JsonResponse  # noqa: E402
from django.test import Client  # noqa: E402
from django.urls import path  # noqa: E402

from pydpop import generate_key, generate_proof  # noqa: E402
from pydpop.integrations.django import DPoPMiddleware, dpop_exempt  # noqa: E402


def data_view(request):
    return JsonResponse({"jkt": request.dpop["jwk_thumbprint"]})


@dpop_exempt
def health_view(request):
    return JsonResponse({"ok": True})


urlpatterns = [
    path("data", data_view),
    path("health", health_view),
]


@pytest.fixture()
def client():
    return Client()


def _proof(key, token=None):
    return generate_proof(
        private_key=key, htm="GET", htu="http://testserver/data", access_token=token
    )


def test_valid_proof_reaches_view(client):
    key = generate_key()
    r = client.get("/data", HTTP_DPOP=_proof(key))
    assert r.status_code == 200
    assert len(r.json()["jkt"]) == 43


def test_missing_proof_401(client):
    r = client.get("/data")
    assert r.status_code == 401
    assert r["WWW-Authenticate"].startswith("DPoP")


def test_tampered_proof_401(client):
    key = generate_key()
    proof = _proof(key)
    r = client.get("/data", HTTP_DPOP=proof[:-4] + "AAAA")
    assert r.status_code == 401


def test_replay_rejected(client):
    key = generate_key()
    proof = _proof(key)
    assert client.get("/data", HTTP_DPOP=proof).status_code == 200
    assert client.get("/data", HTTP_DPOP=proof).status_code == 401


def test_exempt_view_skips_verification(client):
    assert client.get("/health").status_code == 200


def test_ath_binding(client):
    key = generate_key()
    proof = _proof(key, token="tok123")
    r = client.get("/data", HTTP_DPOP=proof, HTTP_AUTHORIZATION="DPoP tok123")
    assert r.status_code == 200
    r2 = client.get("/data", HTTP_DPOP=proof, HTTP_AUTHORIZATION="DPoP wrong")
    assert r2.status_code == 401


def test_middleware_importable_without_django_settings():
    assert DPoPMiddleware is not None
