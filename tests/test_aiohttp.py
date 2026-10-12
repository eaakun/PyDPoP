"""Tests for the aiohttp DPoP client session (requires the aiohttp extra)."""
import pytest

aiohttp = pytest.importorskip("aiohttp")
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from pydpop import generate_key, verify_proof
from pydpop.integrations.aiohttp import DPoPClientSession

pytestmark = pytest.mark.asyncio


async def _make_client(handler):
    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", handler)
    client = TestClient(TestServer(app))
    await client.start_server()
    return client


async def test_proof_attached_and_verifiable():
    seen = {}

    async def handler(request):
        seen["dpop"] = request.headers["DPoP"]
        seen["htu"] = str(request.url.with_query(None))
        return web.json_response({"ok": True})

    client = await _make_client(handler)
    try:
        key = generate_key()
        async with DPoPClientSession(key) as sess:
            async with sess.post(client.make_url("/token"), data={"a": "b"}) as resp:
                assert resp.status == 200
        result = verify_proof(proof=seen["dpop"], htm="POST", htu=seen["htu"])
        assert result["claims"]["htm"] == "POST"
    finally:
        await client.close()


async def test_nonce_challenge_retried_once():
    calls = {"n": 0}

    async def handler(request):
        calls["n"] += 1
        if calls["n"] == 1:
            return web.Response(
                status=400,
                headers={"WWW-Authenticate": 'DPoP error="use_dpop_nonce"',
                         "DPoP-Nonce": "srv-nonce-1"},
            )
        # second call must carry the server nonce
        proof = request.headers["DPoP"]
        result = verify_proof(
            proof=proof, htm="GET", htu=str(request.url.with_query(None)),
            expected_nonce="srv-nonce-1",
        )
        assert result["claims"]["nonce"] == "srv-nonce-1"
        return web.json_response({"ok": True})

    client = await _make_client(handler)
    try:
        key = generate_key()
        async with DPoPClientSession(key) as sess:
            async with sess.get(client.make_url("/data")) as resp:
                assert resp.status == 200
        assert calls["n"] == 2
    finally:
        await client.close()


async def test_ath_binding():
    seen = {}

    async def handler(request):
        seen["auth"] = request.headers.get("Authorization")
        seen["dpop"] = request.headers["DPoP"]
        return web.json_response({"ok": True})

    client = await _make_client(handler)
    try:
        key = generate_key()
        async with DPoPClientSession(key, access_token="tok123") as sess:
            async with sess.get(client.make_url("/x")) as resp:
                assert resp.status == 200
        assert seen["auth"] == "DPoP tok123"
        result = verify_proof(
            proof=seen["dpop"], htm="GET",
            htu="http://127.0.0.1:%d/x" % client.server.port,
            access_token="tok123",
        )
        assert result["claims"]["htm"] == "GET"
    finally:
        await client.close()
