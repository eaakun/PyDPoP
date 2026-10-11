"""Tests for key persistence, requests integration, and the dpop CLI."""
import json

import pytest

requests = pytest.importorskip("requests")

from pydpop import (
    COMPOSITE_ALGS,
    generate_key,
    private_jwk,
    private_key_from_jwk,
    public_jwk,
    verify_proof,
)
from pydpop.cli import main as cli_main
from pydpop.integrations.requests import DPoPAuth


@pytest.mark.parametrize("alg", ["ES256", *COMPOSITE_ALGS])
def test_private_jwk_roundtrip(alg, tmp_path):
    key = generate_key(alg=alg)
    p = tmp_path / "key.json"
    p.write_text(json.dumps(private_jwk(key)))
    key2 = private_key_from_jwk(json.loads(p.read_text()))
    assert public_jwk(key2) == public_jwk(key)


def test_requests_auth_attaches_proof():
    pytest.importorskip("requests")
    import requests as rq

    key = generate_key()
    seen = {}

    class FakeAdapter(rq.adapters.HTTPAdapter):
        def send(self, request, **kw):
            seen["dpop"] = request.headers["DPoP"]
            resp = rq.Response()
            resp.status_code = 200
            resp._content = b'{"ok": true}'
            resp.headers["Content-Type"] = "application/json"
            resp.request = request
            return resp

    s = rq.Session()
    s.auth = DPoPAuth(key)
    s.mount("https://", FakeAdapter())
    r = s.post("https://auth.example.com/token", data={"a": "b"})
    assert r.status_code == 200
    result = verify_proof(proof=seen["dpop"], htm="POST", htu="https://auth.example.com/token")
    assert result["claims"]["htm"] == "POST"


def test_cli_mint_verify_roundtrip(capsys):
    assert cli_main(["mint", "--htm", "POST", "--htu", "https://x.example/token"]) == 0
    proof = capsys.readouterr().out.strip()
    assert cli_main(["verify", "--proof", proof, "--htm", "POST", "--htu", "https://x.example/token"]) == 0
    out = capsys.readouterr().out
    assert "jwk_thumbprint" in out


def test_cli_verify_rejects_bad(capsys):
    assert cli_main(["mint", "--htm", "POST", "--htu", "https://x.example/token"]) == 0
    proof = capsys.readouterr().out.strip()
    h, p, sig = proof.split(".")
    bad = h + "." + p + ".AAAA"
    assert cli_main(["verify", "--proof", bad, "--htm", "POST", "--htu", "https://x.example/token"]) == 1


def test_cli_keygen_thumbprint(tmp_path, capsys):
    assert cli_main(["keygen", "--alg", "ML-DSA-44-ES256"]) == 0
    out = capsys.readouterr().out
    jwk = json.loads(out.split("WARNING")[0])
    assert jwk["kty"] == "AKP"
    kf = tmp_path / "k.json"
    kf.write_text(json.dumps(jwk))
    assert cli_main(["thumbprint", "--key", str(kf)]) == 0
    assert len(capsys.readouterr().out.strip()) == 43
