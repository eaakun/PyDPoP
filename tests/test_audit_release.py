"""Tests for `dpop audit-release` (supply-chain consistency checks).

All fixtures are synthetic: a fake wheel, a minimal SLSA v1
provenance envelope, a CycloneDX SBOM, and a pyproject.toml. The
checker never touches the network and never trusts the artifacts —
it only checks they are consistent with each other.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json

import pytest

from pydpop.cli import cmd_audit_release

PYPROJECT = """[project]
name = "pydpop"
version = "0.2.2"
dependencies = [
    "cryptography>=41",
]
"""

WHEEL = b"fake wheel bytes for audit tests"
SBOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "components": [
        {"type": "library", "name": "cryptography", "version": "50.0.2"},
    ],
}


def _provenance(wheel_sha: str, commit: str = "abc123",
                builder: str = "slsa-framework/slsa-github-generator") -> dict:
    payload = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "pydpop-0.2.2-py3-none-any.whl",
                     "digest": {"sha256": wheel_sha}}],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {"buildType": "https://example.com/build@v1"},
            "runDetails": {"builder": {"id": builder},
                           "metadata": {"invocationId": "run-1"}},
            "invocation": {"configSource": {
                "uri": "git+https://github.com/eaakun/PyDPoP",
                "digest": {"sha1": commit},
                "entryPoint": ".github/workflows/supply-chain.yml"}},
        },
    }
    envelope = {
        "payloadType": "application/vnd.in-toto+json",
        "payload": base64.b64encode(
            json.dumps(payload).encode()).decode(),
        "signatures": [],
    }
    return envelope


@pytest.fixture()
def release_dir(tmp_path):
    d = tmp_path / "dist"
    d.mkdir()
    (d / "pydpop-0.2.2-py3-none-any.whl").write_bytes(WHEEL)
    (d / "pydpop-0.2.2-py3-none-any.whl.intoto.jsonl").write_text(
        json.dumps(_provenance(hashlib.sha256(WHEEL).hexdigest())) + "\n")
    (d / "sbom.cyclonedx.json").write_text(json.dumps(SBOM))
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(PYPROJECT)
    return tmp_path


def _args(release_dir, **overrides):
    kw = {
        "tag": "v0.2.2",
        "artifacts": str(release_dir / "dist"),
        "commit": "abc123",
        "provenance": None,
        "sbom": None,
        "pyproject": str(release_dir / "pyproject.toml"),
        "json": False,
    }
    kw.update(overrides)
    return argparse.Namespace(**kw)


def test_audit_release_passes(release_dir, capsys):
    assert cmd_audit_release(_args(release_dir)) == 0
    out = capsys.readouterr().out
    assert "[PASS] tag_matches_pyproject_version" in out
    assert "[PASS] provenance_subjects_match_files" in out
    assert "[PASS] sbom_cryptography_version" in out
    assert "10/10 checks passed" in out


def test_audit_release_json_report(release_dir, capsys):
    assert cmd_audit_release(_args(release_dir, json=True)) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["passed"] is True
    assert len(report["checks"]) == 10
    assert all(c["ok"] for c in report["checks"])


def test_audit_release_tag_mismatch(release_dir):
    assert cmd_audit_release(_args(release_dir, tag="v0.2.3")) == 1


def test_audit_release_wrong_subject_digest(release_dir):
    d = release_dir / "dist"
    (d / "pydpop-0.2.2-py3-none-any.whl").write_bytes(b"tampered bytes")
    assert cmd_audit_release(_args(release_dir)) == 1


def test_audit_release_wrong_commit(release_dir):
    assert cmd_audit_release(_args(release_dir, commit="deadbeef")) == 1


def test_audit_release_missing_provenance(release_dir):
    (release_dir / "dist" / "pydpop-0.2.2-py3-none-any.whl.intoto.jsonl"
     ).unlink()
    assert cmd_audit_release(_args(release_dir)) == 1


def test_audit_release_sbom_missing_cryptography(release_dir):
    sbom = dict(SBOM, components=[])
    (release_dir / "dist" / "sbom.cyclonedx.json").write_text(
        json.dumps(sbom))
    assert cmd_audit_release(_args(release_dir)) == 1


def test_audit_release_sbom_old_cryptography(release_dir):
    sbom = dict(SBOM, components=[
        {"type": "library", "name": "cryptography", "version": "40.0.0"}])
    (release_dir / "dist" / "sbom.cyclonedx.json").write_text(
        json.dumps(sbom))
    assert cmd_audit_release(_args(release_dir)) == 1


def test_audit_release_non_slsa_builder(release_dir):
    d = release_dir / "dist"
    (d / "pydpop-0.2.2-py3-none-any.whl.intoto.jsonl").write_text(
        json.dumps(_provenance(hashlib.sha256(WHEEL).hexdigest(),
                               builder="my-laptop")) + "\n")
    assert cmd_audit_release(_args(release_dir)) == 1
