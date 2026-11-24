"""`pydpop.__version__` must match pyproject.toml.

It went stale once: `__version__` stayed at "0.2.0" while the package
shipped 0.2.1 and 0.2.2. This test pins the two together so a missed
bump fails CI instead of shipping silently.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

import pydpop


def test_version_matches_pyproject():
    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    if not pyproject.exists():
        pytest.skip("pyproject.toml not present (installed layout)")
    text = pyproject.read_text(encoding="utf-8")
    version = re.search(
        r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE).group(1)
    assert pydpop.__version__ == version
