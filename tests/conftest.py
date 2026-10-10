from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from ctf_phantom.challenges import Challenge, FlagSecret, load_challenge
from ctf_phantom.environments.local import load_app_module
from ctf_phantom.paths import project_root

# Tests must never read or create the operator's real secret (~/.config/ctf-phantom/flag_secret).
TEST_SECRET_VALUE = "test-only-flag-secret-0123456789abcdef"
os.environ["CTF_PHANTOM_FLAG_SECRET"] = TEST_SECRET_VALUE
os.environ["CTF_PHANTOM_FLAG_SECRET_FILE"] = "/nonexistent/ctf-phantom-test-secret"

ROOT = project_root()
CHALLENGES = ROOT / "challenges"
TEST_FLAG = "PHANTOM{0123456789abcdef01234567}"


@pytest.fixture(scope="session")
def challenge() -> Challenge:
    return load_challenge("phantom_001", CHALLENGES)


@pytest.fixture(scope="session")
def app_module(challenge: Challenge) -> ModuleType:
    return load_app_module(str(challenge.root / challenge.spec.app.module), "_test_phantom_app")


@pytest.fixture
def make_client(app_module: ModuleType, challenge: Challenge) -> Callable[..., Any]:
    def _make(variant_id: str, flag: str = TEST_FLAG) -> Any:
        app = app_module.create_app(flag=flag, slots=dict(challenge.variant(variant_id).slots),
                                    session_secret="test-secret")
        app.testing = True
        return app.test_client()

    return _make


@pytest.fixture
def results_tmp(tmp_path: Path) -> Path:
    return tmp_path / "results"


@pytest.fixture
def secret() -> FlagSecret:
    return FlagSecret.from_value(TEST_SECRET_VALUE, "test")
