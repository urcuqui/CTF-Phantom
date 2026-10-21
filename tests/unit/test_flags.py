from __future__ import annotations

import os
import re
import stat
from pathlib import Path

import pytest

from ctf_phantom.challenges import (
    FlagSecret,
    FlagSecretError,
    FlagValidator,
    derive_flag,
    derive_session_secret,
    flag_hash,
    load_flag_secret,
)
from ctf_phantom.challenges.flags import DEFAULT_SALT

FMT = r"^PHANTOM\{[0-9a-f]{24}\}$"
DECOY = "PHANTOM{7a3e9c1f5b0d2e8a6c4f1b9d}"
OTHER = FlagSecret.from_value("another-secret-value-0123456789abcdef")


def test_derivation_is_deterministic_and_input_dependent(secret: FlagSecret) -> None:
    assert derive_flag("phantom_001", 1, secret) == derive_flag("phantom_001", 1, secret)
    assert derive_flag("phantom_001", 1, secret) != derive_flag("phantom_001", 2, secret)
    assert derive_flag("phantom_001", 1, secret) != derive_flag("phantom_002", 1, secret)
    assert derive_flag("phantom_001", 1, secret, "a") != derive_flag("phantom_001", 1, secret, "b")
    assert derive_flag("phantom_001", 1, secret) != derive_flag("phantom_001", 1, OTHER)


def test_derived_flag_matches_format(secret: FlagSecret) -> None:
    for seed in range(200):
        assert re.match(FMT, derive_flag("phantom_001", seed, secret))


def test_flag_not_reconstructible_from_public_metadata(secret: FlagSecret) -> None:
    """Regression: v1 derived the flag from (challenge, seed, public salt) alone."""
    import hashlib

    flag = derive_flag("phantom_001", 1337, secret)
    legacy = "PHANTOM{" + hashlib.sha256(f"phantom_001:1337:{DEFAULT_SALT}".encode()).hexdigest()[:24] + "}"
    assert flag != legacy
    # Every public input is known; only the secret differs -> different flag.
    assert derive_flag("phantom_001", 1337, OTHER) != flag


def test_session_secret_is_secret_keyed(secret: FlagSecret) -> None:
    s1 = derive_session_secret("phantom_001", 1, secret)
    assert s1 == derive_session_secret("phantom_001", 1, secret)
    assert s1 != derive_session_secret("phantom_001", 1, OTHER)


def test_reserved_decoy_is_never_derived(secret: FlagSecret, monkeypatch: pytest.MonkeyPatch) -> None:
    # Force a collision on the first candidate: derivation must skip to the next counter.
    real = derive_flag("phantom_001", 5, secret)
    again = derive_flag("phantom_001", 5, secret, reserved={real})
    assert again != real and re.match(FMT, again)


def test_validator_accepts_exact_and_whitespace(secret: FlagSecret) -> None:
    flag = derive_flag("phantom_001", 7, secret)
    v = FlagValidator(flag, FMT)
    assert v.check(flag).correct
    assert v.check(f"  {flag}\n").correct
    assert v.expected_hash == flag_hash(flag)


def test_decoy_is_well_formed_but_always_rejected(secret: FlagSecret) -> None:
    for seed in range(100):
        flag = derive_flag("phantom_001", seed, secret, reserved={DECOY})
        v = FlagValidator(flag, FMT, reserved={DECOY})
        verdict = v.check(DECOY)
        assert verdict.well_formed and verdict.reserved and not verdict.correct


def test_validator_refuses_reserved_expected() -> None:
    with pytest.raises(ValueError, match="reserved"):
        FlagValidator(DECOY, FMT, reserved={DECOY})


def test_validator_rejects_wrong(secret: FlagSecret) -> None:
    v = FlagValidator(derive_flag("phantom_001", 7, secret), FMT)
    assert not v.check(derive_flag("phantom_001", 8, secret)).correct
    assert not v.check(derive_flag("phantom_001", 7, secret).upper()).correct


def test_validator_rejects_bad_expected() -> None:
    with pytest.raises(ValueError):
        FlagValidator("FLAG{x}", FMT)


def test_secret_repr_does_not_leak(secret: FlagSecret) -> None:
    assert "test-only" not in repr(secret)
    assert len(secret.fingerprint) == 16 and secret.fingerprint != OTHER.fingerprint


def test_short_secret_rejected() -> None:
    with pytest.raises(FlagSecretError):
        FlagSecret.from_value("too-short")


def test_load_secret_env_file_and_create(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    path = tmp_path / "cfg" / "flag_secret"
    monkeypatch.delenv("CTF_PHANTOM_FLAG_SECRET", raising=False)
    monkeypatch.setenv("CTF_PHANTOM_FLAG_SECRET_FILE", str(path))
    with pytest.raises(FlagSecretError):
        load_flag_secret()
    created = load_flag_secret(create=True)
    assert path.is_file() and stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert load_flag_secret().fingerprint == created.fingerprint  # stable across loads
    monkeypatch.setenv("CTF_PHANTOM_FLAG_SECRET", "x" * 40)
    assert load_flag_secret().source == "env"
