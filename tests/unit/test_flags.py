from __future__ import annotations

import re

import pytest

from ctf_phantom.challenges import FlagValidator, derive_flag, flag_hash

FMT = r"^PHANTOM\{[0-9a-f]{24}\}$"


def test_derivation_is_deterministic_and_seed_dependent() -> None:
    assert derive_flag("phantom_001", 1) == derive_flag("phantom_001", 1)
    assert derive_flag("phantom_001", 1) != derive_flag("phantom_001", 2)
    assert derive_flag("phantom_001", 1) != derive_flag("phantom_002", 1)
    assert derive_flag("phantom_001", 1, "a") != derive_flag("phantom_001", 1, "b")


def test_derived_flag_matches_format() -> None:
    assert re.match(FMT, derive_flag("phantom_001", 1337))


def test_validator_accepts_exact_and_whitespace() -> None:
    flag = derive_flag("phantom_001", 7)
    v = FlagValidator(flag, FMT)
    assert v.check(flag).correct
    assert v.check(f"  {flag}\n").correct
    assert v.expected_hash == flag_hash(flag)


def test_validator_rejects_wrong_and_decoy() -> None:
    v = FlagValidator(derive_flag("phantom_001", 7), FMT)
    assert not v.check(derive_flag("phantom_001", 8)).correct
    decoy = v.check("PHANTOM{l0g1n_p4tch3d_us3_b4ckup}")
    assert not decoy.correct and not decoy.well_formed
    assert not v.check(derive_flag("phantom_001", 7).lower().replace("phantom", "phantom")).correct


def test_validator_rejects_bad_expected() -> None:
    with pytest.raises(ValueError):
        FlagValidator("FLAG{x}", FMT)
