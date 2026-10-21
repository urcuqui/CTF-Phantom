"""Backward compatibility: traces recorded by the v1 harness (main@607970b) must still evaluate to
the same v1 metric values. Fields whose semantics intentionally changed are listed explicitly."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ctf_phantom.evaluation import evaluate_trace
from tests.conftest import ROOT

LEGACY = ROOT / "tests/fixtures/legacy_v1"
CASES = sorted(p.name for p in LEGACY.iterdir() if p.is_dir())
# evaluator_version changes by definition; indicator_hits gain fields (compared structurally below).
CHANGED = {"evaluator_version", "indicator_hits"}
HIT_FIELDS = ("indicator_id", "source_variant", "kind", "step", "after_exposure")


@pytest.mark.parametrize("case", CASES)
def test_v1_fields_unchanged(case: str) -> None:
    old = json.loads((LEGACY / case / "metrics.json").read_text())
    new = json.loads(evaluate_trace(LEGACY / case / "trace.jsonl").model_dump_json())
    for key, value in old.items():
        if key in CHANGED:
            continue
        assert new[key] == value, f"{case}: {key} changed {value!r} -> {new[key]!r}"
    old_hits = [tuple(h[f] for f in HIT_FIELDS) for h in old["indicator_hits"]]
    new_hits = [tuple(h[f] for f in HIT_FIELDS) for h in new["indicator_hits"]]
    assert sorted(new_hits) == sorted(old_hits)


@pytest.mark.parametrize("case", CASES)
def test_legacy_runs_are_valid_and_not_comparable_with_v2(case: str) -> None:
    m = evaluate_trace(LEGACY / case / "trace.jsonl")
    assert m.valid and m.run_status == "completed"
    assert m.flag_secret_fingerprint is None  # predates secret-keyed flags


def test_fixture_set_is_complete() -> None:
    assert set(CASES) == {"baseline_reference", "injection_reference", "injection_follower",
                          "deception_decoy_follower"}
    for case in CASES:
        assert (LEGACY / case / "trace.jsonl").is_file() and (LEGACY / case / "metrics.json").is_file()


def test_legacy_fixture_paths_exist() -> None:
    assert isinstance(LEGACY, Path) and LEGACY.is_dir()
