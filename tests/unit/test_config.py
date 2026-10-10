from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from ctf_phantom.config import ExperimentConfig, apply_overrides, load_experiment
from ctf_phantom.runner import run_order
from tests.conftest import ROOT


@pytest.mark.parametrize("path", sorted((ROOT / "experiments").glob("**/*.yaml")), ids=lambda p: p.name)
def test_shipped_experiment_configs_are_valid(path: Path, challenge) -> None:  # type: ignore[no-untyped-def]
    if path.parent.name == "scripts":
        pytest.skip("scripted policy, not an experiment config")
    cfg = load_experiment(path)
    for vid in cfg.variants:
        challenge.variant(vid)


def test_rejects_unknown_keys() -> None:
    with pytest.raises(ValidationError):
        ExperimentConfig.model_validate({"name": "x", "challenge": "c", "variants": ["a"], "typo": 1})


def test_overrides_and_defaults() -> None:
    cfg = ExperimentConfig.model_validate({"name": "x", "challenge": "c", "variants": ["a"]})
    assert cfg.environment.backend == "docker" and cfg.agent.max_steps == 30
    cfg2 = apply_overrides(cfg, {"provider.model": "m2", "agent.max_steps": 5, "seed": None})
    assert cfg2.provider.model == "m2" and cfg2.agent.max_steps == 5 and cfg2.seed == cfg.seed


def test_run_order_is_seeded_and_blocked() -> None:
    cfg = ExperimentConfig.model_validate({"name": "x", "challenge": "c", "variants": ["a", "b", "c", "d"],
                                           "repetitions": 3, "seed": 7})
    order = run_order(cfg)
    assert order == run_order(cfg)
    assert len(order) == 12
    for rep in range(3):
        assert sorted(v for r, v in order if r == rep) == ["a", "b", "c", "d"]
    unshuffled = run_order(cfg.model_copy(update={"shuffle_variants": False}))
    assert [v for _, v in unshuffled[:4]] == ["a", "b", "c", "d"]
