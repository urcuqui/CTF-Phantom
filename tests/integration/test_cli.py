"""CLI behaviour: exit codes, dry runs, compatibility guard, summary outputs."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from ctf_phantom.cli import EXIT_ABORTED, EXIT_CONFIG, EXIT_INCOMPLETE, EXIT_REJECTED, app
from tests.cli_helpers import plain_output
from tests.conftest import ROOT

pytestmark = pytest.mark.integration
runner = CliRunner()


def _write_cfg(tmp_path: Path, **overrides: object) -> Path:
    cfg = {
        "name": "cli", "challenge": "phantom_001", "variants": ["benign_control", "deception"],
        "repetitions": 2, "seed": 5, "environment": {"backend": "local"},
        "provider": {"name": "scripted", "model": "ref", "script": "reference"},
        "output_dir": str(tmp_path / "results"),
    }
    cfg.update(overrides)
    path = tmp_path / "cfg.yaml"
    path.write_text(yaml.safe_dump(cfg))
    return path


def test_run_then_summarize_writes_summary_and_paired(tmp_path: Path) -> None:
    result = runner.invoke(app, ["run", "--config", str(_write_cfg(tmp_path))])
    assert result.exit_code == 0, plain_output(result)
    exp = tmp_path / "results" / "cli"
    result = runner.invoke(app, ["summarize", str(exp)])
    assert result.exit_code == 0, plain_output(result)
    summary = json.loads((exp / "summary.json").read_text())
    paired = json.loads((exp / "paired.json").read_text())
    assert {r["variant"] for r in summary} == {"benign_control", "deception"}
    assert paired[0]["variant"] == "deception" and paired[0]["n_pairs"] == 2


def test_summarize_refuses_incompatible_configs(tmp_path: Path) -> None:
    for steps in (30, 10):
        cfg = _write_cfg(tmp_path, agent={"max_steps": steps}, name=f"cli{steps}",
                         output_dir=str(tmp_path / "results" / "mixed"))
        assert runner.invoke(app, ["run", "--config", str(cfg)]).exit_code == 0
    mixed = tmp_path / "results" / "mixed"
    result = runner.invoke(app, ["summarize", str(mixed)])
    assert result.exit_code == EXIT_ABORTED and "incompatible" in plain_output(result)
    assert runner.invoke(app, ["summarize", str(mixed), "--split-configs"]).exit_code == 0


def test_aborted_experiment_exits_nonzero(tmp_path: Path) -> None:
    cfg = _write_cfg(tmp_path, provider={"name": "scripted", "model": "x",
                                         "script": [{"tool": "$PROVIDER_ERROR", "args": {"recoverable": False}}]})
    result = runner.invoke(app, ["run", "--config", str(cfg)])
    assert result.exit_code == EXIT_ABORTED and "aborted" in plain_output(result)


def test_configuration_error_exits_without_runs(tmp_path: Path) -> None:
    cfg = _write_cfg(tmp_path, variants=["does_not_exist"])
    result = runner.invoke(app, ["run", "--config", str(cfg)])
    assert result.exit_code == EXIT_CONFIG
    assert not (tmp_path / "results").exists()


def test_dry_run_has_no_side_effects(tmp_path: Path) -> None:
    result = runner.invoke(app, ["run", "--config", str(_write_cfg(tmp_path)), "--dry-run"])
    assert result.exit_code == 0 and "4 runs planned" in plain_output(result)
    assert not (tmp_path / "results").exists()


def test_pilot_dry_run_offline() -> None:
    result = runner.invoke(app, ["run", "--config", str(ROOT / "experiments/pilot/phantom_001_pilot.yaml"),
                                 "--dry-run", "--backend", "local", "--provider", "scripted", "--model", "reference"])
    assert result.exit_code == 0, plain_output(result)
    assert "40 runs planned" in plain_output(result)


def test_validate_command(tmp_path: Path) -> None:
    result = runner.invoke(app, ["validate", "--backend", "local", "--output-dir", str(tmp_path)])
    assert result.exit_code == 0, plain_output(result)


def test_pins_command() -> None:
    result = runner.invoke(app, ["pins", "--config", str(ROOT / "experiments/pilot/phantom_001_pilot.yaml")])
    assert result.exit_code == 0 and "challenge_hash" in plain_output(result)


def test_incomplete_execution_exits_nonzero(tmp_path: Path) -> None:
    cfg = _write_cfg(tmp_path, execution={"max_attempts_per_run": 1, "max_consecutive_failures": 10},
                     provider={"name": "scripted", "model": "x",
                               "script": [{"tool": "$PROVIDER_ERROR", "args": {"recoverable": True}}]})
    result = runner.invoke(app, ["run", "--config", str(cfg)])
    assert result.exit_code == EXIT_INCOMPLETE
    assert "status=incomplete" in plain_output(result) and "missing_valid=4" in plain_output(result)


def test_check_acceptance_command_rejects_local_runs(tmp_path: Path) -> None:
    assert runner.invoke(app, ["run", "--config", str(_write_cfg(tmp_path))]).exit_code == 0
    exp = tmp_path / "results" / "cli"
    result = runner.invoke(app, ["check-acceptance", str(exp)])
    assert result.exit_code == EXIT_REJECTED  # local backend, unpinned: never acceptable for reporting
    data = json.loads((exp / "acceptance.json").read_text())
    assert data["verdict"] == "rejected" and data["execution_status"] == "completed"


def test_dry_run_reports_budget_kinds(tmp_path: Path) -> None:
    cfg = _write_cfg(tmp_path, agent={"max_total_tokens": 1000, "max_wall_time_s": 60},
                     execution={"max_experiment_tokens": 2000, "max_experiment_wall_time_s": 1000})
    result = runner.invoke(app, ["run", "--config", str(cfg), "--dry-run"])
    assert result.exit_code == 0
    output = plain_output(result)
    assert "HARD" in output and "SOFT" in output and "warning: worst case" in output


def test_check_provider_with_scripted_provider(tmp_path: Path) -> None:
    result = runner.invoke(app, ["check-provider", "--config", str(_write_cfg(tmp_path))])
    assert result.exit_code == 0 and "provider ready" in plain_output(result)
