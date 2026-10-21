"""Provider readiness evidence, the launch gate, and refusal/mixed experiments (scripted, local)."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import yaml
from typer.testing import CliRunner

from ctf_phantom import readiness
from ctf_phantom import runner as runner_mod
from ctf_phantom.cli import EXIT_PROBE_FAILED, EXIT_REJECTED, app
from ctf_phantom.config import ExperimentConfig, apply_overrides
from ctf_phantom.evaluation import check_acceptance
from ctf_phantom.providers import LLMResponse, ProviderConfig
from ctf_phantom.providers.scripted import ScriptedProvider
from ctf_phantom.runner import execute_experiment, probe_provider
from ctf_phantom.status import ConfigurationError
from tests.cli_helpers import plain_output

pytestmark = pytest.mark.integration
VARIANTS = ["baseline", "benign_control", "deception", "prompt_injection"]
REFUSE = [{"tool": "$REFUSAL", "args": {"category": "cyber", "explanation": "simulated cyber-policy refusal"}}]


def _cfg(results: Path, script: Any = "reference", *, name: str = "ready", required: bool = False,
         variants: list[str] | None = None, **execution: Any) -> ExperimentConfig:
    return ExperimentConfig.model_validate({
        "name": name, "challenge": "phantom_001", "variants": variants or VARIANTS, "seed": 4,
        "shuffle_variants": False, "environment": {"backend": "local"},
        "execution": {"require_provider_check": required, **execution},
        "provider": {"name": "scripted", "model": "probe", "script": script}, "output_dir": str(results),
    })


def _a(result: dict[str, Any], cid: str) -> dict[str, Any]:
    return next(c for c in result["criteria"] if c["id"] == cid)


# ------------------------------------------------------------------ probe + evidence
def test_refusing_probe_is_recorded_as_readiness_evidence(results_tmp: Path) -> None:
    cfg = _cfg(results_tmp, REFUSE)
    probe = probe_provider(cfg)
    assert probe["ok"] is False and probe["outcome"] == "refusal" and probe["refusal_category"] == "cyber"
    record = readiness.record_check(cfg, probe)
    assert record["ok"] is False and record["outcome"] == "refusal" and record["tool_calls"] == []
    assert readiness.latest_check(cfg) == record
    assert "outcome=refusal, category=cyber" in (readiness.readiness_problem(cfg) or "")
    stored = readiness.checks_path(cfg).read_text()
    assert "PHANTOM{" not in stored and "arguments" not in stored  # no raw tool args or flags


def test_successful_tool_calling_probe_passes(results_tmp: Path) -> None:
    cfg = _cfg(results_tmp)
    probe = probe_provider(cfg)
    assert probe["ok"] and probe["outcome"] == "ready" and probe["tool_calls"][0]["name"] == "http_request"
    readiness.record_check(cfg, probe)
    assert readiness.readiness_problem(cfg) is None


@pytest.mark.parametrize(("response", "outcome"), [
    (LLMResponse(text="hi", tool_calls=[], usage=None, model="m", stop_reason="end_turn"), "no_tool_call"),
])
def test_probe_outcomes(results_tmp: Path, monkeypatch: pytest.MonkeyPatch, response: LLMResponse,
                        outcome: str) -> None:
    class _P(ScriptedProvider):
        def complete(self, system, messages, tools):  # type: ignore[no-untyped-def]
            return response

    monkeypatch.setattr(runner_mod, "build_provider", lambda c, ch: _P(c, []))
    assert probe_provider(_cfg(results_tmp))["outcome"] == outcome


def test_checks_are_keyed_to_the_exact_configuration(results_tmp: Path) -> None:
    cfg = _cfg(results_tmp)
    readiness.record_check(cfg, probe_provider(cfg))
    assert readiness.readiness_problem(cfg) is None
    changed = apply_overrides(cfg, {"provider.effort": "high"})
    assert readiness.probe_key(changed) != readiness.probe_key(cfg)
    assert "no provider readiness check recorded" in (readiness.readiness_problem(changed) or "")
    timeout_only = apply_overrides(cfg, {"provider.timeout_s": 5.0})  # cannot change the answer
    assert readiness.probe_key(timeout_only) == readiness.probe_key(cfg)


def test_stale_and_superseded_checks(results_tmp: Path) -> None:
    cfg = _cfg(results_tmp, provider_check_max_age_hours=1)
    readiness.record_check(cfg, probe_provider(cfg), now=datetime.now(UTC) - timedelta(hours=2))
    assert "older than" in (readiness.readiness_problem(cfg) or "")
    readiness.record_check(cfg, probe_provider(cfg))
    assert readiness.readiness_problem(cfg) is None
    # A later failing probe supersedes an earlier pass (latest wins; history kept).
    readiness.record_check(cfg, {"ok": False, "outcome": "refusal", "refusal_category": "cyber"})
    assert "failed" in (readiness.readiness_problem(cfg) or "")
    assert len(readiness.load_checks(cfg)) == 3


# ------------------------------------------------------------------ gate
def test_gate_blocks_execution_after_failed_probe(results_tmp: Path) -> None:
    cfg = _cfg(results_tmp, required=True)
    with pytest.raises(ConfigurationError, match="no provider readiness check"):
        execute_experiment(cfg)
    # The refusing probe's outcome, recorded against THIS configuration's key.
    refused = probe_provider(cfg.model_copy(update={"provider": cfg.provider.model_copy(update={"script": REFUSE})}))
    assert refused["outcome"] == "refusal"
    readiness.record_check(cfg, refused)
    with pytest.raises(ConfigurationError, match="readiness gate: latest provider readiness check failed"):
        execute_experiment(cfg)
    assert not any((results_tmp / "ready").glob("*/trace.jsonl"))  # no run was started


def test_gate_passes_and_readiness_becomes_experiment_evidence(results_tmp: Path) -> None:
    cfg = _cfg(results_tmp, required=True, variants=["baseline"])
    record = readiness.record_check(cfg, probe_provider(cfg))
    report = execute_experiment(cfg)
    meta = json.loads((report.out_dir / "experiment.json").read_text())
    assert meta["readiness"]["required"] is True and meta["readiness"]["provider_check"] == record
    assert _a(check_acceptance(report.out_dir), "A12")["status"] == "pass"


def test_experiment_without_readiness_evidence_fails_a12(results_tmp: Path) -> None:
    report = execute_experiment(_cfg(results_tmp, variants=["baseline"]))
    a12 = _a(check_acceptance(report.out_dir), "A12")
    assert a12["status"] == "fail" and "no readiness evidence" in a12["detail"]["note"]


# ------------------------------------------------------------------ experiments
def test_all_refused_experiment_is_reported_not_scored(results_tmp: Path) -> None:
    report = execute_experiment(_cfg(results_tmp, REFUSE, name="refused"))
    assert report.status == "completed"  # operationally fine: every planned run is valid
    for r in report.results:
        m = r.metrics
        assert m.valid and m.stop_reason == "refusal" and m.tool_call_count == 0 and not m.exposed
        assert m.episode_class == "provider_refusal_pre_exposure" and not m.susceptibility_eligible
    result = CliRunner().invoke(app, ["summarize", str(report.out_dir)])
    assert result.exit_code == 0 and "Provider refusals" in plain_output(result)
    refusals = json.loads((report.out_dir / "refusals.json").read_text())
    assert all(r["pre_exposure_refusal"]["rate"] == 1.0 for r in refusals["by_condition"])
    summary = {r["variant"]: r for r in json.loads((report.out_dir / "summary.json").read_text())}
    assert summary["prompt_injection"]["attack_success_eligible"]["n"] == 0
    acceptance = check_acceptance(report.out_dir)
    assert _a(acceptance, "A11")["status"] == "fail" and acceptance["verdict"] == "rejected"
    assert _a(acceptance, "A11")["detail"]["categories"]["baseline"] == {"cyber": 1}


def test_mixed_refusal_and_tool_calling_outcomes(results_tmp: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Refusals in treatment arms only: eligible metrics exclude them, original metrics keep them."""
    class _Mixed(ScriptedProvider):
        """Refuses at the first turn in treatment arms of repetition 0; otherwise the reference solution."""

        variant = ""
        seed_index = -1

        def complete(self, system, messages, tools):  # type: ignore[no-untyped-def]
            if self.variant in ("deception", "prompt_injection") and self.seed_index == 0:
                return LLMResponse(text="", tool_calls=[], usage=None, model="m", stop_reason="refusal",
                                   extra={"stop_details": {"category": "cyber", "explanation": "x"}})
            return super().complete(system, messages, tools)

    real_run_single = runner_mod.run_single

    def run_single(cfg, challenge, variant_id, repetition, **kw):  # type: ignore[no-untyped-def]
        def factory(config: ProviderConfig, ch: Any) -> ScriptedProvider:
            p = _Mixed(config, list(ch.reference_solution))
            p.variant, p.seed_index = variant_id, repetition
            return p

        monkeypatch.setattr(runner_mod, "build_provider", factory)
        return real_run_single(cfg, challenge, variant_id, repetition, **kw)

    monkeypatch.setattr(runner_mod, "run_single", run_single)
    report = execute_experiment(_cfg(results_tmp, name="mixed").model_copy(update={"repetitions": 2}))
    by = {(r.metrics.variant_id, r.metrics.repetition): r.metrics for r in report.results}
    assert by[("deception", 0)].episode_class == "provider_refusal_pre_exposure"
    assert by[("deception", 1)].episode_class == "agent_episode" and by[("deception", 1)].challenge_completed
    assert by[("baseline", 0)].episode_class == "agent_episode"
    result = CliRunner().invoke(app, ["summarize", str(report.out_dir)])
    assert result.exit_code == 0
    summary = {r["variant"]: r for r in json.loads((report.out_dir / "summary.json").read_text())}
    d = summary["deception"]
    assert (d["completion"]["k"], d["completion"]["n"]) == (1, 2)            # original, unchanged
    assert (d["completion_eligible"]["k"], d["completion_eligible"]["n"]) == (1, 1)
    assert (d["pre_exposure_refusal"]["k"], d["pre_exposure_refusal"]["n"]) == (1, 2)
    assert summary["baseline"]["pre_exposure_refusal"]["k"] == 0
    paired = {r["variant"]: r for r in json.loads((report.out_dir / "paired.json").read_text())}
    assert paired["deception"]["n_pairs"] == 2
    assert paired["deception"]["susceptibility_eligible"]["n_pairs"] == 1
    refusals = json.loads((report.out_dir / "refusals.json").read_text())
    cond = {r["group"]: r for r in refusals["by_condition"]}
    assert (cond["treatment"]["pre_exposure_refusal"]["k"], cond["treatment"]["valid_runs"]) == (2, 4)
    assert cond["control"]["pre_exposure_refusal"]["k"] == 0


# ------------------------------------------------------------------ launch workflow
def _write(tmp_path: Path, script: Any, name: str) -> Path:
    path = tmp_path / f"{name}.yaml"
    path.write_text(yaml.safe_dump(_cfg(tmp_path / "results", script, name=name, required=True,
                                        variants=["baseline", "deception"]).model_dump(mode="json")))
    return path


def test_launch_stops_after_failed_probe(tmp_path: Path) -> None:
    result = CliRunner().invoke(app, ["launch", "--config", str(_write(tmp_path, REFUSE, "pilotlike"))])
    out = plain_output(result)
    assert result.exit_code == EXIT_PROBE_FAILED
    assert "launch stopped" in out and "no runs were started" in out and "category=cyber" in out
    exp = tmp_path / "results" / "pilotlike"
    assert not any(exp.glob("*/trace.jsonl")) and not (exp / "experiment.json").exists()
    (check,) = [json.loads(line) for line in (exp / "readiness" / "provider_checks.jsonl").read_text().splitlines()]
    assert check["outcome"] == "refusal" and check["refusal_category"] == "cyber"


def test_launch_runs_after_passing_probe(tmp_path: Path) -> None:
    result = CliRunner().invoke(app, ["launch", "--config", str(_write(tmp_path, "reference", "pilotok"))])
    out = plain_output(result)
    # Probe passed, runs executed, summary + acceptance produced; local backend => A4 rejects.
    assert result.exit_code == EXIT_REJECTED, out
    assert "provider ready" in out and "3/4 experiment" in out and "acceptance verdict: rejected" in out
    exp = tmp_path / "results" / "pilotok"
    meta = json.loads((exp / "experiment.json").read_text())
    assert meta["readiness"]["provider_check"]["outcome"] == "ready"
    acceptance = json.loads((exp / "acceptance.json").read_text())
    assert _a(acceptance, "A12")["status"] == "pass" and _a(acceptance, "A11")["status"] == "pass"
    assert (exp / "refusals.json").is_file()
