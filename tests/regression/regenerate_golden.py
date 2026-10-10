"""Regenerate golden v2 evaluator fixtures. Run deliberately, review the diff, commit:

    PYTHONPATH=src:. .venv/bin/python -m tests.regression.regenerate_golden

Traces are produced by the real harness (local backend, scripted policies, fixed test secret).
Expected outputs are the evaluator's results at generation time; the regression test then
guarantees that future evaluator changes do not silently alter them.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from pathlib import Path

os.environ["CTF_PHANTOM_FLAG_SECRET"] = "test-only-flag-secret-0123456789abcdef"

from ctf_phantom.config import ExperimentConfig  # noqa: E402
from ctf_phantom.evaluation import evaluate_trace, paired_comparisons, summarize  # noqa: E402
from ctf_phantom.runner import execute_experiment  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
GOLDEN = ROOT / "tests/fixtures/golden_v2"
VARIANTS = ["baseline", "benign_control", "deception", "prompt_injection"]
PROBE_THEN_SOLVE = [
    {"tool": "http_request", "args": {"method": "GET", "url": "/notes"}},
    {"tool": "http_request", "args": {"method": "GET", "url": "/login"}},
    {"tool": "http_request", "args": {"method": "GET", "url": "/api/agent-handshake?ack=x"}},
    {"tool": "http_request", "args": {"method": "POST", "url": "/login",
                                      "form": {"username": "admin'--", "password": "x"}}},
    {"tool": "submit_flag", "args": {"flag": "$EXTRACT"}, "extract_regex": "PHANTOM\\{[0-9a-f]{24}\\}"},
]

EXPERIMENTS = {
    "paired_probe": dict(variants=VARIANTS, repetitions=2, script=PROBE_THEN_SOLVE),
    "injection_follower": dict(variants=["prompt_injection"], repetitions=1,
                               script=str(ROOT / "experiments/scripts/injection_follower.yaml")),
    "decoy_follower": dict(variants=["deception"], repetitions=1,
                           script=str(ROOT / "experiments/scripts/decoy_follower.yaml")),
    "provider_error": dict(variants=["baseline"], repetitions=1,
                           script=[{"tool": "http_request", "args": {"method": "GET", "url": "/"}},
                                   {"tool": "$PROVIDER_ERROR", "args": {"recoverable": True, "status_code": 529}}],
                           execution={"max_attempts_per_run": 1}),
}


def main() -> None:
    shutil.rmtree(GOLDEN, ignore_errors=True)
    with tempfile.TemporaryDirectory() as tmp:
        for name, spec in EXPERIMENTS.items():
            cfg = ExperimentConfig.model_validate({
                "name": name, "challenge": "phantom_001", "variants": spec["variants"],
                "repetitions": spec["repetitions"], "seed": 2026, "shuffle_variants": False,
                "environment": {"backend": "local"},
                "execution": spec.get("execution", {}),
                "provider": {"name": "scripted", "model": "golden", "script": spec["script"]},
                "output_dir": tmp,
            })
            report = execute_experiment(cfg)
            for i, r in enumerate(report.results):
                dst = GOLDEN / name / f"run{i:02d}_{r.metrics.variant_id}_r{r.metrics.repetition}"
                dst.mkdir(parents=True)
                shutil.copy(r.run_dir / "trace.jsonl", dst / "trace.jsonl")
                expected = evaluate_trace(dst / "trace.jsonl")
                (dst / "expected_metrics.json").write_text(expected.model_dump_json(indent=2) + "\n")
    paired_runs = [evaluate_trace(t) for t in sorted((GOLDEN / "paired_probe").glob("*/trace.jsonl"))]
    (GOLDEN / "paired_probe" / "expected_summary.json").write_text(
        json.dumps(summarize(paired_runs), indent=2) + "\n")
    (GOLDEN / "paired_probe" / "expected_paired.json").write_text(
        json.dumps(paired_comparisons(paired_runs), indent=2) + "\n")
    print(f"wrote {sum(1 for _ in GOLDEN.rglob('trace.jsonl'))} golden traces to {GOLDEN}")


if __name__ == "__main__":
    main()
