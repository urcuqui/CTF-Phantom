"""Evaluator regression: frozen v2 traces must evaluate to exactly the frozen expected output.

If an intentional evaluator change breaks this test, bump EVALUATOR_VERSION, regenerate with
``python -m tests.regression.regenerate_golden``, and document the change in the protocol.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ctf_phantom.evaluation import EVALUATOR_VERSION, evaluate_trace, paired_comparisons, summarize
from tests.conftest import ROOT

GOLDEN = ROOT / "tests/fixtures/golden_v2"
TRACES = sorted(GOLDEN.rglob("trace.jsonl"))


def _id(p: Path) -> str:
    return str(p.parent.relative_to(GOLDEN))


def test_golden_fixtures_present() -> None:
    assert len(TRACES) == 11
    statuses = {json.loads((t.parent / "expected_metrics.json").read_text())["run_status"] for t in TRACES}
    assert statuses == {"completed", "provider_error"}


@pytest.mark.parametrize("trace", TRACES, ids=_id)
def test_metrics_match_golden(trace: Path) -> None:
    expected = json.loads((trace.parent / "expected_metrics.json").read_text())
    actual = json.loads(evaluate_trace(trace).model_dump_json())
    assert expected["evaluator_version"] == EVALUATOR_VERSION, "regenerate golden fixtures"
    assert actual == expected


def test_summary_and_paired_match_golden() -> None:
    exp_dir = GOLDEN / "paired_probe"
    runs = [evaluate_trace(t) for t in sorted(exp_dir.glob("*/trace.jsonl"))]
    assert json.loads(json.dumps(summarize(runs))) == json.loads((exp_dir / "expected_summary.json").read_text())
    assert json.loads(json.dumps(paired_comparisons(runs))) == json.loads(
        (exp_dir / "expected_paired.json").read_text())


def test_golden_traces_do_not_contain_plaintext_flags() -> None:
    import re

    for trace in TRACES:
        text = trace.read_text()
        real = set(re.findall(r"PHANTOM\{[0-9a-f]{24}\}", text)) - {"PHANTOM{7a3e9c1f5b0d2e8a6c4f1b9d}"}
        assert not real, f"{_id(trace)} leaks {real}"
