"""ctf-phantom command-line interface."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from ctf_phantom import __version__
from ctf_phantom.challenges import list_challenges, load_challenge, slot_texts
from ctf_phantom.config import ExperimentConfig, apply_overrides, load_dotenv, load_experiment
from ctf_phantom.evaluation import RunMetrics, evaluate_trace, summarize
from ctf_phantom.runner import RunResult, experiment_dir, run_experiment

app = typer.Typer(add_completion=False, no_args_is_help=True,
                  help="CTF-Phantom: adversarial deception of autonomous cybersecurity agents.")
console = Console()


def _fmt_bool(v: bool | None) -> str:
    return "-" if v is None else ("[green]yes[/]" if v else "[red]no[/]")


def _print_run(r: RunResult) -> None:
    m = r.metrics
    console.print(
        f"[bold]{m.variant_id}[/] rep={m.repetition} completed={_fmt_bool(m.challenge_completed)} "
        f"exposed={_fmt_bool(m.exposed)} attack_success={_fmt_bool(m.attack_success)} "
        f"tools={m.tool_call_count} tokens={m.tokens.total_tokens if m.tokens.available else 'n/a'} "
        f"stop={m.stop_reason} t={m.duration_s}s\n  -> {r.run_dir}"
    )


@app.command()
def run(
    challenge: Annotated[str | None, typer.Option(help="Challenge id, e.g. phantom_001.")] = None,
    variant: Annotated[list[str] | None, typer.Option(help="Variant id (repeatable).")] = None,
    config: Annotated[Path | None, typer.Option(help="Experiment YAML.", exists=True)] = None,
    provider: Annotated[str | None, typer.Option(help="anthropic | openai | scripted")] = None,
    model: Annotated[str | None, typer.Option(help="Model id.")] = None,
    backend: Annotated[str | None, typer.Option(help="docker | local")] = None,
    repetitions: Annotated[int | None, typer.Option(min=1)] = None,
    seed: Annotated[int | None, typer.Option()] = None,
    max_steps: Annotated[int | None, typer.Option(min=1)] = None,
    prompt_profile: Annotated[str | None, typer.Option()] = None,
    effort: Annotated[str | None, typer.Option(help="Anthropic effort level.")] = None,
    name: Annotated[str | None, typer.Option(help="Experiment name (output folder).")] = None,
    output_dir: Annotated[Path | None, typer.Option()] = None,
) -> None:
    """Run an experiment (one fresh environment per run)."""
    load_dotenv()
    if config is not None:
        cfg = load_experiment(config)
    else:
        if not challenge:
            raise typer.BadParameter("--challenge is required when --config is not given")
        variants = variant or ["baseline"]
        cfg = ExperimentConfig.model_validate({
            "name": name or f"{challenge}_{'_'.join(variants)}",
            "challenge": challenge,
            "variants": variants,
            "provider": {
                "name": os.environ.get("CTF_PHANTOM_PROVIDER", "anthropic"),
                "model": os.environ.get("CTF_PHANTOM_MODEL", "claude-opus-5-5"),
            },
        })
    cfg = apply_overrides(cfg, {
        "challenge": challenge if config is not None else None,
        "variants": variant if config is not None else None,
        "name": name if config is not None else None,
        "provider.name": provider,
        "provider.model": model,
        "provider.effort": effort,
        "environment.backend": backend,
        "repetitions": repetitions,
        "seed": seed,
        "agent.max_steps": max_steps,
        "agent.prompt_profile": prompt_profile,
        "output_dir": str(output_dir) if output_dir else None,
    })
    console.print(
        f"[bold cyan]experiment[/] {cfg.name}  challenge={cfg.challenge} variants={cfg.variants} "
        f"reps={cfg.repetitions} provider={cfg.provider.name}/{cfg.provider.model} "
        f"backend={cfg.environment.backend} seed={cfg.seed}"
    )
    results = run_experiment(cfg, on_run=_print_run)
    _print_summary([r.metrics for r in results])
    console.print(f"results: {experiment_dir(cfg)}")


@app.command()
def evaluate(run_dir: Annotated[Path, typer.Argument(exists=True, file_okay=False)]) -> None:
    """Re-evaluate a run from its trace and rewrite metrics.json."""
    metrics = evaluate_trace(run_dir / "trace.jsonl")
    (run_dir / "metrics.json").write_text(metrics.model_dump_json(indent=2), encoding="utf-8")
    console.print_json(metrics.model_dump_json())


@app.command("summarize")
def summarize_cmd(exp_dir: Annotated[Path, typer.Argument(exists=True, file_okay=False)]) -> None:
    """Re-evaluate every run in an experiment directory and write summary.json."""
    metrics = [evaluate_trace(t) for t in sorted(exp_dir.glob("*/trace.jsonl"))]
    if not metrics:
        raise typer.BadParameter(f"no runs found in {exp_dir}")
    rows = _print_summary(metrics)
    (exp_dir / "summary.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
    console.print(f"wrote {exp_dir / 'summary.json'}")


def _print_summary(metrics: list[RunMetrics]) -> list[dict[str, object]]:
    rows = summarize(metrics)
    table = Table(title="Summary")
    for col in ("model", "variant", "n", "completion", "exposure", "ASR|exposed", "control FP",
                "tools", "tokens", "dur s"):
        table.add_column(col)

    def rate(d: dict[str, object] | None) -> str:
        if not d or d.get("rate") is None:
            return "-"
        return f"{d['k']}/{d['n']} ({float(d['rate']):.0%})"  # type: ignore[arg-type]

    for r in rows:
        table.add_row(str(r["model"]), str(r["variant"]), str(r["runs"]),
                      rate(r["completion"]), rate(r["exposure"]),
                      rate(r["attack_success_given_exposure"]),
                      rate(r["control_false_positive"]),
                      str(r["mean_tool_calls"]), str(r["mean_total_tokens"]), str(r["mean_duration_s"]))
    console.print(table)
    return rows


@app.command("list-challenges")
def list_challenges_cmd() -> None:
    """List available challenges and their variants."""
    for cid in list_challenges():
        ch = load_challenge(cid)
        console.print(f"[bold]{cid}[/] v{ch.spec.version} ({ch.spec.category}) hash={ch.challenge_hash[:12]}")
        for vid, v in ch.variants.items():
            chars = sum(len(t) for t in slot_texts(ch.spec, v.slots).values())
            console.print(f"  - {vid:<18} {v.condition:<9} {v.attack_class:<26} "
                          f"slot_chars={chars:<4} indicators={len(v.indicators)} "
                          f"hash={ch.variant_hashes[vid][:12]}")


@app.command()
def validate(
    challenge: Annotated[str, typer.Option()] = "phantom_001",
    backend: Annotated[str, typer.Option(help="docker | local")] = "local",
    output_dir: Annotated[Path | None, typer.Option()] = None,
) -> None:
    """Run the reference solution against every variant; all must solve with zero indicator hits."""
    ch = load_challenge(challenge)
    cfg = ExperimentConfig.model_validate({
        "name": f"validate_{challenge}_{backend}",
        "challenge": challenge,
        "variants": list(ch.variants),
        "shuffle_variants": False,
        "environment": {"backend": backend},
        "provider": {"name": "scripted", "model": "reference", "script": "reference"},
        "output_dir": str(output_dir) if output_dir else None,
    })
    results = run_experiment(cfg, on_run=_print_run)
    bad = [r for r in results if not r.metrics.challenge_completed or r.metrics.indicator_hits]
    if bad:
        console.print(f"[red]validation failed for {[r.metrics.variant_id for r in bad]}[/]")
        raise typer.Exit(1)
    console.print("[green]all variants solvable via the reference path; no indicator false positives[/]")


@app.command()
def version() -> None:
    """Print the package version."""
    console.print(__version__)


if __name__ == "__main__":  # pragma: no cover
    app()
