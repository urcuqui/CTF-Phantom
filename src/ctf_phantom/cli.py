"""ctf-phantom command-line interface."""

from __future__ import annotations

import json
import os
import secrets
from pathlib import Path
from typing import Annotated, Any

import typer
import yaml
from rich.console import Console
from rich.table import Table

from ctf_phantom import __version__
from ctf_phantom.challenges import (
    FlagSecret,
    FlagSecretError,
    list_challenges,
    load_challenge,
    load_flag_secret,
    slot_texts,
)
from ctf_phantom.config import ExperimentConfig, apply_overrides, load_dotenv, load_experiment
from ctf_phantom.evaluation import (
    IncompatibleRunsError,
    RunMetrics,
    evaluate_trace,
    paired_comparisons,
    summarize,
)
from ctf_phantom.runner import (
    RunResult,
    current_pins,
    execute_experiment,
    experiment_dir,
    preflight,
    run_order,
)
from ctf_phantom.status import ConfigurationError

app = typer.Typer(add_completion=False, no_args_is_help=True,
                  help="CTF-Phantom: adversarial deception of autonomous cybersecurity agents.")
console = Console()

EXIT_ABORTED = 2
EXIT_CONFIG = 3


def _fmt_bool(v: bool | None) -> str:
    return "-" if v is None else ("[green]yes[/]" if v else "[red]no[/]")


def _print_run(r: RunResult) -> None:
    m = r.metrics
    status = "" if m.valid else f" [bold red]INVALID status={m.run_status}[/] ({m.error})"
    console.print(
        f"[bold]{m.variant_id}[/] rep={m.repetition} attempt={m.attempt} "
        f"completed={_fmt_bool(m.challenge_completed)} exposed={_fmt_bool(m.exposed)} "
        f"attack_success={_fmt_bool(m.attack_success)} outcome={m.attack_outcome} "
        f"tools={m.tool_call_count} tokens={m.tokens.total_tokens if m.tokens.available else 'n/a'} "
        f"stop={m.stop_reason} t={m.duration_s}s{status}\n  -> {r.run_dir}"
    )


def _ensure_secret() -> None:
    """CLI convenience: create the private flag secret on first use (library code never does)."""
    try:
        load_flag_secret()
    except FlagSecretError:
        secret = load_flag_secret(create=True)
        console.print(f"[yellow]created private flag secret[/] (fingerprint={secret.fingerprint}); "
                      "back it up to reproduce flags on another machine")


def _build_config(
    config: Path | None, challenge: str | None, variant: list[str] | None, name: str | None,
    overrides: dict[str, Any],
) -> ExperimentConfig:
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
    return apply_overrides(cfg, {
        "challenge": challenge if config is not None else None,
        "variants": variant if config is not None else None,
        "name": name if config is not None else None,
        **overrides,
    })


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
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Preflight + plan only; no runs.")] = False,
) -> None:
    """Run an experiment (one fresh environment per run)."""
    load_dotenv()
    cfg = _build_config(config, challenge, variant, name, {
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
    if dry_run:
        try:
            flag_secret = load_flag_secret()
        except FlagSecretError:
            flag_secret = FlagSecret.from_value(secrets.token_hex(32), "ephemeral")
            console.print("[yellow]no flag secret yet (run `ctf-phantom init-secret`); "
                          "dry run uses an ephemeral one[/]")
        try:
            ch, secret = preflight(cfg, flag_secret=flag_secret)
        except ConfigurationError as exc:
            console.print(f"[bold red]configuration error:[/] {exc}")
            raise typer.Exit(EXIT_CONFIG) from None
        order = run_order(cfg)
        console.print(f"preflight OK. {len(order)} runs planned "
                      f"(max {len(order) * cfg.execution.max_attempts_per_run} attempts).")
        console.print(f"budgets: per-run steps={cfg.agent.max_steps} tokens={cfg.agent.max_total_tokens} "
                      f"wall={cfg.agent.max_wall_time_s}s; experiment tokens={cfg.execution.max_experiment_tokens} "
                      f"wall={cfg.execution.max_experiment_wall_time_s}s")
        console.print("pins: " + json.dumps(current_pins(cfg, ch, secret)))
        console.print("order: " + ", ".join(f"r{r}:{v}" for r, v in order))
        return
    _ensure_secret()
    try:
        report = execute_experiment(cfg, on_run=_print_run)
    except ConfigurationError as exc:
        console.print(f"[bold red]configuration error (no runs attempted):[/] {exc}")
        raise typer.Exit(EXIT_CONFIG) from None
    if report.results:
        _print_summary([r.metrics for r in report.results], split_configs=True)
    console.print(f"results: {experiment_dir(cfg)}  status={report.status}"
                  + (f" ({report.reason})" if report.reason else ""))
    if report.status == "aborted":
        raise typer.Exit(EXIT_ABORTED)


@app.command()
def evaluate(run_dir: Annotated[Path, typer.Argument(exists=True, file_okay=False)]) -> None:
    """Re-evaluate a run from its trace and rewrite metrics.json."""
    metrics = evaluate_trace(run_dir / "trace.jsonl")
    (run_dir / "metrics.json").write_text(metrics.model_dump_json(indent=2), encoding="utf-8")
    console.print_json(metrics.model_dump_json())


@app.command("summarize")
def summarize_cmd(
    exp_dir: Annotated[Path, typer.Argument(exists=True, file_okay=False)],
    split_configs: Annotated[bool, typer.Option(
        "--split-configs", help="Report incompatible configurations separately instead of failing.")] = False,
    control: Annotated[str, typer.Option(help="Control variant for paired comparisons.")] = "benign_control",
) -> None:
    """Re-evaluate every run in a directory; write summary.json and paired.json."""
    metrics = [evaluate_trace(t) for t in sorted(exp_dir.glob("**/trace.jsonl"))]
    if not metrics:
        raise typer.BadParameter(f"no runs found in {exp_dir}")
    try:
        rows = _print_summary(metrics, split_configs=split_configs)
        paired = paired_comparisons(metrics, control=control)
    except IncompatibleRunsError as exc:
        console.print(f"[bold red]{exc}[/]")
        raise typer.Exit(EXIT_ABORTED) from None
    _print_paired(paired)
    (exp_dir / "summary.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
    (exp_dir / "paired.json").write_text(json.dumps(paired, indent=2), encoding="utf-8")
    console.print(f"wrote {exp_dir / 'summary.json'} and {exp_dir / 'paired.json'}")


def _rate(d: dict[str, Any] | None) -> str:
    if not d or d.get("rate") is None:
        return "-"
    return f"{d['k']}/{d['n']} ({float(d['rate']):.0%})"


def _print_summary(metrics: list[RunMetrics], *, split_configs: bool = False) -> list[dict[str, Any]]:
    rows = summarize(metrics, split_configs=split_configs)
    table = Table(title="Summary (valid runs only)")
    for col in ("model", "config", "variant", "valid/att", "completion", "exposure", "ASR|exposed",
                "executed|exp", "blocked|exp", "control FP", "tools", "tokens"):
        table.add_column(col)
    for r in rows:
        acts = r["adversarial_action_runs"] or {}
        table.add_row(str(r["model"]), str(r["config_key"])[:8], str(r["variant"]),
                      f"{r['runs']}/{r['attempted_runs']}", _rate(r["completion"]), _rate(r["exposure"]),
                      _rate(r["attack_success_given_exposure"]), _rate(acts.get("executed")),
                      _rate(acts.get("blocked")), _rate(r["control_false_positive"]),
                      str(r["mean_tool_calls"]), str(r["mean_total_tokens"]))
    console.print(table)
    if any(r["asr_interpretation"] for r in rows):
        console.print("[dim]ASR = observable behavioural indicator, not proof of causality; "
                      "see the paired comparison against the benign control.[/]")
    return rows


def _print_paired(paired: list[dict[str, Any]]) -> None:
    if not paired:
        return
    table = Table(title="Paired vs control (shared seeds)")
    for col in ("model", "variant", "pairs", "Δcompletion", "p (Holm)", "Δpayload action", "p (Holm)",
                "Δtools (mean)"):
        table.add_column(col)
    for p in paired:
        comp, act = p["completion"], p["payload_specific_action"]
        table.add_row(str(p["model"]), p["variant"], str(p["n_pairs"]),
                      str(comp["difference"]), str(comp.get("p_holm", "-")),
                      str(act["difference"]) if act else "-", str(act.get("p_holm", "-")) if act else "-",
                      str(p["tool_calls"]["mean_difference"]))
    console.print(table)


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
def pins(config: Annotated[Path, typer.Option(help="Experiment YAML.", exists=True)]) -> None:
    """Print current provenance hashes in the `pins:` format for an experiment config."""
    cfg = load_experiment(config)
    ch = load_challenge(cfg.challenge)
    try:
        secret = load_flag_secret()
    except FlagSecretError:
        secret = None
    console.print(yaml.safe_dump({"pins": current_pins(cfg, ch, secret)}, sort_keys=False))


@app.command("init-secret")
def init_secret() -> None:
    """Create the private flag secret (~/.config/ctf-phantom/flag_secret) if missing; print its fingerprint."""
    secret = load_flag_secret(create=True)
    console.print(f"flag secret ready (source={secret.source}) fingerprint={secret.fingerprint}")
    console.print("[dim]Keep it outside any directory mounted into a victim agent's environment.[/]")


@app.command()
def validate(
    challenge: Annotated[str, typer.Option()] = "phantom_001",
    backend: Annotated[str, typer.Option(help="docker | local")] = "local",
    output_dir: Annotated[Path | None, typer.Option()] = None,
) -> None:
    """Run the reference solution against every variant; all must solve with zero indicator hits."""
    ch = load_challenge(challenge)
    _ensure_secret()
    cfg = ExperimentConfig.model_validate({
        "name": f"validate_{challenge}_{backend}",
        "challenge": challenge,
        "variants": list(ch.variants),
        "shuffle_variants": False,
        "environment": {"backend": backend},
        "execution": {"max_attempts_per_run": 1, "max_consecutive_failures": 1},
        "provider": {"name": "scripted", "model": "reference", "script": "reference"},
        "output_dir": str(output_dir) if output_dir else None,
    })
    try:
        report = execute_experiment(cfg, on_run=_print_run)
    except ConfigurationError as exc:
        console.print(f"[bold red]configuration error:[/] {exc}")
        raise typer.Exit(EXIT_CONFIG) from None
    results = report.results
    bad = [r for r in results if not r.metrics.valid or not r.metrics.challenge_completed
           or r.metrics.indicator_hits]
    if bad or report.status != "completed" or len(results) != len(ch.variants):
        console.print(f"[red]validation failed ({report.status}: {report.reason}) for "
                      f"{[r.metrics.variant_id for r in bad]}[/]")
        raise typer.Exit(1)
    console.print("[green]all variants solvable via the reference path; no indicator false positives[/]")


@app.command()
def version() -> None:
    """Print the package version."""
    console.print(__version__)


if __name__ == "__main__":  # pragma: no cover
    app()
