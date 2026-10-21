"""CLI assertions must hold whether or not the terminal forces colour (CI sets FORCE_COLOR=1)."""

from __future__ import annotations

from pathlib import Path

import pytest
import typer.rich_utils
import yaml
from rich.console import Console
from typer.testing import CliRunner

from ctf_phantom import cli
from tests.cli_helpers import plain_output, strip_ansi


@pytest.mark.parametrize(("raw", "plain"), [
    ("preflight OK. \x1b[1;36m40\x1b[0m runs planned", "preflight OK. 40 runs planned"),
    ("\x1b[1;36m-\x1b[0m\x1b[1;36m-run\x1b[0m\x1b[1;36m-id\x1b[0m", "--run-id"),
    ("\x1b]8;id=1;https://example.invalid\x1b\\link\x1b]8;;\x1b\\", "link"),       # OSC 8 hyperlink
    ("\x1b[2K\x1b[1Gstatus=incomplete", "status=incomplete"),                       # cursor control
    ("[REDACTED:flag] [bold] plain [text]", "[REDACTED:flag] [bold] plain [text]"),  # no ESC: untouched
])
def test_strip_ansi(raw: str, plain: str) -> None:
    assert strip_ansi(raw) == plain
    assert strip_ansi(strip_ansi(raw)) == plain  # idempotent


@pytest.fixture
def forced_colour(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reproduce CI: colour forced for the app's console and for Typer's help renderer."""
    monkeypatch.setenv("FORCE_COLOR", "1")
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setattr(cli, "console", Console())          # created at import time in CI
    monkeypatch.setattr(typer.rich_utils, "FORCE_TERMINAL", True)


def test_dry_run_output_is_coloured_in_ci_and_assertable(forced_colour: None, tmp_path: Path) -> None:
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text(yaml.safe_dump({
        "name": "colour", "challenge": "phantom_001", "variants": ["baseline", "deception"], "repetitions": 2,
        "environment": {"backend": "local"}, "provider": {"name": "scripted", "model": "ref"},
        "output_dir": str(tmp_path / "results"),
    }))
    result = CliRunner().invoke(cli.app, ["run", "--config", str(cfg), "--dry-run"])
    assert result.exit_code == 0
    assert "\x1b[" in result.output                 # the raw output really is coloured...
    assert "4 runs planned" not in result.output    # ...which is what broke the old assertions
    assert "4 runs planned" in plain_output(result)


def test_help_options_are_assertable_with_forced_colour(forced_colour: None) -> None:
    result = CliRunner().invoke(cli.app, ["audit", "show", "--help"], terminal_width=200)
    assert result.exit_code == 0 and "\x1b[" in result.output
    assert "--run-id" in plain_output(result)
