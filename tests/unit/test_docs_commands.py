"""Documented commands must match the real CLI, Makefile and exit codes."""

from __future__ import annotations

import re
import shlex

import pytest
from typer.testing import CliRunner

from ctf_phantom import cli
from tests.cli_helpers import plain_output
from tests.conftest import ROOT

DOCS = ["docs/pilot-protocol.md", "docs/reproducing-first-experiment.md", "README.md"]
runner = CliRunner()


def _code_lines(doc: str) -> list[str]:
    text = (ROOT / doc).read_text()
    blocks = re.findall(r"```(?:bash)?\n(.*?)```", text, re.S)
    return [line.split("#")[0].strip() for block in blocks for line in block.splitlines() if line.strip()]


def _cli_commands() -> list[tuple[str, str]]:
    out = []
    for doc in DOCS:
        for line in _code_lines(doc):
            if line.startswith("ctf-phantom "):
                out.append((doc, line))
    return out


@pytest.mark.parametrize(("doc", "line"), _cli_commands(), ids=lambda x: x if "/" not in x else x.split("/")[-1])
def test_documented_cli_commands_exist(doc: str, line: str) -> None:
    args = shlex.split(line.rstrip("\\"))[1:]
    command = args[:2] if args[0] == "audit" else args[:1]  # `audit` is a command group
    help_out = runner.invoke(cli.app, [*command, "--help"], terminal_width=200)
    assert help_out.exit_code == 0, f"{doc}: unknown command `{' '.join(command)}`"
    sub = " ".join(command)
    help_text = plain_output(help_out)
    for opt in (a for a in args[len(command):] if a.startswith("--")):
        assert opt in help_text, f"{doc}: `{sub}` has no option {opt}"


def test_documented_make_targets_exist() -> None:
    makefile = (ROOT / "Makefile").read_text()
    targets = set(re.findall(r"^([a-zA-Z][\w-]*):", makefile, re.M))
    for doc in DOCS:
        for line in _code_lines(doc):
            if line.startswith("make "):
                assert line.split()[1] in targets, f"{doc}: make target {line.split()[1]} missing"


def test_documented_exit_codes_match_cli() -> None:
    table = (ROOT / "docs/pilot-protocol.md").read_text()
    for code in (cli.EXIT_ABORTED, cli.EXIT_CONFIG, cli.EXIT_INCOMPLETE, cli.EXIT_REJECTED, cli.EXIT_PROBE_FAILED,
                 cli.EXIT_REVIEW_REFUSED):
        assert re.search(rf"^\| {code} \|", table, re.M), f"exit code {code} undocumented"
