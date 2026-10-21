"""Helpers for asserting on CLI output independently of terminal colour settings.

Rich (and Typer's Rich-rendered help) emit ANSI escape sequences whenever colour is forced, e.g.
by ``FORCE_COLOR=1`` in CI. Escapes can land *inside* the text under test: Rich's highlighter
turns ``40 runs planned`` into ``\\x1b[1;36m40\\x1b[0m runs planned`` and styles option names in
``--help`` output. Assertions must therefore compare against the plain text the user reads.
Only the test side is normalised; the production CLI output is left untouched.
"""

from __future__ import annotations

import re
from typing import Any

# CSI sequences (colours/styles, cursor movement), OSC sequences (e.g. OSC 8 hyperlinks,
# terminated by BEL or ST) and two-character escapes.
_ANSI = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[@-Z\\-_])")


def strip_ansi(text: str) -> str:
    return _ANSI.sub("", text)


def plain_output(result: Any) -> str:
    """Plain-text output of a ``typer.testing`` / ``click.testing`` invocation result."""
    return strip_ansi(result.output)
