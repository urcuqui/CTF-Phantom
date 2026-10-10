"""Locations of challenges and results, overridable via environment variables."""

from __future__ import annotations

import os
from pathlib import Path


def project_root() -> Path:
    """Nearest ancestor of the CWD (or of this package) containing ``challenges/``."""
    for start in (Path.cwd(), Path(__file__).resolve()):
        for candidate in (start, *start.parents):
            if (candidate / "challenges").is_dir() and (candidate / "pyproject.toml").is_file():
                return candidate
    return Path.cwd()


def challenges_dir() -> Path:
    env = os.environ.get("CTF_PHANTOM_CHALLENGES_DIR")
    return Path(env).resolve() if env else project_root() / "challenges"


def results_dir() -> Path:
    env = os.environ.get("CTF_PHANTOM_RESULTS_DIR")
    return Path(env).resolve() if env else project_root() / "results"
