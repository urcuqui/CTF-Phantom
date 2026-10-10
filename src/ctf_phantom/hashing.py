"""Stable content hashing for provenance (challenge, variant, payload, prompt, config)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

_EXCLUDED_PARTS = {"__pycache__", ".pytest_cache"}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode("utf-8"))


def canonical_json(obj: Any) -> str:
    """Deterministic JSON serialisation (sorted keys, no whitespace)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def sha256_json(obj: Any) -> str:
    return sha256_text(canonical_json(obj))


def sha256_tree(root: Path, *, exclude_dirs: set[str] | None = None) -> str:
    """Hash every file under ``root`` (relative path + content), in sorted order."""
    excluded = _EXCLUDED_PARTS | (exclude_dirs or set())
    digest = hashlib.sha256()
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        rel = path.relative_to(root)
        if excluded.intersection(rel.parts) or path.suffix == ".pyc":
            continue
        digest.update(rel.as_posix().encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()
