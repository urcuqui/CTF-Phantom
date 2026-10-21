"""Immutable Docker image identifiers and their comparison (shared by runner and acceptance).

Two identifiers are recorded per compose service:

* **engine ID** (``docker image inspect .Id`` / container ``.Image``): exact identity on one
  engine. With the containerd image store it is a manifest/index digest that changes on every
  rebuild, even for byte-identical content (non-reproducible layer compression), so it is only
  comparable within one experiment.
* **content ID** (``content_id``): SHA-256 over what determines runtime behaviour: the
  uncompressed layer digests (``RootFS.Layers``), OS/architecture and the runtime config,
  excluding compose's bookkeeping labels. Stable across rebuilds, project names and engines;
  this is what acceptance A4 compares.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from typing import Any

_HEX64 = re.compile(r"[0-9a-f]{64}")


def normalize_image_id(raw: str) -> str:
    """Canonical immutable image ID: ``sha256:<64 lowercase hex>``.

    Accepts the full ID with or without the ``sha256:`` prefix. Short IDs (as printed by some
    ``docker images`` / ``compose images`` formats) are ambiguous and rejected, never compared.
    """
    value = raw.strip().lower()
    if value.startswith("sha256:"):
        value = value[len("sha256:"):]
    if not _HEX64.fullmatch(value):
        raise ValueError(f"not a full immutable image ID: {raw.strip()!r}")
    return f"sha256:{value}"


def compare_image_maps(expected: Mapping[str, str], used: Mapping[str, str]) -> str | None:
    """None if a run used exactly the experiment's images, else a problem code.

    Both maps are ``{compose service: image ID}``. Comparison is per service on normalized IDs,
    so container names, ID prefixes, letter case and short-vs-full formatting cannot cause false
    mismatches, and a swapped service (right IDs, wrong services) is still detected. Legacy maps
    keyed by something other than service names fall back to comparing the sets of IDs.
    """
    if not expected:
        return "experiment_images_not_recorded"
    if not used:
        return "run_images_not_recorded"
    try:
        exp = {k: normalize_image_id(v) for k, v in expected.items()}
        got = {k: normalize_image_id(v) for k, v in used.items()}
    except ValueError:
        return "image_id_not_immutable"
    if set(exp) & set(got):
        return None if exp == got else "images_differ_from_experiment"
    return None if set(exp.values()) == set(got.values()) else "images_differ_from_experiment"


_CONFIG_KEYS = ("Env", "Cmd", "Entrypoint", "User", "WorkingDir", "ExposedPorts", "Healthcheck", "Volumes",
                "StopSignal")


def content_id(inspect: Mapping[str, Any]) -> str:
    """Rebuild-stable content identifier from one ``docker image inspect`` object."""
    config = inspect.get("Config") or {}
    layers = (inspect.get("RootFS") or {}).get("Layers") or []
    if not layers:
        raise ValueError("image inspect has no RootFS layers")
    material = {
        "os": inspect.get("Os"),
        "architecture": inspect.get("Architecture"),
        "variant": inspect.get("Variant"),
        "layers": [normalize_image_id(layer) for layer in layers],
        "config": {k: config.get(k) for k in _CONFIG_KEYS}
        | {"Labels": {k: v for k, v in (config.get("Labels") or {}).items()
                      if not k.startswith("com.docker.compose.")}},
    }
    return "sha256:" + hashlib.sha256(json.dumps(material, sort_keys=True).encode()).hexdigest()


def compare_run_images(expected_ids: Mapping[str, str], used_ids: Mapping[str, str],
                       expected_content: Mapping[str, str] | None = None,
                       used_content: Mapping[str, str] | None = None) -> str | None:
    """A4 image check: content IDs when both sides recorded them, else engine IDs (legacy)."""
    if expected_content and used_content:
        return compare_image_maps(expected_content, used_content)
    return compare_image_maps(expected_ids, used_ids)
