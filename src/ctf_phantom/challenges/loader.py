"""Load and validate challenges from ``challenges/<id>/``."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from ctf_phantom.challenges.spec import Challenge, ChallengeSpec, IndicatorType, SlotKind, VariantSpec
from ctf_phantom.hashing import sha256_json, sha256_tree
from ctf_phantom.paths import challenges_dir


class ChallengeValidationError(ValueError):
    pass


def _read_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict):
        raise ChallengeValidationError(f"{path}: expected a mapping")
    return data


def slot_texts(spec: ChallengeSpec, slots: dict[str, Any]) -> dict[str, str]:
    """Flatten slot values to plain text (used for hashing, exposure, and length checks)."""
    out: dict[str, str] = {}
    for name, value in slots.items():
        kind = spec.content_slots[name].kind
        out[name] = f"{value['author']}\n{value['body']}" if kind is SlotKind.NOTE else str(value)
    return out


def validate_variant(spec: ChallengeSpec, variant: VariantSpec) -> None:
    """Enforce that a variant only touches declared low-trust slots, within their limits."""
    declared = set(spec.content_slots)
    used = set(variant.slots)
    if used != declared:
        raise ChallengeValidationError(
            f"variant {variant.id}: must define exactly the declared slots {sorted(declared)}, "
            f"got {sorted(used)}"
        )
    for name, value in variant.slots.items():
        slot = spec.content_slots[name]
        if slot.kind is SlotKind.NOTE:
            if not isinstance(value, dict) or set(value) != {"author", "body"}:
                raise ChallengeValidationError(
                    f"variant {variant.id}: slot {name} must be {{author, body}}"
                )
            length = len(value["author"]) + len(value["body"])
        else:
            if not isinstance(value, str):
                raise ChallengeValidationError(f"variant {variant.id}: slot {name} must be text")
            length = len(value)
        if length > slot.max_chars:
            raise ChallengeValidationError(
                f"variant {variant.id}: slot {name} has {length} chars > max {slot.max_chars}"
            )
    texts = "\n".join(slot_texts(spec, variant.slots).values())
    flag_format = re.compile(spec.flag.format_regex)
    for ind in variant.indicators:
        if ind.type is IndicatorType.FLAG_SUBMITTED:
            # A decoy that violates the official format is trivially dismissible and would
            # confound "deception" with "format mismatch"; it must also appear in the payload.
            if not flag_format.match(ind.value or ""):
                raise ChallengeValidationError(
                    f"variant {variant.id}: decoy flag {ind.value!r} does not match the flag format"
                )
            if (ind.value or "") not in texts:
                raise ChallengeValidationError(
                    f"variant {variant.id}: decoy flag {ind.value!r} is not present in slot content"
                )
    for marker in variant.exposure_markers:
        if marker not in texts:
            raise ChallengeValidationError(
                f"variant {variant.id}: exposure marker {marker!r} not present in slot content"
            )


def load_challenge(challenge_id: str, root: Path | None = None) -> Challenge:
    base = (root or challenges_dir()) / challenge_id
    if not (base / "challenge.yaml").is_file():
        raise FileNotFoundError(f"challenge {challenge_id!r} not found under {base.parent}")
    spec = ChallengeSpec.model_validate(_read_yaml(base / "challenge.yaml"))
    if spec.id != challenge_id:
        raise ChallengeValidationError(f"challenge.yaml id {spec.id!r} != directory {challenge_id!r}")

    variants: dict[str, VariantSpec] = {}
    for vid in spec.variants:
        variant = VariantSpec.model_validate(_read_yaml(base / "variants" / f"{vid}.yaml"))
        if variant.id != vid:
            raise ChallengeValidationError(f"variant file {vid}.yaml declares id {variant.id!r}")
        validate_variant(spec, variant)
        variants[vid] = variant

    # Indicator ids must be globally unique so cross-variant false-positive analysis is unambiguous.
    seen: set[str] = set()
    for variant in variants.values():
        for ind in variant.indicators:
            if ind.id in seen:
                raise ChallengeValidationError(f"duplicate indicator id {ind.id!r}")
            seen.add(ind.id)

    return Challenge(
        spec=spec,
        variants=variants,
        root=base,
        challenge_hash=sha256_tree(base, exclude_dirs={"variants"}),
        variant_hashes={vid: sha256_json(v.model_dump(mode="json")) for vid, v in variants.items()},
        payload_hashes={
            vid: {name: sha256_json(value) for name, value in v.slots.items()}
            for vid, v in variants.items()
        },
    )


def list_challenges(root: Path | None = None) -> list[str]:
    base = root or challenges_dir()
    return sorted(p.parent.name for p in base.glob("*/challenge.yaml"))
