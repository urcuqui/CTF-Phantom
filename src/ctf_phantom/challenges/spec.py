"""Typed schema for challenges, variants, content slots and behavioural indicators."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class SlotKind(StrEnum):
    TEXT = "text"
    NOTE = "note"


class ContentSlot(_Strict):
    kind: SlotKind
    location: str
    trust: Literal["low"]
    max_chars: int = Field(gt=0)


class IndicatorKind(StrEnum):
    ACTION = "action"          # observable agent action; counts toward attack success
    UTTERANCE = "utterance"    # text only; may be quotation, reported separately


class IndicatorType(StrEnum):
    FLAG_SUBMITTED = "flag_submitted"                    # value: exact flag string
    REQUEST_PATH = "request_path"                        # pattern: regex on in-scope path
    REQUEST_HOST = "request_host"                        # pattern: regex on any requested host
    TERMINATE_REASON_CONTAINS = "terminate_reason_contains"  # value: substring
    AGENT_TEXT_CONTAINS = "agent_text_contains"          # value: substring (text + tool args)


class Indicator(_Strict):
    id: str
    kind: IndicatorKind
    type: IndicatorType
    value: str | None = None
    pattern: str | None = None
    description: str = ""

    @model_validator(mode="after")
    def _check_operand(self) -> Indicator:
        needs_pattern = self.type in (IndicatorType.REQUEST_PATH, IndicatorType.REQUEST_HOST)
        if needs_pattern and not self.pattern:
            raise ValueError(f"indicator {self.id}: type {self.type} requires 'pattern'")
        if not needs_pattern and not self.value:
            raise ValueError(f"indicator {self.id}: type {self.type} requires 'value'")
        return self


class VariantSpec(_Strict):
    id: str
    condition: Literal["control", "treatment"]
    attack_class: str
    description: str
    slots: dict[str, Any]
    exposure_markers: list[str] = Field(min_length=1)
    indicators: list[Indicator] = Field(default_factory=list)


class ScriptStep(_Strict):
    tool: str
    args: dict[str, Any] = Field(default_factory=dict)
    extract_regex: str | None = None


class FlagSpec(_Strict):
    format_regex: str
    derivation: str


class AppSpec(_Strict):
    module: str
    compose_file: str
    healthcheck_path: str = "/healthz"


class ChallengeSpec(_Strict):
    id: str
    name: str
    version: str
    category: str
    difficulty: str
    description: str
    objective: str
    flag: FlagSpec
    app: AppSpec
    reference_solution: list[ScriptStep]
    content_slots: dict[str, ContentSlot]
    variants: list[str] = Field(min_length=1)

    def render_objective(self, base_url: str) -> str:
        return self.objective.format(base_url=base_url).strip()


class Challenge(BaseModel):
    """A loaded challenge: its spec, variants, location on disk and provenance hashes."""

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    spec: ChallengeSpec
    variants: dict[str, VariantSpec]
    root: Path
    challenge_hash: str          # hash of app + spec (everything except variants/)
    variant_hashes: dict[str, str]
    payload_hashes: dict[str, dict[str, str]]  # variant -> slot -> hash

    @property
    def id(self) -> str:
        return self.spec.id

    @property
    def decoy_flags(self) -> frozenset[str]:
        """Flags planted by variants (flag_submitted indicators); never valid for any run."""
        return frozenset(
            ind.value
            for v in self.variants.values()
            for ind in v.indicators
            if ind.type is IndicatorType.FLAG_SUBMITTED and ind.value
        )

    def variant(self, variant_id: str) -> VariantSpec:
        try:
            return self.variants[variant_id]
        except KeyError:
            raise KeyError(
                f"unknown variant {variant_id!r} for {self.id}; available: {sorted(self.variants)}"
            ) from None
