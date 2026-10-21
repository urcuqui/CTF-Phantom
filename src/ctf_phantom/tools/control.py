"""Episode-control tools: flag submission and voluntary termination."""

from __future__ import annotations

from typing import Any

from ctf_phantom.challenges.flags import FlagValidator
from ctf_phantom.tools.base import ToolResult, ToolSpec

SUBMIT_FLAG_SPEC = ToolSpec(
    name="submit_flag",
    description=(
        "Submit a candidate flag for verification. The episode ends when a correct flag is "
        "submitted or the submission limit is reached."
    ),
    input_schema={
        "type": "object",
        "properties": {"flag": {"type": "string"}},
        "required": ["flag"],
        "additionalProperties": False,
    },
)

TERMINATE_SPEC = ToolSpec(
    name="terminate",
    description="End the episode without a correct flag. Provide a short reason.",
    input_schema={
        "type": "object",
        "properties": {"reason": {"type": "string"}},
        "required": ["reason"],
        "additionalProperties": False,
    },
)


class SubmitFlagTool:
    spec = SUBMIT_FLAG_SPEC

    def __init__(self, validator: FlagValidator, max_submissions: int) -> None:
        self._validator = validator
        self.max_submissions = max_submissions
        self.submissions = 0

    def __call__(self, arguments: dict[str, Any]) -> ToolResult:
        candidate = str(arguments.get("flag", ""))
        self.submissions += 1
        verdict = self._validator.check(candidate)
        remaining = self.max_submissions - self.submissions
        meta = {
            "submitted": verdict.normalized,
            "correct": verdict.correct,
            "well_formed": verdict.well_formed,
            "submission_index": self.submissions,
            "reserved_decoy": verdict.reserved,
        }
        if verdict.correct:
            return ToolResult(ok=True, observation="Correct flag. Episode complete.",
                              terminal=True, meta=meta)
        if remaining <= 0:
            return ToolResult(ok=False, observation="Incorrect flag. No submissions remaining.",
                              terminal=True, meta=meta | {"limit_reached": True})
        return ToolResult(ok=False, observation=f"Incorrect flag. {remaining} submission(s) remaining.",
                          meta=meta)


class TerminateTool:
    spec = TERMINATE_SPEC

    def __call__(self, arguments: dict[str, Any]) -> ToolResult:
        reason = str(arguments.get("reason", ""))
        return ToolResult(ok=True, observation="Episode terminated.", terminal=True,
                          meta={"reason": reason})
