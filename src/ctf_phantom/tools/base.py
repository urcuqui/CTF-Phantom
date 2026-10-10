"""Provider-neutral tool definitions and results."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    input_schema: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {"name": self.name, "description": self.description, "input_schema": self.input_schema}


@dataclass
class ToolResult:
    ok: bool
    observation: str                       # exactly what the model will see
    raw_chars: int = 0                     # size before truncation
    truncated: bool = False
    terminal: bool = False                 # ends the episode (correct flag, terminate, budget)
    meta: dict[str, Any] = field(default_factory=dict)


class Tool(Protocol):
    spec: ToolSpec

    def __call__(self, arguments: dict[str, Any]) -> ToolResult: ...
