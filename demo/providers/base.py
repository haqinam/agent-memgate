"""Provider interface.

Messages are provider-neutral dicts:
  {"role": "system",    "content": str}
  {"role": "user",      "content": str}
  {"role": "assistant", "content": str, "tool_calls": [{"id","name","args"}], "raw": <provider-native>}
  {"role": "tool",      "tool_call_id": str, "name": str, "content": str}

`raw` lets a provider replay its own native assistant turn verbatim (thinking
blocks, thought signatures) on the next request.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass
class ToolCall:
    id: str
    name: str
    args: dict


@dataclass
class AssistantMessage:
    content: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    raw: Any = None
    stop_reason: str | None = None

    def to_message(self) -> dict:
        return {
            "role": "assistant",
            "content": self.content,
            "tool_calls": [{"id": t.id, "name": t.name, "args": t.args} for t in self.tool_calls],
            "raw": self.raw,
            "stop_reason": self.stop_reason,
        }


class Provider(Protocol):
    name: str
    model: str

    def complete(self, messages: list[dict], tools: list[dict]) -> AssistantMessage: ...


def split_system(messages: list[dict]) -> tuple[str, list[dict]]:
    system = "\n\n".join(m["content"] for m in messages if m["role"] == "system")
    return system, [m for m in messages if m["role"] != "system"]
