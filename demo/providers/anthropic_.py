"""Anthropic Messages API provider (official `anthropic` SDK). Needs ANTHROPIC_API_KEY."""

from __future__ import annotations

import json

from .base import AssistantMessage, ToolCall, split_system

DEFAULT_MODEL = "claude-sonnet-5-5"


class AnthropicProvider:
    name = "anthropic"

    def __init__(self, model: str | None = None, max_tokens: int = 16000) -> None:
        import anthropic

        self.client = anthropic.Anthropic()
        self.model = model or DEFAULT_MODEL
        self.max_tokens = max_tokens

    @staticmethod
    def _to_native(conv: list[dict]) -> list[dict]:
        out: list[dict] = []
        for m in conv:
            if m["role"] == "user":
                out.append({"role": "user", "content": m["content"]})
            elif m["role"] == "assistant":
                if m.get("raw"):
                    content = m["raw"]  # replay native blocks verbatim (incl. thinking)
                else:
                    content = ([{"type": "text", "text": m["content"]}] if m["content"] else []) + [
                        {"type": "tool_use", "id": t["id"], "name": t["name"], "input": t["args"]}
                        for t in m["tool_calls"]
                    ]
                out.append({"role": "assistant", "content": content})
            elif m["role"] == "tool":
                block = {"type": "tool_result", "tool_use_id": m["tool_call_id"], "content": m["content"]}
                # all results for one assistant turn go in a single user message
                if out and out[-1]["role"] == "user" and isinstance(out[-1]["content"], list) \
                        and out[-1]["content"] and out[-1]["content"][0].get("type") == "tool_result":
                    out[-1]["content"].append(block)
                else:
                    out.append({"role": "user", "content": [block]})
        return out

    def complete(self, messages: list[dict], tools: list[dict]) -> AssistantMessage:
        system, conv = split_system(messages)
        resp = self.client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            system=system,
            messages=self._to_native(conv),
            tools=[{"name": t["name"], "description": t["description"], "input_schema": t["parameters"]}
                   for t in tools],
        )
        raw = [b.model_dump(mode="json", exclude_none=True) for b in resp.content]
        if resp.stop_reason == "refusal":
            return AssistantMessage("[refusal]", [], raw=raw, stop_reason="refusal")
        text = "".join(b.text for b in resp.content if b.type == "text")
        calls = [ToolCall(b.id, b.name, dict(b.input) if isinstance(b.input, dict) else json.loads(b.input))
                 for b in resp.content if b.type == "tool_use"]
        return AssistantMessage(text, calls, raw=raw, stop_reason=resp.stop_reason)
