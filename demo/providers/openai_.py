"""OpenAI Chat Completions provider. Needs OPENAI_API_KEY.

Also works with any OpenAI-compatible endpoint via OPENAI_BASE_URL
(e.g. Ollama: OPENAI_BASE_URL=http://localhost:11434/v1 OPENAI_API_KEY=ollama).
"""

from __future__ import annotations

import json

from .base import AssistantMessage, ToolCall, split_system

DEFAULT_MODEL = "gpt-5.5"  # override with --model; verify against OpenAI's model list


class OpenAIProvider:
    name = "openai"

    def __init__(self, model: str | None = None) -> None:
        import openai

        self.client = openai.OpenAI()  # reads OPENAI_API_KEY and OPENAI_BASE_URL
        self.model = model or DEFAULT_MODEL

    @staticmethod
    def _to_native(system: str, conv: list[dict]) -> list[dict]:
        out: list[dict] = [{"role": "system", "content": system}] if system else []
        for m in conv:
            if m["role"] == "user":
                out.append({"role": "user", "content": m["content"]})
            elif m["role"] == "assistant":
                msg: dict = {"role": "assistant", "content": m["content"] or None}
                if m["tool_calls"]:
                    msg["tool_calls"] = [
                        {"id": t["id"], "type": "function",
                         "function": {"name": t["name"], "arguments": json.dumps(t["args"])}}
                        for t in m["tool_calls"]
                    ]
                out.append(msg)
            elif m["role"] == "tool":
                out.append({"role": "tool", "tool_call_id": m["tool_call_id"], "content": m["content"]})
        return out

    def complete(self, messages: list[dict], tools: list[dict]) -> AssistantMessage:
        system, conv = split_system(messages)
        resp = self.client.chat.completions.create(
            model=self.model,
            messages=self._to_native(system, conv),
            tools=[{"type": "function", "function": t} for t in tools],
        )
        choice = resp.choices[0]
        msg = choice.message
        calls = []
        for tc in msg.tool_calls or []:
            try:
                args = json.loads(tc.function.arguments or "{}")
            except json.JSONDecodeError:
                args = {"_unparseable": tc.function.arguments}
            calls.append(ToolCall(tc.id, tc.function.name, args))
        refusal = getattr(msg, "refusal", None)
        return AssistantMessage(msg.content or (f"[refusal] {refusal}" if refusal else ""), calls,
                                raw=msg.model_dump(mode="json", exclude_none=True),
                                stop_reason="refusal" if refusal else choice.finish_reason)


class OpenWeightsProvider(OpenAIProvider):
    """Open-weights model behind any OpenAI-compatible server (Ollama, vLLM, llama.cpp, LM Studio).

    OPENWEIGHTS_BASE_URL  e.g. http://localhost:11434/v1   (required)
    OPENWEIGHTS_MODEL     e.g. the server's model tag      (or pass --model / set it in eval/models.yaml)
    OPENWEIGHTS_API_KEY   optional; most local servers ignore it
    """

    name = "openweights"

    def __init__(self, model: str | None = None) -> None:
        import os

        import openai

        model = model or os.environ.get("OPENWEIGHTS_MODEL")
        if not model:
            raise SystemExit("openweights: set OPENWEIGHTS_MODEL or pass a model id")
        self.client = openai.OpenAI(base_url=os.environ["OPENWEIGHTS_BASE_URL"],
                                    api_key=os.environ.get("OPENWEIGHTS_API_KEY", "not-needed"))
        self.model = model
