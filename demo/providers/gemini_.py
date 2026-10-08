"""Google Gemini provider (official `google-genai` SDK). Needs GEMINI_API_KEY."""

from __future__ import annotations

import os

from .base import AssistantMessage, ToolCall, split_system

DEFAULT_MODEL = "gemini-3.6-flash"  # override with --model; verify against Google's model list


class GeminiProvider:
    name = "gemini"

    def __init__(self, model: str | None = None) -> None:
        from google import genai
        from google.genai import types

        self.types = types
        self.client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])
        self.model = model or DEFAULT_MODEL

    def _to_native(self, conv: list[dict]) -> list:
        t = self.types
        out: list = []
        for m in conv:
            if m["role"] == "user":
                out.append(t.Content(role="user", parts=[t.Part(text=m["content"])]))
            elif m["role"] == "assistant":
                if m.get("raw"):
                    out.append(t.Content.model_validate(m["raw"]))  # keeps thought signatures
                else:
                    parts = ([t.Part(text=m["content"])] if m["content"] else []) + [
                        t.Part(function_call=t.FunctionCall(name=c["name"], args=c["args"], id=c["id"]))
                        for c in m["tool_calls"]
                    ]
                    out.append(t.Content(role="model", parts=parts))
            elif m["role"] == "tool":
                part = t.Part.from_function_response(name=m["name"], response={"result": m["content"]})
                if out and out[-1].role == "user" and out[-1].parts and out[-1].parts[0].function_response:
                    out[-1].parts.append(part)
                else:
                    out.append(t.Content(role="user", parts=[part]))
        return out

    def complete(self, messages: list[dict], tools: list[dict]) -> AssistantMessage:
        t = self.types
        system, conv = split_system(messages)
        decls = [t.FunctionDeclaration(name=x["name"], description=x["description"],
                                       parameters_json_schema=x["parameters"]) for x in tools]
        config = t.GenerateContentConfig(
            system_instruction=system,
            tools=[t.Tool(function_declarations=decls)],
            automatic_function_calling=t.AutomaticFunctionCallingConfig(disable=True),
        )
        resp = self.client.models.generate_content(model=self.model, contents=self._to_native(conv), config=config)
        cand = resp.candidates[0] if resp.candidates else None
        if cand is None or cand.content is None:
            reason = getattr(resp.prompt_feedback, "block_reason", None) if resp.prompt_feedback else None
            return AssistantMessage(f"[refusal] {reason}", stop_reason="refusal")
        calls = [ToolCall(fc.id or f"fc_{i}", fc.name, dict(fc.args or {}))
                 for i, fc in enumerate(resp.function_calls or [])]
        text = "".join(p.text for p in (cand.content.parts or []) if p.text and not p.thought)
        return AssistantMessage(text, calls, raw=cand.content.model_dump(mode="json", exclude_none=True),
                                stop_reason=str(cand.finish_reason))
