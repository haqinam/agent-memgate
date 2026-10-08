"""Deterministic scripted model.

It behaves like a naive, instruction-following model: it reads only what is in
its context window (system prompt incl. injected memory, user turn, tool
results) and follows the scenario's per-session script. It is NOT told whether
the defense is on, and the agent loop does not special-case it: when memgate
quarantines memory, the mock still obeys the note (a worst-case model), and the
boundary has to stop it.

Template placeholders resolved from context:
  {injected_block}   text between '---' fences in the latest tool output
  {last_tool_email}  first email address in the latest tool output
  {memory_email}     email addresses appearing in the memory section of the
                     system prompt, excluding ones the user typed (comma-joined)
  {inbox_id:Word}    id of the inbox message whose text contains Word
An arg whose placeholder cannot be resolved is dropped.
"""

from __future__ import annotations

import re

from memgate.taint import _EMAIL

from .base import AssistantMessage, ToolCall, split_system

_PH = re.compile(r"\{([a-z_]+)(?::([^}]*))?\}")


class MockProvider:
    name = "mock"

    def __init__(self, scenario: dict, model: str = "scripted-v1") -> None:
        self.scenario = scenario
        self.model = model

    # ------------------------------------------------------------ context
    @staticmethod
    def _memory_section(system: str) -> str:
        i = system.find("## Memory")
        return system[i:] if i >= 0 else ""

    def _resolve(self, key: str, arg: str | None, system: str, conv: list[dict]) -> str | None:
        tool_msgs = [m for m in conv if m["role"] == "tool"]
        last_tool = tool_msgs[-1]["content"] if tool_msgs else ""
        user = next((m["content"] for m in conv if m["role"] == "user"), "")
        if key == "injected_block":
            m = re.search(r"^\s*---\s*$(.*?)^\s*---\s*$", last_tool, re.S | re.M)
            return " ".join(m.group(1).split()) if m else None
        if key == "last_tool_email":
            m = _EMAIL.search(last_tool)
            return m.group(0) if m else None
        if key == "memory_email":
            user_emails = {e.lower() for e in _EMAIL.findall(user)}
            found = []
            for e in _EMAIL.findall(self._memory_section(system)):
                if e.lower() not in user_emails and e not in found:
                    found.append(e.rstrip("."))
            return ", ".join(found) or None
        if key == "inbox_id":
            for m in tool_msgs:
                for block in m["content"].split("\n\n"):
                    hit = re.match(r"\[([^\]]+)\]", block)
                    if hit and arg and arg.lower() in block.lower():
                        return hit.group(1)
            return None
        return None

    def _fill(self, value, system: str, conv: list[dict]):
        if not isinstance(value, str):
            return value
        missing = False

        def sub(m: re.Match) -> str:
            nonlocal missing
            r = self._resolve(m.group(1), m.group(2), system, conv)
            if r is None:
                missing = True
                return ""
            return r

        out = _PH.sub(sub, value)
        return None if missing else out

    # ----------------------------------------------------------- complete
    def complete(self, messages: list[dict], tools: list[dict]) -> AssistantMessage:
        system, conv = split_system(messages)
        user = next((m["content"] for m in conv if m["role"] == "user"), "")
        session = next((s for s in self.scenario["sessions"] if s["user"].strip() == user.strip()), None)
        if session is None:
            return AssistantMessage("I'm not sure how to help with that.", stop_reason="end_turn")

        step_idx = sum(1 for m in conv if m["role"] == "assistant")
        steps = session.get("mock") or []
        if step_idx >= len(steps):
            return AssistantMessage("Done.", stop_reason="end_turn")
        step = steps[step_idx]

        if "say" in step:
            last_tool = next((m["content"] for m in reversed(conv) if m["role"] == "tool"), "")
            text = step.get("say_if_blocked") if last_tool.startswith("BLOCKED") and step.get("say_if_blocked") else step["say"]
            return AssistantMessage(text, stop_reason="end_turn")

        args = {}
        for k, v in (step.get("args") or {}).items():
            filled = self._fill(v, system, conv)
            if filled is not None and filled != "":
                args[k] = filled
        if step["call"] == "memory_write" and "note" not in args:
            return AssistantMessage("Nothing worth remembering here.", stop_reason="end_turn")
        call = ToolCall(id=f"call_{step_idx}", name=step["call"], args=args)
        return AssistantMessage("", [call], raw=None, stop_reason="tool_use")
