"""Minimal provider-agnostic tool-calling agent loop.

Every tool call goes through the memgate ToolBoundary, for every provider,
with the defense on or off. Defense off = permissive policy + non-quarantining
memory store; the code path is identical.
"""

from __future__ import annotations

from typing import Callable

from memgate import ProvenanceMemoryStore, ToolBoundary

from .providers.base import Provider
from .world import World

EventFn = Callable[[dict], None]


class Agent:
    def __init__(
        self,
        provider: Provider,
        boundary: ToolBoundary,
        store: ProvenanceMemoryStore,
        world: World,
        system_prompt: str,
        tools: list[dict],
        max_steps: int = 8,
        on_event: EventFn | None = None,
    ) -> None:
        self.provider = provider
        self.boundary = boundary
        self.store = store
        self.world = world
        self.system_prompt = system_prompt.strip()
        self.tools = tools
        self.max_steps = max_steps
        self.on_event = on_event or (lambda e: None)
        self.events: list[dict] = []

    def _emit(self, ev: dict) -> None:
        self.events.append(ev)
        self.on_event(ev)

    def run_session(self, session_id: str, user_text: str) -> list[dict]:
        self.world.current_session = session_id
        memory_ctx = self.boundary.inject_memory(self.store, session_id)
        self.boundary.record_user(user_text, session_id)
        messages: list[dict] = [
            {"role": "system", "content": self.system_prompt + "\n\n" + memory_ctx},
            {"role": "user", "content": user_text},
        ]
        self._emit({"type": "session_start", "session": session_id, "user": user_text, "memory": memory_ctx})

        for _ in range(self.max_steps):
            try:
                msg = self.provider.complete(messages, self.tools)
            except Exception as e:  # provider/network error: record and end session
                self._emit({"type": "error", "session": session_id, "error": f"{type(e).__name__}: {e}"})
                break
            messages.append(msg.to_message())
            self._emit({"type": "assistant", "session": session_id, "content": msg.content,
                        "tool_calls": [{"id": t.id, "name": t.name, "args": t.args} for t in msg.tool_calls],
                        "stop_reason": msg.stop_reason})
            if not msg.tool_calls:
                break
            for tc in msg.tool_calls:
                r = self.boundary.call(tc.name, tc.args, session_id)
                self._emit({
                    "type": "tool",
                    "session": session_id,
                    "tool": tc.name,
                    "args": tc.args,
                    "decision": r.decision.kind.value,
                    "reason": r.decision.reason,
                    "violations": r.decision.violations,
                    "taint": {k: sorted(t.sources) for k, t in r.tainted_args.items()},
                    "executed": r.executed,
                    "confirmed": r.confirmed,
                    "assigned_label": r.assigned_label.to_dict() if r.assigned_label else None,
                    "quarantined": bool(r.assigned_label and self.store.quarantine
                                        and r.assigned_label.trust.name == "UNTRUSTED"),
                    "output": r.output,
                })
                messages.append({"role": "tool", "tool_call_id": tc.id, "name": tc.name, "content": r.output})
        self._emit({"type": "session_end", "session": session_id})
        return messages
