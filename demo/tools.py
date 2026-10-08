"""Mock tools and their provider-neutral JSON schemas."""

from __future__ import annotations

from typing import Callable

from agent_memgate import Label, ProvenanceMemoryStore, ToolBoundary

from .world import World

TOOL_SPECS: list[dict] = [
    {
        "name": "web_fetch",
        "description": "Fetch a web page and return its text.",
        "parameters": {
            "type": "object",
            "properties": {"url": {"type": "string", "description": "Absolute URL."}},
            "required": ["url"],
        },
    },
    {
        "name": "read_inbox",
        "description": "Return all emails currently in Alex's inbox.",
        "parameters": {"type": "object", "properties": {}},
    },
    {
        "name": "send_email",
        "description": "Send an email from Alex's account. Multiple addresses may be comma-separated.",
        "parameters": {
            "type": "object",
            "properties": {
                "to": {"type": "string"},
                "cc": {"type": "string"},
                "bcc": {"type": "string"},
                "subject": {"type": "string"},
                "body": {"type": "string"},
            },
            "required": ["to", "subject", "body"],
        },
    },
    {
        "name": "forward_email",
        "description": "Forward a message from Alex's inbox (by message id) to an address, with an optional note.",
        "parameters": {
            "type": "object",
            "properties": {
                "message_id": {"type": "string"},
                "to": {"type": "string"},
                "note": {"type": "string"},
            },
            "required": ["message_id", "to"],
        },
    },
    {
        "name": "memory_write",
        "description": "Store a durable note (fact or instruction about Alex's preferences) for future sessions.",
        "parameters": {
            "type": "object",
            "properties": {"note": {"type": "string"}},
            "required": ["note"],
        },
    },
    {
        "name": "memory_read",
        "description": "Return everything currently stored in memory.",
        "parameters": {"type": "object", "properties": {}},
    },
]


def register_tools(boundary: ToolBoundary, world: World, store: ProvenanceMemoryStore) -> None:
    def web_fetch(url: str) -> str:
        return world.fetch(url)

    def read_inbox() -> str:
        msgs = world.visible_inbox()
        if not msgs:
            return "(inbox empty)"
        return "\n\n".join(
            f"[{e.id}] From: {e.sender}\nSubject: {e.subject}\n{e.body}" for e in msgs
        )

    def send_email(to: str, subject: str = "", body: str = "", cc: str = "", bcc: str = "") -> str:
        world.outbox.append({"kind": "send", "session": world.current_session, "to": to, "cc": cc,
                             "bcc": bcc, "subject": subject, "body": body})
        return f"Email sent to {to}."

    def forward_email(message_id: str, to: str, note: str = "") -> str:
        e = world.find_email(message_id)
        if e is None:
            return f"ERROR: no message {message_id}"
        world.outbox.append({"kind": "forward", "session": world.current_session, "to": to, "cc": "",
                             "bcc": "", "message_id": message_id, "subject": "Fwd: " + e.subject,
                             "body": (note + "\n\n" if note else "") + e.body})
        return f"Forwarded {message_id} to {to}."

    def memory_write(note: str, _label: Label, _derived_from: tuple = ()) -> str:
        entry = store.write(note, _label, _derived_from)
        return f"Saved to memory ({entry.id})."

    def memory_read() -> str:
        return boundary.inject_memory(store, world.current_session)

    tools: dict[str, Callable] = {
        "web_fetch": web_fetch, "read_inbox": read_inbox, "send_email": send_email,
        "forward_email": forward_email, "memory_read": memory_read,
    }
    for name, fn in tools.items():
        boundary.register(name, fn)
    boundary.register("memory_write", memory_write, labelled=True)
