"""The fake world: web pages, an inbox that fills up over sessions, an outbox.

All content comes from the scenario YAML; this module only serves it. The
attacker-controlled page / email is whatever the scenario puts there.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class Email:
    id: str
    sender: str
    subject: str
    body: str
    arrives: str


@dataclass
class World:
    web: dict[str, str]
    inbox: list[Email]
    session_order: list[str]
    current_session: str = ""
    outbox: list[dict] = field(default_factory=list)

    @classmethod
    def from_scenario(cls, scenario: dict) -> "World":
        w = scenario.get("world") or {}
        order = [s["id"] for s in scenario["sessions"]]
        inbox = [
            Email(e["id"], e["from"], e["subject"], str(e["body"]).strip(), e.get("arrives", order[0]))
            for e in (w.get("inbox") or [])
        ]
        return cls(web=dict(w.get("web") or {}), inbox=inbox, session_order=order)

    def visible_inbox(self) -> list[Email]:
        idx = self.session_order.index(self.current_session) if self.current_session in self.session_order else len(self.session_order)
        visible = set(self.session_order[: idx + 1])
        return [e for e in self.inbox if e.arrives in visible]

    def fetch(self, url: str) -> str:
        page = self.web.get(url) or self.web.get(url.rstrip("/"))
        return page if page is not None else f"404 Not Found: {url}"

    def find_email(self, message_id: str) -> Email | None:
        return next((e for e in self.visible_inbox() if e.id == message_id), None)


def load_scenario(path: str | Path) -> dict:
    sc = yaml.safe_load(Path(path).read_text())
    sc["_path"] = str(path)
    return sc
