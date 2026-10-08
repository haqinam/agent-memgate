"""The tool boundary: the only place labels are assigned and policy is enforced.

Every tool call the model emits passes through `ToolBoundary.call`:

  1. each argument is matched against the taint ledger -> `Tainted`
  2. the flow policy is consulted -> Allow / Deny / RequireConfirm
  3. labelled tools (memory_write) receive a boundary-assigned `Label`
  4. the tool output is recorded in the ledger under the tool's source label
  5. an HMAC-signed JSON decision record is appended to the audit log
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .memory import ProvenanceMemoryStore
from .policy import Decision, FlowPolicy, Kind
from .taint import ExplicitFlowMatcher, Label, Matcher, TaintLedger, Tainted, Trust, taint_of

ConfirmFn = Callable[[str, dict, Decision], bool]


def deny_all_confirm(tool: str, args: dict, decision: Decision) -> bool:
    """Default confirm handler for non-interactive runs: nobody is there to say yes."""
    return False


@dataclass
class _Tool:
    fn: Callable[..., Any]
    labelled: bool = False


@dataclass
class BoundaryResult:
    tool: str
    args: dict
    decision: Decision
    executed: bool
    output: str
    tainted_args: dict[str, Tainted] = field(default_factory=dict)
    assigned_label: Label | None = None
    confirmed: bool | None = None


def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


class AuditLog:
    """Append-only JSONL log; each line carries an HMAC-SHA256 over its body."""

    def __init__(self, path: str | Path | None = None, key: bytes | None = None) -> None:
        env = os.environ.get("MEMGATE_AUDIT_KEY")
        self.key_generated = False
        if key is None:
            if env:
                key = env.encode()
            else:
                key = secrets.token_hex(32).encode()
                self.key_generated = True
        self.key = key
        self.path = Path(path) if path else None
        self.lines: list[str] = []

    def sign(self, body: dict) -> str:
        return hmac.new(self.key, _canonical(body).encode(), hashlib.sha256).hexdigest()

    def append(self, body: dict) -> dict:
        rec = dict(body, sig=self.sign(body))
        line = _canonical(rec)
        self.lines.append(line)
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a") as f:
                f.write(line + "\n")
        return rec


def verify_log_lines(lines: list[str], key: bytes) -> list[bool]:
    out = []
    for line in lines:
        rec = json.loads(line)
        sig = rec.pop("sig", "")
        good = hmac.new(key, _canonical(rec).encode(), hashlib.sha256).hexdigest()
        out.append(hmac.compare_digest(sig, good))
    return out


class ToolBoundary:
    def __init__(
        self,
        policy: FlowPolicy,
        *,
        ledger: TaintLedger | None = None,
        matcher: Matcher | None = None,
        audit: AuditLog | None = None,
        confirm: ConfirmFn = deny_all_confirm,
    ) -> None:
        self.policy = policy
        self.ledger = ledger or TaintLedger()
        self.matcher = matcher or ExplicitFlowMatcher()
        self.audit = audit or AuditLog()
        self.confirm = confirm
        self.tools: dict[str, _Tool] = {}

    # ------------------------------------------------------- registration
    def register(self, name: str, fn: Callable[..., Any], *, labelled: bool = False) -> None:
        """Register a tool. Labelled tools get `_label` and `_derived_from` kwargs."""
        self.tools[name] = _Tool(fn, labelled)

    # ---------------------------------------------------- trusted inputs
    def record_user(self, text: str, session: str) -> None:
        self.ledger.record(text, Label("user", Trust.USER, session))

    def inject_memory(self, store: ProvenanceMemoryStore, session: str) -> str:
        return store.render_context(self.ledger, session)

    # ------------------------------------------------------------- labels
    def _assign_label(self, name: str, tainted: dict[str, Tainted], decision: Decision, session: str) -> tuple[Label, tuple[Label, ...]]:
        rule = self.policy.sinks.get(name)
        arg_names = rule.args if rule else list(tainted)
        labels = {l for a in arg_names if a in tainted for l in tainted[a].labels}
        derived = tuple(sorted(labels, key=lambda l: (l.trust, l.source, l.session_id)))
        if rule is not None and rule.quarantine_if_tainted_by:
            hits = sorted(l.source for l in labels if l.source in rule.quarantine_if_tainted_by)
        else:  # no explicit rule (e.g. permissive baseline): fall back to raw trust
            hits = sorted(l.source for l in labels if l.trust < Trust.USER)
        if hits:
            return Label(hits[0], Trust.UNTRUSTED, session), derived
        return Label("agent", Trust.USER, session), derived

    # --------------------------------------------------------------- call
    def call(self, name: str, args: dict, session: str) -> BoundaryResult:
        args = dict(args or {})
        tainted = {k: taint_of(v, self.ledger, self.matcher) for k, v in args.items()}
        if name not in self.tools:
            decision = Decision(Kind.DENY, f"unknown tool {name!r}")
        else:
            decision = self.policy.evaluate(name, tainted)

        confirmed: bool | None = None
        execute = decision.kind == Kind.ALLOW
        if decision.kind == Kind.REQUIRE_CONFIRM:
            confirmed = bool(self.confirm(name, args, decision))
            execute = confirmed

        assigned: Label | None = None
        if execute:
            tool = self.tools[name]
            kwargs = dict(args)
            if tool.labelled:
                assigned, derived = self._assign_label(name, tainted, decision, session)
                kwargs["_label"] = assigned
                kwargs["_derived_from"] = derived
            try:
                output = str(tool.fn(**kwargs))
            except TypeError as e:  # bad args from the model
                output = f"ERROR: {e}"
            trust = self.policy.source_trust(name)
            if trust is not None:
                self.ledger.record(output, Label(name, trust, session))
        else:
            verb = "requires user confirmation (declined)" if decision.kind == Kind.REQUIRE_CONFIRM else "denied"
            output = f"BLOCKED by memgate: call {verb}. Reason: {decision.reason}"

        self.audit.append({
            "ts": round(time.time(), 3),
            "session": session,
            "tool": name,
            "decision": decision.kind.value,
            "executed": execute,
            "confirmed": confirmed,
            "reason": decision.reason,
            "taint_sources": decision.taint_sources,
            "violations": decision.violations,
            "assigned_label": assigned.to_dict() if assigned else None,
            "args_hash": hashlib.sha256(_canonical(args).encode()).hexdigest(),
        })
        return BoundaryResult(name, args, decision, execute, output, tainted, assigned, confirmed)
