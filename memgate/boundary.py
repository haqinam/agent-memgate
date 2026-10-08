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


@dataclass
class Gate:
    """Pre-execution verdict for one tool call (see ToolBoundary.gate)."""
    name: str
    session: str
    args: dict
    kwargs: dict  # args plus boundary-assigned _label/_derived_from for labelled tools
    tainted: dict[str, Tainted]
    decision: Decision
    execute: bool
    confirmed: bool | None
    assigned: Label | None


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
    # `call` / `acall` run registered tools. Framework adapters that own tool
    # execution themselves use the two halves directly: `gate` (taint, policy,
    # confirm, label) before running the tool and `finish` (ledger, audit) after.

    def gate(self, name: str, args: dict, session: str, *, labelled: bool = False,
             known: bool = True) -> Gate:
        args = dict(args or {})
        tainted = {k: taint_of(v, self.ledger, self.matcher) for k, v in args.items()}
        decision = self.policy.evaluate(name, tainted) if known else Decision(Kind.DENY, f"unknown tool {name!r}")
        confirmed: bool | None = None
        execute = decision.kind == Kind.ALLOW
        if decision.kind == Kind.REQUIRE_CONFIRM:
            confirmed = bool(self.confirm(name, args, decision))
            execute = confirmed
        kwargs = dict(args)
        assigned: Label | None = None
        if execute and labelled:
            assigned, derived = self._assign_label(name, tainted, decision, session)
            kwargs["_label"] = assigned
            kwargs["_derived_from"] = derived
        return Gate(name, session, args, kwargs, tainted, decision, execute, confirmed, assigned)

    def finish(self, g: Gate, output: object | None = None) -> BoundaryResult:
        if g.execute:
            out = str(output)
            trust = self.policy.source_trust(g.name)
            if trust is not None:
                self.ledger.record(out, Label(g.name, trust, g.session))
        else:
            verb = "requires user confirmation (declined)" if g.decision.kind == Kind.REQUIRE_CONFIRM else "denied"
            out = f"BLOCKED by memgate: call {verb}. Reason: {g.decision.reason}"
        self.audit.append({
            "ts": round(time.time(), 3),
            "session": g.session,
            "tool": g.name,
            "decision": g.decision.kind.value,
            "executed": g.execute,
            "confirmed": g.confirmed,
            "reason": g.decision.reason,
            "taint_sources": g.decision.taint_sources,
            "violations": g.decision.violations,
            "assigned_label": g.assigned.to_dict() if g.assigned else None,
            "args_hash": hashlib.sha256(_canonical(g.args).encode()).hexdigest(),
        })
        return BoundaryResult(g.name, g.args, g.decision, g.execute, out, g.tainted, g.assigned, g.confirmed)

    def call(self, name: str, args: dict, session: str) -> BoundaryResult:
        tool = self.tools.get(name)
        g = self.gate(name, args, session, labelled=bool(tool and tool.labelled), known=tool is not None)
        output = None
        if g.execute:
            try:
                output = tool.fn(**g.kwargs)
            except TypeError as e:  # bad args from the model
                output = f"ERROR: {e}"
        return self.finish(g, output)

    async def acall(self, name: str, args: dict, session: str) -> BoundaryResult:
        """Like `call`, for registered tools that may be coroutine functions."""
        import inspect

        tool = self.tools.get(name)
        g = self.gate(name, args, session, labelled=bool(tool and tool.labelled), known=tool is not None)
        output = None
        if g.execute:
            try:
                output = tool.fn(**g.kwargs)
                if inspect.isawaitable(output):
                    output = await output
            except TypeError as e:
                output = f"ERROR: {e}"
        return self.finish(g, output)
