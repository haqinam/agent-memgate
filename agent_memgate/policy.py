"""Flow policy: which labelled sources may reach which sink arguments."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

import yaml

from .taint import Tainted, Trust


class Kind(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_CONFIRM = "require_confirm"


@dataclass(frozen=True)
class Decision:
    kind: Kind
    reason: str = ""
    # arg name -> sorted list of offending sources
    violations: dict[str, list[str]] = field(default_factory=dict)
    # all sources seen on any checked arg (for the audit log)
    taint_sources: list[str] = field(default_factory=list)
    quarantine: bool = False

    @property
    def allowed(self) -> bool:
        return self.kind == Kind.ALLOW


# Convenience constructors matching the spec's vocabulary.
def Allow(reason: str = "", **kw) -> Decision:
    return Decision(Kind.ALLOW, reason, **kw)


def Deny(reason: str, **kw) -> Decision:
    return Decision(Kind.DENY, reason, **kw)


def RequireConfirm(reason: str, **kw) -> Decision:
    return Decision(Kind.REQUIRE_CONFIRM, reason, **kw)


_TRUST_NAMES = {"untrusted": Trust.UNTRUSTED, "user": Trust.USER, "system": Trust.SYSTEM}


@dataclass
class SinkRule:
    args: list[str]
    deny_if_tainted_by: list[str] = field(default_factory=list)
    on_violation: Kind = Kind.REQUIRE_CONFIRM
    quarantine_if_tainted_by: list[str] = field(default_factory=list)


@dataclass
class FlowPolicy:
    sinks: dict[str, SinkRule] = field(default_factory=dict)
    # tool name -> Trust of its output, or None meaning "do not record output"
    sources: dict[str, Trust | None] = field(default_factory=dict)
    default_source_trust: Trust | None = Trust.UNTRUSTED

    # ------------------------------------------------------------ loading
    @classmethod
    def from_dict(cls, d: dict) -> "FlowPolicy":
        sinks = {}
        for name, r in (d.get("sinks") or {}).items():
            sinks[name] = SinkRule(
                args=list(r.get("args", [])),
                deny_if_tainted_by=list(r.get("deny_if_tainted_by", [])),
                on_violation=Kind(r.get("on_violation", "require_confirm")),
                quarantine_if_tainted_by=list(r.get("quarantine_if_tainted_by", [])),
            )
        sources: dict[str, Trust | None] = {}
        default = Trust.UNTRUSTED
        for name, t in (d.get("sources") or {}).items():
            val = None if t in (None, "none") else _TRUST_NAMES[t]
            if name == "default":
                default = val
            else:
                sources[name] = val
        return cls(sinks=sinks, sources=sources, default_source_trust=default)

    @classmethod
    def load(cls, path: str | Path) -> "FlowPolicy":
        return cls.from_dict(yaml.safe_load(Path(path).read_text()) or {})

    @classmethod
    def permissive(cls, sources: dict[str, Trust | None] | None = None) -> "FlowPolicy":
        """No sink rules: everything is allowed. Used for the defense-off baseline."""
        return cls(sinks={}, sources=dict(sources or {}))

    def source_trust(self, tool_name: str) -> Trust | None:
        return self.sources.get(tool_name, self.default_source_trust)

    # --------------------------------------------------------- evaluation
    def evaluate(self, tool_name: str, args: dict[str, Tainted]) -> Decision:
        rule = self.sinks.get(tool_name)
        all_sources = sorted({s for t in args.values() for s in t.sources})
        if rule is None:
            return Allow("no rule for tool", taint_sources=all_sources)

        violations: dict[str, list[str]] = {}
        quarantine_hits: set[str] = set()
        for a in rule.args:
            t = args.get(a)
            if t is None or not t.value:
                continue
            bad = sorted(t.sources & set(rule.deny_if_tainted_by))
            if bad:
                violations[a] = bad
            quarantine_hits |= t.sources & set(rule.quarantine_if_tainted_by)

        if violations:
            detail = "; ".join(f"arg '{a}' tainted by {', '.join(s)}" for a, s in violations.items())
            reason = f"{tool_name}: {detail}"
            ctor = Deny if rule.on_violation == Kind.DENY else RequireConfirm
            return ctor(reason, violations=violations, taint_sources=all_sources)

        if quarantine_hits:
            return Allow(
                f"{tool_name}: allowed but quarantined (derived from {', '.join(sorted(quarantine_hits))})",
                taint_sources=all_sources,
                quarantine=True,
            )
        return Allow("no tainted flow into sink args", taint_sources=all_sources)
