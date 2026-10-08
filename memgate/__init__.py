"""memgate: provenance-labelled agent memory + flow policy at the tool boundary."""

from .boundary import AuditLog, BoundaryResult, Gate, ToolBoundary, deny_all_confirm, verify_log_lines
from .memory import TRUSTED_MEMORY, UNTRUSTED_MEMORY, MemoryEntry, ProvenanceMemoryStore
from .policy import Allow, Decision, Deny, FlowPolicy, Kind, RequireConfirm, SinkRule
from .taint import (
    ExplicitFlowMatcher,
    Label,
    Matcher,
    TaintLedger,
    Tainted,
    Trust,
    extract_identifiers,
    join,
    taint_of,
)

__all__ = [
    "Allow", "AuditLog", "BoundaryResult", "Decision", "Deny", "ExplicitFlowMatcher",
    "FlowPolicy", "Gate", "Kind", "Label", "Matcher", "MemoryEntry", "ProvenanceMemoryStore",
    "RequireConfirm", "SinkRule", "TaintLedger", "Tainted", "ToolBoundary", "Trust",
    "TRUSTED_MEMORY", "UNTRUSTED_MEMORY", "deny_all_confirm", "extract_identifiers",
    "join", "taint_of", "verify_log_lines",
]
__version__ = "0.1.0"
