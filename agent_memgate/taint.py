"""Taint labels, tainted values, and explicit-flow matching.

v1 propagation rule (explicit flows only):

  A string is tainted by source S if
    (a) it contains a span of >= `min_len` characters (after whitespace
        collapsing and case folding) that appeared in an output from S, or
    (b) it contains an identifier (email address, URL, token-like string)
        whose *first* appearance in the ledger was in an output from S.

Paraphrase defeats (a); re-encoding an identifier defeats (b). Both are
documented limitations. `Matcher` is a protocol so a semantic matcher can be
dropped in without touching the policy or boundary.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Iterable, Protocol


class Trust(IntEnum):
    UNTRUSTED = 0
    USER = 1
    SYSTEM = 2


@dataclass(frozen=True)
class Label:
    source: str
    trust: Trust
    session_id: str
    entry_id: str | None = None

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "trust": self.trust.name,
            "session_id": self.session_id,
            "entry_id": self.entry_id,
        }


def join(*label_sets: Iterable[Label]) -> frozenset[Label]:
    """Least upper bound of taint: the union of all labels."""
    out: set[Label] = set()
    for ls in label_sets:
        out.update(ls)
    return frozenset(out)


@dataclass(frozen=True)
class Tainted:
    value: str
    labels: frozenset[Label] = field(default_factory=frozenset)

    @property
    def sources(self) -> frozenset[str]:
        return frozenset(l.source for l in self.labels)

    @property
    def trust(self) -> Trust:
        """Lowest trust among labels; an unlabelled value is USER-trust."""
        return min((l.trust for l in self.labels), default=Trust.USER)

    def derive(self, value: str, *others: "Tainted") -> "Tainted":
        return Tainted(value, join(self.labels, *(o.labels for o in others)))

    def __str__(self) -> str:  # pragma: no cover - convenience
        return self.value


# ---------------------------------------------------------------- identifiers

_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_URL = re.compile(r"https?://[^\s<>\"'()\[\]]+")
_TOKEN = re.compile(
    r"(?<![A-Za-z0-9_\-])(?=[A-Za-z0-9_\-]*\d)(?=[A-Za-z0-9_\-]*[A-Za-z])"
    r"[A-Za-z0-9_\-]{20,}(?![A-Za-z0-9_\-])"
)


def extract_identifiers(text: str) -> set[str]:
    """Emails, URLs and token-like strings, normalised to lower case."""
    ids: set[str] = set()
    for m in _EMAIL.finditer(text):
        ids.add(m.group(0).lower().rstrip("."))
    for m in _URL.finditer(text):
        ids.add(m.group(0).lower().rstrip(".,;:"))
    for m in _TOKEN.finditer(text):
        ids.add(m.group(0).lower())
    return ids


def mask_identifiers(text: str) -> str:
    for rx in (_URL, _EMAIL, _TOKEN):
        text = rx.sub("\x00", text)
    return text


def normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text).casefold()


# --------------------------------------------------------------------- ledger


@dataclass
class _Record:
    text: str  # normalised
    label: Label
    _grams: dict[int, set[str]] = field(default_factory=dict)

    def grams(self, n: int) -> set[str]:
        if n not in self._grams:
            t = self.text
            self._grams[n] = {t[i : i + n] for i in range(max(0, len(t) - n + 1))}
        return self._grams[n]


class TaintLedger:
    """Append-only record of every labelled text the agent has observed.

    The ledger persists across sessions (that is the point: session 3's
    clean-looking argument must still be traced back to session 2's web page).
    """

    def __init__(self) -> None:
        self.records: list[_Record] = []
        self.first_seen: dict[str, Label] = {}

    def record(self, text: str, label: Label) -> None:
        self.records.append(_Record(normalize(text), label))
        for ident in extract_identifiers(text):
            self.first_seen.setdefault(ident, label)

    def to_list(self) -> list[dict]:
        return [{"label": r.label.to_dict(), "text": r.text} for r in self.records]


# -------------------------------------------------------------------- matcher


class Matcher(Protocol):
    def match(self, value: str, ledger: TaintLedger) -> set[Label]: ...


class ExplicitFlowMatcher:
    """Substring (>= min_len) + first-seen-identifier matcher. See module doc."""

    def __init__(self, min_len: int = 12) -> None:
        self.min_len = min_len

    def substring_labels(self, value: str, ledger: TaintLedger) -> set[Label]:
        # Identifiers are attributed only by the first-seen rule. Masking them
        # here stops shared fragments (e.g. "@example.com") from tainting a
        # user-supplied address just because another address shares a domain.
        v = normalize(mask_identifiers(value))
        n = self.min_len
        vgrams = {v[i : i + n] for i in range(len(v) - n + 1)}
        vgrams = {g for g in vgrams if "\x00" not in g}
        if not vgrams:
            return set()
        return {r.label for r in ledger.records if not vgrams.isdisjoint(r.grams(n))}

    def identifier_labels(self, value: str, ledger: TaintLedger) -> set[Label]:
        out: set[Label] = set()
        for ident in extract_identifiers(value):
            lab = ledger.first_seen.get(ident)
            if lab is not None:
                out.add(lab)
        return out

    def match(self, value: str, ledger: TaintLedger) -> set[Label]:
        return self.substring_labels(value, ledger) | self.identifier_labels(value, ledger)


def taint_of(value: object, ledger: TaintLedger, matcher: Matcher) -> Tainted:
    s = value if isinstance(value, str) else ("" if value is None else str(value))
    return Tainted(s, frozenset(matcher.match(s, ledger)))
