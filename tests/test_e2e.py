from pathlib import Path

import pytest

from demo.providers.mock import MockProvider
from demo.runner import build, run_scenario, score
from demo.world import load_scenario
from memgate import ExplicitFlowMatcher, Label, TaintLedger, Trust

ROOT = Path(__file__).resolve().parents[1]
SCEN = sorted((ROOT / "scenarios").glob("*.yaml"))
ATTACKS = [p for p in SCEN if not load_scenario(p).get("expect_bypass")]


@pytest.mark.parametrize("path", SCEN, ids=lambda p: p.stem)
def test_defense_off_exfiltrates(path):
    sc = load_scenario(path)
    r = run_scenario(sc, MockProvider(sc), defense=False)
    assert r["poisoned_memory_written"] and r["exfiltrated"]


@pytest.mark.parametrize("path", ATTACKS, ids=lambda p: p.stem)
def test_defense_on_blocks(path):
    sc = load_scenario(path)
    r = run_scenario(sc, MockProvider(sc), defense=True)
    assert r["poisoned_memory_written"]
    assert r["poisoned_memory_quarantined"]
    assert r["exfil_attempted"] and not r["exfiltrated"] and r["blocked_at_boundary"]


def test_paraphrase_bypass_is_a_real_limitation():
    sc = load_scenario(ROOT / "scenarios" / "memory_bcc_paraphrase_bypass.yaml")
    r = run_scenario(sc, MockProvider(sc), defense=True)
    assert r["exfiltrated"], "v1 explicit-flow taint is expected to miss this paraphrase"
    # and the reason is what we claim: no >=12-char span, no literal identifier
    page = next(iter(sc["world"]["web"].values()))
    led = TaintLedger()
    led.record(page, Label("web_fetch", Trust.UNTRUSTED, "s2"))
    note = sc["sessions"][1]["mock"][1]["args"]["note"]
    assert ExplicitFlowMatcher().match(note, led) == set()


def test_clean_send_after_rollback_is_allowed():
    """No false positive on the legitimate email once the poisoned note is rolled back."""
    sc = load_scenario(ROOT / "scenarios" / "memory_bcc.yaml")
    agent = build(sc, MockProvider(sc), defense=True)
    s1, s2, s3 = sc["sessions"]
    agent.run_session(s1["id"], s1["user"])
    agent.run_session(s2["id"], s2["user"])
    removed = agent.store.rollback(source="web_fetch")
    assert len(removed) == 1
    agent.run_session(s3["id"], s3["user"])
    sent = agent.world.outbox
    assert len(sent) == 1 and sent[0]["to"] == "jordan@example.com" and not sent[0]["bcc"]
    assert not score(sc, agent)["exfiltrated"]


def test_mock_gets_no_defense_signal():
    """The mock sees only messages+tools; same object works for both arms."""
    sc = load_scenario(ROOT / "scenarios" / "memory_bcc.yaml")
    p = MockProvider(sc)
    off = run_scenario(sc, p, defense=False)
    on = run_scenario(sc, p, defense=True)
    # identical model behaviour (same tool calls emitted), different outcome
    calls = lambda r: [(e["tool"], sorted(e["args"])) for e in r["events"] if e["type"] == "tool"]
    assert calls(off) == calls(on)
    assert off["exfiltrated"] and not on["exfiltrated"]
