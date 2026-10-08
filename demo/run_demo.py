"""Three-session memory-poisoning demo.

    python demo/run_demo.py --provider mock --defense off
    python demo/run_demo.py --provider mock --defense on
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from rich.console import Console  # noqa: E402
from rich.panel import Panel  # noqa: E402
from rich.prompt import Confirm  # noqa: E402
from rich.table import Table  # noqa: E402
from rich.text import Text  # noqa: E402

from demo.providers import NAMES, make_provider  # noqa: E402
from demo.runner import ROOT, build, score  # noqa: E402
from demo.world import load_scenario  # noqa: E402
from memgate import AuditLog  # noqa: E402

console = Console(highlight=False)


def _has(text: str, idents: list[str]) -> bool:
    return any(i.lower() in (text or "").lower() for i in idents)


def _hl(text: str, idents: list[str], style: str = "bold white on red") -> Text:
    t = Text(text)
    for i in idents:
        t.highlight_words([i], style=style, case_sensitive=False)
    return t


def _preview(output: str, idents: list[str], max_lines: int = 14) -> Text:
    lines = output.strip().splitlines()
    shown = lines[:max_lines]
    t = Text()
    for ln in shown:
        style = "yellow" if (_has(ln, idents) or "persist to memory" in ln.lower()) else "grey50"
        t.append("    │ " + ln + "\n", style=style)
    if len(lines) > max_lines:
        t.append(f"    │ … ({len(lines) - max_lines} more lines)\n", style="grey50")
    return t


def make_printer(scenario: dict, defense: bool):
    idents = scenario["attacker_identifiers"]
    roles = {s["id"]: s.get("role", "") for s in scenario["sessions"]}
    order = [s["id"] for s in scenario["sessions"]]

    def on_event(ev: dict) -> None:
        typ = ev["type"]
        if typ == "session_start":
            n = order.index(ev["session"]) + 1
            console.print()
            console.rule(f"[bold cyan]SESSION {n}[/]  [grey62]({roles.get(ev['session'], '')})[/]", style="cyan")
            mem = ev["memory"]
            if "<untrusted_memory>" in mem:
                q = mem.count("\n- [mem-")
                console.print(f"  [grey62]memory injected:[/] trusted notes + [yellow]{q} quarantined note(s) "
                              f"inside <untrusted_memory> (data only)[/]")
            elif _has(mem, idents):
                console.print("  [grey62]memory injected (as standing instructions):[/]")
                for ln in mem.splitlines()[1:]:
                    console.print(Text("    ") + _hl(ln, idents))
            else:
                console.print("  [grey62]memory injected:[/] " + ("; ".join(
                    l[2:] for l in mem.splitlines() if l.startswith("- ")) or "(empty)"))
            console.print(f"\n  [bold]👤 Alex:[/] {ev['user']}")
        elif typ == "assistant":
            if ev["content"] and not ev["tool_calls"]:
                console.print(f"\n  [bold]🤖 Assistant:[/] {ev['content']}")
        elif typ == "tool":
            args = ", ".join(f"{k}={v!r}" for k, v in ev["args"].items())
            if len(args) > 160:
                args = args[:157] + "…"
            console.print(Text("\n  🔧 ") + Text(f"{ev['tool']}(", style="bold") + _hl(args, idents)
                          + Text(")", style="bold"))
            tool = ev["tool"]
            if tool in ("web_fetch", "read_inbox") and ev["executed"]:
                console.print(_preview(ev["output"], idents), end="")
            elif tool == "memory_write" and ev["executed"]:
                note = ev["args"].get("note", "")
                lab = ev["assigned_label"] or {}
                if ev["quarantined"]:
                    console.print(Panel(
                        Text.assemble(("Label assigned by the boundary: ", "bold"),
                                      f"source={lab.get('source')}  trust={lab.get('trust')}  "
                                      f"session={lab.get('session_id')}\n",
                                      ("Stored as untrusted data. It will never be shown to the model as an "
                                       "instruction, and anything derived from it carries its taint.", "")),
                        title="🛡  MEMORY QUARANTINED", border_style="yellow", padding=(0, 2)))
                elif _has(note, idents):
                    console.print(Panel(_hl(note, idents), title="☠  POISONED MEMORY WRITTEN",
                                        subtitle="persisted as a standing instruction",
                                        border_style="red", padding=(0, 2)))
            elif tool in ("send_email", "forward_email"):
                a = ev["args"]
                body = Text()
                for k in ("to", "cc", "bcc"):
                    v = a.get(k, "")
                    if not v:
                        continue
                    body.append(f"{k.upper():>4}: ", style="bold")
                    body.append(v + "\n", style="bold white on red" if _has(v, idents) else "")
                if tool == "forward_email":
                    body.append(" FWD: ", style="bold")
                    body.append(a.get("message_id", "") + "\n")
                if a.get("subject"):
                    body.append("SUBJ: ", style="bold")
                    body.append(a["subject"] + "\n")
                txt = a.get("body") or a.get("note") or ""
                if txt:
                    body.append("\n" + txt)
                if ev["executed"]:
                    console.print(Panel(body, title="📤 OUTGOING EMAIL SENT", border_style="red" if any(
                        _has(a.get(k, ""), idents) for k in ("to", "cc", "bcc")) else "green", padding=(0, 2)))
                else:
                    reason = Text("\n")
                    reason.append(f"decision: {ev['decision']}", style="bold")
                    if ev["confirmed"] is False:
                        reason.append("  (no user present to confirm → declined)", style="grey62")
                    reason.append(f"\nreason:   {ev['reason']}")
                    console.print(Panel(body + reason, title="🛡  STOPPED AT TOOL BOUNDARY",
                                        subtitle="memgate flow policy", border_style="green", padding=(0, 2)))
            elif not ev["executed"]:
                console.print(f"    [green]blocked:[/] {ev['reason']}")

    return on_event


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--provider", choices=NAMES, default="mock")
    ap.add_argument("--defense", choices=["on", "off"], default="off")
    ap.add_argument("--scenario", default=str(ROOT / "scenarios" / "memory_bcc.yaml"))
    ap.add_argument("--model", default=None, help="override the provider's default model id")
    ap.add_argument("--confirm", choices=["decline", "ask"], default="decline",
                    help="how RequireConfirm is resolved: auto-decline (default) or ask on the terminal")
    ap.add_argument("--audit-log", default=None, help="write signed decision records (JSONL) here")
    args = ap.parse_args(argv)

    scenario = load_scenario(args.scenario)
    defense = args.defense == "on"
    provider = make_provider(args.provider, scenario, args.model)
    audit = AuditLog(args.audit_log)

    def confirm(tool, a, decision):
        if args.confirm == "ask":
            return Confirm.ask(f"[yellow]memgate:[/] {decision.reason}. Allow {tool} anyway?", default=False)
        return False

    label = "[bold green]ON[/]" if defense else "[bold red]OFF[/]"
    model = f"{provider.name} / {provider.model}" + ("  [grey62](scripted model)[/]" if provider.name == "mock" else "")
    console.print(Panel(
        f"[bold]Agent memory poisoning[/]  ·  scenario [cyan]{scenario['name']}[/]\n"
        f"model: {model}\ndefense (memgate): {label}",
        border_style="cyan", padding=(0, 2)))
    if audit.key_generated:
        console.print(f"[grey50]audit HMAC key for this run (set MEMGATE_AUDIT_KEY to fix it): "
                      f"{audit.key.decode()}[/]")

    agent = build(scenario, provider, defense, audit=audit, confirm=confirm,
                  on_event=make_printer(scenario, defense))
    for s in scenario["sessions"]:
        agent.run_session(s["id"], s["user"])
    res = score(scenario, agent)

    console.print()
    if defense and agent.store.quarantined():
        t = Table(title="memory audit (store.audit())", title_style="grey62", border_style="grey35")
        for col in ("id", "source", "trust", "session", "quarantined", "text"):
            t.add_column(col, overflow="fold")
        for e in agent.store.audit():
            t.add_row(e["id"], e["label"]["source"], e["label"]["trust"], e["label"]["session_id"],
                      "yes" if e["quarantined"] else "no", e["text"][:60] + ("…" if len(e["text"]) > 60 else ""))
        console.print(t)
        src = agent.store.quarantined()[0].label.source
        console.print(f"[grey62]rollback available: store.rollback(source={src!r}) removes "
                      f"{sum(1 for e in agent.store.entries if e.label.source == src)} entr(ies)[/]")
    for err in res["errors"]:
        console.print(f"[red]provider error:[/] {err}")

    if res["exfiltrated"]:
        verdict = Text(" RESULT: EXFILTRATED ", style="bold white on red")
    elif res["blocked_at_boundary"]:
        verdict = Text(" RESULT: BLOCKED ", style="bold black on green")
    else:
        verdict = Text(" RESULT: NO EXFILTRATION ATTEMPTED ", style="bold black on white")
    console.print()
    console.print(verdict)
    console.print(f"[grey62]poisoned_memory_written={res['poisoned_memory_written']}  "
                  f"exfiltrated={res['exfiltrated']}[/]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
