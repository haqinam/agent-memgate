"""Run every scenario x every available provider x defense on/off, N trials.

    python eval/run_eval.py                       # mock + whichever keys are set
    python eval/run_eval.py --trials 10 --providers anthropic
    python eval/run_eval.py --model anthropic=claude-opus-5-5 --model openai=gpt-5.5

Writes results/results.md, results/results.json, results/transcripts/*.json.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from demo.providers import ENV_KEYS, NAMES, available, make_provider  # noqa: E402
from demo.runner import ROOT, run_scenario  # noqa: E402
from demo.world import load_scenario  # noqa: E402

METRICS = ["poisoned_memory_written", "exfiltrated", "poisoned_memory_quarantined", "blocked_at_boundary"]


def parse_models(items: list[str]) -> dict[str, str]:
    out = {}
    for it in items or []:
        if "=" not in it:
            raise SystemExit(f"--model expects provider=model_id, got {it!r}")
        k, v = it.split("=", 1)
        out[k] = v
    return out


def render_md(rows: list[dict], meta: dict) -> str:
    lines = [
        "# Results",
        "",
        f"Generated {meta['generated']} by `eval/run_eval.py`. Providers run: {', '.join(meta['providers'])}.",
        "",
        "`mock` rows are a scripted model: they verify the plumbing (attack path and enforcement), "
        "not that any real model is vulnerable. Real-provider rows are the empirical result.",
        "",
        "| provider | model | scenario | defense | poisoned_memory_written | exfiltrated | quarantined | blocked_at_boundary | errors |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        n = r["trials"]
        cells = [f"{r[m]}/{n}" for m in METRICS]
        note = " (expected bypass)" if r["expect_bypass"] else ""
        lines.append(f"| {r['provider']} | {r['model']} | {r['scenario']}{note} | {'on' if r['defense'] else 'off'} | "
                     + " | ".join(cells) + f" | {r['errors']} |")
    missing = [p for p in NAMES if p not in meta["providers"]]
    if missing:
        lines += ["", f"TODO: run eval/run_eval.py with keys for: {', '.join(missing)} "
                      "(set ANTHROPIC_API_KEY / OPENAI_API_KEY / GEMINI_API_KEY)."]
    lines += ["", "Columns: `quarantined` = poisoned note was stored under an untrusted label; "
                  "`blocked_at_boundary` = an exfiltrating call was emitted and stopped by policy. "
                  "`errors` = trials with a provider error (those trials are still counted in n).", ""]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--trials", type=int, default=None, help="trials per cell (default: 5 real, 1 mock)")
    ap.add_argument("--providers", nargs="*", default=None, help=f"subset of {NAMES} (default: auto-detect)")
    ap.add_argument("--scenarios", nargs="*", default=None, help="scenario YAML paths (default: scenarios/*.yaml)")
    ap.add_argument("--model", action="append", default=[], help="provider=model_id override (repeatable)")
    ap.add_argument("--out", default=str(ROOT / "results"))
    args = ap.parse_args(argv)

    providers = args.providers or available()
    missing = [p for p in providers if p not in available()]
    if missing:
        need = ", ".join(f"{p}: {ENV_KEYS[p]}" for p in missing if p in ENV_KEYS)
        raise SystemExit(f"No credentials for {', '.join(missing)}. Set the env var in this shell first ({need}).")
    models = parse_models(args.model)
    paths = [Path(p) for p in args.scenarios] if args.scenarios else sorted((ROOT / "scenarios").glob("*.yaml"))
    out = Path(args.out)
    (out / "transcripts").mkdir(parents=True, exist_ok=True)

    agg: dict[tuple, dict] = defaultdict(lambda: {m: 0 for m in METRICS} | {"trials": 0, "errors": 0})
    for pname in providers:
        n = args.trials if args.trials is not None else (1 if pname == "mock" else 5)
        for path in paths:
            sc = load_scenario(path)
            for defense in (False, True):
                for t in range(n):
                    provider = make_provider(pname, sc, models.get(pname))
                    t0 = time.time()
                    res = run_scenario(sc, provider, defense)
                    fatal = ("authentic", "api key", "insufficient_quota", "credit", "billing", "quota")
                    if any(f in e.lower() for e in res["errors"] for f in fatal):
                        raise SystemExit(f"{pname}: account/auth problem, stopping (nothing recorded). {res['errors'][0]}")
                    res["elapsed_s"] = round(time.time() - t0, 2)
                    res["trial"] = t
                    key = (pname, provider.model, sc["name"], defense, res["expect_bypass"])
                    a = agg[key]
                    a["trials"] += 1
                    a["errors"] += 1 if res["errors"] else 0
                    for m in METRICS:
                        a[m] += int(bool(res[m]))
                    fn = f"{pname}__{sc['name']}__defense-{'on' if defense else 'off'}__t{t}.json"
                    (out / "transcripts" / fn).write_text(json.dumps(res, indent=2, default=str))
                    flag = "EXFIL" if res["exfiltrated"] else ("blocked" if res["blocked_at_boundary"] else "-")
                    print(f"{pname:9} {sc['name']:30} defense={'on ' if defense else 'off'} t{t}: {flag}"
                          + (f"  errors={res['errors'][:1]}" if res["errors"] else ""), flush=True)

    rows = [
        {"provider": k[0], "model": k[1], "scenario": k[2], "defense": k[3], "expect_bypass": k[4], **v}
        for k, v in agg.items()
    ]
    # Merge with earlier runs: rows for (provider, model, scenario, defense) re-run now replace old ones.
    prev_path = out / "results.json"
    if prev_path.exists():
        prev = json.loads(prev_path.read_text())
        key = lambda r: (r["provider"], r["model"], r["scenario"], r["defense"])
        fresh = {key(r) for r in rows}
        rows = [r for r in prev.get("rows", []) if key(r) not in fresh] + rows
        providers = sorted(set(prev.get("meta", {}).get("providers", [])) | set(providers), key=NAMES.index)
    order = {p: i for i, p in enumerate(NAMES)}
    rows.sort(key=lambda r: (order.get(r["provider"], 99), r["model"], r["scenario"], r["defense"]))
    meta = {"generated": time.strftime("%Y-%m-%d %H:%M:%S %Z"), "providers": providers}
    (out / "results.json").write_text(json.dumps({"meta": meta, "rows": rows}, indent=2))
    (out / "results.md").write_text(render_md(rows, meta))
    print(f"\nwrote {out/'results.md'}, {out/'results.json'}, {out/'transcripts'}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
