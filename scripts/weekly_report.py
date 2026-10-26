#!/usr/bin/env python3
"""Compose the weekly capability report from live evidence.

Runs, in order, and writes a markdown report:
  1. preflight        - is the state complete, untampered and honest?
  2. registry check   - obsolete / incompatible / missing rollback / stale
  3. reverify         - re-run stale evidence and demote failures (or dry-run)
  4. deps inventory   - dependency, licence and advisory coverage, with limits

Nothing here is asserted from memory: every line of the report comes from a
command that actually ran in this process.

Usage
  python3 scripts/weekly_report.py --out weekly-report.md
  python3 scripts/weekly_report.py --out weekly-report.md --reverify
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def run(script: str, *args: str) -> dict:
    cmd = [sys.executable, os.path.join(HERE, script), *args]
    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    try:
        parsed = json.loads(proc.stdout)
    except json.JSONDecodeError:
        parsed = None
    return {"cmd": " ".join(cmd), "exit_code": proc.returncode,
            "stdout": proc.stdout, "stderr": proc.stderr, "json": parsed}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Weekly capability report")
    p.add_argument("--registry", default="capability-registry.json")
    p.add_argument("--max-evidence-days", type=float, default=90.0)
    p.add_argument("--out", default="weekly-report.md")
    p.add_argument("--reverify", action="store_true",
                   help="actually re-run stale evidence (default: dry run)")
    args = p.parse_args(argv)

    reg = ["--registry", args.registry]
    pre = run("preflight.py", *reg, "--max-evidence-days", str(args.max_evidence_days))
    chk = run("capability_registry.py", *reg, "check",
              "--max-age-days", str(int(args.max_evidence_days)))
    aud = run("capability_registry.py", *reg, "verify-audit")
    rev = run("reverify.py", *reg, "--max-age-days", str(args.max_evidence_days),
              *([] if args.reverify else ["--dry-run"]))
    inv = run("deps_inventory.py", "--json")

    registry = {}
    try:
        with open(os.path.join(ROOT, args.registry), "r", encoding="utf-8") as fh:
            registry = json.load(fh)
    except (OSError, json.JSONDecodeError):
        registry = {}

    caps = registry.get("capabilities", {})
    by_status: dict[str, list[str]] = {}
    for name, entry in caps.items():
        by_status.setdefault(entry.get("status", "?"), []).append(name)

    L = []
    L.append("# APEX-X weekly capability report")
    L.append("")
    L.append(f"Generated {datetime.now(timezone.utc).isoformat(timespec='seconds')} "
             f"from live execution in `{ROOT}`.")
    L.append("")
    L.append("| gate | exit | meaning |")
    L.append("|---|---|---|")
    L.append(f"| preflight | {pre['exit_code']} | "
             f"{'clean' if pre['exit_code'] == 0 else ('state missing/tampered' if pre['exit_code'] == 2 else 'integrity problems')} |")
    L.append(f"| registry check | {chk['exit_code']} | "
             f"{'clean' if chk['exit_code'] == 0 else 'problems reported'} |")
    L.append(f"| audit chain | {aud['exit_code']} | "
             f"{'intact' if aud['exit_code'] == 0 else 'BROKEN'} |")
    L.append(f"| re-verification | {rev['exit_code']} | "
             f"{'all fresh' if rev['exit_code'] == 0 else 'demotions or skips'} "
             f"({'live' if args.reverify else 'dry run'}) |")
    L.append("")
    L.append("## Registry state")
    L.append("")
    if not caps:
        L.append("The registry contains **no capabilities**.")
    for status in sorted(by_status):
        L.append(f"- **{status}** ({len(by_status[status])}): "
                 + ", ".join(f"`{n}`" for n in sorted(by_status[status])))
    L.append("")
    L.append(f"Lessons recorded: {len(registry.get('lessons', []))}")
    L.append("")

    L.append("## Findings")
    L.append("")
    findings = []
    if isinstance(pre.get("json"), dict):
        findings += [f"**state**: {f['message']}" for f in pre["json"].get("state_findings", [])]
        findings += [f"**problem**: {f['message']}"
                     + (f" (`{f['capability']}`)" if f.get("capability") else "")
                     for f in pre["json"].get("problems", [])]
    if isinstance(chk.get("json"), dict):
        for name, problems in (chk["json"].get("problems") or {}).items():
            findings += [f"**{name}**: {p}" for p in problems]
    if isinstance(rev.get("json"), dict):
        for d in rev["json"].get("demoted", []):
            findings.append(f"**{d['name']}**: demoted - {d['reason']}")
        for s in rev["json"].get("skipped", []):
            findings.append(f"**{s['name']}**: skipped - {s['reason']}")
    if findings:
        L += [f"- {f}" for f in findings]
    else:
        L.append("No findings: the registry is complete, consistent and every "
                 "verified claim has unexpired execution evidence.")
    L.append("")

    L.append("## Dependency and licence coverage")
    L.append("")
    if isinstance(inv.get("json"), dict):
        i = inv["json"]
        L.append(f"- Manifests: {len(i['manifests'])}")
        L.append(f"- Declared direct dependencies: {len(i['direct_dependencies'])}")
        L.append(f"- Installed distributions: {i['installed_distributions']}")
        L.append(f"- Vulnerability coverage: **{i['vulnerability_coverage']}**")
        for f in i.get("advisory_feeds", []):
            L.append(f"- Feed {f['feed']}: "
                     f"{'reachable' if f['reachable'] else 'UNREACHABLE'} ({f['detail']})")
        L.append("")
        L.append("Coverage limitations:")
        L += [f"- {x}" for x in i["limitations"]]
    else:
        L.append("Dependency inventory did not produce JSON; see command output.")
    L.append("")

    L.append("## Commands run")
    L.append("")
    L.append("```")
    for r in (pre, chk, aud, rev, inv):
        L.append(f"$ {r['cmd']}   # exit {r['exit_code']}")
    L.append("```")
    L.append("")

    text = "\n".join(L)
    out_path = os.path.join(ROOT, args.out)
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(text)
    print(f"wrote {out_path}")

    blocking = pre["exit_code"] != 0 or chk["exit_code"] != 0 or aud["exit_code"] != 0
    return 2 if blocking else 0


if __name__ == "__main__":
    raise SystemExit(main())
