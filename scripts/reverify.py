#!/usr/bin/env python3
"""Scheduled re-verification: keep every "verified" claim fresh.

A capability verified once is not verified forever. This re-runs each verified
capability's recorded test command and writes a timestamped result:

  * evidence younger than --max-age-days is left alone (and reported as fresh);
  * older evidence is re-executed with the *stored argument list* (no shell);
  * exit 0  -> status stays verified, a new timestamped reverify_result is
               recorded, and the event is appended to the audit log;
  * non-zero -> the capability is demoted to "failed" through an explicit,
               audited transition with a failure_reason. A failed re-run never
               leaves a stale "verified" behind.

Recovery after a demotion is the documented lifecycle:
  failed -> assessed (recovery_note) -> approved -> installed -> verify

Usage
  python3 scripts/reverify.py --registry capability-registry.json \\
      --max-age-days 90            # only what is stale
  python3 scripts/reverify.py --all # everything verified, regardless of age
"""
from __future__ import annotations

import argparse
import json
import os
import shlex
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import capability_registry as cr  # noqa: E402


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _age_days(ts: str):
    try:
        dt = datetime.fromisoformat(ts)
    except (TypeError, ValueError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - dt).total_seconds() / 86400.0


def stored_argv(entry: dict) -> list[str] | None:
    """The reproducible command for a capability, as an argument list."""
    argv = entry.get("test_argv") or []
    if isinstance(argv, list) and argv and all(isinstance(a, str) for a in argv):
        return list(argv)
    tests = entry.get("tests") or []
    if tests and isinstance(tests[0], str) and tests[0].strip():
        return shlex.split(tests[0])
    return None


def reverify(registry_path: str, *, max_age_days: float = 90.0, force_all: bool = False,
             dry_run: bool = False, timeout: int = 300, actor: str = "apex-x") -> dict:
    report = {"checked": [], "fresh": [], "reverified": [], "demoted": [],
              "skipped": [], "dry_run": dry_run}
    with cr.locked(registry_path):
        registry = cr.load(registry_path)

        for name, entry in sorted(registry["capabilities"].items()):
            if entry.get("status") != "verified":
                continue
            report["checked"].append(name)

            vr = entry.get("verify_result") or {}
            age = _age_days(vr.get("at", ""))
            if not force_all and age is not None and age <= max_age_days:
                report["fresh"].append({"name": name, "age_days": round(age, 2)})
                continue

            argv = stored_argv(entry)
            if not argv:
                report["skipped"].append(
                    {"name": name, "reason": "no reproducible test command recorded"})
                continue

            if dry_run:
                report["reverified"].append({"name": name, "dry_run": True,
                                             "command": argv})
                continue

            result = cr.run_command(argv, cwd=None, timeout=timeout)
            record = {
                "at": _now(), "command": argv, "exit_code": result["exit_code"],
                "timeout": result["timeout"], "stdout": result["stdout"][:1000],
                "stderr": result["stderr"][:1000], "env": cr.current_env(),
                "artifact_sha256": entry.get("sha256") or None,
                "previous_verified_at": vr.get("at"),
            }
            entry["reverify_result"] = record
            entry.setdefault("reverify_history", []).append(record)

            if result["exit_code"] == 0:
                entry["evidence"] = cr.redact(
                    f"re-verified {argv} -> exit 0 at {record['at']}")
                entry.setdefault("history", []).append(
                    {"status": "verified", "at": record["at"], "note": "reverified"})
                cr.audit(registry_path, actor, "reverify", name=name, ok=True,
                         exit_code=0)
                report["reverified"].append({"name": name, "exit_code": 0,
                                             "command": argv})
            else:
                reason = (f"scheduled re-verification failed: {argv} exited "
                          f"{result['exit_code']} at {record['at']}")
                cr.transition(registry, name, "failed", failure_reason=reason,
                              actor=actor)
                cr.audit(registry_path, actor, "reverify", name=name, ok=False,
                         exit_code=result["exit_code"])
                report["demoted"].append({"name": name,
                                          "exit_code": result["exit_code"],
                                          "command": argv, "reason": reason})

        if not dry_run:
            cr.save(registry_path, registry)

    report["ok"] = not report["demoted"] and not report["skipped"]
    return report


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Re-verify capabilities and demote stale ones")
    p.add_argument("--registry", default="capability-registry.json")
    p.add_argument("--max-age-days", type=float, default=90.0)
    p.add_argument("--all", action="store_true", dest="force_all",
                   help="re-run every verified capability regardless of age")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--timeout", type=int, default=300)
    p.add_argument("--actor", default="apex-x")
    args = p.parse_args(argv)

    report = reverify(args.registry, max_age_days=args.max_age_days,
                      force_all=args.force_all, dry_run=args.dry_run,
                      timeout=args.timeout, actor=args.actor)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
