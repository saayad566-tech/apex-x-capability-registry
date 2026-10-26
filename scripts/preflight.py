#!/usr/bin/env python3
"""Fail-closed preflight for the APEX-X capability registry.

Runs *before* anything trusts the registry. It answers one question: is the
state on disk complete, well-formed, untampered and honest?

Exit codes
  0  clean - every check passed
  1  integrity problems - the state is readable but wrong (a false "verified"
     claim, missing evidence, a stale approval, an artifact whose checksum no
     longer matches, a dependency cycle, ...)
  2  state missing or tampered with - the registry or audit log is absent,
     unparseable, structurally invalid, or the audit hash chain is broken

Exit 2 deliberately outranks exit 1: if the audit trail cannot be trusted,
individual findings cannot be trusted either.

Usage
  python3 scripts/preflight.py --registry capability-registry.json \\
      --max-evidence-days 90
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import capability_registry as cr  # noqa: E402

EXIT_OK = 0
EXIT_PROBLEMS = 1
EXIT_STATE = 2

# Audit actions that change a capability's status, and the status they imply.
STATUS_EVENTS = {"transition", "verify", "reverify", "demote"}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse(ts: str):
    try:
        return datetime.fromisoformat(ts)
    except (TypeError, ValueError):
        return None


def _age_days(ts: str) -> float | None:
    dt = _parse(ts)
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (_now() - dt).total_seconds() / 86400.0


def _status_from_audit(rec: dict) -> str | None:
    action = rec.get("action")
    if action == "transition":
        return rec.get("to")
    if action in ("verify", "reverify"):
        return "verified" if rec.get("ok") else "failed"
    if action == "demote":
        return "failed"
    return None


def preflight(registry_path: str, *, max_evidence_days: float = 90.0,
              require_audit: bool = True) -> dict:
    findings: list[dict] = []

    def add(severity: str, message: str, capability: str | None = None) -> None:
        findings.append({"severity": severity, "capability": capability,
                         "message": message})

    # -- 1. the registry file itself ------------------------------------- #
    if not os.path.exists(registry_path):
        add("state", f"registry missing: {registry_path}")
        return _finish(findings, registry_path)

    try:
        registry = cr.load(registry_path)
    except cr.RegistryError as exc:
        add("state", f"registry unreadable or malformed: {exc}")
        return _finish(findings, registry_path)

    if not isinstance(registry.get("version"), int):
        add("state", "registry has no integer 'version' field")
    if not isinstance(registry.get("capabilities"), dict):
        add("state", "registry 'capabilities' must be a mapping")
    if not isinstance(registry.get("lessons"), list):
        add("state", "registry 'lessons' must be a list")
    if any(f["severity"] == "state" for f in findings):
        return _finish(findings, registry_path)

    # -- 2. the audit log and its hash chain ----------------------------- #
    audit_path = cr._audit_path(registry_path)
    audit_records: list[dict] = []
    if not os.path.exists(audit_path):
        if require_audit:
            add("state", f"audit log missing: {audit_path}")
        else:
            add("problem", "audit log absent (allowed by --allow-missing-audit)")
    else:
        try:
            audit_records = cr._read_audit_lines(registry_path)
            chain = cr.verify_audit(registry_path)
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
            add("state", f"audit log is not valid JSON lines: {exc}")
            chain = {"ok": False}
        if not chain.get("ok") and not any(
                f["severity"] == "state" for f in findings):
            add("state", f"audit hash chain broken at record "
                         f"{chain.get('broken_at')}: {chain.get('reason')}")
    if any(f["severity"] == "state" for f in findings):
        return _finish(findings, registry_path, audit_records)

    # -- 3. per-capability honesty checks -------------------------------- #
    base = os.path.dirname(os.path.abspath(registry_path))
    for name, entry in sorted(registry["capabilities"].items()):
        for problem in cr.validate_entry(entry):
            add("problem", problem, name)

        status = entry.get("status")

        # a verified or installed capability must be reversible
        if status in cr.PRESENT_STATUSES and not entry.get("rollback"):
            add("problem", f"{status} without a rollback procedure", name)

        # verified must mean "executed", not "declared"
        if status == "verified":
            if not entry.get("evidence"):
                add("problem", "verified without evidence", name)
            vr = entry.get("verify_result") or {}
            if not vr:
                add("problem", "verified without an executed test "
                               "(declaration only)", name)
            elif vr.get("exit_code") != 0:
                add("problem", f"verified but its recorded test exited "
                               f"{vr.get('exit_code')}", name)
            if not entry.get("sha256"):
                add("problem", "verified without an artifact checksum", name)

            age = _age_days(vr.get("at", ""))
            if age is None:
                add("problem", "verified without a usable evidence timestamp", name)
            elif age > max_evidence_days:
                add("problem", f"evidence is stale: {age:.1f} days old "
                               f"(limit {max_evidence_days:g})", name)

        # the artifact on disk must still be the one that was verified
        artifact = entry.get("artifact")
        if artifact and entry.get("sha256"):
            path = artifact if os.path.isabs(artifact) else os.path.join(base, artifact)
            if not os.path.exists(path):
                add("problem", f"artifact missing on disk: {artifact}", name)
            else:
                actual = cr.sha256_of(path)
                if actual != entry["sha256"]:
                    add("problem", f"artifact checksum mismatch for {artifact}: "
                                   f"recorded {entry['sha256'][:12]}..., "
                                   f"actual {actual[:12]}...", name)

        # an approval that no longer matches the artifact is stale
        approved_sha = entry.get("approved_sha256")
        if approved_sha and entry.get("sha256") and approved_sha != entry["sha256"]:
            add("problem", "stale approval: artifact checksum changed since "
                           "approval; re-approval required", name)

        for problem in cr.check_compatibility(entry):
            add("problem", problem, name)

        missing = cr._missing_dependencies(registry, entry)
        if missing and status in cr.PRESENT_STATUSES:
            add("problem", "unmet dependencies: " + ", ".join(missing), name)

        # the current status must be the last status the audit trail recorded
        if audit_records:
            events = [r for r in audit_records
                      if r.get("action") in STATUS_EVENTS and r.get("name") == name]
            if not events:
                add("problem", "no audited status event for this capability "
                               "(status was never recorded through the log)", name)
            else:
                implied = _status_from_audit(events[-1])
                if implied and implied != status:
                    add("problem", f"status {status!r} is not the last audited "
                                   f"transition ({implied!r}, "
                                   f"{events[-1].get('at')})", name)

    for cycle in cr.detect_cycles(registry):
        add("problem", "dependency cycle: " + " -> ".join(cycle))

    return _finish(findings, registry_path, audit_records)


def _finish(findings: list[dict], registry_path: str,
            audit_records: list[dict] | None = None) -> dict:
    state = [f for f in findings if f["severity"] == "state"]
    problems = [f for f in findings if f["severity"] == "problem"]
    if state:
        code = EXIT_STATE
    elif problems:
        code = EXIT_PROBLEMS
    else:
        code = EXIT_OK
    return {
        "ok": code == EXIT_OK,
        "exit_code": code,
        "registry": registry_path,
        "audit_records": len(audit_records or []),
        "state_findings": state,
        "problems": problems,
        "checked_at": _now().isoformat(timespec="seconds"),
    }


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Fail-closed capability registry preflight")
    p.add_argument("--registry", default="capability-registry.json")
    p.add_argument("--max-evidence-days", type=float, default=90.0)
    p.add_argument("--allow-missing-audit", action="store_true",
                   help="treat an absent audit log as a problem, not fatal state")
    p.add_argument("--quiet", action="store_true")
    args = p.parse_args(argv)

    result = preflight(args.registry,
                       max_evidence_days=args.max_evidence_days,
                       require_audit=not args.allow_missing_audit)
    if not args.quiet:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        for f in result["state_findings"] + result["problems"]:
            where = f" [{f['capability']}]" if f["capability"] else ""
            print(f"{f['severity'].upper()}{where}: {f['message']}")
    return result["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
