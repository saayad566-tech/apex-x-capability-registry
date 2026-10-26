#!/usr/bin/env python3
"""Capability registry for APEX-X self-evolution.  (v3 — security-hardened)

Adds, on top of v2:
  * file-locked updates (no lost updates under concurrency)
  * a hash-chained, tamper-evident audit log (+ `verify-audit`)
  * approval binding: approval is tied to the plan hash and the artifact
    checksum, so changing the artifact/version/plan invalidates it (fail closed)
  * self-approval guard (an agent may not approve its own protected operation)
  * real verification execution: `verify` runs the test as an argument list with
    a timeout, captures exit code + output, and only then records evidence
  * secret redaction on stored evidence/log output
  * `migrate` (v1/v2 -> v3, with backup) and `backup`

Storage is a JSON file (default ./capability-registry.json); the audit log is
<registry>.audit.jsonl. Writes are atomic (tmp + os.replace); `load` recovers a
leftover .tmp from an interrupted write.
"""
from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone

KINDS = {"tool", "skill", "model", "package", "api", "runtime", "connector"}
RISK_LEVELS = {"low", "medium", "high", "critical"}
STATUSES = {
    "discovered", "assessed", "approved", "installed",
    "verified", "failed", "rejected", "retired",
}
EXTERNAL_KINDS = {"connector", "api", "model"}
PROTECTED_RISK = {"high", "critical"}
TRANSITIONS = {
    "discovered": {"assessed", "rejected", "retired"},
    "assessed": {"approved", "rejected", "retired"},
    "approved": {"installed", "rejected", "retired"},
    "installed": {"verified", "failed", "retired"},
    # verified -> failed is allowed so that scheduled re-verification can demote a
    # stale claim through an audited transition instead of leaving it green.
    "verified": {"failed", "retired"},
    "failed": {"assessed", "retired"},
    "rejected": {"retired"},
    "retired": set(),
}
REQUIRED_FIELDS = ("name", "kind", "purpose")
PRESENT_STATUSES = {"installed", "verified"}
GENESIS = "0" * 64
REGISTRY_VERSION = 3

# Redaction: never store obvious credentials in evidence or audit output.
SECRET_PATTERNS = [
    (re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"), "[REDACTED_GITHUB_TOKEN]"),
    (re.compile(r"sk-[A-Za-z0-9]{20,}"), "[REDACTED_API_KEY]"),
    (re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]{12,}"), "Bearer [REDACTED]"),
    (re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*\S+"), "aws_secret_access_key=[REDACTED]"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "[REDACTED_AWS_KEY_ID]"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
     "[REDACTED_PRIVATE_KEY]"),
]


class RegistryError(Exception):
    """Raised when an operation would record a dishonest or unsafe state."""


def redact(text: str) -> str:
    if not text:
        return text
    for pat, repl in SECRET_PATTERNS:
        text = pat.sub(repl, text)
    return text


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# --------------------------------------------------------------------------- #
# locking / persistence
# --------------------------------------------------------------------------- #
@contextlib.contextmanager
def locked(path: str):
    """Exclusive advisory lock around a read-modify-write on `path`."""
    lock_path = path + ".lock"
    fh = open(lock_path, "w", encoding="utf-8")
    try:
        fcntl.flock(fh, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fh, fcntl.LOCK_UN)
        fh.close()


def load(path: str) -> dict:
    # recover a leftover .tmp from an interrupted write
    if not os.path.exists(path) and os.path.exists(path + ".tmp"):
        path = path + ".tmp"
    if not os.path.exists(path):
        return {"version": REGISTRY_VERSION, "updated": _now(),
                "capabilities": {}, "lessons": []}
    with open(path, "r", encoding="utf-8") as fh:
        try:
            data = json.load(fh)
        except json.JSONDecodeError as exc:
            raise RegistryError(f"registry {path!r} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise RegistryError(f"registry {path!r} must contain a JSON object")
    data.setdefault("version", 1)
    data.setdefault("capabilities", {})
    data.setdefault("lessons", [])
    if not isinstance(data["capabilities"], dict):
        raise RegistryError("registry 'capabilities' must be a mapping")
    if not isinstance(data["lessons"], list):
        raise RegistryError("registry 'lessons' must be a list")
    return data


def save(path: str, data: dict) -> None:
    data["version"] = REGISTRY_VERSION
    data["updated"] = _now()
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


# --------------------------------------------------------------------------- #
# tamper-evident audit log
# --------------------------------------------------------------------------- #
def _audit_path(registry_path: str) -> str:
    return registry_path + ".audit.jsonl"


def _read_audit_lines(registry_path: str) -> list[dict]:
    ap = _audit_path(registry_path)
    if not os.path.exists(ap):
        return []
    out = []
    with open(ap, "r", encoding="utf-8") as fh:
        for raw in fh:
            raw = raw.strip()
            if raw:
                out.append(json.loads(raw))
    return out


def _chain_hash(prev: str, record: dict) -> str:
    canon = json.dumps({k: v for k, v in record.items() if k != "hash"},
                       sort_keys=True)
    return hashlib.sha256((prev + canon).encode("utf-8")).hexdigest()


def audit(registry_path: str, actor: str, action: str, **fields) -> dict:
    lines = _read_audit_lines(registry_path)
    seq = len(lines)
    prev = lines[-1]["hash"] if lines else GENESIS
    rec = {"seq": seq, "prev": prev, "at": _now(), "actor": actor, "action": action}
    for k, v in fields.items():
        if v in (None, ""):
            continue
        rec[k] = redact(v) if isinstance(v, str) else v
    rec["hash"] = _chain_hash(prev, rec)
    with open(_audit_path(registry_path), "a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec, sort_keys=True) + "\n")
    return rec


def read_audit(registry_path: str) -> list[dict]:
    return _read_audit_lines(registry_path)


def verify_audit(registry_path: str) -> dict:
    """Recompute the hash chain; report the first broken record, if any."""
    lines = _read_audit_lines(registry_path)
    prev = GENESIS
    for i, rec in enumerate(lines):
        if rec.get("prev") != prev:
            return {"ok": False, "broken_at": i, "reason": "prev-hash mismatch"}
        if rec.get("hash") != _chain_hash(prev, rec):
            return {"ok": False, "broken_at": i, "reason": "record hash mismatch"}
        prev = rec["hash"]
    return {"ok": True, "records": len(lines), "head": prev}


# --------------------------------------------------------------------------- #
# environment / integrity
# --------------------------------------------------------------------------- #
def current_env() -> dict:
    return {
        "python": platform.python_version(),
        "os": "linux" if sys.platform.startswith("linux") else sys.platform,
        "arch": platform.machine(),
    }


def _cmp_version(have: str, spec: str) -> bool:
    m = re.match(r"^\s*(>=|<=|==|>|<)\s*([0-9][0-9.]*)\s*$", spec)
    if not m:
        raise RegistryError(f"unsupported version spec {spec!r}")
    op, want = m.group(1), m.group(2)

    def parts(v):
        return [int(x) for x in v.split(".") if x != ""]

    a, b = parts(have), parts(want)
    n = max(len(a), len(b))
    a += [0] * (n - len(a))
    b += [0] * (n - len(b))
    return {">=": a >= b, "<=": a <= b, ">": a > b, "<": a < b, "==": a == b}[op]


def check_compatibility(entry: dict, env: dict | None = None) -> list[str]:
    env = env or current_env()
    problems: list[str] = []
    req = entry.get("requires") or {}
    if not isinstance(req, dict):
        return ["'requires' must be a mapping"]
    if "python" in req and not _cmp_version(env["python"], req["python"]):
        problems.append(f"python {env['python']} does not satisfy {req['python']}")
    if "os" in req and env["os"] != req["os"]:
        problems.append(f"os {env['os']} != required {req['os']}")
    if "arch" in req and env["arch"] != req["arch"]:
        problems.append(f"arch {env['arch']} != required {req['arch']}")
    return problems


def sha256_of(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def plan_hash(plan: dict) -> str:
    return hashlib.sha256(json.dumps(plan, sort_keys=True).encode("utf-8")).hexdigest()


def verify_integrity(entry: dict, artifact: str) -> dict:
    recorded = entry.get("sha256")
    if not recorded:
        return {"ok": False, "reason": "no sha256 recorded for this capability"}
    if not os.path.exists(artifact):
        return {"ok": False, "reason": f"artifact not found: {artifact}"}
    actual = sha256_of(artifact)
    return {"ok": actual == recorded, "recorded": recorded, "actual": actual,
            "trusted": bool(entry.get("sha256_trusted")),
            "reason": "" if actual == recorded else "checksum mismatch"}


# --------------------------------------------------------------------------- #
# core operations
# --------------------------------------------------------------------------- #
def validate_entry(entry: dict) -> list[str]:
    problems: list[str] = []
    for field in REQUIRED_FIELDS:
        if not entry.get(field):
            problems.append(f"missing required field {field!r}")
    if entry.get("kind") and entry["kind"] not in KINDS:
        problems.append(f"invalid kind {entry['kind']!r}; allowed: {sorted(KINDS)}")
    if entry.get("risk_level") and entry["risk_level"] not in RISK_LEVELS:
        problems.append(f"invalid risk_level {entry['risk_level']!r}")
    if entry.get("status") and entry["status"] not in STATUSES:
        problems.append(f"invalid status {entry['status']!r}")
    return problems


def add_capability(
    registry: dict, name: str, kind: str, purpose: str, *,
    source: str = "", license: str = "", risk_level: str = "medium",
    requires: dict | None = None, dependencies: list[str] | None = None,
    sha256: str = "", sha256_trusted: bool = False, artifact: str = "",
) -> dict:
    if name in registry["capabilities"]:
        raise RegistryError(f"capability {name!r} already exists")
    if kind not in KINDS:
        raise RegistryError(f"invalid kind {kind!r}; allowed: {sorted(KINDS)}")
    if risk_level not in RISK_LEVELS:
        raise RegistryError(f"invalid risk_level {risk_level!r}")
    if sha256 and not re.fullmatch(r"[0-9a-f]{64}", sha256):
        raise RegistryError("sha256 must be 64 lowercase hex characters")
    entry = {
        "name": name, "kind": kind, "purpose": purpose, "source": source,
        "license": license, "risk_level": risk_level, "requires": requires or {},
        "dependencies": dependencies or [], "sha256": sha256,
        "sha256_trusted": bool(sha256_trusted), "artifact": artifact,
        "status": "discovered", "approval_by": None, "approval_ref": None,
        "plan_hash": None, "approved_sha256": None,
        "evidence": "", "tests": [], "verify_result": None,
        "rollback": "", "rollback_tested": False,
        "failure_reason": "", "recovery_note": "",
        "history": [{"status": "discovered", "at": _now()}],
    }
    registry["capabilities"][name] = entry
    return entry


def _is_protected(entry: dict) -> bool:
    return entry["kind"] in EXTERNAL_KINDS or entry["risk_level"] in PROTECTED_RISK


def _missing_dependencies(registry: dict, entry: dict) -> list[str]:
    missing = []
    for dep in entry.get("dependencies", []):
        d = registry["capabilities"].get(dep)
        if d is None or d.get("status") not in PRESENT_STATUSES:
            missing.append(dep)
    return missing


def detect_cycles(registry: dict) -> list[list[str]]:
    """Return any dependency cycles among registered capabilities."""
    cycles = []
    seen_global = set()

    def visit(node, stack, path):
        if node in stack:
            cycles.append(path[path.index(node):] + [node])
            return
        if node in seen_global or node not in registry["capabilities"]:
            return
        stack.add(node)
        for dep in registry["capabilities"][node].get("dependencies", []):
            visit(dep, stack, path + [dep])
        stack.discard(node)
        seen_global.add(node)

    for name in registry["capabilities"]:
        visit(name, set(), [name])
    return cycles


def transition(
    registry: dict, name: str, to: str, *,
    evidence: str = "", tests: list[str] | None = None, rollback: str = "",
    failure_reason: str = "", approval_by: str = "", approval_ref: str = "",
    recovery_note: str = "", rollback_tested: bool = False,
    plan_hash_value: str = "", actor: str = "apex-x", env: dict | None = None,
) -> dict:
    if name not in registry["capabilities"]:
        raise RegistryError(f"unknown capability {name!r}")
    entry = registry["capabilities"][name]
    current = entry["status"]
    if to not in STATUSES:
        raise RegistryError(f"invalid status {to!r}")
    if to not in TRANSITIONS[current]:
        raise RegistryError(
            f"illegal transition {current!r} -> {to!r} "
            f"(allowed: {sorted(TRANSITIONS[current]) or 'none'})"
        )

    if to == "approved":
        if not approval_by or not approval_by.strip():
            raise RegistryError(
                f"{name!r} requires a recorded approver (approval_by) to be approved"
            )
        approver = approval_by.strip()
        # self-approval guard: an agent may not approve its own protected op
        if approver == actor and _is_protected(entry):
            raise RegistryError(
                f"{name!r} is a protected capability; the approver must differ "
                f"from the executing identity ({actor!r})"
            )
        # protected operations must be bound to a reviewed plan
        if _is_protected(entry) and not plan_hash_value:
            raise RegistryError(
                f"{name!r} is protected (external kind or high risk); a plan_hash "
                "is required so the approval binds to a reviewed plan"
            )
        entry["approval_by"] = approver
        entry["approval_ref"] = approval_ref.strip() or None
        entry["plan_hash"] = plan_hash_value or None
        entry["approved_sha256"] = entry.get("sha256") or None

    if to == "installed":
        if not entry.get("approval_by"):
            raise RegistryError(
                f"{name!r} cannot be installed without a recorded approval"
            )
        # stale-approval check: the artifact must not have changed since approval
        approved_sha = entry.get("approved_sha256")
        if approved_sha and entry.get("sha256") and approved_sha != entry["sha256"]:
            raise RegistryError(
                f"{name!r} approval is stale: the artifact checksum changed "
                "since approval; re-approval is required"
            )
        if not rollback and not entry.get("rollback"):
            raise RegistryError(
                f"{name!r} cannot be installed without a rollback procedure"
            )
        problems = check_compatibility(entry, env)
        if problems:
            raise RegistryError(
                "incompatible with this environment: " + "; ".join(problems)
            )
        missing = _missing_dependencies(registry, entry)
        if missing:
            raise RegistryError("unmet dependencies: " + ", ".join(missing))
        if rollback:
            entry["rollback"] = rollback
        if rollback_tested:
            entry["rollback_tested"] = True

    if to == "verified":
        # Declaration alone is not proof; `verify` (execution) sets verify_result.
        if not evidence and not entry.get("evidence"):
            raise RegistryError(f"{name!r} cannot be marked verified without evidence")
        if not tests and not entry.get("tests"):
            raise RegistryError(f"{name!r} cannot be marked verified without a test command")
        if evidence:
            entry["evidence"] = redact(evidence)
        if tests:
            entry["tests"] = list(tests)

    if to == "failed":
        if not failure_reason:
            raise RegistryError(f"{name!r} -> failed requires a failure_reason")
        entry["failure_reason"] = redact(failure_reason)

    if to == "assessed" and current == "failed":
        entry["recovery_note"] = recovery_note or "retry after failure"
        entry["failure_reason"] = ""

    entry["status"] = to
    entry.setdefault("history", []).append({"status": to, "at": _now()})
    return entry


# --------------------------------------------------------------------------- #
# real verification execution
# --------------------------------------------------------------------------- #
def run_command(argv: list[str], cwd: str | None = None, timeout: int = 60) -> dict:
    """Run a command as an argument list (no shell). Returns exit code + output."""
    if not isinstance(argv, list) or not argv or not all(isinstance(a, str) for a in argv):
        raise RegistryError("command must be a non-empty list of string arguments")
    try:
        proc = subprocess.run(argv, cwd=cwd, capture_output=True, text=True,
                              timeout=timeout, shell=False)
    except subprocess.TimeoutExpired:
        return {"exit_code": -1, "stdout": "", "stderr": f"timed out after {timeout}s",
                "timeout": True}
    except FileNotFoundError as exc:
        return {"exit_code": 127, "stdout": "", "stderr": str(exc), "timeout": False}
    return {"exit_code": proc.returncode,
            "stdout": redact(proc.stdout[-2000:]),
            "stderr": redact(proc.stderr[-2000:]),
            "timeout": False}


def verify_capability(registry: dict, name: str, argv: list[str], *,
                      cwd: str | None = None, timeout: int = 60,
                      actor: str = "apex-x") -> dict:
    """Execute the real test; only a clean exit marks the capability verified."""
    if name not in registry["capabilities"]:
        raise RegistryError(f"unknown capability {name!r}")
    entry = registry["capabilities"][name]
    if entry["status"] != "installed":
        raise RegistryError(f"{name!r} must be installed before it can be verified")
    result = run_command(argv, cwd=cwd, timeout=timeout)
    record = {
        "at": _now(), "command": argv, "cwd": cwd, "exit_code": result["exit_code"],
        "timeout": result["timeout"], "stdout": result["stdout"][:1000],
        "stderr": result["stderr"][:1000], "env": current_env(),
        "artifact_sha256": entry.get("sha256") or None,
    }
    entry["verify_result"] = record
    entry["test_argv"] = list(argv)
    entry["tests"] = [" ".join(argv)]
    if result["exit_code"] != 0:
        entry["status"] = "failed"
        entry["failure_reason"] = redact(
            f"verification command exited {result['exit_code']}")
        entry.setdefault("history", []).append({"status": "failed", "at": _now()})
        return {"ok": False, "record": record}
    entry["evidence"] = redact(
        f"ran {' '.join(argv)} -> exit 0 at {record['at']}")
    entry["status"] = "verified"
    entry.setdefault("history", []).append({"status": "verified", "at": _now()})
    return {"ok": True, "record": record}


# --------------------------------------------------------------------------- #
# lessons / memory
# --------------------------------------------------------------------------- #
def add_lesson(registry: dict, topic: str, lesson: str, *,
               capability: str = "", source: str = "",
               status: str = "assumed", capability_version: str = "") -> dict:
    if status not in {"verified", "assumed", "outdated"}:
        raise RegistryError(f"invalid lesson status {status!r}")
    if not topic or not lesson:
        raise RegistryError("lesson requires both topic and lesson")
    item = {"at": _now(), "topic": redact(topic), "lesson": redact(lesson),
            "capability": capability, "capability_version": capability_version,
            "source": source, "status": status}
    registry.setdefault("lessons", []).append(item)
    return item


# --------------------------------------------------------------------------- #
# validation / review
# --------------------------------------------------------------------------- #
def check_registry(registry: dict, env: dict | None = None,
                   max_age_days: int = 0) -> dict:
    problems: dict[str, list[str]] = {}
    sources: dict[str, list[str]] = {}
    for name, entry in registry["capabilities"].items():
        p = validate_entry(entry)
        if entry.get("status") in {"installed", "verified"} and not entry.get("rollback"):
            p.append("installed/verified without a rollback procedure")
        if entry.get("status") == "verified" and not entry.get("evidence"):
            p.append("verified without evidence")
        if entry.get("status") == "verified" and not entry.get("verify_result"):
            p.append("verified without an executed test (declaration only)")
        approved_sha = entry.get("approved_sha256")
        if approved_sha and entry.get("sha256") and approved_sha != entry["sha256"]:
            p.append("stale approval: artifact checksum changed since approval")
        p.extend(check_compatibility(entry, env))
        missing = _missing_dependencies(registry, entry)
        if missing and entry.get("status") in PRESENT_STATUSES:
            p.append("unmet dependencies: " + ", ".join(missing))
        if max_age_days and entry.get("history"):
            last = entry["history"][-1].get("at", "")
            try:
                age = (datetime.now(timezone.utc)
                       - datetime.fromisoformat(last)).days
                if age > max_age_days:
                    p.append(f"outdated: last change {age} days ago")
            except ValueError:
                pass
        if entry.get("source"):
            sources.setdefault(entry["source"], []).append(name)
        if p:
            problems[name] = p
    for src, names in sources.items():
        if len(names) > 1:
            for n in names:
                problems.setdefault(n, []).append(
                    f"possible duplicate of {sorted(set(names) - {n})} (same source)")
    return {"ok": not problems, "problems": problems,
            "cycles": detect_cycles(registry)}


# --------------------------------------------------------------------------- #
# migration / backup
# --------------------------------------------------------------------------- #
def migrate(registry: dict) -> dict:
    """Bring a v1/v2 registry up to v3, adding missing fields. Backward-compatible."""
    changed = []
    for name, e in registry["capabilities"].items():
        for field, default in (
            ("sha256", ""), ("sha256_trusted", False), ("plan_hash", None),
            ("approved_sha256", None), ("verify_result", None),
            ("rollback_tested", False), ("recovery_note", ""),
            ("dependencies", []), ("requires", {}), ("test_argv", []),
            ("artifact", ""), ("reverify_result", None), ("reverify_history", []),
        ):
            if field not in e:
                e[field] = default
                changed.append(f"{name}.{field}")
    registry.setdefault("lessons", [])
    registry["version"] = REGISTRY_VERSION
    return {"changed": changed, "version": REGISTRY_VERSION}


def backup(registry_path: str) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    dest = f"{registry_path}.bak.{stamp}"
    shutil.copy2(registry_path, dest)
    ap = _audit_path(registry_path)
    if os.path.exists(ap):
        shutil.copy2(ap, dest + ".audit.jsonl")
    return dest


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def _cmd_add(args):
    with locked(args.registry):
        reg = load(args.registry)
        entry = add_capability(
            reg, args.name, args.kind, args.purpose,
            source=args.source, license=args.license, risk_level=args.risk,
            requires=json.loads(args.requires) if args.requires else None,
            dependencies=args.dependencies.split(",") if args.dependencies else None,
            sha256=args.sha256, sha256_trusted=args.sha256_trusted,
            artifact=args.artifact,
        )
        save(args.registry, reg)
        audit(args.registry, args.actor, "add", name=args.name, kind=args.kind,
              status="discovered", risk=args.risk)
    print(json.dumps(entry, indent=2, sort_keys=True))


def _cmd_transition(args):
    with locked(args.registry):
        reg = load(args.registry)
        entry = transition(
            reg, args.name, args.to, evidence=args.evidence or "",
            tests=args.tests.split(",") if args.tests else None,
            rollback=args.rollback or "", failure_reason=args.failure_reason or "",
            approval_by=args.approval_by or "", approval_ref=args.approval_ref or "",
            recovery_note=args.recovery_note or "", rollback_tested=args.rollback_tested,
            plan_hash_value=args.plan_hash or "", actor=args.actor,
        )
        save(args.registry, reg)
        audit(args.registry, args.actor, "transition", name=args.name, to=args.to,
              approval_by=args.approval_by)
    print(json.dumps(entry, indent=2, sort_keys=True))


def _cmd_verify(args):
    argv = json.loads(args.command)
    with locked(args.registry):
        reg = load(args.registry)
        result = verify_capability(reg, args.name, argv, cwd=args.cwd,
                                   timeout=args.timeout, actor=args.actor)
        save(args.registry, reg)
        audit(args.registry, args.actor, "verify", name=args.name,
              exit_code=result["record"]["exit_code"], ok=result["ok"])
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 1


def _cmd_verify_audit(args):
    result = verify_audit(args.registry)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 1


def _cmd_list(args):
    reg = load(args.registry)
    rows = [
        {"name": e["name"], "kind": e["kind"], "status": e["status"],
         "risk": e["risk_level"], "purpose": e["purpose"]}
        for e in reg["capabilities"].values()
        if not args.status or e["status"] == args.status
    ]
    print(json.dumps(rows, indent=2, sort_keys=True))


def _cmd_show(args):
    reg = load(args.registry)
    if args.name not in reg["capabilities"]:
        raise RegistryError(f"unknown capability {args.name!r}")
    print(json.dumps(reg["capabilities"][args.name], indent=2, sort_keys=True))


def _cmd_check(args):
    reg = load(args.registry)
    result = check_registry(reg, max_age_days=args.max_age_days)
    result["audit"] = verify_audit(args.registry)
    with locked(args.registry):
        audit(args.registry, args.actor, "check", ok=result["ok"])
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] and result["audit"]["ok"] else 1


def _cmd_verify_integrity(args):
    reg = load(args.registry)
    if args.name not in reg["capabilities"]:
        raise RegistryError(f"unknown capability {args.name!r}")
    result = verify_integrity(reg["capabilities"][args.name], args.artifact)
    with locked(args.registry):
        audit(args.registry, args.actor, "verify-integrity", name=args.name,
              ok=result["ok"])
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 1


def _cmd_lesson(args):
    with locked(args.registry):
        reg = load(args.registry)
        item = add_lesson(reg, args.topic, args.lesson, capability=args.capability,
                          source=args.source, status=args.status,
                          capability_version=args.capability_version)
        save(args.registry, reg)
        audit(args.registry, args.actor, "lesson", topic=args.topic, status=args.status)
    print(json.dumps(item, indent=2, sort_keys=True))


def _cmd_lessons(args):
    reg = load(args.registry)
    items = reg.get("lessons", [])
    if args.status:
        items = [i for i in items if i.get("status") == args.status]
    print(json.dumps(items, indent=2, sort_keys=True))


def _cmd_export(args):
    reg = load(args.registry)
    bundle = {
        "exported": _now(), "version": REGISTRY_VERSION,
        "capabilities": reg["capabilities"], "lessons": reg.get("lessons", []),
        "audit": read_audit(args.registry), "audit_head": verify_audit(args.registry),
    }
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(bundle, fh, indent=2, sort_keys=True)
    with locked(args.registry):
        audit(args.registry, args.actor, "export", out=args.out)
    print(f"wrote {args.out} ({len(bundle['capabilities'])} capabilities, "
          f"{len(bundle['lessons'])} lessons)")


def _cmd_migrate(args):
    with locked(args.registry):
        if not os.path.exists(args.registry):
            raise RegistryError(f"no registry at {args.registry}")
        if not args.no_backup:
            dest = backup(args.registry)
            print(f"backup: {dest}")
        reg = load(args.registry)
        result = migrate(reg)
        save(args.registry, reg)
        audit(args.registry, args.actor, "migrate", version=result["version"])
    print(json.dumps(result, indent=2, sort_keys=True))


def _cmd_backup(args):
    dest = backup(args.registry)
    print(dest)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="APEX-X capability registry (v3)")
    p.add_argument("--registry", default="capability-registry.json")
    p.add_argument("--actor", default="apex-x", help="who is performing the action")
    sub = p.add_subparsers(dest="command", required=True)

    a = sub.add_parser("add")
    a.add_argument("--name", required=True)
    a.add_argument("--kind", required=True)
    a.add_argument("--purpose", required=True)
    a.add_argument("--source", default="")
    a.add_argument("--license", default="")
    a.add_argument("--risk", default="medium", choices=sorted(RISK_LEVELS))
    a.add_argument("--requires", default="")
    a.add_argument("--dependencies", default="")
    a.add_argument("--sha256", default="")
    a.add_argument("--sha256-trusted", action="store_true",
                   help="the sha256 came from a trusted source, not the download itself")
    a.add_argument("--artifact", default="",
                   help="path to the installed artifact (verified by preflight)")
    a.set_defaults(func=_cmd_add)

    t = sub.add_parser("transition")
    t.add_argument("--name", required=True)
    t.add_argument("--to", required=True, choices=sorted(STATUSES))
    t.add_argument("--evidence", default="")
    t.add_argument("--tests", default="")
    t.add_argument("--rollback", default="")
    t.add_argument("--failure-reason", default="")
    t.add_argument("--approval-by", default="")
    t.add_argument("--approval-ref", default="")
    t.add_argument("--plan-hash", default="")
    t.add_argument("--recovery-note", default="")
    t.add_argument("--rollback-tested", action="store_true")
    t.set_defaults(func=_cmd_transition)

    v = sub.add_parser("verify", help="execute the real test command")
    v.add_argument("--name", required=True)
    v.add_argument("--command", required=True, help="JSON arg list, e.g. '[\"pytest\",\"-q\"]'")
    v.add_argument("--cwd", default=None)
    v.add_argument("--timeout", type=int, default=60)
    v.set_defaults(func=_cmd_verify)

    va = sub.add_parser("verify-audit")
    va.set_defaults(func=_cmd_verify_audit)

    l = sub.add_parser("list")
    l.add_argument("--status", default="")
    l.set_defaults(func=_cmd_list)

    s = sub.add_parser("show")
    s.add_argument("--name", required=True)
    s.set_defaults(func=_cmd_show)

    c = sub.add_parser("check")
    c.add_argument("--max-age-days", type=int, default=0)
    c.set_defaults(func=_cmd_check)

    vi = sub.add_parser("verify-integrity")
    vi.add_argument("--name", required=True)
    vi.add_argument("--artifact", required=True)
    vi.set_defaults(func=_cmd_verify_integrity)

    ls = sub.add_parser("lesson")
    ls.add_argument("--topic", required=True)
    ls.add_argument("--lesson", required=True)
    ls.add_argument("--capability", default="")
    ls.add_argument("--capability-version", default="")
    ls.add_argument("--source", default="")
    ls.add_argument("--status", default="assumed",
                    choices=["verified", "assumed", "outdated"])
    ls.set_defaults(func=_cmd_lesson)

    lls = sub.add_parser("lessons")
    lls.add_argument("--status", default="")
    lls.set_defaults(func=_cmd_lessons)

    e = sub.add_parser("export")
    e.add_argument("--out", required=True)
    e.set_defaults(func=_cmd_export)

    m = sub.add_parser("migrate")
    m.add_argument("--no-backup", action="store_true")
    m.set_defaults(func=_cmd_migrate)

    b = sub.add_parser("backup")
    b.set_defaults(func=_cmd_backup)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args) or 0
    except RegistryError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as exc:
        print(f"ERROR: invalid JSON argument: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
