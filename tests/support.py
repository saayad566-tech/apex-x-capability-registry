"""Shared fixtures for the capability-registry test suite.

Every fixture is built through the *real* lifecycle functions, so the tests
exercise the same code path production uses. Nothing is hand-written into the
JSON except where a test is deliberately simulating tampering.
"""
from __future__ import annotations

import hashlib
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_SCRIPTS = os.path.join(os.path.dirname(_HERE), "scripts")
if _SCRIPTS not in sys.path:
    sys.path.insert(0, _SCRIPTS)

import capability_registry as cr  # noqa: E402
import preflight as pf  # noqa: E402
import reverify as rv  # noqa: E402

OK_CMD = ["python3", "-c", "print('ok')"]
FAIL_CMD = ["python3", "-c", "import sys; sys.exit(3)"]


def sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def build(tmpdir: str, name: str = "demo", *, artifact_text: str = "demo-artifact",
          stop_at: str = "verified", test_argv=None, evidence_at: str | None = None,
          rollback: str = "rm artifact.txt") -> str:
    """Create a registry + artifact + audit trail consistent with `stop_at`."""
    reg_path = os.path.join(tmpdir, "capability-registry.json")
    art_rel = "artifact.txt"
    with open(os.path.join(tmpdir, art_rel), "w", encoding="utf-8") as fh:
        fh.write(artifact_text)

    reg = cr.load(reg_path)
    cr.add_capability(reg, name, "tool", "fixture capability", risk_level="low",
                      sha256=sha(artifact_text), artifact=art_rel)
    cr.save(reg_path, reg)
    cr.audit(reg_path, "test", "add", name=name, kind="tool", status="discovered")

    def step(to: str, **kw):
        cr.transition(reg, name, to, **kw)
        cr.save(reg_path, reg)
        cr.audit(reg_path, "test", "transition", name=name, to=to)

    step("assessed")
    step("approved", approval_by="reviewer", approval_ref="fixture approval")
    step("installed", rollback=rollback)
    if stop_at == "installed":
        return reg_path

    argv = list(test_argv or OK_CMD)
    result = cr.verify_capability(reg, name, argv)
    if evidence_at:
        entry = reg["capabilities"][name]
        entry["verify_result"]["at"] = evidence_at
        entry["history"][-1]["at"] = evidence_at
    cr.save(reg_path, reg)
    cr.audit(reg_path, "test", "verify", name=name, ok=result["ok"],
             exit_code=result["record"]["exit_code"])
    return reg_path


def read_registry(reg_path: str) -> dict:
    import json
    with open(reg_path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def write_registry(reg_path: str, data: dict) -> None:
    import json
    with open(reg_path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)


def mutate(reg_path: str, name: str, **fields) -> None:
    data = read_registry(reg_path)
    data["capabilities"][name].update(fields)
    write_registry(reg_path, data)
