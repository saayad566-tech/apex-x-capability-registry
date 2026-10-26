"""Preflight is fail-closed: missing/tampered state exits 2, dishonest state exits 1."""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import support
import capability_registry as cr
import preflight as pf


def _old(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="seconds")


class PreflightStateTests(unittest.TestCase):
    """Exit code 2 - the state cannot be trusted at all."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name

    def tearDown(self):
        self._tmp.cleanup()

    def test_missing_registry_is_fatal(self):
        result = pf.preflight(os.path.join(self.tmp, "capability-registry.json"))
        self.assertEqual(result["exit_code"], pf.EXIT_STATE)
        self.assertIn("registry missing", result["state_findings"][0]["message"])

    def test_malformed_registry_is_fatal(self):
        path = os.path.join(self.tmp, "capability-registry.json")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("{ this is not json")
        result = pf.preflight(path)
        self.assertEqual(result["exit_code"], pf.EXIT_STATE)
        self.assertIn("malformed", result["state_findings"][0]["message"])

    def test_registry_must_be_an_object(self):
        path = os.path.join(self.tmp, "capability-registry.json")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("[1, 2, 3]")
        self.assertEqual(pf.preflight(path)["exit_code"], pf.EXIT_STATE)

    def test_missing_audit_log_is_fatal(self):
        path = support.build(self.tmp)
        os.remove(cr._audit_path(path))
        self.assertEqual(pf.preflight(path)["exit_code"], pf.EXIT_STATE)
        lenient = pf.preflight(path, require_audit=False)
        self.assertEqual(lenient["exit_code"], pf.EXIT_PROBLEMS)

    def test_tampered_audit_log_is_fatal(self):
        path = support.build(self.tmp)
        audit_path = cr._audit_path(path)
        with open(audit_path, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
        lines[-1] = lines[-1].replace('"ok": true', '"ok": false')
        with open(audit_path, "w", encoding="utf-8") as fh:
            fh.writelines(lines)
        result = pf.preflight(path)
        self.assertEqual(result["exit_code"], pf.EXIT_STATE)
        self.assertTrue(any("hash chain broken" in f["message"]
                            for f in result["state_findings"]))

    def test_corrupt_audit_log_is_fatal(self):
        path = support.build(self.tmp)
        with open(cr._audit_path(path), "a", encoding="utf-8") as fh:
            fh.write("{not json}\n")
        self.assertEqual(pf.preflight(path)["exit_code"], pf.EXIT_STATE)


class PreflightHonestyTests(unittest.TestCase):
    """Exit code 1 - readable state that makes a claim it cannot support."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name

    def tearDown(self):
        self._tmp.cleanup()

    def _messages(self, result):
        return " | ".join(f["message"] for f in result["problems"])

    def test_clean_registry_passes(self):
        path = support.build(self.tmp)
        result = pf.preflight(path)
        self.assertEqual(result["exit_code"], pf.EXIT_OK, result["problems"])

    def test_declaration_only_verified_is_caught(self):
        path = support.build(self.tmp)
        support.mutate(path, "demo", verify_result=None)
        result = pf.preflight(path)
        self.assertEqual(result["exit_code"], pf.EXIT_PROBLEMS)
        self.assertIn("declaration only", self._messages(result))

    def test_verified_without_evidence_is_caught(self):
        path = support.build(self.tmp)
        support.mutate(path, "demo", evidence="")
        self.assertEqual(pf.preflight(path)["exit_code"], pf.EXIT_PROBLEMS)

    def test_verified_with_a_failing_recorded_test_is_caught(self):
        path = support.build(self.tmp)
        data = support.read_registry(path)
        data["capabilities"]["demo"]["verify_result"]["exit_code"] = 1
        support.write_registry(path, data)
        result = pf.preflight(path)
        self.assertEqual(result["exit_code"], pf.EXIT_PROBLEMS)
        self.assertIn("exited 1", self._messages(result))

    def test_stale_evidence_is_caught(self):
        path = support.build(self.tmp, evidence_at=_old(200))
        result = pf.preflight(path, max_evidence_days=90)
        self.assertEqual(result["exit_code"], pf.EXIT_PROBLEMS)
        self.assertIn("stale", self._messages(result))

    def test_evidence_inside_the_window_passes(self):
        path = support.build(self.tmp, evidence_at=_old(10))
        self.assertEqual(pf.preflight(path, max_evidence_days=90)["exit_code"],
                         pf.EXIT_OK)

    def test_artifact_checksum_mismatch_is_caught(self):
        path = support.build(self.tmp)
        with open(os.path.join(self.tmp, "artifact.txt"), "w", encoding="utf-8") as fh:
            fh.write("swapped artifact")
        result = pf.preflight(path)
        self.assertEqual(result["exit_code"], pf.EXIT_PROBLEMS)
        self.assertIn("checksum mismatch", self._messages(result))

    def test_missing_artifact_is_caught(self):
        path = support.build(self.tmp)
        os.remove(os.path.join(self.tmp, "artifact.txt"))
        result = pf.preflight(path)
        self.assertEqual(result["exit_code"], pf.EXIT_PROBLEMS)
        self.assertIn("artifact missing", self._messages(result))

    def test_verified_without_a_checksum_is_caught(self):
        path = support.build(self.tmp)
        support.mutate(path, "demo", sha256="", artifact="")
        result = pf.preflight(path)
        self.assertEqual(result["exit_code"], pf.EXIT_PROBLEMS)
        self.assertIn("without an artifact checksum", self._messages(result))

    def test_missing_rollback_is_caught(self):
        path = support.build(self.tmp)
        support.mutate(path, "demo", rollback="")
        result = pf.preflight(path)
        self.assertEqual(result["exit_code"], pf.EXIT_PROBLEMS)
        self.assertIn("without a rollback", self._messages(result))

    def test_status_out_of_sync_with_audit_trail_is_caught(self):
        path = support.build(self.tmp)
        support.mutate(path, "demo", status="installed")
        result = pf.preflight(path)
        self.assertEqual(result["exit_code"], pf.EXIT_PROBLEMS)
        self.assertIn("not the last audited transition", self._messages(result))

    def test_hand_written_capability_with_no_audit_event_is_caught(self):
        path = support.build(self.tmp)
        data = support.read_registry(path)
        data["capabilities"]["ghost"] = {
            "name": "ghost", "kind": "tool", "purpose": "fabricated",
            "risk_level": "low", "status": "verified", "rollback": "rm ghost",
            "evidence": "trust me", "tests": ["true"], "sha256": "0" * 64,
            "verify_result": {"at": _old(0), "exit_code": 0}, "history": [],
        }
        support.write_registry(path, data)
        result = pf.preflight(path)
        self.assertEqual(result["exit_code"], pf.EXIT_PROBLEMS)
        self.assertIn("no audited status event", self._messages(result))


if __name__ == "__main__":
    unittest.main()
