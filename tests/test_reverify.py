"""Re-verification: stale evidence is re-run, failures demote, recovery is audited."""
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
import reverify as rv


def _old(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="seconds")


class ReverifyTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name

    def tearDown(self):
        self._tmp.cleanup()

    def _entry(self, path, name="demo"):
        return support.read_registry(path)["capabilities"][name]

    def test_fresh_evidence_is_left_alone(self):
        path = support.build(self.tmp)
        report = rv.reverify(path, max_age_days=90)
        self.assertTrue(report["ok"])
        self.assertEqual([f["name"] for f in report["fresh"]], ["demo"])
        self.assertEqual(report["reverified"], [])

    def test_stale_evidence_is_rerun_and_stays_verified(self):
        path = support.build(self.tmp, evidence_at=_old(120))
        previous = self._entry(path)["verify_result"]["at"]
        report = rv.reverify(path, max_age_days=90)
        self.assertTrue(report["ok"], report)
        self.assertEqual([r["name"] for r in report["reverified"]], ["demo"])
        entry = self._entry(path)
        self.assertEqual(entry["status"], "verified")
        self.assertEqual(entry["reverify_result"]["exit_code"], 0)
        self.assertEqual(entry["reverify_result"]["previous_verified_at"], previous)
        self.assertIn("re-verified", entry["evidence"])

    def test_failing_rerun_demotes_and_is_audited(self):
        # a capability that verified cleanly, whose test now fails
        path = support.build(self.tmp, evidence_at=_old(120))
        support.mutate(path, "demo", test_argv=support.FAIL_CMD)
        report = rv.reverify(path, max_age_days=90)
        self.assertFalse(report["ok"])
        self.assertEqual([d["name"] for d in report["demoted"]], ["demo"])
        entry = self._entry(path)
        self.assertEqual(entry["status"], "failed")
        self.assertIn("scheduled re-verification failed", entry["failure_reason"])

        audit = cr.read_audit(path)
        self.assertEqual(audit[-1]["action"], "reverify")
        self.assertFalse(audit[-1]["ok"])
        # the demotion is visible to preflight as a real, audited state
        self.assertEqual(pf.preflight(path)["exit_code"], pf.EXIT_OK)

    def test_demoted_capability_can_recover_through_the_lifecycle(self):
        path = support.build(self.tmp, evidence_at=_old(120))
        support.mutate(path, "demo", test_argv=support.FAIL_CMD)
        rv.reverify(path, max_age_days=90)
        support.mutate(path, "demo", test_argv=support.OK_CMD)

        reg = cr.load(path)
        cr.transition(reg, "demo", "assessed",
                      recovery_note="fixed the test command; retrying")
        cr.audit(path, "test", "transition", name="demo", to="assessed")
        cr.transition(reg, "demo", "approved", approval_by="reviewer",
                      approval_ref="recovery approval")
        cr.audit(path, "test", "transition", name="demo", to="approved")
        cr.transition(reg, "demo", "installed")
        cr.audit(path, "test", "transition", name="demo", to="installed")
        cr.save(path, reg)

        reg = cr.load(path)
        result = cr.verify_capability(reg, "demo", support.OK_CMD)
        cr.save(path, reg)
        cr.audit(path, "test", "verify", name="demo", ok=result["ok"],
                 exit_code=result["record"]["exit_code"])

        self.assertTrue(result["ok"])
        entry = self._entry(path)
        self.assertEqual(entry["status"], "verified")
        self.assertEqual(entry["recovery_note"], "fixed the test command; retrying")
        self.assertEqual(pf.preflight(path)["exit_code"], pf.EXIT_OK)

    def test_missing_test_command_is_reported_not_guessed(self):
        path = support.build(self.tmp, evidence_at=_old(120))
        support.mutate(path, "demo", test_argv=[], tests=[])
        report = rv.reverify(path, max_age_days=90)
        self.assertFalse(report["ok"])
        self.assertEqual(report["skipped"][0]["name"], "demo")
        self.assertEqual(self._entry(path)["status"], "verified")

    def test_dry_run_changes_nothing(self):
        path = support.build(self.tmp, evidence_at=_old(120))
        before = support.read_registry(path)
        report = rv.reverify(path, max_age_days=90, dry_run=True)
        self.assertTrue(report["dry_run"])
        self.assertEqual([r["name"] for r in report["reverified"]], ["demo"])
        self.assertEqual(support.read_registry(path), before)

    def test_force_all_reruns_fresh_evidence(self):
        path = support.build(self.tmp)
        report = rv.reverify(path, max_age_days=90, force_all=True)
        self.assertEqual([r["name"] for r in report["reverified"]], ["demo"])
        self.assertEqual(report["fresh"], [])


if __name__ == "__main__":
    unittest.main()
