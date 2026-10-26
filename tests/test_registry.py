"""Registry-level guards: illegal transitions and dishonest states are refused."""
from __future__ import annotations

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import support  # noqa: F401  (sets sys.path to scripts/)
import capability_registry as cr


class RegistryLifecycleTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name
        self.path = os.path.join(self.tmp, "capability-registry.json")
        self.reg = cr.load(self.path)
        cr.add_capability(self.reg, "alpha", "tool", "test capability",
                          risk_level="low")
        cr.save(self.path, self.reg)

    def tearDown(self):
        self._tmp.cleanup()

    def test_empty_registry_is_clean(self):
        empty = cr.load(os.path.join(self.tmp, "other.json"))
        self.assertTrue(cr.check_registry(empty)["ok"])

    def test_illegal_transition_is_refused(self):
        with self.assertRaises(cr.RegistryError):
            cr.transition(self.reg, "alpha", "verified")
        with self.assertRaises(cr.RegistryError):
            cr.transition(self.reg, "alpha", "installed")

    def test_approval_requires_a_recorded_approver(self):
        cr.transition(self.reg, "alpha", "assessed")
        with self.assertRaises(cr.RegistryError):
            cr.transition(self.reg, "alpha", "approved")

    def test_install_requires_a_rollback(self):
        cr.transition(self.reg, "alpha", "assessed")
        cr.transition(self.reg, "alpha", "approved", approval_by="reviewer")
        with self.assertRaises(cr.RegistryError) as ctx:
            cr.transition(self.reg, "alpha", "installed")
        self.assertIn("rollback", str(ctx.exception))

    def test_verified_requires_evidence_and_a_test(self):
        cr.transition(self.reg, "alpha", "assessed")
        cr.transition(self.reg, "alpha", "approved", approval_by="reviewer")
        cr.transition(self.reg, "alpha", "installed", rollback="rm alpha")
        with self.assertRaises(cr.RegistryError):
            cr.transition(self.reg, "alpha", "verified")

    def test_protected_capability_needs_a_plan_hash(self):
        cr.add_capability(self.reg, "ext", "connector", "external service",
                          risk_level="medium")
        cr.transition(self.reg, "ext", "assessed")
        with self.assertRaises(cr.RegistryError) as ctx:
            cr.transition(self.reg, "ext", "approved", approval_by="reviewer")
        self.assertIn("plan_hash", str(ctx.exception))

    def test_self_approval_of_a_protected_capability_is_refused(self):
        cr.add_capability(self.reg, "ext2", "connector", "external service",
                          risk_level="medium")
        cr.transition(self.reg, "ext2", "assessed")
        with self.assertRaises(cr.RegistryError) as ctx:
            cr.transition(self.reg, "ext2", "approved", approval_by="apex-x",
                          plan_hash_value="a" * 64, actor="apex-x")
        self.assertIn("must differ", str(ctx.exception))

    def test_stale_approval_blocks_install(self):
        cr.transition(self.reg, "alpha", "assessed")
        self.reg["capabilities"]["alpha"]["sha256"] = "0" * 64
        cr.transition(self.reg, "alpha", "approved", approval_by="reviewer")
        self.reg["capabilities"]["alpha"]["sha256"] = "1" * 64
        with self.assertRaises(cr.RegistryError) as ctx:
            cr.transition(self.reg, "alpha", "installed", rollback="rm alpha")
        self.assertIn("stale", str(ctx.exception))

    def test_unmet_dependency_blocks_install(self):
        cr.add_capability(self.reg, "beta", "tool", "depends on a ghost",
                          risk_level="low", dependencies=["ghost"])
        cr.transition(self.reg, "beta", "assessed")
        cr.transition(self.reg, "beta", "approved", approval_by="reviewer")
        with self.assertRaises(cr.RegistryError) as ctx:
            cr.transition(self.reg, "beta", "installed", rollback="rm beta")
        self.assertIn("unmet dependencies", str(ctx.exception))

    def test_lesson_requires_topic_and_lesson(self):
        with self.assertRaises(cr.RegistryError):
            cr.add_lesson(self.reg, "", "x")
        with self.assertRaises(cr.RegistryError):
            cr.add_lesson(self.reg, "x", "")
        with self.assertRaises(cr.RegistryError):
            cr.add_lesson(self.reg, "x", "y", status="certain")
        item = cr.add_lesson(self.reg, "x", "y", status="verified")
        self.assertEqual(item["status"], "verified")

    def test_secrets_are_redacted_in_lessons(self):
        # built at runtime so the repository never contains a literal that
        # trips a secret scanner (this is a fixture, not a credential)
        fake = "sk-" + "a" * 24
        item = cr.add_lesson(self.reg, "leak", "token " + fake)
        self.assertNotIn(fake, item["lesson"])
        self.assertIn("REDACTED", item["lesson"])


class AuditChainTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name
        self.path = os.path.join(self.tmp, "capability-registry.json")
        cr.save(self.path, cr.load(self.path))
        cr.audit(self.path, "test", "one", name="a")
        cr.audit(self.path, "test", "two", name="b")

    def tearDown(self):
        self._tmp.cleanup()

    def test_chain_is_intact_after_appends(self):
        result = cr.verify_audit(self.path)
        self.assertTrue(result["ok"])
        self.assertEqual(result["records"], 2)

    def test_edited_record_breaks_the_chain(self):
        audit_path = cr._audit_path(self.path)
        with open(audit_path, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
        lines[0] = lines[0].replace('"actor": "test"', '"actor": "mallory"')
        with open(audit_path, "w", encoding="utf-8") as fh:
            fh.writelines(lines)
        result = cr.verify_audit(self.path)
        self.assertFalse(result["ok"])
        self.assertEqual(result["broken_at"], 0)

    def test_deleted_record_breaks_the_chain(self):
        audit_path = cr._audit_path(self.path)
        with open(audit_path, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
        with open(audit_path, "w", encoding="utf-8") as fh:
            fh.writelines(lines[1:])
        self.assertFalse(cr.verify_audit(self.path)["ok"])


class CycleTests(unittest.TestCase):
    def test_dependency_cycle_is_detected(self):
        reg = {"version": 3, "capabilities": {}, "lessons": []}
        cr.add_capability(reg, "a", "tool", "a", dependencies=["b"])
        cr.add_capability(reg, "b", "tool", "b", dependencies=["a"])
        cycles = cr.detect_cycles(reg)
        self.assertTrue(cycles)
        self.assertIn("a", cycles[0])


if __name__ == "__main__":
    unittest.main()
