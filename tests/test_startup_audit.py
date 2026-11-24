"""Actual controlled entry/runtime/shared-queue flow with an explicit fake SDK."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
RUNNER = (ROOT / "tests/startup_audit_fixture.py").read_text()


class StartupAuditTests(unittest.TestCase):
    def run_fixture(self, scenario):
        temporary = tempfile.TemporaryDirectory(prefix="startup-audit-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        package = root / "installed"
        package.mkdir(mode=0o700)
        (root / "private").mkdir(mode=0o700)
        for name in ("AutodeskFusionMCP.py", "addon_runtime.py", "settings.py", "config.py"):
            shutil.copyfile(ROOT / name, package / name)
        for name in ("lib", "fusion_bridge", "commands"):
            shutil.copytree(ROOT / name, package / name,
                            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        for path in package.rglob("*"):
            path.chmod(0o700 if path.is_dir() else 0o600)
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        result = subprocess.run(
            [sys.executable, "-I", "-S", "-B", "-c", RUNNER, str(root), scenario],
            env=env, text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        records = [line for line in result.stdout.splitlines()
                   if line.startswith("FIXTURE_RESULT=")]
        self.assertEqual(len(records), 1, result.stdout + result.stderr)
        return json.loads(records[0].split("=", 1)[1]), result

    def test_real_queue_getters_and_original_receipts_precede_listener(self):
        facts, result = self.run_fixture("valid")
        self.assertTrue(facts["listener"], result.stdout)
        entry, returned = facts["entry"], facts["returned"]
        self.assertEqual(entry["version"], 2)
        self.assertEqual(entry["purpose"], "isolated-stdout-v1")
        self.assertEqual(returned["entry"]["sha256"], facts["entrySha256"])
        self.assertEqual(entry["intent"]["sha256"], facts["originalIntentSha256"])
        self.assertEqual(entry["executable"], returned["executable"])
        audit = entry["startupAudit"]
        self.assertEqual(set(audit), {
            "kind", "version", "applicationVersion", "preferences", "scripts"})
        self.assertEqual(audit["scripts"]["countBefore"], 2)
        self.assertEqual(audit["scripts"]["countAfter"], 2)
        rows = audit["scripts"]["items"]
        self.assertEqual(len(rows), 2)
        self.assertFalse(rows[0]["isRunOnStartup"])
        self.assertIsNone(rows[1]["isRunOnStartup"])
        self.assertFalse(rows[1]["isVisible"], "Hidden scripts must not be filtered")
        self.assertEqual(rows[0]["location"], {
            "name": "UserDefinedScriptSourceLocation", "value": 30})
        self.assertEqual(facts["events"].count("getter:isRunOnStartup"), 1)
        self.assertLess(facts["events"].index("bootstrap-register-custom-event"),
                        facts["events"].index("getter:preferences"))
        self.assertLess(facts["events"].index("getter:manifestContent"),
                        facts["events"].index("server-construct"))
        self.assertNotIn("startupAudit", returned)

    def test_invalid_original_identity_never_touches_sdk(self):
        for scenario in ("bad-intent", "bad-executable"):
            with self.subTest(scenario=scenario):
                facts, result = self.run_fixture(scenario)
                self.assertEqual(facts["events"], [], result.stdout)
                self.assertFalse(facts["listener"])
                self.assertIsNone(facts["entry"])
                self.assertIsNone(facts["returned"])

    def test_source_change_before_event_is_checked_before_getters(self):
        facts, result = self.run_fixture("source-before-event")
        self.assertFalse(any(item.startswith("getter:") for item in facts["events"]))
        self.assertIsNone(facts["entry"])
        self.assertFalse(facts["listener"], result.stdout)

    def test_getter_types_null_unknown_and_count_changes_fail_closed(self):
        for scenario in (
            "getter-failure", "folder-null", "folder-relative", "unknown-enum",
            "boolean-int", "running-null", "missing-property", "null-collection",
            "count-null", "count-boolean", "count-negative", "count-budget",
            "count-change", "null-item", "preference-null", "preference-change",
        ):
            with self.subTest(scenario=scenario):
                facts, result = self.run_fixture(scenario)
                self.assertFalse(facts["listener"], result.stdout)
                self.assertIsNone(facts["entry"])
                self.assertIsNone(facts["returned"])
                self.assertIn("Controlled startup refused/UNKNOWN", result.stdout)

    def test_raw_manifest_is_strict_json_object_and_bounded(self):
        for scenario in (
            "manifest-null", "manifest-empty", "manifest-number", "manifest-malformed",
            "manifest-duplicate", "manifest-nonfinite", "manifest-array",
            "manifest-budget", "audit-budget",
        ):
            with self.subTest(scenario=scenario):
                facts, result = self.run_fixture(scenario)
                self.assertFalse(facts["listener"], result.stdout)
                self.assertIsNone(facts["entry"])
                self.assertIsNone(facts["returned"])

    def test_genuine_zero_count_is_not_a_failure_fallback(self):
        facts, result = self.run_fixture("empty")
        self.assertTrue(facts["listener"], result.stdout)
        self.assertEqual(facts["entry"]["startupAudit"]["scripts"], {
            "countBefore": 0, "countAfter": 0, "items": []})
        self.assertNotIn("complete", facts["entry"]["startupAudit"])

    def test_reentry_and_concurrent_source_or_input_mutation_cannot_publish(self):
        for scenario in ("recursive-audit", "source-change", "intent-change", "profile-change"):
            with self.subTest(scenario=scenario):
                facts, result = self.run_fixture(scenario)
                self.assertIsNone(facts["entry"])
                self.assertIsNone(facts["returned"])
                self.assertFalse(facts["listener"], result.stdout)

    def test_tampered_original_entry_cannot_start_admission(self):
        facts, result = self.run_fixture("entry-tamper")
        self.assertEqual(facts["entry"], {}, result.stdout)
        self.assertIsNone(facts["returned"])
        self.assertFalse(facts["listener"])

    def test_queue_timeout_does_not_fall_back_to_direct_getters(self):
        for scenario in ("timeout-before-event", "audit-timeout"):
            with self.subTest(scenario=scenario):
                facts, result = self.run_fixture(scenario)
                self.assertIsNone(facts["entry"])
                self.assertIsNone(facts["returned"])
                self.assertFalse(facts["listener"], result.stdout)
                if scenario == "timeout-before-event":
                    self.assertFalse(any(item.startswith("getter:") for item in facts["events"]))

    def test_duplicate_and_replayed_start_do_not_repeat_sdk_audit(self):
        for scenario in ("duplicate-schedule", "replay"):
            with self.subTest(scenario=scenario):
                facts, result = self.run_fixture(scenario)
                self.assertTrue(facts["listener"], result.stdout)
                self.assertEqual(facts["events"].count("getter:scripts"), 1)
                self.assertIn("Failed to start", result.stdout)

    def test_public_payload_cannot_select_private_startup_queue_operation(self):
        facts, result = self.run_fixture("public-spoof")
        self.assertTrue(facts["listener"], result.stdout)
        self.assertIn("public-spoof-denied", facts["events"])
        self.assertEqual(facts["events"].count("getter:scripts"), 1)

    def test_existing_shared_lock_delays_audit_without_direct_fallback(self):
        facts, result = self.run_fixture("queue-lock-held")
        self.assertTrue(facts["listener"], result.stdout)
        self.assertLess(facts["events"].index("shared-lock-delayed-audit"),
                        facts["events"].index("getter:version"))

    def test_background_custom_event_cannot_read_sdk(self):
        facts, result = self.run_fixture("background-event")
        self.assertFalse(facts["listener"], result.stdout)
        self.assertIsNone(facts["entry"])
        self.assertFalse(any(item.startswith("getter:") for item in facts["events"]))

    def test_addon_failure_preserves_audit_but_never_success_return(self):
        facts, result = self.run_fixture("addon-import-failure")
        self.assertIsNotNone(facts["entry"], result.stdout)
        self.assertIsNone(facts["returned"])
        self.assertFalse(facts["listener"])

    def test_controlled_start_and_stop_never_import_optional_commands(self):
        facts, result = self.run_fixture("controlled-stop")
        self.assertTrue(facts["listener"], result.stdout)
        self.assertIn("controlled-stop-returned", facts["events"])
        self.assertNotIn("forbidden-commands-import", facts["events"])
