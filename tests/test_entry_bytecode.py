"""Real entry/cold imports with ignored ENV; fake SDK/server, never Fusion."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
AUDIT_RUNNER = (ROOT / "tests/startup_audit_fixture.py").read_text()
ORDINARY_RUNNER = r'''
import json, os, pathlib, sys, types
package = pathlib.Path(sys.argv[1])
assert sys.flags.ignore_environment == 1
assert os.environ["PYTHONDONTWRITEBYTECODE"] == "1"
assert sys.dont_write_bytecode is False
os.environ.pop("FUSION_MCP_BOOTSTRAP_INTENT", None)
pkg = types.ModuleType("ordinary_fixture")
pkg.__path__ = [str(package)]
sys.modules[pkg.__name__] = pkg
entry = types.ModuleType("ordinary_fixture.AutodeskFusionMCP")
entry.__package__ = pkg.__name__
entry.__file__ = str(package / "AutodeskFusionMCP.py")
exec(compile(pathlib.Path(entry.__file__).read_bytes(), entry.__file__, "exec"), entry.__dict__)
entry.run({"ordinary": True})
print("ORDINARY_RESULT=" + json.dumps({
    "dontWriteBytecode": sys.dont_write_bytecode,
    "files": sorted(p.relative_to(package).as_posix() for p in package.rglob("*.pyc")),
    "bootstrapImported": "ordinary_fixture.lib.bootstrap_entry" in sys.modules,
}))
'''


class EntryBytecodeTests(unittest.TestCase):
    def fixture(self, scenario, loader_spelling="native"):
        temporary = tempfile.TemporaryDirectory(prefix="entry-bytecode-owned-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        package = root / "installed"
        package.mkdir(mode=0o700)
        (root / "private").mkdir(mode=0o700)
        for name in ("AutodeskFusionMCP.py", "AutodeskFusionMCP.manifest",
                     "addon_runtime.py", "settings.py", "config.py"):
            shutil.copyfile(ROOT / name, package / name)
        for name in ("lib", "fusion_bridge", "commands"):
            shutil.copytree(ROOT / name, package / name,
                            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        for file in package.rglob("*"):
            file.chmod(0o700 if file.is_dir() else 0o600)
        result = subprocess.run(
            [sys.executable, "-I", "-S", "-c", AUDIT_RUNNER,
              str(root), scenario, "ignored-bytecode-env", loader_spelling],
            env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"),
            capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        rows = [line.split("=", 1)[1] for line in result.stdout.splitlines()
                if line.startswith("FIXTURE_RESULT=")]
        self.assertEqual(len(rows), 1, result.stdout + result.stderr)
        return json.loads(rows[0]), result, package

    def test_owned_cold_imports_and_deferred_runtime_never_write_own_bytecode(self):
        facts, result, _ = self.fixture("owned-valid")
        self.assertEqual(facts["bytecode"]["initial"], False)
        self.assertEqual(facts["bytecode"]["ignoreEnvironment"], 1)
        self.assertTrue(facts["listener"], result.stdout + result.stderr)
        self.assertTrue(facts["bytecode"]["afterEntry"])
        self.assertTrue(facts["bytecode"]["afterDeferred"])
        self.assertEqual(facts["bytecode"]["files"], [])
        self.assertEqual(facts["entry"]["version"], 3)
        self.assertEqual(facts["returned"]["phase"], "run-returned")
        self.assertIn("vendor-utility-ui-getter", facts["events"])
        self.assertIn("listener-start", facts["events"])

    def test_manual_v2_keeps_audit_and_original_receipts_with_no_bytecode(self):
        facts, result, _ = self.fixture("valid")
        self.assertTrue(facts["listener"], result.stdout + result.stderr)
        self.assertEqual(facts["entry"]["version"], 2)
        self.assertEqual(facts["bytecode"]["files"], [])
        self.assertTrue(facts["bytecode"]["afterDeferred"])

    def test_owned_loader_forward_slashes_keep_original_receipt_pair(self):
        facts, result, _ = self.fixture("owned-valid", "forward-slash")
        self.assertTrue(facts["listener"], result.stdout + result.stderr)
        self.assertEqual(facts["entry"]["version"], 3)
        self.assertEqual(facts["returned"]["phase"], "run-returned")
        self.assertEqual(facts["bytecode"]["files"], [])

    def test_manual_v2_loader_forward_slashes_keep_original_receipt_pair(self):
        facts, result, _ = self.fixture("valid", "forward-slash")
        self.assertTrue(facts["listener"], result.stdout + result.stderr)
        self.assertEqual(facts["entry"]["version"], 2)
        self.assertEqual(facts["returned"]["phase"], "run-returned")
        self.assertEqual(facts["bytecode"]["files"], [])

    def test_loader_relative_parent_alias_and_different_entry_are_refused(self):
        for spelling in ("relative", "parent-alias", "different-entry", "linked-parent"):
            with self.subTest(spelling=spelling):
                facts, result, _ = self.fixture("owned-valid", spelling)
                self.assertFalse(facts["listener"], result.stdout + result.stderr)
                self.assertIsNone(facts["entry"])
                self.assertIsNone(facts["returned"])
                self.assertEqual(facts["events"], [])
                self.assertEqual(facts["bytecode"]["files"], [])

    @unittest.skipUnless(os.name == "nt", "Windows intent path spelling contract")
    def test_loader_normalization_does_not_normalize_intent_paths(self):
        facts, result, _ = self.fixture(
            "owned-noncanonical-profile-path", "forward-slash")
        self.assertFalse(facts["listener"], result.stdout + result.stderr)
        self.assertIsNone(facts["entry"])
        self.assertIsNone(facts["returned"])
        self.assertEqual(facts["events"], [])
        self.assertEqual(facts["bytecode"]["files"], [])

    def test_preexisting_cache_is_not_ignored_removed_or_authorized(self):
        facts, result, package = self.fixture("owned-preexisting-cache")
        self.assertFalse(facts["listener"], result.stdout + result.stderr)
        self.assertIsNone(facts["entry"])
        self.assertIsNone(facts["returned"])
        file = "lib/__pycache__/unlisted.cpython-314.pyc"
        self.assertEqual((package / file).read_bytes(), b"ORIGINAL-UNLISTED-CACHE")
        self.assertEqual(facts["bytecode"]["files"], [file])
        self.assertFalse(any(e.startswith("getter:") for e in facts["events"]))

    def test_intent_presence_does_not_approve_wrong_owned_mode(self):
        facts, result, _ = self.fixture("owned-bad-mode")
        self.assertFalse(facts["listener"], result.stdout + result.stderr)
        self.assertIsNone(facts["entry"])
        self.assertIsNone(facts["returned"])
        self.assertEqual(facts["events"], [])
        self.assertEqual(facts["bytecode"]["files"], [])

    def test_normal_start_without_intent_preserves_original_runtime_policy(self):
        temporary = tempfile.TemporaryDirectory(prefix="entry-bytecode-ordinary-")
        self.addCleanup(temporary.cleanup)
        package = Path(temporary.name)
        shutil.copyfile(ROOT / "AutodeskFusionMCP.py", package / "AutodeskFusionMCP.py")
        (package / "ordinary_probe.py").write_text("VALUE = 'ordinary'\n")
        (package / "addon_runtime.py").write_text(
            "from . import ordinary_probe\n"
            "def run(context):\n"
            "    assert context == {'ordinary': True}\n"
            "    assert ordinary_probe.VALUE == 'ordinary'\n")
        result = subprocess.run(
            [sys.executable, "-I", "-S", "-c", ORDINARY_RUNNER, str(package)],
            env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"),
            capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        rows = [line.split("=", 1)[1] for line in result.stdout.splitlines()
                if line.startswith("ORDINARY_RESULT=")]
        self.assertEqual(len(rows), 1, result.stdout + result.stderr)
        facts = json.loads(rows[0])
        self.assertFalse(facts["dontWriteBytecode"])
        self.assertFalse(facts["bootstrapImported"])
        self.assertEqual(len(facts["files"]), 2)


if __name__ == "__main__":
    unittest.main()
