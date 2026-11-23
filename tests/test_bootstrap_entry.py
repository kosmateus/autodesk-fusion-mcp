"""Whole-entrypoint SDK-free subprocess tests; no Fusion or native server."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
RUNNER = r'''
import hashlib, importlib.util, json, os, pathlib, subprocess, sys, types
root = pathlib.Path(sys.argv[1])
scenario = sys.argv[2]
package = root / "installed"
private = root / "private"
sys.path.insert(0, str(package))
from lib.rebaseline_fence import observe_process_birth
sha = lambda b: hashlib.sha256(b).hexdigest()
profile = private / "profile.json"
profile.write_bytes(b'{"controlledProfile":"fixture-not-authority"}')
profile.chmod(0o600)
intent_file = private / "intent.json"
intent = {
    "kind": "fmcad-bootstrap-entry-intent", "version": 1, "nonce": "a" * 32,
    "process": {"pid": os.getpid(), "birth": observe_process_birth(os.getpid())},
    "purpose": "isolated-stdout-v1", "engineVersion": 2,
    "installed": {
        "directory": str(package), "source": "b" * 40,
        "files": {str(p.relative_to(package)).replace(os.sep, "/"): sha(p.read_bytes())
                  for p in package.rglob("*") if p.is_file()}
    },
    "profile": {"path": str(profile), "sha256": sha(profile.read_bytes())},
    "receipts": {"directory": str(private), "entry": "entry.json", "returned": "returned.json"}
}
if scenario == "wrong-birth": intent["process"]["birth"] += "-wrong"
if scenario == "wrong-pid": intent["process"]["pid"] += 1
if scenario == "wrong-hash": intent["installed"]["files"]["addon_runtime.py"] = "0" * 64
if scenario == "wrong-profile": intent["profile"]["sha256"] = "0" * 64
if scenario == "wrong-path": intent["installed"]["directory"] += "/../installed"
if scenario == "wrong-source": intent["installed"]["source"] = "not-a-pin"
if scenario == "wrong-purpose": intent["purpose"] = "raw"
if scenario == "boolean-version": intent["version"] = True
if scenario == "boolean-engine": intent["engineVersion"] = True
if scenario == "extra-field": intent["fresh"] = True
if scenario == "traversal": intent["installed"]["files"]["../outside.py"] = "0" * 64
if scenario == "same-output": intent["receipts"]["returned"] = "entry.json"
if scenario == "case-alias-output": intent["receipts"]["returned"] = "ENTRY.json"
if scenario == "reserved-output": intent["receipts"]["entry"] = "con.json"
if scenario == "reserved-com-output": intent["receipts"]["entry"] = "com1.json"
if scenario == "reserved-lpt-output": intent["receipts"]["entry"] = "lpt9.json"
if scenario == "trailing-dot-output": intent["receipts"]["entry"] = "entry.json."
if scenario == "trailing-space-output": intent["receipts"]["entry"] = "entry.json "
if scenario == "output-traversal": intent["receipts"]["entry"] = "../entry.json"
if scenario == "output-in-source": intent["receipts"]["directory"] = str(package)
raw = json.dumps(intent).encode()
if scenario == "malformed": raw = b'{"broken":'
if scenario == "duplicate-key": raw = raw[:-1] + b', "version":1}'
if scenario == "invalid-utf8": raw = raw[:-1] + b'\xff}'
intent_file.write_bytes(raw)
intent_file.chmod(0o600)
def make_public(path, mode):
    if os.name == "nt":
        subprocess.run([str(pathlib.Path(os.environ["SystemRoot"]) / "System32" / "icacls.exe"),
                        str(path), "/grant", "*S-1-1-0:R"], check=True, capture_output=True)
    else:
        path.chmod(mode)
if scenario == "public-intent": make_public(intent_file, 0o644)
if scenario == "public-directory": make_public(private, 0o755)
if scenario == "public-source": make_public(package / "addon_runtime.py", 0o644)
if scenario == "extra-source":
    (package / "unexpected.py").write_text("pass")
    (package / "unexpected.py").chmod(0o600)
if scenario == "mutated-source":
    with (package / "addon_runtime.py").open("a") as f: f.write("\n# changed")
if scenario == "symlink-source":
    try:
        (package / "alias.py").symlink_to(package / "addon_runtime.py")
    except OSError as exc:
        if os.name == "nt" and exc.winerror == 1314:
            print("FIXTURE_NOTRUN=WINDOWS_SYMLINK_PRIVILEGE_UNAVAILABLE"); sys.exit(77)
        raise
if scenario == "symlink-intent":
    alias = private / "alias.json"
    try:
        alias.symlink_to(intent_file)
    except OSError as exc:
        if os.name == "nt" and exc.winerror == 1314:
            print("FIXTURE_NOTRUN=WINDOWS_SYMLINK_PRIVILEGE_UNAVAILABLE"); sys.exit(77)
        raise
    intent_file = alias
if scenario == "hardlink-intent":
    alias = private / "hardlink.json"; os.link(intent_file, alias); intent_file = alias
if scenario == "junction-source":
    subprocess.run([str(pathlib.Path(os.environ["SystemRoot"]) / "System32" / "cmd.exe"),
                    "/d", "/c", "mklink", "/J", str(package / "junction"), str(package / "lib")],
                   check=True, capture_output=True)
if scenario == "preexisting-entry":
    (private / "entry.json").write_bytes(b"ORIGINAL"); (private / "entry.json").chmod(0o600)
if scenario == "preexisting-return":
    (private / "returned.json").write_bytes(b"ORIGINAL"); (private / "returned.json").chmod(0o600)
if not scenario.startswith("absent"): os.environ["FUSION_MCP_BOOTSTRAP_INTENT"] = str(intent_file)
if scenario == "empty-env": os.environ["FUSION_MCP_BOOTSTRAP_INTENT"] = ""
os.environ["FIXTURE_SCENARIO"] = scenario
os.environ["FIXTURE_PRIVATE"] = str(private)
pkg = types.ModuleType("fixture_addin")
pkg.__path__ = [str(package)]
sys.modules["fixture_addin"] = pkg
spec = importlib.util.spec_from_file_location("fixture_addin.AutodeskFusionMCP", package / "AutodeskFusionMCP.py")
entry = importlib.util.module_from_spec(spec); spec.loader.exec_module(entry)
entry.run({"fixture": True})
if scenario == "replay": entry.run({"fixture": True})
if scenario == "valid" and os.name == "nt":
    from lib.physical_authority import _check_windows_acl
    _check_windows_acl(private / "entry.json")
    _check_windows_acl(private / "returned.json")
    print("RECEIPT_ACL_PRIVATE=True")
print("SDK_MODULES=" + json.dumps([m for m in sys.modules if m == "adsk" or m.startswith("adsk.")]))
'''

ADDON = '''
import json, os
from pathlib import Path
private = Path(os.environ["FIXTURE_PRIVATE"])
scenario = os.environ["FIXTURE_SCENARIO"]
with (private / "events").open("a") as f:
    f.write("import\\n")
if not scenario.startswith("absent"):
    entry = json.loads((private / "entry.json").read_text())
    assert entry["phase"] == "entry-before-addon-import"
    assert not (private / "returned.json").exists()
if scenario == "import-failure":
    raise RuntimeError("FIXTURE_IMPORT_FAILURE")

def run(context):
    assert context == {"fixture": True}
    with (private / "events").open("a") as f:
        f.write("run\\n")
    if scenario in ("run-failure", "absent-run-failure"):
        raise RuntimeError("FIXTURE_RUN_FAILURE")
    if scenario == "mutate-intent-during-run":
        (private / "intent.json").write_text("{}")
    if scenario == "mutate-profile-during-run":
        (private / "profile.json").write_text("{}")
    if scenario == "mutate-source-during-run":
        with Path(__file__).open("a") as f:
            f.write("\\n# changed during run")
    if scenario == "mutate-entry-during-run":
        (private / "entry.json").write_text("{}")
    if scenario == "create-return-during-run":
        (private / "returned.json").write_bytes(b"ORIGINAL")
        (private / "returned.json").chmod(0o600)
'''


class BootstrapEntryTests(unittest.TestCase):
    def run_fixture(self, scenario):
        temporary = tempfile.TemporaryDirectory(prefix="bootstrap-entry-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        package = root / "installed"
        private = root / "private"
        package.mkdir(mode=0o700)
        (package / "lib").mkdir(mode=0o700)
        private.mkdir(mode=0o700)
        for name in (
            "AutodeskFusionMCP.py", "lib/bootstrap_entry.py", "lib/admission_json.py",
            "lib/physical_authority.py", "lib/rebaseline_fence.py",
            "lib/rebaseline_fence_store.py", "lib/request_admission.py",
        ):
            destination = package / name
            destination.write_bytes((ROOT / name).read_bytes())
            destination.chmod(0o600)
        (package / "addon_runtime.py").write_text(ADDON)
        (package / "addon_runtime.py").chmod(0o600)
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        env.pop("FUSION_MCP_BOOTSTRAP_INTENT", None)
        result = subprocess.run(
            [sys.executable, "-I", "-B", "-c", RUNNER, str(root), scenario],
            env=env, text=True, capture_output=True, timeout=15,
        )
        if result.returncode == 77 and "FIXTURE_NOTRUN=WINDOWS_SYMLINK_PRIVILEGE_UNAVAILABLE" in result.stdout:
            self.skipTest("Actual Windows symlink fixture NOTRUN: token lacks SeCreateSymbolicLinkPrivilege")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("SDK_MODULES=[]", result.stdout)
        return private, result

    def test_absent_intent_preserves_ordinary_import_and_run(self):
        private, result = self.run_fixture("absent")
        self.assertEqual((private / "events").read_text(), "import\nrun\n")
        self.assertFalse((private / "entry.json").exists())
        self.assertFalse((private / "returned.json").exists())
        self.assertNotIn("Failed to start", result.stdout)

    def test_valid_entry_and_return_are_original_bound_facts(self):
        import hashlib
        private, result = self.run_fixture("valid")
        self.assertEqual((private / "events").read_text(), "import\nrun\n")
        entry_bytes = (private / "entry.json").read_bytes()
        entry = json.loads(entry_bytes)
        returned = json.loads((private / "returned.json").read_bytes())
        intent_bytes = (private / "intent.json").read_bytes()
        intent = json.loads(intent_bytes)
        self.assertEqual(entry["phase"], "entry-before-addon-import")
        self.assertEqual(returned["phase"], "run-returned")
        self.assertEqual(entry["process"], intent["process"])
        self.assertEqual(entry["nonce"], intent["nonce"])
        for key in ("nonce", "process", "intent", "profile", "installed", "purpose", "engineVersion"):
            self.assertEqual(entry[key], returned[key])
        self.assertEqual(entry["intent"], {
            "path": str(private / "intent.json"), "sha256": hashlib.sha256(intent_bytes).hexdigest()})
        self.assertEqual(returned["entry"], {
            "path": str(private / "entry.json"), "sha256": hashlib.sha256(entry_bytes).hexdigest()})
        self.assertNotIn("ready", returned)
        self.assertNotIn("clean", returned)
        if os.name == "nt":
            self.assertIn("RECEIPT_ACL_PRIVATE=True", result.stdout)
        else:
            self.assertEqual((private / "entry.json").stat().st_mode & 0o777, 0o600)
        self.assertNotIn("Failed to start", result.stdout)

    def test_invalid_intents_never_import_addon_runtime(self):
        scenarios = (
            "malformed", "duplicate-key", "invalid-utf8", "wrong-birth", "wrong-pid",
            "wrong-hash", "wrong-profile", "wrong-path", "wrong-source", "wrong-purpose",
            "boolean-version", "boolean-engine", "extra-field", "traversal", "same-output",
            "case-alias-output", "reserved-output",
            "reserved-com-output", "reserved-lpt-output", "trailing-dot-output",
            "trailing-space-output",
            "output-traversal", "output-in-source", "public-intent", "public-directory",
            "public-source", "extra-source", "mutated-source", "symlink-source",
            "symlink-intent", "empty-env",
        )
        if os.name == "nt":
            scenarios += ("hardlink-intent", "junction-source")
        for scenario in scenarios:
            with self.subTest(scenario=scenario):
                private, result = self.run_fixture(scenario)
                self.assertFalse((private / "events").exists())
                self.assertFalse((private / "entry.json").exists())
                self.assertFalse((private / "returned.json").exists())
                self.assertIn("Failed to start", result.stdout)

    def test_existing_receipts_are_never_overwritten_or_resumed(self):
        for scenario, name in (
            ("preexisting-entry", "entry.json"), ("preexisting-return", "returned.json"),
        ):
            with self.subTest(scenario=scenario):
                private, result = self.run_fixture(scenario)
                self.assertEqual((private / name).read_bytes(), b"ORIGINAL")
                self.assertFalse((private / "events").exists())
                self.assertIn("Failed to start", result.stdout)

    def test_failed_run_leaves_entry_only(self):
        private, result = self.run_fixture("run-failure")
        self.assertEqual((private / "events").read_text(), "import\nrun\n")
        self.assertTrue((private / "entry.json").exists())
        self.assertFalse((private / "returned.json").exists())
        self.assertIn("FIXTURE_RUN_FAILURE", result.stdout)

    def test_failed_import_leaves_entry_only(self):
        private, result = self.run_fixture("import-failure")
        self.assertEqual((private / "events").read_text(), "import\n")
        self.assertTrue((private / "entry.json").exists())
        self.assertFalse((private / "returned.json").exists())
        self.assertIn("FIXTURE_IMPORT_FAILURE", result.stdout)

    def test_absent_intent_preserves_ordinary_failure_handling(self):
        private, result = self.run_fixture("absent-run-failure")
        self.assertEqual((private / "events").read_text(), "import\nrun\n")
        self.assertFalse((private / "entry.json").exists())
        self.assertFalse((private / "returned.json").exists())
        self.assertIn("Failed to start: FIXTURE_RUN_FAILURE", result.stdout)

    def test_changed_fences_during_run_never_emit_success(self):
        for scenario in (
            "mutate-intent-during-run", "mutate-profile-during-run",
            "mutate-source-during-run", "mutate-entry-during-run",
        ):
            with self.subTest(scenario=scenario):
                private, result = self.run_fixture(scenario)
                self.assertEqual((private / "events").read_text(), "import\nrun\n")
                self.assertTrue((private / "entry.json").exists())
                self.assertFalse((private / "returned.json").exists())
                self.assertIn("Failed to start", result.stdout)

    def test_exclusive_return_write_preserves_competing_original(self):
        private, result = self.run_fixture("create-return-during-run")
        self.assertTrue((private / "entry.json").exists())
        self.assertEqual((private / "returned.json").read_bytes(), b"ORIGINAL")
        self.assertIn("Failed to start", result.stdout)

    def test_replay_does_not_import_or_run_again(self):
        private, result = self.run_fixture("replay")
        self.assertEqual((private / "events").read_text(), "import\nrun\n")
        self.assertTrue((private / "entry.json").exists())
        self.assertTrue((private / "returned.json").exists())
        self.assertIn("Failed to start", result.stdout)


if __name__ == "__main__":
    unittest.main()
