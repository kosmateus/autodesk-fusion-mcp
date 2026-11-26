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
    "purpose": "bootstrap-entry-data-v1", "engineVersion": 2,
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
if scenario == "legacy-isolated-purpose": intent["purpose"] = "isolated-stdout-v1"
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
            "legacy-isolated-purpose",
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


class BootstrapDiagnosticTests(unittest.TestCase):
    """Real private writer/entrypoint, explicit offline scheduling/SDK ports."""

    @classmethod
    def setUpClass(cls):
        import importlib
        import types
        package = types.ModuleType("diagnostic_fixture_addin")
        package.__path__ = [str(ROOT)]
        sys.modules[package.__name__] = package
        cls.package = package.__name__
        cls.entry_module = importlib.import_module(cls.package + ".lib.bootstrap_entry")
        cls.boot = importlib.import_module(cls.package + ".AutodeskFusionMCP")

    def setUp(self):
        from unittest.mock import patch
        self.patch = patch
        temporary = tempfile.TemporaryDirectory(prefix="bootstrap-diagnostic-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.root.chmod(0o700)
        if os.name == "nt":
            import csv
            sid = list(csv.reader(subprocess.check_output(
                ["whoami.exe", "/user", "/fo", "csv", "/nh"], text=True).strip().splitlines()))[0][1]
            subprocess.run(["icacls.exe", str(self.root), "/inheritance:r", "/grant:r",
                            "*" + sid + ":(OI)(CI)F", "*S-1-5-18:(OI)(CI)F",
                            "*S-1-5-32-544:(OI)(CI)F"], check=True, capture_output=True)
        self.intent_path = self.root / "intent.json"
        self.enterContext(patch.dict(os.environ, FUSION_MCP_BOOTSTRAP_INTENT=str(self.intent_path)))
        self.intent = {
            "kind": "fmcad-bootstrap-entry-intent", "version": 3, "mode": "owned-autoload-v1",
            "nonce": "a" * 32, "purpose": "isolated-stdout-v1", "engineVersion": 2,
            "process": {"pid": os.getpid(), "birth": self.entry_module.observe_process_birth(os.getpid())},
            "installed": {}, "profile": {}, "receipts": {}, "executable": {},
            "provision": {}, "generation": {},
        }
        self.write_intent()

    def write_intent(self):
        self.intent_path.write_text(json.dumps(self.intent))
        self.intent_path.chmod(0o600)

    def report(self, phase="constructor", error=None):
        return self.entry_module.report_bootstrap_failure(
            str(self.intent_path), phase, error or ValueError("SECRET-TOKEN /private/user/intent"))

    def artifacts(self):
        return list(self.root.glob("bootstrap-failure-*.json"))

    def test_private_sanitized_facts_not_receipt_and_no_secret_fields(self):
        namespace = {}
        exec(compile("def SECRET_TOKEN_FUNCTION():\n raise ValueError('SECRET_TOKEN_MESSAGE')",
                     "/SECRET_TOKEN_DIRECTORY/SECRET_TOKEN_FILE.py", "exec"), namespace)
        try:
            namespace["SECRET_TOKEN_FUNCTION"]()
        except ValueError as error:
            self.assertTrue(self.report(error=error))
        files = self.artifacts()
        self.assertEqual(len(files), 1)
        raw = files[0].read_text()
        data = json.loads(raw)
        self.assertNotIn("SECRET_TOKEN", raw)
        self.assertNotIn(str(self.root), raw)
        self.assertEqual(data["phase"], "constructor")
        self.assertEqual(data["exceptionClass"], "ValueError")
        self.assertEqual(data["authority"], "NONE")
        self.assertFalse(data["receipt"])
        self.assertFalse(data["ready"])
        self.assertEqual(data["historicalOutcome"], "UNKNOWN_UNCHANGED")
        self.assertTrue(data["stack"])
        self.assertEqual(set(data["stack"][0]), {"file", "function", "line"})
        self.assertFalse((self.root / "entry.json").exists())
        self.assertFalse((self.root / "returned.json").exists())
        self.entry_module._read(files[0])  # Real private ACL/regular-file reader.
        if os.name != "nt":
            self.assertEqual(files[0].stat().st_mode & 0o777, 0o600)

    def test_invalid_process_intent_and_paths_never_publish(self):
        original = json.loads(json.dumps(self.intent))
        for change in [
            lambda i: i["process"].update(pid=os.getpid() + 1),
            lambda i: i["process"].update(birth="wrong"),
            lambda i: i.update(nonce="../outside"),
            lambda i: i.update(version=1),
            lambda i: i.update(extra=True),
        ]:
            self.intent = json.loads(json.dumps(original))
            change(self.intent)
            self.write_intent()
            self.assertFalse(self.report())
            self.assertEqual(self.artifacts(), [])
        self.intent = original
        self.write_intent()
        with self.patch.object(self.entry_module, "observe_process_birth", side_effect=OSError("SECRET")):
            self.assertFalse(self.report())
        with self.patch.object(self.entry_module, "_check_windows_acl", side_effect=PermissionError("SECRET")):
            self.assertFalse(self.report())
        self.assertFalse(self.entry_module.report_bootstrap_failure(
            str(self.root / ".." / self.root.name / "intent.json"), "audit", ValueError()))
        self.assertFalse(self.report(phase="../not-a-phase"))
        self.assertEqual(self.artifacts(), [])

    def test_foreign_receipt_paths_are_not_diagnostic_targets(self):
        self.intent["receipts"] = {"directory": "/foreign", "entry": "../outside", "returned": "/elsewhere"}
        self.write_intent()
        self.assertTrue(self.report())
        self.assertEqual(len(self.artifacts()), 1)
        self.assertEqual(len(list(self.root.iterdir())), 2)

    def test_existing_diagnostic_and_receipts_are_never_overwritten(self):
        for name in ["entry.json", "returned.json"]:
            (self.root / name).write_bytes(b"ORIGINAL")
        with self.patch.object(self.entry_module.os, "urandom", return_value=b"x" * 16):
            self.assertTrue(self.report())
            existing = self.artifacts()[0]
            before = existing.read_bytes()
            self.assertFalse(self.report(phase="audit"))
        self.assertEqual(existing.read_bytes(), before)
        self.assertEqual(len(self.artifacts()), 1)
        for name in ["entry.json", "returned.json"]:
            self.assertEqual((self.root / name).read_bytes(), b"ORIGINAL")

    def test_public_or_hardlinked_intent_refuses(self):
        if os.name == "nt":
            subprocess.run(["icacls.exe", str(self.intent_path), "/grant", "*S-1-1-0:R"],
                           check=True, capture_output=True)
        else:
            self.intent_path.chmod(0o644)
        self.assertFalse(self.report())
        self.assertEqual(self.artifacts(), [])

    def test_hardlinked_intent_refuses_without_artifact(self):
        os.link(self.intent_path, self.root / "alias.json")
        self.assertFalse(self.report())
        self.assertEqual(self.artifacts(), [])

    def test_current_environment_binding_is_required(self):
        with self.patch.dict(os.environ, FUSION_MCP_BOOTSTRAP_INTENT="other-intent.json"):
            self.assertFalse(self.report())
        self.assertEqual(self.artifacts(), [])

    def test_public_inherited_child_acl_refuses_before_publication(self):
        if os.name != "nt":
            self.root.chmod(0o755)
        else:
            subprocess.run(["icacls.exe", str(self.root), "/grant", "*S-1-1-0:(OI)(CI)(IO)R"],
                           check=True, capture_output=True)
        self.assertFalse(self.report())
        self.assertEqual(self.artifacts(), [])
        self.assertFalse(list(self.root.glob(".write-*")))

    def test_actual_entrypoint_and_async_consumer_faults_are_distinguished(self):
        import ast
        import contextlib
        import io
        import threading
        import types
        real_entry = self.entry_module.BootstrapEntry
        for scenario in ["constructor", "schedule", "audit", "queue-timeout"]:
            for old in self.artifacts():
                old.unlink()
            source = ast.parse((ROOT / "fusion_bridge/dispatch.py").read_text())
            consumer = next(n for n in source.body if isinstance(n, ast.FunctionDef)
                            and n.name == "_consume_bootstrap_entry")
            test = self
            class OfflineEntry:
                audited = True
                owned_autoload = True
                before_import = real_entry.before_import
                report_failure = real_entry.report_failure
                def __init__(self, intent_path, _):
                    self.intent_path = Path(intent_path)
                    self._begun, self.entry_bytes = False, None
                    self.returned_path = test.root / "returned.json"
                def run_queued(self, _):
                    raise RuntimeError("SECRET_AUDIT_MESSAGE")
                def refuse(self, _):
                    pass
            def schedule(entry, context):
                if scenario == "schedule":
                    raise ValueError("SECRET_SCHEDULE_MESSAGE")
                halt = threading.Event()
                envelope = {"_bootstrap_entry": entry, "_bootstrap_context": context,
                            "_state": "queued", "_lock": threading.Lock(), "_shutdown": halt,
                            "_bootstrap_timer": types.SimpleNamespace(cancel=lambda: None)}
                ports = {"__package__": self.package + ".fusion_bridge", "threading": threading,
                         "_startup_entry": None, "_running_handlers": 0,
                         "_lifecycle_lock": threading.Lock(), "_startup_ticket": envelope,
                         "_halt": halt, "request_main_thread_shutdown": lambda _: None}
                if scenario == "queue-timeout":
                    scheduling = next(n for n in source.body if isinstance(n, ast.FunctionDef)
                                      and n.name == "schedule_bootstrap_entry")
                    expired = next(n for n in scheduling.body if isinstance(n, ast.FunctionDef)
                                   and n.name == "expired")
                    ports.update(entry=entry, envelope=envelope, shutdown=halt, _try_remove=lambda _: None)
                    exec(compile(ast.Module(body=[expired], type_ignores=[]), "dispatch.py", "exec"), ports)
                    ports["expired"]()
                    return
                exec(compile(ast.Module(body=[consumer], type_ignores=[]), "dispatch.py", "exec"), ports)
                ports["_consume_bootstrap_entry"](envelope)
            dispatch = types.ModuleType(self.package + ".fusion_bridge.dispatch")
            dispatch.schedule_bootstrap_entry = schedule
            stdout, stderr = io.StringIO(), io.StringIO()
            with self.patch.dict(os.environ, FUSION_MCP_BOOTSTRAP_INTENT=str(self.intent_path)), \
                    self.patch.dict(sys.modules, {dispatch.__name__: dispatch}), \
                    self.patch.object(self.entry_module, "BootstrapEntry",
                                      real_entry if scenario == "constructor" else OfflineEntry), \
                    contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                self.boot.run({"offline": True})
            self.assertEqual(len(self.artifacts()), 1, scenario)
            data = json.loads(self.artifacts()[0].read_text())
            self.assertEqual(data["phase"], scenario)
            self.assertNotIn("SECRET_", self.artifacts()[0].read_text())
            self.assertNotIn("SECRET_", stdout.getvalue() + stderr.getvalue())
            self.assertFalse((self.root / "entry.json").exists())
            self.assertFalse((self.root / "returned.json").exists())
        self.assertFalse(any(n == "adsk" or n.startswith("adsk.") for n in sys.modules))


if __name__ == "__main__":
    unittest.main()
