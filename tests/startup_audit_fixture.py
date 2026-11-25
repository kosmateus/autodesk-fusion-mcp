"""Whole controlled-start fixture: real producer/runtime/queue, explicit fake SDK.

Run only as a benign subprocess with an owned copied package and private files.
The fake server never opens a socket; its start method observes startup ordering.
"""

import hashlib
import importlib
import importlib.abc
import json
import os
from pathlib import Path
import queue
import sys
import threading
import time
import types


root = Path(sys.argv[1])
scenario = sys.argv[2]
ignored_bytecode_env = len(sys.argv) > 3 and sys.argv[3] == "ignored-bytecode-env"
initial_bytecode_policy = sys.dont_write_bytecode
if ignored_bytecode_env:
    assert sys.flags.ignore_environment == 1
    assert os.environ["PYTHONDONTWRITEBYTECODE"] == "1"
    assert initial_bytecode_policy is False, "Child must not inherit a -B policy"
    # Fixture preparation is not Fusion entry. Do not warm its source tree with
    # cache, then unload these setup-only modules before the real cold imports.
    sys.dont_write_bytecode = True
owned = scenario.startswith("owned-")
if owned:
    scenario = scenario[len("owned-"):]
package = root / "installed"
private = root / "private"
events = []
errors = []
signals = queue.Queue()
started = threading.Event()
event = None
sha = lambda data: hashlib.sha256(data).hexdigest()
pkg = types.ModuleType("audit_fixture")
pkg.__path__ = [str(package)]
sys.modules["audit_fixture"] = pkg
sys.path.insert(0, str(package))
from audit_fixture.lib.rebaseline_fence import observe_process_birth
from audit_fixture.lib.bootstrap_entry import _process_image

profile = private / "profile.json"
profile.write_bytes(b'{"owned":"SDK-free fixture, not authority"}')
profile.chmod(0o600)
intent_file = private / "intent.json"
image = _process_image()
provision_file = private / "provision.json"
if owned:
    from audit_fixture.lib.request_admission import AdmissionStore
    database = private / "admission.sqlite"
    store = AdmissionStore(database, instance="fixture-instance", epoch="fixture-epoch")
    store.close()
    provision = {
        "database": str(database), "pid": os.getpid(),
        "birth": observe_process_birth(os.getpid()),
        "instance": "fixture-instance", "epoch": "fixture-epoch",
        "source": "broker-source", "build": "broker-build",
        "credentials": {"fixture-token-" + "a" * 32: "fixture-owner"},
    }
    provision_file.write_text(json.dumps(provision))
    provision_file.chmod(0o600)
    from audit_fixture.lib import physical_authority
    physical_authority.authority_directory = lambda: private / "physical"
intent = {
    "kind": "fmcad-bootstrap-entry-intent", "version": 2, "nonce": "a" * 32,
    "process": {"pid": os.getpid(), "birth": observe_process_birth(os.getpid())},
    "purpose": "isolated-stdout-v1", "engineVersion": 2,
    "executable": {"path": str(image), "sha256": sha(image.read_bytes())},
    "installed": {"directory": str(package), "source": "b" * 40,
                  "files": {p.relative_to(package).as_posix(): sha(p.read_bytes())
                            for p in package.rglob("*") if p.is_file()}},
    "profile": {"path": str(profile), "sha256": sha(profile.read_bytes())},
    "receipts": {"directory": str(private), "entry": "entry.json", "returned": "returned.json"},
}
if owned:
    intent.update(
        version=3, mode="owned-autoload-v1",
        provision={"path": str(provision_file), "sha256": sha(provision_file.read_bytes())},
        generation={"instance": "fixture-instance", "epoch": "fixture-epoch"})
    if scenario == "bad-mode": intent["mode"] = "manual"
    if scenario == "bad-version": intent["version"] = 4
    if scenario == "boolean-version": intent["version"] = True
    if scenario == "boolean-engine": intent["engineVersion"] = True
    if scenario == "v2-with-owned-fields": intent["version"] = 2
    if scenario == "missing-mode": del intent["mode"]
    if scenario == "missing-provision": del intent["provision"]
    if scenario == "missing-generation": del intent["generation"]
    if scenario == "missing-epoch": del intent["generation"]["epoch"]
    if scenario == "extra-field": intent["owned"] = True
    if scenario == "extra-generation": intent["generation"]["owned"] = True
    if scenario == "boolean-generation": intent["generation"]["instance"] = True
    if scenario == "bad-generation": intent["generation"]["epoch"] = "wrong"
    if scenario == "bad-provision-hash": intent["provision"]["sha256"] = "0" * 64
    if scenario == "extra-provision": intent["provision"]["owned"] = True
    if scenario == "missing-provision-sha": del intent["provision"]["sha256"]
    if scenario == "boolean-mode": intent["mode"] = True
    if scenario.startswith("provision-"):
        field = scenario[len("provision-"):]
        if field == "extra": provision["owned"] = True
        elif field == "pid": provision["pid"] += 1
        elif field == "boolean-pid": provision["pid"] = True
        elif field == "generation": provision["epoch"] += "-wrong"
        elif field == "birth": provision["birth"] += "-wrong"
        elif field == "credentials": provision["credentials"] = {}
        elif field == "database": provision["database"] = "relative.sqlite"
        elif field == "source": provision["source"] = False
        elif field == "missing-build": del provision["build"]
        provision_file.write_text(json.dumps(provision))
        if field == "duplicate":
            provision_file.write_text(json.dumps(provision)[:-1] + ', "pid":1}')
        if field == "malformed": provision_file.write_text("{")
        intent["provision"]["sha256"] = sha(provision_file.read_bytes())
    if scenario == "public-provision":
        if os.name == "nt":
            import subprocess
            subprocess.run([
                str(Path(os.environ["SystemRoot"]) / "System32" / "icacls.exe"),
                str(provision_file), "/grant", "*S-1-1-0:R"],
                check=True, capture_output=True)
        else:
            provision_file.chmod(0o644)
    if scenario == "receipt-overwrites-provision":
        intent["receipts"]["entry"] = "provision.json"
    if scenario in ("preexisting-entry", "preexisting-returned"):
        name = scenario[len("preexisting-"):] + ".json"
        (private / name).write_text('{"original":"must survive"}')
        (private / name).chmod(0o600)
if scenario == "bad-intent":
    intent["process"]["birth"] += "-wrong"
if scenario == "bad-executable":
    intent["executable"]["sha256"] = "0" * 64
intent_file.write_text(json.dumps(intent))
intent_file.chmod(0o600)
os.environ["FUSION_MCP_BOOTSTRAP_INTENT"] = str(intent_file)
os.environ.pop("FUSION_MCP_ADMISSION_PROVISION", None)
if owned:
    os.environ["FUSION_MCP_ADMISSION_PROVISION"] = str(provision_file)
    if scenario == "missing-provision-env":
        del os.environ["FUSION_MCP_ADMISSION_PROVISION"]
    if scenario == "wrong-provision-env":
        os.environ["FUSION_MCP_ADMISSION_PROVISION"] += ".wrong"


def observe(field):
    events.append(field)
    if field.startswith("getter:"):
        from audit_fixture.fusion_bridge import dispatch
        assert threading.current_thread() is threading.main_thread(), field
        assert dispatch._run_lock.locked(), field
        assert dispatch._startup_entry is not None, field
        assert not started.is_set(), "Public admission/listener preceded audit"


class Script:
    def __init__(self, index):
        object.__setattr__(self, "index", index)

    def __setattr__(self, name, value):
        raise AssertionError("No SDK property setters: " + name)

    @property
    def folder(self):
        observe("getter:folder")
        if scenario == "recursive-audit":
            from audit_fixture.fusion_bridge import dispatch
            dispatch._startup_entry.run_queued({})
        if scenario == "getter-failure":
            raise RuntimeError("owned fake SDK getter failure")
        if scenario == "folder-null":
            return None
        if scenario == "folder-relative":
            return "relative/folder"
        if owned and self.index == 0 and scenario != "missing-own":
            return str(package)
        if owned and scenario == "duplicate-own":
            return str(package)
        return str(root / ("script-" + str(self.index)))

    @property
    def location(self):
        observe("getter:location")
        return 999 if scenario == "unknown-enum" else 30

    @property
    def isAddIn(self):
        observe("getter:isAddIn")
        return (1 if scenario == "boolean-int" else
                self.index == 0 and scenario != "own-is-script"
                or (owned and scenario in (
                    "foreign-startup", "foreign-addin-off", "duplicate-own")))

    @property
    def isRunOnStartup(self):
        observe("getter:isRunOnStartup")
        if self.index != 0 and scenario not in (
                "foreign-startup", "foreign-addin-off", "duplicate-own"):
            raise AssertionError("SDK forbids startup getter for a script")
        if owned:
            return (self.index == 0 and scenario != "own-startup-off"
                    or self.index != 0 and scenario in ("foreign-startup", "duplicate-own"))
        return False

    @property
    def isRunning(self):
        observe("getter:isRunning")
        return (None if scenario == "running-null" else
                (self.index == 0 and scenario != "own-not-running")
                or (owned and scenario in ("foreign-running", "duplicate-own")))

    @property
    def isVisible(self):
        observe("getter:isVisible")
        if scenario == "missing-property":
            raise AttributeError("isVisible unavailable")
        return False if self.index else True

    @property
    def manifestContent(self):
        observe("getter:manifestContent")
        if scenario == "source-change" and self.index == 0:
            with (package / "settings.py").open("a") as stream:
                stream.write("\n# owned concurrent source change\n")
        if scenario == "intent-change":
            intent_file.write_text("{}")
        if scenario == "profile-change":
            profile.write_text("{}")
        if scenario == "provision-change":
            provision_file.write_text("{}")
        if scenario == "provision-env-change":
            os.environ.pop("FUSION_MCP_ADMISSION_PROVISION", None)
        if scenario == "audit-timeout":
            time.sleep(0.05)
        if scenario == "manifest-null":
            return None
        if scenario == "manifest-empty":
            return ""
        if scenario == "manifest-number":
            return 123
        if scenario == "manifest-malformed":
            return "{"
        if scenario == "manifest-duplicate":
            return '{"x":1,"x":2}'
        if scenario == "manifest-nonfinite":
            return '{"x":NaN}'
        if scenario == "manifest-array":
            return "[]"
        if scenario == "manifest-budget":
            return '{"x":"' + "x" * (256 * 1024) + '"}'
        if scenario == "audit-budget":
            return '{"x":"' + "x" * (256 * 1024 - 100) + '"}'
        if owned and (self.index == 0 or scenario == "duplicate-own"):
            if scenario == "wrong-own-manifest":
                return '{"wrong":"manifest"}'
            return (package / "AutodeskFusionMCP.manifest").read_bytes().decode("utf-8")
        return '{"autodeskProduct":"Fusion","custom":"<b>data, never HTML executed</b>"}'

    def run(self, *args):
        raise AssertionError("SDK Script.run forbidden")

    def stop(self):
        raise AssertionError("SDK Script.stop forbidden")

    def unlink(self):
        raise AssertionError("SDK Script.unlink forbidden")


class Scripts:
    reads = 0

    @property
    def count(self):
        observe("getter:count")
        self.reads += 1
        if scenario == "count-null":
            return None
        if scenario == "count-boolean":
            return True
        if scenario == "count-negative":
            return -1
        if scenario == "count-budget":
            return 1025
        if scenario == "count-change" and self.reads > 1:
            return 3
        if scenario == "empty":
            return 0
        return 17 if scenario == "audit-budget" else 2

    def item(self, index):
        observe("getter:item")
        if scenario == "null-item":
            return None
        return Script(index)

    def addExisting(self, *args):
        raise AssertionError("SDK addExisting forbidden")


class APIPreferences:
    reads = 0

    @property
    def defaultPathForScriptsAndAddIns(self):
        observe("getter:apiPreference")
        self.reads += 1
        if scenario == "preference-null":
            return None
        if scenario == "preference-change" and self.reads > 1:
            return str(root / "changed")
        return str(root / "effective-api-parent")


class Event:
    def add(self, handler):
        self.handler = handler
        return True

    def remove(self, handler):
        return True


class Application:
    _scripts = Scripts()
    _api = APIPreferences()

    @property
    def preferences(self):
        observe("getter:preferences")
        return types.SimpleNamespace(apiPreferences=self._api)

    @property
    def scripts(self):
        observe("getter:scripts")
        return None if scenario == "null-collection" else self._scripts

    @property
    def version(self):
        observe("getter:version")
        return "owned-fake-SDK-1"

    @property
    def userInterface(self):
        events.append("vendor-utility-ui-getter")
        assert (private / "entry.json").exists(), "Addon imported before audited entry"
        if scenario == "addon-import-failure":
            raise RuntimeError("owned addon import failure")
        if scenario == "entry-tamper":
            (private / "entry.json").write_text("{}")
        return types.SimpleNamespace(messageBox=lambda *args: None)

    def registerCustomEvent(self, event_id):
        global event
        events.append("bootstrap-register-custom-event")
        event = Event()
        return event

    def fireCustomEvent(self, event_id):
        signals.put(event_id)
        return True

    def unregisterCustomEvent(self, event_id):
        return True

    def log(self, *args):
        return None


app = Application()
adsk = types.ModuleType("adsk")
core = types.ModuleType("adsk.core")
adsk.core = core
adsk.fusion = types.ModuleType("adsk.fusion")
core.Application = types.SimpleNamespace(get=lambda: app)
core.Event = Event
core.CustomEventHandler = type("CustomEventHandler", (), {})
core.LogLevels = types.SimpleNamespace(InfoLogLevel=0, ErrorLogLevel=1, WarningLogLevel=2)
core.LogTypes = types.SimpleNamespace(FileLogType=0, ConsoleLogType=1)
core.ScriptSourceLocations = types.SimpleNamespace(**{
    name: (index + 1) * 10 for index, name in enumerate((
        "AppStoreScriptSourceLocation", "OtherInstalledScriptSourceLocation",
        "UserDefinedScriptSourceLocation", "InternalScriptSourceLocation",
        "SamplesScriptSourceLocation", "LinkedScriptSourceLocation"))})
sys.modules.update({"adsk": adsk, "adsk.core": core, "adsk.fusion": adsk.fusion})

# Explicit SDK-free external ports. Producer, entrypoint, addon runtime, bridge
# runtime, admission-runtime and shared dispatch implementation remain REAL.
class ForbidOptionalCommands(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "audit_fixture.commands" or fullname.startswith("audit_fixture.commands."):
            events.append("forbidden-commands-import")
            raise AssertionError("Controlled startup must not even import optional commands")
        return None


sys.meta_path.insert(0, ForbidOptionalCommands())
server_module = types.ModuleType("audit_fixture.lib.mcp_server")


class Server:
    is_running = False

    def __init__(self, **kwargs):
        assert (private / "entry.json").exists()
        assert (private / "returned.json").exists()
        if owned:
            assert kwargs["physical_authority"]._grant is None, "No physical grant issued"
        else:
            assert kwargs["physical_authority"] is None, "No fake physical grant"
        events.append("server-construct")
        self.resources = []
        if scenario == "provision-before-listener":
            provision_file.write_text("{}")
        if scenario == "provision-env-before-listener":
            os.environ.pop("FUSION_MCP_ADMISSION_PROVISION", None)

    def start(self):
        entry_bytes = (private / "entry.json").read_bytes()
        entry = json.loads(entry_bytes)
        returned = json.loads((private / "returned.json").read_bytes())
        assert entry["version"] == returned["version"] == (3 if owned else 2)
        assert entry["phase"] == "entry-audited-before-addon-import"
        assert returned["entry"]["sha256"] == sha(entry_bytes)
        assert entry["startupAudit"]["scripts"]["countBefore"] == (
            0 if scenario == "empty" else 2)
        events.append("listener-start")
        self.is_running = True
        started.set()

    def stop(self):
        self.is_running = False


server_module.MCPServer = Server
server_module.SERVER_INFO = {"version": "owned-offline-fixture"}
sys.modules["audit_fixture.lib.mcp_server"] = server_module
operations = types.ModuleType("audit_fixture.fusion_bridge.operations")
operations.TOOL_HANDLERS = {}
sys.modules["audit_fixture.fusion_bridge.operations"] = operations

if ignored_bytecode_env:
    for name in sorted(tuple(sys.modules), key=len, reverse=True):
        if (name != "audit_fixture.lib.mcp_server"
                and (name == "audit_fixture.lib" or name.startswith("audit_fixture.lib."))):
            module = sys.modules.pop(name)
            parent, _, attribute = name.rpartition(".")
            owner = sys.modules.get(parent)
            if owner is not None and getattr(owner, attribute, None) is module:
                delattr(owner, attribute)
    assert not list(package.rglob("*.pyc"))
    if scenario == "preexisting-cache":
        cache = package / "lib" / "__pycache__"
        cache.mkdir(mode=0o700)
        (cache / "unlisted.cpython-314.pyc").write_bytes(b"ORIGINAL-UNLISTED-CACHE")
        (cache / "unlisted.cpython-314.pyc").chmod(0o600)
    sys.dont_write_bytecode = False
    # Fusion loads the entry itself without a top-level pyc in the observed
    # failure. Reproduce that external loader boundary, not an importlib cache.
    entrypoint = types.ModuleType("audit_fixture.AutodeskFusionMCP")
    entrypoint.__package__ = "audit_fixture"
    entrypoint.__file__ = str(package / "AutodeskFusionMCP.py")
    sys.modules[entrypoint.__name__] = entrypoint
    exec(compile((package / "AutodeskFusionMCP.py").read_bytes(),
                 entrypoint.__file__, "exec"), entrypoint.__dict__)
else:
    entrypoint = importlib.import_module("audit_fixture.AutodeskFusionMCP")
entrypoint.run({"ownedFixture": True})
policy_after_entry = sys.dont_write_bytecode
if ignored_bytecode_env and "audit_fixture.lib.physical_authority" in sys.modules:
    # External fixture port; never the real host authority directory.
    sys.modules["audit_fixture.lib.physical_authority"].authority_directory = lambda: private / "physical"
dispatch = sys.modules.get("audit_fixture.fusion_bridge.dispatch")
if dispatch is not None:
    # The real event queue is pumped ONLY by this main thread. Disable periodic
    # fake SDK signals, not the dispatcher/its _pending/_run_lock machinery.
    dispatch._scheduler_active.clear()
    if scenario == "source-before-event":
        with (package / "settings.py").open("a") as stream:
            stream.write("\n# changed before the queued audit\n")
    if scenario == "timeout-before-event":
        dispatch._startup_ticket["_bootstrap_timer"].function()
    if scenario == "duplicate-schedule":
        entrypoint.run({"ownedFixture": True})
    if scenario == "audit-timeout":
        timer = dispatch._startup_ticket["_bootstrap_timer"]
        timer.cancel()
        replacement = threading.Timer(0.01, timer.function)
        replacement.daemon = True
        dispatch._startup_ticket["_bootstrap_timer"] = replacement
        replacement.start()
    if scenario == "queue-lock-held":
        dispatch._run_lock.acquire()
        try:
            event.handler.notify(None)
            assert not any(item.startswith("getter:") for item in events)
        finally:
            dispatch._run_lock.release()
        events.append("shared-lock-delayed-audit")
    if scenario == "background-event":
        worker = threading.Thread(target=lambda: event.handler.notify(None))
        worker.start()
        worker.join()
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline and not started.is_set() and not dispatch._halt.is_set():
        try:
            signals.get(timeout=0.01)
        except queue.Empty:
            continue
        event.handler.notify(None)
    if started.is_set() and scenario == "replay":
        count = len([item for item in events if item.startswith("getter:")])
        entrypoint.run({"ownedFixture": True})
        assert len([item for item in events if item.startswith("getter:")]) == count
    if started.is_set() and scenario == "public-spoof":
        try:
            dispatch.dispatch_to_main_thread({
                "params": {"name": "__startup_audit__"},
                "_bootstrap_entry": {"audit": True},
            })
        except PermissionError:
            events.append("public-spoof-denied")
        else:
            raise AssertionError("Public input bypassed physical admission")
    if started.is_set() and scenario == "controlled-stop":
        from audit_fixture import addon_runtime
        addon_runtime.stop(None)
        events.append("controlled-stop-returned")
    dispatch.request_main_thread_shutdown()

entry_path = private / "entry.json"
returned_path = private / "returned.json"
print("FIXTURE_RESULT=" + json.dumps({
    "scenario": scenario, "events": events, "listener": started.is_set(),
    "entry": json.loads(entry_path.read_bytes()) if entry_path.exists() else None,
    "returned": json.loads(returned_path.read_bytes()) if returned_path.exists() else None,
    "entrySha256": sha(entry_path.read_bytes()) if entry_path.exists() else None,
    "intentSha256": sha(intent_file.read_bytes()),
    "originalIntentSha256": sha(json.dumps(intent).encode()),
    "originalIntent": intent,
    "sdk": "EXPLICIT_FAKE_ONLY", "network": "NONE", "errors": errors,
    "bytecode": {
        "ignoreEnvironment": sys.flags.ignore_environment,
        "initial": initial_bytecode_policy, "afterEntry": policy_after_entry,
        "afterDeferred": sys.dont_write_bytecode,
        "files": sorted(p.relative_to(package).as_posix() for p in package.rglob("*.pyc")),
    },
}))
