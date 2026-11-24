"""Whole controlled-start fixture: real producer/runtime/queue, explicit fake SDK.

Run only as a benign subprocess with an owned copied package and private files.
The fake server never opens a socket; its start method observes startup ordering.
"""

import hashlib
import importlib
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
if scenario == "bad-intent":
    intent["process"]["birth"] += "-wrong"
if scenario == "bad-executable":
    intent["executable"]["sha256"] = "0" * 64
intent_file.write_text(json.dumps(intent))
intent_file.chmod(0o600)
os.environ["FUSION_MCP_BOOTSTRAP_INTENT"] = str(intent_file)
os.environ.pop("FUSION_MCP_ADMISSION_PROVISION", None)


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
        return str(root / ("script-" + str(self.index)))

    @property
    def location(self):
        observe("getter:location")
        return 999 if scenario == "unknown-enum" else 30

    @property
    def isAddIn(self):
        observe("getter:isAddIn")
        return 1 if scenario == "boolean-int" else self.index == 0

    @property
    def isRunOnStartup(self):
        observe("getter:isRunOnStartup")
        if self.index != 0:
            raise AssertionError("SDK forbids startup getter for a script")
        return False

    @property
    def isRunning(self):
        observe("getter:isRunning")
        return None if scenario == "running-null" else self.index == 0

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
commands = types.ModuleType("audit_fixture.commands")
commands.start = lambda: (_ for _ in ()).throw(AssertionError("No controlled UI setup"))
commands.stop = lambda: None
sys.modules["audit_fixture.commands"] = commands
server_module = types.ModuleType("audit_fixture.lib.mcp_server")


class Server:
    is_running = False

    def __init__(self, **kwargs):
        assert (private / "entry.json").exists()
        assert (private / "returned.json").exists()
        assert kwargs["physical_authority"] is None, "No fake physical grant"
        events.append("server-construct")
        self.resources = []

    def start(self):
        entry_bytes = (private / "entry.json").read_bytes()
        entry = json.loads(entry_bytes)
        returned = json.loads((private / "returned.json").read_bytes())
        assert entry["version"] == returned["version"] == 2
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

entrypoint = importlib.import_module("audit_fixture.AutodeskFusionMCP")
entrypoint.run({"ownedFixture": True})
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
    "sdk": "EXPLICIT_FAKE_ONLY", "network": "NONE", "errors": errors,
}))
