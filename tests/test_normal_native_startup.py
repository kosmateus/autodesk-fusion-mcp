"""Ordinary add-in startup and local discovery, without a live Fusion SDK."""

import _fusion_test_bootstrap  # noqa: F401
import json
import os
from pathlib import Path
import subprocess
import sqlite3
import sys
import threading
import time
import unittest
import uuid
from unittest.mock import patch

from fusion_bridge import runtime, admission_runtime
from lib import physical_authority
from lib import normal_runtime
from lib.request_admission import AdmissionError
import test_admission_runtime as runtime_fixtures
import _physical_test_support as physical_fixtures


@unittest.skipUnless(sys.platform.startswith("linux"),
                     "Local broker fixtures use Linux; Windows requires the separate WSL fixture")
class NormalNativeStartupTests(unittest.TestCase):
    def setUp(self):
        f = self.fixture = runtime_fixtures.RuntimeAdmissionContracts()
        f.setUp()
        self.addCleanup(f.doCleanups)
        env = dict(os.environ)
        env.pop("FUSION_MCP_ADMISSION_PROVISION", None)
        self.enterContext(patch.dict(os.environ, env, clear=True))
        self.root = f.file.parent
        self.host = self.root / "ordinary-physical"
        self.enterContext(patch.object(physical_authority, "authority_directory",
                                      return_value=self.host))
        original = physical_fixtures.descriptor

        def descriptor(authority, **kwargs):
            result = original(authority, **kwargs)
            profile = self.host / "normal-runtime.json"
            if profile.exists():
                result["handoffId"] = json.loads(profile.read_text())["descriptor"]["handoffId"]
            queue = physical_authority.private_directory(self.root / "broker-queue")
            result["brokerOwner"].update(
                pid=os.getpid(), birth=admission_runtime.process_birth(),
                nonce="normal-test-claim", queueDirectory=str(queue),
            )
            physical_authority.write_private(queue / "broker.lock", {
                key: result["brokerOwner"][key] for key in ("pid", "birth", "nonce")
            } | dict(protocol=2))
            return result

        self.enterContext(patch.object(physical_fixtures, "descriptor", descriptor))

    def test_ordinary_start_creates_authority_before_serving_and_requires_a_grant(self):
        self.fixture.start_runtime(broker_owner="fmcad-normal-broker")
        self.assertIsNotNone(runtime._admission, "Normal startup cannot expose an unprovisioned server")
        config = json.loads((self.host / "normal-runtime.json").read_text())
        self.assertEqual(config["kind"], "fmcad-normal-native-runtime")
        self.assertEqual(config["descriptor"]["physicalRuntime"]["pid"], os.getpid())
        self.assertEqual(config["descriptor"]["endpointURL"], "http://127.0.0.1:0/mcp")
        self.assertNotIn("credentials", json.dumps(config))
        self.assertNotIn("token", json.dumps(config))
        self.assertIsNotNone(runtime._admission.physical)
        with self.assertRaises(PermissionError):
            runtime._admission.physical.authenticate([])
        runtime._admission.physical.authenticate([self.fixture.grant_token]).validate()

    def test_discovery_cli_is_readonly_sdk_free_and_never_prints_credentials(self):
        self.fixture.start_runtime(broker_owner="fmcad-normal-broker")
        config_path = self.host / "normal-runtime.json"
        config = json.loads(config_path.read_text())
        provision_path = Path(config["provisionPath"])
        before = provision_path.read_bytes()
        credentials = json.loads(before)["credentials"]
        result = self.discovery_cli()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), config)
        for secret in credentials:
            self.assertNotIn(secret, result.stdout + result.stderr)
        self.assertEqual(provision_path.read_bytes(), before)

    def discovery_cli(self):
        script = """
import sys
from pathlib import Path
from lib import physical_authority
physical_authority.authority_directory=lambda:Path(sys.argv[1])
from lib import physical_lifecycle
physical_lifecycle.authority_directory=physical_authority.authority_directory
code=physical_lifecycle.main(["discover"])
assert not any(name == "adsk" or name.startswith("adsk.") for name in sys.modules)
raise SystemExit(code)
"""
        return subprocess.run(
            [sys.executable, "-B", "-c", script, str(self.host)],
            cwd=str(Path(__file__).resolve().parents[1]), capture_output=True, text=True, timeout=10,
        )

    def test_malformed_discovery_is_sanitized_without_issuing_or_resetting(self):
        self.fixture.start_runtime(broker_owner="fmcad-normal-broker")
        path = self.host / "normal-runtime.json"
        config = json.loads(path.read_text())
        original_provision = Path(config["provisionPath"]).read_bytes()
        marker = "private-value-must-not-escape"
        physical_authority.write_private(path, {"secret": marker})
        result = self.discovery_cli()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout)["state"], "unavailable")
        self.assertNotIn(marker, result.stdout + result.stderr)
        self.assertEqual(Path(config["provisionPath"]).read_bytes(), original_provision)

    def test_discovery_refuses_changed_runtime_binding(self):
        self.fixture.start_runtime(broker_owner="fmcad-normal-broker")
        store = runtime._admission._store
        original = store._db.execute("SELECT binding FROM physical_runtime_binding").fetchone()[0]
        modified = json.loads(original)
        modified["physicalRuntime"]["birth"] = "foreign"
        store._db.execute("UPDATE physical_runtime_binding SET binding=?", (json.dumps(modified),))
        with self.assertRaises(AdmissionError):
            normal_runtime.discover()

    def test_ordinary_start_then_supported_grant_cli_enters_the_real_lifecycle_queue(self):
        f = self.fixture
        ping = threading.Event()
        f.app.fireCustomEvent.side_effect = lambda *_: ping.set()
        self.assertTrue(runtime.start())
        self.assertTrue(ping.wait(2))
        handler = f.app.registerCustomEvent.return_value.add.call_args.args[0]
        handler.notify(None)
        f.wait_until(lambda: runtime._server is not None)
        authority = runtime._admission.physical
        with self.assertRaises(PermissionError):
            authority.authenticate([])
        config = normal_runtime.discover()
        request = dict(kind="fmcad-physical-grant", version=1, **config["descriptor"])
        queue = physical_authority.private_directory(self.root / "broker-queue")
        request["brokerOwner"] = dict(
            pid=os.getpid(), birth=admission_runtime.process_birth(), nonce="current-broker",
            clientId="fmcad-normal-broker", queueDirectory=str(queue),
        )
        physical_authority.write_private(queue / "broker.lock", {
            key: request["brokerOwner"][key] for key in ("pid", "birth", "nonce")
        } | dict(protocol=2))
        attempt = physical_authority.private_directory(
            Path(config["nativePrivateDirectory"]) / str(uuid.uuid4()))
        source, output = attempt / "request.json", attempt / "grant.json"
        physical_authority.write_private(source, request)
        script = """
import sys
from pathlib import Path
from lib import physical_authority
physical_authority.authority_directory=lambda:Path(sys.argv[1])
from lib import physical_lifecycle
physical_lifecycle.authority_directory=physical_authority.authority_directory
raise SystemExit(physical_lifecycle.main(["grant","--request",sys.argv[2],"--output",sys.argv[3],"--timeout","5"]))
"""
        child = subprocess.Popen(
            [sys.executable, "-B", "-c", script, str(self.host), str(source), str(output)],
            cwd=str(Path(__file__).resolve().parents[1]), stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True,
        )
        try:
            deadline = time.monotonic() + 8
            while child.poll() is None and time.monotonic() < deadline:
                handler.notify(None)
                threading.Event().wait(0.01)
            stdout, stderr = child.communicate(timeout=2)
            self.assertEqual(child.returncode, 0, stdout + stderr)
            self.assertEqual(json.loads(stdout)["state"], "granted")
            grant = physical_authority.read_private(output)
            authority.authenticate([grant["token"]]).validate()
            self.assertNotIn(grant["token"], stdout + stderr)
            self.assertEqual(Path(config["nativePrivateDirectory"]), self.host.parent / "clients")
            with self.assertRaises(AdmissionError):
                authority.publish_grant(request, self.host / "must-remain-protected.json")
            self.assertFalse((self.host / "must-remain-protected.json").exists())
        finally:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=2)
            child.stdout.close()
            child.stderr.close()

    def test_repeated_normal_start_preserves_provision_and_all_existing_rows(self):
        self.fixture.start_runtime(broker_owner="fmcad-normal-broker")
        provision = Path(json.loads((self.host / "normal-runtime.json").read_text())["provisionPath"])
        before = provision.read_bytes()
        db = runtime._admission._store
        generation = db._db.execute("SELECT * FROM generation").fetchone()
        self.assertTrue(runtime.stop())
        self.fixture.start_runtime(broker_owner="fmcad-normal-broker")
        self.assertEqual(provision.read_bytes(), before)
        self.assertEqual(runtime._admission._store._db.execute(
            "SELECT * FROM generation").fetchone(), generation)

    def test_missing_discovery_never_recreates_or_resets_an_existing_store(self):
        self.host.mkdir(mode=0o700)
        database = self.host / "normal-admissions.sqlite"
        database.write_bytes(b"original unknown store")
        with self.assertRaises(AdmissionError):
            admission_runtime.AdmissionRuntime.from_environment(lambda _: None)
        self.assertEqual(database.read_bytes(), b"original unknown store")

    def first_process(self):
        script = """
import sys, threading
sys.path.insert(0,"tests")
import _fusion_test_bootstrap
from pathlib import Path
from lib import physical_authority
physical_authority.authority_directory=lambda:Path(sys.argv[1])
from fusion_bridge import admission_runtime
normal=admission_runtime.AdmissionRuntime.from_environment(lambda _: None, version="unknown",
                                         endpoint="http://127.0.0.1:0/mcp")
store=normal._store
binding=dict(version=1,owner="original",request="original",instance=store._instance,
             epoch=store._epoch,source="source",build="build",document="doc",inputHash="hash")
store.admit(binding)
store.claim(binding)
print("ready",flush=True)
threading.Event().wait(60)
"""
        child = subprocess.Popen(
            [sys.executable, "-B", "-c", script, str(self.host)],
            cwd=str(Path(__file__).resolve().parents[1]), stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True,
        )

        def stop():
            if child.poll() is None:
                child.terminate()
            child.wait(timeout=5)
            child.stdout.close()
            child.stderr.close()

        self.addCleanup(stop)
        line = child.stdout.readline()
        self.assertEqual(line, "ready\n", child.stderr.read() if not line else "")
        return child

    @unittest.skipUnless(sys.platform.startswith("linux") or sys.platform == "win32",
                         "Actual process observation")
    def test_live_native_process_is_not_replaced(self):
        self.first_process()
        profile = (self.host / "normal-runtime.json").read_bytes()
        with self.assertRaises(AdmissionError):
            admission_runtime.AdmissionRuntime.from_environment(lambda _: None)
        self.assertEqual((self.host / "normal-runtime.json").read_bytes(), profile)

    @unittest.skipUnless(sys.platform.startswith("linux") or sys.platform == "win32",
                         "Actual process observation")
    def test_normal_native_process_restart_preserves_unknown_and_original_provision(self):
        child = self.first_process()
        old_config = json.loads((self.host / "normal-runtime.json").read_text())
        old_provision = Path(old_config["provisionPath"])
        original = old_provision.read_bytes()
        child.terminate()
        child.wait(timeout=5)
        self.fixture.start_runtime(broker_owner="fmcad-normal-broker")
        self.assertEqual(old_provision.read_bytes(), original)
        state = runtime._admission._store._db.execute(
            "SELECT request,state,result FROM admissions").fetchall()
        self.assertEqual(state, [("original", "claimed", None)])
        new_config = json.loads((self.host / "normal-runtime.json").read_text())
        self.assertNotEqual(new_config["descriptor"]["generation"], old_config["descriptor"]["generation"])
        self.assertEqual(new_config["descriptor"]["physicalRuntime"]["pid"], os.getpid())

    def test_normal_restart_upgrades_old_output_namespace_without_resetting_history(self):
        child = self.first_process()
        profile = self.host / "normal-runtime.json"
        old = json.loads(profile.read_text())
        old["nativePrivateDirectory"] = str(self.host / "clients")
        physical_authority.write_private(profile, old)
        provision = physical_authority.read_private(Path(old["provisionPath"]))
        original_provision = Path(old["provisionPath"]).read_bytes()
        database = Path(provision["database"])
        identity = (database.stat().st_dev, database.stat().st_ino)
        snapshot = self.host / "normal-runtimes" / (provision["instance"] + ".json")
        # Fixture for the original 51a0dd91 projection, not a runtime rewrite.
        physical_authority.write_private(snapshot, old)
        original = snapshot.read_bytes()
        with self.assertRaises(AdmissionError):
            normal_runtime.discover()
        with self.assertRaises(AdmissionError):
            admission_runtime.AdmissionRuntime.from_environment(lambda _: None)
        child.terminate()
        child.wait(timeout=5)
        self.fixture.start_runtime(broker_owner="fmcad-normal-broker")
        current = normal_runtime.discover()
        self.assertEqual(Path(current["nativePrivateDirectory"]), self.host.parent / "clients")
        self.assertEqual(snapshot.read_bytes(), original)
        self.assertEqual(Path(old["provisionPath"]).read_bytes(), original_provision)
        self.assertEqual((database.stat().st_dev, database.stat().st_ino), identity)
        self.assertEqual(runtime._admission._store._db.execute(
            "SELECT request,state,result FROM admissions").fetchall(), [("original", "claimed", None)])

    def test_legacy_output_namespace_requires_its_own_unchanged_snapshot(self):
        child = self.first_process()
        profile = self.host / "normal-runtime.json"
        config = json.loads(profile.read_text())
        config["nativePrivateDirectory"] = str(self.host / "clients")
        physical_authority.write_private(profile, config)
        child.terminate()
        child.wait(timeout=5)
        with self.assertRaises(AdmissionError):
            admission_runtime.AdmissionRuntime.from_environment(lambda _: None)
        self.assertEqual(json.loads(profile.read_text()), config)
        with sqlite3.connect(self.host / "normal-admissions.sqlite") as db:
            self.assertEqual(db.execute(
                "SELECT request,state,result FROM admissions").fetchall(), [("original", "claimed", None)])

    def crash_start(self, stage):
        script = """
import sys, os, importlib
from contextlib import contextmanager
sys.path.insert(0,"tests")
import _fusion_test_bootstrap
from pathlib import Path
from lib import physical_authority
physical_authority.authority_directory=lambda:Path(sys.argv[1])
from fusion_bridge import admission_runtime
normal=importlib.import_module(admission_runtime.__package__.rsplit(".",1)[0]+".lib.normal_runtime")
stage=sys.argv[2]
original_store=normal.AdmissionStore
if stage=="admissions-only":
    @contextmanager
    def crash_transaction(*args,**kwargs):
        os._exit(73)
        yield
    original_store._transaction=crash_transaction
def crash_store(*args,**kwargs):
    if stage=="empty-db":
        os._exit(73)
    store=original_store(*args,**kwargs)
    if stage=="initialized-db":
        store.close()
        os._exit(73)
    return store
normal.AdmissionStore=crash_store
original_write=normal.write_private
def crash_discovery(path,value):
    if stage=="before-db" and Path(path).name=="normal-starting.json":
        original_write(path,value)
        os._exit(73)
    if Path(path).name=="normal-runtime.json":
        provision=physical_authority.read_private(Path(value["provisionPath"]))
        with original_store(provision["database"],instance=provision["instance"],
                            epoch=provision["epoch"],create=False) as store:
            binding=dict(version=1,owner="crashed",request="bootstrap-unknown",
                         instance=provision["instance"],epoch=provision["epoch"],
                         source="s",build="b",document="doc",inputHash="hash")
            store.admit(binding)
            store.claim(binding)
        if stage=="after-discovery":
            original_write(path,value)
        os._exit(73)
    return original_write(path,value)
if stage in ("before-db","before-discovery","after-discovery"):
    normal.write_private=crash_discovery
admission_runtime.AdmissionRuntime.from_environment(lambda _: None,version="unknown",
                                                   endpoint="http://127.0.0.1:0/mcp")
raise RuntimeError("Crash boundary was not reached")
"""
        child = subprocess.run(
            [sys.executable, "-B", "-c", script, str(self.host), stage],
            cwd=str(Path(__file__).resolve().parents[1]), capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(child.returncode, 73, child.stderr)

    def test_crash_before_discovery_resumes_owned_store_without_resetting_unknown(self):
        self.crash_start("before-discovery")
        self.assertFalse((self.host / "normal-runtime.json").exists())
        originals = {path: path.read_bytes() for path in (self.host / "normal-provisions").glob("*.json")}
        self.fixture.start_runtime(broker_owner="fmcad-normal-broker")
        self.assertEqual(runtime._admission._store._db.execute(
            "SELECT request,state,result FROM admissions").fetchall(),
            [("bootstrap-unknown", "claimed", None)])
        for path, value in originals.items():
            self.assertEqual(path.read_bytes(), value)

    def test_crash_after_empty_database_creation_resumes_initialization(self):
        self.crash_start("empty-db")
        self.assertEqual((self.host / "normal-admissions.sqlite").stat().st_size, 0)
        self.fixture.start_runtime(broker_owner="fmcad-normal-broker")
        self.assertIsNotNone(runtime._admission.physical)

    def test_crash_after_schema_commit_resumes_without_resetting_generation_history(self):
        self.crash_start("initialized-db")
        self.fixture.start_runtime(broker_owner="fmcad-normal-broker")
        self.assertEqual(runtime._admission._store._db.execute(
            "SELECT COUNT(*) FROM generation_history").fetchone()[0], 2)

    def test_crash_after_first_schema_statement_resumes_partial_initialization(self):
        self.crash_start("admissions-only")
        self.fixture.start_runtime(broker_owner="fmcad-normal-broker")
        self.assertIsNotNone(runtime._admission.physical)

    def test_crashed_restart_with_old_discovery_keeps_both_unknown_records(self):
        old = self.first_process()
        old.terminate()
        old.wait(timeout=5)
        self.crash_start("before-discovery")
        self.fixture.start_runtime(broker_owner="fmcad-normal-broker")
        self.assertEqual(runtime._admission._store._db.execute(
            "SELECT request,state,result FROM admissions ORDER BY request").fetchall(),
            [("bootstrap-unknown", "claimed", None), ("original", "claimed", None)])

    def test_crash_before_database_creation_resumes_only_the_owned_preparation(self):
        self.crash_start("before-db")
        self.assertFalse((self.host / "normal-admissions.sqlite").exists())
        self.fixture.start_runtime(broker_owner="fmcad-normal-broker")
        self.assertIsNotNone(runtime._admission.physical)

    def test_crashed_restart_before_generation_commit_keeps_the_previous_head(self):
        old = self.first_process()
        old.terminate()
        old.wait(timeout=5)
        self.crash_start("empty-db")
        self.fixture.start_runtime(broker_owner="fmcad-normal-broker")
        store = runtime._admission._store
        self.assertEqual(store._db.execute("SELECT COUNT(*) FROM generation_history").fetchone()[0], 2)
        self.assertEqual(store._db.execute(
            "SELECT request,state,result FROM admissions").fetchall(), [("original", "claimed", None)])

    def test_crash_after_discovery_publication_is_idempotently_recovered(self):
        self.crash_start("after-discovery")
        self.assertTrue((self.host / "normal-runtime.json").exists())
        self.fixture.start_runtime(broker_owner="fmcad-normal-broker")
        self.assertEqual(runtime._admission._store._db.execute(
            "SELECT request,state,result FROM admissions").fetchall(),
            [("bootstrap-unknown", "claimed", None)])
        self.assertFalse((self.host / "normal-starting.json").exists())

    def test_interrupted_startup_does_not_adopt_a_changed_generation_or_settle_unknown(self):
        self.crash_start("before-discovery")
        database = self.host / "normal-admissions.sqlite"
        with sqlite3.connect(database) as db:
            db.execute("UPDATE generation SET instance='foreign',epoch='foreign'")
            rows = db.execute("SELECT * FROM admissions").fetchall()
        with self.assertRaises(AdmissionError):
            admission_runtime.AdmissionRuntime.from_environment(lambda _: None)
        with sqlite3.connect(database) as db:
            self.assertEqual(db.execute("SELECT * FROM admissions").fetchall(), rows)
            self.assertEqual(db.execute(
                "SELECT instance,epoch FROM generation").fetchone(), ("foreign", "foreign"))
        self.assertFalse((self.host / "normal-runtime.json").exists())
        self.assertTrue((self.host / "normal-starting.json").exists())

    def test_interrupted_startup_never_initializes_unrelated_existing_tables(self):
        self.crash_start("before-db")
        database = self.host / "normal-admissions.sqlite"
        with sqlite3.connect(database) as db:
            db.execute("CREATE TABLE unrelated_original (value TEXT)")
            db.execute("INSERT INTO unrelated_original VALUES ('UNKNOWN')")
        with self.assertRaises(AdmissionError):
            admission_runtime.AdmissionRuntime.from_environment(lambda _: None)
        with sqlite3.connect(database) as db:
            self.assertEqual(db.execute("SELECT * FROM unrelated_original").fetchall(), [("UNKNOWN",)])
            self.assertEqual(db.execute(
                "SELECT name FROM sqlite_master WHERE type='table'").fetchall(),
                [("unrelated_original",)])


if __name__ == "__main__":
    unittest.main()
