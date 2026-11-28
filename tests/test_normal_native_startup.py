"""Ordinary add-in startup and local discovery, without a live Fusion SDK."""

import _fusion_test_bootstrap  # noqa: F401
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
import unittest
from unittest.mock import patch

from fusion_bridge import runtime, admission_runtime
from lib import physical_authority
from lib import normal_runtime
from lib.request_admission import AdmissionError
import test_admission_runtime as runtime_fixtures
import _physical_test_support as physical_fixtures


@unittest.skipUnless(sys.platform.startswith("linux") or sys.platform == "win32",
                     "Provisioned native admission supports Linux and Windows")
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
        request["brokerOwner"] = dict(
            pid=os.getpid(), birth=admission_runtime.process_birth(), nonce="current-broker",
            clientId="fmcad-normal-broker", queueDirectory=str(self.root),
        )
        source, output = self.root / "grant-request.json", self.root / "physical-grant.json"
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
            self.assertEqual(child.returncode, 0, stderr)
            self.assertEqual(json.loads(stdout)["state"], "granted")
            grant = physical_authority.read_private(output)
            authority.authenticate([grant["token"]]).validate()
            self.assertNotIn(grant["token"], stdout + stderr)
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


if __name__ == "__main__":
    unittest.main()
