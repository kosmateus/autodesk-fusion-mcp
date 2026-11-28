"""Kernel-backed normal broker replacement on one actual normal runtime."""

import _fusion_test_bootstrap  # noqa: F401
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import uuid
from types import SimpleNamespace
from unittest.mock import patch

from fusion_bridge import admission_runtime
from lib import physical_authority, normal_runtime
from lib.request_admission import AdmissionError
from lib.rebaseline_fence import observe_process_birth


@unittest.skipUnless(sys.platform.startswith("linux"), "Actual local Linux broker namespace")
class NormalBrokerSuccessionTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.enterContext(patch.object(physical_authority, "authority_directory",
                                      return_value=self.root / "physical"))
        env = dict(os.environ)
        env.pop("FUSION_MCP_ADMISSION_PROVISION", None)
        self.enterContext(patch.dict(os.environ, env, clear=True))
        self.runtime = admission_runtime.AdmissionRuntime.from_environment(lambda _: None)
        self.addCleanup(self.runtime.close)
        self.authority = self.runtime.physical
        self.config = normal_runtime.discover()
        self.queue = physical_authority.private_directory(self.root / "queue")
        self.old = self.broker()
        self.new = self.broker()
        self.first = self.descriptor(self.old, "original")
        self.successor = self.descriptor(self.new, "successor")
        self.claim(self.first)
        self.grant = self.authority.issue(self.first)
        self.capability = self.authority.authenticate([self.grant["token"]])

    def broker(self):
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        def stop():
            if child.poll() is None:
                child.terminate()
            child.wait(timeout=5)
        self.addCleanup(stop)
        return child

    def descriptor(self, child, nonce):
        return dict(
            kind="fmcad-physical-grant", version=1, **copy.deepcopy(self.config["descriptor"]),
            brokerOwner=dict(pid=child.pid, birth=observe_process_birth(child.pid), nonce=nonce,
                             clientId="fmcad-normal-broker", queueDirectory=str(self.queue)),
        )

    def claim(self, descriptor):
        owner = descriptor["brokerOwner"]
        physical_authority.write_private(self.queue / "broker.lock", {
            key: owner[key] for key in ("pid", "birth", "nonce")
        } | dict(protocol=2))

    def stop_original(self):
        self.old.terminate()
        self.old.wait(timeout=5)
        self.claim(self.successor)

    def test_normal_first_grant_stop_successor_rotates_without_consumed_root_or_realm(self):
        store = self.runtime._store
        binding = dict(version=1, owner="original", request="unknown", instance=store._instance,
                       epoch=store._epoch, source="s", build="b", document="doc", inputHash="hash")
        store.admit(binding)
        store.claim(binding)
        rows = list(store._db.execute("SELECT * FROM admissions"))
        generation = list(store._db.execute("SELECT * FROM generation"))
        profile = (self.root / "physical" / "normal-runtime.json").read_bytes()
        self.assertIsNone(store._provision_fence_head())
        self.assertFalse((self.queue / "runtime-verification").exists())
        self.stop_original()
        fresh = self.authority.issue(self.successor)
        self.assertNotEqual(fresh["token"], self.grant["token"])
        self.assertEqual(self.authority.issue(self.successor), fresh)
        with self.assertRaises(PermissionError):
            self.capability.validate()
        self.authority.authenticate([fresh["token"]]).validate()
        self.assertEqual(list(store._db.execute("SELECT * FROM admissions")), rows)
        self.assertEqual(list(store._db.execute("SELECT * FROM generation")), generation)
        self.assertEqual((self.root / "physical" / "normal-runtime.json").read_bytes(), profile)

    def test_live_predecessor_is_never_replaced(self):
        self.claim(self.successor)
        with self.assertRaises(AdmissionError):
            self.authority.issue(self.successor)
        self.capability.validate()

    def test_wrong_nonce_birth_and_foreign_queue_do_not_replace_owner(self):
        self.stop_original()
        for field, value in (("nonce", "stale"), ("birth", "stale"),
                             ("queueDirectory", str(self.root / "foreign"))):
            request = copy.deepcopy(self.successor)
            request["brokerOwner"][field] = value
            with self.subTest(field=field), self.assertRaises(AdmissionError):
                self.authority.issue(request)
        self.capability.validate()

    def test_replaced_private_queue_inode_is_not_the_recorded_namespace(self):
        self.stop_original()
        self.queue.rename(self.root / "original-queue")
        physical_authority.private_directory(self.queue)
        self.claim(self.successor)
        with self.assertRaises(AdmissionError):
            self.authority.issue(self.successor)
        self.capability.validate()

    def test_public_queue_cannot_be_used_as_kernel_owner_proof(self):
        self.stop_original()
        self.queue.chmod(0o755)
        with self.assertRaises(AdmissionError):
            self.authority.issue(self.successor)
        self.capability.validate()

    def test_unreleased_queued_and_active_turns_block_normal_rotation(self):
        turn = self.capability.prepare_turn("queued", "document")
        self.stop_original()
        before = list(self.runtime._store._db.execute("SELECT * FROM physical_turns"))
        with self.assertRaises(AdmissionError):
            self.authority.issue(self.successor)
        self.assertEqual(list(self.runtime._store._db.execute("SELECT * FROM physical_turns")), before)
        turn.cancel_queued()
        active = self.capability.prepare_turn("active", "document")
        active.start()
        with self.assertRaises(AdmissionError):
            self.authority.issue(self.successor)
        active.finish()
        self.authority.issue(self.successor)
        with self.assertRaises(PermissionError):
            turn.start()
        with self.assertRaises(PermissionError):
            active.start()

    def test_current_claim_is_rechecked_for_delayed_normal_owner_requests(self):
        self.stop_original()
        fresh = self.authority.issue(self.successor)
        self.claim(self.first)
        with self.assertRaises(AdmissionError):
            self.authority.issue(self.successor)
        with self.assertRaises(AdmissionError):
            self.authority.issue(self.first)
        self.claim(self.successor)
        self.assertEqual(self.authority.issue(self.successor), fresh)

    def test_normal_origin_does_not_bypass_pending_or_foreign_consumed_head(self):
        self.stop_original()
        store = self.runtime._store
        before = list(store._db.execute("SELECT binding FROM physical_owners"))
        store._db.executescript("""
            CREATE TABLE provision_fences (
                request_id TEXT PRIMARY KEY,binding TEXT,key_id TEXT,key_digest TEXT,
                state TEXT,publication_json TEXT,receipt_json TEXT
            );
            CREATE TABLE provision_fence_head(singleton INTEGER PRIMARY KEY,request_id TEXT);
            INSERT INTO provision_fences VALUES ('pending','{}','key','digest','pending',NULL,NULL);
            INSERT INTO provision_fence_head VALUES (1,'pending');
        """)
        with self.assertRaises(AdmissionError):
            self.authority.issue(self.successor)
        store._db.execute("UPDATE provision_fences SET state='consumed'")
        with self.assertRaises(AdmissionError):
            self.authority.issue(self.successor)
        store._db.execute("UPDATE provision_fence_head SET request_id='foreign'")
        with self.assertRaises(AdmissionError):
            self.authority.issue(self.successor)
        self.assertEqual(list(store._db.execute("SELECT binding FROM physical_owners")), before)

    def test_caller_made_normal_origin_is_not_a_capability(self):
        self.stop_original()
        store = self.runtime._store
        before = list(store._db.execute("SELECT binding FROM physical_owners"))
        forged = SimpleNamespace(assert_valid=lambda *_: None)
        with self.assertRaises(AdmissionError):
            store.bind_physical_owner(self.successor, normal_origin=forged)
        self.assertEqual(list(store._db.execute("SELECT binding FROM physical_owners")), before)


LINUX_BROKER = r'''
import json, os, pathlib, sys, tempfile, uuid
root = pathlib.Path(sys.argv[1]) if sys.argv[1] else pathlib.Path(
    tempfile.mkdtemp(prefix="normal-native-owner-fixture-", dir="/tmp/opencode"))
assert root.is_absolute() and str(root) == os.path.realpath(root)
info = root.stat()
assert info.st_uid == os.getuid() and not info.st_mode & 0o077
with open("/proc/self/stat") as stream:
    raw = stream.read()
with open("/proc/sys/kernel/random/boot_id") as stream:
    boot = stream.read().strip()
owner = dict(pid=os.getpid(),birth=boot+":"+raw[raw.rindex(")")+2:].split()[19],
             nonce=str(uuid.uuid4()),clientId="fmcad-normal-broker",queueDirectory=str(root))
claim = {key:owner[key] for key in ("pid","birth","nonce")}
claim["protocol"] = 2
temporary = root / (".claim-" + str(uuid.uuid4()))
fd = os.open(temporary, os.O_CREAT|os.O_EXCL|os.O_WRONLY, 0o600)
with os.fdopen(fd,"w") as stream:
    json.dump(claim,stream)
    stream.flush()
    os.fsync(stream.fileno())
os.replace(temporary,root/"broker.lock")
print(json.dumps(owner),flush=True)
sys.stdin.readline()
'''


@unittest.skipUnless(sys.platform == "win32" and os.environ.get("WSL_DISTRO_NAME"),
                     "Requires actual Windows Python with an explicitly routed WSL fixture")
class WindowsNormalBrokerSuccessionTests(unittest.TestCase):
    def test_actual_windows_normal_origin_replaces_only_its_dead_wsl_broker(self):
        root = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.enterContext(patch.object(physical_authority, "authority_directory",
                                      return_value=root / "physical"))
        env = dict(os.environ)
        env.pop("FUSION_MCP_ADMISSION_PROVISION", None)
        self.enterContext(patch.dict(os.environ, env, clear=True))
        native = admission_runtime.AdmissionRuntime.from_environment(lambda _: None)
        self.addCleanup(native.close)
        config = normal_runtime.discover()
        distro = os.environ["WSL_DISTRO_NAME"]
        command = [str(Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "wsl.exe"),
                   "--distribution", distro, "--exec", "/usr/bin/python3", "-I", "-S", "-B"]

        def broker(queue=""):
            child = subprocess.Popen(
                command + ["-c", LINUX_BROKER, queue],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            def stop():
                if child.poll() is None:
                    child.stdin.write("\n")
                    child.stdin.flush()
                    child.wait(timeout=10)
                child.stdin.close()
                child.stdout.close()
                child.stderr.close()
            line = child.stdout.readline()
            self.assertTrue(line, child.stderr.read() if not line else "")
            owner = json.loads(line)
            if not queue:
                cleanup = r'''
import os,sys
root=sys.argv[1]
assert root.startswith("/tmp/opencode/normal-native-owner-fixture-")
assert os.path.realpath(root)==root and os.stat(root).st_uid==os.getuid()
os.unlink(root+"/broker.lock")
os.rmdir(root)
'''
                self.addCleanup(lambda: subprocess.run(
                    command + ["-c", cleanup, owner["queueDirectory"]],
                    check=True, capture_output=True, text=True, timeout=10,
                ))
            self.addCleanup(stop)
            return child, owner, stop

        _, original, stop = broker()
        request = dict(kind="fmcad-physical-grant", version=1, **config["descriptor"],
                       brokerOwner=original)
        first = native.physical.issue(request, broker_namespace=distro)
        with self.assertRaises(AdmissionError):
            native.physical.issue(request, broker_namespace=distro + "-foreign")
        old_capability = native.physical.authenticate([first["token"]])
        store = native._store
        binding = dict(version=1,owner="original",request="unknown",instance=store._instance,
                       epoch=store._epoch,source="s",build="b",document="doc",inputHash="hash")
        store.admit(binding)
        store.claim(binding)
        before = list(store._db.execute("SELECT * FROM admissions"))
        generation = list(store._db.execute("SELECT * FROM generation"))
        queued = old_capability.prepare_turn("queued-windows", "document")
        stop()
        _, successor, _ = broker(original["queueDirectory"])
        next_request = dict(request, brokerOwner=successor)
        with self.assertRaises(AdmissionError):
            native.physical.issue(next_request, broker_namespace=distro)
        queued.cancel_queued()
        active = old_capability.prepare_turn("active-windows", "document")
        active.start()
        with self.assertRaises(AdmissionError):
            native.physical.issue(next_request, broker_namespace=distro)
        active.finish()
        fresh = native.physical.issue(next_request, broker_namespace=distro)
        self.assertNotEqual(fresh["token"], first["token"])
        self.assertEqual(native.physical.issue(next_request, broker_namespace=distro), fresh)
        with self.assertRaises(PermissionError):
            old_capability.validate()
        native.physical.authenticate([fresh["token"]]).validate()
        self.assertEqual(list(store._db.execute("SELECT * FROM admissions")), before)
        self.assertEqual(list(store._db.execute("SELECT * FROM generation")), generation)
        self.assertIsNone(store._provision_fence_head())


if __name__ == "__main__":
    unittest.main()
