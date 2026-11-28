"""Normal broker restart on one native generation, with real Linux processes."""

import _fusion_test_bootstrap  # noqa: F401
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from lib.physical_authority import write_private
from lib.physical_lifecycle import LifecycleMailbox
from lib.request_admission import AdmissionError, _encode
from lib.rebaseline_fence import observe_process_birth
from lib.rebaseline_fence_store import activation_for
from lib import rebaseline_fence
from lib import physical_owner_witness
import test_rebaseline_fence as fence_fixtures


@unittest.skipUnless(sys.platform.startswith("linux"), "Actual Linux process/lease witness")
class BrokerOwnerSuccessionTests(unittest.TestCase):
    def setUp(self):
        f = self.fixture = fence_fixtures.NativeFenceContracts()
        f.setUp()
        self.addCleanup(f.doCleanups)
        self.queue = Path(f.store_path)
        self.queue.mkdir(mode=0o700)
        info = self.queue.stat()
        f.request["store"].update(device=info.st_dev, inode=info.st_ino)
        realm = self.queue / "runtime-verification"
        realm.mkdir(mode=0o700)
        digest = hashlib.sha256(f.key).hexdigest()
        (realm / "verification.key").write_bytes(f.key)
        (realm / "verification.key").chmod(0o600)
        write_private(realm / "realm.json", dict(
            kind="fmcad-runtime-verification-realm", version=1,
            keyId="fmcad-rebaseline-" + digest, sha256=digest,
        ))
        operator, _ = f.operator()
        pending = rebaseline_fence.begin_fence(operator, f.request)
        consumed = rebaseline_fence.consume_fence(operator, f.publication(pending["binding"]))
        self.activation = activation_for(consumed["receiptJson"])
        self.old = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        self.addCleanup(self.reap_old)
        self.first = f.grant_descriptor()
        self.first["brokerOwner"].update(
            pid=self.old.pid, birth=observe_process_birth(self.old.pid), nonce="old-nonce",
        )
        self.grant = f.authority.issue(self.first, activation=self.activation)
        self.capability = f.authority.authenticate([self.grant["token"]])
        self.next = copy.deepcopy(self.first)
        self.next["brokerOwner"].update(
            pid=os.getpid(), birth=observe_process_birth(os.getpid()), nonce="new-nonce",
        )
        self.claim()

    def reap_old(self):
        if self.old.poll() is None:
            self.old.terminate()
        self.old.wait(timeout=5)

    def claim(self, descriptor=None):
        owner = (descriptor or self.next)["brokerOwner"]
        write_private(self.queue / "broker.lock", {
            key: owner[key] for key in ("pid", "birth", "nonce")
        } | dict(protocol=2))

    def issue(self, descriptor=None):
        return self.fixture.authority.issue(descriptor or self.next, activation=self.activation)

    def test_dead_predecessor_rotates_token_and_preserves_original_unknown_and_root(self):
        f = self.fixture
        unknown = dict(version=1, owner="old", request="historical-unknown",
                       instance="runtime", epoch="epoch", source="s", build="b",
                       document="doc", inputHash="hash")
        f.store.admit(unknown)
        # Persisted historical UNKNOWN is not an active physical producer.
        f.store._db.execute("UPDATE admissions SET state='claimed',claim='lost'")
        before = list(f.store._db.execute("SELECT * FROM admissions"))
        root_before = list(f.store._db.execute("SELECT * FROM provision_fences"))
        self.reap_old()
        fresh = self.issue()
        self.assertEqual(fresh["brokerOwner"], self.next["brokerOwner"])
        self.assertNotEqual(fresh["token"], self.grant["token"])
        self.assertEqual(self.issue(), fresh)
        with self.assertRaises(PermissionError):
            self.capability.validate()
        f.authority.authenticate([fresh["token"]]).validate()
        self.assertEqual(list(f.store._db.execute("SELECT * FROM admissions")), before)
        self.assertEqual(list(f.store._db.execute("SELECT * FROM provision_fences")), root_before)

    def test_live_predecessor_cannot_be_overwritten(self):
        with self.assertRaises(AdmissionError):
            self.issue()
        self.capability.validate()

    def test_dead_predecessor_does_not_authorize_stale_nonce_or_birth(self):
        self.reap_old()
        for field, value in (("nonce", "stale"), ("birth", "wrong-birth")):
            bad = copy.deepcopy(self.next)
            bad["brokerOwner"][field] = value
            with self.subTest(field=field), self.assertRaises(AdmissionError):
                self.issue(bad)
        self.capability.validate()

    def test_foreign_queue_and_forged_realm_are_denied(self):
        self.reap_old()
        foreign = copy.deepcopy(self.next)
        foreign["brokerOwner"]["queueDirectory"] += "-foreign"
        with self.assertRaises(AdmissionError):
            self.issue(foreign)
        key = self.queue / "runtime-verification" / "verification.key"
        key.write_bytes(b"x" * 32)
        with self.assertRaises(AdmissionError):
            self.issue()
        self.capability.validate()

    def test_unreleased_physical_turn_blocks_succession_without_replaying_or_settling(self):
        turn = self.capability.prepare_turn("original-physical-turn", "document")
        self.reap_old()
        before = list(self.fixture.store._db.execute("SELECT * FROM physical_turns"))
        with self.assertRaises(AdmissionError):
            self.issue()
        self.assertEqual(list(self.fixture.store._db.execute("SELECT * FROM physical_turns")), before)
        self.capability.validate()
        turn.cancel_queued()
        active = self.capability.prepare_turn("active-sdk-turn", "document")
        active.start()
        with self.assertRaises(AdmissionError):
            self.issue()
        active.finish()
        self.issue()
        with self.assertRaises(PermissionError):
            turn.start()
        with self.assertRaises(PermissionError):
            active.start()

    def test_captured_delayed_request_cannot_overwrite_current_live_successor(self):
        self.reap_old()
        fresh = self.issue()
        with self.assertRaises(AdmissionError):
            self.issue(self.first)
        self.assertEqual(self.issue(), fresh)

    def test_reused_pid_with_distinct_kernel_birth_is_a_dead_predecessor(self):
        f = self.fixture
        previous = copy.deepcopy(self.first)
        previous["brokerOwner"].update(pid=os.getpid(), birth="previous-kernel-birth")
        # Seed the durable predecessor as observed before this PID was reused.
        f.store._db.execute("UPDATE physical_owners SET binding=?", (_encode(previous),))
        fresh = self.issue()
        self.assertEqual(fresh["brokerOwner"], self.next["brokerOwner"])
        with self.assertRaises(PermissionError):
            self.capability.validate()

    def test_dead_successor_and_removed_current_claim_are_not_authority(self):
        self.reap_old()
        vanished = copy.deepcopy(self.next)
        vanished["brokerOwner"].update(
            pid=self.old.pid, birth=self.first["brokerOwner"]["birth"],
        )
        self.claim(vanished)
        with self.assertRaises(AdmissionError):
            self.issue(vanished)
        (self.queue / "broker.lock").unlink()
        with self.assertRaises(AdmissionError):
            self.issue()
        self.capability.validate()

    def test_symlinked_claim_and_public_realm_key_cannot_prove_current_owner(self):
        self.reap_old()
        lock = self.queue / "broker.lock"
        saved = self.queue / "saved-lock"
        lock.rename(saved)
        lock.symlink_to(saved)
        with self.assertRaises(AdmissionError):
            self.issue()
        lock.unlink()
        saved.rename(lock)
        key = self.queue / "runtime-verification" / "verification.key"
        key.chmod(0o644)
        with self.assertRaises(AdmissionError):
            self.issue()
        self.capability.validate()

    def test_private_mailbox_rechecks_claim_at_handler_execution_not_publication(self):
        self.reap_old()
        mailbox = LifecycleMailbox(self.fixture.authority, lambda **_: self.fail("No handoff"))
        output = self.fixture.root / "successor-grant.json"
        request = dict(operation="grant", request=self.next, activation=self.activation,
                       output=str(output), ownerDead=True)
        write_private(mailbox.directory / "stale.request.json", request)
        foreign = copy.deepcopy(self.next)
        foreign["brokerOwner"]["nonce"] = "newer-claim"
        self.claim(foreign)
        mailbox.poll()
        result = json.loads((mailbox.directory / "stale.result.json").read_text())
        self.assertEqual(result["state"], "rejected")
        self.assertFalse(output.exists())
        self.capability.validate()
        request["request"] = foreign
        write_private(mailbox.directory / "current.request.json", request)
        mailbox.poll()
        result = json.loads((mailbox.directory / "current.result.json").read_text())
        self.assertEqual(result["state"], "granted")
        fresh = json.loads(output.read_text())
        self.assertEqual(fresh["brokerOwner"], foreign["brokerOwner"])
        with self.assertRaises(PermissionError):
            self.capability.validate()

    def test_windows_namespace_is_only_a_route_not_a_caller_supplied_witness(self):
        with patch.object(sys, "platform", "win32"):
            for forged in (None, {"ownerDead": True}, "--exec", "Ubuntu/foreign", "x\nx"):
                with self.subTest(route=forged), self.assertRaises(AdmissionError):
                    physical_owner_witness.verify_owner_succession(
                        self.first["brokerOwner"], self.next["brokerOwner"],
                        realm={}, broker_namespace=forged,
                    )


if __name__ == "__main__":
    unittest.main()
