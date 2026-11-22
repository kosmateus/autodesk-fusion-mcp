"""Durable operator recovery and transaction fencing; all stores are fixtures."""

import _fusion_test_bootstrap  # noqa: F401
from contextlib import closing
import copy
import hashlib
import hmac
import importlib.util
import json
import os
from pathlib import Path
import secrets
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from lib import request_admission, physical_authority, rebaseline_fence
from lib.physical_authority import PhysicalAuthority, read_private, write_private
from lib.rebaseline_fence_store import activation_for
from lib.request_admission import AdmissionStore, AdmissionError, _encode
from fusion_bridge import admission_runtime, runtime
from _physical_test_support import descriptor


class ExistingPendingFenceRegression(unittest.TestCase):
    """Run this same behavioral repro against the exact unfenced 29b source."""

    def setUp(self):
        self.module = request_admission
        source = os.environ.get("NATIVE_FENCE_ADMISSION_MODULE")
        if source:
            spec = importlib.util.spec_from_file_location("baseline_admission", source)
            self.module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(self.module)
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.store = self.module.AdmissionStore(root / "native.sqlite", instance="runtime", epoch="epoch")
        self.addCleanup(self.store.close)
        self.binding = dict(version=1, owner="owner", request="old", instance="runtime", epoch="epoch",
                            source="source", build="build", document="document", inputHash="hash")

    def pending(self):
        self.store._db.executescript("""
            CREATE TABLE provision_fences (
                request_id TEXT PRIMARY KEY,binding TEXT,key_id TEXT,key_digest TEXT,
                state TEXT,publication_json TEXT,receipt_json TEXT
            );
            CREATE TABLE provision_fence_head(singleton INTEGER PRIMARY KEY,request_id TEXT);
            INSERT INTO provision_fences VALUES ('operator-A','{}','key','digest','pending',NULL,NULL);
            INSERT INTO provision_fence_head VALUES (1,'operator-A');
        """)

    def test_pending_blocks_owner_binding_in_the_same_transaction(self):
        self.pending()
        with self.assertRaises(self.module.AdmissionError):
            self.store.bind_physical_owner(dict(generation=dict(instance="runtime", epoch="epoch")))

    def test_pending_blocks_handoff_without_another_native_cas(self):
        self.pending()
        with self.assertRaises(self.module.AdmissionError):
            self.store.advance_generation(instance="next", epoch="next", handoff_id="new")
        self.assertEqual(self.store._db.execute("SELECT * FROM generation").fetchone(),
                         (1, "runtime", "epoch"))

    def test_pending_blocks_new_admission(self):
        self.pending()
        with self.assertRaises(self.module.AdmissionError):
            self.store.admit_once(self.binding)

    def test_pending_blocks_a_stale_accepted_claim(self):
        self.store.admit(self.binding)
        self.pending()
        with self.assertRaises(self.module.AdmissionError):
            self.store.claim(self.binding)
        self.assertEqual(self.store.status(self.binding), dict(state="accepted"))

    def test_pending_blocks_new_physical_turn(self):
        self.pending()
        with self.assertRaises(self.module.AdmissionError):
            self.store.prepare_physical_turn(dict(turnId="stale", generation=dict(instance="runtime", epoch="epoch")))


class NativeFenceContracts(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.database = self.root / "native.sqlite"
        with AdmissionStore(self.database, instance="old", epoch="old") as old:
            old.advance_generation(instance="runtime", epoch="epoch", handoff_id="host-handoff")
        self.store = AdmissionStore(self.database, instance="runtime", epoch="epoch", create=False)
        self.addCleanup(self.store.close)
        self.enterContext(patch.object(physical_authority, "authority_directory",
                                      return_value=self.root / "host"))
        self.provision = dict(
            database=str(self.database), instance="runtime", epoch="epoch",
            pid=os.getpid(), birth=rebaseline_fence.observe_process_birth(os.getpid()),
            source="offline-new-fence-source", build="offline-new-fence-build",
        )
        self.authority = PhysicalAuthority(self.provision, self.store, admission_runtime._lease,
                                            version="offline", endpoint="http://127.0.0.1:0/mcp")
        self.addCleanup(self.authority.close)
        self.key = secrets.token_bytes(32)
        self.profile = dict(
            kind="fmcad-rebaseline-operator", version=1, operatorId="operator-A",
            database=str(self.database),
            runtime=dict(handoffId="host-handoff", **copy.deepcopy(self.authority._pins)),
            publicationVerifier=dict(keyId="verified-posix-writer", keyHex=self.key.hex()),
        )
        self.store_path = (str(self.root / "posix-store") if os.name != "nt" else "/linux/canonical-store")
        self.request = dict(
            requestId="operation-1", handoffId="host-handoff", expectedHead="1" * 64,
            writerGeneration="writer-A", store=dict(path=self.store_path, device=17, inode=19),
            intentReferences=[dict(path="/immutable/original-intent.json", sha256="2" * 64)],
        )

    def operator(self, name="operator-A", **changes):
        profile = copy.deepcopy(self.profile)
        profile["operatorId"] = name
        profile.update(changes)
        path = self.root / (name + ".private.json")
        write_private(path, profile)
        return rebaseline_fence.OperatorAuthority.from_private_file(path), path

    def begin(self, name="operator-A", **changes):
        authority, _ = self.operator(name)
        return rebaseline_fence.begin_fence(authority, dict(self.request, **changes))

    def publication(self, binding, **changes):
        reference = dict(
            path=self.store_path + "/runtime-rebaselines/" + binding["requestId"] + "/record.json",
            sha256="3" * 64,
        )
        publication = dict(
            store=self.store_path, storeDevice=self.request["store"]["device"],
            storeInode=self.request["store"]["inode"], expectedHead=self.request["expectedHead"],
            expectedFiles={name: None for name in (
                "physical-backend-head.json", "isolated-admission-epoch.json",
                "instance.json", "queue-state.json", "queue-state.pending.json",
                "runtime-rebaseline-head.json",
            )},
            activationFile=self.store_path + "/runtime-rebaseline-head.json",
            activationBytes=json.dumps(dict(version=1, newHead="4" * 64, record=reference),
                                       ensure_ascii=False, separators=(",", ":")),
            record=reference,
        )
        publication.update(changes)
        raw = json.dumps(publication, ensure_ascii=False, separators=(",", ":"))
        digest = hashlib.sha256(raw.encode()).hexdigest()
        mac = hmac.new(self.key, b"fmcad-posix-publication-v1\0" + _encode(dict(
            binding=binding, publicationDigest=digest,
        )).encode(), hashlib.sha256).hexdigest()
        return dict(requestId=binding["requestId"], fenceNonce=binding["fenceNonce"],
                    publicationJson=raw, attestation=dict(keyId=self.profile["publicationVerifier"]["keyId"], mac=mac))

    def grant_descriptor(self):
        request = descriptor(self.authority, owner="new-broker", queue=self.store_path)
        request["handoffId"] = "host-handoff"
        return request

    def cli(self, action, profile_path, request, *, kill_after=False, before_commit=False):
        path = self.root / (secrets.token_hex(8) + ".request.json")
        write_private(path, request)
        if not kill_after and not before_commit:
            return subprocess.run(
                [sys.executable, "-m", "lib.rebaseline_fence", action,
                 "--operator-file", str(profile_path), "--request", str(path)],
                cwd=str(Path(__file__).resolve().parents[1]), capture_output=True, text=True, timeout=15,
            )
        script = """
import json,os,sys
from contextlib import contextmanager
from pathlib import Path
from lib.rebaseline_fence import OperatorAuthority,begin_fence,consume_fence
from lib.physical_authority import read_private
from lib.request_admission import AdmissionStore
if sys.argv[4]=='before':
    original=AdmissionStore._transaction
    @contextmanager
    def crash_before_commit(self):
        with original(self):
            yield
            print('PRECOMMIT',flush=True)
            os._exit(72)
    AdmissionStore._transaction=crash_before_commit
authority=OperatorAuthority.from_private_file(Path(sys.argv[2]))
request=read_private(Path(sys.argv[3]))
result=(begin_fence if sys.argv[1]=='begin' else consume_fence)(authority,request)
print('COMMITTED',flush=True)
os._exit(71)
"""
        return subprocess.run(
            [sys.executable, "-c", script, action, str(profile_path), str(path),
             "before" if before_commit else "after"],
            cwd=str(Path(__file__).resolve().parents[1]), capture_output=True, text=True, timeout=15,
        )

    def test_absent_is_authenticated_readonly_exit_zero_not_error_fallback(self):
        _, profile = self.operator()
        before = self.database.read_bytes()
        result = self.cli("query", profile, dict(requestId="operation-1"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), dict(
            kind="fmcad-provision-fence", version=1, state="absent", requestId="operation-1",
        ))
        self.assertEqual(self.database.read_bytes(), before)
        wrong = copy.deepcopy(self.profile["runtime"])
        wrong["physicalRuntime"]["birth"] = "reused-pid-wrong-birth"
        _, bad_profile = self.operator("invalid-operator", runtime=wrong)
        refused = self.cli("query", bad_profile, dict(requestId="operation-1"))
        self.assertEqual(refused.returncode, 1)
        self.assertEqual(json.loads(refused.stdout)["state"], "refused")

    def test_regression_corrupt_pointer_without_record_table_is_never_absent(self):
        self.begin()
        operator, _ = self.operator("operator-B")
        self.store._db.execute("ALTER TABLE provision_fences RENAME TO lost_fence_records")
        with self.assertRaises((AdmissionError, sqlite3.DatabaseError)):
            rebaseline_fence.query_fence(operator, dict(requestId="operation-1"))
        _, profile = self.operator("operator-C")
        result = self.cli("query", profile, dict(requestId="operation-1"))
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout)["state"], "refused")

    def test_corrupt_dropped_table_and_missing_record_pointer_fail_closed(self):
        self.begin()
        operator, _ = self.operator()
        self.store._db.execute("UPDATE provision_fence_head SET request_id='missing-record'")
        with self.assertRaises(AdmissionError):
            rebaseline_fence.query_fence(operator, dict(requestId="missing-record"))
        self.store._db.execute("DROP TABLE provision_fences")
        with self.assertRaises((AdmissionError, sqlite3.DatabaseError)):
            rebaseline_fence.query_fence(operator, dict(requestId="operation-1"))

    def test_regression_consumed_grant_allows_legitimate_handoff_not_a_global_deadend(self):
        pending = self.begin()
        operator, _ = self.operator("operator-B")
        with self.assertRaises(AdmissionError):
            self.store.advance_generation(instance="next", epoch="next", handoff_id="ordinary-next")
        consumed = rebaseline_fence.consume_fence(operator, self.publication(pending["binding"]))
        activation = activation_for(consumed["receiptJson"])
        with self.assertRaises(AdmissionError):
            self.store.advance_generation(instance="next", epoch="next", handoff_id="ordinary-next")
        grant = self.authority.issue(self.grant_descriptor(), activation=activation)
        capability = self.authority.authenticate([grant["token"]])
        turn = capability.prepare_turn("ordinary-turn", "document-A")
        turn.start()
        turn.finish()  # Existing main-thread drain still precedes the legitimate CAS.
        receipt = self.store.advance_generation(instance="next", epoch="next", handoff_id="ordinary-next")
        self.assertEqual(receipt["state"], "committed")
        self.authority.close()
        with AdmissionStore(self.database, instance="next", epoch="next", create=False) as successor:
            provision = dict(self.provision, instance="next", epoch="next")
            next_authority = PhysicalAuthority(provision, successor, admission_runtime._lease,
                                               version="offline", endpoint="http://127.0.0.1:0/mcp")
            try:
                request = descriptor(next_authority, owner="successor", queue=self.store_path)
                request["handoffId"] = "ordinary-next"
                with self.assertRaises(AdmissionError):
                    next_authority.issue(request, activation=activation)
                ordinary = next_authority.issue(request)
                next_authority.authenticate([ordinary["token"]])
                profile = copy.deepcopy(self.profile)
                profile["operatorId"] = "operator-C"
                profile["runtime"] = dict(handoffId="ordinary-next", **copy.deepcopy(next_authority._pins))
                current_operator = rebaseline_fence.OperatorAuthority(profile)
                self.assertEqual(rebaseline_fence.query_fence(
                    current_operator, dict(requestId="operation-1"),
                ), consumed)
                successor.advance_generation(instance="third", epoch="third", handoff_id="ordinary-third")
                self.assertEqual(successor._db.execute(
                    "SELECT receipt_json FROM provision_fences WHERE request_id='operation-1'",
                ).fetchone()[0], consumed["receiptJson"])
            finally:
                next_authority.close()

    def test_ordinary_handoff_and_activation_retirement_roll_back_together(self):
        pending = self.begin()
        operator, _ = self.operator()
        consumed = rebaseline_fence.consume_fence(operator, self.publication(pending["binding"]))
        activation = activation_for(consumed["receiptJson"])
        self.authority.issue(self.grant_descriptor(), activation=activation)
        from lib import rebaseline_fence_store
        original_retire = rebaseline_fence_store.retire_after_handoff

        def interrupted(*args):
            original_retire(*args)
            raise AdmissionError("Fixture death before ordinary handoff commit")

        with patch.object(rebaseline_fence_store, "retire_after_handoff", side_effect=interrupted):
            with self.assertRaises(AdmissionError):
                self.store.advance_generation(instance="next", epoch="next", handoff_id="ordinary-next")
        self.assertEqual(self.store._db.execute("SELECT instance,epoch FROM generation").fetchone(),
                         ("runtime", "epoch"))
        self.assertIsNone(self.store._db.execute(
            "SELECT result FROM physical_handoffs WHERE id='ordinary-next'",
        ).fetchone())
        self.assertEqual(rebaseline_fence.query_fence(operator, dict(requestId="operation-1")), consumed)
        self.authority.issue(self.grant_descriptor(), activation=activation)
        self.store.advance_generation(instance="next", epoch="next", handoff_id="ordinary-next")

    def test_unproven_retirement_cannot_clear_a_pending_fence(self):
        self.begin()
        self.store._db.execute(
            "CREATE TABLE provision_fence_retirements "
            "(request_id TEXT PRIMARY KEY,handoff_id TEXT,next_instance TEXT,next_epoch TEXT)",
        )
        self.store._db.execute("INSERT INTO provision_fence_retirements VALUES (?,?,?,?)",
                               ("operation-1", "not-a-committed-handoff", "next", "next"))
        with self.assertRaises(AdmissionError):
            self.authority.issue(self.grant_descriptor())
        operator, _ = self.operator()
        with self.assertRaises(AdmissionError):
            rebaseline_fence.query_fence(operator, dict(requestId="operation-1"))

    @unittest.skipUnless(os.name == "posix", "POSIX FIFO fixture")
    def test_regression_fifo_operator_cli_naturally_refuses_without_blocking(self):
        fifo = self.root / "fifo-operator"
        os.mkfifo(fifo, 0o600)
        # timeout is a FAILURE, never a successful refusal established by killing.
        result = self.cli("query", fifo, dict(requestId="operation-1"))
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout)["state"], "refused")

    def test_private_regular_reader_accepts_exact_bytes_and_rejects_hardlinks(self):
        _, path = self.operator()
        expected = path.read_bytes()
        self.assertEqual(physical_authority._read_private_bytes(path), expected)
        alias = self.root / "hardlink-profile"
        os.link(path, alias)
        with self.assertRaises(AdmissionError):
            physical_authority._read_private_bytes(path)

    def test_private_reader_preserves_missing_file_signal_for_private_mailbox(self):
        with self.assertRaises(FileNotFoundError):
            physical_authority._read_private_bytes(self.root / "not-yet-published.json")

    @unittest.skipUnless(os.name == "posix", "POSIX opened inode race")
    def test_private_reader_rejects_path_swap_or_same_inode_modification(self):
        _, path = self.operator()
        original_fdopen = os.fdopen

        replacement = self.root / "replacement"
        write_private(replacement, dict(untrusted="other-file"))

        def swap(fd, *args, **kwargs):
            os.replace(replacement, path)
            return original_fdopen(fd, *args, **kwargs)

        with patch.object(physical_authority.os, "fdopen", side_effect=swap):
            with self.assertRaises(AdmissionError):
                physical_authority._read_private_bytes(path)
        _, path = self.operator("same-inode")

        def modify(fd, *args, **kwargs):
            with path.open("ab") as stream:
                stream.write(b" ")
            return original_fdopen(fd, *args, **kwargs)

        with patch.object(physical_authority.os, "fdopen", side_effect=modify):
            with self.assertRaises(AdmissionError):
                physical_authority._read_private_bytes(path)

    @unittest.skipUnless(os.name == "nt", "Actual Windows HANDLE/ACL/share fixture")
    def test_windows_private_reader_acl_uses_frozen_actual_handle_not_path(self):
        _, path = self.operator()
        expected = path.read_bytes()
        replacement = self.root / "replacement-profile"
        write_private(replacement, dict(database="different-native-database"))
        checker = physical_authority._check_windows_acl
        observed = []

        def check(no_path, *, handle=None):
            self.assertIsNone(no_path)
            self.assertIsNotNone(handle)
            observed.append(handle)
            with self.assertRaises(OSError):
                os.replace(replacement, path)
            with self.assertRaises(OSError):
                with path.open("wb"):
                    self.fail("Frozen HANDLE unexpectedly allowed writer")
            return checker(None, handle=handle)

        with patch.object(physical_authority, "_check_windows_acl", side_effect=check):
            self.assertEqual(physical_authority._read_private_bytes(path), expected)
        self.assertEqual(len(observed), 2)
        self.assertEqual(observed[0], observed[1])
        os.replace(replacement, path)  # No lingering share lock after verified read.
        self.assertEqual(read_private(path), dict(database="different-native-database"))

    @unittest.skipUnless(os.name == "nt", "Actual Windows HANDLE ACL refusal")
    def test_windows_public_handle_is_rejected_before_reading_secret(self):
        _, path = self.operator()
        subprocess.run(["icacls", str(path), "/grant", "*S-1-1-0:(R)"],
                       check=True, capture_output=True)
        with patch.object(physical_authority.os, "fdopen",
                          side_effect=AssertionError("Public HANDLE must not reach read")):
            with self.assertRaises(AdmissionError):
                physical_authority._read_private_bytes(path)

    def test_new_operator_and_writer_resume_same_frozen_identity_without_old_token(self):
        original = self.begin()
        resumed = self.begin("operator-B", writerGeneration="writer-B")
        self.assertEqual(resumed, original)
        authority, _ = self.operator("operator-C")
        queried = rebaseline_fence.query_fence(authority, dict(requestId="operation-1"))
        self.assertEqual(queried, original)
        self.assertEqual(queried["binding"]["initiatorOperatorId"], "operator-A")
        self.assertEqual(queried["binding"]["writerGeneration"], "writer-A")
        self.assertEqual(self.store._db.execute(
            "SELECT writer_generation FROM provision_fence_audit WHERE operator_id='operator-B'",
        ).fetchall(), [("writer-B",)])

    def test_process_a_dies_after_begin_process_b_queries_and_consumes_without_old_token(self):
        _, profile_a = self.operator()
        result = self.cli("begin", profile_a, self.request, kill_after=True)
        self.assertEqual((result.returncode, result.stdout.strip()), (71, "COMMITTED"), result.stderr)
        _, profile_b = self.operator("operator-B")
        query = self.cli("query", profile_b, dict(requestId="operation-1"))
        self.assertEqual(query.returncode, 0, query.stderr)
        pending = json.loads(query.stdout)
        with self.assertRaises(AdmissionError):
            self.authority.issue(self.grant_descriptor())
        consumed = self.cli("consume", profile_b, self.publication(pending["binding"]))
        self.assertEqual(consumed.returncode, 0, consumed.stderr)
        value = json.loads(consumed.stdout)
        self.assertEqual(value["state"], "consumed")
        self.assertEqual(value["binding"], pending["binding"])
        self.assertEqual(json.loads(value["receiptJson"])["consumedBy"], "operator-B")
        self.assertEqual(self.store._db.execute("SELECT COUNT(*) FROM physical_handoffs").fetchone()[0], 1)
        self.assertEqual(self.store._db.execute("SELECT COUNT(*) FROM physical_owners").fetchone()
                         if self.store._db.execute(
                             "SELECT 1 FROM sqlite_master WHERE name='physical_owners'",
                         ).fetchone() else (0,), (0,))

    def test_death_before_begin_commit_leaves_absent_not_a_false_pending(self):
        _, profile_a = self.operator()
        result = self.cli("begin", profile_a, self.request, before_commit=True)
        self.assertEqual((result.returncode, result.stdout.strip()), (72, "PRECOMMIT"), result.stderr)
        operator_b, _ = self.operator("operator-B")
        absent = rebaseline_fence.query_fence(operator_b, dict(requestId="operation-1"))
        self.assertEqual(absent["state"], "absent")
        resumed = rebaseline_fence.begin_fence(
            operator_b, dict(self.request, writerGeneration="writer-B"),
        )
        self.assertEqual(resumed["binding"]["initiatorOperatorId"], "operator-B")
        self.assertEqual(resumed["binding"]["writerGeneration"], "writer-B")

    def test_death_before_consume_commit_preserves_pending_for_new_operator(self):
        pending = self.begin()
        proof = self.publication(pending["binding"])
        _, profile_b = self.operator("operator-B")
        result = self.cli("consume", profile_b, proof, before_commit=True)
        self.assertEqual((result.returncode, result.stdout.strip()), (72, "PRECOMMIT"), result.stderr)
        operator_c, _ = self.operator("operator-C")
        self.assertEqual(rebaseline_fence.query_fence(operator_c, dict(requestId="operation-1")), pending)
        with self.assertRaises(AdmissionError):
            self.authority.issue(self.grant_descriptor())
        consumed = rebaseline_fence.consume_fence(operator_c, proof)
        self.assertEqual(json.loads(consumed["receiptJson"])["consumedBy"], "operator-C")
        self.assertEqual(self.store._db.execute("SELECT COUNT(*) FROM physical_handoffs").fetchone()[0], 1)

    def test_consumed_ack_loss_returns_exact_receipt_without_second_host_cas(self):
        pending = self.begin()
        proof = self.publication(pending["binding"])
        _, profile_b = self.operator("operator-B")
        result = self.cli("consume", profile_b, proof, kill_after=True)
        self.assertEqual((result.returncode, result.stdout.strip()), (71, "COMMITTED"), result.stderr)
        authority_c, _ = self.operator("operator-C")
        first = rebaseline_fence.query_fence(authority_c, dict(requestId="operation-1"))
        repeated = rebaseline_fence.consume_fence(authority_c, proof)
        self.assertEqual(repeated, first)
        self.assertEqual(json.loads(first["receiptJson"])["consumedBy"], "operator-B")
        self.assertEqual(self.store._db.execute("SELECT COUNT(*) FROM physical_handoffs").fetchone()[0], 1)

    def test_pending_blocks_concurrent_grant_admission_and_native_handoff(self):
        self.begin()
        binding = dict(version=1, owner="owner", request="never-sent", instance="runtime", epoch="epoch",
                       source="source", build="build", document="document", inputHash="hash")
        failures = []

        def competing(action):
            try:
                with AdmissionStore(self.database, instance="runtime", epoch="epoch", create=False) as store:
                    if action == "grant":
                        store.bind_physical_owner(self.grant_descriptor())
                    elif action == "admit":
                        store.admit(binding)
                    else:
                        store.advance_generation(instance="other", epoch="other", handoff_id="forbidden")
            except AdmissionError:
                failures.append(action)

        threads = [threading.Thread(target=competing, args=(action,)) for action in ("grant", "admit", "handoff")]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(6)
            self.assertFalse(thread.is_alive())
        self.assertCountEqual(failures, ["grant", "admit", "handoff"])
        self.assertEqual(self.store._db.execute("SELECT COUNT(*) FROM physical_handoffs").fetchone()[0], 1)
        self.assertEqual(self.store._db.execute("SELECT COUNT(*) FROM admissions").fetchone()[0], 0)

    def test_zero_check_to_pending_commit_has_no_interprocess_grant_gap(self):
        _, profile_a = self.operator()
        request_path = self.root / "atomic-request.json"
        write_private(request_path, self.request)
        script = """
import sys
from pathlib import Path
from lib.rebaseline_fence import OperatorAuthority,begin_fence
from lib.physical_authority import read_private
from lib.request_admission import AdmissionStore
original=AdmissionStore.__init__
def observed(self,*args,**kwargs):
    original(self,*args,**kwargs)
    def trace(sql):
        if sql.startswith("INSERT INTO provision_fences "):
            print("ZERO_CHECKED_WRITE_TX_HELD",flush=True)
            assert sys.stdin.readline().strip()=="COMMIT"
    self._db.set_trace_callback(trace)
AdmissionStore.__init__=observed
authority=OperatorAuthority.from_private_file(Path(sys.argv[1]))
begin_fence(authority,read_private(Path(sys.argv[2])))
print("PENDING_COMMITTED",flush=True)
"""
        child = subprocess.Popen(
            [sys.executable, "-c", script, str(profile_a), str(request_path)],
            cwd=str(Path(__file__).resolve().parents[1]),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        failures, started = [], threading.Event()

        def issue():
            started.set()
            try:
                with AdmissionStore(self.database, instance="runtime", epoch="epoch", create=False) as store:
                    store.bind_physical_owner(self.grant_descriptor())
            except AdmissionError:
                failures.append("fenced")

        thread = threading.Thread(target=issue)
        try:
            self.assertEqual(child.stdout.readline().strip(), "ZERO_CHECKED_WRITE_TX_HELD")
            with closing(sqlite3.connect(self.database, isolation_level=None, timeout=0.05)) as competitor:
                with self.assertRaises(sqlite3.OperationalError):
                    competitor.execute("BEGIN IMMEDIATE")
            thread.start()
            self.assertTrue(started.wait(2))
            child.stdin.write("COMMIT\n")
            child.stdin.flush()
            output, errors = child.communicate(timeout=10)
            self.assertEqual(child.returncode, 0, errors)
            self.assertEqual(output.strip(), "PENDING_COMMITTED")
            thread.join(6)
            self.assertFalse(thread.is_alive())
            self.assertEqual(failures, ["fenced"])
        finally:
            if child.poll() is None:
                child.kill()
                child.communicate(timeout=5)
            if thread.ident is not None:
                thread.join(6)

    def test_historical_unknown_turns_and_receipts_survive_begin_and_consume_unchanged(self):
        old_binding = dict(version=1, owner="old-owner", request="historical", instance="old", epoch="old",
                           source="old-source", build="old-build", document="old-document", inputHash="old-hash")
        self.store._db.execute("INSERT INTO admissions VALUES (?,?,'claimed',?,NULL)",
                               ("historical", _encode(old_binding), "original-unknown-claim"))
        self.store._turn_schema()
        self.store._db.execute("INSERT INTO physical_turns VALUES (?,?,'active',NULL)", (
            "old-active-snapshot", _encode(dict(turnId="old-active-snapshot",
                                               generation=dict(instance="old", epoch="old"))),
        ))
        tables = ("admissions", "physical_turns", "physical_handoffs", "generation_history", "generation")
        before = {table: self.store._db.execute("SELECT * FROM " + table).fetchall() for table in tables}
        pending = self.begin()
        operator, _ = self.operator("operator-B")
        rebaseline_fence.consume_fence(operator, self.publication(pending["binding"]))
        self.assertEqual(
            {table: self.store._db.execute("SELECT * FROM " + table).fetchall() for table in tables}, before,
        )

    def test_bad_binding_key_nonce_store_head_and_refs_cannot_consume(self):
        pending = self.begin()
        operator, _ = self.operator()
        original = self.publication(pending["binding"])
        variants = [
            dict(original, fenceNonce="0" * 64),
            dict(original, requestId="foreign-operation"),
            dict(original, attestation=dict(keyId="wrong", mac=original["attestation"]["mac"])),
            dict(original, attestation=dict(keyId=original["attestation"]["keyId"], mac="0" * 64)),
            self.publication(pending["binding"], store="/other/store"),
            self.publication(pending["binding"], storeInode=20),
            self.publication(pending["binding"], expectedHead="9" * 64),
            self.publication(pending["binding"], record=dict(path="/foreign/record.json", sha256="3" * 64)),
        ]
        for proof in variants:
            with self.subTest(proof_fields=list(proof)), self.assertRaises(AdmissionError):
                rebaseline_fence.consume_fence(operator, proof)
        self.assertEqual(rebaseline_fence.query_fence(operator, dict(requestId="operation-1"))["state"], "pending")

    def test_manifest_accepts_exact_root_six_and_complete_one_epoch_three(self):
        pending = self.begin()
        operator, _ = self.operator("operator-B")
        roots = json.loads(self.publication(pending["binding"])["publicationJson"])["expectedFiles"]
        self.assertEqual(len(roots), 6)
        for epoch in (None, "epoch_A-7", "x" * 128):
            files = dict(roots)
            if epoch is not None:
                files.update({
                    "admission-epochs/" + epoch + "/" + name: "a" * 64
                    for name in ("instance.json", "queue-state.json", "queue-state.pending.json")
                })
            with self.subTest(epoch=epoch):
                proof = self.publication(pending["binding"], expectedFiles=files)
                operator.verify_publication(pending["binding"], proof)

    def test_manifest_rejects_old_root_five_missing_pending_extra_and_cross_namespace(self):
        pending = self.begin()
        operator, _ = self.operator("operator-B")
        roots = json.loads(self.publication(pending["binding"])["publicationJson"])["expectedFiles"]
        epoch = {
            "admission-epochs/epoch-A/" + name: "a" * 64
            for name in ("instance.json", "queue-state.json", "queue-state.pending.json")
        }
        full = dict(roots, **epoch)
        invalid = {
            "old-root-five": {k: v for k, v in roots.items() if k != "queue-state.pending.json"},
            "missing-epoch-pending": {k: v for k, v in full.items()
                                      if k != "admission-epochs/epoch-A/queue-state.pending.json"},
            "extra-root": dict(roots, **{"unapproved.json": None}),
            "extra-epoch": dict(full, **{"admission-epochs/epoch-A/unapproved.json": None}),
            "cross-namespace": {
                **roots, "admission-epochs/epoch-A/instance.json": None,
                "admission-epochs/epoch-B/queue-state.json": None,
                "admission-epochs/epoch-A/queue-state.pending.json": None,
            },
            "two-complete-epochs": dict(full, **{
                key.replace("epoch-A", "epoch-B"): value for key, value in epoch.items()
            }),
        }
        for bad_epoch in ("..", "../epoch-A", "epoch.A", "epoch A", "", "x" * 129):
            invalid["invalid-epoch-" + bad_epoch] = dict(roots, **{
                "admission-epochs/" + bad_epoch + "/" + name: None
                for name in ("instance.json", "queue-state.json", "queue-state.pending.json")
            })
        invalid["backslash-namespace"] = dict(roots, **{
            key.replace("/", "\\"): value for key, value in epoch.items()
        })
        for name, files in invalid.items():
            # Even a trusted publisher's MAC cannot authorize a malformed scope.
            with self.subTest(layout=name), self.assertRaises(AdmissionError):
                rebaseline_fence.consume_fence(
                    operator, self.publication(pending["binding"], expectedFiles=files),
                )
        self.assertEqual(rebaseline_fence.query_fence(operator, dict(requestId="operation-1"))["state"], "pending")

    def test_root_and_epoch_pending_ledgers_and_epoch_identity_are_byte_bound(self):
        pending = self.begin()
        operator, _ = self.operator("operator-B")
        roots = json.loads(self.publication(pending["binding"])["publicationJson"])["expectedFiles"]
        files = dict(roots, **{
            "admission-epochs/epoch-A/" + name: "a" * 64
            for name in ("instance.json", "queue-state.json", "queue-state.pending.json")
        })
        original = self.publication(pending["binding"], expectedFiles=files)
        for changed in ("queue-state.pending.json", "admission-epochs/epoch-A/queue-state.pending.json",
                        "epoch-identity"):
            proof = copy.deepcopy(original)
            publication = json.loads(proof["publicationJson"])
            if changed == "epoch-identity":
                publication["expectedFiles"] = {
                    key.replace("epoch-A", "epoch-B"): value for key, value in files.items()
                }
            else:
                publication["expectedFiles"][changed] = "b" * 64
            proof["publicationJson"] = json.dumps(publication, separators=(",", ":"))
            with self.subTest(changed=changed), self.assertRaises(AdmissionError):
                rebaseline_fence.consume_fence(operator, proof)
        consumed = rebaseline_fence.consume_fence(operator, original)
        self.assertEqual(consumed["publicationJson"], original["publicationJson"])

    def test_verified_profile_composition_does_not_reopen_operator_path(self):
        _, profile_path = self.operator()
        # Trusted helper authenticates these exact bytes and retains the decoded
        # profile; a later pathname replacement must not change its authority.
        verified_profile = json.loads(physical_authority._read_private_bytes(profile_path))
        write_private(profile_path, dict(untrusted="replacement"))
        with patch.object(rebaseline_fence, "_read_private_bytes",
                          side_effect=AssertionError("must not reopen operator path")):
            operator = rebaseline_fence.OperatorAuthority(verified_profile)
            pending = rebaseline_fence.begin_fence(operator, self.request)
            self.assertEqual(rebaseline_fence.query_fence(operator, dict(requestId="operation-1")), pending)
            consumed = rebaseline_fence.consume_fence(operator, self.publication(pending["binding"]))
            self.assertEqual(consumed["state"], "consumed")

    def test_other_operation_and_mutated_original_intent_are_refused(self):
        self.begin()
        for changes in (
            dict(requestId="competitor"),
            dict(expectedHead="a" * 64),
            dict(intentReferences=[dict(path="/replaced/intent.json", sha256="2" * 64)]),
        ):
            with self.subTest(changes=changes), self.assertRaises(AdmissionError):
                self.begin("operator-B", **changes)

    def test_consumption_alone_grants_nothing_only_exact_approval_can_issue(self):
        pending = self.begin()
        operator, _ = self.operator("operator-B")
        consumed = rebaseline_fence.consume_fence(operator, self.publication(pending["binding"]))
        activation = activation_for(consumed["receiptJson"])
        request = self.grant_descriptor()
        for wrong in (None, dict(activation, newHead="f" * 64),
                      dict(activation, receiptDigest="e" * 64)):
            with self.subTest(activation=wrong), self.assertRaises(AdmissionError):
                self.authority.issue(request, activation=wrong)
        wrong_store = dict(request, brokerOwner=dict(request["brokerOwner"], queueDirectory="/other/store"))
        with self.assertRaises(AdmissionError):
            self.authority.issue(wrong_store, activation=activation)
        grant = self.authority.issue(request, activation=activation)
        self.assertEqual(self.authority.authenticate([grant["token"]])._authority, self.authority)
        self.assertEqual(self.store._db.execute("SELECT COUNT(*) FROM physical_handoffs").fetchone()[0], 1)

    def test_pending_survives_runtime_object_restart_without_new_grant(self):
        pending = self.begin()
        self.authority.close()
        replacement = PhysicalAuthority(self.provision, self.store, admission_runtime._lease,
                                         version="offline", endpoint="http://127.0.0.1:0/mcp")
        self.addCleanup(replacement.close)
        with self.assertRaises(AdmissionError):
            replacement.issue(self.grant_descriptor())
        operator, _ = self.operator("operator-B")
        self.assertEqual(rebaseline_fence.query_fence(operator, dict(requestId="operation-1")), pending)

    def test_runtime_source_birth_generation_or_operator_key_mismatch_is_not_authority(self):
        self.begin()
        for key, value in (("source", "old-runtime-source"), ("birth", "different-birth")):
            bad = copy.deepcopy(self.profile["runtime"])
            bad["physicalRuntime"][key] = value
            operator, _ = self.operator("bad-" + key, runtime=bad)
            with self.subTest(key=key), self.assertRaises(AdmissionError):
                rebaseline_fence.query_fence(operator, dict(requestId="operation-1"))
        operator, _ = self.operator("wrong-key", publicationVerifier=dict(keyId="other-key", keyHex="a" * 64))
        with self.assertRaises(AdmissionError):
            rebaseline_fence.query_fence(operator, dict(requestId="operation-1"))
        wrong_generation = copy.deepcopy(self.profile["runtime"])
        wrong_generation["generation"]["epoch"] = "stale-epoch"
        operator, _ = self.operator("wrong-generation", runtime=wrong_generation)
        with self.assertRaises(AdmissionError):
            rebaseline_fence.query_fence(operator, dict(requestId="operation-1"))

    def test_modeling_grant_or_public_booleans_are_not_an_operator_capability(self):
        public = self.root / "modeling-grant.json"
        write_private(public, dict(kind="fmcad-physical-grant", version=1, operator=True))
        with self.assertRaises(AdmissionError):
            rebaseline_fence.OperatorAuthority.from_private_file(public)
        pending = self.begin()
        operator, _ = self.operator("operator-B")
        forged = dict(self.publication(pending["binding"]), weCommitted=True)
        with self.assertRaises(AdmissionError):
            rebaseline_fence.consume_fence(operator, forged)

    def test_pending_does_not_allow_runtime_pin_replacement_or_native_handoff_rundown(self):
        pending = self.begin()
        pins = copy.deepcopy(self.authority._pins)
        pins["physicalRuntime"]["birth"] = "different-process"
        with self.assertRaises(AdmissionError):
            self.store.register_physical_runtime(pins)
        from types import SimpleNamespace
        with patch.object(runtime, "_admission", SimpleNamespace(_store=self.store)):
            with patch.object(runtime, "_begin_rundown") as rundown:
                with self.assertRaises(AdmissionError):
                    runtime.handoff_admission_generation(instance="next", epoch="next", handoff_id="no-cas")
                rundown.assert_not_called()
        operator, _ = self.operator()
        self.assertEqual(rebaseline_fence.query_fence(operator, dict(requestId="operation-1")), pending)

    def test_missing_durable_head_is_unproven_not_an_open_provision_slot(self):
        self.begin()
        self.store._db.execute("DELETE FROM provision_fence_head")
        with self.assertRaises(AdmissionError):
            self.authority.issue(self.grant_descriptor())
        with self.assertRaises(AdmissionError):
            self.begin("operator-B", writerGeneration="writer-B")

    def test_literal_publication_bytes_and_original_intent_refs_are_authenticated(self):
        pending = self.begin()
        operator, _ = self.operator("operator-B")
        proof = self.publication(pending["binding"])
        # Equivalent parsed data with different bytes is not the signed message.
        proof["publicationJson"] = json.dumps(json.loads(proof["publicationJson"]), indent=2)
        with self.assertRaises(AdmissionError):
            rebaseline_fence.consume_fence(operator, proof)
        binding = copy.deepcopy(pending["binding"])
        binding["intentReferences"][0]["sha256"] = "f" * 64
        forged = self.publication(binding)
        with self.assertRaises(AdmissionError):
            rebaseline_fence.consume_fence(operator, forged)

    def test_zero_grants_and_admissions_are_checked_in_begin_transaction(self):
        self.authority.issue(self.grant_descriptor())
        with self.assertRaises(AdmissionError):
            self.begin()
        operator, _ = self.operator()
        self.assertEqual(rebaseline_fence.query_fence(operator, dict(requestId="operation-1"))["state"], "absent")

    def test_query_of_pending_has_only_selects_and_no_audit_mutation(self):
        self.begin()
        operator, _ = self.operator("reader")
        statements = []
        from lib import rebaseline_fence_store
        self.store._db.set_trace_callback(statements.append)
        try:
            rebaseline_fence_store.query(self.store, "operation-1", operator)
        finally:
            self.store._db.set_trace_callback(None)
        self.assertTrue(statements)
        self.assertTrue(all(sql.lstrip().upper().startswith("SELECT") for sql in statements), statements)

    @unittest.skipUnless(os.name == "posix", "Actual Linux/POSIX writer publication boundary")
    def test_posix_cas_child_death_gap_resumes_exact_new_under_lock_before_native_consume(self):
        import fcntl
        directory = Path(self.store_path)
        directory.mkdir(mode=0o700)
        info = directory.stat()
        self.request["store"].update(device=info.st_dev, inode=info.st_ino)
        pointer = directory / "runtime-rebaseline-head.json"
        old_bytes = b'{"old":"frozen-unproven-history"}'
        pointer.write_bytes(old_bytes)
        with pointer.open("rb") as stream:
            os.fsync(stream.fileno())
        self.request["expectedHead"] = hashlib.sha256(old_bytes).hexdigest()
        intent = directory / "original-intent.json"
        write_private(intent, dict(original="unchanged"))
        self.request["intentReferences"] = [dict(path=str(intent), sha256=hashlib.sha256(intent.read_bytes()).hexdigest())]
        _, profile_a = self.operator()
        request_path = self.root / "writer-request.json"
        write_private(request_path, self.request)
        child_script = r"""
import fcntl,hashlib,json,os,sys
from pathlib import Path
from lib.physical_authority import read_private,write_private
from lib.rebaseline_fence import OperatorAuthority,begin_fence
from lib.request_admission import _encode
operator=OperatorAuthority.from_private_file(Path(sys.argv[1]))
request=read_private(Path(sys.argv[2]))
root=Path(request["store"]["path"])
lock=os.open(root/".writer.lock",os.O_CREAT|os.O_RDWR,0o600)
fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
pending=begin_fence(operator,request)
binding=pending["binding"]
record=root/"runtime-rebaselines"/binding["requestId"]/"record.json"
record.parent.mkdir(mode=0o700,parents=True)
write_private(record,dict(fence=binding,newHead="4"*64))
reference=dict(path=str(record),sha256=hashlib.sha256(record.read_bytes()).hexdigest())
head=root/"runtime-rebaseline-head.json"
assert hashlib.sha256(head.read_bytes()).hexdigest()==binding["oldHead"]
activation=json.dumps(dict(version=1,newHead="4"*64,record=reference),separators=(",",":"))
temporary=root/".activation-new"
fd=os.open(temporary,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
with os.fdopen(fd,"wb") as stream:
    stream.write(activation.encode());stream.flush();os.fsync(stream.fileno())
os.replace(temporary,head) # the ONE real POSIX activation CAS in this fixture
for item in (record.parent,record.parent.parent,root,root.parent):
    fd=os.open(item,os.O_RDONLY)
    try:os.fsync(fd)
    finally:os.close(fd)
assert head.read_bytes()==activation.encode()
publication=dict(store=str(root),storeDevice=request["store"]["device"],storeInode=request["store"]["inode"],
 expectedHead=binding["oldHead"],expectedFiles={name:None for name in
 ["physical-backend-head.json","isolated-admission-epoch.json","instance.json","queue-state.json","queue-state.pending.json","runtime-rebaseline-head.json"]},
 activationFile=str(head),activationBytes=activation,record=reference)
print(json.dumps(dict(binding=binding,publicationJson=json.dumps(publication,separators=(",",":")))),flush=True)
os._exit(73) # lost operator/lock after Linux CAS, before consume ACK
"""
        child = subprocess.run(
            [sys.executable, "-c", child_script, str(profile_a), str(request_path)],
            cwd=str(Path(__file__).resolve().parents[1]), capture_output=True, text=True, timeout=15,
        )
        self.assertEqual(child.returncode, 73, child.stderr)
        packet = json.loads(child.stdout)
        publication = json.loads(packet["publicationJson"])
        operator_b, _ = self.operator("operator-B")
        pending = rebaseline_fence.query_fence(operator_b, dict(requestId="operation-1"))
        self.assertEqual(pending["state"], "pending")
        self.assertEqual(pending["binding"], packet["binding"])
        # The child and its native DB transaction/OS lock are gone. The durable
        # fence, not a heartbeat, still rejects new grant and native handoff.
        with self.assertRaises(AdmissionError):
            self.authority.issue(self.grant_descriptor())
        with self.assertRaises(AdmissionError):
            self.store.advance_generation(instance="forbidden", epoch="forbidden", handoff_id="forbidden")
        lock = os.open(directory / ".writer.lock", os.O_RDWR)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)  # new operator's maintained writer lease
            self.assertEqual(pointer.read_bytes(), publication["activationBytes"].encode())
            record_path = Path(publication["record"]["path"])
            self.assertEqual(hashlib.sha256(record_path.read_bytes()).hexdigest(), publication["record"]["sha256"])
            for item in (record_path, pointer, intent):
                with item.open("rb") as stream:
                    os.fsync(stream.fileno())
            for item in (record_path.parent, record_path.parent.parent, directory, directory.parent):
                fd = os.open(item, os.O_RDONLY)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
            raw = packet["publicationJson"]
            digest = hashlib.sha256(raw.encode()).hexdigest()
            proof = dict(
                requestId="operation-1", fenceNonce=pending["binding"]["fenceNonce"],
                publicationJson=raw, attestation=dict(
                    keyId=self.profile["publicationVerifier"]["keyId"],
                    mac=hmac.new(self.key, b"fmcad-posix-publication-v1\0" + _encode(dict(
                        binding=pending["binding"], publicationDigest=digest,
                    )).encode(), hashlib.sha256).hexdigest(),
                ),
            )
            with patch.object(os, "replace", wraps=os.replace) as another_cas:
                consumed = rebaseline_fence.consume_fence(operator_b, proof)
                another_cas.assert_not_called()  # exact NEW was re-fsynced, never CASed again
            self.assertEqual(consumed["state"], "consumed")
            self.assertEqual(consumed["binding"]["initiatorOperatorId"], "operator-A")
            self.assertEqual(consumed["binding"]["writerGeneration"], "writer-A")
            self.assertEqual(json.loads(consumed["receiptJson"])["consumedBy"], "operator-B")
            self.assertEqual(pointer.read_bytes(), publication["activationBytes"].encode())
        finally:
            os.close(lock)  # only AFTER native consume ACK
        self.assertEqual(self.store._db.execute("SELECT COUNT(*) FROM admissions").fetchone()[0], 0)
        self.assertEqual(self.store._db.execute("SELECT COUNT(*) FROM physical_handoffs").fetchone()[0], 1)
