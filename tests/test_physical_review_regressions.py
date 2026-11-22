"""Regressions for Astra's physical authority review; no SDK or live runtime."""

import _fusion_test_bootstrap  # noqa: F401
import os
from contextlib import redirect_stdout
import io
import json
from pathlib import Path, PureWindowsPath
import subprocess
import threading
import unittest
from unittest.mock import Mock, patch

from lib import physical_authority
from lib.physical_authority import read_private, write_private
from lib.physical_lifecycle import LifecycleMailbox, query_handoff
from lib import physical_lifecycle
from lib.request_admission import AdmissionError
from fusion_bridge import runtime
from _physical_test_support import descriptor
import test_physical_authority
import test_admission_runtime


class ReviewAuthorityRegressions(unittest.TestCase):
    setUp = test_physical_authority.PhysicalOwnershipTests.setUp
    make_authority = test_physical_authority.PhysicalOwnershipTests.make_authority

    def test_broker_wsl_namespace_is_not_resolved_by_windows_receiver(self):
        request = descriptor(self.authority)
        request["brokerOwner"]["queueDirectory"] = "/home/kamil/fmcad/queue"
        with patch.object(physical_authority, "Path", PureWindowsPath):
            grant = self.authority.issue(request)
        self.assertEqual(grant["brokerOwner"]["queueDirectory"], "/home/kamil/fmcad/queue")
        foreign = dict(request, brokerOwner=dict(request["brokerOwner"], queueDirectory="/other/queue"))
        with self.assertRaises(AdmissionError):
            self.authority.issue(foreign)

    def test_relative_and_lexical_queue_aliases_are_refused(self):
        for queue in ("relative/queue", "/home/kamil/../queue", "/home//queue",
                      "/home/./queue", "/home/queue/", "//home/queue"):
            with self.subTest(queue=queue):
                request = descriptor(self.authority)
                request["brokerOwner"]["queueDirectory"] = queue
                with self.assertRaises(AdmissionError):
                    self.authority.issue(request)

    def test_null_missing_empty_handoff_id_never_calls_runtime(self):
        handoff = Mock(return_value=True)
        mailbox = LifecycleMailbox(self.authority, handoff)
        for number, handoff_id in enumerate((None, "", "missing")):
            request = dict(generation=self.authority._pins["generation"],
                           nextGeneration=dict(instance="runtime", epoch="new"))
            if handoff_id != "missing":
                request["handoffId"] = handoff_id
            write_private(mailbox.directory / f"{number}.request.json",
                          dict(operation="handoff", request=request))
            mailbox.poll()
            result = read_private(mailbox.directory / f"{number}.result.json")
            self.assertEqual(result["state"], "rejected")
        handoff.assert_not_called()

    def test_existing_output_is_not_replaced_or_claimed(self):
        output = self.directory / "preserved.json"
        original = b'{"existing":"must survive"}'
        output.write_bytes(original)
        output.chmod(0o600)
        inode = output.stat().st_ino
        mailbox = LifecycleMailbox(self.authority, Mock())
        write_private(mailbox.directory / "existing.request.json", dict(
            operation="grant", request=descriptor(self.authority), output=str(output),
        ))
        mailbox.poll()
        self.assertEqual(output.read_bytes(), original)
        self.assertEqual(output.stat().st_ino, inode)
        self.assertIsNone(self.authority._grant)
        self.assertEqual(read_private(mailbox.directory / "existing.result.json")["state"], "rejected")

    def test_same_grant_publication_preserves_exact_bytes_and_inode(self):
        output = self.directory / "same-grant.json"
        request = descriptor(self.authority)
        first = self.authority.publish_grant(request, output)
        before, inode = output.read_bytes(), output.stat().st_ino
        self.assertEqual(self.authority.publish_grant(request, output), first)
        self.assertEqual(output.read_bytes(), before)
        self.assertEqual(output.stat().st_ino, inode)

    def test_semantically_equal_but_different_grant_bytes_are_not_rewritten(self):
        output = self.directory / "different-bytes.json"
        request = descriptor(self.authority)
        grant = self.authority.issue(request)
        output.write_text(json.dumps(grant, indent=2), encoding="utf-8")
        output.chmod(0o600)
        before, inode = output.read_bytes(), output.stat().st_ino
        with self.assertRaises(AdmissionError):
            self.authority.publish_grant(request, output)
        self.assertEqual(output.read_bytes(), before)
        self.assertEqual(output.stat().st_ino, inode)

    def test_authority_database_and_lease_paths_are_forbidden_outputs(self):
        mailbox = LifecycleMailbox(self.authority, Mock())
        locked_empty_files = []
        for number, output in enumerate((
            self.authority.directory / "database.json",
            self.authority.directory / "authority.lease",
            Path(self.provision["database"]),
            Path(self.provision["database"] + ".lease"),
        )):
            if not output.exists():
                output.touch(mode=0o600)
            info = output.stat()
            locked = os.name == "nt" and output == self.authority.directory / "authority.lease"
            # Windows byte-range locks deny reads even of this process's own
            # empty lease. Check metadata while held and bytes after release.
            before = None if locked else output.read_bytes()
            if locked:
                self.assertEqual(info.st_size, 0)
                locked_empty_files.append(output)
            write_private(mailbox.directory / f"protected-{number}.request.json", dict(
                operation="grant", request=descriptor(self.authority), output=str(output),
            ))
            mailbox.poll()
            if before is not None:
                self.assertEqual(output.read_bytes(), before)
            self.assertEqual(output.stat().st_ino, info.st_ino)
            self.assertEqual(output.stat().st_size, info.st_size)
            self.assertEqual(output.stat().st_mtime_ns, info.st_mtime_ns)
            self.assertEqual(read_private(
                mailbox.directory / f"protected-{number}.result.json",
            )["state"], "rejected")
        self.assertIsNone(self.authority._grant)
        self.authority.close()
        for output in locked_empty_files:
            self.assertEqual(output.read_bytes(), b"")

    def test_absent_sqlite_sidecar_is_also_a_forbidden_grant_output(self):
        output = Path(self.provision["database"] + "-wal")
        self.assertFalse(output.exists())
        with self.assertRaises(AdmissionError):
            self.authority.publish_grant(descriptor(self.authority), output)
        self.assertFalse(output.exists())
        self.assertIsNone(self.authority._grant)

    def test_two_writers_cannot_replace_a_published_file(self):
        output = self.directory / "contended.json"
        barrier = threading.Barrier(3)
        successes, failures = [], []

        def writer(number):
            barrier.wait()
            try:
                physical_authority.publish_private(output, dict(writer=number))
                successes.append(number)
            except (AdmissionError, FileExistsError):
                failures.append(number)

        workers = [threading.Thread(target=writer, args=(number,)) for number in range(2)]
        for worker in workers:
            worker.start()
        barrier.wait()
        for worker in workers:
            worker.join(3)
        self.assertEqual((len(successes), len(failures)), (1, 1))
        self.assertEqual(read_private(output), dict(writer=successes[0]))

    def test_empty_temporary_file_is_acl_checked_before_serializing_secret(self):
        observed = []

        def check(path):
            if path.name.startswith(".write-"):
                observed.append(path.stat().st_size)
                raise AdmissionError("Inherited public file ACL")

        with patch.object(physical_authority, "_check_windows_acl", side_effect=check):
            with patch.object(physical_authority.json, "dump") as serialize:
                with self.assertRaises(AdmissionError):
                    write_private(self.directory / "secret.json", dict(token="must-not-be-written"))
                serialize.assert_not_called()
        self.assertEqual(observed, [0])
        self.assertFalse(list(self.directory.glob(".write-*")))

    @unittest.skipUnless(os.name == "nt", "Actual Windows inheritable file ACL")
    def test_windows_inherit_only_public_children_acl_never_receives_secret(self):
        parent = self.directory / "inherited-public-files"
        parent.mkdir(mode=0o700)
        subprocess.run(
            ["icacls", str(parent), "/grant", "*S-1-1-0:(OI)(IO)(R)"],
            check=True, capture_output=True,
        )
        physical_authority._check_windows_acl(parent)  # Effective directory itself is private.
        with patch.object(physical_authority.json, "dump") as serialize:
            with self.assertRaises(AdmissionError):
                write_private(parent / "secret.json", dict(token="must-not-be-written"))
            serialize.assert_not_called()
        self.assertFalse((parent / "secret.json").exists())
        self.assertFalse(list(parent.glob(".write-*")))


class ReviewRuntimeRegressions(unittest.TestCase):
    setUp = test_admission_runtime.RuntimeAdmissionContracts.setUp
    write_provision = test_admission_runtime.RuntimeAdmissionContracts.write_provision
    start_runtime = test_admission_runtime.RuntimeAdmissionContracts.start_runtime
    wait_until = test_admission_runtime.RuntimeAdmissionContracts.wait_until
    generation = test_admission_runtime.RuntimeAdmissionContracts.generation

    def test_invalid_handoff_id_is_rejected_before_rundown(self):
        with patch.object(runtime, "_admission", Mock()):
            with patch.object(runtime, "_begin_rundown") as rundown:
                for value in (None, "", 12):
                    with self.subTest(value=value), self.assertRaises(ValueError):
                        runtime.handoff_admission_generation(
                            instance="addin", epoch="next", handoff_id=value,
                        )
                rundown.assert_not_called()

    def test_committed_cas_retire_failure_is_unknown_and_same_id_cannot_repeat_cas(self):
        self.start_runtime()
        request = dict(handoffId="retire-failed", generation=dict(instance="addin", epoch="first"),
                       nextGeneration=dict(instance="addin", epoch="next"))
        mailbox = LifecycleMailbox(runtime._admission.physical, runtime.handoff_admission_generation)
        store = runtime._admission._store
        input_path = self.file.parent / "handoff-input.json"
        write_private(input_path, request)
        with patch.object(store, "advance_generation", wraps=store.advance_generation) as advance:
            with patch.object(runtime, "_retire", side_effect=RuntimeError("after committed CAS")):
                with patch.object(physical_lifecycle, "authority_directory",
                                  return_value=mailbox.authority.directory):
                    with patch.object(physical_lifecycle.time, "sleep",
                                      side_effect=lambda _: mailbox.poll()):
                        for _ in range(2):
                            output = io.StringIO()
                            with redirect_stdout(output):
                                code = physical_lifecycle.main([
                                    "handoff", "--request", str(input_path), "--timeout", "2",
                                ])
                            self.assertEqual(code, 3)
                            self.assertEqual(json.loads(output.getvalue())["state"], "unknown")
                            query_output = io.StringIO()
                            with redirect_stdout(query_output):
                                self.assertEqual(physical_lifecycle.main([
                                    "query", "--database", str(self.database),
                                    "--handoff-id", "retire-failed",
                                ]), 0)
                            self.assertEqual(json.loads(query_output.getvalue())["state"], "committed")
                            self.assertEqual(query_handoff(
                                self.database, "retire-failed",
                            )["state"], "committed")
                advance.assert_called_once()
        self.assertEqual(self.generation(), ("addin", "next"))
