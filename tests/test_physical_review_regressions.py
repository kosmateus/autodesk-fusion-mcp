"""Regressions for Astra's physical authority review; no SDK or live runtime."""

import _fusion_test_bootstrap  # noqa: F401
import os
from pathlib import Path, PureWindowsPath
import subprocess
import threading
import unittest
from unittest.mock import Mock, patch

from lib import physical_authority
from lib.physical_authority import read_private, write_private
from lib.physical_lifecycle import LifecycleMailbox, query_handoff
from lib.request_admission import AdmissionError
from fusion_bridge import runtime
from _physical_test_support import descriptor
import test_physical_authority
import test_admission_runtime


class ReviewAuthorityRegressions(test_physical_authority.PhysicalOwnershipTests):
    # Reuse fixtures, not inherited test cases.
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

    def test_authority_database_and_lease_paths_are_forbidden_outputs(self):
        mailbox = LifecycleMailbox(self.authority, Mock())
        for number, output in enumerate((
            self.authority.directory / "database.json",
            self.authority.directory / "authority.lease",
            Path(self.provision["database"]),
            Path(self.provision["database"] + ".lease"),
        )):
            if not output.exists():
                output.touch(mode=0o600)
            before, inode = output.read_bytes(), output.stat().st_ino
            write_private(mailbox.directory / f"protected-{number}.request.json", dict(
                operation="grant", request=descriptor(self.authority), output=str(output),
            ))
            mailbox.poll()
            self.assertEqual(output.read_bytes(), before)
            self.assertEqual(output.stat().st_ino, inode)
            self.assertEqual(read_private(
                mailbox.directory / f"protected-{number}.result.json",
            )["state"], "rejected")
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


class ReviewRuntimeRegressions(test_admission_runtime.RuntimeAdmissionContracts):
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
        with patch.object(store, "advance_generation", wraps=store.advance_generation) as advance:
            with patch.object(runtime, "_retire", side_effect=RuntimeError("after committed CAS")):
                for number in range(2):
                    write_private(mailbox.directory / f"{number}.request.json",
                                  dict(operation="handoff", request=request))
                    mailbox.poll()
                    result = read_private(mailbox.directory / f"{number}.result.json")
                    self.assertEqual(result["state"], "unknown")
                    receipt = query_handoff(self.database, "retire-failed")
                    self.assertEqual(receipt["state"], "committed")
                advance.assert_called_once()
        self.assertEqual(self.generation(), ("addin", "next"))


# unittest discovers inherited methods too; these classes deliberately own only
# the new regressions while borrowing fixture/helper methods from the old suites.
for _class, _base in (
    (ReviewAuthorityRegressions, test_physical_authority.PhysicalOwnershipTests),
    (ReviewRuntimeRegressions, test_admission_runtime.RuntimeAdmissionContracts),
):
    for _name in _base.__dict__:
        if _name.startswith("test_") and _name not in _class.__dict__:
            setattr(_class, _name, None)
del _class, _base, _name
