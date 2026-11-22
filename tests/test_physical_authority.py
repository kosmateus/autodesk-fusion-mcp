"""Physical single-owner acceptance tests: no live SDK, port or deployment."""

import _fusion_test_bootstrap  # noqa: F401
import copy
import base64
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

from fusion_bridge import admission_runtime, dispatch
from lib import physical_authority
from lib.physical_authority import PhysicalAuthority, read_private, write_private
from lib.physical_lifecycle import LifecycleMailbox, query_handoff
from lib.request_admission import AdmissionError, AdmissionStore, GenerationUnchangedError
from _physical_test_support import descriptor
from test_http_protocols import HTTPFixture, modern, sse_message


class WindowsPrivateACLTests(unittest.TestCase):
    def test_cpython_owner_rights_ace_is_bound_to_a_trusted_owner(self):
        user = "S-1-5-21-offline-user"
        for owner in (user, "S-1-5-32-544", "S-1-5-18"):
            physical_authority._validate_windows_private_acl(
                owner, user, ["S-1-5-18", "S-1-5-32-544", "S-1-3-4"],
            )
        with self.assertRaises(AdmissionError):
            physical_authority._validate_windows_private_acl(
                "S-1-5-21-foreign", user, ["S-1-3-4"],
            )

    @unittest.skipUnless(os.name == "nt", "Actual Windows private directory ACL")
    def test_new_windows_private_directory_has_only_trusted_effective_principals(self):
        snapshot = []
        validate = physical_authority._validate_windows_private_acl

        def capture(*args):
            snapshot.append(args)
            return validate(*args)

        with tempfile.TemporaryDirectory() as directory:
            with patch.object(physical_authority, "_validate_windows_private_acl",
                              side_effect=capture):
                try:
                    physical_authority.private_directory(Path(directory) / "private")
                except AdmissionError as exc:
                    self.fail(f"New private directory ACL rejected: {exc}; ACL identities={snapshot}")

    def test_elevated_administrator_owner_with_private_dacl_is_valid(self):
        user = "S-1-5-21-offline-user"
        physical_authority._validate_windows_private_acl(
            "S-1-5-32-544", user, [user, "S-1-5-18", "S-1-5-32-544"],
        )

    def test_privileged_owner_never_makes_public_or_foreign_acl_private(self):
        user = "S-1-5-21-offline-user"
        for owner, principal in (
            ("S-1-5-32-544", "S-1-1-0"),
            ("S-1-5-18", "S-1-5-11"),
            (user, "S-1-5-21-foreign"),
            ("S-1-5-21-foreign", user),
        ):
            with self.subTest(owner=owner, principal=principal):
                with self.assertRaises(AdmissionError):
                    physical_authority._validate_windows_private_acl(owner, user, [principal])


class PhysicalOwnershipTests(HTTPFixture, unittest.TestCase):
    def setUp(self):
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(patch.object(
            physical_authority, "authority_directory",
            return_value=self.directory / "host",
        ))
        self.store = AdmissionStore(self.directory / "admissions.sqlite",
                                    instance="runtime", epoch="old")
        self.addCleanup(self.store.close)
        self.provision = dict(database=str(self.directory / "admissions.sqlite"),
                              pid=os.getpid(), birth="sdk-birth", instance="runtime",
                              epoch="old", source="source", build="build")
        self.authority = self.make_authority()
        self.enterContext(patch.object(dispatch, "_halt", threading.Event()))
        self.enterContext(patch.object(dispatch, "_lifecycle_poll", None))
        self.addCleanup(dispatch.set_tool_handler, None)

    def make_authority(self, provision=None, store=None):
        authority = PhysicalAuthority(provision or self.provision, store or self.store,
                                      admission_runtime._lease, version="sdk-version",
                                      endpoint="http://127.0.0.1:8765/mcp")
        self.addCleanup(authority.close)
        return authority

    def grant(self):
        return self.authority.issue(descriptor(self.authority))

    def capability(self):
        return self.authority.authenticate([self.grant()["token"]])

    def test_two_queue_directories_race_for_one_owner(self):
        barrier = threading.Barrier(3)
        granted, denied = [], []

        def contender(queue):
            request = descriptor(self.authority, queue=queue)
            barrier.wait()
            try:
                granted.append(self.authority.issue(request))
            except AdmissionError:
                denied.append(queue)

        workers = [threading.Thread(target=contender, args=(f"/queue/{i}",)) for i in range(2)]
        for worker in workers:
            worker.start()
        barrier.wait()
        for worker in workers:
            worker.join(3)
            self.assertFalse(worker.is_alive())
        self.assertEqual((len(granted), len(denied)), (1, 1))

    def test_host_lease_rejects_another_database_and_later_rebinding(self):
        other_db = self.directory / "other.sqlite"
        with AdmissionStore(other_db, instance="runtime", epoch="old") as other:
            provision = dict(self.provision, database=str(other_db))
            with self.assertRaises(OSError):
                self.make_authority(provision, other)
            self.authority.close()
            with self.assertRaisesRegex(AdmissionError, "another database"):
                self.make_authority(provision, other)

    def test_restart_cannot_change_owner_without_generation_cas(self):
        first = self.grant()
        self.authority.close()
        restarted = self.make_authority()
        with self.assertRaises(AdmissionError):
            restarted.issue(descriptor(restarted, queue="/queue/other"))
        fresh = restarted.issue(descriptor(restarted))
        self.assertNotEqual(first["token"], fresh["token"])
        with self.assertRaises(PermissionError):
            restarted.authenticate([first["token"]])

    def test_missing_grant_is_denied_before_preflight_and_sdk(self):
        preflight = Mock()
        sdk = Mock()
        dispatch.set_tool_handler(sdk)
        with self.assertRaises(PermissionError):
            dispatch.dispatch_to_main_thread({}, admission_consumer=preflight)
        preflight.assert_not_called()
        sdk.assert_not_called()

    def test_delayed_legacy_and_admission_capabilities_are_rechecked(self):
        capability = self.capability()
        payload = dict(params=dict(name="echo"), _physical_capability=capability,
                       _physical_turn=capability.prepare_turn("delayed", "document"))
        sdk, preflight = Mock(), Mock()
        dispatch.set_tool_handler(sdk)
        self.authority.revoke()
        for consumer in (None, preflight):
            with self.assertRaises(PermissionError):
                dispatch.dispatch_to_main_thread(payload, admission_consumer=consumer)
        sdk.assert_not_called()
        preflight.assert_not_called()

    def test_current_grant_produces_exactly_one_sdk_call(self):
        sdk = Mock(return_value={"ok": True})
        dispatch.set_tool_handler(sdk)
        capability = self.capability()
        result = dispatch.dispatch_to_main_thread(
            dict(params=dict(name="echo"), _physical_capability=capability,
                 _physical_turn=capability.prepare_turn("legal", "document")),
        )
        self.assertEqual(result, {"ok": True})
        sdk.assert_called_once()

    def test_lost_sdk_result_still_releases_turn_without_settling_job(self):
        capability = self.capability()
        turn = capability.prepare_turn("lost-result", "document-A")
        self.assertEqual(self.authority.turn_status(turn.binding)["state"], "active")
        observed = []

        def lose_result(_payload):
            observed.append(self.authority.turn_status(turn.binding)["state"])
            raise RuntimeError("SDK finished but result was lost")

        dispatch.set_tool_handler(lose_result)
        with self.assertRaises(RuntimeError):
            dispatch.dispatch_to_main_thread(dict(
                _physical_capability=capability, _physical_turn=turn,
            ))
        self.assertEqual(observed, ["active"])
        result = self.authority.turn_status(turn.binding)
        self.assertEqual(result["state"], "released")
        self.assertEqual(result["physicalEvidenceReference"],
                         "fmcad-physical-turn:sha256:" + result["evidenceDigest"])
        self.assertEqual(self.store._db.execute("SELECT COUNT(*) FROM admissions").fetchone()[0], 0)
        with self.assertRaises(AdmissionError):
            capability.prepare_turn("lost-result", "document-A")

    def test_queued_turn_is_active_until_durable_cancel_and_late_event_cannot_start(self):
        capability = self.capability()
        turn = capability.prepare_turn("queued", "document-A")
        scheduled, cancelled = threading.Event(), threading.Event()
        sdk = Mock()
        dispatch.set_tool_handler(sdk)
        results = []
        payload = dict(_physical_capability=capability, _physical_turn=turn,
                       _cancel_event=cancelled)
        with patch.object(dispatch, "get_app") as app:
            app.return_value.fireCustomEvent.side_effect = lambda *_: scheduled.set()
            worker = threading.Thread(
                target=lambda: results.append(dispatch.dispatch_to_main_thread(payload)),
                daemon=True,
            )
            worker.start()
            self.assertTrue(scheduled.wait(2))
            self.assertEqual(self.authority.turn_status(turn.binding)["state"], "active")
            cancelled.set()
            worker.join(3)
            self.assertFalse(worker.is_alive())
            self.assertEqual(self.authority.turn_status(turn.binding)["state"], "released")
            dispatch._flush_pending()
        self.assertEqual(len(results), 1)
        sdk.assert_not_called()
        with self.assertRaises(AdmissionError):
            dispatch.dispatch_to_main_thread(dict(_physical_capability=capability,
                                                  _physical_turn=turn))
        sdk.assert_not_called()

    def test_foreign_turn_runtime_generation_and_target_have_no_release_proof(self):
        capability = self.capability()
        turn = capability.prepare_turn("turn", "document")
        turn.cancel_queued()
        for key, replacement in (
            ("target", "foreign"),
            ("turnId", "foreign"),
            ("generation", dict(instance="foreign", epoch="old")),
            ("physicalRuntime", dict(self.authority._pins["physicalRuntime"], birth="foreign")),
            ("grantDigest", "0" * 64),
        ):
            result = self.authority.turn_status(dict(turn.binding, **{key: replacement}))
            self.assertEqual(result["state"], "unknown")
            self.assertNotIn("evidenceDigest", result)

    def test_turn_digest_is_exact_private_grant_file_digest(self):
        import hashlib
        grant = self.grant()
        path = self.directory / "grant.json"
        write_private(path, grant)
        turn = self.authority.authenticate([grant["token"]]).prepare_turn("digest", "document")
        self.assertEqual(turn.binding["grantDigest"], hashlib.sha256(path.read_bytes()).hexdigest())

    def test_typed_http_turn_status_is_private_read_only_and_exact_bound(self):
        capability = self.capability()
        turn = capability.prepare_turn("typed-query", "document")
        turn.cancel_queued()
        self.start_server(physical_authority=self.authority)
        connection = self.connect()
        connection.request("POST", "/physical/v1/turn-status", json.dumps(turn.binding),
                           {"X-Fmcad-Physical-Grant": self.grant()["token"]})
        response = connection.getresponse()
        self.assertEqual(response.status, 200)
        result = json.loads(response.read())
        self.assertEqual(result["state"], "released")
        self.assertEqual(result["binding"], turn.binding)
        self.assertEqual(self.store._db.execute("SELECT COUNT(*) FROM admissions").fetchone()[0], 0)

    def test_both_http_protocols_carry_turn_to_actual_dispatch_and_release(self):
        self.start_server(physical_authority=self.authority,
                          tool_handlers={"echo": dispatch.dispatch_to_main_thread})
        effects = []
        dispatch.set_tool_handler(lambda payload: effects.append(payload["params"]) or {
            "content": [{"type": "text", "text": "executed"}],
        })
        for protocol in ("legacy", "modern"):
            with self.subTest(protocol=protocol):
                request, headers = modern("tools/call", dict(
                    name="echo", arguments=dict(text="requested"),
                ))
                if protocol == "legacy":
                    request["params"].pop("_meta")
                    headers = {"Content-Type": "application/json",
                               "Accept": "application/json, text/event-stream"}
                headers.update({
                    "X-Fmcad-Physical-Grant": self.grant()["token"],
                    "X-Fmcad-Physical-Turn": protocol,
                    "X-Fmcad-Physical-Target": base64.urlsafe_b64encode(b"document").decode().rstrip("="),
                })
                scheduled = threading.Event()
                results = []
                connection = self.connect()

                def post():
                    response = self.send(request, headers, connection)
                    results.append(sse_message(response))
                    response.read()

                with patch.object(dispatch, "get_app") as app:
                    app.return_value.fireCustomEvent.side_effect = lambda *_: scheduled.set()
                    worker = threading.Thread(target=post, daemon=True)
                    worker.start()
                    self.assertTrue(scheduled.wait(2))
                    binding = self.authority._turn_binding(protocol, "document")
                    self.assertEqual(self.authority.turn_status(binding)["state"], "active")
                    dispatch._flush_pending()
                    worker.join(3)
                    self.assertFalse(worker.is_alive())
                self.assertEqual(results[0]["result"]["content"][0]["text"], "executed")
                self.assertEqual(self.authority.turn_status(binding)["state"], "released")
        self.assertEqual(len(effects), 2)

    @unittest.skipIf(os.name == "nt", "Windows denies replacement of an open lease inode")
    def test_replaced_lock_inode_revokes_existing_grant(self):
        capability = self.capability()
        lease = self.authority.directory / "authority.lease"
        lease.rename(self.authority.directory / "original.lease")
        lease.touch(mode=0o600)
        with self.assertRaises(PermissionError):
            capability.validate()

    def test_cas_and_handoff_result_are_atomic_and_do_not_replay(self):
        self.store._db.execute("""
            INSERT INTO admissions VALUES ('old-request','old-binding','claimed','claim',NULL)
        """)
        before = self.store._db.execute("SELECT * FROM admissions").fetchall()
        result = self.store.advance_generation(instance="runtime", epoch="new", handoff_id="id")
        # Simulate caller death after commit: use only a new read-only connection.
        self.assertEqual(query_handoff(self.provision["database"], "id"), result)
        self.assertEqual(self.store._db.execute("SELECT * FROM admissions").fetchall(), before)
        self.assertEqual(self.store.advance_generation(
            instance="runtime", epoch="new", handoff_id="id",
        ), result)
        self.assertEqual(self.store._db.execute(
            "SELECT COUNT(*) FROM generation_history",
        ).fetchone()[0], 2)
        with self.assertRaises(GenerationUnchangedError):
            self.store.advance_generation(instance="runtime", epoch="other", handoff_id="id")

    def test_private_file_rejects_symlink_and_public_permissions(self):
        path = self.directory / "grant.json"
        write_private(path, {"test": "not-a-secret"})
        link = self.directory / "link.json"
        link.symlink_to(path)
        with self.assertRaises((AdmissionError, OSError)):
            read_private(link)
        if os.name != "nt":
            path.chmod(0o644)
            with self.assertRaises(AdmissionError):
                read_private(path)

    def test_local_mailbox_grant_writes_secret_only_to_private_output(self):
        mailbox = LifecycleMailbox(self.authority, Mock())
        output = self.directory / "grant.json"
        path = mailbox.directory / "one.request.json"
        write_private(path, dict(operation="grant", request=descriptor(self.authority),
                                 output=str(output)))
        mailbox.poll()
        grant = read_private(output)
        self.assertIn("token", grant)
        result = read_private(mailbox.directory / "one.result.json")
        self.assertNotIn("token", json.dumps(result))
        self.assertNotIn(grant["token"], json.dumps(result))
        self.assertFalse(path.exists())

    def test_http_legacy_modern_and_admission_require_private_header(self):
        api = Mock()
        self.start_server(physical_authority=self.authority, admission_api=api)
        for path in ("/mcp", "/admission/v1"):
            connection = self.connect()
            connection.request("POST", path, "{}", {"Content-Type": "application/json"})
            response = connection.getresponse()
            self.assertEqual(response.status, 401)
            response.read()
        api.handle.assert_not_called()
        request, headers = modern("tools/call", {"name": "echo", "arguments": {"text": "ok"}})
        headers["X-Fmcad-Physical-Grant"] = self.grant()["token"]
        headers["X-Fmcad-Physical-Turn"] = "http-turn"
        headers["X-Fmcad-Physical-Target"] = base64.urlsafe_b64encode(b"document").decode().rstrip("=")
        response = self.send(request, headers, self.connect())
        self.assertEqual(response.status, 200)
        self.assertEqual(sse_message(response)["result"]["content"][0]["text"], "ok")
        duplicate = self.connect()
        duplicate.putrequest("POST", "/mcp")
        duplicate.putheader("X-Fmcad-Physical-Grant", headers["X-Fmcad-Physical-Grant"])
        duplicate.putheader("X-Fmcad-Physical-Grant", headers["X-Fmcad-Physical-Grant"])
        duplicate.putheader("Content-Length", "2")
        duplicate.endheaders(b"{}")
        response = duplicate.getresponse()
        self.assertEqual(response.status, 401)
        response.read()
