"""Production bootstrap and HTTP/SDK dispatch, without a Fusion process."""

import _fusion_test_bootstrap  # noqa: F401
from contextlib import closing
import hashlib
import base64
import http.client
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, PropertyMock, patch

from fusion_bridge import admission_document, admission_runtime, dispatch, runtime
from _addin_root import addon_runtime


class RuntimeAdmissionContracts(unittest.TestCase):
    def setUp(self):
        if sys.platform not in ("linux", "win32"):
            self.enterContext(patch.object(
                admission_runtime, "process_birth", return_value="offline-synthetic-birth",
            ))
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.file = Path(temp.name) / "provision.json"
        from lib import physical_authority
        self.enterContext(patch.object(physical_authority, "authority_directory",
                                      return_value=Path(temp.name) / "physical"))
        self.database = Path(temp.name) / "requests.sqlite"
        self.token = "test-token-" + "a" * 32
        self.provision = dict(
            database=str(self.database), pid=os.getpid(), birth=admission_runtime.process_birth(),
            instance="addin", epoch="first", source="source", build="build",
            credentials={self.token: "owner"},
        )
        self.write_provision()
        self.enterContext(patch.dict(os.environ, {"FUSION_MCP_ADMISSION_PROVISION": str(self.file)}))
        self.enterContext(patch.object(runtime.settings, "MCP_SERVER_PORT", 0))
        self.enterContext(patch.object(dispatch, "_schedule_tick"))
        self.enterContext(patch.object(dispatch, "_halt", threading.Event()))
        self.app = Mock()
        self.app.documents = []
        self.enterContext(patch.object(dispatch, "get_app", return_value=self.app))
        self.enterContext(patch.object(admission_document, "get_app", return_value=self.app))
        self.addCleanup(dispatch.set_tool_handler, None)
        self.addCleanup(runtime.stop)

    def write_provision(self):
        self.file.write_text(json.dumps(self.provision), encoding="utf-8")

    def start_runtime(self, *, wait_for_starter=True, broker_owner="owner"):
        if "FUSION_MCP_ADMISSION_PROVISION" in os.environ and not self.database.exists():
            with admission_runtime.AdmissionStore(
                self.database, instance=self.provision["instance"], epoch=self.provision["epoch"],
            ):
                pass
        ping = threading.Event()
        self.app.fireCustomEvent.side_effect = lambda *_: ping.set()
        self.assertTrue(runtime.start())
        self.handler = self.app.registerCustomEvent.return_value.add.call_args.args[0]
        self.assertTrue(ping.wait(2))
        self.assertIsNone(runtime._server, "Socket must not bind before readiness round-trip")
        self.handler.notify(None)
        self.wait_until(lambda: runtime._server is not None)
        if wait_for_starter:
            self.wait_until(lambda: not runtime._server_lock.locked())
        self.port = runtime._server.httpd.server_address[1]
        self.grant_token = None
        if runtime._admission is not None:
            from _physical_test_support import descriptor
            grant = runtime._admission.physical.issue(descriptor(
                runtime._admission.physical, owner=broker_owner,
            ))
            self.grant_token = grant["token"]
        self.app.fireCustomEvent.reset_mock(side_effect=True)

    def wait_until(self, predicate):
        deadline = time.monotonic() + 4
        while not predicate():
            self.assertLess(time.monotonic(), deadline, "Expected condition did not occur")
            threading.Event().wait(0.01)

    def assert_invalid_start(self):
        ping = threading.Event()
        self.app.fireCustomEvent.side_effect = lambda *_: ping.set()
        self.assertTrue(runtime.start())
        self.assertTrue(ping.wait(2))
        self.app.registerCustomEvent.return_value.add.call_args.args[0].notify(None)
        self.assertTrue(dispatch.get_shutdown_flag().wait(2))
        self.wait_until(lambda: not runtime._server_lock.locked())
        self.assertIsNone(runtime._server)
        self.assertTrue(runtime.stop())

    def call(self, operation, binding, encoded=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        try:
            message = dict(version=1, operation=operation, binding=binding)
            if encoded is not None:
                message["payloadJson"] = encoded
            headers = {"Authorization": "Bearer " + self.token}
            if getattr(self, "grant_token", None):
                headers["X-Fmcad-Physical-Grant"] = self.grant_token
                if operation == "admit":
                    headers["X-Fmcad-Physical-Turn"] = binding["request"]
                    headers["X-Fmcad-Physical-Target"] = base64.urlsafe_b64encode(
                        binding["document"].encode("utf-8"),
                    ).decode().rstrip("=")
            conn.request("POST", "/admission/v1", json.dumps(message), headers)
            response = conn.getresponse()
            body = response.read()
            return response.status, json.loads(body)["record"] if body else None
        finally:
            conn.close()

    def payload(self, *, name="get_open_document_metadata", arguments=None,
                document=None, request="request"):
        encoded = json.dumps(dict(
            jsonrpc="2.0", id=request, method="tools/call",
            params=dict(name=name, arguments=arguments if arguments is not None
                        else {"fileId": "file", "version": 2}),
        ), ensure_ascii=False)
        if document is None:
            document = '{"creationId":"target-é","fileId":"file","version":2}'
        binding = dict(version=1, owner="owner", request=request, instance="addin",
                       epoch=self.provision["epoch"], source="source", build="build",
                       document=document, inputHash=hashlib.sha256(encoded.encode()).hexdigest())
        return binding, encoded

    def admit(self, binding, encoded, *, consume=True):
        scheduled = threading.Event()
        self.app.fireCustomEvent.side_effect = lambda *_: scheduled.set()
        result = []
        thread = threading.Thread(
            target=lambda: result.append(self.call("admit", binding, encoded)), daemon=True,
        )
        thread.start()
        try:
            self.assertTrue(scheduled.wait(2))
            if consume:
                self.handler.notify(None)
            else:
                self.assertFalse(runtime.handoff_admission_generation(
                    instance="addin", epoch="next", handoff_id="offline-bootstrap"))
        finally:
            thread.join(4)
        self.assertFalse(thread.is_alive())
        self.assertEqual(len(result), 1)
        return result[0]

    def document(self, *, creation_id="target-é", file_id="file", version=2):
        document = Mock(isSaved=True, creationId=creation_id,
                        dataFile=SimpleNamespace(id=file_id, versionNumber=version))
        read_name = PropertyMock(return_value="Exact document")
        type(document).name = read_name
        document.isModified = False
        return document, read_name

    def generation(self):
        with closing(sqlite3.connect(self.database)) as db:
            return db.execute("SELECT instance, epoch FROM generation").fetchone()

    def test_disabled_and_invalid_provision_do_not_create_admission_database(self):
        with patch.dict(os.environ):
            os.environ.pop("FUSION_MCP_ADMISSION_PROVISION")
            self.start_runtime()
            self.assertEqual(self.call("status", self.payload()[0])[0], 404)
            self.assertTrue(runtime.stop())
        self.provision["birth"] = "stale"
        self.write_provision()
        self.assert_invalid_start()
        self.provision.update(birth=admission_runtime.process_birth(), credentials={})
        self.write_provision()
        self.assert_invalid_start()
        self.assertFalse(self.database.exists())
        self.provision["credentials"] = {self.token: "owner"}
        self.write_provision()
        self.assert_invalid_start()
        self.assertFalse(self.database.exists())

    def test_only_exact_off_tab_target_is_used_and_result_is_replayed_passively(self):
        self.start_runtime()
        active, read_active = self.document(creation_id="active", version=1)
        target, read_target = self.document()
        self.app.activeDocument = active
        self.app.documents = [active, target]
        binding, encoded = self.payload()
        self.assertEqual(self.call("status", binding), (200, None))
        self.assertEqual(self.call("admit", dict(binding, build="untrusted"), encoded)[0], 400)
        status, record = self.admit(binding, encoded)
        self.assertEqual(status, 200)
        self.assertEqual(record["state"], "terminal")
        metadata = json.loads(record["result"]["content"][0]["text"])
        self.assertEqual(metadata, dict(creationId="target-é", fileId="file", version=2,
                                        name="Exact document", isModified=False))
        self.assertEqual(self.call("admit", binding, encoded), (200, record))
        self.assertEqual(self.call("status", binding), (200, record))
        read_target.assert_called_once()
        read_active.assert_not_called()
        self.app.fireCustomEvent.assert_called_once()

    def test_broker_owner_is_separate_from_each_authenticated_admission_beneficiary(self):
        other_token = "other-token-" + "b" * 32
        self.provision["credentials"][other_token] = "other-beneficiary"
        self.write_provision()
        self.start_runtime(broker_owner="sole-physical-broker")
        target, read_target = self.document()
        self.app.documents = [target]
        binding, encoded = self.payload()
        self.assertEqual(self.admit(binding, encoded)[1]["state"], "terminal")
        read_target.assert_called_once()
        self.token = other_token
        self.assertEqual(self.call("status", binding)[0], 400)
        read_target.assert_called_once()
        self.app.fireCustomEvent.assert_called_once()

    def test_dynamic_tools_and_invalid_selectors_are_refused_before_enqueue(self):
        self.start_runtime()
        for name, arguments in [
            ("execute_python", {}), ("call_autodesk_api", {}),
            ("get_open_document_metadata", {"fileId": "file", "version": True}),
        ]:
            with self.subTest(name=name, arguments=arguments):
                binding, encoded = self.payload(name=name, arguments=arguments)
                self.assertEqual(self.call("admit", binding, encoded)[0], 400)
                self.assertEqual(self.call("status", binding), (200, None))
        self.app.fireCustomEvent.assert_not_called()

    def test_wrong_or_ambiguous_target_never_reaches_handler(self):
        self.start_runtime()
        target, read_target = self.document()
        other, read_other = self.document(creation_id="other")
        self.app.documents = [target]
        forged_binding, encoded = self.payload(document="not-the-resolved-document")
        self.assertEqual(self.admit(forged_binding, encoded)[0], 400)
        self.app.documents.append(other)
        binding, encoded = self.payload(request="ambiguous")
        self.assertEqual(self.admit(binding, encoded)[0], 400)
        self.app.documents.remove(other)
        self.assertEqual(self.call("status", binding), (200, {"state": "accepted"}))
        self.assertEqual(self.call("admit", binding, encoded), (200, {"state": "accepted"}))
        self.assertEqual(self.call("withdraw", binding), (200, {"state": "withdrawn"}))
        read_target.assert_not_called()
        read_other.assert_not_called()

    def test_handoff_blocks_inside_started_handler_and_preserves_unknown(self):
        self.start_runtime()
        binding, encoded = self.payload()
        target, read_target = self.document()
        self.app.documents = [target]
        observed = {}

        def fail_after_claim():
            observed["handoff"] = runtime.handoff_admission_generation(
                instance="addin", epoch="next", handoff_id="offline-bootstrap")
            observed["generation"] = self.generation()
            observed["status"] = self.call("status", binding)
            other, payload = self.payload(request="blocked")
            observed["new"] = self.call("admit", other, payload)
            raise RuntimeError("No terminal result")

        read_target.side_effect = fail_after_claim
        self.assertEqual(self.admit(binding, encoded), (200, {"state": "unknown"}))
        self.assertEqual(observed, dict(handoff=False, generation=("addin", "first"),
                                        status=(200, {"state": "unknown"}), new=(503, None)))
        old_dispatch = dispatch.bind_dispatch()
        old_handler = self.handler
        self.assertTrue(runtime.handoff_admission_generation(
            instance="addin", epoch="next", handoff_id="offline-bootstrap"))
        self.assertEqual(self.generation(), ("addin", "next"))
        with closing(sqlite3.connect(self.database)) as db:
            self.assertEqual(db.execute(
                "SELECT state, result FROM admissions WHERE request='request'").fetchone(),
                ("claimed", None))
        self.provision["epoch"] = "next"
        self.write_provision()
        self.start_runtime()
        self.assertTrue(old_dispatch({})["isError"])
        self.assertEqual(self.call("status", binding)[0], 400)
        with patch.object(dispatch, "_flush_pending") as flush:
            old_handler.notify(None)
            flush.assert_not_called()
        read_target.assert_called_once()

    def test_historical_unknown_does_not_block_independent_document_or_handoff(self):
        self.start_runtime()
        first, read_first = self.document()
        self.app.documents = [first]
        binding, encoded = self.payload()
        read_first.side_effect = RuntimeError("No durable terminal observation")
        self.assertEqual(self.admit(binding, encoded), (200, {"state": "unknown"}))
        physical = runtime._admission.physical
        proof = physical.turn_status(physical._turn_binding(binding["request"], binding["document"]))
        self.assertEqual(proof["state"], "released")
        self.assertIn("evidenceDigest", proof)
        second, read_second = self.document(creation_id="independent", file_id="other-file")
        self.app.documents.append(second)
        other_binding, other_payload = self.payload(
            request="independent-request",
            arguments={"fileId": "other-file", "version": 2},
            document='{"creationId":"independent","fileId":"other-file","version":2}',
        )
        status, result = self.admit(other_binding, other_payload)
        self.assertEqual(status, 200)
        self.assertEqual(result["state"], "terminal")
        read_first.assert_called_once()
        read_second.assert_called_once()
        self.assertEqual(self.call("admit", binding, encoded), (200, {"state": "unknown"}))
        read_first.assert_called_once()
        self.assertTrue(runtime.handoff_admission_generation(
            instance="addin", epoch="next", handoff_id="independent-handoff"))
        with closing(sqlite3.connect(self.database)) as db:
            self.assertEqual(db.execute(
                "SELECT state FROM admissions WHERE request='request'",
            ).fetchone(), ("claimed",))

    def test_handoff_rejects_queued_work_and_retires_after_http_rundown(self):
        self.start_runtime()
        binding, encoded = self.payload()
        target, read_target = self.document()
        self.app.documents = [target]
        with self.assertRaises(OSError):
            admission_runtime.AdmissionRuntime(self.provision, dispatch.bind_dispatch())
        self.assertEqual(self.admit(binding, encoded, consume=False),
                         (200, {"state": "accepted"}))
        self.handler.notify(None)
        self.assertEqual(self.generation(), ("addin", "first"))
        self.assertEqual(self.call("withdraw", binding), (200, {"state": "withdrawn"}))
        self.assertTrue(runtime.handoff_admission_generation(
            instance="addin", epoch="next", handoff_id="offline-bootstrap"))
        read_target.assert_not_called()

    def assert_handoff_waits_for_signal(self, send):
        self.start_runtime()
        firing, release = threading.Event(), threading.Event()
        self.app.fireCustomEvent.side_effect = lambda *_: (firing.set(), release.wait(4))
        worker = threading.Thread(target=send, daemon=True)
        worker.start()
        try:
            self.assertTrue(firing.wait(2))
            self.assertFalse(runtime.handoff_admission_generation(
                instance="addin", epoch="next", handoff_id="offline-bootstrap"))
            self.assertEqual(self.generation(), ("addin", "first"))
            self.app.unregisterCustomEvent.assert_not_called()
            with self.assertRaises(OSError):
                admission_runtime.AdmissionRuntime(self.provision, dispatch.bind_dispatch())
        finally:
            release.set()
            worker.join(5)
        self.assertFalse(worker.is_alive())
        self.assertTrue(runtime.handoff_admission_generation(
            instance="addin", epoch="next", handoff_id="offline-bootstrap"))
        self.assertEqual(self.generation(), ("addin", "next"))

    def test_handoff_waits_for_legacy_signal(self):
        self.assert_handoff_waits_for_signal(lambda: dispatch.bind_dispatch()({}))

    def test_handoff_waits_for_timer_signal(self):
        with patch.object(dispatch, "_last_fire_time", 0.0):
            self.assert_handoff_waits_for_signal(dispatch._fire_event_if_needed)

    def test_reentrant_host_stop_finishes_without_another_stop_call(self):
        self.start_runtime()
        target, read_name = self.document()
        self.app.documents = [target]
        binding, encoded = self.payload()
        with (patch.object(addon_runtime.commands, "stop") as commands_stop,
              patch.object(addon_runtime.futil, "clear_handlers") as clear_handlers):
            def read_while_stopping():
                addon_runtime.stop(None)
                self.assertIsNotNone(runtime._server)
                commands_stop.assert_not_called()
                return "After stop was requested"

            read_name.side_effect = read_while_stopping
            self.assertEqual(self.admit(binding, encoded)[0], 200)
            signal = threading.Event()
            self.app.fireCustomEvent.side_effect = lambda *_: signal.set()
            # As Fusion would, service main-thread control events, never another stop.
            deadline = time.monotonic() + 4
            while runtime._server is not None:
                self.assertLess(time.monotonic(), deadline)
                self.assertTrue(signal.wait(2))
                signal.clear()
                self.handler.notify(None)
            commands_stop.assert_called_once_with()
            clear_handlers.assert_called_once_with()
            self.app.unregisterCustomEvent.assert_called_once()
        with self.assertRaises(OSError):
            self.call("status", self.payload()[0])
        self.start_runtime()
        self.assertEqual(self.call("status", binding)[1]["state"], "terminal")
        read_name.assert_called_once()

    def test_busy_starter_defers_handoff_without_sealing_recovery(self):
        published, release = threading.Event(), threading.Event()
        log = runtime.log

        def hold_published_listener(message, *args):
            if message.startswith("[SUCCESS]"):
                published.set()
                release.wait(8)
            log(message, *args)

        binding, encoded = self.payload()
        during, _ = self.payload(request="withdraw-while-busy")
        after, _ = self.payload(request="withdraw-after-release")
        with patch.object(runtime, "log", side_effect=hold_published_listener):
            try:
                self.start_runtime(wait_for_starter=False)
                self.assertTrue(published.wait(2))
                self.assertTrue(runtime._server_lock.locked())
                self.assertEqual(self.call("withdraw", binding), (200, {"state": "withdrawn"}))
                with patch.object(runtime._admission, "advance_generation") as advance:
                    self.assertFalse(runtime.handoff_admission_generation(
                        instance="addin", epoch="next", handoff_id="offline-bootstrap"))
                    advance.assert_not_called()
                self.assertEqual(self.generation(), ("addin", "first"))
                self.assertEqual(self.call("admit", binding, encoded), (503, None))
                self.assertEqual(self.call("status", binding), (200, {"state": "withdrawn"}))
                self.assertEqual(self.call("withdraw", during), (200, {"state": "withdrawn"}))
            finally:
                release.set()
                self.wait_until(lambda: not runtime._server_lock.locked())

        self.assertEqual(self.call("status", binding), (200, {"state": "withdrawn"}))
        self.assertEqual(self.call("withdraw", after), (200, {"state": "withdrawn"}))
        self.assertEqual(self.call("admit", binding, encoded), (503, None))
        self.assertTrue(runtime.handoff_admission_generation(
            instance="addin", epoch="next", handoff_id="offline-bootstrap"))
        self.assertEqual(self.generation(), ("addin", "next"))

    def test_rejected_epoch_preserves_recovery_without_reopening_admit(self):
        self.start_runtime()
        binding, encoded = self.payload()
        self.assertEqual(self.call("withdraw", binding), (200, {"state": "withdrawn"}))
        with self.assertRaisesRegex(ValueError, "reuse"):
            runtime.handoff_admission_generation(
                instance="addin", epoch="first", handoff_id="offline-bootstrap")
        self.assertEqual(self.generation(), ("addin", "first"))
        self.assertEqual(self.call("status", binding), (200, {"state": "withdrawn"}))
        new, _ = self.payload(request="new")
        self.assertEqual(self.call("withdraw", new), (200, {"state": "withdrawn"}))
        self.assertEqual(self.call("admit", binding, encoded), (503, None))
        with self.assertRaisesRegex(ValueError, "required"):
            runtime.handoff_admission_generation(
                instance="addin", epoch="", handoff_id="offline-bootstrap")
        self.assertEqual(self.call("status", new), (200, {"state": "withdrawn"}))

    def test_indeterminate_transition_does_not_reopen_recovery(self):
        self.start_runtime()
        binding, _ = self.payload()
        self.assertEqual(self.call("withdraw", binding), (200, {"state": "withdrawn"}))
        store = runtime._admission._store
        advance = store.advance_generation

        def lost_outcome(**kwargs):
            advance(**kwargs)
            raise sqlite3.OperationalError("CAS result not observed")

        with patch.object(store, "advance_generation", side_effect=lost_outcome) as transition:
            with self.assertRaisesRegex(sqlite3.OperationalError, "not observed"):
                runtime.handoff_admission_generation(
                    instance="addin", epoch="next", handoff_id="offline-bootstrap")
            with self.assertRaisesRegex(ValueError, "outcome is unknown"):
                runtime.handoff_admission_generation(
                    instance="addin", epoch="next", handoff_id="offline-bootstrap")
            transition.assert_called_once()
        self.assertEqual(self.generation(), ("addin", "next"))
        self.assertEqual(self.call("status", binding), (401, None))
        self.assertEqual(self.call("withdraw", binding), (401, None))

    def test_old_ready_starter_cannot_publish_after_stop_and_restart(self):
        old_after_ping, release, old_exited = (
            threading.Event(), threading.Event(), threading.Event(),
        )
        done = []
        first = []
        wait = runtime.wait_for_main_thread
        worker = runtime._server_start_worker
        start = runtime.mcp_server_module.MCPServer.start

        def start_worker(shutdown):
            if not first:
                first.append(shutdown)
            try:
                worker(shutdown)
            finally:
                if shutdown is first[0]:
                    old_exited.set()

        def wait_at_barrier(*, poll_interval, shutdown):
            ready = wait(poll_interval, shutdown)
            if shutdown is first[0]:
                old_after_ping.set()
                release.wait(4)
            return ready

        def record_start(server):
            start(server)
            done.append(server)

        ping = threading.Event()
        self.app.fireCustomEvent.side_effect = lambda *_: ping.set()
        with (patch.object(runtime, "_server_start_worker", side_effect=start_worker),
              patch.object(runtime, "wait_for_main_thread", side_effect=wait_at_barrier),
              patch.object(runtime.mcp_server_module.MCPServer, "start", autospec=True,
                           side_effect=record_start)):
            try:
                self.assertTrue(runtime.start())
                self.assertTrue(ping.wait(2))
                self.app.registerCustomEvent.return_value.add.call_args.args[0].notify(None)
                self.assertTrue(old_after_ping.wait(2))
                self.assertTrue(runtime.stop())
                self.start_runtime()
            finally:
                release.set()
            self.assertTrue(old_exited.wait(2))
            self.assertEqual(done, [runtime._server])
