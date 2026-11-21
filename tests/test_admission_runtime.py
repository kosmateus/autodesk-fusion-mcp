"""Production bootstrap and HTTP/SDK dispatch, without a Fusion process."""

import _fusion_test_bootstrap  # noqa: F401
import hashlib
import http.client
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, PropertyMock, patch

from fusion_bridge import admission_document, admission_runtime, dispatch, runtime


class RuntimeAdmissionContracts(unittest.TestCase):
    def setUp(self):
        if sys.platform not in ("linux", "win32"):
            self.enterContext(patch.object(
                admission_runtime, "process_birth", return_value="offline-synthetic-birth",
            ))
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.file = Path(temp.name) / "provision.json"
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
        self.app = Mock()
        self.app.documents = []
        self.enterContext(patch.object(dispatch, "get_app", return_value=self.app))
        self.enterContext(patch.object(admission_document, "get_app", return_value=self.app))
        self.addCleanup(dispatch._halt.clear)
        self.addCleanup(dispatch.set_tool_handler, None)
        self.addCleanup(runtime.stop)

    def write_provision(self):
        self.file.write_text(json.dumps(self.provision), encoding="utf-8")

    def start_runtime(self):
        if "FUSION_MCP_ADMISSION_PROVISION" in os.environ and not self.database.exists():
            with admission_runtime.AdmissionStore(
                self.database, instance=self.provision["instance"], epoch=self.provision["epoch"],
            ):
                pass
        self.assertTrue(runtime.start())
        self.port = runtime._server.httpd.server_address[1]
        self.handler = self.app.registerCustomEvent.return_value.add.call_args.args[0]

    def call(self, operation, binding, encoded=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        try:
            message = dict(version=1, operation=operation, binding=binding)
            if encoded is not None:
                message["payloadJson"] = encoded
            conn.request("POST", "/admission/v1", json.dumps(message),
                         {"Authorization": "Bearer " + self.token})
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
                    instance="addin", epoch="next"))
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
        with sqlite3.connect(self.database) as db:
            return db.execute("SELECT instance, epoch FROM generation").fetchone()

    def test_disabled_and_invalid_provision_do_not_create_admission_database(self):
        with patch.dict(os.environ):
            os.environ.pop("FUSION_MCP_ADMISSION_PROVISION")
            self.start_runtime()
            self.assertEqual(self.call("status", self.payload()[0])[0], 404)
            self.assertTrue(runtime.stop())
        self.provision["birth"] = "stale"
        self.write_provision()
        self.assertFalse(runtime.start())
        self.provision.update(birth=admission_runtime.process_birth(), credentials={})
        self.write_provision()
        self.assertFalse(runtime.start())
        self.assertFalse(self.database.exists())
        self.provision["credentials"] = {self.token: "owner"}
        self.write_provision()
        self.assertFalse(runtime.start())
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
                instance="addin", epoch="next")
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
        self.assertTrue(runtime.handoff_admission_generation(instance="addin", epoch="next"))
        self.assertEqual(self.generation(), ("addin", "next"))
        with sqlite3.connect(self.database) as db:
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
        self.assertTrue(runtime.handoff_admission_generation(instance="addin", epoch="next"))
        read_target.assert_not_called()
