"""Real HTTP boundary with durable admission and a controlled SDK substitute."""

import json
import unittest
import threading
from unittest.mock import patch

from lib.admission_http import AdmissionHTTP
import test_admission_receiver
from test_http_protocols import HTTPFixture
from fusion_bridge import dispatch


class AdmissionHTTPContracts(HTTPFixture, unittest.TestCase):
    def setUp(self):
        test_admission_receiver.ReceiverContracts.setUp(self)
        self.effects = []
        self.sends = []

        def dispatch(payload, *, admission_consumer):
            self.sends.append(payload)
            return admission_consumer(self.execute)

        self.token = "a" * 32
        self.api = AdmissionHTTP(
            self.receiver, dispatch, credentials={self.token: "owner", "b" * 32: "other"},
        )
        self.start_server(admission_api=self.api)

    def execute(self, payload):
        self.effects.append(payload)
        return {"ok": True}

    def request(self, operation, *, token=None, binding=None):
        connection = self.connect()
        message = {"version": 1, "operation": operation,
                   "binding": binding or self.binding,
                   "payloadJson": json.dumps(self.payload, sort_keys=True, separators=(",", ":"))}
        headers = {"Content-Type": "application/json"}
        if token is not None:
            headers["Authorization"] = "Bearer " + token
        connection.request("POST", "/admission/v1", json.dumps(message), headers)
        response = connection.getresponse()
        body = response.read()
        return response.status, json.loads(body) if body else None

    def test_authentication_and_owner_are_checked_before_admission(self):
        for token, expected in [(None, 401), ("wrong", 401), ("b" * 32, 400)]:
            with self.subTest(token=token):
                self.assertEqual(self.request("admit", token=token)[0], expected)
        self.assertEqual(self.effects, [])
        self.assertIsNone(self.receiver.status("owner", self.binding))

    def test_duplicate_and_status_do_not_dispatch_again(self):
        first = self.request("admit", token=self.token)
        duplicate = self.request("admit", token=self.token)
        status = self.request("status", token=self.token)
        self.assertEqual(first[0], 200)
        self.assertEqual(first, duplicate)
        self.assertEqual(first, status)
        self.assertEqual(len(self.sends), 1)
        self.assertEqual(len(self.effects), 1)

    def test_withdrawal_blocks_late_admission_without_dispatch(self):
        withdrawn = self.request("withdraw", token=self.token)
        admitted = self.request("admit", token=self.token)
        self.assertEqual(withdrawn[0], 200)
        self.assertEqual(admitted, withdrawn)
        self.assertEqual(admitted[1]["record"]["state"], "withdrawn")
        self.assertEqual(self.sends, [])
        self.assertEqual(self.effects, [])

    def test_exception_after_effect_remains_unknown_without_retry(self):
        def interrupted(payload):
            self.effects.append(payload)
            raise ValueError("Effect occurred without terminal receipt")

        self.execute = interrupted
        self.assertEqual(self.request("admit", token=self.token)[0], 500)
        status = self.request("status", token=self.token)
        retry = self.request("admit", token=self.token)
        self.assertEqual(status[0], 200)
        self.assertEqual(status[1]["record"]["state"], "unknown")
        self.assertEqual(retry, status)
        self.assertEqual(len(self.sends), 1)
        self.assertEqual(len(self.effects), 1)

    def test_duplicate_authorization_headers_are_rejected(self):
        connection = self.connect()
        body = json.dumps({"version": 1, "operation": "admit",
                           "binding": self.binding,
                           "payloadJson": json.dumps(self.payload, sort_keys=True, separators=(",", ":"))})
        connection.putrequest("POST", "/admission/v1")
        connection.putheader("Authorization", "Bearer " + self.token)
        connection.putheader("Authorization", "Bearer " + "b" * 32)
        connection.putheader("Content-Length", str(len(body.encode())))
        connection.endheaders(body.encode())
        response = connection.getresponse()
        self.assertEqual(response.status, 401)
        response.read()
        self.assertEqual(self.sends, [])

    def test_non_integer_protocol_versions_are_rejected(self):
        for version in (True, 1.0):
            with self.subTest(version=version):
                connection = self.connect()
                message = {"version": version, "operation": "admit",
                           "binding": self.binding,
                           "payloadJson": json.dumps(self.payload, sort_keys=True, separators=(",", ":"))}
                connection.request("POST", "/admission/v1", json.dumps(message),
                                   {"Authorization": "Bearer " + self.token})
                response = connection.getresponse()
                self.assertEqual(response.status, 400)
                response.read()
        self.assertEqual(self.sends, [])

    def test_overlong_content_length_returns_controlled_error(self):
        connection = self.connect()
        connection.putrequest("POST", "/admission/v1")
        connection.putheader("Authorization", "Bearer " + self.token)
        connection.putheader("Content-Length", "9" * 5000)
        connection.endheaders()
        response = connection.getresponse()
        self.assertEqual(response.status, 400)
        response.read()
        self.assertEqual(self.sends, [])

    def test_real_dispatch_error_returns_durable_unknown_record(self):
        scheduled = threading.Event()
        responses = []

        def fail(payload):
            self.effects.append(payload)
            raise RuntimeError("Effect occurred")

        dispatch.set_tool_handler(fail)
        self.addCleanup(dispatch.set_tool_handler, None)
        self.server.admission_api = AdmissionHTTP(
            self.receiver, dispatch.dispatch_to_main_thread,
            credentials={self.token: "owner"}, timeout=2,
        )
        with patch.object(dispatch, "get_app") as app:
            app.return_value.fireCustomEvent.side_effect = lambda _: scheduled.set()
            worker = threading.Thread(
                target=lambda: responses.append(self.request("admit", token=self.token)),
                daemon=True,
            )
            worker.start()
            try:
                self.assertTrue(scheduled.wait(2))
                dispatch._BridgeEventHandler().notify(None)
            finally:
                worker.join(3)
            self.assertFalse(worker.is_alive())
        self.assertEqual(responses, [(200, {
            "version": 1, "binding": self.binding, "record": {"state": "unknown"},
        })])
        self.assertEqual(len(self.effects), 1)

    def test_stalled_real_queue_times_out_without_effect(self):
        self.server.admission_api = AdmissionHTTP(
            self.receiver, dispatch.dispatch_to_main_thread,
            credentials={self.token: "owner"}, timeout=0.05,
        )
        with patch.object(dispatch, "get_app"):
            status, body = self.request("admit", token=self.token)
        self.assertEqual(status, 200)
        self.assertEqual(body["record"]["state"], "accepted")
        dispatch.set_tool_handler(self.execute)
        self.addCleanup(dispatch.set_tool_handler, None)
        dispatch._BridgeEventHandler().notify(None)
        self.assertEqual(self.effects, [])
        withdrawn = self.request("withdraw", token=self.token)
        self.assertEqual(withdrawn[1]["record"]["state"], "withdrawn")
        self.assertEqual(self.request("admit", token=self.token), withdrawn)

    def test_capacity_refuses_new_admission_but_allows_status(self):
        entered = threading.Event()
        release = threading.Event()
        responses = []

        def blocked(payload, *, admission_consumer):
            entered.set()
            if not release.wait(2):
                raise RuntimeError("Test barrier expired")
            return admission_consumer(self.execute)

        self.server.admission_api = AdmissionHTTP(
            self.receiver, blocked, credentials={self.token: "owner"},
            max_pending=1,
        )
        worker = threading.Thread(
            target=lambda: responses.append(self.request("admit", token=self.token)),
            daemon=True,
        )
        worker.start()
        try:
            self.assertTrue(entered.wait(2))
            other = dict(self.binding, request="another-request")
            self.assertEqual(self.request("admit", token=self.token, binding=other)[0], 503)
            self.assertIsNone(self.receiver.status("owner", other))
            self.assertEqual(self.request("status", token=self.token)[0], 200)
        finally:
            release.set()
            worker.join(3)
        self.assertFalse(worker.is_alive())
        self.assertEqual(responses[0][0], 200)
        self.assertEqual(len(self.effects), 1)

    def test_duplicate_envelope_and_binding_keys_are_rejected(self):
        binding = json.dumps(self.binding)
        payload = json.dumps(json.dumps(self.payload, sort_keys=True, separators=(",", ":")))
        envelopes = [
            '{"version":1,"version":1,"operation":"admit","binding":' + binding +
            ',"payloadJson":' + payload + '}',
            '{"version":1,"operation":"admit","binding":' +
            binding.replace('"owner": "owner"', '"owner": "owner","owner": "owner"') +
            ',"payloadJson":' + payload + '}',
        ]
        for body in envelopes:
            connection = self.connect()
            connection.request("POST", "/admission/v1", body,
                               {"Authorization": "Bearer " + self.token})
            response = connection.getresponse()
            self.assertEqual(response.status, 400)
            response.read()
        self.assertEqual(self.sends, [])
        self.assertIsNone(self.receiver.status("owner", self.binding))
