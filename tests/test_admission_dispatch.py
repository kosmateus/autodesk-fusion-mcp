"""Integration of admission and the real dispatcher, with a fake SDK handler."""

import _fusion_test_bootstrap  # noqa: F401
import unittest
import threading
from unittest.mock import patch
from fusion_bridge import dispatch
import test_admission_receiver


class AdmissionDispatchContracts(unittest.TestCase):
    setUp = test_admission_receiver.ReceiverContracts.setUp

    def test_queued_withdrawal_prevents_effect_at_consumption(self):
        _, consumer = self.receiver.prepare("owner", self.binding, self.payload)
        scheduled = threading.Event()
        effects = []
        results = []
        errors = []
        dispatch.set_tool_handler(lambda payload: effects.append(payload))
        self.addCleanup(dispatch.set_tool_handler, None)

        def submit():
            try:
                results.append(dispatch.dispatch_to_main_thread(
                    self.payload, admission_consumer=consumer,
                ))
            except Exception as exc:
                errors.append(exc)

        # The SDK event signal is the barrier: the envelope is queued, but
        # the main thread has not consumed it yet.
        with patch.object(dispatch, "get_app") as get_app:
            get_app.return_value.fireCustomEvent.side_effect = lambda _: scheduled.set()
            worker = threading.Thread(target=submit, daemon=True)
            worker.start()
            try:
                self.assertTrue(scheduled.wait(2), "Dispatcher did not enqueue")
                self.receiver.withdraw("owner", self.binding)
            finally:
                dispatch._BridgeEventHandler().notify(None)
                worker.join(2)
            self.assertFalse(worker.is_alive(), "Dispatcher did not return")
        self.assertEqual(errors, [])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["state"], "withdrawn")
        self.assertEqual(effects, [])

    def test_main_thread_dispatch_checks_withdrawal_before_handler(self):
        _, consumer = self.receiver.prepare("owner", self.binding, self.payload)
        self.receiver.withdraw("owner", self.binding)
        effects = []
        dispatch.set_tool_handler(lambda payload: effects.append(payload))
        self.addCleanup(dispatch.set_tool_handler, None)
        result = dispatch.dispatch_to_main_thread(
            self.payload, admission_consumer=consumer,
        )
        self.assertEqual(result["state"], "withdrawn")
        self.assertEqual(effects, [])

    def test_main_thread_dispatch_deduplicates_and_preserves_legacy_result(self):
        _, first = self.receiver.prepare("owner", self.binding, self.payload)
        _, duplicate = self.receiver.prepare("owner", self.binding, self.payload)
        effects = []

        def handler(payload):
            effects.append(payload)
            return {"content": [{"type": "text", "text": "done"}]}

        dispatch.set_tool_handler(handler)
        self.addCleanup(dispatch.set_tool_handler, None)
        one = dispatch.dispatch_to_main_thread(self.payload, admission_consumer=first)
        self.assertIsNone(duplicate)
        two = self.receiver.status("owner", self.binding)
        self.assertEqual(one, two)
        self.assertEqual(len(effects), 1)
        legacy = dispatch.dispatch_to_main_thread(self.payload)
        self.assertEqual(legacy, one["result"])
        self.assertEqual(len(effects), 2)
