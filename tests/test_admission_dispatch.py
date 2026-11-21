"""Integration of admission and the real dispatcher, with a fake SDK handler."""

import _fusion_test_bootstrap  # noqa: F401
import unittest
from fusion_bridge import dispatch
import test_admission_receiver


class AdmissionDispatchContracts(unittest.TestCase):
    setUp = test_admission_receiver.ReceiverContracts.setUp

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
        two = dispatch.dispatch_to_main_thread(self.payload, admission_consumer=duplicate)
        self.assertEqual(one, two)
        self.assertEqual(len(effects), 1)
        legacy = dispatch.dispatch_to_main_thread(self.payload)
        self.assertEqual(legacy, one["result"])
        self.assertEqual(len(effects), 2)
