"""Public receiver contract with a controlled, delayed SDK queue substitute."""

import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lib.admission_receiver import AdmissionReceiver
from lib.request_admission import AdmissionError, AdmissionStore


class ReceiverContracts(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = AdmissionStore(str(Path(self.tmp.name) / "state.db"),
                                    instance="server", epoch="epoch")
        self.addCleanup(self.store.close)
        self.receiver = AdmissionReceiver(self.store, source="source", build="build")
        self.payload = {"name": "execute", "arguments": {"code": "original"}}
        digest = hashlib.sha256(json.dumps(
            self.payload, sort_keys=True, separators=(",", ":"),
        ).encode()).hexdigest()
        self.binding = dict(version=1, owner="owner", request="request",
                            instance="server", epoch="epoch", source="source",
                            build="build", document="doc", inputHash=digest)

    def test_duplicate_delivery_executes_frozen_input_once(self):
        _, first = self.receiver.prepare("owner", self.binding, self.payload)
        _, second = self.receiver.prepare("owner", self.binding, self.payload)
        self.payload["arguments"]["code"] = "changed after admission"
        effects = []

        def handler(payload):
            effects.append(payload["arguments"]["code"])
            return {"ok": True}

        self.assertEqual(first(handler)["state"], "terminal")
        self.assertEqual(second(handler)["state"], "terminal")
        self.assertEqual(effects, ["original"])

    def test_withdrawal_wins_before_delayed_consumer(self):
        _, callback = self.receiver.prepare("owner", self.binding, self.payload)
        self.receiver.withdraw("owner", self.binding)
        effects = []
        self.assertEqual(callback(lambda payload: effects.append(payload))["state"],
                         "withdrawn")
        self.assertEqual(effects, [])

    def test_untrusted_inputs_are_rejected_without_admission(self):
        for principal, binding in [
            ("intruder", self.binding),
            ("owner", dict(self.binding, source="other")),
            ("owner", dict(self.binding, build="other")),
            ("owner", dict(self.binding, inputHash="wrong")),
        ]:
            with self.subTest(principal=principal, binding=binding):
                with self.assertRaises(AdmissionError):
                    self.receiver.prepare(principal, binding, self.payload)
        self.assertIsNone(self.receiver.status("owner", self.binding))

    def test_handler_exception_remains_unknown_without_replay(self):
        _, callback = self.receiver.prepare("owner", self.binding, self.payload)
        effects = []

        def handler(payload):
            effects.append(payload)
            raise RuntimeError("Effect happened; response unavailable")

        with self.assertRaises(RuntimeError):
            callback(handler)
        record, retry = self.receiver.prepare("owner", self.binding, self.payload)
        self.assertEqual(record["state"], "unknown")
        self.assertIsNone(retry)
        self.assertEqual(len(effects), 1)


if __name__ == "__main__":
    unittest.main()
