"""Module-level admission contracts, without Fusion or private implementation access."""

import importlib.util
import json
import queue
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "lib" / "request_admission.py"
spec = importlib.util.spec_from_file_location("admission", SOURCE)
admission = importlib.util.module_from_spec(spec)
spec.loader.exec_module(admission)


class AdmissionContracts(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.file = str(Path(self.tmp.name) / "state.sqlite3")
        self.binding = dict(version=1, owner="owner-a", request="request-a",
                            instance="instance-a", epoch="epoch-a", source="source-a",
                            build="build-a", document="document-a", inputHash="hash-a")
        self.store = self.open()
        self.addCleanup(self.store.close)

    def open(self):
        return admission.AdmissionStore(
            self.file, instance="instance-a", epoch="epoch-a",
        )

    def test_admission_execution_and_immutable_terminal_evidence(self):
        self.assertIsNone(self.store.status(self.binding))
        self.assertEqual(self.store.admit(self.binding)["state"], "accepted")
        self.store.admit(self.binding)
        for field in ("owner", "source", "build", "document", "inputHash", "epoch"):
            with self.subTest(field=field), self.assertRaises(admission.AdmissionError):
                self.store.admit(dict(self.binding, **{field: "other"}))
        self.assertTrue(self.store.claim(self.binding))
        self.assertFalse(self.store.claim(self.binding))
        with self.open() as observer:
            self.assertEqual(observer.status(self.binding)["state"], "unknown")
            with self.assertRaises(admission.AdmissionError):
                observer.complete(self.binding, {"ok": True})
        self.store.complete(self.binding, {"ok": True})
        self.store.complete(self.binding, {"ok": True})
        with self.assertRaises(admission.AdmissionError):
            self.store.complete(self.binding, {"ok": False})
        self.store.close()
        with self.open() as reopened:
            self.assertEqual(reopened.status(self.binding),
                             {"state": "terminal", "result": {"ok": True}})
            self.assertFalse(reopened.claim(self.binding))

    def test_withdrawal_blocks_late_delivery_and_survives_reopen(self):
        for already_admitted in (False, True):
            binding = dict(self.binding, request=str(already_admitted))
            if already_admitted:
                self.store.admit(binding)
            self.assertEqual(self.store.withdraw(binding)["state"], "withdrawn")
            with self.open() as receiver:
                self.assertEqual(receiver.admit(binding)["state"], "withdrawn")
                self.assertFalse(receiver.claim(binding))
                with self.assertRaises(admission.AdmissionError):
                    receiver.complete(binding, {"invented": "result"})

    def test_process_crash_after_effect_does_not_replay_or_invent_completion(self):
        self.store.admit(self.binding)
        effect = Path(self.tmp.name) / "effect"
        program = """
import importlib.util, json, os, sys
spec = importlib.util.spec_from_file_location("admission", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
store = module.AdmissionStore(sys.argv[2], instance="instance-a", epoch="epoch-a")
assert store.claim(json.loads(sys.argv[3]))
with open(sys.argv[4], "x") as output:
    output.write("effect")
    output.flush()
    os.fsync(output.fileno())
os._exit(23)
"""
        result = subprocess.run(
            [sys.executable, "-I", "-S", "-c", program, str(SOURCE),
             self.file, json.dumps(self.binding), str(effect)],
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(result.returncode, 23, result.stderr)
        self.assertEqual(effect.read_text(), "effect")
        with self.open() as reopened:
            self.assertEqual(reopened.status(self.binding)["state"], "unknown")
            self.assertFalse(reopened.claim(self.binding))
            with self.assertRaises(admission.AdmissionError):
                reopened.withdraw(self.binding)
            with self.assertRaises(admission.AdmissionError):
                reopened.complete(self.binding, {"invented": "result"})

    def test_independent_receivers_grant_only_one_execution(self):
        self.store.admit(self.binding)
        program = """
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("admission", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
with module.AdmissionStore(sys.argv[2], instance="instance-a", epoch="epoch-a") as store:
    print("ready", flush=True)
    assert sys.stdin.readline().strip() == "claim"
    print(json.dumps(store.claim(json.loads(sys.argv[3]))), flush=True)
"""
        children = []
        try:
            for _ in range(2):
                children.append(subprocess.Popen(
                    [sys.executable, "-I", "-S", "-c", program, str(SOURCE),
                     self.file, json.dumps(self.binding)],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, text=True,
                ))
            for child in children:
                # Windows selectors cannot wait on a subprocess pipe.
                ready = queue.Queue(maxsize=1)
                reader = threading.Thread(
                    target=lambda pipe=child.stdout, result=ready: result.put(pipe.readline()),
                    daemon=True,
                )
                reader.start()
                try:
                    self.assertEqual(ready.get(timeout=10).strip(), "ready")
                except queue.Empty:
                    # Unblock readline before cleanup calls communicate().
                    child.kill()
                    self.fail("Receiver not ready")
                finally:
                    reader.join(timeout=10)
            for child in children:
                child.stdin.write("claim\n")
                child.stdin.flush()
            claims = []
            for child in children:
                stdout, stderr = child.communicate(timeout=10)
                self.assertEqual(child.returncode, 0, stderr)
                claims.append(json.loads(stdout))
            self.assertEqual(sorted(claims), [False, True])
            self.assertEqual(self.store.status(self.binding)["state"], "unknown")
        finally:
            for child in children:
                if child.poll() is None:
                    child.kill()
                child.communicate(timeout=10)


if __name__ == "__main__":
    unittest.main()
