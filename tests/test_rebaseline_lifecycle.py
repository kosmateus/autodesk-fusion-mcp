"""Actual runtime handoff producer with fixture SDK, never a live Fusion process."""

import _fusion_test_bootstrap  # noqa: F401
import copy
import os
import secrets
import unittest
from unittest.mock import patch

import test_admission_runtime as _runtime_tests
import test_rebaseline_fence as _fence_tests
from lib import rebaseline_fence
from lib.physical_authority import PhysicalAuthority
from lib.request_admission import AdmissionStore, AdmissionError
from lib.rebaseline_fence_store import activation_for
from fusion_bridge import admission_runtime, runtime
from _physical_test_support import descriptor


class FenceRuntimeLifecycleProducer(unittest.TestCase):
    setUp = _runtime_tests.RuntimeAdmissionContracts.setUp
    write_provision = _runtime_tests.RuntimeAdmissionContracts.write_provision
    start_runtime = _runtime_tests.RuntimeAdmissionContracts.start_runtime
    wait_until = _runtime_tests.RuntimeAdmissionContracts.wait_until
    payload = _runtime_tests.RuntimeAdmissionContracts.payload
    document = _runtime_tests.RuntimeAdmissionContracts.document
    call = _runtime_tests.RuntimeAdmissionContracts.call
    admit = _runtime_tests.RuntimeAdmissionContracts.admit

    def test_real_producer_pending_denies_consumed_grant_drains_then_next_grant_and_handoff(self):
        birth = rebaseline_fence.observe_process_birth(os.getpid())
        self.enterContext(patch.object(admission_runtime, "process_birth", return_value=birth))
        self.provision["birth"] = birth
        self.write_provision()
        with AdmissionStore(self.database, instance="before", epoch="before") as old:
            old.advance_generation(instance="addin", epoch="first", handoff_id="initial-bootstrap")
        original_issue = PhysicalAuthority.issue
        consumed, profiles = [], []
        self.root = self.database.parent.resolve()
        self.key = secrets.token_bytes(32)

        def bootstrap(authority, request, *, activation=None):
            request = dict(request, handoffId="initial-bootstrap")
            self.store_path = request["brokerOwner"]["queueDirectory"]
            self.profile = dict(
                kind="fmcad-rebaseline-operator", version=1, operatorId="original-operator",
                database=str(self.database),
                runtime=dict(handoffId="initial-bootstrap", **copy.deepcopy(authority._pins)),
                publicationVerifier=dict(keyId="verified-writer", keyHex=self.key.hex()),
            )
            operator = rebaseline_fence.OperatorAuthority(self.profile)
            self.request = dict(
                requestId="producer-rebaseline", handoffId="initial-bootstrap",
                expectedHead="1" * 64, writerGeneration="original-writer",
                store=dict(path=self.store_path, device=17, inode=19),
                intentReferences=[dict(path="/immutable/producer.json", sha256="2" * 64)],
            )
            pending = rebaseline_fence.begin_fence(operator, self.request)
            with self.assertRaises(AdmissionError):
                runtime.handoff_admission_generation(
                    instance="addin", epoch="next", handoff_id="offline-bootstrap",
                )
            proof = _fence_tests.NativeFenceContracts.publication(self, pending["binding"])
            result = rebaseline_fence.consume_fence(operator, proof)
            consumed.append(result)
            profiles.append(copy.deepcopy(self.profile))
            return original_issue(authority, request, activation=activation_for(result["receiptJson"]))

        with patch.object(PhysicalAuthority, "issue", new=bootstrap):
            self.start_runtime(broker_owner="first-owner")
        old_activation = activation_for(consumed[0]["receiptJson"])
        document, effect = self.document()
        self.app.documents = [document]
        binding, payload = self.payload()
        self.assertEqual(self.admit(binding, payload)[0], 200)
        effect.assert_called_once()
        self.assertTrue(runtime.handoff_admission_generation(
            instance="addin", epoch="next", handoff_id="offline-bootstrap",
        ))
        self.provision["epoch"] = "next"
        self.write_provision()
        self.start_runtime(broker_owner="second-owner")
        authority = runtime._admission.physical
        request = descriptor(authority, owner="second-owner")
        with self.assertRaises(AdmissionError):
            authority.issue(request, activation=old_activation)
        authority.authenticate([self.grant_token])
        profile = profiles[0]
        profile["operatorId"] = "historical-reader"
        profile["runtime"] = dict(handoffId="offline-bootstrap", **copy.deepcopy(authority._pins))
        self.assertEqual(rebaseline_fence.query_fence(
            rebaseline_fence.OperatorAuthority(profile), dict(requestId="producer-rebaseline"),
        ), consumed[0])
        self.assertTrue(runtime.handoff_admission_generation(
            instance="addin", epoch="third", handoff_id="later-ordinary",
        ))
