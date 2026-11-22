"""Passive ancestor proof: real SQLite CAS/leases and HTTP, no live SDK."""

import _fusion_test_bootstrap  # noqa: F401
import copy
from contextlib import closing
import hashlib
import http.client
import json
import sqlite3
import unittest
from fusion_bridge import runtime
from lib.request_admission import AdmissionError, AdmissionStore, _encode
from _physical_test_support import descriptor
import test_physical_authority
import test_admission_runtime


class HistoryStoreTests(unittest.TestCase):
    setUp = test_physical_authority.PhysicalOwnershipTests.setUp
    make_authority = test_physical_authority.PhysicalOwnershipTests.make_authority
    grant = test_physical_authority.PhysicalOwnershipTests.grant
    def capability(self):
        if hasattr(self, "current_grant"):
            return self.authority.authenticate([self.current_grant["token"]])
        return test_physical_authority.PhysicalOwnershipTests.capability(self)

    def old_turn(self, state="released", reason="dispatch-finally"):
        capability = self.capability()
        turn = capability.prepare_turn("old-turn", "document-A")
        if state != "queued":
            turn.start()
        if state == "released":
            turn.finish()
            if reason != "dispatch-finally":
                self.store._db.execute(
                    "UPDATE physical_turns SET released_by=? WHERE id='old-turn'", (reason,),
                )
        return copy.deepcopy(turn.binding)

    def successor(self, epoch="new", handoff_id="h1", *, issue=True):
        self.store.advance_generation(instance="runtime", epoch=epoch, handoff_id=handoff_id)
        self.authority.close()
        self.store.close()
        self.store = AdmissionStore(self.provision["database"],
                                    instance="runtime", epoch=epoch, create=False)
        self.addCleanup(self.store.close)
        self.provision = dict(self.provision, epoch=epoch)
        self.authority = self.make_authority()
        request = descriptor(self.authority, owner="broker-" + epoch, queue="/queue/" + epoch)
        request["handoffId"] = handoff_id
        if issue:
            self.current_grant = self.authority.issue(request)
        elif hasattr(self, "current_grant"):
            del self.current_grant
        return self.authority

    def test_successor_reads_exact_original_proof_without_weakening_current_query(self):
        binding = self.old_turn()
        original = self.authority.turn_status(binding)
        self.successor()
        self.assertEqual(self.authority.turn_status(binding), dict(state="unknown", binding=binding))
        self.assertEqual(self.authority.turn_history(binding), original)

    def test_multiple_committed_generations_prove_ancestor_not_only_parent(self):
        binding = self.old_turn()
        original = self.authority.turn_status(binding)
        self.successor()
        self.successor(epoch="third", handoff_id="h2")
        self.assertEqual(self.authority.turn_history(binding), original)

    def test_adjacent_native_chain_allows_an_ungranted_intermediate_generation(self):
        binding = self.old_turn()
        original = self.authority.turn_status(binding)
        self.successor(issue=False)
        self.successor(epoch="third", handoff_id="h2")
        self.assertEqual(self.authority.turn_history(binding), original)

    def test_ancestor_runtime_pins_are_not_replaced_by_new_runtime_pins(self):
        binding = self.old_turn()
        original = self.authority.turn_status(binding)
        self.provision = dict(self.provision, pid=self.provision["pid"] + 1000,
                              birth="successor-sdk-birth", source="successor-source", build="successor-build")
        self.successor()
        self.assertNotEqual(binding["physicalRuntime"], self.current_grant["physicalRuntime"])
        self.assertEqual(self.authority.turn_history(binding), original)

    def test_already_cancelled_before_sdk_proof_is_preserved_exactly(self):
        capability = self.capability()
        turn = capability.prepare_turn("cancelled", "document-A")
        turn.cancel_queued()
        original = self.authority.turn_status(turn.binding)
        self.successor()
        self.assertEqual(self.authority.turn_history(turn.binding), original)

    def test_original_unicode_binding_uses_the_same_compact_ascii_evidence_digest(self):
        capability = self.capability()
        turn = capability.prepare_turn("unicode", '{"creationId":"żółć-🚀"}')
        turn.start()
        turn.finish()
        expected = hashlib.sha256(_encode(dict(
            binding=turn.binding, state="released", releasedBy="dispatch-finally",
        )).encode("utf-8")).hexdigest()
        self.successor()
        result = self.authority.turn_history(turn.binding)
        self.assertEqual(result["evidenceDigest"], expected)
        self.assertEqual(result["physicalEvidenceReference"], "fmcad-physical-turn:sha256:" + expected)

    def test_history_never_releases_queued_or_active_snapshots(self):
        for state in ("queued", "active"):
            with self.subTest(state=state):
                capability = self.capability()
                turn = capability.prepare_turn("left-" + state, "document-A")
                if state == "active":
                    turn.start()
                binding = copy.deepcopy(turn.binding)
                self.successor(epoch="after-" + state, handoff_id="handoff-" + state)
                before = self.store._db.execute(
                    "SELECT binding,state,released_by FROM physical_turns WHERE id=?",
                    (binding["turnId"],),
                ).fetchone()
                self.assertEqual(self.authority.turn_history(binding),
                                 dict(state="unknown", binding=binding))
                self.assertEqual(self.store._db.execute(
                    "SELECT binding,state,released_by FROM physical_turns WHERE id=?",
                    (binding["turnId"],),
                ).fetchone(), before)

    def test_other_release_reason_has_no_history_proof(self):
        binding = self.old_turn(reason="sdk-process-exit")
        self.successor()
        self.assertEqual(self.authority.turn_history(binding), dict(state="unknown", binding=binding))

    def test_current_generation_does_not_become_history(self):
        binding = self.old_turn()
        self.assertEqual(self.authority.turn_history(binding), dict(state="unknown", binding=binding))

    def test_lost_current_authority_cannot_read_ancestor_proof(self):
        binding = self.old_turn()
        self.successor()
        self.authority.close()
        with self.assertRaises(PermissionError):
            self.authority.turn_history(binding)

    def test_current_grant_cannot_replay_a_historical_released_turn_id(self):
        binding = self.old_turn()
        self.successor()
        with self.assertRaises(AdmissionError):
            self.capability().prepare_turn(binding["turnId"], "document-B")
        self.assertEqual(self.authority.turn_history(binding)["state"], "released")

    def test_foreign_or_spliced_binding_never_gets_a_proof(self):
        binding = self.old_turn()
        self.successor()
        for key, value in (
            ("grantDigest", "0" * 64),
            ("generation", dict(instance="foreign", epoch="old")),
            ("physicalRuntime", dict(binding["physicalRuntime"], birth="foreign")),
            ("target", "document-B"),
            ("turnId", "foreign-turn"),
        ):
            query = dict(binding, **{key: value})
            with self.subTest(key=key):
                self.assertEqual(self.authority.turn_history(query),
                                 dict(state="unknown", binding=query))

    def test_foreign_store_row_is_not_authority_in_current_store(self):
        binding = self.old_turn()
        self.successor()
        foreign = dict(binding, turnId="foreign-db-turn")
        with AdmissionStore(self.directory / "foreign.sqlite", instance="runtime", epoch="old") as other:
            other.prepare_physical_turn(foreign)
            other.start_physical_turn(foreign)
            other.release_physical_turn(foreign)
            self.assertEqual(other.physical_turn_status(foreign)["state"], "released")
        self.assertEqual(self.authority.turn_history(foreign), dict(state="unknown", binding=foreign))

    def test_missing_committed_link_has_no_fallback(self):
        binding = self.old_turn()
        self.successor()
        self.successor(epoch="third", handoff_id="h2")
        self.store._db.execute("DELETE FROM physical_handoffs WHERE id='h1'")
        self.assertEqual(self.authority.turn_history(binding), dict(state="unknown", binding=binding))

    def test_shortcut_skipping_middle_generation_is_not_an_ancestor_proof(self):
        binding = self.old_turn()
        self.successor()
        self.successor(epoch="third", handoff_id="h2")
        # Keep the current owner's real h2 ID and target C, but forge A→C.
        # This remains a well-shaped acyclic graph and must still be refused.
        receipt = json.loads(self.store._db.execute(
            "SELECT result FROM physical_handoffs WHERE id='h2'",
        ).fetchone()[0])
        receipt["generation"] = binding["generation"]
        self.store._db.execute("DELETE FROM physical_handoffs WHERE id='h1'")
        self.store._db.execute("UPDATE physical_handoffs SET result=? WHERE id='h2'", (_encode(receipt),))
        self.assertEqual(self.authority.turn_history(binding), dict(state="unknown", binding=binding))

    def test_current_generation_with_a_successor_edge_is_not_a_valid_tail(self):
        binding = self.old_turn()
        self.successor()
        middle = dict(instance="runtime", epoch="new")
        self.successor(epoch="third", handoff_id="h2")
        current = dict(instance="runtime", epoch="third")
        with self.store._transaction():
            self.store._db.execute("DELETE FROM physical_handoffs")
            self.store._db.executemany("INSERT INTO physical_handoffs VALUES (?,?)", (
                ("h2", _encode(dict(handoffId="h2", generation=binding["generation"],
                                   nextGeneration=current, state="committed"))),
                ("after-current", _encode(dict(handoffId="after-current", generation=current,
                                              nextGeneration=middle, state="committed"))),
            ))
        self.assertEqual(self.authority.turn_history(binding), dict(state="unknown", binding=binding))

    def test_current_must_be_the_last_persisted_history_generation(self):
        binding = self.old_turn()
        self.successor()
        self.store._db.execute("INSERT INTO generation_history VALUES ('runtime','after-current')")
        self.assertEqual(self.authority.turn_history(binding), dict(state="unknown", binding=binding))

    def test_consistent_renamed_receipt_id_must_match_current_grant_handoff_id(self):
        binding = self.old_turn()
        self.successor()
        receipt = json.loads(self.store._db.execute(
            "SELECT result FROM physical_handoffs WHERE id='h1'",
        ).fetchone()[0])
        receipt["handoffId"] = "renamed-current"
        self.store._db.execute(
            "UPDATE physical_handoffs SET id=?,result=? WHERE id='h1'",
            ("renamed-current", _encode(receipt)),
        )
        self.assertEqual(self.authority.turn_history(binding), dict(state="unknown", binding=binding))

    def test_middle_receipt_must_match_its_existing_target_owner_handoff_id(self):
        binding = self.old_turn()
        self.successor()
        self.successor(epoch="third", handoff_id="h2")
        receipt = json.loads(self.store._db.execute(
            "SELECT result FROM physical_handoffs WHERE id='h1'",
        ).fetchone()[0])
        receipt["handoffId"] = "renamed-middle"
        self.store._db.execute(
            "UPDATE physical_handoffs SET id=?,result=? WHERE id='h1'",
            ("renamed-middle", _encode(receipt)),
        )
        self.assertEqual(self.authority.turn_history(binding), dict(state="unknown", binding=binding))

    def test_persisted_native_order_is_not_replaced_by_graph_or_name_order(self):
        binding = self.old_turn()
        self.successor()
        self.successor(epoch="third", handoff_id="h2")
        with self.store._transaction():
            self.store._db.execute("UPDATE generation_history SET rowid=-1 WHERE epoch='old'")
            self.store._db.execute("UPDATE generation_history SET rowid=1 WHERE epoch='new'")
            self.store._db.execute("UPDATE generation_history SET rowid=2 WHERE rowid=-1")
        self.assertEqual(self.authority.turn_history(binding), dict(state="unknown", binding=binding))

    def test_missing_native_ordinal_is_not_backfilled(self):
        binding = self.old_turn()
        self.successor()
        self.store._db.execute("UPDATE generation_history SET rowid=99 WHERE epoch='new'")
        self.assertEqual(self.authority.turn_history(binding), dict(state="unknown", binding=binding))

    def test_current_owner_must_remain_present_and_bound_to_actual_current_grant(self):
        binding = self.old_turn()
        self.successor()
        receipt = json.loads(self.store._db.execute(
            "SELECT result FROM physical_handoffs WHERE id='h1'",
        ).fetchone()[0])
        owner = json.loads(self.store._db.execute(
            "SELECT binding FROM physical_owners WHERE generation=?",
            (_encode(self.current_grant["generation"]),),
        ).fetchone()[0])
        receipt["handoffId"] = owner["handoffId"] = "coherently-renamed"
        self.store._db.execute("UPDATE physical_handoffs SET id=?,result=? WHERE id='h1'",
                               ("coherently-renamed", _encode(receipt)))
        self.store._db.execute("UPDATE physical_owners SET binding=? WHERE generation=?",
                               (_encode(owner), _encode(owner["generation"])))
        self.assertEqual(self.authority.turn_history(binding), dict(state="unknown", binding=binding))
        self.store._db.execute("DELETE FROM physical_owners WHERE generation=?",
                               (_encode(owner["generation"]),))
        self.assertEqual(self.authority.turn_history(binding), dict(state="unknown", binding=binding))

    def test_cycle_is_refused_even_when_target_is_reached_before_cycle(self):
        binding = self.old_turn()
        self.successor()
        self.store._db.execute("INSERT INTO physical_handoffs VALUES (?,?)", (
            "cycle", _encode(dict(handoffId="cycle", generation=dict(instance="runtime", epoch="new"),
                                 nextGeneration=binding["generation"], state="committed")),
        ))
        self.assertEqual(self.authority.turn_history(binding), dict(state="unknown", binding=binding))

    def test_ambiguous_parent_and_fork_are_refused(self):
        binding = self.old_turn()
        self.successor()
        current = dict(instance="runtime", epoch="new")
        foreign = dict(instance="runtime", epoch="foreign")
        self.store._db.execute("INSERT INTO generation_history VALUES ('runtime','foreign')")
        for source, target in ((foreign, current), (binding["generation"], foreign)):
            with self.subTest(source=source, target=target):
                self.store._db.execute("INSERT INTO physical_handoffs VALUES (?,?)", (
                    "splice", _encode(dict(handoffId="splice", generation=source,
                                          nextGeneration=target, state="committed")),
                ))
                self.assertEqual(self.authority.turn_history(binding),
                                 dict(state="unknown", binding=binding))
                self.store._db.execute("DELETE FROM physical_handoffs WHERE id='splice'")

    def test_receipt_id_state_and_generation_history_are_checked(self):
        binding = self.old_turn()
        self.successor()
        raw = self.store._db.execute("SELECT result FROM physical_handoffs WHERE id='h1'").fetchone()[0]
        receipt = json.loads(raw)
        for change in (dict(handoffId="wrong"), dict(state="completed"),
                       dict(generation=dict(instance="runtime", epoch="absent"))):
            with self.subTest(change=change):
                self.store._db.execute("UPDATE physical_handoffs SET result=? WHERE id='h1'",
                                       (_encode(dict(receipt, **change)),))
                self.assertEqual(self.authority.turn_history(binding),
                                 dict(state="unknown", binding=binding))
        self.store._db.execute("UPDATE physical_handoffs SET result=? WHERE id='h1'", (raw,))

    def test_chain_query_is_bounded(self):
        binding = self.old_turn()
        self.successor()
        with self.store._transaction():
            self.store._db.executemany("INSERT INTO physical_handoffs VALUES (?,?)",
                                      ((f"extra-{i}", "{}") for i in range(1024)))
        self.assertEqual(self.authority.turn_history(binding), dict(state="unknown", binding=binding))

    def test_history_has_no_sql_writes_or_schema_changes(self):
        binding = self.old_turn()
        self.successor()
        statements = []
        self.store._db.set_trace_callback(statements.append)
        try:
            self.assertEqual(self.authority.turn_history(binding)["state"], "released")
        finally:
            self.store._db.set_trace_callback(None)
        self.assertTrue(statements)
        self.assertTrue(all(sql.lstrip().upper().startswith("SELECT") for sql in statements), statements)


class HistoryRuntimeTests(unittest.TestCase):
    setUp = test_admission_runtime.RuntimeAdmissionContracts.setUp
    write_provision = test_admission_runtime.RuntimeAdmissionContracts.write_provision
    start_runtime = test_admission_runtime.RuntimeAdmissionContracts.start_runtime
    wait_until = test_admission_runtime.RuntimeAdmissionContracts.wait_until
    generation = test_admission_runtime.RuntimeAdmissionContracts.generation
    payload = test_admission_runtime.RuntimeAdmissionContracts.payload
    document = test_admission_runtime.RuntimeAdmissionContracts.document
    admit = test_admission_runtime.RuntimeAdmissionContracts.admit
    call = test_admission_runtime.RuntimeAdmissionContracts.call

    def query(self, path, binding, *, token=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        try:
            connection.request("POST", path, json.dumps(binding), {
                "X-Fmcad-Physical-Grant": self.grant_token if token is None else token,
            })
            response = connection.getresponse()
            body = response.read()
            return response.status, json.loads(body) if body else None
        finally:
            connection.close()

    def test_history_http_malformed_and_duplicate_auth_never_enqueue_sdk(self):
        self.start_runtime()
        authority = runtime._admission.physical
        binding = authority._turn_binding("missing", "document-A")
        self.app.fireCustomEvent.reset_mock()
        for query in (dict(binding, version=True),
                      dict(binding, physicalRuntime=dict(binding["physicalRuntime"], pid=True)),
                      dict(binding, extra="not-allowed")):
            self.assertEqual(self.query("/physical/v1/turn-history", query), (400, None))
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        try:
            body = json.dumps(binding).encode()
            connection.putrequest("POST", "/physical/v1/turn-history")
            connection.putheader("X-Fmcad-Physical-Grant", self.grant_token)
            connection.putheader("X-Fmcad-Physical-Grant", self.grant_token)
            connection.putheader("Content-Length", str(len(body)))
            connection.endheaders(body)
            response = connection.getresponse()
            self.assertEqual(response.status, 401)
            response.read()
        finally:
            connection.close()
        self.app.fireCustomEvent.assert_not_called()

    def test_actual_owner_a_unknown_finally_cas_owner_b_history_sdk0_then_new_sdk1(self):
        self.start_runtime(broker_owner="broker-A")
        document_a, effect_a = self.document()
        self.app.documents = [document_a]
        effect_a.side_effect = RuntimeError("Broker A loses the terminal observation")
        request_a, payload_a = self.payload()
        self.assertEqual(self.admit(request_a, payload_a), (200, {"state": "unknown"}))
        old_authority = runtime._admission.physical
        old_binding = old_authority._turn_binding(request_a["request"], request_a["document"])
        old_proof = old_authority.turn_status(old_binding)
        old_token = self.grant_token
        self.assertEqual(old_proof["state"], "released")
        effect_a.assert_called_once()
        self.assertTrue(runtime.handoff_admission_generation(
            instance="addin", epoch="next", handoff_id="offline-bootstrap"))
        self.provision["epoch"] = "next"
        self.write_provision()
        self.start_runtime(broker_owner="broker-B")
        self.app.fireCustomEvent.reset_mock()
        self.assertEqual(self.query("/physical/v1/turn-history", old_binding), (200, old_proof))
        self.assertEqual(self.query("/physical/v1/turn-status", old_binding),
                         (200, dict(state="unknown", binding=old_binding)))
        self.assertEqual(self.query("/physical/v1/turn-history", old_binding, token=old_token), (401, None))
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        try:
            connection.request("POST", "/mcp", payload_a, {"X-Fmcad-Physical-Grant": old_token})
            response = connection.getresponse()
            self.assertEqual(response.status, 401)
            response.read()
        finally:
            connection.close()
        self.app.fireCustomEvent.assert_not_called()
        effect_a.assert_called_once()  # Neither history nor the old POST reached SDK.
        with closing(sqlite3.connect(self.database)) as database:
            self.assertEqual(database.execute(
                "SELECT state,result FROM admissions WHERE request='request'",
            ).fetchone(), ("claimed", None))
        document_b, effect_b = self.document(creation_id="doc-B", file_id="file-B")
        self.app.documents = [document_b]
        request_b, payload_b = self.payload(
            request="request-B", arguments=dict(fileId="file-B", version=2),
            document='{"creationId":"doc-B","fileId":"file-B","version":2}',
        )
        status, result = self.admit(request_b, payload_b)
        self.assertEqual((status, result["state"]), (200, "terminal"))
        effect_b.assert_called_once()  # New owner B's legal turn reaches SDK exactly once.
