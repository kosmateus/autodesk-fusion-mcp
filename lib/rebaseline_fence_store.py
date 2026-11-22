"""Durable administrative fence in the existing AdmissionStore only."""

import hashlib
import json
import secrets

from .request_admission import AdmissionError, _encode


def _table(store, name):
    return store._db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,),
    ).fetchone() is not None


def _database(store):
    if store._path is None:
        raise AdmissionError("Rebaseline requires an existing file-backed AdmissionStore")
    info = store._path.stat()
    if (info.st_dev, info.st_ino) != store._file_identity:
        raise AdmissionError("AdmissionStore file identity changed")
    return dict(path=str(store._path), device=info.st_dev, inode=info.st_ino)


def head(store):
    return store._provision_fence_head()


def activation_for(receipt_json):
    receipt = json.loads(receipt_json)
    activation = receipt["activation"]
    return dict(
        requestId=activation["requestId"], fenceNonce=activation["fenceNonce"],
        newHead=activation["newHead"], publicationDigest=activation["publicationDigest"],
        receiptDigest=hashlib.sha256(receipt_json.encode("utf-8")).hexdigest(),
    )


def assert_activation(store, activation, *, descriptor=None):
    row = head(store)
    if row is None:
        if activation is not None:
            raise AdmissionError("No native activation approval exists")
        return
    if row[4] == "pending":
        raise AdmissionError("Durable rebaseline provision fence is pending")
    if row[6] is None or activation != activation_for(row[6]):
        raise AdmissionError("Exact consumed activation approval is required")
    binding = json.loads(row[1])
    if (binding["generation"] != dict(instance=store._instance, epoch=store._epoch)
            or (descriptor is not None and (
                descriptor["generation"] != binding["generation"]
                or descriptor["physicalRuntime"] != binding["physicalRuntime"]
                or descriptor["endpointURL"] != binding["endpointURL"]
                or descriptor["handoffId"] != binding["handoffId"]
                or descriptor["brokerOwner"]["queueDirectory"] != binding["store"]["path"]
            ))):
        raise AdmissionError("Grant does not match the approved root and physical generation")


def register_runtime(store, pins):
    with store._transaction():
        store.assert_current_generation()
        database = _database(store)
        if _table(store, "physical_runtime_binding"):
            previous = store._db.execute(
                "SELECT binding FROM physical_runtime_binding WHERE singleton=1",
            ).fetchone()
            if previous is not None and json.loads(previous[0]).get("database") != database:
                raise AdmissionError("Registered physical database identity changed")
        if pins["generation"] != dict(instance=store._instance, epoch=store._epoch):
            raise AdmissionError("Runtime registration generation mismatch")
        row = head(store)
        if row is not None:
            binding = json.loads(row[1])
            if any(binding[key] != pins[key] for key in (
                "generation", "physicalRuntime", "endpointURL",
            )):
                raise AdmissionError("Durable provision fence pins another physical runtime")
        value = dict(protocol="fmcad-provision-fence-v1", database=database, **pins)
        store._db.execute("""
            CREATE TABLE IF NOT EXISTS physical_runtime_binding (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1), binding TEXT NOT NULL
            )
        """)
        store._db.execute("INSERT OR REPLACE INTO physical_runtime_binding VALUES (1,?)",
                          (_encode(value),))


def _schema(store):
    store._db.execute("""
        CREATE TABLE IF NOT EXISTS provision_fences (
            request_id TEXT PRIMARY KEY, binding TEXT NOT NULL,
            key_id TEXT NOT NULL, key_digest TEXT NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('pending','consumed')),
            publication_json TEXT, receipt_json TEXT
        )
    """)
    store._db.execute("""
        CREATE TABLE IF NOT EXISTS provision_fence_head (
            singleton INTEGER PRIMARY KEY CHECK(singleton=1), request_id TEXT NOT NULL
        )
    """)
    store._db.execute("""
        CREATE TABLE IF NOT EXISTS provision_fence_audit (
            request_id TEXT NOT NULL, operator_id TEXT NOT NULL, action TEXT NOT NULL,
            writer_generation TEXT NOT NULL,
            PRIMARY KEY(request_id,operator_id,action,writer_generation)
        )
    """)


def _verify_runtime(store, authority):
    store.assert_current_generation()
    authority.verify_process()
    if not _table(store, "physical_runtime_binding"):
        raise AdmissionError("Running runtime has no native provision-fence support")
    row = store._db.execute("SELECT binding FROM physical_runtime_binding WHERE singleton=1").fetchone()
    expected = dict(
        protocol="fmcad-provision-fence-v1", database=_database(store),
        **{key: authority.runtime[key] for key in ("generation", "physicalRuntime", "endpointURL")},
    )
    if row is None or row[0] != _encode(expected):
        raise AdmissionError("Verified physical runtime binding changed")
    runtime = authority.runtime
    if runtime["generation"] != dict(instance=store._instance, epoch=store._epoch):
        raise AdmissionError("Operator capability is bound to another generation")
    if not _table(store, "physical_handoffs"):
        raise AdmissionError("Current committed native handoff is required")
    receipt = store._db.execute(
        "SELECT result FROM physical_handoffs WHERE id=?", (runtime["handoffId"],),
    ).fetchone()
    if receipt is None:
        raise AdmissionError("Current committed native handoff is required")
    value = json.loads(receipt[0])
    if (value.get("state") != "committed" or value.get("handoffId") != runtime["handoffId"]
            or value.get("nextGeneration") != runtime["generation"]):
        raise AdmissionError("Current committed native handoff does not match")


def _assert_empty(store):
    generation = dict(instance=store._instance, epoch=store._epoch)
    if _table(store, "physical_owners") and store._db.execute(
        "SELECT 1 FROM physical_owners WHERE generation=?", (_encode(generation),),
    ).fetchone():
        raise AdmissionError("Current generation has an issued physical owner/grant")
    for table in ("admissions", "physical_turns"):
        if not _table(store, table):
            continue
        for (raw,) in store._db.execute("SELECT binding FROM " + table):
            try:
                binding = json.loads(raw)
                pin = (binding["generation"] if table == "physical_turns"
                       else dict(instance=binding["instance"], epoch=binding["epoch"]))
            except (ValueError, TypeError, KeyError):
                raise AdmissionError("Cannot prove absence of current admissions/turns") from None
            if pin == generation:
                raise AdmissionError("Current generation has admissions or physical turns")


def _row(store, request_id, authority):
    row = store._db.execute(
        "SELECT request_id,binding,key_id,key_digest,state,publication_json,receipt_json "
        "FROM provision_fences WHERE request_id=?", (request_id,),
    ).fetchone()
    if row is not None and (row[2], row[3]) != (authority.key_id, authority.key_digest):
        raise AdmissionError("Operation belongs to another private verifier")
    return row


def _audit(store, request_id, authority, action, writer_generation=""):
    store._db.execute("INSERT OR IGNORE INTO provision_fence_audit VALUES (?,?,?,?)",
                      (request_id, authority.operator_id, action, writer_generation))


def _response(row, authority):
    result = dict(kind="fmcad-provision-fence", version=1, state=row[4], binding=json.loads(row[1]))
    if row[4] == "consumed":
        result.update(publicationJson=row[5], receiptJson=row[6],
                      receiptDigest=hashlib.sha256(row[6].encode("utf-8")).hexdigest(),
                      receiptMac=authority.receipt_mac(row[6]))
    return result


def begin(store, facts, authority):
    with store._transaction():
        _verify_runtime(store, authority)
        _schema(store)
        previous = _row(store, facts["requestId"], authority)
        if previous is not None:
            binding = json.loads(previous[1])
            if any(binding[key] != value for key, value in facts.items() if key != "writerGeneration"):
                raise AdmissionError("Rebaseline request ID binding conflict")
            if previous[4] == "pending":
                latest = head(store)
                if latest is None or latest[0] != previous[0]:
                    raise AdmissionError("Pending operation lost its durable fence pointer")
                _assert_empty(store)
            _audit(store, facts["requestId"], authority, "resume", facts["writerGeneration"])
            return _response(previous, authority)
        latest = head(store)
        if latest is not None:
            if latest[4] == "pending":
                raise AdmissionError("Another durable rebaseline operation is pending")
            prior = json.loads(latest[1])
            approval = activation_for(latest[6])
            if facts["store"] != prior["store"] or facts["oldHead"] != approval["newHead"]:
                raise AdmissionError("New intent does not extend the approved activation root")
        _assert_empty(store)
        binding = dict(facts, fenceNonce=secrets.token_hex(32),
                       initiatorOperatorId=authority.operator_id)
        store._db.execute("INSERT INTO provision_fences VALUES (?,?,?,?,'pending',NULL,NULL)",
                          (facts["requestId"], _encode(binding), authority.key_id, authority.key_digest))
        store._db.execute("INSERT OR REPLACE INTO provision_fence_head VALUES (1,?)",
                          (facts["requestId"],))
        _audit(store, facts["requestId"], authority, "begin", facts["writerGeneration"])
        return _response(_row(store, facts["requestId"], authority), authority)


def query(store, request_id, authority):
    with store._lock:
        _verify_runtime(store, authority)
        if not _table(store, "provision_fences"):
            return dict(kind="fmcad-provision-fence", version=1, state="absent", requestId=request_id)
        row = _row(store, request_id, authority)
        if row is None:
            return dict(kind="fmcad-provision-fence", version=1, state="absent", requestId=request_id)
        return _response(row, authority)


def consume(store, request, authority):
    with store._transaction():
        _verify_runtime(store, authority)
        if not _table(store, "provision_fences"):
            raise AdmissionError("No durable rebaseline intent exists")
        row = _row(store, request["requestId"], authority)
        if row is None:
            raise AdmissionError("No durable rebaseline intent exists")
        binding = json.loads(row[1])
        publication = authority.verify_publication(binding, request)
        if row[4] == "consumed":
            if row[5] != request["publicationJson"]:
                raise AdmissionError("Consumed publication bytes conflict")
            _audit(store, request["requestId"], authority, "consume-resume")
            return _response(row, authority)
        if head(store)[0] != row[0]:
            raise AdmissionError("Operation no longer owns the provision fence")
        _assert_empty(store)
        receipt = dict(
            kind="fmcad-rebaseline-consumed", version=1, fence=binding,
            activation=dict(
                requestId=binding["requestId"], fenceNonce=binding["fenceNonce"],
                newHead=publication["newHead"], publicationDigest=publication["digest"],
                record=publication["record"], initiatorOperatorId=binding["initiatorOperatorId"],
            ),
            consumedBy=authority.operator_id,
        )
        store._db.execute(
            "UPDATE provision_fences SET state='consumed',publication_json=?,receipt_json=? "
            "WHERE request_id=? AND state='pending'",
            (request["publicationJson"], _encode(receipt), request["requestId"]),
        )
        _audit(store, request["requestId"], authority, "consume")
        return _response(_row(store, request["requestId"], authority), authority)
