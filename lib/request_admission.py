"""Durable admission primitives; callers supply authenticated server bindings.

No Fusion calls or historical recovery. A committed execution claim without
terminal evidence is UNKNOWN and can never grant a second execution.
"""

from contextlib import contextmanager
import json
import hashlib
from pathlib import Path
import sqlite3
import threading
import uuid


class AdmissionError(ValueError):
    pass


class GenerationUnchangedError(AdmissionError):
    """The proposed transition was rejected before any CAS write."""


def _encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


class AdmissionStore:
    _MAX_HISTORY_HANDOFFS = 1024
    _FIELDS = {"version", "owner", "request", "instance", "epoch",
               "source", "build", "document", "inputHash"}

    def __init__(self, filename, *, instance, epoch, create=True):
        if not all(isinstance(v, str) and v for v in (instance, epoch)):
            raise AdmissionError("Server instance and epoch are required")
        self._instance, self._epoch = instance, epoch
        self._lock = threading.RLock()
        self._claims = {}
        self._path = None if str(filename) == ":memory:" else Path(filename).resolve()
        location = filename if create else Path(filename).resolve().as_uri() + "?mode=rw"
        self._db = sqlite3.connect(location, uri=not create, isolation_level=None,
                                   check_same_thread=False, timeout=5)
        self._file_identity = None
        if self._path is not None:
            info = self._path.stat()
            self._file_identity = (info.st_dev, info.st_ino)
        try:
            self._db.execute("PRAGMA synchronous=FULL")
            if not create:
                current = self._db.execute(
                    "SELECT instance,epoch FROM generation WHERE singleton=1"
                ).fetchone()
                if current != (instance, epoch):
                    raise AdmissionError("Opening stale generation is forbidden")
                return
            self._db.execute("""
                CREATE TABLE IF NOT EXISTS admissions (
                    request TEXT PRIMARY KEY, binding TEXT NOT NULL,
                    state TEXT NOT NULL CHECK (
                        state IN ('accepted','claimed','withdrawn','terminal')
                    ), claim TEXT, result TEXT
                )
            """)
            with self._transaction():
                self._db.execute("""
                    CREATE TABLE IF NOT EXISTS generation (
                        singleton INTEGER PRIMARY KEY CHECK (singleton=1),
                        instance TEXT NOT NULL, epoch TEXT NOT NULL
                    )
                """)
                self._db.execute("INSERT OR IGNORE INTO generation VALUES (1,?,?)",
                                 (instance, epoch))
                current = self._db.execute(
                    "SELECT instance,epoch FROM generation WHERE singleton=1"
                ).fetchone()
                if current != (instance, epoch):
                    raise AdmissionError("Opening stale generation is forbidden")
                self._db.execute("""
                    CREATE TABLE IF NOT EXISTS generation_history (
                        instance TEXT NOT NULL, epoch TEXT NOT NULL,
                        PRIMARY KEY (instance,epoch)
                    )
                """)
                self._db.execute("INSERT OR IGNORE INTO generation_history VALUES (?,?)",
                                 (instance, epoch))
        except BaseException:
            self._db.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def close(self):
        with self._lock:
            if self._db is not None:
                self._db.close()
                self._db = None
                self._claims.clear()

    def advance_generation(self, *, instance, epoch, handoff_id=None):
        """Explicit CAS transition by the current runtime after a safe handoff.

        This does not stop active SDK work; bootstrap must quiesce it first.
        Previous generations can never become current again.
        """
        if not all(isinstance(v, str) and v for v in (instance, epoch)):
            raise GenerationUnchangedError("Server instance and epoch are required")
        if handoff_id is not None and (not isinstance(handoff_id, str) or not handoff_id):
            raise GenerationUnchangedError("A nonempty handoff ID is required")
        with self._transaction():
            self.assert_provision_lifecycle_allowed()
            self._db.execute("""
                CREATE TABLE IF NOT EXISTS physical_handoffs (
                    id TEXT PRIMARY KEY, result TEXT NOT NULL
                )
            """)
            result = dict(handoffId=handoff_id,
                          generation=dict(instance=self._instance, epoch=self._epoch),
                          nextGeneration=dict(instance=instance, epoch=epoch),
                          state="committed")
            if handoff_id is not None:
                previous = self._db.execute(
                    "SELECT result FROM physical_handoffs WHERE id=?", (handoff_id,),
                ).fetchone()
                if previous is not None:
                    if previous[0] != _encode(result):
                        raise GenerationUnchangedError("Handoff ID binding conflict")
                    return json.loads(previous[0])
            current = self._db.execute(
                "SELECT instance,epoch FROM generation WHERE singleton=1"
            ).fetchone()
            if current != (self._instance, self._epoch):
                raise AdmissionError("Generation transition lost its fence")
            if self._db.execute(
                "SELECT 1 FROM generation_history WHERE instance=? AND epoch=?",
                (instance, epoch),
            ).fetchone():
                raise GenerationUnchangedError("Generation reuse is forbidden")
            self._db.execute("INSERT INTO generation_history VALUES (?,?)",
                             (instance, epoch))
            changed = self._db.execute(
                "UPDATE generation SET instance=?,epoch=? "
                "WHERE singleton=1 AND instance=? AND epoch=?",
                (instance, epoch, self._instance, self._epoch),
            ).rowcount
            if changed != 1:
                raise AdmissionError("Generation transition lost its fence")
            if handoff_id is not None:
                self._db.execute("INSERT INTO physical_handoffs VALUES (?,?)",
                                 (handoff_id, _encode(result)))
            if self._provision_fence_head() is not None:
                from .rebaseline_fence_store import retire_after_handoff
                retire_after_handoff(self, instance, epoch, handoff_id)
            return result

    def assert_current_generation(self):
        with self._lock:
            if self._db is None or self._db.execute(
                "SELECT instance,epoch FROM generation WHERE singleton=1",
            ).fetchone() != (self._instance, self._epoch):
                raise AdmissionError("Physical generation is no longer current")

    def _provision_fence_head(self):
        tables = {row[0] for row in self._db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name IN ('provision_fence_head','provision_fences')",
        )}
        pointer = (self._db.execute(
            "SELECT request_id FROM provision_fence_head WHERE singleton=1",
        ).fetchone() if "provision_fence_head" in tables else None)
        if pointer is None:
            if "provision_fences" in tables and self._db.execute(
                "SELECT 1 FROM provision_fences LIMIT 1",
            ).fetchone():
                raise AdmissionError("Durable provision fence pointer is missing")
            return None
        row = self._db.execute(
            "SELECT request_id,binding,key_id,key_digest,state,publication_json,receipt_json "
            "FROM provision_fences WHERE request_id=?", pointer,
        ).fetchone()
        if row is None or row[4] not in ("pending", "consumed"):
            raise AdmissionError("Durable provision fence is unproven")
        return row

    def _guard_pending_provision(self):
        row = self._provision_fence_head()
        if row is not None and row[4] == "pending":
            raise AdmissionError("Durable rebaseline provision fence is pending")

    def assert_provision_lifecycle_allowed(self):
        with self._lock:
            if self._provision_fence_head() is None:
                return
            from .rebaseline_fence_store import assert_handoff_allowed
            assert_handoff_allowed(self)

    def assert_sdk_authority(self, activation=None):
        from .rebaseline_fence_store import assert_activation
        with self._lock:
            self.assert_current_generation()
            assert_activation(self, activation)

    def register_physical_runtime(self, pins):
        from .rebaseline_fence_store import register_runtime
        return register_runtime(self, pins)

    def bind_physical_owner(self, descriptor, *, activation=None, broker_namespace=None):
        """Persist the owner binding in this same store, never another queue DB."""
        generation = _encode(descriptor["generation"])
        binding = _encode(descriptor)
        with self._transaction():
            self.assert_current_generation()
            from .rebaseline_fence_store import assert_activation
            assert_activation(self, activation, descriptor=descriptor)
            if self._db.execute("SELECT COUNT(*) FROM generation_history").fetchone()[0] > 1:
                self._db.execute("""
                    CREATE TABLE IF NOT EXISTS physical_handoffs (
                        id TEXT PRIMARY KEY, result TEXT NOT NULL
                    )
                """)
                receipt = self._db.execute(
                    "SELECT result FROM physical_handoffs WHERE id=?",
                    (descriptor["handoffId"],),
                ).fetchone()
                if receipt is None or json.loads(receipt[0])["nextGeneration"] != descriptor["generation"]:
                    raise AdmissionError("Physical grant requires its durable generation handoff")
            self._db.execute("""
                CREATE TABLE IF NOT EXISTS physical_owners (
                    generation TEXT PRIMARY KEY, binding TEXT NOT NULL
                )
            """)
            row = self._db.execute(
                "SELECT binding FROM physical_owners WHERE generation=?", (generation,),
            ).fetchone()
            if row is not None and row[0] != binding:
                previous = json.loads(row[0])
                if (any(previous[key] != descriptor[key] for key in descriptor if key != "brokerOwner")
                        or previous["brokerOwner"]["queueDirectory"] !=
                        descriptor["brokerOwner"]["queueDirectory"]):
                    raise AdmissionError("Physical generation belongs to another namespace")
                from .rebaseline_fence_store import active_head
                fence = active_head(self)
                if fence is None or fence[4] != "consumed":
                    raise AdmissionError("Owner succession requires its consumed native root")
                self._turn_schema()
                if self._db.execute(
                    "SELECT 1 FROM physical_turns WHERE state!='released' LIMIT 1",
                ).fetchone() is not None:
                    raise AdmissionError("An unreleased physical turn prevents owner succession")
                from .physical_owner_witness import verify_owner_succession
                root = json.loads(fence[1])["store"]
                verify_owner_succession(
                    previous["brokerOwner"], descriptor["brokerOwner"],
                    realm=dict(root, keyDigest=fence[3]),
                    broker_namespace=broker_namespace,
                )
                changed = self._db.execute(
                    "UPDATE physical_owners SET binding=? WHERE generation=? AND binding=?",
                    (binding, generation, row[0]),
                ).rowcount
                if changed != 1:
                    raise AdmissionError("Physical owner succession lost its binding")
                return
            self._db.execute("INSERT OR IGNORE INTO physical_owners VALUES (?,?)",
                             (generation, binding))

    def _turn_schema(self):
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS physical_turns (
                id TEXT PRIMARY KEY, binding TEXT NOT NULL,
                state TEXT NOT NULL CHECK (state IN ('queued','active','released')),
                released_by TEXT
            )
        """)

    def prepare_physical_turn(self, binding):
        with self._transaction():
            self.assert_current_generation()
            self._guard_pending_provision()
            self._turn_schema()
            if self._db.execute(
                "SELECT 1 FROM physical_turns WHERE id=?", (binding["turnId"],),
            ).fetchone() is not None:
                raise AdmissionError("Physical turn ID cannot be replayed")
            self._db.execute(
                "INSERT INTO physical_turns VALUES (?,?,'queued',NULL)",
                (binding["turnId"], _encode(binding)),
            )

    def start_physical_turn(self, binding):
        with self._transaction():
            self.assert_current_generation()
            self._guard_pending_provision()
            changed = self._db.execute(
                "UPDATE physical_turns SET state='active' "
                "WHERE id=? AND binding=? AND state='queued'",
                (binding["turnId"], _encode(binding)),
            ).rowcount
            if changed != 1:
                raise AdmissionError("Physical turn is already consumed or sealed")

    def release_physical_turn(self, binding, *, queued_only=False):
        with self._transaction():
            # A generation handoff cannot overtake an active main-thread turn.
            # Do not infer release just because a different generation exists.
            self.assert_current_generation()
            self._db.execute(
                "UPDATE physical_turns SET state='released',released_by=? "
                "WHERE id=? AND binding=? AND state=?",
                ("cancelled-before-sdk" if queued_only else "dispatch-finally",
                 binding["turnId"], _encode(binding), "queued" if queued_only else "active"),
            )

    def physical_turn_status(self, binding):
        with self._lock:
            self.assert_current_generation()
            result = dict(state="unknown", binding=binding)
            if self._db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='physical_turns'",
            ).fetchone() is None:
                return result
            row = self._db.execute(
                "SELECT binding,state,released_by FROM physical_turns WHERE id=?",
                (binding["turnId"],),
            ).fetchone()
            if row is None or row[0] != _encode(binding):
                return result
            if row[1] == "released":
                return self._released_turn_evidence(binding, row[2])
            result["state"] = "active"
            return result

    @staticmethod
    def _released_turn_evidence(binding, reason):
        evidence = dict(binding=binding, state="released", releasedBy=reason)
        digest = hashlib.sha256(_encode(evidence).encode("utf-8")).hexdigest()
        return dict(state="released", binding=binding,
                    physicalEvidenceReference="fmcad-physical-turn:sha256:" + digest,
                    evidenceDigest=digest)

    def physical_turn_history(self, binding, *, current_owner):
        """Read already-sealed ancestor evidence; never infer release or write."""
        with self._lock:
            self.assert_current_generation()
            unknown = dict(state="unknown", binding=binding)
            tables = self._db.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name IN ('physical_turns','physical_handoffs','physical_owners')",
            ).fetchall()
            if len(tables) != 3:
                return unknown
            row = self._db.execute(
                "SELECT binding,state,released_by FROM physical_turns WHERE id=?",
                (binding["turnId"],),
            ).fetchone()
            if (row is None or row[0] != _encode(binding) or row[1] != "released"
                    or row[2] not in ("dispatch-finally", "cancelled-before-sdk")
                    or not self._committed_ancestor(binding["generation"], current_owner)):
                return unknown
            return self._released_turn_evidence(binding, row[2])

    def _committed_ancestor(self, generation, current_owner):
        current = (self._instance, self._epoch)
        ancestor = (generation["instance"], generation["epoch"])
        if ancestor == current or not isinstance(current_owner, dict):
            return False
        limit = self._MAX_HISTORY_HANDOFFS
        rows = self._db.execute(
            "SELECT id,result FROM physical_handoffs LIMIT ?", (limit + 1,),
        ).fetchall()
        # Native CAS appends generation_history in the SAME transaction as
        # generation + handoff. Its persisted ROWID, not names or graph shape,
        # supplies insertion order. Missing/reordered native evidence is not
        # repaired or reconstructed by this read-only query.
        try:
            generations = self._db.execute(
                "SELECT rowid,instance,epoch FROM generation_history ORDER BY rowid LIMIT ?",
                (limit + 2,),
            ).fetchall()
        except sqlite3.OperationalError:
            return False  # No native persisted order: no legacy inference.
        owner_rows = self._db.execute(
            "SELECT generation,binding FROM physical_owners LIMIT ?", (limit + 2,),
        ).fetchall()
        if (len(rows) > limit or not generations or len(generations) > limit + 1
                or len(owner_rows) > limit + 1
                or [row[0] for row in generations] != list(range(1, len(generations) + 1))):
            return False
        ordered = [(row[1], row[2]) for row in generations]
        if any(not isinstance(value, str) or not value for pin in ordered for value in pin):
            return False
        positions = {pin: index for index, pin in enumerate(ordered)}
        if (len(positions) != len(ordered) or ancestor not in positions
                or ordered[-1] != current):
            return False
        owners = {}
        for encoded_generation, raw in owner_rows:
            try:
                pin, owner = json.loads(encoded_generation), json.loads(raw)
                if (not isinstance(pin, dict) or set(pin) != {"instance", "epoch"}
                        or any(not isinstance(value, str) or not value for value in pin.values())
                        or _encode(pin) != encoded_generation or not isinstance(owner, dict)
                        or set(owner) != {"kind", "version", "handoffId", "generation",
                                         "brokerOwner", "endpointURL", "physicalRuntime"}
                        or owner["kind"] != "fmcad-physical-grant"
                        or type(owner["version"]) is not int or owner["version"] != 1
                        or _encode(owner) != raw or owner.get("generation") != pin
                        or not isinstance(owner.get("handoffId"), str) or not owner["handoffId"]):
                    return False
                key = (pin["instance"], pin["epoch"])
                if key not in positions or key in owners:
                    return False
                owners[key] = (owner["handoffId"], raw)
            except (ValueError, TypeError, KeyError):
                return False
        if current not in owners or owners[current][1] != _encode(current_owner):
            return False
        incoming, outgoing = {}, {}
        for handoff_id, raw in rows:
            try:
                record = json.loads(raw)
                if (not isinstance(record, dict) or set(record) != {
                    "handoffId", "generation", "nextGeneration", "state",
                } or record["state"] != "committed" or not isinstance(handoff_id, str)
                        or not handoff_id or record["handoffId"] != handoff_id
                        or _encode(record) != raw):
                    return False
                ends = []
                for name in ("generation", "nextGeneration"):
                    pin = record[name]
                    if (not isinstance(pin, dict) or set(pin) != {"instance", "epoch"}
                            or any(not isinstance(value, str) or not value for value in pin.values())):
                        return False
                    ends.append((pin["instance"], pin["epoch"]))
                source, target = ends
            except (ValueError, TypeError, KeyError):
                return False
            if (source not in positions or target not in positions
                    or positions[target] != positions[source] + 1
                    or source in outgoing or target in incoming):
                return False
            if target in owners and owners[target][0] != handoff_id:
                return False
            outgoing[source], incoming[target] = target, (source, handoff_id)
        if (current in outgoing or current not in incoming
                or incoming[current][1] != current_owner.get("handoffId")):
            return False
        # Require EVERY adjacent transition from the ancestor to the real tail.
        # Forward-only adjacent edges also make cycles impossible.
        for index in range(positions[ancestor] + 1, len(ordered)):
            edge = incoming.get(ordered[index])
            if edge is None or edge[0] != ordered[index - 1]:
                return False
        return True

    def _binding(self, binding):
        if not isinstance(binding, dict) or set(binding) != self._FIELDS:
            raise AdmissionError("Exact binding required")
        if type(binding["version"]) is not int or binding["version"] != 1:
            raise AdmissionError("Unsupported version")
        if any(not isinstance(binding[k], str) or not binding[k]
               for k in self._FIELDS - {"version"}):
            raise AdmissionError("Nonempty binding fields required")
        if (binding["instance"], binding["epoch"]) != (self._instance, self._epoch):
            raise AdmissionError("Server instance/epoch mismatch")
        return _encode(binding)

    @contextmanager
    def _transaction(self, *, read_snapshot=False):
        with self._lock:
            if self._db is None:
                raise AdmissionError("Store closed")
            self._db.execute("BEGIN DEFERRED" if read_snapshot else "BEGIN IMMEDIATE")
            try:
                yield
                self._db.execute("COMMIT")
            except BaseException:
                if self._db.in_transaction:
                    self._db.execute("ROLLBACK")
                raise

    def _read(self, binding, encoded):
        generation = self._db.execute(
            "SELECT instance,epoch FROM generation WHERE singleton=1"
        ).fetchone()
        if generation != (self._instance, self._epoch):
            raise AdmissionError("Receiver generation is no longer current")
        row = self._db.execute(
            "SELECT binding,state,claim,result FROM admissions WHERE request=?",
            (binding["request"],),
        ).fetchone()
        if row is not None and row[0] != encoded:
            raise AdmissionError("Request binding conflict")
        return row

    @staticmethod
    def _public(row):
        if row is None:
            return None
        result = {"state": "unknown" if row[1] == "claimed" else row[1]}
        if row[1] == "terminal":
            result["result"] = json.loads(row[3])
        return result

    def status(self, binding):
        encoded = self._binding(binding)
        with self._lock:
            if self._db is None:
                raise AdmissionError("Store closed")
            return self._public(self._read(binding, encoded))

    def admit(self, binding):
        return self.admit_once(binding)[0]

    def admit_once(self, binding):
        """Only the transaction creating the admission may schedule its callback."""
        encoded = self._binding(binding)
        with self._transaction():
            self._guard_pending_provision()
            created = self._read(binding, encoded) is None
            if created:
                self._db.execute(
                    "INSERT INTO admissions(request,binding,state) VALUES (?,?,'accepted')",
                    (binding["request"], encoded),
                )
            return self._public(self._read(binding, encoded)), created

    def withdraw(self, binding):
        encoded = self._binding(binding)
        with self._transaction():
            self._guard_pending_provision()
            row = self._read(binding, encoded)
            if row is None:
                self._db.execute(
                    "INSERT INTO admissions(request,binding,state) VALUES (?,?,'withdrawn')",
                    (binding["request"], encoded),
                )
            elif row[1] == "accepted":
                self._db.execute(
                    "UPDATE admissions SET state='withdrawn' WHERE request=?",
                    (binding["request"],),
                )
            elif row[1] != "withdrawn":
                raise AdmissionError("Cannot withdraw dispatched or terminal work")
            return self._public(self._read(binding, encoded))

    def claim(self, binding):
        encoded = self._binding(binding)
        token = str(uuid.uuid4())
        with self._lock:
            with self._transaction():
                self._guard_pending_provision()
                row = self._read(binding, encoded)
                if row is None:
                    raise AdmissionError("Request not admitted")
                if row[1] != "accepted":
                    return False
                self._db.execute(
                    "UPDATE admissions SET state='claimed',claim=? WHERE request=?",
                    (token, binding["request"]),
                )
            self._claims[binding["request"]] = token
            return True

    def complete(self, binding, result):
        encoded, serialized = self._binding(binding), _encode(result)
        with self._transaction():
            row = self._read(binding, encoded)
            if row is not None and row[1] == "terminal":
                if row[3] != serialized:
                    raise AdmissionError("Terminal evidence is immutable")
                return self._public(row)
            if (row is None or row[1] != "claimed"
                    or self._claims.get(binding["request"]) != row[2]):
                raise AdmissionError("Completion requires this live claim")
            self._db.execute(
                "UPDATE admissions SET state='terminal',result=? WHERE request=?",
                (serialized, binding["request"]),
            )
            return self._public(self._read(binding, encoded))
