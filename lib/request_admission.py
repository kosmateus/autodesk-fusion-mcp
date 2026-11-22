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
    _FIELDS = {"version", "owner", "request", "instance", "epoch",
               "source", "build", "document", "inputHash"}

    def __init__(self, filename, *, instance, epoch, create=True):
        if not all(isinstance(v, str) and v for v in (instance, epoch)):
            raise AdmissionError("Server instance and epoch are required")
        self._instance, self._epoch = instance, epoch
        self._lock = threading.RLock()
        self._claims = {}
        location = filename if create else Path(filename).resolve().as_uri() + "?mode=rw"
        self._db = sqlite3.connect(location, uri=not create, isolation_level=None,
                                   check_same_thread=False, timeout=5)
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
            return result

    def assert_current_generation(self):
        with self._lock:
            if self._db is None or self._db.execute(
                "SELECT instance,epoch FROM generation WHERE singleton=1",
            ).fetchone() != (self._instance, self._epoch):
                raise AdmissionError("Physical generation is no longer current")

    def bind_physical_owner(self, descriptor):
        """Persist the owner binding in this same store, never another queue DB."""
        generation = _encode(descriptor["generation"])
        binding = _encode(descriptor)
        with self._transaction():
            self.assert_current_generation()
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
                raise AdmissionError("Physical generation already belongs to another owner")
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
            result["state"] = "released" if row[1] == "released" else "active"
            if row[1] == "released":
                evidence = dict(binding=binding, state="released", releasedBy=row[2])
                digest = hashlib.sha256(_encode(evidence).encode("utf-8")).hexdigest()
                result.update(physicalEvidenceReference="fmcad-physical-turn:sha256:" + digest,
                              evidenceDigest=digest)
            return result

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
    def _transaction(self):
        with self._lock:
            if self._db is None:
                raise AdmissionError("Store closed")
            self._db.execute("BEGIN IMMEDIATE")
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
