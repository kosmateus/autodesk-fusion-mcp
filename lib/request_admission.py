"""Durable admission primitives; callers supply authenticated server bindings.

No Fusion calls or historical recovery. A committed execution claim without
terminal evidence is UNKNOWN and can never grant a second execution.
"""

from contextlib import contextmanager
import json
import sqlite3
import threading
import uuid


class AdmissionError(ValueError):
    pass


def _encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


class AdmissionStore:
    _FIELDS = {"version", "owner", "request", "instance", "epoch",
               "source", "build", "document", "inputHash"}

    def __init__(self, filename, *, instance, epoch):
        if not all(isinstance(v, str) and v for v in (instance, epoch)):
            raise AdmissionError("Server instance and epoch are required")
        self._instance, self._epoch = instance, epoch
        self._lock = threading.RLock()
        self._claims = {}
        self._db = sqlite3.connect(
            filename, isolation_level=None, check_same_thread=False, timeout=5,
        )
        try:
            self._db.execute("PRAGMA synchronous=FULL")
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
                self._db.execute(
                    "INSERT OR REPLACE INTO generation VALUES (1,?,?)",
                    (instance, epoch),
                )
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
