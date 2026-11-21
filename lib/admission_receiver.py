"""Opt-in admission boundary; HTTP authentication and SDK scheduling are adapters."""

import hashlib
import json

from .request_admission import AdmissionError
from .admission_json import decode_json


class AdmissionReceiver:
    def __init__(self, store, *, source, build, resolve_document=None,
                 select_operation=None):
        if not all(isinstance(v, str) and v for v in (source, build)):
            raise AdmissionError("Trusted source and build are required")
        self._store = store
        self._source, self._build = source, build
        if (callable(resolve_document) == callable(select_operation)):
            raise AdmissionError("Exactly one trusted execution adapter is required")
        self._resolve_document = resolve_document
        self._select_operation = select_operation

    def _authorize(self, principal, binding):
        # Principal must come from server authentication, never request JSON.
        if not isinstance(principal, str) or not principal:
            raise AdmissionError("Authenticated principal required")
        if not isinstance(binding, dict) or binding.get("owner") != principal:
            raise AdmissionError("Owner mismatch")
        if (binding.get("source"), binding.get("build")) != (self._source, self._build):
            raise AdmissionError("Server source/build mismatch")

    def status(self, principal, binding):
        self._authorize(principal, binding)
        return self._store.status(binding)

    def withdraw(self, principal, binding):
        self._authorize(principal, binding)
        return self._store.withdraw(binding)

    def prepare(self, principal, binding, payload):
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True, allow_nan=False)
        return self.prepare_encoded(principal, binding, encoded)

    def prepare_encoded(self, principal, binding, encoded):
        """Return a callback for the shared SDK queue, or no callback for a terminal key.

        Only the creator schedules a callback. The durable claim is checked
        at consumption, not at enqueue. Exceptions after claim leave UNKNOWN.
        """
        self._authorize(principal, binding)
        if not isinstance(encoded, str):
            raise AdmissionError("Encoded input must be text")
        frozen_payload = decode_json(encoded)
        if not isinstance(frozen_payload, dict):
            raise AdmissionError("Admission payload must be an object")
        digest = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
        if binding.get("inputHash") != digest:
            raise AdmissionError("Input hash mismatch")
        # Detach from mutable objects owned by an HTTP caller.
        frozen_binding = dict(binding)
        resolve = self._select_operation(frozen_payload) if self._select_operation else None
        record, created = self._store.admit_once(frozen_binding)
        if not created:
            return record, None

        def consume(handler):
            current = self._store.status(frozen_binding)
            if current["state"] != "accepted":
                return current
            if resolve is None:
                descriptor = self._resolve_document(json.loads(encoded))
                execute = lambda: handler(frozen_payload)
            else:
                descriptor, execute = resolve()
            if descriptor != frozen_binding["document"]:
                raise AdmissionTargetError("Execution document mismatch")
            if not self._store.claim(frozen_binding):
                return self._store.status(frozen_binding)
            result = execute()
            return self._store.complete(frozen_binding, result)

        return record, consume


class AdmissionTargetError(AdmissionError):
    """The typed target was refused before the execution claim."""
