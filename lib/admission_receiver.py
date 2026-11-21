"""Opt-in admission boundary; HTTP authentication and SDK scheduling are adapters."""

import hashlib
import json

from .request_admission import AdmissionError


class AdmissionReceiver:
    def __init__(self, store, *, source, build, resolve_document):
        if not all(isinstance(v, str) and v for v in (source, build)):
            raise AdmissionError("Trusted source and build are required")
        self._store = store
        self._source, self._build = source, build
        if not callable(resolve_document):
            raise AdmissionError("Trusted document resolver required")
        self._resolve_document = resolve_document

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
        """Return a callback for the shared SDK queue, or no callback for a terminal key.

        Only the creator schedules a callback. The durable claim is checked
        at consumption, not at enqueue. Exceptions after claim leave UNKNOWN.
        """
        self._authorize(principal, binding)
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True, allow_nan=False)
        digest = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
        if binding.get("inputHash") != digest:
            raise AdmissionError("Input hash mismatch")
        # Detach from mutable objects owned by an HTTP caller.
        frozen_binding = dict(binding)
        frozen_payload = json.loads(encoded)
        record, created = self._store.admit_once(frozen_binding)
        if not created:
            return record, None

        def consume(handler):
            if self._resolve_document(frozen_payload) != frozen_binding["document"]:
                raise AdmissionError("Execution document mismatch")
            if not self._store.claim(frozen_binding):
                return self._store.status(frozen_binding)
            result = handler(frozen_payload)
            return self._store.complete(frozen_binding, result)

        return record, consume
