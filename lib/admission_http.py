"""Opt-in versioned admission API with server-configured bearer principals."""

import hmac

from .request_admission import AdmissionError


class AdmissionHTTP:
    def __init__(self, receiver, dispatch, *, credentials):
        # Credentials are supplied by server bootstrap, never by request data.
        if not credentials or any(
            not isinstance(token, str) or not token.isascii() or len(token) < 32
            or not isinstance(owner, str) or not owner
            for token, owner in credentials.items()
        ):
            raise ValueError("Admission requires server-configured credentials")
        self._credentials = dict(credentials)
        self._receiver = receiver
        self._dispatch = dispatch

    def authenticate(self, authorization):
        if len(authorization) != 1:
            raise PermissionError("Admission authentication required")
        value = authorization[0]
        if not isinstance(value, str) or not value.startswith("Bearer "):
            raise PermissionError("Admission authentication required")
        token = value[7:]
        if not token.isascii():
            raise PermissionError("Admission authentication required")
        principal = None
        for candidate, owner in self._credentials.items():
            if hmac.compare_digest(token, candidate):
                principal = owner
        if principal is None:
            raise PermissionError("Admission authentication required")
        return principal

    def handle(self, principal, message):
        if not isinstance(message, dict) or message.get("version") != 1:
            raise AdmissionError("Unsupported admission protocol")
        operation = message.get("operation")
        binding = message.get("binding")
        if operation == "status":
            return self._receiver.status(principal, binding)
        if operation == "withdraw":
            return self._receiver.withdraw(principal, binding)
        if operation == "admit":
            payload = message.get("payload")
            if not isinstance(payload, dict):
                raise AdmissionError("Admission payload must be an object")
            record, consumer = self._receiver.prepare(principal, binding, payload)
            if consumer is None:
                return record
            return self._dispatch(payload, admission_consumer=consumer)
        raise AdmissionError("Unsupported admission operation")
