"""Opt-in versioned admission API with server-configured bearer principals."""

import hmac
import math
import threading

from .request_admission import AdmissionError


class AdmissionCapacityError(AdmissionError):
    pass


class AdmissionHTTP:
    def __init__(self, receiver, dispatch, *, credentials,
                 max_pending=16, timeout=120.0):
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
        if type(max_pending) is not int or max_pending < 1:
            raise ValueError("Positive admission capacity required")
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("Finite positive admission timeout required")
        self._slots = threading.BoundedSemaphore(max_pending)
        self._timeout = timeout

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
        if (not isinstance(message, dict)
                or type(message.get("version")) is not int or message["version"] != 1):
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
            if not self._slots.acquire(blocking=False):
                raise AdmissionCapacityError("Admission capacity exhausted")
            timer = None
            try:
                record, consumer = self._receiver.prepare(principal, binding, payload)
                if consumer is None:
                    return record
                cancelled = threading.Event()
                timer = threading.Timer(self._timeout, cancelled.set)
                timer.daemon = True
                timer.start()
                # Local lifecycle metadata is not part of the admitted payload.
                # The consumer passes its frozen original to the SDK handler.
                self._dispatch(dict(payload, _cancel_event=cancelled),
                               admission_consumer=consumer)
                # Dispatch can translate exceptions into a legacy MCP error.
                # Only the durable receiver determines the outcome.
                return self._receiver.status(principal, binding)
            finally:
                if timer is not None:
                    timer.cancel()
                self._slots.release()
        raise AdmissionError("Unsupported admission operation")
