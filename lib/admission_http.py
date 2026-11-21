"""Opt-in versioned admission API with server-configured bearer principals."""

import hmac
import math
import threading

from .admission_receiver import AdmissionTargetError
from .request_admission import AdmissionError


class AdmissionCapacityError(AdmissionError):
    pass


class AdmissionHTTP:
    @staticmethod
    def validate_credentials(credentials):
        if not isinstance(credentials, dict) or not credentials or any(
            not isinstance(token, str) or not token.isascii() or len(token) < 32
            or not isinstance(owner, str) or not owner
            for token, owner in credentials.items()
        ):
            raise ValueError("Admission requires server-configured credentials")

    def __init__(self, receiver, dispatch, *, credentials,
                 max_pending=16, timeout=120.0, shutdown=None):
        # Credentials are supplied by server bootstrap, never by request data.
        self.validate_credentials(credentials)
        self._credentials = dict(credentials)
        self._receiver = receiver
        self._dispatch = dispatch
        if type(max_pending) is not int or max_pending < 1:
            raise ValueError("Positive admission capacity required")
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("Finite positive admission timeout required")
        self._slots = threading.BoundedSemaphore(max_pending)
        self._timeout = timeout
        self._lifecycle = threading.Lock()
        self._shutdown = shutdown
        self._accepting = True
        self._sealed = False
        self._requests = 0

    def begin_quiescence(self):
        """Fence new admissions; allow evidence lookup and withdrawal meanwhile."""
        with self._lifecycle:
            self._accepting = False

    def seal_if_idle(self):
        """Only after shared SDK dispatch is quiescent, fence all store access."""
        with self._lifecycle:
            if self._accepting or self._requests:
                return False
            self._sealed = True
            return True

    def restore_recovery(self):
        """Undo only the seal after a generation transition proved no write."""
        with self._lifecycle:
            self._sealed = False

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
        with self._lifecycle:
            if self._sealed or (
                isinstance(message, dict) and message.get("operation") == "admit"
                and (not self._accepting
                     or (self._shutdown is not None and self._shutdown.is_set()))
            ):
                raise AdmissionCapacityError("Admission runtime is quiescing")
            self._requests += 1
        try:
            return self._handle(principal, message)
        finally:
            with self._lifecycle:
                self._requests -= 1

    def _handle(self, principal, message):
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
            encoded = message.get("payloadJson")
            if not isinstance(encoded, str):
                raise AdmissionError("Admission requires exact payloadJson bytes")
            if not self._slots.acquire(blocking=False):
                raise AdmissionCapacityError("Admission capacity exhausted")
            timer = None
            try:
                record, consumer = self._receiver.prepare_encoded(principal, binding, encoded)
                if consumer is None:
                    return record
                cancelled = threading.Event()
                timer = threading.Timer(self._timeout, cancelled.set)
                timer.daemon = True
                timer.start()
                # Local lifecycle metadata is not part of the admitted payload.
                # The consumer passes its frozen original to the SDK handler.
                try:
                    self._dispatch({"_cancel_event": cancelled},
                                   admission_consumer=consumer)
                except AdmissionTargetError:
                    raise
                except Exception as exc:
                    # Adapter failures are not malformed client input, even
                    # when their Python exception happens to be ValueError.
                    raise RuntimeError("Admission dispatch failed") from exc
                # Dispatch can translate exceptions into a legacy MCP error.
                # Only the durable receiver determines the outcome.
                return self._receiver.status(principal, binding)
            finally:
                if timer is not None:
                    timer.cancel()
                self._slots.release()
        raise AdmissionError("Unsupported admission operation")
