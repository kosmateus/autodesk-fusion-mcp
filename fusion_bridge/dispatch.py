"""Thread-safe callback relay for executing work on the Fusion main thread."""

import queue
import threading
import time
import traceback
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime

import adsk.core

from .. import settings
from ..lib.admission_receiver import AdmissionTargetError
from ..lib.physical_authority import PhysicalCapability, PhysicalTurn

# ── Module state ──────────────────────────────────────────────────────────

_callback_impl = None
_pending = queue.Queue()
_callback_event = None
_scheduler_active = threading.Event()
_halt = threading.Event()
_run_lock = threading.Lock()
_lifecycle_lock = threading.Lock()
_running_handlers = 0
_running_signals = 0
_deferred_retirement = None
_lifecycle_poll = None
_startup_entry = None
_startup_ticket = None


def _logging_utils():
    # Importing the vendor utility reads Application/userInterface. Controlled
    # startup imports this dispatcher before its audit, so defer that import.
    from ..lib import fusionAddInUtils
    return fusionAddInUtils


def __getattr__(name):
    if name == "futil":  # Preserve the existing logging integration/test seam.
        return _logging_utils()
    raise AttributeError(name)


def set_lifecycle_poll(callback):
    global _lifecycle_poll
    _lifecycle_poll = callback


@dataclass
class _Retirement:
    shutdown: threading.Event
    callback: Callable[[], bool]
    done: threading.Event = field(default_factory=threading.Event)
    delivering: bool = False

_deferred_messages = []
_msg_lock = threading.Lock()
_registered = False

CALLBACK_EVENT_ID = "FusionBridgeCallback"
_TICK_INTERVAL = 0.075
_KEEPALIVE_INTERVAL = 2.0
_BATCH_LIMIT = 8


# ── Fusion application accessor ──────────────────────────────────────────


def get_app():
    return adsk.core.Application.get()


# ── Thread-safe logging ──────────────────────────────────────────────────


def format_duration(elapsed_ms):
    """Human-readable elapsed time.

    Under one second -> integer milliseconds (e.g. ``122ms``);
    one second or longer -> seconds with two decimals (e.g. ``4.52s``).
    """
    if elapsed_ms < 1000:
        return f"{elapsed_ms:.0f}ms"
    return f"{elapsed_ms / 1000:.2f}s"


def log(message: str, level=None):
    """Log immediately on the main thread, or defer for later flushing.

    The message is timestamped at call time so deferred (background-thread)
    lines reflect when they were logged, not when they were flushed.
    """
    stamped = f"{datetime.now().isoformat(timespec='milliseconds')} {message}"
    if threading.current_thread() is threading.main_thread():
        futil = _logging_utils()
        futil.log(stamped) if level is None else futil.log(stamped, level)
        return
    with _msg_lock:
        _deferred_messages.append((stamped, level))


def drain_logs():
    """Flush any log messages that were deferred from background threads."""
    with _msg_lock:
        if not _deferred_messages:
            return
        snapshot = list(_deferred_messages)
        _deferred_messages.clear()
    for text, lvl in snapshot:
        futil = _logging_utils()
        futil.log(text) if lvl is None else futil.log(text, lvl)


# ── Custom-event handler ─────────────────────────────────────────────────


class _BridgeEventHandler(adsk.core.CustomEventHandler):
    """Responds to the custom Fusion event by draining the work queue."""

    def __init__(self, shutdown=None):
        super().__init__()
        self._shutdown = shutdown

    def notify(self, args):
        del args
        if self._shutdown is not None and self._shutdown.is_set():
            _try_deferred_retirement(self._shutdown)
            return
        _flush_pending()
        _try_deferred_retirement(self._shutdown)


# ── Recursive timer scheduler ────────────────────────────────────────────


def _schedule_tick(shutdown=None):
    """Fire a single tick, then reschedule if still active."""
    shutdown = shutdown if shutdown is not None else _halt
    if shutdown.is_set() or not _scheduler_active.is_set():
        return
    try:
        _fire_event_if_needed(shutdown)
    except Exception as exc:
        log(f"Scheduler tick error: {exc}", adsk.core.LogLevels.ErrorLogLevel)
    if _scheduler_active.is_set() and not shutdown.is_set():
        t = threading.Timer(_TICK_INTERVAL, _schedule_tick, args=(shutdown,))
        t.daemon = True
        t.start()


_last_fire_time = 0.0


def _fire_event_if_needed(shutdown=None):
    """Signal the main thread when there is queued work or a keepalive is due."""
    import time

    global _last_fire_time
    now = time.time()
    has_work = not _pending.empty()
    keepalive_due = (now - _last_fire_time) >= _KEEPALIVE_INTERVAL
    if has_work or keepalive_due:
        if _fire_signal(_halt if shutdown is None else shutdown):
            _last_fire_time = now


def _fire_signal(shutdown, *, retirement=None):
    """Count calls into the SDK, not merely handlers reached by the event."""
    global _running_signals
    with _lifecycle_lock:
        if shutdown is not _halt:
            return False
        if retirement is None:
            if shutdown.is_set():
                return False
        elif (
            retirement is not _deferred_retirement or retirement.delivering
            or _running_handlers or _running_signals
        ):
            return False
        _running_signals += 1
    try:
        get_app().fireCustomEvent(CALLBACK_EVENT_ID)
        return True
    finally:
        with _lifecycle_lock:
            _running_signals -= 1


# ── Public dispatch API ──────────────────────────────────────────────────

# Envelope lifecycle: queued -> running -> done, or queued -> cancelled.
# Each envelope carries its own ``_lock`` so the submitting thread (on
# timeout) and the Fusion main thread (in _flush_pending) transition the
# state atomically.  Lock ordering: ``_lock`` -> queue mutex only; the
# _inflight lock is never held while taking ``_lock``.

_QUEUED_CANCEL_TEXT = (
    "Error: Request cancelled: the tool was queued but never executed "
    "(Fusion main thread did not service it). Safe to retry."
)
_RUNNING_TIMEOUT_TEXT = (
    "Error: Timeout: the tool is still executing on the Fusion main thread "
    "and may complete. Do NOT blindly retry — retrying could duplicate "
    "the operation."
)

_CANCELLED_TEXT = (
    "Error: Request cancelled; work that already started may still complete."
)

# Server/session/request key -> envelope; never key by JSON-RPC ID alone.
_inflight = {}
_inflight_lock = threading.Lock()


def _text_result(text):
    return {
        "content": [{"type": "text", "text": text}],
        "isError": True,
    }


def _new_envelope(call_data, reply):
    return {
        "payload": call_data,
        "reply": reply,
        "_lock": threading.Lock(),
        "_state": "queued",
    }


def assert_startup_queue(entry):
    """Internal origin and queue-context check, never dispatch authority."""
    with _lifecycle_lock:
        if (threading.current_thread() is not threading.main_thread()
                or not _run_lock.locked() or _startup_entry is not entry
                or _startup_ticket is None or _halt.is_set()):
            raise PermissionError("Startup audit requires its original shared-queue turn")


def schedule_bootstrap_entry(entry, context):
    """One fixed startup operation, not a public tool or arbitrary callback."""
    from ..lib.bootstrap_entry import BootstrapEntry
    global _startup_ticket
    if type(entry) is not BootstrapEntry or not entry.audited:
        raise PermissionError("Original audited BootstrapEntry required")
    if threading.current_thread() is not threading.main_thread():
        raise RuntimeError("Controlled bootstrap scheduling requires the main thread")
    entry.mark_scheduled()
    # Only the reviewed custom-event registration/signal minimum precedes audit.
    init_main_thread_dispatch()
    shutdown = _halt
    envelope = _new_envelope({}, queue.Queue(maxsize=1))
    envelope["_shutdown"] = shutdown
    envelope["_bootstrap_entry"] = entry
    envelope["_bootstrap_context"] = context

    def expired():
        with envelope["_lock"]:
            if envelope["_state"] == "done":
                return
            entry.refuse("BOOTSTRAP_STARTUP_AUDIT_QUEUE_TIMEOUT")
            if envelope["_state"] == "queued":
                _try_remove(envelope)
                envelope["_state"] = "cancelled"
        request_main_thread_shutdown(shutdown)
        print("[AutodeskFusionMCP] Controlled startup UNKNOWN: audit queue timeout")

    timer = threading.Timer(settings.MCP_MAIN_THREAD_TIMEOUT, expired)
    timer.daemon = True
    envelope["_bootstrap_timer"] = timer
    with _lifecycle_lock:
        if _startup_ticket is not None or shutdown.is_set() or not _registered:
            raise PermissionError("Controlled startup already scheduled or unavailable")
        _startup_ticket = envelope
        _pending.put(envelope)
    timer.start()
    try:
        if not _fire_signal(shutdown):
            raise RuntimeError("Controlled startup signal refused")
    except BaseException:
        timer.cancel()
        entry.refuse("BOOTSTRAP_STARTUP_AUDIT_QUEUE_SIGNAL_FAILED")
        request_main_thread_shutdown(shutdown)
        raise


def _consume_bootstrap_entry(envelope):
    """Runs under the same _run_lock/lifecycle count as ordinary SDK handlers."""
    from ..lib.bootstrap_entry import BootstrapEntry
    global _startup_entry, _running_handlers
    entry = envelope["_bootstrap_entry"]
    try:
        with envelope["_lock"]:
            if envelope["_state"] != "queued":
                return
            envelope["_state"] = "running"
        with _lifecycle_lock:
            if (type(entry) is not BootstrapEntry or _startup_ticket is not envelope
                    or envelope["_shutdown"] is not _halt or _halt.is_set()
                    or _startup_entry is not None
                    or threading.current_thread() is not threading.main_thread()):
                raise PermissionError("Controlled startup queue origin changed")
            _startup_entry = entry
            _running_handlers += 1
        try:
            entry.run_queued(envelope["_bootstrap_context"])
        finally:
            with _lifecycle_lock:
                _startup_entry = None
                _running_handlers -= 1
    except BaseException as exc:
        entry.refuse(str(exc))
        request_main_thread_shutdown(envelope["_shutdown"])
        print(f"[AutodeskFusionMCP] Controlled startup refused/UNKNOWN: {exc}")
    finally:
        envelope["_bootstrap_timer"].cancel()
        with envelope["_lock"]:
            envelope["_state"] = "done"


def _put_reply(reply, result):
    try:
        reply.put_nowait(result)
    except queue.Full:
        pass


def _deregister_inflight(envelope):
    request_key = envelope.get("_request_key")
    if request_key is None:
        return
    with _inflight_lock:
        if _inflight.get(request_key) is envelope:
            del _inflight[request_key]


def set_tool_handler(handler):
    global _callback_impl
    _callback_impl = handler


def cancel_request(request_key):
    """Cancel a queued request before the Fusion main thread executes it.

    Returns ``True`` when the request was still queued and has been
    cancelled; ``False`` when it is unknown, already executing, or already
    finished.  Fusion work that is underway cannot be aborted, so a
    ``False`` return means the caller must treat the operation as possibly
    completing anyway.
    """
    with _inflight_lock:
        envelope = _inflight.get(request_key)
    if envelope is None:
        return False

    with envelope["_lock"]:
        if envelope["_state"] != "queued":
            return False
        if not _try_remove(envelope):
            # Lost the race with _flush_pending: the work is executing.
            return False
        envelope["_state"] = "cancelled"

    _deregister_inflight(envelope)
    # Wake the thread blocked in dispatch_to_main_thread with the answer.
    _put_reply(envelope["reply"], _text_result(_QUEUED_CANCEL_TEXT))
    return True


def bind_dispatch(shutdown=None):
    """Bind a listener (including keep-alives) to one dispatch lifetime."""
    shutdown = _halt if shutdown is None else shutdown

    def dispatch(call_data, *, admission_consumer=None):
        return _submit(shutdown, call_data, admission_consumer)

    return dispatch


def dispatch_to_main_thread(call_data, *, admission_consumer=None):
    """Submit *call_data* for execution on the Fusion main thread and block
    until the result is available.  If already on the main thread, execute
    directly."""
    return _submit(_halt, call_data, admission_consumer)


def _submit(shutdown, call_data, admission_consumer):
    turn = call_data.get("_physical_turn") if isinstance(call_data, dict) else None
    try:
        return _submit_impl(shutdown, call_data, admission_consumer)
    finally:
        if isinstance(turn, PhysicalTurn):
            try:
                turn.cancel_queued()
            except Exception:
                # Missing durable release is conservative: status stays active.
                pass


def _submit_impl(shutdown, call_data, admission_consumer):
    cancel_event = (
        call_data.get("_cancel_event") if isinstance(call_data, dict) else None
    )
    if threading.current_thread() is threading.main_thread():
        return _execute(shutdown, call_data, admission_consumer)

    reply = queue.Queue(maxsize=1)
    envelope = _new_envelope(call_data, reply)
    envelope["_shutdown"] = shutdown
    envelope["_admission_consumer"] = admission_consumer

    request_key = (
        call_data.get("_request_key") if isinstance(call_data, dict) else None
    )
    with _lifecycle_lock:
        if (shutdown is not _halt or shutdown.is_set()
                or (cancel_event is not None and cancel_event.is_set())):
            return _text_result(_CANCELLED_TEXT)
        if request_key is not None:
            envelope["_request_key"] = request_key
            with _inflight_lock:
                if request_key in _inflight:
                    return _text_result("Error: Request ID is already in flight in this session")
                _inflight[request_key] = envelope
                # Publish the envelope before cancellation can find it.
                _pending.put(envelope)
        else:
            _pending.put(envelope)

    try:
        _fire_signal(shutdown)
    except Exception as exc:
        with envelope["_lock"]:
            if envelope["_state"] == "queued" and _try_remove(envelope):
                envelope["_state"] = "cancelled"
        _deregister_inflight(envelope)
        log(
            f"Failed to fire main-thread event: {exc}",
            adsk.core.LogLevels.ErrorLogLevel,
        )
        return _text_result(
            f"Error: RuntimeError: failed to schedule Fusion main-thread "
            f"work ({exc})"
        )

    deadline = time.monotonic() + settings.MCP_MAIN_THREAD_TIMEOUT
    while True:
        if shutdown.is_set() or (cancel_event is not None and cancel_event.is_set()):
            if cancel_event is not None:
                cancel_event.set()
            with envelope["_lock"]:
                if envelope["_state"] == "queued":
                    _try_remove(envelope)
                    envelope["_state"] = "cancelled"
            _deregister_inflight(envelope)
            return _text_result(_CANCELLED_TEXT)
        try:
            return _dispatch_result(reply.get(timeout=0.05))
        except queue.Empty:
            pass
        if time.monotonic() >= deadline:
            result, cancelled_flag = _classify_timeout(envelope)
            if cancelled_flag:
                _deregister_inflight(envelope)
            log(
                f"Timed out waiting for the Fusion main thread ({settings.MCP_MAIN_THREAD_TIMEOUT:.0f}s); "
                + ("request cancelled before execution" if cancelled_flag
                   else "request may still be executing"),
                adsk.core.LogLevels.ErrorLogLevel,
            )
            return _dispatch_result(result)


def _dispatch_result(result):
    if isinstance(result, AdmissionTargetError):
        raise result
    return result


def _execute(shutdown, payload, consumer):
    global _running_handlers
    cancel_event = payload.get("_cancel_event") if isinstance(payload, dict) else None
    with _lifecycle_lock:
        if (shutdown is not _halt or shutdown.is_set()
                or (cancel_event is not None and cancel_event.is_set())):
            return _text_result(_CANCELLED_TEXT)
        handler = _callback_impl
        if handler is None:
            raise RuntimeError("Tool implementation is not initialized")
        _running_handlers += 1
    try:
        capability = payload.get("_physical_capability") if isinstance(payload, dict) else None
        if not isinstance(capability, PhysicalCapability):
            raise PermissionError("Physical grant required before SDK dispatch")
        capability.validate()
        turn = payload.get("_physical_turn")
        if not isinstance(turn, PhysicalTurn) or turn.capability is not capability:
            raise PermissionError("Bound physical turn required before SDK dispatch")
        turn.start()
        try:
            return consumer(handler) if consumer is not None else handler(payload)
        finally:
            turn.finish()
    finally:
        with _lifecycle_lock:
            _running_handlers -= 1


def _classify_timeout(envelope):
    """Build the client-facing answer for a timed-out request.

    Distinguishes work that was still queued (cancelled for real, safe to
    retry) from work already executing on the Fusion main thread (cannot
    be aborted; the client is told it may still complete and must not
    blindly retry).
    """
    with envelope["_lock"]:
        if envelope["_state"] == "queued":
            if _try_remove(envelope):
                envelope["_state"] = "cancelled"
                return _text_result(_QUEUED_CANCEL_TEXT), True
            # Raced with _flush_pending: it already dequeued the envelope
            # and is waiting on this lock, so the work is executing.
            envelope["_state"] = "running"

        state = envelope["_state"]
        if state == "done":
            try:
                return envelope["reply"].get_nowait(), False
            except queue.Empty:
                state = "running"
        if state == "cancelled":
            # A concurrent cancel_request() already produced the answer.
            try:
                return envelope["reply"].get_nowait(), False
            except queue.Empty:
                return _text_result(_QUEUED_CANCEL_TEXT), True
        return _text_result(_RUNNING_TIMEOUT_TEXT), False


def wait_for_main_thread(poll_interval=1.0, shutdown=None):
    """Block until the Fusion main thread services a work item.

    Enqueues a lightweight ``__startup_ping__`` envelope and waits for it
    to round-trip through the Custom Event dispatcher.  Used to defer
    startup work until Fusion's event loop is actually pumping, which is
    not yet the case while an auto-loaded add-in's ``run()`` executes
    during Fusion's own cold start.

    Only call from background threads: the main thread cannot service the
    queue while blocked inside an add-in callback, so waiting here from
    ``run()`` would deadlock.  Returns ``True`` once the main thread is
    live, ``False`` if *shutdown* (a ``threading.Event``) is set before
    that happens.
    """
    if threading.current_thread() is threading.main_thread():
        return True

    generation = _halt
    shutdown = generation if shutdown is None else shutdown
    while not generation.is_set() and not shutdown.is_set():
        reply = queue.Queue(maxsize=1)
        envelope = _new_envelope(
            {"params": {"name": "__startup_ping__"}}, reply
        )
        envelope["_shutdown"] = generation
        with _lifecycle_lock:
            if generation is not _halt or generation.is_set() or shutdown.is_set():
                return False
            _pending.put(envelope)

        try:
            _fire_signal(generation)
        except Exception:
            # The scheduler's keepalive ticks fire this event too, so a
            # single failure here is not fatal.
            pass

        try:
            result = reply.get(timeout=poll_interval)
        except queue.Empty:
            _try_remove(envelope)
            continue
        _try_remove(envelope)
        if _is_ready_reply(result):
            return not generation.is_set() and not shutdown.is_set()
        # A reply that is not the expected ready answer means the ping was
        # mishandled; keep waiting for a genuine main-thread round-trip.

    return False


def _is_ready_reply(result):
    return (
        isinstance(result, dict)
        and bool(result.get("content"))
        and isinstance(result["content"][0], dict)
        and result["content"][0].get("text") == "ready"
    )


# ── Internal helpers ─────────────────────────────────────────────────────


def _try_remove(envelope):
    """Best-effort removal of an unprocessed envelope from the queue."""
    with _pending.mutex:
        try:
            _pending.queue.remove(envelope)
            return True
        except ValueError:
            return False


def _flush_pending():
    """Process up to *_BATCH_LIMIT* envelopes from the queue."""
    if not _run_lock.acquire(blocking=False):
        return
    try:
        drain_logs()
        if _lifecycle_poll is not None:
            _lifecycle_poll()
        processed = 0
        while processed < _BATCH_LIMIT:
            try:
                envelope = _pending.get_nowait()
            except queue.Empty:
                break

            payload = envelope["payload"]
            reply = envelope["reply"]
            shutdown = envelope.get("_shutdown")
            if shutdown is not None and shutdown.is_set():
                with envelope["_lock"]:
                    envelope["_state"] = "cancelled"
                _deregister_inflight(envelope)
                _put_reply(reply, _text_result(_QUEUED_CANCEL_TEXT))
                processed += 1
                continue

            if "_bootstrap_entry" in envelope:
                _consume_bootstrap_entry(envelope)
                processed += 1
                continue

            # The readiness ping is answered here, before any tool routing,
            # so it succeeds even while the tool handler is not installed
            # (cold start, add-in not fully running).
            ping_params = (
                payload.get("params") if isinstance(payload, dict) else None
            )
            if (
                isinstance(ping_params, dict)
                and ping_params.get("name") == "__startup_ping__"
            ):
                with envelope["_lock"]:
                    envelope["_state"] = "done"
                _put_reply(
                    reply, {"content": [{"type": "text", "text": "ready"}]}
                )
                processed += 1
                continue

            # Honour the upstream v1.4.0 `_cancel_event` so a queued request
            # that was cancelled / timed out by the protocol layer is never
            # executed.
            cancel_ev = (
                payload.get("_cancel_event") if isinstance(payload, dict) else None
            )
            if cancel_ev is not None and (cancel_ev.is_set() or _halt.is_set()):
                with envelope["_lock"]:
                    envelope["_state"] = "done"
                _deregister_inflight(envelope)
                _put_reply(reply, _text_result(_CANCELLED_TEXT))
                processed += 1
                continue

            with envelope["_lock"]:
                if envelope["_state"] == "cancelled":
                    envelope["_state"] = "done"
                    cancelled = True
                else:
                    envelope["_state"] = "running"
                    cancelled = False

            if cancelled:
                _deregister_inflight(envelope)
                _put_reply(reply, _text_result(_QUEUED_CANCEL_TEXT))
                processed += 1
                continue

            try:
                result = _execute(shutdown if shutdown is not None else _halt,
                                  payload, envelope.get("_admission_consumer"))
            except AdmissionTargetError as exc:
                result = exc
            except Exception as exc:
                tb = traceback.format_exc()
                log(
                    f"Main-thread work item failed: {exc}",
                    adsk.core.LogLevels.ErrorLogLevel,
                )
                log(tb, adsk.core.LogLevels.ErrorLogLevel)
                result = {
                    "content": [
                        {
                            "type": "text",
                            "text": (
                                f"Error: {type(exc).__name__}: {exc}\n"
                                "Call: _flush_pending()\n"
                                f"Traceback:\n{tb}"
                            ),
                        }
                    ],
                    "isError": True,
                }

            with envelope["_lock"]:
                envelope["_state"] = "done"
            _deregister_inflight(envelope)
            _put_reply(reply, result)
            processed += 1

        drain_logs()
    finally:
        _run_lock.release()


# ── Lifecycle ─────────────────────────────────────────────────────────────


def init_main_thread_dispatch():
    global _callback_event, _registered, _halt, _startup_ticket

    with _lifecycle_lock:
        if _registered or _running_handlers or _running_signals:
            raise RuntimeError("The prior main-thread dispatch is not retired")
        # A stopped generation stays stopped, even after a fast restart.
        _halt = threading.Event()
        _startup_ticket = None
    _scheduler_active.clear()
    _callback_event = get_app().registerCustomEvent(CALLBACK_EVENT_ID)
    handler = _BridgeEventHandler(_halt)
    _callback_event.add(handler)
    # Store handler on the event object to prevent GC
    _callback_event._bridge_handler = handler
    _registered = True

    _scheduler_active.set()
    _schedule_tick()


def request_main_thread_shutdown(shutdown=None):
    """Signal shutdown from any thread; no Fusion API calls here."""
    pending = []
    with _lifecycle_lock:
        if shutdown is not None and shutdown is not _halt:
            return False
        _halt.set()
        _scheduler_active.clear()
        while True:
            try:
                pending.append(_pending.get_nowait())
            except queue.Empty:
                break
        quiescent = _running_handlers == 0 and _running_signals == 0
    for envelope in pending:
        with envelope["_lock"]:
            envelope["_state"] = "cancelled"
        _deregister_inflight(envelope)
        _put_reply(envelope["reply"], _text_result(_QUEUED_CANCEL_TEXT))
    return quiescent


def defer_main_thread_retirement(callback):
    """Arrange a main-thread continuation for a host stop that cannot wait."""
    global _deferred_retirement
    with _lifecycle_lock:
        if not _registered or _deferred_retirement is not None:
            return
        retirement = _Retirement(_halt, callback)
        _deferred_retirement = retirement

    def signal_until_retired():
        while not retirement.done.wait(_TICK_INTERVAL):
            try:
                _fire_signal(retirement.shutdown, retirement=retirement)
            except Exception as exc:
                log(f"Retirement signal failed: {exc}", adsk.core.LogLevels.ErrorLogLevel)

    thread = threading.Thread(target=signal_until_retired, daemon=True)
    thread.start()


def _try_deferred_retirement(shutdown):
    if threading.current_thread() is not threading.main_thread():
        return
    with _lifecycle_lock:
        retirement = _deferred_retirement
        if (retirement is None or shutdown is not retirement.shutdown
                or retirement.delivering or _running_handlers or _running_signals):
            return
        # Do not let the control worker issue another signal as the callback
        # checks rundown and unregisters the event.
        retirement.delivering = True
    try:
        retirement.callback()
    finally:
        with _lifecycle_lock:
            retirement.delivering = False


def stop_main_thread_dispatch():
    global _callback_event, _registered, _deferred_retirement

    if not request_main_thread_shutdown():
        return False
    with _lifecycle_lock:
        # Freeze retirement signals at the same boundary as the idle check.
        if _running_handlers or _running_signals:
            return False
        if _deferred_retirement is not None:
            _deferred_retirement.done.set()
            _deferred_retirement = None

    if _callback_event and hasattr(_callback_event, "_bridge_handler"):
        try:
            _callback_event.remove(_callback_event._bridge_handler)
        except Exception as exc:
            log(
                f"Error removing event handler: {exc}",
                adsk.core.LogLevels.WarningLogLevel,
            )

    app = None
    try:
        app = get_app()
    except Exception:
        app = None

    if app and _registered and hasattr(app, "unregisterCustomEvent"):
        try:
            app.unregisterCustomEvent(CALLBACK_EVENT_ID)
        except Exception as exc:
            log(
                f"Error unregistering custom event: {exc}",
                adsk.core.LogLevels.WarningLogLevel,
            )

    _registered = False
    _callback_event = None
    return True


def get_shutdown_flag():
    return _halt
