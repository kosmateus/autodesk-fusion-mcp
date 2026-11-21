"""Thread-safe callback relay for executing work on the Fusion main thread."""

import queue
import threading
import traceback
from datetime import datetime

import adsk.core

from ..lib import fusionAddInUtils as futil
from ..lib.admission_receiver import AdmissionTargetError

# ── Module state ──────────────────────────────────────────────────────────

_callback_impl = None
_pending = queue.Queue()
_callback_event = None
_scheduler_active = threading.Event()
_halt = threading.Event()
_run_lock = threading.Lock()
_lifecycle_lock = threading.Lock()
_generation = object()
_running_handlers = 0

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
        futil.log(text) if lvl is None else futil.log(text, lvl)


# ── Custom-event handler ─────────────────────────────────────────────────


class _BridgeEventHandler(adsk.core.CustomEventHandler):
    """Responds to the custom Fusion event by draining the work queue."""

    def __init__(self, generation=None):
        super().__init__()
        self._generation = generation

    def notify(self, args):
        del args
        if self._generation is not None:
            with _lifecycle_lock:
                if self._generation is not _generation:
                    return
        _flush_pending()


# ── Recursive timer scheduler ────────────────────────────────────────────


def _schedule_tick(active):
    """Fire a single tick, then reschedule if still active."""
    if not active.is_set():
        return
    try:
        _fire_event_if_needed()
    except Exception as exc:
        log(f"Scheduler tick error: {exc}", adsk.core.LogLevels.ErrorLogLevel)
    if active.is_set():
        t = threading.Timer(_TICK_INTERVAL, _schedule_tick, (active,))
        t.daemon = True
        t.start()


_last_fire_time = 0.0


def _fire_event_if_needed():
    """Signal the main thread when there is queued work or a keepalive is due."""
    import time

    global _last_fire_time
    now = time.time()
    has_work = not _pending.empty()
    keepalive_due = (now - _last_fire_time) >= _KEEPALIVE_INTERVAL
    if has_work or keepalive_due:
        get_app().fireCustomEvent(CALLBACK_EVENT_ID)
        _last_fire_time = now


# ── Public dispatch API ──────────────────────────────────────────────────


def set_tool_handler(handler):
    global _callback_impl
    _callback_impl = handler


def bind_dispatch():
    """Bind an HTTP listener to this dispatch lifetime, including keep-alives."""
    with _lifecycle_lock:
        generation = _generation

    def dispatch(call_data, *, admission_consumer=None):
        return _submit(generation, call_data, admission_consumer)

    return dispatch


def dispatch_to_main_thread(call_data, *, admission_consumer=None):
    """Submit *call_data* for execution on the Fusion main thread and block
    until the result is available.  If already on the main thread, execute
    directly."""
    with _lifecycle_lock:
        generation = _generation
    return _submit(generation, call_data, admission_consumer)


def _submit(generation, call_data, admission_consumer):
    cancelled = call_data.get("_cancel_event")
    if threading.current_thread() is threading.main_thread():
        return _execute(generation, call_data, admission_consumer)

    reply = queue.Queue(maxsize=1)
    envelope = {
        "generation": generation, "payload": call_data, "reply": reply,
        "admission_consumer": admission_consumer,
    }
    with _lifecycle_lock:
        if _halt.is_set() or generation is not _generation or (
            cancelled is not None and cancelled.is_set()
        ):
            return _cancelled_result()
        _pending.put(envelope)

    try:
        get_app().fireCustomEvent(CALLBACK_EVENT_ID)
    except Exception as exc:
        _try_remove(envelope)
        log(
            f"Failed to fire main-thread event: {exc}",
            adsk.core.LogLevels.ErrorLogLevel,
        )
        return {
            "content": [
                {
                    "type": "text",
                    "text": f"Error: RuntimeError: failed to schedule Fusion main-thread work ({exc})",
                }
            ],
            "isError": True,
        }

    if cancelled is None:
        return _receive(reply)
    while True:
        if cancelled.is_set() or _halt.is_set():
            cancelled.set()
            _try_remove(envelope)
            return _cancelled_result()
        try:
            return _receive(reply, timeout=0.05)
        except queue.Empty:
            pass


# ── Internal helpers ─────────────────────────────────────────────────────


def _receive(reply, timeout=None):
    result = reply.get(timeout=timeout)
    if isinstance(result, AdmissionTargetError):
        raise result
    return result


def _execute(generation, payload, consumer):
    global _running_handlers
    cancelled = payload.get("_cancel_event")
    with _lifecycle_lock:
        if _halt.is_set() or generation is not _generation or (
            cancelled is not None and cancelled.is_set()
        ):
            return _cancelled_result()
        handler = _callback_impl
        if handler is None:
            raise RuntimeError("Tool implementation is not initialized")
        _running_handlers += 1
    try:
        if consumer is not None:
            return consumer(handler)
        return handler(payload)
    finally:
        with _lifecycle_lock:
            _running_handlers -= 1


def _cancelled_result():
    return {
        "content": [{"type": "text", "text": "Request cancelled; work already started may still complete."}],
        "isError": True,
    }


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
        processed = 0
        while processed < _BATCH_LIMIT:
            try:
                envelope = _pending.get_nowait()
            except queue.Empty:
                break

            payload = envelope["payload"]
            reply = envelope["reply"]
            try:
                result = _execute(
                    envelope["generation"], payload, envelope["admission_consumer"],
                )
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

            reply.put(result)
            processed += 1

        drain_logs()
    finally:
        _run_lock.release()


# ── Lifecycle ─────────────────────────────────────────────────────────────


def init_main_thread_dispatch():
    global _callback_event, _registered, _generation, _scheduler_active

    with _lifecycle_lock:
        if _registered or _running_handlers:
            raise RuntimeError("The prior main-thread dispatch is not retired")

    _scheduler_active.clear()
    _scheduler_active = threading.Event()
    generation = object()
    _callback_event = get_app().registerCustomEvent(CALLBACK_EVENT_ID)
    handler = _BridgeEventHandler(generation)
    _callback_event.add(handler)
    # Store handler on the event object to prevent GC
    _callback_event._bridge_handler = handler
    _registered = True
    with _lifecycle_lock:
        _generation = generation
        _halt.clear()

    _scheduler_active.set()
    _schedule_tick(_scheduler_active)


def quiesce_main_thread_dispatch():
    """Close intake without waiting on Fusion's main thread.

    A re-entrant stop cannot complete while a handler remains on the stack.
    Pending envelopes never become executable again.
    """
    with _lifecycle_lock:
        _halt.set()
        while True:
            try:
                envelope = _pending.get_nowait()
            except queue.Empty:
                break
            envelope["reply"].put_nowait(_cancelled_result())
        return _running_handlers == 0


def stop_main_thread_dispatch():
    global _callback_event, _registered

    quiescent = quiesce_main_thread_dispatch()
    _scheduler_active.clear()
    if not quiescent:
        return False

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
