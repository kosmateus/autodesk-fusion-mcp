"""Fusion bridge server assembly and startup/shutdown wiring."""

import platform
import threading
import time
import traceback

import adsk.core

from .. import settings
from ..lib import mcp_server as mcp_server_module
from ..lib.request_admission import GenerationUnchangedError
from . import doc_lookup, python_exec, tool_surface
from .admission_runtime import AdmissionRuntime
from .dispatch import (
    bind_dispatch,
    defer_main_thread_retirement,
    drain_logs,
    format_duration,
    get_shutdown_flag,
    init_main_thread_dispatch,
    log,
    set_tool_handler,
    set_lifecycle_poll,
    stop_main_thread_dispatch,
    wait_for_main_thread,
    request_main_thread_shutdown,
)


_server = None
_admission = None
_server_lock = threading.Lock()
_host_stop = None
_sdk_version = "unknown"


def handle_any_tool(call_data):
    """Route to the correct handler based on tool name, timing execution."""
    from . import operations

    tool_name = call_data.get("params", {}).get("name", "")
    if tool_name == "__startup_ping__":
        # Internal readiness probe used by wait_for_main_thread(); not a
        # real tool, so skip routing and per-command timing.
        return {"content": [{"type": "text", "text": "ready"}]}
    handler = operations.TOOL_HANDLERS.get(tool_name)
    if handler is None:
        return {
            "content": [{"type": "text", "text": f"Unknown tool: {tool_name}"}],
            "isError": True,
        }

    start = time.perf_counter()
    result = None
    try:
        result = handler(call_data)
        return result
    finally:
        elapsed_ms = (time.perf_counter() - start) * 1000
        is_error = result is None or (
            isinstance(result, dict) and result.get("isError")
        )
        status = "failed" if is_error else "completed"
        log(f"[MCP] {tool_name} {status} in {format_duration(elapsed_ms)}")


def create_server(dispatch, *, admission_api=None, physical_authority=None):
    from . import operations

    set_tool_handler(handle_any_tool)

    server = mcp_server_module.MCPServer(
        port=settings.MCP_SERVER_PORT,
        tools=tool_surface.TOOL_DEFINITIONS,
        tool_handlers={
            name: dispatch for name in operations.TOOL_HANDLERS
        },
        log_callback=log,
        admission_api=admission_api,
        physical_authority=physical_authority,
    )

    server.resources.append(
        {
            "uri": tool_surface.RESOURCE_URI,
            "name": tool_surface.RESOURCE_NAME,
            "description": tool_surface.RESOURCE_DESCRIPTION,
            "mimeType": "text/markdown",
            "content_fn": doc_lookup.read_design_guide,
        }
    )

    try:
        info = python_exec.get_version_info(python_exec.get_addin_dir())
        if "(" in info:
            server.git_commit = info.split("(")[1].rstrip(")")
    except Exception:
        pass

    return server


def _start_server(shutdown_flag):
    global _server, _admission

    if _server and _server.is_running:
        log("MCP server already running")
        return True

    log(f"Starting MCP server on port {settings.MCP_SERVER_PORT}...")
    attempt = 0
    dispatch = bind_dispatch(shutdown_flag)
    admission = AdmissionRuntime.from_environment(
        dispatch, shutdown=shutdown_flag, version=_sdk_version,
        endpoint=f"http://127.0.0.1:{settings.MCP_SERVER_PORT}/mcp",
    )
    try:
        server = create_server(dispatch, admission_api=admission.http if admission else None,
                               physical_authority=admission.physical if admission else None)
    except BaseException:
        if admission is not None:
            admission.close()
        raise
    try:
        return _listen(server, admission, shutdown_flag, attempt)
    finally:
        if admission is not None and _admission is not admission:
            admission.close()


def _listen(server, admission, shutdown_flag, attempt):
    global _server, _admission
    while not shutdown_flag.is_set():
        try:
            server.start()
            _server, _admission = server, admission
            if admission is not None:
                from ..lib.physical_lifecycle import LifecycleMailbox
                mailbox = LifecycleMailbox(admission.physical, handoff_admission_generation,
                                            retry=defer_main_thread_retirement)
                set_lifecycle_poll(mailbox.poll)
            break
        except OSError as exc:
            if "Address already in use" not in str(exc):
                raise
            attempt += 1
            delay = 2 if attempt <= 60 else min(2 ** (attempt - 60), 60)
            log(
                f"Port {settings.MCP_SERVER_PORT} busy, retrying in {delay}s (attempt {attempt})..."
            )
            shutdown_flag.wait(delay)
    else:
        log("MCP server start aborted (add-in stopping)")
        return False

    version_info = python_exec.get_version_info(python_exec.get_addin_dir())
    log(
        f"[SUCCESS] MCP server {version_info} running at http://127.0.0.1:{settings.MCP_SERVER_PORT}/mcp"
    )
    return True


def _server_start_worker(shutdown_flag=None, bootstrap=None):
    """Bind the MCP port only once Fusion's main thread is pumping events.

    During a cold start Fusion auto-loads add-ins before its event loop is
    live.  Binding the socket from ``run()`` in that window leaves a
    listening port that never serves requests, so MCP clients hang until
    the add-in is manually restarted.  Waiting here replicates the
    conditions of a manual (post-startup) add-in start.
    """
    shutdown_flag = shutdown_flag if shutdown_flag is not None else get_shutdown_flag()
    if shutdown_flag.is_set():
        return

    log("Waiting for the Fusion main thread to become ready...")
    wait_started = time.monotonic()
    if not wait_for_main_thread(poll_interval=1.0, shutdown=shutdown_flag):
        log("Add-in stopped before Fusion was ready; MCP server not started")
        return
    log(
        "Fusion main thread ready after "
        f"{format_duration((time.monotonic() - wait_started) * 1000)}"
    )

    with _server_lock:
        if shutdown_flag.is_set():
            return
        try:
            if bootstrap is not None:
                bootstrap.assert_ready_for_listener()
            if not _start_server(shutdown_flag):
                request_main_thread_shutdown(shutdown_flag)
        except Exception as exc:
            log(
                f"ERROR: Failed to start MCP server: {exc}",
                adsk.core.LogLevels.ErrorLogLevel,
            )
            log(traceback.format_exc(), adsk.core.LogLevels.ErrorLogLevel)
            request_main_thread_shutdown(shutdown_flag)


def start(*, bootstrap=None):
    global _sdk_version
    _require_main_thread()
    version_info = python_exec.get_version_info(python_exec.get_addin_dir())
    log(f"MCP Integration starting... add-in {version_info}")
    if bootstrap is not None:
        from ..lib.bootstrap_entry import BootstrapEntry
        if type(bootstrap) is not BootstrapEntry:
            raise PermissionError("Original controlled bootstrap required")
        bootstrap.assert_queued_entry()
        fusion_version = bootstrap.audit_version
    else:
        fusion_version = getattr(adsk.core.Application.get(), "version", "unknown")
    _sdk_version = str(fusion_version)
    log(f"Runtime: Autodesk Fusion {fusion_version}; Python {platform.python_version()}")

    try:
        if bootstrap is None:
            init_main_thread_dispatch()
    except Exception as exc:
        log(
            f"ERROR: Failed to initialize main-thread dispatch: {exc}",
            adsk.core.LogLevels.ErrorLogLevel,
        )
        log(traceback.format_exc(), adsk.core.LogLevels.ErrorLogLevel)
        return False

    if settings.MCP_AUTO_CONNECT:
        try:
            starter = threading.Thread(
                target=_server_start_worker,
                args=((get_shutdown_flag(), bootstrap) if bootstrap is not None
                      else (get_shutdown_flag(),)),
                name="AutodeskFusionMCP-server-start",
                daemon=True,
            )
            starter.start()
            log("MCP Integration started (server binds once Fusion is ready)")
        except Exception as exc:
            log(
                f"ERROR: Failed to start MCP server: {exc}",
                adsk.core.LogLevels.ErrorLogLevel,
            )
            log(traceback.format_exc(), adsk.core.LogLevels.ErrorLogLevel)
            stop_main_thread_dispatch()
            return False
    else:
        log("MCP_AUTO_CONNECT is False - MCP server disabled")
        log("Set MCP_AUTO_CONNECT = True in settings.py to enable")

    drain_logs()
    return True


def _require_main_thread():
    if threading.current_thread() is not threading.main_thread():
        raise RuntimeError("Fusion runtime lifecycle requires the main thread")


def _begin_rundown():
    if _admission:
        _admission.http.begin_quiescence()
    return request_main_thread_shutdown()


def _seal_if_idle():
    return _admission is None or _admission.http.seal_if_idle()


def _retire():
    global _server, _admission

    if not stop_main_thread_dispatch():
        raise RuntimeError("Dispatch became active during retirement")
    if _server:
        _server.stop()
        _server = None
    if _admission:
        _admission.close()
        _admission = None
    set_lifecycle_poll(None)


def handoff_admission_generation(*, instance, epoch, handoff_id=None):
    """Explicit trusted handoff; False means retry after outstanding work settles."""
    _require_main_thread()
    if not isinstance(handoff_id, str) or not handoff_id:
        raise GenerationUnchangedError("A nonempty handoff ID is required before rundown")
    if _admission is None:
        raise RuntimeError("No admission runtime to hand off")
    _admission._store.assert_provision_lifecycle_allowed()
    if _host_stop is not None or not _begin_rundown():
        return False
    if not _server_lock.acquire(blocking=False):
        return False
    try:
        if not _seal_if_idle():
            return False
        try:
            _admission.advance_generation(instance=instance, epoch=epoch, handoff_id=handoff_id)
        except GenerationUnchangedError:
            _admission.http.restore_recovery()
            raise
        except BaseException:
            _admission.physical.revoke()
            raise
        _admission.physical.revoke()
        _retire()
    finally:
        _server_lock.release()
    return True


def _finish_host_stop():
    global _host_stop
    if _host_stop is None:
        return True
    if not _begin_rundown():
        return False
    if not _server_lock.acquire(blocking=False):
        return False
    try:
        # A cold-start worker may have published a listener after the
        # first rundown attempt. Its own shutdown flag already fences admit.
        if not _begin_rundown() or not _seal_if_idle():
            return False
        _retire()
        (on_retired,) = _host_stop
        _host_stop = None
    finally:
        _server_lock.release()
    log("MCP Integration stopped")
    drain_logs()
    if on_retired is not None:
        on_retired()
    return True


def stop(*, on_retired=None):
    _require_main_thread()
    global _host_stop
    if _host_stop is not None:
        return False
    log("MCP Integration stopping...")
    _host_stop = (on_retired,)
    if _finish_host_stop():
        return True
    defer_main_thread_retirement(_finish_host_stop)
    log("MCP Integration still quiescing; retirement deferred")
    return False
