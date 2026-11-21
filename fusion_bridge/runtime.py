"""Fusion bridge server assembly and startup/shutdown wiring."""

import platform
import threading
import time
import traceback

import adsk.core

from .. import settings
from ..lib import mcp_server as mcp_server_module
from . import doc_lookup, python_exec, tool_surface
from .admission_runtime import AdmissionRuntime
from .dispatch import (
    bind_dispatch,
    drain_logs,
    format_duration,
    get_shutdown_flag,
    init_main_thread_dispatch,
    log,
    quiesce_main_thread_dispatch,
    set_tool_handler,
    stop_main_thread_dispatch,
)


_server = None
_admission = None


def handle_any_tool(call_data):
    """Route to the correct handler based on tool name, timing execution."""
    from . import operations

    tool_name = call_data.get("params", {}).get("name", "")
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


def create_server(dispatch, *, admission_api=None):
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


def _start_server():
    global _server, _admission

    if _server and _server.is_running:
        log("MCP server already running")
        return True

    log(f"Starting MCP server on port {settings.MCP_SERVER_PORT}...")
    dispatch = bind_dispatch()
    _admission = AdmissionRuntime.from_environment(dispatch)
    _server = create_server(dispatch, admission_api=_admission.http if _admission else None)
    attempt = 0
    shutdown_flag = get_shutdown_flag()
    while not shutdown_flag.is_set():
        try:
            _server.start()
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


def start():
    _require_main_thread()
    version_info = python_exec.get_version_info(python_exec.get_addin_dir())
    log(f"MCP Integration starting... add-in {version_info}")
    fusion_version = getattr(adsk.core.Application.get(), "version", "unknown")
    log(f"Runtime: Autodesk Fusion {fusion_version}; Python {platform.python_version()}")

    try:
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
            if not _start_server():
                stop()
                return False
            log("MCP Integration started successfully")
        except Exception as exc:
            log(
                f"ERROR: Failed to start MCP server: {exc}",
                adsk.core.LogLevels.ErrorLogLevel,
            )
            log(traceback.format_exc(), adsk.core.LogLevels.ErrorLogLevel)
            stop()
            return False
    else:
        log("MCP_AUTO_CONNECT is False - MCP server disabled")
        log("Set MCP_AUTO_CONNECT = True in settings.py to enable")

    drain_logs()
    return True


def _require_main_thread():
    if threading.current_thread() is not threading.main_thread():
        raise RuntimeError("Fusion runtime lifecycle requires the main thread")


def _seal():
    if _admission:
        _admission.http.begin_quiescence()
    if not quiesce_main_thread_dispatch():
        return False
    return _admission is None or _admission.http.seal_if_idle()


def _retire():
    global _server, _admission

    if _server:
        _server.stop()
        _server = None
    stop_main_thread_dispatch()
    if _admission:
        _admission.close()
        _admission = None


def handoff_admission_generation(*, instance, epoch):
    """Explicit trusted handoff; False means retry after outstanding work settles."""
    _require_main_thread()
    if _admission is None:
        raise RuntimeError("No admission runtime to hand off")
    if not _seal():
        return False
    _admission.advance_generation(instance=instance, epoch=epoch)
    _retire()
    return True


def stop():
    _require_main_thread()
    log("MCP Integration stopping...")
    if not _seal():
        log("MCP Integration still quiescing; retirement deferred")
        return False

    _retire()
    log("MCP Integration stopped")
    drain_logs()
    return True
