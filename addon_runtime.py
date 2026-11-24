# -*- coding: utf-8 -*-
"""Autodesk Fusion MCP add-in runtime wiring."""

from . import settings
from .fusion_bridge import runtime as fusion_runtime
from .lib import fusionAddInUtils as futil

commands = None


def run(context, *, bootstrap=None):
    global commands
    del context
    try:
        fusion_runtime.log("Autodesk Fusion MCP starting...")
        fusion_runtime.log(f"  MCP_AUTO_CONNECT: {settings.MCP_AUTO_CONNECT}")
        fusion_runtime.log(f"  MCP_SERVER_PORT: {settings.MCP_SERVER_PORT}")
        started = (fusion_runtime.start(bootstrap=bootstrap) if bootstrap is not None
                   else fusion_runtime.start())
        if not started:
            fusion_runtime.log("ERROR: Autodesk Fusion MCP startup aborted")
            return False
        if bootstrap is None:
            # Controlled startup must not create optional UI commands while
            # qualifying its getter-only bootstrap. Ordinary startup is unchanged.
            from . import commands as optional_commands
            commands = optional_commands
            commands.start()
        fusion_runtime.log("[OK] Autodesk Fusion MCP started")
        return True
    except Exception:
        if bootstrap is not None:
            raise
        futil.handle_error("run")
        return False


def stop(context):
    del context

    def retired():
        try:
            if commands is not None:
                commands.stop()
            futil.clear_handlers()
            fusion_runtime.log("[OK] Autodesk Fusion MCP stopped")
        except Exception:
            futil.handle_error("stop")

    try:
        fusion_runtime.log("Autodesk Fusion MCP stopping...")
        fusion_runtime.stop(on_retired=retired)
    except Exception:
        futil.handle_error("stop")
