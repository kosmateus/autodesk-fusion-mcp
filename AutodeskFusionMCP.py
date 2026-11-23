# -*- coding: utf-8 -*-
"""
Autodesk Fusion MCP - Add-in entry point.

Starts a standalone MCP server inside Autodesk Fusion that allows
AI agents (Claude, etc.) to control Fusion directly.
"""


def run(context):
    """Entry point - Fusion calls this when the add-in starts."""
    try:
        import os

        bootstrap = None
        if "FUSION_MCP_BOOTSTRAP_INTENT" in os.environ:
            from .lib.bootstrap_entry import BootstrapEntry

            bootstrap = BootstrapEntry(os.environ["FUSION_MCP_BOOTSTRAP_INTENT"], __file__)
            bootstrap.before_import()

        from . import addon_runtime

        addon_runtime.run(context)
        if bootstrap is not None:
            bootstrap.run_returned()
    except Exception as e:
        print(f"[AutodeskFusionMCP] Failed to start: {e}")
        import traceback

        traceback.print_exc()


def stop(context):
    """Shutdown - Fusion calls this when the add-in stops."""
    try:
        from . import addon_runtime

        addon_runtime.stop(context)
    except Exception as e:
        print(f"[AutodeskFusionMCP] Error during shutdown: {e}")
