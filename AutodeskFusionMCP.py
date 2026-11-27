# -*- coding: utf-8 -*-
"""
Autodesk Fusion MCP - Add-in entry point.

Starts a standalone MCP server inside Autodesk Fusion that allows
AI agents (Claude, etc.) to control Fusion directly.
"""


def run(context):
    """Entry point - Fusion calls this when the add-in starts."""
    failure_reporter = None
    intent_path = None
    private_startup = False
    phase = "constructor"
    try:
        import os

        bootstrap = None
        if "FUSION_MCP_BOOTSTRAP_INTENT" in os.environ:
            intent_path = os.environ["FUSION_MCP_BOOTSTRAP_INTENT"]
            private_startup = True
            import sys

            # Embedded hosts may ignore PYTHONDONTWRITEBYTECODE. Preserve the
            # pinned tree through deferred imports too; this is not admission.
            sys.dont_write_bytecode = True
            from .lib.bootstrap_entry import BootstrapEntry, report_bootstrap_failure
            failure_reporter = report_bootstrap_failure

            # Fusion's loader may spell Windows __file__ with forward slashes.
            # Normalize separators only; keep strict path/identity validation.
            bootstrap = BootstrapEntry(
                intent_path,
                __file__.replace("/", os.sep))
            private_startup = bootstrap.audited
            bootstrap.before_import()
            if bootstrap.audited:
                phase = "schedule"
                from .fusion_bridge.dispatch import schedule_bootstrap_entry
                schedule_bootstrap_entry(bootstrap, context)
                return

        from . import addon_runtime

        addon_runtime.run(context)
        if bootstrap is not None:
            bootstrap.run_returned()
    except Exception as e:
        if failure_reporter is not None:
            failure_reporter(intent_path, phase, e)
        if private_startup:
            print("[AutodeskFusionMCP] Failed to start: private startup diagnostic only")
            return
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
