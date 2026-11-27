"""Fixed getter-only startup data. Callable only in the shared SDK queue.

This inventories Application.scripts, not arbitrary Python autorun mechanisms.
No returned dictionary is a capability or permission to dispatch SDK work.
"""

import hashlib
from pathlib import Path
from typing import TYPE_CHECKING, Callable

from .admission_json import decode_json
from .request_admission import AdmissionError, _encode

if TYPE_CHECKING:
    import adsk.core


MAX_SCRIPTS = 1024
MAX_MANIFEST_BYTES = 256 * 1024
MAX_AUDIT_BYTES = 4 * 1024 * 1024
_LOCATIONS = (
    "AppStoreScriptSourceLocation", "OtherInstalledScriptSourceLocation",
    "UserDefinedScriptSourceLocation", "InternalScriptSourceLocation",
    "SamplesScriptSourceLocation", "LinkedScriptSourceLocation",
)


class StartupAuditError(AdmissionError):
    def __init__(self, code: str, field: str):
        super().__init__(f"BOOTSTRAP_STARTUP_AUDIT_{code}: {field}")


def _get(field: str, getter: Callable[[], object]) -> object:
    try:
        return getter()
    except Exception:
        raise StartupAuditError("GETTER_FAILED", field) from None


def _text(value: object, field: str, *, limit: int, path: bool = False) -> str:
    if type(value) is not str:
        raise StartupAuditError("VALUE_UNVERIFIED", field)
    try:
        size = len(value.encode("utf-8"))
    except UnicodeError:
        raise StartupAuditError("VALUE_UNVERIFIED", field) from None
    if not value or size > limit or "\0" in value:
        raise StartupAuditError("VALUE_UNVERIFIED", field)
    if path and not Path(value).is_absolute():
        raise StartupAuditError("VALUE_UNVERIFIED", field)
    return value


def _bool(value: object, field: str) -> bool:
    if type(value) is not bool:
        raise StartupAuditError("VALUE_UNVERIFIED", field)
    return value


def _count(value: object, field: str) -> int:
    if type(value) is not int or value < 0:
        raise StartupAuditError("VALUE_UNVERIFIED", field)
    if value > MAX_SCRIPTS:
        raise StartupAuditError("COUNT_BUDGET_EXCEEDED", field)
    return value


def _capture(app: "adsk.core.Application", entry) -> dict:
    import adsk.core
    from ..fusion_bridge.dispatch import assert_startup_queue

    def guard():
        assert_startup_queue(entry)
        entry.assert_not_refused()

    def read(field: str, getter: Callable[[], object]) -> object:
        guard()
        value = _get(field, getter)
        guard()
        return value

    if app is None:
        raise StartupAuditError("VALUE_UNVERIFIED", "Application")
    version = _text(read("Application.version", lambda: app.version),
                    "Application.version", limit=65536)
    preference = _text(read(
        "defaultPathForScriptsAndAddIns",
        lambda: app.preferences.apiPreferences.defaultPathForScriptsAndAddIns,
    ), "defaultPathForScriptsAndAddIns", limit=65536, path=True)
    guard()
    scripts = app.scripts
    guard()
    if scripts is None:
        raise StartupAuditError("VALUE_UNVERIFIED", "Application.scripts")
    before = _count(read("scripts.countBefore", lambda: scripts.count), "scripts.countBefore")
    locations = {}
    for name in _LOCATIONS:
        value = read("ScriptSourceLocations." + name,
                     lambda name=name: getattr(adsk.core.ScriptSourceLocations, name))
        if type(value) is not int or value in locations:
            raise StartupAuditError("ENUM_UNVERIFIED", "ScriptSourceLocations." + name)
        locations[value] = name
    rows = []
    budget = 0
    for index in range(before):
        field = f"scripts.item[{index}]"
        guard()
        script = scripts.item(index)
        guard()
        if script is None:
            raise StartupAuditError("VALUE_UNVERIFIED", field)
        folder = _text(read(field + ".folder", lambda: script.folder),
                       field + ".folder", limit=65536, path=True)
        location = read(field + ".location", lambda: script.location)
        if type(location) is not int or location not in locations:
            raise StartupAuditError("ENUM_UNVERIFIED", field + ".location")
        is_addin = _bool(read(field + ".isAddIn", lambda: script.isAddIn),
                         field + ".isAddIn")
        # SDK contract: isRunOnStartup is valid ONLY for add-ins, not scripts.
        startup = (_bool(read(field + ".isRunOnStartup", lambda: script.isRunOnStartup),
                         field + ".isRunOnStartup") if is_addin else None)
        running = _bool(read(field + ".isRunning", lambda: script.isRunning),
                        field + ".isRunning")
        visible = _bool(read(field + ".isVisible", lambda: script.isVisible),
                        field + ".isVisible")
        manifest = _text(read(field + ".manifestContent", lambda: script.manifestContent),
                         field + ".manifestContent", limit=MAX_MANIFEST_BYTES)
        try:
            parsed = decode_json(manifest)
        except (ValueError, UnicodeError, RecursionError):
            raise StartupAuditError("MANIFEST_UNVERIFIED", field + ".manifestContent") from None
        if type(parsed) is not dict:
            raise StartupAuditError("MANIFEST_UNVERIFIED", field + ".manifestContent")
        row = {
            "index": index, "folder": folder,
            "location": {"name": locations[location], "value": location},
            "isAddIn": is_addin, "isRunOnStartup": startup,
            "isRunning": running, "isVisible": visible,
            "manifest": {
                "content": manifest,
                "sha256": hashlib.sha256(manifest.encode("utf-8")).hexdigest(),
                "parseStatus": "json-object",
            },
        }
        budget += len(_encode(row).encode("utf-8"))
        if budget > MAX_AUDIT_BYTES:
            raise StartupAuditError("BYTE_BUDGET_EXCEEDED", "scripts")
        rows.append(row)
    after = _count(read("scripts.countAfter", lambda: scripts.count), "scripts.countAfter")
    if before != after:
        raise StartupAuditError("COLLECTION_CHANGED", "scripts.count")
    preference_after = _text(read(
        "defaultPathForScriptsAndAddInsAfter",
        lambda: app.preferences.apiPreferences.defaultPathForScriptsAndAddIns,
    ), "defaultPathForScriptsAndAddInsAfter", limit=65536, path=True)
    if preference != preference_after:
        raise StartupAuditError("PREFERENCES_CHANGED", "defaultPathForScriptsAndAddIns")
    audit = {
        "kind": "fmcad-startup-sdk-audit", "version": 1,
        "applicationVersion": version,
        "preferences": {"defaultPathForScriptsAndAddIns": preference},
        "scripts": {"countBefore": before, "countAfter": after, "items": rows},
    }
    if len(_encode(audit).encode("utf-8")) > MAX_AUDIT_BYTES:
        raise StartupAuditError("BYTE_BUDGET_EXCEEDED", "audit")
    return audit


def collect_startup_audit(entry) -> dict:
    """Fixed SDK getters, never a user callback or externally supplied result."""
    from ..fusion_bridge.dispatch import assert_startup_queue
    import adsk.core

    assert_startup_queue(entry)
    entry.assert_current()
    entry.begin_sdk_audit()
    try:
        audit = _capture(adsk.core.Application.get(), entry)
    except StartupAuditError:
        raise
    except Exception:
        raise StartupAuditError("GETTER_FAILED", "Application.scripts") from None
    entry.assert_current()
    assert_startup_queue(entry)
    return audit
