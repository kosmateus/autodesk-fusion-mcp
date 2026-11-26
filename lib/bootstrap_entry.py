"""Optional private startup facts, not a grant, readiness or clean-host proof.

The operator/OS and reviewed bootstrap are trusted. Receipts only record entry
into this code and a successful return from addon_runtime.run. A later native
consumer must authenticate the original references and qualify admission closure.
"""

import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import threading

from .admission_json import decode_json
from .physical_authority import _read_private_bytes, _check_windows_acl
from .rebaseline_fence import observe_process_birth
from .request_admission import AdmissionError, _encode


def _deny():
    raise AdmissionError("BOOTSTRAP_ENTRY_INTENT_REJECTED")


def _exact(value, keys):
    if type(value) is not dict or set(value) != set(keys):
        _deny()
    return value


def _text(value):
    if type(value) is not str or not value or len(value.encode("utf-8")) > 65536:
        _deny()
    return value


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _digest(value):
    if type(value) is not str or re.fullmatch("[0-9a-f]{64}", value) is None:
        _deny()
    return value


def _profile_digest(data):
    try:
        value = decode_json(data.decode("utf-8"))
        if type(value) is not dict:
            _deny()
        return _sha(_encode(value).encode("utf-8"))
    except (ValueError, UnicodeError, RecursionError):
        _deny()


def _path(value):
    path = Path(_text(value))
    if not path.is_absolute() or str(path) != value or path.resolve() != path:
        _deny()
    return path


def _directory(path):
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & 0x400
            or (os.name != "nt" and
                (info.st_uid != os.getuid() or info.st_mode & 0o077))):
        _deny()
    _check_windows_acl(path)
    return info.st_dev, info.st_ino


def _process_image():
    if sys.platform.startswith("linux"):
        return Path("/proc/self/exe").resolve()
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        kernel.QueryFullProcessImageNameW.argtypes = [
            wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR,
            ctypes.POINTER(wintypes.DWORD)]
        image = ctypes.create_unicode_buffer(32768)
        size = wintypes.DWORD(len(image))
        if not kernel.QueryFullProcessImageNameW(
                kernel.GetCurrentProcess(), 0, image, ctypes.byref(size)):
            _deny()
        return Path(image.value).resolve()
    _deny()


def _read(path):
    _directory(path.parent)
    return _read_private_bytes(path)


class BootstrapEntry:
    """One original intent, never resumable/replayable; no caller token API."""

    def __init__(self, intent_path, entry_file):
        self.intent_path = _path(intent_path)
        self.intent_bytes = _read(self.intent_path)
        value = decode_json(self.intent_bytes.decode("utf-8"))
        if type(value) is not dict or type(value.get("version")) is not int:
            _deny()
        self.owned_autoload = value["version"] == 3
        self.audited = value["version"] in (2, 3)
        fields = (
            "kind", "version", "nonce", "process", "purpose", "engineVersion",
            "installed", "profile", "receipts")
        self.intent = _exact(
            value, fields + (("executable",) if self.audited else ())
            + (("mode", "provision", "generation") if self.owned_autoload else ()))
        intent = self.intent
        if (intent["kind"] != "fmcad-bootstrap-entry-intent"
                or intent["version"] not in (1, 2, 3)
                or intent["purpose"] != (
                    "isolated-stdout-v1" if self.audited else "bootstrap-entry-data-v1")
                or type(intent["engineVersion"]) is not int or intent["engineVersion"] != 2
                or type(intent["nonce"]) is not str
                or re.fullmatch("[0-9a-f]{32}", intent["nonce"]) is None):
            _deny()
        process = _exact(intent["process"], ("pid", "birth"))
        if type(process["pid"]) is not int or process["pid"] != os.getpid():
            _deny()
        _text(process["birth"])
        self.executable = None
        if self.audited:
            executable = _exact(intent["executable"], ("path", "sha256"))
            self.executable = _path(executable["path"])
            _digest(executable["sha256"])
        installed = _exact(intent["installed"], ("directory", "source", "files"))
        self.installed = _path(installed["directory"])
        if (self.installed != Path(__file__).resolve().parent.parent
                or _path(str(entry_file)) != self.installed / "AutodeskFusionMCP.py"
                or type(installed["source"]) is not str
                or re.fullmatch("[0-9a-f]{40}", installed["source"]) is None):
            _deny()
        files = installed["files"]
        if (type(files) is not dict or not files
                or not {"AutodeskFusionMCP.py", "addon_runtime.py",
                        "lib/bootstrap_entry.py"}.issubset(files)):
            _deny()
        for name, digest in files.items():
            relative = PurePosixPath(_text(name))
            if (relative.is_absolute() or str(relative) != name
                    or ".." in relative.parts or "\\" in name or ":" in name):
                _deny()
            _digest(digest)
        profile_fields = ("path", "sha256")
        if (self.owned_autoload and type(intent["profile"]) is dict
                and "semanticSha256" in intent["profile"]):
            profile_fields += ("semanticSha256",)
        profile = _exact(intent["profile"], profile_fields)
        self.profile = _path(profile["path"])
        _digest(profile["sha256"])
        self.profile_semantic_sha256 = (
            _digest(profile["semanticSha256"])
            if "semanticSha256" in profile else None)
        self.profile_bytes = _read(self.profile)
        if self.profile_semantic_sha256 is not None:
            if not self._profile_matches(self.profile_bytes):
                _deny()
        elif _sha(self.profile_bytes) != profile["sha256"]:
            _deny()
        self.provision = None
        self.provision_bytes = None
        if self.owned_autoload:
            if intent["mode"] != "owned-autoload-v1":
                _deny()
            generation = _exact(intent["generation"], ("instance", "epoch"))
            for value in generation.values():
                _text(value)
            provision = _exact(intent["provision"], ("path", "sha256"))
            self.provision = _path(provision["path"])
            _digest(provision["sha256"])
            self.provision_bytes = _read(self.provision)
            if _sha(self.provision_bytes) != provision["sha256"]:
                _deny()
            data = _exact(decode_json(self.provision_bytes.decode("utf-8")), (
                "database", "pid", "birth", "instance", "epoch", "source", "build",
                "credentials"))
            if (type(data["pid"]) is not int or data["pid"] != process["pid"]
                    or data["birth"] != process["birth"]
                    or {key: data[key] for key in generation} != generation):
                _deny()
            for key in ("birth", "instance", "epoch", "source", "build"):
                _text(data[key])
            _path(data["database"])
            from .admission_http import AdmissionHTTP
            AdmissionHTTP.validate_credentials(data["credentials"])
        receipts = _exact(intent["receipts"], ("directory", "entry", "returned"))
        self.output = _path(receipts["directory"])
        self.output_identity = _directory(self.output)
        names = (receipts["entry"], receipts["returned"])
        if names[0] == names[1]:
            _deny()
        for name in names:
            if (type(name) is not str or re.fullmatch("[a-z0-9_-]+[.]json", name) is None
                    or re.fullmatch("(con|prn|aux|nul|com[1-9]|lpt[1-9])[.]json", name)):
                _deny()
        self.entry_path, self.returned_path = (self.output / name for name in names)
        # Output must not alter the full installed manifest or any original input.
        if (self.output == self.installed or self.installed in self.output.parents
                or {self.entry_path, self.returned_path}
                & {self.intent_path, self.profile, self.provision}):
            _deny()
        self.entry_bytes = None
        self.returned_bytes = None
        self.audit_version = None
        self._begun = False
        self._scheduled = False
        self._audit_started = False
        self._refused = None
        self._state_lock = threading.Lock()
        self.assert_current()
        if os.path.lexists(self.entry_path) or os.path.lexists(self.returned_path):
            _deny()

    def _profile_matches(self, data):
        if self.profile_semantic_sha256 is not None:
            return _profile_digest(data) == self.profile_semantic_sha256
        return data == self.profile_bytes

    def assert_current(self):
        with self._state_lock:
            if self._refused is not None:
                _deny()
        intent = self.intent
        if (os.getpid() != intent["process"]["pid"]
                or observe_process_birth(os.getpid()) != intent["process"]["birth"]
                or _read(self.intent_path) != self.intent_bytes
                or not self._profile_matches(_read(self.profile))
                or _directory(self.output) != self.output_identity):
            _deny()
        if self.audited and (
                _process_image() != self.executable
                or _sha(self.executable.read_bytes()) != intent["executable"]["sha256"]):
            _deny()
        if self.owned_autoload and (
                os.environ.get("FUSION_MCP_ADMISSION_PROVISION") != str(self.provision)
                or _read(self.provision) != self.provision_bytes):
            _deny()
        # No ignored caches, plugins or extra files: the operator must pin the
        # complete deployed tree. PYTHONDONTWRITEBYTECODE avoids import writes.
        actual = {}
        pending = [self.installed]
        while pending:
            directory = pending.pop()
            _directory(directory)
            for child in directory.iterdir():
                info = child.lstat()
                if child.is_symlink() or getattr(info, "st_file_attributes", 0) & 0x400:
                    _deny()
                if stat.S_ISDIR(info.st_mode):
                    pending.append(child)
                elif stat.S_ISREG(info.st_mode):
                    actual[child.relative_to(self.installed).as_posix()] = _sha(_read(child))
                else:
                    _deny()
        if actual != intent["installed"]["files"]:
            _deny()

    def _write(self, path, phase, entry=None, audit=None):
        self.assert_current()
        receipt = {
            "kind": "fmcad-bootstrap-entry-receipt",
            "version": self.intent["version"],
            "phase": phase,
            "nonce": self.intent["nonce"],
            "process": self.intent["process"],
            "purpose": self.intent["purpose"],
            "engineVersion": 2,
            "intent": {"path": str(self.intent_path), "sha256": _sha(self.intent_bytes)},
            "profile": self.intent["profile"],
            "installed": {
                "directory": str(self.installed),
                "source": self.intent["installed"]["source"],
                "filesDigest": _sha(_encode(self.intent["installed"]["files"]).encode("utf-8")),
            },
        }
        if self.audited:
            receipt["executable"] = self.intent["executable"]
        if self.owned_autoload:
            for key in ("mode", "provision", "generation"):
                receipt[key] = self.intent[key]
        if audit is not None:
            receipt["startupAudit"] = audit
        if entry is not None:
            receipt["entry"] = entry
        data = _encode(receipt).encode("utf-8")
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL
                     | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            if os.name == "nt":
                import msvcrt
                _check_windows_acl(None, handle=msvcrt.get_osfhandle(fd))
            else:
                info = os.fstat(fd)
                if info.st_mode & 0o077 or info.st_uid != os.getuid() or info.st_nlink != 1:
                    _deny()
            with os.fdopen(fd, "wb", closefd=False) as stream:
                stream.write(data)
                stream.flush()
                os.fsync(fd)
        finally:
            os.close(fd)
        # Never remove a partial/original artifact on failure or replay it.
        self.assert_current()
        if _read(path) != data:
            _deny()
        if os.name != "nt":
            directory_fd = os.open(self.output, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        return data

    def before_import(self):
        if self._begun or self.entry_bytes is not None or os.path.lexists(self.returned_path):
            _deny()
        self._begun = True
        if not self.audited:
            self.entry_bytes = self._write(self.entry_path, "entry-before-addon-import")

    def run_returned(self):
        if self.entry_bytes is None or _read(self.entry_path) != self.entry_bytes:
            _deny()
        self.returned_bytes = self._write(self.returned_path, "run-returned", {
            "path": str(self.entry_path), "sha256": _sha(self.entry_bytes)})

    def mark_scheduled(self):
        with self._state_lock:
            if not self.audited or not self._begun or self._scheduled or self._refused:
                _deny()
            self._scheduled = True
        self.assert_current()

    def refuse(self, reason):
        with self._state_lock:
            self._refused = str(reason)

    def begin_sdk_audit(self):
        with self._state_lock:
            if self._refused or not self._scheduled or self._audit_started:
                _deny()
            self._audit_started = True

    def assert_not_refused(self):
        with self._state_lock:
            if self._refused is not None:
                _deny()

    def assert_queued_entry(self):
        from ..fusion_bridge.dispatch import assert_startup_queue
        assert_startup_queue(self)
        self.assert_current()
        if (not self.audited or self.entry_bytes is None
                or _read(self.entry_path) != self.entry_bytes or self.audit_version is None):
            _deny()

    def assert_ready_for_listener(self):
        self.assert_current()
        if (not self.audited or self.entry_bytes is None or self.returned_bytes is None
                or _read(self.entry_path) != self.entry_bytes
                or _read(self.returned_path) != self.returned_bytes):
            _deny()

    def run_queued(self, context):
        from ..fusion_bridge.dispatch import assert_startup_queue
        from .startup_audit import collect_startup_audit
        assert_startup_queue(self)
        if not self.audited or not self._scheduled or self.entry_bytes is not None:
            _deny()
        audit = collect_startup_audit(self)
        if self.owned_autoload:
            self._qualify_owned_audit(audit)
        self.audit_version = audit["applicationVersion"]
        self.entry_bytes = self._write(
            self.entry_path, "entry-audited-before-addon-import", audit=audit)
        from .. import addon_runtime
        if addon_runtime.run(context, bootstrap=self) is not True:
            _deny()
        self.run_returned()

    def _qualify_owned_audit(self, audit):
        """Only the exact pinned fork may auto-start; no JSON grants authority."""
        own = []
        manifest = self.intent["installed"]["files"].get("AutodeskFusionMCP.manifest")
        if manifest is None:
            _deny()

        for row in audit["scripts"]["items"]:
            folder = _path(row["folder"])
            if folder == self.installed:
                if (not row["isAddIn"] or row["isRunOnStartup"] is not True
                        or row["isRunning"] is not True
                        or row["manifest"]["sha256"] != manifest):
                    _deny()
                own.append(row)
            elif (row["isRunning"] is not False
                    or (row["isAddIn"] and row["isRunOnStartup"] is not False)):
                _deny()
        if len(own) != 1:
            _deny()

    def admission_provision(self):
        """Return the bound original, never a second ambient provision read."""
        if not self.owned_autoload:
            _deny()
        self.assert_ready_for_listener()
        return decode_json(self.provision_bytes.decode("utf-8"))
