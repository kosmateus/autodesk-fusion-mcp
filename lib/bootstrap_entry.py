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


def _read(path):
    _directory(path.parent)
    return _read_private_bytes(path)


class BootstrapEntry:
    """One original intent, never resumable/replayable; no caller token API."""

    def __init__(self, intent_path, entry_file):
        self.intent_path = _path(intent_path)
        self.intent_bytes = _read(self.intent_path)
        self.intent = _exact(decode_json(self.intent_bytes.decode("utf-8")), (
            "kind", "version", "nonce", "process", "purpose", "engineVersion",
            "installed", "profile", "receipts"))
        intent = self.intent
        if (intent["kind"] != "fmcad-bootstrap-entry-intent"
                or type(intent["version"]) is not int or intent["version"] != 1
                or intent["purpose"] != "isolated-stdout-v1"
                or type(intent["engineVersion"]) is not int or intent["engineVersion"] != 2
                or type(intent["nonce"]) is not str
                or re.fullmatch("[0-9a-f]{32}", intent["nonce"]) is None):
            _deny()
        process = _exact(intent["process"], ("pid", "birth"))
        if type(process["pid"]) is not int or process["pid"] != os.getpid():
            _deny()
        _text(process["birth"])
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
        profile = _exact(intent["profile"], ("path", "sha256"))
        self.profile = _path(profile["path"])
        _digest(profile["sha256"])
        self.profile_bytes = _read(self.profile)
        if _sha(self.profile_bytes) != profile["sha256"]:
            _deny()
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
                or {self.entry_path, self.returned_path} & {self.intent_path, self.profile}):
            _deny()
        self.entry_bytes = None
        self.assert_current()
        if os.path.lexists(self.entry_path) or os.path.lexists(self.returned_path):
            _deny()

    def assert_current(self):
        intent = self.intent
        if (os.getpid() != intent["process"]["pid"]
                or observe_process_birth(os.getpid()) != intent["process"]["birth"]
                or _read(self.intent_path) != self.intent_bytes
                or _read(self.profile) != self.profile_bytes
                or _directory(self.output) != self.output_identity):
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

    def _write(self, path, phase, entry=None):
        self.assert_current()
        receipt = {
            "kind": "fmcad-bootstrap-entry-receipt",
            "version": 1,
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
        if self.entry_bytes is not None or os.path.lexists(self.returned_path):
            _deny()
        self.entry_bytes = self._write(self.entry_path, "entry-before-addon-import")

    def run_returned(self):
        if self.entry_bytes is None or _read(self.entry_path) != self.entry_bytes:
            _deny()
        self._write(self.returned_path, "run-returned", {
            "path": str(self.entry_path), "sha256": _sha(self.entry_bytes)})
