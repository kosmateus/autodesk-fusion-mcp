"""Private, host-global physical ownership. No SDK imports or public API."""

import copy
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import secrets
import stat
import sys
import threading

from .request_admission import AdmissionError


HEADER = "X-Fmcad-Physical-Grant"
TURN_HEADER = "X-Fmcad-Physical-Turn"
TARGET_HEADER = "X-Fmcad-Physical-Target"


def authority_directory():
    if sys.platform == "win32":
        return Path(os.environ["LOCALAPPDATA"]) / "AutodeskFusionMCP" / "physical"
    return Path.home() / ".local" / "state" / "autodesk-fusion-mcp" / "physical"


def _validate_windows_private_acl(owner, current, allowed_principals):
    trusted = {current, "S-1-5-18", "S-1-5-32-544"}
    # Elevated Windows processes create files owned by Administrators rather
    # than their TokenUser SID. These privileged principals already control
    # process memory; accepting their ownership does not authorize other users.
    # CPython's Windows mkdir(0o700) uses OW (OWNER RIGHTS, S-1-3-4)
    # rather than an explicit user ACE. OW grants only the already-checked
    # object's owner, never an arbitrary other user.
    if owner not in trusted or any(
        principal not in trusted and principal != "S-1-3-4"
        for principal in allowed_principals
    ):
        raise AdmissionError("Private Windows owner and DACL required")


def _check_windows_acl(path):
    """Fail closed on public/inherited ACLs, including nonstandard allow ACEs."""
    if os.name != "nt":
        return
    import ctypes
    from ctypes import wintypes

    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD,
                                       ctypes.POINTER(wintypes.HANDLE)]
    advapi.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
                                          wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    advapi.GetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR, ctypes.c_int, wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    advapi.GetAce.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]

    def sid_string(sid):
        text = wintypes.LPWSTR()
        if not advapi.ConvertSidToStringSidW(sid, ctypes.byref(text)):
            raise AdmissionError("Cannot validate private Windows SID")
        try:
            return text.value
        finally:
            kernel.LocalFree(ctypes.cast(text, ctypes.c_void_p))

    token = wintypes.HANDLE()
    if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token)):
        raise AdmissionError("Cannot validate private Windows token")
    try:
        size = wintypes.DWORD()
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
        data = ctypes.create_string_buffer(size.value)
        if not advapi.GetTokenInformation(token, 1, data, size, ctypes.byref(size)):
            raise AdmissionError("Cannot validate private Windows owner")
        current = sid_string(ctypes.cast(data, ctypes.POINTER(ctypes.c_void_p))[0])
    finally:
        kernel.CloseHandle(token)
    owner, dacl, descriptor = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
    if advapi.GetNamedSecurityInfoW(str(path), 1, 5, ctypes.byref(owner), None,
                                   ctypes.byref(dacl), None, ctypes.byref(descriptor)):
        raise AdmissionError("Cannot validate private Windows ACL")
    try:
        if not dacl.value:
            raise AdmissionError("Private Windows DACL required")
        # ACL header: BYTE revision, BYTE reserved, WORD size, WORD ACE count.
        count = ctypes.cast(dacl.value + 4, ctypes.POINTER(wintypes.WORD))[0]
        allowed_principals = []
        for index in range(count):
            ace = ctypes.c_void_p()
            if not advapi.GetAce(dacl, index, ctypes.byref(ace)):
                raise AdmissionError("Cannot validate private Windows ACE")
            ace_type = ctypes.cast(ace, ctypes.POINTER(ctypes.c_ubyte))[0]
            ace_flags = ctypes.cast(ace, ctypes.POINTER(ctypes.c_ubyte))[1]
            if ace_flags & 0x08:  # INHERIT_ONLY: not effective on this object.
                continue
            if ace_type == 1:  # A deny ACE cannot expose private data.
                continue
            if ace_type != 0:
                raise AdmissionError("Unsupported private Windows allow ACE")
            allowed_principals.append(sid_string(ace.value + 8))
        _validate_windows_private_acl(sid_string(owner), current, allowed_principals)
    finally:
        kernel.LocalFree(descriptor)


def private_directory(path):
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400 or (
        os.name != "nt" and (info.st_uid != os.getuid() or info.st_mode & 0o077)
    ):
        raise AdmissionError("Physical authority requires a private real directory")
    _check_windows_acl(path)
    return path


def read_private(path):
    return json.loads(_read_private_bytes(path).decode("utf-8"))


def _read_private_bytes(path):
    """No symlink following; validate the opened inode rather than a prior stat."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or (
            os.name != "nt" and (info.st_uid != os.getuid() or info.st_mode & 0o077)
        ) or Path(path).is_symlink():
            raise AdmissionError("A private regular file is required")
        _check_windows_acl(path)
        with os.fdopen(fd, "rb", closefd=False) as stream:
            return stream.read()
    finally:
        os.close(fd)


def write_private(path, value):
    _write_private(path, value, replace=True)


def publish_private(path, value):
    """Atomically publish without replacing any inode, including symlinks."""
    _write_private(path, value, replace=False)


def _write_private(path, value, *, replace):
    path = Path(path)
    private_directory(path.parent)
    temporary = path.parent / (".write-" + secrets.token_hex(16))
    fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        # An effectively private parent may still grant public access through
        # INHERIT_ONLY ACEs. Validate the empty child before writing any secret.
        _check_windows_acl(temporary)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            fd = None  # fdopen owns the descriptor from this point.
            json.dump(value, stream, sort_keys=True, allow_nan=False)
            stream.flush()
            os.fsync(stream.fileno())
        if replace:
            os.replace(temporary, path)
        else:
            os.link(temporary, path)
        if os.name != "nt":
            directory_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        if fd is not None:
            os.close(fd)
        if temporary.exists():
            temporary.unlink()


def _canonical_broker_queue(value):
    """Lexical broker namespace validation, never receiver-host resolution."""
    if not isinstance(value, str) or not value or "\0" in value:
        return False
    if value.startswith("/"):
        path = PurePosixPath(value)
        return (not value.startswith("//") and path.is_absolute()
                and str(path) == value and ".." not in path.parts)
    path = PureWindowsPath(value)
    return (path.is_absolute() and str(path) == value and ".." not in path.parts)


class PhysicalCapability:
    """Unforgeable local object; never decoded from a request body."""

    def __init__(self, authority, token):
        self._authority = authority
        self._token = token

    def validate(self):
        self._authority.authenticate([self._token])

    def prepare_turn(self, turn_id, target):
        self.validate()
        return self._authority.prepare_turn(self, turn_id, target)


class PhysicalTurn:
    """Durable single-use dispatch claim, separate from a job's outcome."""

    def __init__(self, capability, binding):
        self.capability = capability
        self.binding = binding

    def start(self):
        self.capability.validate()
        self.capability._authority._store.start_physical_turn(self.binding)

    def finish(self):
        self.capability._authority._store.release_physical_turn(self.binding)

    def cancel_queued(self):
        self.capability._authority._store.release_physical_turn(self.binding, queued_only=True)


class PhysicalAuthority:
    def __init__(self, provision, store, acquire_lease, *, version, endpoint):
        self._lock = threading.RLock()
        self._lease = None
        self._store = store
        self._grant = None
        self._revoked = False
        self.directory = private_directory(authority_directory())
        self.database = Path(provision["database"]).resolve()
        self._pins = dict(
            generation=dict(instance=provision["instance"], epoch=provision["epoch"]),
            endpointURL=endpoint,
            physicalRuntime=dict(pid=provision["pid"], birth=provision["birth"],
                                 version=version, source=provision["source"],
                                 build=provision["build"]),
        )
        try:
            self._lease = acquire_lease(self.directory / "authority")
            self._lease_identity = os.fstat(self._lease)
            binding_path = self.directory / "database.json"
            binding = dict(database=str(Path(provision["database"]).resolve()))
            if binding_path.exists():
                if read_private(binding_path) != binding:
                    raise AdmissionError("Host physical authority is bound to another database")
            else:
                write_private(binding_path, binding)
        except BaseException:
            self.close()
            raise

    def issue(self, descriptor):
        if (not isinstance(descriptor, dict) or set(descriptor) != {
            "kind", "version", "handoffId", "generation", "brokerOwner",
            "endpointURL", "physicalRuntime",
        } or descriptor["kind"] != "fmcad-physical-grant"
                or type(descriptor["version"]) is not int or descriptor["version"] != 1
                or not isinstance(descriptor["handoffId"], str) or not descriptor["handoffId"]
                or any(descriptor[k] != v for k, v in self._pins.items())):
            raise AdmissionError("Physical grant pins do not match this runtime")
        owner = descriptor["brokerOwner"]
        if (not isinstance(owner, dict) or set(owner) != {
            "pid", "birth", "nonce", "clientId", "queueDirectory",
        } or type(owner["pid"]) is not int or owner["pid"] <= 0
                or any(not isinstance(owner[k], str) or not owner[k] for k in owner.keys() - {"pid"})
                or not _canonical_broker_queue(owner["queueDirectory"])):
            raise AdmissionError("Exact physical broker owner is required")
        with self._lock:
            if self._lease is None or self._revoked:
                raise AdmissionError("Physical authority is retired")
            self._store.bind_physical_owner(descriptor)
            if self._grant is None:
                self._grant = copy.deepcopy(descriptor)
                self._grant["token"] = secrets.token_urlsafe(48)
            return copy.deepcopy(self._grant)

    def publish_grant(self, descriptor, output):
        output = Path(output)
        if not output.is_absolute():
            raise AdmissionError("An absolute private grant output is required")
        canonical = output.resolve()
        protected = {Path(str(self.database) + suffix) for suffix in (
            "", ".lease", "-wal", "-shm", "-journal",
        )}
        if (canonical in protected or canonical == self.directory.resolve()
                or self.directory.resolve() in canonical.parents):
            raise AdmissionError("Grant output cannot name lifecycle, database or lease files")
        private_directory(output.parent)
        with self._lock:
            # Check existing data before binding an owner. A raced publication
            # is still protected by the hard-link no-replace commit below.
            if os.path.lexists(output):
                if self._grant is None or _read_private_bytes(output) != json.dumps(
                    self._grant, sort_keys=True, allow_nan=False,
                ).encode("utf-8"):
                    raise AdmissionError("Grant output already contains another file")
            grant = self.issue(descriptor)
            try:
                publish_private(output, grant)
            except FileExistsError:
                if _read_private_bytes(output) != json.dumps(
                    grant, sort_keys=True, allow_nan=False,
                ).encode("utf-8"):
                    raise AdmissionError("Grant output publication lost a race") from None
            return grant

    def authenticate(self, values):
        with self._lock:
            if (self._lease is None or self._revoked or self._grant is None
                    or len(values) != 1 or not isinstance(values[0], str)
                    or not values[0].isascii()
                    or not hmac.compare_digest(values[0], self._grant["token"])):
                raise PermissionError("Current physical grant required")
            try:
                os.fstat(self._lease)
                current = (self.directory / "authority.lease").lstat()
                if (current.st_dev, current.st_ino) != (
                    self._lease_identity.st_dev, self._lease_identity.st_ino,
                ):
                    raise OSError("Physical lease path changed")
                self._store.assert_current_generation()
            except (OSError, AdmissionError):
                self._revoked = True
                raise PermissionError("Physical authority fence lost") from None
            return PhysicalCapability(self, values[0])

    def _turn_binding(self, turn_id, target):
        if (not isinstance(turn_id, str) or not turn_id or len(turn_id) > 256
                or not turn_id.isascii() or not isinstance(target, str)
                or not target or len(target.encode("utf-8")) > 16384):
            raise AdmissionError("Exact physical turn ID and document target required")
        return dict(version=1, grantDigest=hashlib.sha256(json.dumps(
            self._grant, sort_keys=True, allow_nan=False,
        ).encode("utf-8")).hexdigest(), turnId=turn_id, target=target,
                    generation=copy.deepcopy(self._pins["generation"]),
                    physicalRuntime=copy.deepcopy(self._pins["physicalRuntime"]))

    def prepare_turn(self, capability, turn_id, target):
        with self._lock:
            capability.validate()
            if capability._authority is not self:
                raise PermissionError("Foreign physical capability")
            binding = self._turn_binding(turn_id, target)
            self._store.prepare_physical_turn(binding)
            return PhysicalTurn(capability, binding)

    @staticmethod
    def turn_headers(headers):
        ids, targets = headers.get_all(TURN_HEADER, []), headers.get_all(TARGET_HEADER, [])
        if len(ids) != 1 or len(targets) != 1:
            raise AdmissionError("Exact private turn headers required")
        try:
            encoded = targets[0]
            target = base64.b64decode(encoded + "=" * (-len(encoded) % 4),
                                      altchars=b"-_", validate=True).decode("utf-8")
            if base64.urlsafe_b64encode(target.encode("utf-8")).decode().rstrip("=") != encoded:
                raise ValueError("Noncanonical target header")
        except (ValueError, UnicodeError):
            raise AdmissionError("Invalid private document target header") from None
        return ids[0], target

    def turn_from_headers(self, capability, headers):
        turn_id, target = self.turn_headers(headers)
        return capability.prepare_turn(turn_id, target)

    def turn_status(self, binding):
        with self._lock:
            if not isinstance(binding, dict) or set(binding) != {
                "version", "grantDigest", "generation", "physicalRuntime", "turnId", "target",
            } or type(binding["version"]) is not int or binding["version"] != 1:
                raise AdmissionError("Exact private physical turn binding required")
            expected = self._turn_binding(binding["turnId"], binding["target"])
            if binding != expected:
                return dict(state="unknown", binding=binding)
            return self._store.physical_turn_status(binding)

    def revoke(self):
        with self._lock:
            self._revoked = True

    def close(self):
        with self._lock:
            self._revoked = True
            if self._lease is not None:
                os.close(self._lease)
                self._lease = None
