"""Private administrative provision fence CLI. No SDK or public MCP entry."""

import argparse
import hashlib
import hmac
import json
from pathlib import Path, PurePosixPath
import sys

from .admission_json import decode_json
from .physical_authority import _read_private_bytes, private_directory, _canonical_broker_queue
from .request_admission import AdmissionError, AdmissionStore, _encode
from . import rebaseline_fence_store


def _exact(value, fields):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise AdmissionError("Exact private rebaseline fields required")
    return value


def _text(value):
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 65536:
        raise AdmissionError("Nonempty strict UTF-8 text required")
    return value


def _hash(value):
    if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise AdmissionError("Lowercase SHA-256 required")
    return value


def _request_id(value):
    _text(value)
    if len(value) > 128 or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for c in value):
        raise AdmissionError("Invalid rebaseline request ID")
    return value


def _reference(value):
    _exact(value, ("path", "sha256"))
    _text(value["path"])
    if not _canonical_broker_queue(value["path"]):
        raise AdmissionError("Canonical immutable reference path required")
    _hash(value["sha256"])
    return value


def _store_identity(value):
    _exact(value, ("path", "device", "inode"))
    path = _text(value["path"])
    pure = PurePosixPath(path)
    if (not pure.is_absolute() or path.startswith("//") or str(pure) != path or ".." in pure.parts
            or any(type(value[key]) is not int or not 0 <= value[key] <= 9007199254740991
                   for key in ("device", "inode"))):
        raise AdmissionError("Exact POSIX store identity required")
    return value


def _runtime(value):
    _exact(value, ("handoffId", "generation", "physicalRuntime", "endpointURL"))
    _text(value["handoffId"])
    _exact(value["generation"], ("instance", "epoch"))
    for item in value["generation"].values():
        _text(item)
    physical = _exact(value["physicalRuntime"], ("pid", "birth", "version", "source", "build"))
    if type(physical["pid"]) is not int or physical["pid"] <= 0:
        raise AdmissionError("Exact physical process identity required")
    for key in ("birth", "version", "source", "build"):
        _text(physical[key])
    _text(value["endpointURL"])
    return value


def observe_process_birth(pid):
    """Read-only process observation; never imports or probes Fusion SDK."""
    if type(pid) is not int or pid <= 0:
        raise AdmissionError("Invalid process identity")
    if sys.platform.startswith("linux"):
        raw = Path(f"/proc/{pid}/stat").read_text()
        fields = raw[raw.rindex(")") + 2:].split()
        if fields[0] == "Z":
            raise AdmissionError("Physical process is not running")
        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        return f"{boot}:{fields[19]}"
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        process = kernel.OpenProcess(0x1000, False, pid)  # QUERY_LIMITED_INFORMATION
        if not process:
            raise AdmissionError("Physical process observation failed")
        try:
            times = (wintypes.FILETIME * 4)()
            if not kernel.GetProcessTimes(process, *times) or (
                times[1].dwHighDateTime or times[1].dwLowDateTime
            ):
                raise AdmissionError("Physical process is not running")
            return str((times[0].dwHighDateTime << 32) | times[0].dwLowDateTime)
        finally:
            kernel.CloseHandle(process)
    if sys.platform == "darwin":
        import ctypes
        class BSDInfo(ctypes.Structure):
            _fields_ = [("prefix", ctypes.c_uint32 * 12), ("comm", ctypes.c_char * 16),
                        ("name", ctypes.c_char * 32), ("fields", ctypes.c_uint32 * 6),
                        ("seconds", ctypes.c_uint64), ("microseconds", ctypes.c_uint64)]
        library = ctypes.CDLL("/usr/lib/libproc.dylib")
        library.proc_pidinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64,
                                         ctypes.c_void_p, ctypes.c_int]
        info = BSDInfo()
        if (library.proc_pidinfo(pid, 3, 0, ctypes.byref(info), ctypes.sizeof(info)) != ctypes.sizeof(info)
                or info.prefix[3] != pid or not info.seconds):
            raise AdmissionError("Physical process observation failed")
        return f"{info.seconds}:{info.microseconds}"
    raise AdmissionError("Physical process observation is unsupported")


class OperatorAuthority:
    """Only the private OS-validated administrative carrier constructs this."""

    def __init__(self, profile):
        _exact(profile, ("kind", "version", "operatorId", "database", "runtime", "publicationVerifier"))
        if profile["kind"] != "fmcad-rebaseline-operator" or type(profile["version"]) is not int or profile["version"] != 1:
            raise AdmissionError("Private administrative capability required")
        self.operator_id = _text(profile["operatorId"])
        database = Path(_text(profile["database"]))
        if not database.is_absolute() or database.is_symlink():
            raise AdmissionError("Canonical native AdmissionStore path required")
        self.database = database.resolve()
        self.runtime = _runtime(profile["runtime"])
        verifier = _exact(profile["publicationVerifier"], ("keyId", "keyHex"))
        self.key_id = _text(verifier["keyId"])
        self._key = bytes.fromhex(_hash(verifier["keyHex"]))
        self.key_digest = hashlib.sha256(self._key).hexdigest()

    @classmethod
    def from_private_file(cls, path):
        path = Path(path)
        if not path.is_absolute() or path.resolve() != path:
            raise AdmissionError("Canonical private administrative carrier path required")
        private_directory(path.parent)
        return cls(decode_json(_read_private_bytes(path).decode("utf-8")))

    def verify_process(self):
        physical = self.runtime["physicalRuntime"]
        try:
            actual = observe_process_birth(physical["pid"])
        except (OSError, ValueError):
            raise AdmissionError("Physical process observation failed") from None
        if actual != physical["birth"]:
            raise AdmissionError("Physical PID/birth changed")

    def receipt_mac(self, receipt_json):
        return hmac.new(self._key, b"fmcad-native-consume-v1\0" + receipt_json.encode("utf-8"),
                        hashlib.sha256).hexdigest()

    def verify_publication(self, binding, request):
        _exact(request, ("requestId", "fenceNonce", "publicationJson", "attestation"))
        if (request["requestId"] != binding["requestId"] or request["fenceNonce"] != binding["fenceNonce"]):
            raise AdmissionError("Publication belongs to another durable fence")
        raw = _text(request["publicationJson"])
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        attestation = _exact(request["attestation"], ("keyId", "mac"))
        if attestation["keyId"] != self.key_id:
            raise AdmissionError("Wrong POSIX publication verifier")
        expected = hmac.new(self._key, b"fmcad-posix-publication-v1\0" + _encode(dict(
            binding=binding, publicationDigest=digest,
        )).encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(_hash(attestation["mac"]), expected):
            raise AdmissionError("Authenticated POSIX publication bytes required")
        publication = _exact(decode_json(raw), (
            "store", "storeDevice", "storeInode", "expectedHead", "expectedFiles",
            "activationFile", "activationBytes", "record",
        ))
        expected_store = binding["store"]
        if (publication["store"] != expected_store["path"]
                or type(publication["storeDevice"]) is not int
                or type(publication["storeInode"]) is not int
                or publication["storeDevice"] != expected_store["device"]
                or publication["storeInode"] != expected_store["inode"]
                or publication["expectedHead"] != binding["oldHead"]
                or publication["activationFile"] != expected_store["path"] + "/runtime-rebaseline-head.json"):
            raise AdmissionError("POSIX publication store/head mismatch")
        record = _reference(publication["record"])
        if record["path"] != expected_store["path"] + "/runtime-rebaselines/" + binding["requestId"] + "/record.json":
            raise AdmissionError("Immutable rebaseline record reference mismatch")
        pointer = _exact(decode_json(_text(publication["activationBytes"])), ("version", "newHead", "record"))
        if type(pointer["version"]) is not int or pointer["version"] != 1 or pointer["record"] != record:
            raise AdmissionError("Published activation pointer/reference mismatch")
        _hash(pointer["newHead"])
        files = publication["expectedFiles"]
        if not isinstance(files, dict) or set(files) != {
            "physical-backend-head.json", "isolated-admission-epoch.json",
            "instance.json", "queue-state.json", "runtime-rebaseline-head.json",
        }:
            raise AdmissionError("Exact immutable activation inputs required")
        for value in files.values():
            if value is not None:
                _hash(value)
        return dict(newHead=pointer["newHead"], digest=digest, record=record)


def begin_fence(authority, request):
    _exact(request, ("requestId", "handoffId", "expectedHead", "store", "intentReferences",
                     "writerGeneration"))
    if request["handoffId"] != authority.runtime["handoffId"]:
        raise AdmissionError("Rebaseline handoff mismatch")
    references = request["intentReferences"]
    if not isinstance(references, list) or not references or len(references) > 128:
        raise AdmissionError("Immutable intent references required")
    for reference in references:
        _reference(reference)
    if len({reference["path"] for reference in references}) != len(references):
        raise AdmissionError("Duplicate intent reference")
    facts = dict(
        requestId=_request_id(request["requestId"]), handoffId=request["handoffId"],
        writerGeneration=_text(request["writerGeneration"]),
        oldHead=_hash(request["expectedHead"]), store=_store_identity(request["store"]),
        intentReferences=references,
        **{key: authority.runtime[key] for key in ("generation", "physicalRuntime", "endpointURL")},
    )
    return _with_store(authority, lambda store: rebaseline_fence_store.begin(store, facts, authority))


def query_fence(authority, request):
    _exact(request, ("requestId",))
    request_id = _request_id(request["requestId"])
    return _with_store(authority, lambda store: rebaseline_fence_store.query(store, request_id, authority))


def consume_fence(authority, request):
    _exact(request, ("requestId", "fenceNonce", "publicationJson", "attestation"))
    _request_id(request["requestId"])
    return _with_store(authority, lambda store: rebaseline_fence_store.consume(store, request, authority))


def _with_store(authority, operation):
    generation = authority.runtime["generation"]
    with AdmissionStore(authority.database, instance=generation["instance"],
                        epoch=generation["epoch"], create=False) as store:
        return operation(store)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("begin", "query", "consume"))
    parser.add_argument("--operator-file", required=True)
    parser.add_argument("--request", required=True)
    args = parser.parse_args(argv)
    try:
        authority = OperatorAuthority.from_private_file(Path(args.operator_file))
        request = decode_json(_read_private_bytes(Path(args.request)).decode("utf-8"))
        operation = dict(begin=begin_fence, query=query_fence, consume=consume_fence)[args.action]
        result = operation(authority, request)
    except Exception:
        # Never leak private carrier/key/request bytes through tracebacks.
        print(json.dumps(dict(state="refused", error="Private rebaseline authority or binding refused")))
        return 1
    print(json.dumps(result, sort_keys=True, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
