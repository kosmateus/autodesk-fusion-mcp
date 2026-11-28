"""Automatic private admission for an ordinary add-in start; no SDK imports."""

from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
import sys

from . import physical_authority
from .physical_authority import private_directory, read_private, publish_private, write_private
from .request_admission import AdmissionError, AdmissionStore
from .rebaseline_fence import observe_process_birth


KIND = "fmcad-normal-native-runtime"
PRINCIPAL = "fmcad-normal-broker"


def _source():
    root = Path(__file__).resolve().parents[1]
    files = sorted(
        file for folder in ("lib", "fusion_bridge") for file in (root / folder).rglob("*.py")
        if "__pycache__" not in file.parts
    )
    files += sorted(root.glob("*.py"))
    value = hashlib.sha256()
    for file in files:
        value.update(str(file.relative_to(root)).replace("\\", "/").encode("utf-8") + b"\0")
        value.update(hashlib.sha256(file.read_bytes()).digest())
    return str(root), value.hexdigest()


def _handoff(provision):
    return "normal-start-" + provision["instance"] + "-" + provision["epoch"]


def _descriptor(provision, version, endpoint):
    return dict(
        handoffId=_handoff(provision),
        generation=dict(instance=provision["instance"], epoch=provision["epoch"]),
        endpointURL=endpoint,
        physicalRuntime=dict(
            pid=provision["pid"], birth=provision["birth"], version=version,
            source=provision["source"], build=provision["build"],
        ),
    )


def _load(directory, config=None):
    if config is None:
        config = read_private(directory / "normal-runtime.json")
    if (not isinstance(config, dict) or set(config) != {
            "kind", "version", "provisionPath", "installedForkDirectory",
            "nativePrivateDirectory", "descriptor",
    } or config["kind"] != KIND or type(config["version"]) is not int or config["version"] != 1):
        raise AdmissionError("Normal native runtime discovery is invalid")
    path = Path(config["provisionPath"])
    if (not path.is_absolute() or path.resolve() != path
            or path.parent != directory / "normal-provisions"):
        raise AdmissionError("Normal native provision path changed")
    provision = read_private(path)
    if (not isinstance(provision, dict) or set(provision) != {
            "database", "pid", "birth", "instance", "epoch", "source", "build", "credentials",
    } or provision["database"] != str(directory / "normal-admissions.sqlite")):
        raise AdmissionError("Normal native provision binding changed")
    runtime = config["descriptor"]["physicalRuntime"]
    if config["descriptor"] != _descriptor(provision, runtime["version"], config["descriptor"]["endpointURL"]):
        raise AdmissionError("Normal native discovery pins changed")
    # Read historical v1 snapshots across an ordinary process restart. Discovery
    # and all newly created configurations accept only the usable sibling path.
    if config["nativePrivateDirectory"] not in (
            str(directory.parent / "clients"), str(directory / "clients")):
        raise AdmissionError("Normal native client namespace changed")
    if config["nativePrivateDirectory"] == str(directory / "clients"):
        snapshot = directory / "normal-runtimes" / (provision["instance"] + ".json")
        if read_private(snapshot) != config:
            raise AdmissionError("Historical normal native client namespace is unproven")
    return config, provision


def _alive(provision):
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel.WaitForSingleObject.restype = wintypes.DWORD
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        process = kernel.OpenProcess(0x1000 | 0x100000, False, provision["pid"])
        if not process:
            if ctypes.get_last_error() == 87:  # ERROR_INVALID_PARAMETER: PID absent.
                return False
            raise AdmissionError("Previous normal native process is unobservable")
        try:
            status = kernel.WaitForSingleObject(process, 0)
            if status == 0:
                return False
            if status != 258:
                raise AdmissionError("Previous normal native process is unobservable")
            return observe_process_birth(provision["pid"]) == provision["birth"]
        finally:
            kernel.CloseHandle(process)
    try:
        return observe_process_birth(provision["pid"]) == provision["birth"]
    except (FileNotFoundError, ProcessLookupError):
        return False
    except OSError:
        # Never turn permission failures into a dead-owner proof.
        raise AdmissionError("Previous normal native process is unobservable") from None


def _recover_starting(directory):
    journal = directory / "normal-starting.json"
    try:
        record = read_private(journal)
    except FileNotFoundError:
        return
    if (not isinstance(record, dict) or set(record) != {"config", "previous"}
            or not isinstance(record["config"], dict)):
        raise AdmissionError("Normal native startup record changed")
    config, provision = _load(directory, record["config"])
    snapshot = directory / "normal-runtimes" / (provision["instance"] + ".json")
    if read_private(snapshot) != config:
        raise AdmissionError("Normal native startup snapshot changed")
    if ((provision["pid"], provision["birth"]) != (os.getpid(), observe_process_birth(os.getpid()))
            and _alive(provision)):
        raise AdmissionError("Another normal native startup is still alive")
    previous = None
    if record["previous"] is not None:
        _, previous = _load(directory, record["previous"])
    current_file = directory / "normal-runtime.json"
    if current_file.exists() and read_private(current_file) not in (config, record["previous"]):
        raise AdmissionError("Normal native discovery changed during interrupted startup")
    database = Path(provision["database"])
    if not database.exists():
        if previous is not None:
            raise AdmissionError("Existing normal native database disappeared")
        fd = os.open(database, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        os.close(fd)
    # A crash may leave either an empty file, the first admissions table, or a
    # committed generation. Never reset/adopt unrelated tables or a foreign head.
    with closing(sqlite3.connect(database.as_uri() + "?mode=rw", uri=True)) as db:
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        generation = (db.execute("SELECT instance,epoch FROM generation WHERE singleton=1").fetchone()
                      if "generation" in tables else None)
        if generation is None:
            if (previous is not None or tables - {"admissions"} or
                    ("admissions" in tables and db.execute("SELECT 1 FROM admissions LIMIT 1").fetchone())):
                raise AdmissionError("Normal native initialization does not own this database")
        elif generation == (provision["instance"], provision["epoch"]):
            pass
        elif previous is not None and generation == (previous["instance"], previous["epoch"]):
            # The intended transition did not commit. Keep the original
            # projection; the ordinary start will prepare its own fresh attempt.
            config = record["previous"]
        else:
            raise AdmissionError("Interrupted normal startup lost its generation")
    if generation is None:
        with AdmissionStore(database, instance=provision["instance"], epoch=provision["epoch"]):
            pass
    private_directory(directory.parent / "clients")
    write_private(current_file, config)
    if read_private(journal) != record:
        raise AdmissionError("Normal native startup record changed during recovery")
    journal.unlink()


def create_runtime(runtime_class, dispatch, *, shutdown=None, version="unknown",
                   endpoint="http://127.0.0.1:8765/mcp"):
    # Import only on the add-in's ordinary start, not on public discovery.
    from ..fusion_bridge.admission_runtime import _lease
    directory = private_directory(physical_authority.authority_directory()).resolve()
    control = _lease(directory / "normal-startup")
    result = None
    try:
        installed, source = _source()
        database = directory / "normal-admissions.sqlite"
        config_file = directory / "normal-runtime.json"
        previous = None
        previous_config = None
        _recover_starting(directory)
        if config_file.exists():
            config, previous = _load(directory)
            previous_config = config
            if (previous["pid"], previous["birth"]) == (os.getpid(), observe_process_birth(os.getpid())):
                if (previous["source"] != source or previous["build"] != source
                        or config["descriptor"] != _descriptor(previous, version, endpoint)
                        or config["installedForkDirectory"] != installed
                        or config["nativePrivateDirectory"] != str(directory.parent / "clients")):
                    raise AdmissionError("Running normal native source or endpoint changed")
                return runtime_class(previous, dispatch, shutdown=shutdown, version=version, endpoint=endpoint)
            if _alive(previous):
                raise AdmissionError("Another normal native runtime is still alive")
        elif database.exists():
            raise AdmissionError("Existing normal native store has no proven startup record")

        provision = dict(
            database=str(database), pid=os.getpid(), birth=observe_process_birth(os.getpid()),
            instance=secrets.token_hex(16), epoch=secrets.token_hex(16),
            source=source, build=source, credentials={secrets.token_urlsafe(48): PRINCIPAL},
        )
        provisions = private_directory(directory / "normal-provisions")
        provision_path = provisions / (provision["instance"] + ".json")
        publish_private(provision_path, provision)
        config = dict(
            kind=KIND, version=1, provisionPath=str(provision_path),
            installedForkDirectory=installed, nativePrivateDirectory=str(directory.parent / "clients"),
            descriptor=_descriptor(provision, version, endpoint),
        )
        snapshots = private_directory(directory / "normal-runtimes")
        publish_private(snapshots / (provision["instance"] + ".json"), config)
        # Durable ownership of this preparation must precede the first DB
        # creation/change. Discovery is still published only after authority.
        starting = directory / "normal-starting.json"
        write_private(starting, dict(config=config, previous=previous_config))
        if previous is None:
            fd = os.open(database, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
            os.close(fd)
            with AdmissionStore(database, instance=provision["instance"], epoch=provision["epoch"]):
                pass
        else:
            # The prior native process is kernel-dead. Keep every original row,
            # including UNKNOWN. Existing consumed-root handoff guards still run.
            lease = _lease(database)
            try:
                with AdmissionStore(database, instance=previous["instance"],
                                    epoch=previous["epoch"], create=False) as store:
                    store.advance_generation(instance=provision["instance"], epoch=provision["epoch"],
                                             handoff_id=_handoff(provision))
            finally:
                os.close(lease)
        private_directory(directory.parent / "clients")
        result = runtime_class(provision, dispatch, shutdown=shutdown, version=version, endpoint=endpoint)
        # Preserve each process's original configuration; only the discovery
        # projection changes. No original provision, receipt or history is reset.
        write_private(config_file, config)
        starting.unlink()
        return result
    except BaseException:
        if result is not None:
            result.close()
        raise
    finally:
        os.close(control)


def discover():
    directory = physical_authority.authority_directory().resolve()
    config, provision = _load(directory)
    if config["nativePrivateDirectory"] != str(directory.parent / "clients"):
        raise AdmissionError("Normal native client output namespace requires restart")
    installed, source = _source()
    if (not _alive(provision) or config["installedForkDirectory"] != installed
            or provision["source"] != source or provision["build"] != source):
        raise AdmissionError("Normal native runtime is no longer current")
    if read_private(directory / "database.json") != dict(database=provision["database"]):
        raise AdmissionError("Normal native authority database changed")
    with closing(sqlite3.connect(Path(provision["database"]).as_uri() + "?mode=ro", uri=True)) as db:
        db.execute("BEGIN")
        if db.execute("SELECT instance,epoch FROM generation WHERE singleton=1").fetchone() != (
                provision["instance"], provision["epoch"]):
            raise AdmissionError("Normal native generation changed")
        row = db.execute("SELECT binding FROM physical_runtime_binding WHERE singleton=1").fetchone()
        binding = json.loads(row[0]) if row else {}
        identity = Path(provision["database"]).stat()
        if binding.get("database") != dict(
                path=provision["database"], device=identity.st_dev, inode=identity.st_ino):
            raise AdmissionError("Normal native database identity changed")
        if any(binding.get(key) != config["descriptor"][key] for key in (
                "generation", "physicalRuntime", "endpointURL")):
            raise AdmissionError("Normal native runtime binding changed")
    return config
