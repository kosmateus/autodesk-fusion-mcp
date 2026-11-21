"""Opt-in bootstrap for a provisioned, process-bound admission database."""

import os
from pathlib import Path
import sys

from ..lib.admission_http import AdmissionHTTP
from ..lib.admission_json import decode_json
from ..lib.admission_receiver import AdmissionReceiver
from ..lib.request_admission import AdmissionError, AdmissionStore
from .admission_document import select_operation


def process_birth():
    if sys.platform.startswith("linux"):
        stat = Path("/proc/self/stat").read_text()
        ticks = stat[stat.rindex(")") + 2:].split()[19]
        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        return f"{boot}:{ticks}"
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes

        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        kernel.GetProcessTimes.argtypes = [wintypes.HANDLE] + [
            ctypes.POINTER(wintypes.FILETIME)
        ] * 4
        kernel.GetProcessTimes.restype = wintypes.BOOL
        times = (wintypes.FILETIME * 4)()
        if not kernel.GetProcessTimes(kernel.GetCurrentProcess(), *times):
            raise ctypes.WinError(ctypes.get_last_error())
        return str((times[0].dwHighDateTime << 32) | times[0].dwLowDateTime)
    raise AdmissionError("Admission process identity is unsupported on this platform")


def _lease(database):
    # The provisioner supplies a private local directory and canonical path.
    # Never unlink the sidecar: contenders must lock the very same file.
    fd = os.open(str(database) + ".lease", os.O_CREAT | os.O_RDWR, 0o600)
    try:
        if sys.platform == "win32":
            import msvcrt
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fd
    except BaseException:
        os.close(fd)
        raise


class AdmissionRuntime:
    def __init__(self, provision, dispatch):
        fields = {"database", "pid", "birth", "instance", "epoch", "source",
                  "build", "credentials"}
        if (not isinstance(provision, dict) or set(provision) != fields
                or any(not isinstance(provision[k], str) or not provision[k]
                       for k in fields - {"pid", "credentials"})):
            raise AdmissionError("Invalid admission provision")
        AdmissionHTTP.validate_credentials(provision["credentials"])
        if type(provision["pid"]) is not int or (
            provision["pid"], provision["birth"]
        ) != (os.getpid(), process_birth()):
            raise AdmissionError("Admission provision is not bound to this process")
        database = Path(provision["database"])
        if not database.is_absolute():
            raise AdmissionError("Admission database must use an absolute local path")
        database = database.resolve()
        self._lease = _lease(database)
        self._store = None
        try:
            self._store = AdmissionStore(database, instance=provision["instance"],
                                         epoch=provision["epoch"], create=False)
            receiver = AdmissionReceiver(
                self._store, source=provision["source"], build=provision["build"],
                select_operation=select_operation,
            )
            self.http = AdmissionHTTP(receiver, dispatch, credentials=provision["credentials"])
        except BaseException:
            self.close()
            raise

    @classmethod
    def from_environment(cls, dispatch):
        path = os.environ.get("FUSION_MCP_ADMISSION_PROVISION")
        if path is None:
            return None
        provision_path = Path(path)
        if not provision_path.is_absolute():
            raise AdmissionError("Admission provision must use an absolute local path")
        return cls(decode_json(provision_path.read_text(encoding="utf-8")), dispatch)

    def advance_generation(self, *, instance, epoch):
        self._store.advance_generation(instance=instance, epoch=epoch)

    def close(self):
        if self._store is not None:
            self._store.close()
        os.close(self._lease)
