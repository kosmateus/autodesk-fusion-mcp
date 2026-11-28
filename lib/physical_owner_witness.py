"""Fixed read-only kernel witness for a consumed root's normal broker restart."""

import json
import os
from pathlib import Path
import subprocess
import sys

from .request_admission import AdmissionError


# Runs in the broker's Linux namespace, not in the Windows caller. No supplied
# program, module, command, interpreter path or caller-made observation is used.
LINUX_WITNESS = r'''
import hashlib, json, os, stat, sys

def decode(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            assert key not in result
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique)

def private(info, directory):
    assert (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
    assert info.st_uid == os.getuid() and not info.st_mode & 0o077
    if not directory:
        assert info.st_nlink == 1
    return info

def identity(info):
    return info.st_dev, info.st_ino, info.st_uid, info.st_mode

def stamp(info):
    return identity(info) + (info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

def read(parent, name, maximum):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    try:
        before = private(os.fstat(fd), False)
        assert before.st_size <= maximum
        data = os.read(fd, maximum + 1)
        assert len(data) == before.st_size
        assert stamp(os.fstat(fd)) == stamp(before)
        assert stamp(os.stat(name, dir_fd=parent, follow_symlinks=False)) == stamp(before)
        return data
    finally:
        os.close(fd)

def birth(pid):
    try:
        with open("/proc/%d/stat" % pid) as stream:
            value = stream.read()
    except FileNotFoundError:
        return None
    fields = value[value.rindex(")") + 2:].split()
    with open("/proc/sys/kernel/random/boot_id") as stream:
        boot = stream.read().strip()
    return boot + ":" + fields[19]

def verify():
    request = json.load(sys.stdin)
    previous, successor, realm = request["previous"], request["successor"], request["realm"]
    path = successor["queueDirectory"]
    assert path == previous["queueDirectory"] == realm["path"] == os.path.realpath(path)
    root = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK)
    realm_fd = None
    try:
        original = private(os.fstat(root), True)
        assert (original.st_dev, original.st_ino) == (realm["device"], realm["inode"])
        realm_fd = os.open("runtime-verification", os.O_RDONLY | os.O_DIRECTORY |
                           os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=root)
        realm_info = private(os.fstat(realm_fd), True)
        key = read(realm_fd, "verification.key", 32)
        assert len(key) == 32
        digest = hashlib.sha256(key).hexdigest()
        assert digest == realm["keyDigest"]
        metadata = decode(read(realm_fd, "realm.json", 512))
        assert type(metadata["version"]) is int
        assert metadata == dict(
            kind="fmcad-runtime-verification-realm", version=1,
            keyId="fmcad-rebaseline-" + digest, sha256=digest)
        expected = {name: successor[name] for name in ("pid", "birth", "nonce")}
        expected["protocol"] = 2
        claim = decode(read(root, "broker.lock", 4096))
        assert type(claim["pid"]) is int and type(claim["protocol"]) is int
        assert claim == expected
        assert birth(previous["pid"]) != previous["birth"]
        assert birth(successor["pid"]) == successor["birth"]
        assert os.stat("/proc/%d" % successor["pid"]).st_uid == os.getuid()
        # Repeat after all reads: a delayed mailbox request cannot select a
        # replacement claim or an old PID recycled while verifying the realm.
        assert decode(read(root, "broker.lock", 4096)) == expected
        assert birth(previous["pid"]) != previous["birth"]
        assert birth(successor["pid"]) == successor["birth"]
        assert identity(os.stat("runtime-verification", dir_fd=root,
                                follow_symlinks=False)) == identity(realm_info)
        assert identity(os.lstat(path)) == identity(original)
        assert os.path.realpath("/proc/self/fd/%d" % root) == path
    finally:
        if realm_fd is not None:
            os.close(realm_fd)
        os.close(root)

try:
    verify()
except Exception:
    sys.exit(1)
print("verified")
'''


def verify_owner_succession(previous, successor, *, realm, broker_namespace=None):
    """Observe now, while the authority lock and owner-write transaction are held.

    The namespace hint is private mailbox routing, never evidence. The existing
    consumed root's device/inode and verifier digest authenticate what it opens.
    """
    if sys.platform == "win32":
        if (not isinstance(broker_namespace, str) or not broker_namespace
                or len(broker_namespace) > 256 or not broker_namespace.isascii()
                or broker_namespace.startswith("-")
                or any(char in broker_namespace for char in "\0/\\\r\n")):
            raise AdmissionError("Exact private Linux namespace routing is required")
        command = [
            str(Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "wsl.exe"),
            "--distribution", broker_namespace, "--exec", "/usr/bin/python3",
        ]
    elif sys.platform.startswith("linux"):
        command = ["/usr/bin/python3"]
    else:
        raise AdmissionError("Broker kernel observation is unavailable")
    try:
        result = subprocess.run(
            command + ["-I", "-S", "-B", "-c", LINUX_WITNESS],
            input=json.dumps(dict(previous=previous, successor=successor, realm=realm)),
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
            timeout=10, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        raise AdmissionError("Broker kernel observation is unavailable") from None
    if result.returncode != 0 or result.stdout != "verified\n":
        raise AdmissionError("Broker owner succession is not kernel-proven")
