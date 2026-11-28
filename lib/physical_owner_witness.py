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
    previous, successor = request["previous"], request["successor"]
    normal = "namespace" in request
    realm = None if normal else request["realm"]
    path = successor["queueDirectory"]
    assert path == os.path.realpath(path)
    if previous is not None:
        assert path == previous["queueDirectory"]
    if not normal:
        assert path == realm["path"]
    root = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK)
    realm_fd = None
    try:
        original = private(os.fstat(root), True)
        if not normal:
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
        if previous is not None:
            assert birth(previous["pid"]) != previous["birth"]
        assert birth(successor["pid"]) == successor["birth"]
        assert os.stat("/proc/%d" % successor["pid"]).st_uid == os.getuid()
        observed = None
        if normal:
            spaces = {}
            for name in ("pid", "mnt"):
                own = os.stat("/proc/self/ns/" + name)
                broker = os.stat("/proc/%d/ns/%s" % (successor["pid"], name))
                assert (own.st_dev, own.st_ino) == (broker.st_dev, broker.st_ino)
                spaces[name] = [own.st_dev, own.st_ino]
            with open("/proc/sys/kernel/random/boot_id") as stream:
                boot = stream.read().strip()
            observed = dict(path=path, device=original.st_dev, inode=original.st_ino,
                            uid=os.getuid(), bootId=boot, spaces=spaces)
            if request["namespace"] is not None:
                assert observed == request["namespace"]
        # Repeat after all reads: a delayed mailbox request cannot select a
        # replacement claim or an old PID recycled while verifying the realm.
        assert decode(read(root, "broker.lock", 4096)) == expected
        if previous is not None:
            assert birth(previous["pid"]) != previous["birth"]
        assert birth(successor["pid"]) == successor["birth"]
        if not normal:
            assert identity(os.stat("runtime-verification", dir_fd=root,
                                    follow_symlinks=False)) == identity(realm_info)
        assert identity(os.lstat(path)) == identity(original)
        assert os.path.realpath("/proc/self/fd/%d" % root) == path
        return observed
    finally:
        if realm_fd is not None:
            os.close(realm_fd)
        os.close(root)

try:
    observed = verify()
except Exception:
    sys.exit(1)
print("verified" if observed is None else json.dumps(observed, sort_keys=True))
'''


def _invoke(payload, broker_namespace):
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
            input=json.dumps(payload),
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
            timeout=10, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        raise AdmissionError("Broker kernel observation is unavailable") from None
    if result.returncode != 0:
        raise AdmissionError("Broker owner succession is not kernel-proven")
    return result.stdout


def verify_owner_succession(previous, successor, *, realm, broker_namespace=None):
    """The consumed-root path always requires its pinned existing realm key."""
    result = _invoke(dict(previous=previous, successor=successor, realm=realm), broker_namespace)
    if result != "verified\n":
        raise AdmissionError("Broker owner succession is not kernel-proven")


def observe_normal_owner(previous, successor, *, expected=None, broker_namespace=None):
    """Selected only by authenticated NormalRuntimeOrigin, never by request flags."""
    route = broker_namespace if sys.platform == "win32" else None
    if expected is not None and (
            not isinstance(expected, dict) or set(expected) != {"route", "kernel"}
            or expected["route"] != route):
        raise AdmissionError("Normal broker namespace routing changed")
    result = _invoke(dict(
        previous=previous, successor=successor,
        namespace=None if expected is None else expected["kernel"],
    ), broker_namespace)
    try:
        kernel = json.loads(result)
        if (not isinstance(kernel, dict) or set(kernel) != {
                "path", "device", "inode", "uid", "bootId", "spaces",
        } or kernel["path"] != successor["queueDirectory"]):
            raise ValueError()
    except (ValueError, TypeError):
        raise AdmissionError("Normal broker kernel observation is invalid") from None
    return dict(route=route, kernel=kernel)
