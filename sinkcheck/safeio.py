"""Non-detonating file reads.

Rules, each one earned by a way a scanner can hang or misbehave:

1. stat() before open(). A FIFO, socket or device node is never opened;
   opening a FIFO for reading blocks forever.
2. Only regular files are read. Anything else is reported, not followed.
3. Open with O_NONBLOCK where the platform has it, then fstat() the
   descriptor and confirm it is the same regular file we stat()ed.
4. Reads are capped. An oversized file is reported, not truncated into a
   misleading partial parse.
5. Nothing here ever opens a file for writing.
"""

import os
import re
import stat
import sys
from dataclasses import dataclass

MAX_CONFIG_BYTES = 1024 * 1024

_WIN_DRIVE_RELATIVE = re.compile(r"[A-Za-z]:(?![\\/])")
# Filesystem types whose "regular files" can have side effects when read (kernel log,
# trace pipes, control files). Identified by the filesystem the file really lives on,
# never by what its path looks like: ../../proc/x, //proc/x and a symlink into /proc
# all end up on the same device.
PSEUDO_FSTYPES = frozenset((
    "proc", "sysfs", "debugfs", "tracefs", "securityfs", "cgroup", "cgroup2", "pstore", "bpf",
    "configfs", "fusectl", "binfmt_misc", "devpts", "devtmpfs", "selinuxfs", "efivarfs",
    "mqueue", "hugetlbfs", "autofs", "rpc_pipefs", "nsfs",
))
_MOUNTINFO = "/proc/self/mountinfo"
_mount_cache = {"table": None}


def _parse_mountinfo(text):
    table = {}
    for line in text.splitlines():
        left, sep, right = line.partition(" - ")
        if not sep:
            continue
        fields = left.split(" ")
        rest = right.split(" ")
        if len(fields) < 3 or not rest or not rest[0]:
            continue
        try:
            major, minor = fields[2].split(":")
            table.setdefault((int(major), int(minor)), set()).add(rest[0])
        except ValueError:
            continue
    return table


def _load_mounts():
    try:
        with open(_MOUNTINFO, "rb") as fh:
            data = fh.read(4 * 1024 * 1024)
    except OSError:
        return None
    return _parse_mountinfo(data.decode("utf-8", errors="replace"))


def classify_device(table, device):
    """Return '' or a reason. device: (major, minor). table: {(major, minor): {fstype}}
    or None (mount table unreadable)."""
    major, minor = device
    if table is None:
        if major == 0:
            return "its filesystem could not be identified (mount table unreadable) and it is on an anonymous device"
        return ""
    types = table.get(device)
    if types is None:
        return ""
    bad = sorted(types & PSEUDO_FSTYPES)
    if bad:
        return "it lives on a %s pseudo-filesystem (reads can have side effects)" % bad[0]
    return ""


def pseudo_fs_reason(st):
    """Reason string if the stat result belongs to a pseudo-filesystem, else ''.
    Linux only: other platforms have no equivalent device-to-type table. The
    result comes from os.stat (which follows symlinks), so it describes the file
    that would really be read."""
    if os.name == "nt" or not sys.platform.startswith("linux") or not hasattr(os, "major"):
        return ""
    table = _mount_cache["table"]
    key = (os.major(st.st_dev), os.minor(st.st_dev))
    if table is None or key not in table:
        table = _load_mounts()  # mounts change; re-read when a device is unknown
        _mount_cache["table"] = table
    return classify_device(table, key)


def unsafe_path_reason(path):
    """Return a reason string if this path must not be handed to the OS at
    all, else ''. Checked BEFORE any stat/open/realpath, because on Windows
    even a stat of a UNC path opens a network connection (and may send
    credentials), and because a NUL or lone surrogate raises ValueError
    instead of OSError."""
    if not isinstance(path, str):
        return "not a text path"
    if "\x00" in path:
        return "path contains a NUL byte"
    try:
        path.encode("utf-8")
    except UnicodeEncodeError:
        pass  # surrogateescape'd bytes are legal on POSIX; the OS call decides
    if os.name == "nt":
        norm = path.replace("/", "\\")
        if norm.startswith("\\\\"):
            return "UNC or device path (would touch the network or a device)"
        if _WIN_DRIVE_RELATIVE.match(path):
            return "drive-relative path"
        if ":" in path[2:]:
            return "alternate data stream or device syntax"
    return ""


@dataclass(frozen=True)
class ReadResult:
    status: str  # ok | missing | not_regular | too_large | error
    data: bytes = b""
    detail: str = ""
    is_symlink: bool = False


def _kind(mode):
    if stat.S_ISDIR(mode):
        return "directory"
    if stat.S_ISFIFO(mode):
        return "fifo"
    if stat.S_ISSOCK(mode):
        return "socket"
    if stat.S_ISCHR(mode):
        return "character device"
    if stat.S_ISBLK(mode):
        return "block device"
    return "non-regular file"


def read_regular_file(path, max_bytes=MAX_CONFIG_BYTES):
    reason = unsafe_path_reason(path)
    if reason:
        return ReadResult("error", detail="path refused before any filesystem call: %s" % reason)
    try:
        lst = os.lstat(path)
    except FileNotFoundError:
        return ReadResult("missing")
    except (OSError, ValueError) as exc:
        return ReadResult("error", detail="lstat failed: %s" % exc.__class__.__name__)
    is_link = stat.S_ISLNK(lst.st_mode)

    try:
        st = os.stat(path)
    except (OSError, ValueError) as exc:
        return ReadResult(
            "error",
            detail="stat failed (dangling symlink?): %s" % exc.__class__.__name__,
            is_symlink=is_link,
        )

    if not stat.S_ISREG(st.st_mode):
        return ReadResult("not_regular", detail=_kind(st.st_mode), is_symlink=is_link)
    pseudo = pseudo_fs_reason(st)
    if pseudo:
        return ReadResult("error", detail="refused before opening: %s" % pseudo, is_symlink=is_link)
    if st.st_size > max_bytes:
        return ReadResult(
            "too_large",
            detail="%d bytes exceeds cap of %d" % (st.st_size, max_bytes),
            is_symlink=is_link,
        )

    flags = os.O_RDONLY
    flags |= os.O_BINARY if hasattr(os, "O_BINARY") else 0
    flags |= os.O_NONBLOCK if hasattr(os, "O_NONBLOCK") else 0
    flags |= os.O_NOCTTY if hasattr(os, "O_NOCTTY") else 0
    try:
        fd = os.open(path, flags)
    except (OSError, ValueError) as exc:
        return ReadResult("error", detail="open failed: %s" % exc.__class__.__name__, is_symlink=is_link)

    try:
        fst = os.fstat(fd)
        if not stat.S_ISREG(fst.st_mode):
            return ReadResult("not_regular", detail="changed type after stat", is_symlink=is_link)
        if st.st_ino and fst.st_ino and (st.st_ino, st.st_dev) != (fst.st_ino, fst.st_dev):
            return ReadResult("error", detail="file replaced between stat and open", is_symlink=is_link)
        chunks = []
        total = 0
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                return ReadResult(
                    "too_large",
                    detail="grew past cap of %d while reading" % max_bytes,
                    is_symlink=is_link,
                )
            chunks.append(chunk)
        return ReadResult("ok", data=b"".join(chunks), is_symlink=is_link)
    except OSError as exc:
        return ReadResult("error", detail="read failed: %s" % exc.__class__.__name__, is_symlink=is_link)
    finally:
        os.close(fd)


def path_kind(path):
    """Return 'missing', 'dir', 'file', 'symlink-dir', 'symlink-file',
    'symlink-other' or 'other' using lstat/stat only. Never opens anything."""
    if unsafe_path_reason(path):
        return "other"
    try:
        lst = os.lstat(path)
    except FileNotFoundError:
        return "missing"
    except (OSError, ValueError):
        return "other"
    if stat.S_ISLNK(lst.st_mode):
        try:
            st = os.stat(path)
        except (OSError, ValueError):
            return "symlink-other"
        if stat.S_ISDIR(st.st_mode):
            return "symlink-dir"
        if stat.S_ISREG(st.st_mode):
            return "symlink-file"
        return "symlink-other"
    if stat.S_ISDIR(lst.st_mode):
        return "dir"
    if stat.S_ISREG(lst.st_mode):
        return "file"
    return "other"
