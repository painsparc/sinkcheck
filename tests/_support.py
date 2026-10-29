"""Shared helpers for the test suite.

The fixtures here contain REAL, benign payloads: a config value that, if
git (or anything) ran it, would append a line to a SENTINEL file placed
outside the scanned tree. The detonation gate asserts the scanner never
causes that file to exist.
"""

import builtins
import contextlib
import os
import shutil
import subprocess
import sys
import tempfile
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

PAYLOAD_SOURCE = (
    "import os\n"
    "d = os.path.dirname(os.path.abspath(__file__))\n"
    "with open(os.path.join(d, 'SENTINEL'), 'a') as fh:\n"
    "    fh.write('detonated\\n')\n"
)


def cfg_quote(value):
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def section_header(section, subsection):
    if subsection is None:
        return "[%s]\n" % section
    return '[%s "%s"]\n' % (section, subsection.replace("\\", "\\\\").replace('"', '\\"'))


class Fixture:
    """A scratch area: <base>/tree (scanned) and <base>/outside (payload,
    sentinel, include targets). Everything lives under one temp dir."""

    def __init__(self):
        self.base = tempfile.mkdtemp(prefix="sinkcheck_gate_")
        self.tree = os.path.join(self.base, "tree")
        self.outside = os.path.join(self.base, "outside")
        os.makedirs(self.tree)
        os.makedirs(self.outside)
        self.payload = os.path.join(self.outside, "payload.py")
        self.sentinel = os.path.join(self.outside, "SENTINEL")
        with open(self.payload, "w") as fh:
            fh.write(PAYLOAD_SOURCE)

    def cleanup(self):
        shutil.rmtree(self.base, ignore_errors=True)

    @property
    def payload_command(self):
        py = sys.executable.replace("\\", "/")
        pl = self.payload.replace("\\", "/")
        return '"%s" "%s"' % (py, pl)

    @property
    def sentinel_exists(self):
        return os.path.exists(self.sentinel)

    @property
    def git_dir(self):
        return os.path.join(self.tree, ".git")

    @property
    def config_path(self):
        return os.path.join(self.git_dir, "config")

    def make_bare_minimum_gitdir(self):
        """Hand-made .git skeleton. No git binary involved."""
        os.makedirs(os.path.join(self.git_dir, "objects"))
        os.makedirs(os.path.join(self.git_dir, "refs"))
        with open(os.path.join(self.git_dir, "HEAD"), "w") as fh:
            fh.write("ref: refs/heads/main\n")

    def write_config(self, text):
        with open(self.config_path, "w", newline="\n", encoding="utf-8") as fh:
            fh.write(text)


def write_file(path, text):
    """Create parent directories and write a UTF-8 text file (test setup only)."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="\n", encoding="utf-8") as fh:
        fh.write(text)


def make_gitdir(path, config_text=None):
    """Hand-made git directory skeleton at `path` (no git binary)."""
    os.makedirs(os.path.join(path, "objects"), exist_ok=True)
    os.makedirs(os.path.join(path, "refs"), exist_ok=True)
    write_file(os.path.join(path, "HEAD"), "ref: refs/heads/main\n")
    if config_text is not None:
        write_file(os.path.join(path, "config"), config_text)


def clear_git_env():
    """Remove GIT_* variables from os.environ; returns a started patcher the
    caller must stop (use addCleanup(p.stop))."""
    p = mock.patch.dict(os.environ)
    p.start()
    for k in list(os.environ):
        if k.upper().startswith("GIT_"):
            del os.environ[k]
    return p


def hardened_git_env(home):
    env = dict(os.environ)
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["HOME"] = home
    env["USERPROFILE"] = home
    env["XDG_CONFIG_HOME"] = os.path.join(home, "xdg")
    env["GIT_TERMINAL_PROMPT"] = "0"
    for var in ("GIT_DIR", "GIT_WORK_TREE", "GIT_CONFIG", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM"):
        env.pop(var, None)
    return env


def run_git(args, cwd, home):
    """Used only by the test harness, never by the package under test."""
    return subprocess.run(
        ["git"] + list(args),
        cwd=cwd,
        env=hardened_git_env(home),
        capture_output=True,
        text=True,
        timeout=120,
    )


def snapshot(root):
    items = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(dirnames + filenames):
            p = os.path.join(dirpath, name)
            st = os.lstat(p)
            items.append((os.path.relpath(p, root), st.st_size, st.st_mtime_ns))
    return items


class Guard:
    """Context manager that makes forbidden operations raise AssertionError
    and records every path opened through os.open."""

    def __init__(self):
        self.opened = []  # every path opened through open() or os.open()
        self.touched = []  # every path passed to stat/lstat/scandir/realpath/readlink/listdir
        self._stack = contextlib.ExitStack()

    def _deny(self, name):
        def fn(*args, **kwargs):
            raise AssertionError("forbidden operation during scan: %s" % name)

        return fn

    def __enter__(self):
        real_builtin_open = builtins.open
        real_os_open = os.open
        opened = self.opened
        write_flags = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_TRUNC

        touched = self.touched

        def guarded_open(file, mode="r", *args, **kwargs):
            if any(c in str(mode) for c in "wax+"):
                raise AssertionError("write-mode open during scan: %r" % (file,))
            opened.append(str(file))
            return real_builtin_open(file, mode, *args, **kwargs)

        def recording(real, name):
            def fn(path=".", *args, **kwargs):
                touched.append(str(path))
                return real(path, *args, **kwargs)

            return fn

        def guarded_os_open(path, flags, *args, **kwargs):
            if flags & write_flags:
                raise AssertionError("write-flag os.open during scan: %r" % (path,))
            opened.append(str(path))
            return real_os_open(path, flags, *args, **kwargs)

        s = self._stack
        s.enter_context(mock.patch("builtins.open", guarded_open))
        s.enter_context(mock.patch("io.open", guarded_open))
        s.enter_context(mock.patch("os.open", guarded_os_open))
        for name in ("stat", "lstat", "scandir", "listdir", "readlink"):
            s.enter_context(mock.patch("os." + name, recording(getattr(os, name), name)))
        s.enter_context(mock.patch("os.path.realpath", recording(os.path.realpath, "realpath")))
        s.enter_context(mock.patch("subprocess.Popen", self._deny("subprocess.Popen")))
        deny_names = ("system", "popen", "execv", "execve", "execvp", "execvpe", "execl", "execle", "execlp", "execlpe",
                      "spawnl", "spawnle", "spawnlp", "spawnlpe", "spawnv", "spawnve", "spawnvp", "spawnvpe",
                      "posix_spawn", "posix_spawnp", "startfile", "fork", "forkpty", "remove", "unlink", "rename",
                      "replace", "rmdir", "mkdir", "makedirs", "symlink", "link", "chmod", "truncate", "utime")
        for name in deny_names:
            if hasattr(os, name):
                s.enter_context(mock.patch("os." + name, self._deny("os." + name)))
        # os is a thin wrapper over posix (nt on Windows); the originals must be denied too
        low = sys.modules.get("posix") or sys.modules.get("nt")
        if low is not None:
            for name in deny_names + ("mkfifo", "mknod", "chown", "chdir", "setxattr"):
                if hasattr(low, name):
                    s.enter_context(mock.patch.object(low, name, self._deny("posix." + name)))
        for modname, attr in (("_posixsubprocess", "fork_exec"), ("_winapi", "CreateProcess"),
                              ("_socket", "getaddrinfo"), ("_socket", "gethostbyname")):
            mod = sys.modules.get(modname)
            if mod is None:
                try:
                    mod = __import__(modname)
                except ImportError:
                    mod = None
            if mod is not None and hasattr(mod, attr):
                s.enter_context(mock.patch.object(mod, attr, self._deny(modname + "." + attr)))
        import _io

        s.enter_context(mock.patch.object(_io, "open", guarded_open))
        import socket

        for name in ("create_connection", "getaddrinfo", "gethostbyname"):
            s.enter_context(mock.patch("socket." + name, self._deny("socket." + name)))
        for name in ("connect", "connect_ex", "bind", "sendto"):
            s.enter_context(mock.patch("socket.socket." + name, self._deny("socket." + name)))
        for name in ("mkfifo", "mknod", "chown", "chdir", "setxattr"):
            if hasattr(os, name):
                s.enter_context(mock.patch("os." + name, self._deny("os." + name)))
        return self

    def __exit__(self, *exc):
        self._stack.close()
        return False
