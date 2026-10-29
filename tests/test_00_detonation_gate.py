"""THE DETONATION GATE.

This is a gate, not a test. If any test in this file fails, nothing ships.
It runs before every other test (tools/run_gate.py runs it alone first and
aborts the whole run on failure).

What it proves
--------------
1. POSITIVE CONTROL. The fixture's core.fsmonitor payload really is live:
   a plain `git status` on it writes the SENTINEL file outside the tree. If
   git is missing or the control does not fire, the gate FAILS, because a
   scanner test against a dud payload proves nothing.
2. The scanner, run on that same fixture BEFORE the control, never causes
   the SENTINEL to exist, and still reports CRITICAL (exit 1).
3. The same holds for a config that sets EVERY sink in the ruleset to the
   payload, generated from the ruleset so new sinks are covered
   automatically, including an include.path target outside the tree.
4. During a scan: no subprocess, no os.system/exec/spawn, no network, no
   file or directory creation/removal/rename, no write-mode opens, and the
   scanned tree is byte-for-byte untouched (size + mtime snapshot).
5. The package source contains no import of subprocess, socket, urllib,
   ctypes, pty, or any git binding (AST check, so docstrings cannot trip
   or hide it).
6. Hostile filesystem objects at .git/config (FIFO, directory, device
   symlink, oversize file) are refused without being opened and without
   hanging.

NOTE: item 1 deliberately runs `git status` on a throwaway fixture inside a
temp directory. The payload only appends a line to a file next to itself.
"""

import ast
import contextlib
import io
import json
import os
import stat
import sys
import threading
import unittest
from unittest import mock

from tests._support import Fixture, Guard, cfg_quote, clear_git_env, make_gitdir, run_git, section_header, snapshot, write_file, ROOT

from sinkcheck import engine
from sinkcheck.cli import main as cli_main
from sinkcheck.engine import MAX_INCLUDE_DEPTH, MAX_INCLUDE_FILES, scan_target, verdict_of
from sinkcheck.host import scan_host
from sinkcheck.report import render_text
from sinkcheck.ruleset import load_ruleset

PKG_DIR = os.path.join(ROOT, "sinkcheck")

BANNED_MODULES = {
    "subprocess", "socket", "ssl", "urllib", "http", "ftplib", "smtplib", "telnetlib", "xmlrpc",
    "requests", "httpx", "aiohttp", "ctypes", "pty", "multiprocessing", "asyncio",
    "git", "pygit2", "dulwich", "dugite", "sh", "plumbum",
}
BANNED_MODULES |= {"shutil", "pickle", "marshal", "runpy", "importlib", "webbrowser", "tempfile", "code", "pdb", "cgi"}
# low-level twins of the modules above, which a denylist of the public names would miss
BANNED_MODULES |= {
    "posix", "nt", "_posixsubprocess", "_winapi", "_socket", "_io", "_thread", "builtins",
    "sqlite3", "concurrent", "pathlib", "logging", "platform", "uuid", "io", "signal", "fcntl", "mmap",
}
# The package may import ONLY these. An allowlist cannot be sidestepped by a module nobody thought to ban.
ALLOWED_IMPORTS = {"os", "sys", "re", "json", "stat", "datetime", "argparse", "dataclasses", "itertools"}
BANNED_ATTR_NAMES = {"write_text", "write_bytes", "touch", "FileHandler", "modules", "__builtins__", "__import__"}
BANNED_OS_ATTRS = {
    "system", "popen", "execv", "execve", "execvp", "execvpe", "execl", "execle", "execlp", "execlpe",
    "spawnl", "spawnle", "spawnlp", "spawnlpe", "spawnv", "spawnve", "spawnvp", "spawnvpe",
    "posix_spawn", "posix_spawnp", "startfile", "fork", "forkpty",
    # writes and filesystem mutation
    "remove", "unlink", "rename", "renames", "replace", "rmdir", "removedirs", "mkdir", "makedirs",
    "symlink", "link", "chmod", "chown", "truncate", "utime", "mkfifo", "mknod", "chdir", "chroot",
    "write", "ftruncate", "fchmod", "fchown", "setxattr", "removexattr",
    # flags that make os.open write, create or truncate
    "O_WRONLY", "O_RDWR", "O_CREAT", "O_APPEND", "O_TRUNC", "O_EXCL",
}


def package_offenders(tree, name):
    """Static check of one parsed module. Returns a list of offences (empty = clean).

    Imports are checked against an ALLOWLIST. Beyond that: no os alias by assignment
    (`o = os`), no os.path.os, no sys.modules, no bare `open` (only direct read-mode
    calls), no write-flag os.open, no eval/exec/__import__."""
    off = []
    os_aliases = {"os"}
    parent = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parent[child] = node
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                top = a.name.split(".")[0]
                if top in BANNED_MODULES or top not in ALLOWED_IMPORTS:
                    off.append("%s: import %s" % (name, a.name))
                if a.name == "os" and a.asname:
                    os_aliases.add(a.asname)
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            mod = (node.module or "").split(".")[0]
            if mod in BANNED_MODULES or mod not in ALLOWED_IMPORTS:
                off.append("%s: from %s import ..." % (name, node.module))
            if mod == "os":
                for a in node.names:
                    if a.name in BANNED_OS_ATTRS or a.name == "*":
                        off.append("%s: from os import %s" % (name, a.name))
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name) and node.value.id in os_aliases and node.attr in BANNED_OS_ATTRS:
                off.append("%s: os.%s" % (name, node.attr))
            if node.attr in BANNED_ATTR_NAMES:
                off.append("%s: attribute .%s" % (name, node.attr))
            if node.attr == "os":
                off.append("%s: reaching os through another object" % name)
        elif isinstance(node, ast.Name):
            p = parent.get(node)
            if node.id in os_aliases:
                ok_attr = isinstance(p, ast.Attribute) and p.value is node
                ok_hasattr = (isinstance(p, ast.Call) and isinstance(p.func, ast.Name)
                              and p.func.id == "hasattr" and p.args and p.args[0] is node)
                if not (ok_attr or ok_hasattr):
                    off.append("%s: bare reference to os (alias or escape)" % name)
            if node.id in ("__builtins__", "builtins"):
                off.append("%s: reference to builtins" % name)
            if node.id == "open" and not (isinstance(p, ast.Call) and p.func is node):
                off.append("%s: bare reference to open" % name)
        elif isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Name) and f.id in ("eval", "exec", "compile", "__import__"):
                off.append("%s: call to %s" % (name, f.id))
            if (
                isinstance(f, ast.Name)
                and f.id in ("getattr", "setattr", "delattr", "vars")
                and node.args
                and isinstance(node.args[0], ast.Name)
                and node.args[0].id in os_aliases | {"sys", "builtins", "subprocess"}
            ):
                off.append("%s: %s() on a module" % (name, f.id))
            if isinstance(f, ast.Name) and f.id == "open":
                modes = [a for a in node.args[1:2]] + [k.value for k in node.keywords if k.arg == "mode"]
                if not modes:
                    continue  # default mode is read-only
                for m in modes:
                    if not (isinstance(m, ast.Constant) and isinstance(m.value, str) and not set(m.value) & set("wax+")):
                        off.append("%s: open() with a non-read mode" % name)
    return off


def all_sinks_config(ruleset, command, include_target):
    parts = ["[core]\n\trepositoryformatversion = 0\n"]
    for rule in ruleset.rules:
        key = rule.key
        first, last = key.find("."), key.rfind(".")
        section, name = key[:first], key[last + 1:]
        subsection = None
        if first != last:
            subsection = key[first + 1:last]
            if subsection == "*":
                subsection = "zz"
        elif name == "*":
            name = "zz"
        if rule.match == "bang_prefix":
            value = "!" + command
        elif rule.match == "ext_url":
            value = "ext::" + command
        elif rule.match == "value_in":
            value = rule.hit_values[0]
        elif rule.match == "include":
            value = include_target
        elif rule.match == "any_value":
            value = "zz"
        else:
            value = command
        parts.append(section_header(section, subsection))
        parts.append("\t%s = %s\n" % (name, cfg_quote(value)))
    return "".join(parts)


class DetonationGate(unittest.TestCase):
    def setUp(self):
        self.fx = Fixture()
        self.addCleanup(self.fx.cleanup)
        self.ruleset = load_ruleset()

    # 1 + 2 ---------------------------------------------------------------
    def test_fsmonitor_payload_is_live_and_scanner_never_fires_it(self):
        fx = self.fx
        home = os.path.join(fx.base, "home")
        os.makedirs(home)

        try:
            init = run_git(["init", "-q", fx.tree], cwd=fx.base, home=home)
        except (OSError, FileNotFoundError) as exc:
            self.fail("GATE CANNOT PROVE ANYTHING: git is not runnable (%s). Install git and rerun." % exc)
        self.assertEqual(init.returncode, 0, "git init failed: %s" % init.stderr)

        with open(fx.config_path, "a", newline="\n") as fh:
            fh.write("[core]\n\tfsmonitor = %s\n" % cfg_quote(fx.payload_command))

        self.assertFalse(fx.sentinel_exists, "sentinel existed before the scan: fixture is dirty")

        before = snapshot(fx.tree)
        with Guard() as guard:
            result = scan_target(fx.tree, self.ruleset)
            text = render_text(result)
        after = snapshot(fx.tree)

        self.assertFalse(fx.sentinel_exists, "SCANNER DETONATED THE PAYLOAD")
        self.assertEqual(before, after, "scanner modified the scanned tree")
        self.assertEqual(verdict_of(result), ("CRITICAL", 1))
        self.assertIn("core.fsmonitor", text)
        self.assertTrue(
            any(os.path.normpath(fx.config_path) in os.path.normpath(e) for e in result.examined),
            "the fixture config was not recorded as examined",
        )

        # Positive control, AFTER the scan so it cannot contaminate step 2.
        control = run_git(["status"], cwd=fx.tree, home=home)
        self.assertTrue(
            fx.sentinel_exists,
            "POSITIVE CONTROL FAILED: plain `git status` did not run the payload "
            "(git stderr: %r). The gate cannot prove the fixture is live." % control.stderr[:300],
        )

    # 3 -------------------------------------------------------------------
    def test_every_sink_in_ruleset_set_to_payload_is_not_detonated(self):
        fx = self.fx
        fx.make_bare_minimum_gitdir()
        include_file = os.path.join(fx.outside, "evil.cfg")
        with open(include_file, "w", newline="\n") as fh:
            fh.write("[core]\n\tfsmonitor = %s\n" % cfg_quote(fx.payload_command))
        fx.write_config(all_sinks_config(self.ruleset, fx.payload_command, include_file.replace("\\", "/")))

        before = snapshot(fx.tree)
        with Guard():
            result = scan_target(fx.tree, self.ruleset)
            render_text(result)
        after = snapshot(fx.tree)

        self.assertFalse(fx.sentinel_exists, "SCANNER DETONATED THE PAYLOAD")
        self.assertEqual(before, after)
        self.assertEqual(verdict_of(result)[1], 1)

        self.assertTrue(
            any("evil.cfg" in e for e in result.examined),
            "the include target outside the tree was never read, so the include chain is untested here",
        )
        hit_ids = {f.rule.id for f in result.findings if f.kind == "sink" and f.rule is not None}
        missing = [r.id for r in self.ruleset.rules if r.id not in hit_ids]
        self.assertEqual(missing, [], "rules that did not fire on their own sample assignment")

    # 4 -------------------------------------------------------------------
    def test_forbidden_operations_raise_inside_guard(self):
        """Self-test of the guard: if the guard cannot catch these, steps 2-3 prove nothing."""
        import subprocess

        with Guard():
            with self.assertRaises(AssertionError):
                subprocess.Popen([sys.executable, "-c", "pass"])
            with self.assertRaises(AssertionError):
                os.system("echo x")
            with self.assertRaises(AssertionError):
                open(os.path.join(self.fx.base, "w.txt"), "w")
            with self.assertRaises(AssertionError):
                os.mkdir(os.path.join(self.fx.base, "d"))
            with self.assertRaises(AssertionError):
                os.open(os.path.join(self.fx.base, "w2.txt"), os.O_WRONLY | os.O_CREAT)
            low = sys.modules.get("posix") or sys.modules.get("nt")
            if low is not None and hasattr(low, "system"):
                with self.assertRaises(AssertionError):
                    low.system("echo x")  # the low-level twin of os.system
            if hasattr(os, "posix_spawn"):
                with self.assertRaises(AssertionError):
                    os.posix_spawn(sys.executable, [sys.executable, "-c", "pass"], {})
            with self.assertRaises(AssertionError):
                import socket

                socket.create_connection(("127.0.0.1", 9))

    # 5 -------------------------------------------------------------------
    def test_package_source_has_no_process_network_or_git_binding_imports(self):
        offenders = []
        sources = []
        for dirpath, dirnames, filenames in os.walk(PKG_DIR):
            dirnames[:] = [d for d in dirnames if d != "__pycache__"]
            for name in sorted(filenames):
                if name.endswith(".py"):
                    sources.append(os.path.join(dirpath, name))
        self.assertTrue(sources)
        for path in sources:
            name = os.path.relpath(path, PKG_DIR)
            with open(path, "rb") as fh:
                tree = ast.parse(fh.read(), filename=path)
            offenders.extend(package_offenders(tree, name))
        self.assertEqual(offenders, [], "forbidden constructs in package source")

    def test_static_check_rejects_deliberately_bad_snippets(self):
        """Negative control: a checker that cannot fail proves nothing. Every snippet below
        is a way to run a process, write, or reach the network that a name-by-name denylist
        would miss; each must be rejected, and a harmless snippet must pass."""
        bad = {
            "posix twin of os": "import posix\nposix.system('x')\n",
            "fork_exec": "import _posixsubprocess\n",
            "raw socket": "import _socket\n",
            "sqlite creates files": "import sqlite3\nsqlite3.connect('x.db')\n",
            "process pool": "from concurrent.futures import ProcessPoolExecutor\n",
            "os alias by assignment": "import os\no = os\no.system('x')\n",
            "os through os.path": "import os\nos.path.os.system('x')\n",
            "builtins open": "import builtins\nbuiltins.open('f', 'w')\n",
            "pathlib write": "from pathlib import Path\nPath('x').write_text('y')\n",
            "logging file": "import logging\nlogging.FileHandler('x')\n",
            "write-mode open": "open('f', 'w')\n",
            "open aliased": "f = open\nf('x', 'w')\n",
            "sys.modules lookup": "import sys\nsys.modules['posix'].system('x')\n",
            "os.system": "import os\nos.system('x')\n",
            "os.write": "import os\nos.write(1, b'x')\n",
            "os.open for writing": "import os\nos.open('f', os.O_WRONLY | os.O_CREAT)\n",
            "eval": "eval('1')\n",
            "dynamic import": "x = __import__('posix')\n",
            "ctypes": "import ctypes\n",
            "io.FileIO": "import io\nio.FileIO('f', 'w')\n",
        }
        for label, src in bad.items():
            self.assertTrue(package_offenders(ast.parse(src), "bad"), "checker accepted: %s" % label)
        good = (
            "import os\nimport re\n"
            "x = os.path.join('a', 'b')\n"
            "if hasattr(os, 'O_BINARY'):\n    pass\n"
            "open('f', 'rb')\nwith open('g', 'rb') as fh:\n    fh.read()\n"
        )
        self.assertEqual(package_offenders(ast.parse(good), "good"), [])

    # 6 -------------------------------------------------------------------
    def _scan_with_timeout(self, seconds=15):
        box = {}

        def work():
            try:
                box["result"] = scan_target(self.fx.tree, self.ruleset)
            except BaseException as exc:  # surface in the main thread
                box["error"] = exc

        t = threading.Thread(target=work, daemon=True)
        t.start()
        t.join(seconds)
        self.assertFalse(t.is_alive(), "scanner HUNG on a hostile filesystem object")
        if "error" in box:
            raise box["error"]
        return box["result"]

    def test_fifo_at_config_is_refused_without_hanging(self):
        if not hasattr(os, "mkfifo"):
            self.skipTest("no os.mkfifo on this platform")
        self.fx.make_bare_minimum_gitdir()
        os.mkfifo(self.fx.config_path)
        result = self._scan_with_timeout()
        self.assertEqual(verdict_of(result)[1], 2)
        self.assertTrue(any(f.kind == "read" and "not_regular" in f.note for f in result.findings))

    def test_directory_at_config_is_refused(self):
        self.fx.make_bare_minimum_gitdir()
        os.mkdir(self.fx.config_path)
        result = self._scan_with_timeout()
        self.assertEqual(verdict_of(result)[1], 2)
        self.assertTrue(any(f.kind == "read" and "not_regular" in f.note for f in result.findings))

    def test_device_symlink_at_config_is_refused(self):
        self.fx.make_bare_minimum_gitdir()
        try:
            os.symlink(os.devnull, self.fx.config_path)
        except (OSError, NotImplementedError, AttributeError):
            self.skipTest("cannot create symlinks here")
        result = self._scan_with_timeout()
        self.assertEqual(verdict_of(result)[1], 2)
        self.assertFalse(any(f.severity == "critical" for f in result.findings))

    def test_oversize_config_is_reported_not_parsed(self):
        self.fx.make_bare_minimum_gitdir()
        with open(self.fx.config_path, "wb") as fh:
            fh.write(b"# pad\n" * (400 * 1024))
        result = self._scan_with_timeout()
        self.assertEqual(verdict_of(result)[1], 2)
        self.assertTrue(any(f.kind == "read" and "too_large" in f.note for f in result.findings))

    def test_unreadable_modes_do_not_crash(self):
        self.fx.make_bare_minimum_gitdir()
        self.fx.write_config("[core]\n\tbare = false\n")
        if os.name != "nt":
            os.chmod(self.fx.config_path, 0)
            self.addCleanup(os.chmod, self.fx.config_path, stat.S_IRUSR | stat.S_IWUSR)
        result = self._scan_with_timeout()
        self.assertIn(verdict_of(result)[1], (0, 2))

    # 7: Phase 2 discovery paths. Each one carries a LIVE payload; the scan
    # must find it and still never fire it or open the payload script. ----
    def _scan_guarded(self, tree=None):
        fx = self.fx
        with Guard() as guard:
            result = scan_target(tree or fx.tree, self.ruleset, ceiling=fx.base, environ={})
            render_text(result)
        self.assertFalse(fx.sentinel_exists, "SCANNER DETONATED THE PAYLOAD")
        self.assertFalse(
            any(os.path.basename(p) in ("payload.py", "SENTINEL") for p in guard.opened),
            "scanner opened the payload or sentinel",
        )
        return result

    def _payload_cfg(self):
        return "[core]\n\tfsmonitor = %s\n" % cfg_quote(self.fx.payload_command)

    def test_include_chain_reaches_payload_without_firing_it(self):
        fx = self.fx
        fx.make_bare_minimum_gitdir()
        a, b, c = (os.path.join(fx.outside, n) for n in ("a.cfg", "b.cfg", "c.cfg"))
        write_file(a, "[include]\n\tpath = b.cfg\n")
        write_file(b, "[include]\n\tpath = %s\n" % c.replace("\\", "/"))
        write_file(c, self._payload_cfg())
        fx.write_config("[include]\n\tpath = %s\n" % a.replace("\\", "/"))
        result = self._scan_guarded()
        self.assertEqual(verdict_of(result)[1], 1)
        hits = [f for f in result.findings if f.kind == "sink" and f.severity == "critical"]
        self.assertTrue(hits)
        self.assertEqual(hits[0].via.count("include at"), 3)

    def test_include_cycle_and_depth_are_bounded(self):
        fx = self.fx
        fx.make_bare_minimum_gitdir()
        a, b = os.path.join(fx.outside, "a.cfg"), os.path.join(fx.outside, "b.cfg")
        write_file(a, "[include]\n\tpath = b.cfg\n")
        write_file(b, "[include]\n\tpath = a.cfg\n")
        fx.write_config("[include]\n\tpath = %s\n" % a.replace("\\", "/"))
        self._scan_guarded()  # terminates
        # a chain longer than git's own limit
        files = [os.path.join(fx.outside, "d%d.cfg" % i) for i in range(MAX_INCLUDE_DEPTH + 3)]
        for i, p in enumerate(files):
            nxt = files[i + 1].replace("\\", "/") if i + 1 < len(files) else None
            write_file(p, ("[include]\n\tpath = %s\n" % nxt) if nxt else self._payload_cfg())
        fx.write_config("[include]\n\tpath = %s\n" % files[0].replace("\\", "/"))
        result = self._scan_guarded()
        self.assertTrue(any(f.kind == "include" and "nesting deeper" in f.note for f in result.findings))
        self.assertEqual(verdict_of(result)[1], 3)  # a truncated chain is an unfinished scan: never clean, never review-only

    def test_buried_bare_repository_is_found_and_not_fired(self):
        fx = self.fx
        buried = os.path.join(fx.tree, "vendor", "x")
        make_gitdir(buried, self._payload_cfg())
        result = self._scan_guarded()
        self.assertEqual(verdict_of(result)[1], 1)
        self.assertTrue(any("buried" in f.note for f in result.findings if f.kind == "structure"))

    def test_gitfile_redirect_outside_tree_is_followed_and_not_fired(self):
        fx = self.fx
        real = os.path.join(fx.outside, "real.git")
        make_gitdir(real, self._payload_cfg())
        write_file(os.path.join(fx.tree, ".git"), "gitdir: %s\n" % real.replace("\\", "/"))
        result = self._scan_guarded()
        self.assertEqual(verdict_of(result)[1], 1)
        self.assertTrue(any("OUTSIDE" in f.note for f in result.findings))

    def test_hook_files_are_reported_by_name_and_never_opened(self):
        fx = self.fx
        fx.make_bare_minimum_gitdir()
        fx.write_config("[core]\n\tbare = false\n")
        hook = os.path.join(fx.git_dir, "hooks", "pre-commit")
        py = sys.executable.replace("\\", "/")
        write_file(hook, "#!/bin/sh\n\"%s\" \"%s\"\n" % (py, fx.payload.replace("\\", "/")))
        os.chmod(hook, 0o755)  # test setup: a hook git would really run, so "never ran it" means something
        if os.name != "nt":
            self.assertTrue(os.access(hook, os.X_OK), "hook fixture is not executable; the test would prove nothing")
        with Guard() as guard:
            result = scan_target(fx.tree, self.ruleset, ceiling=fx.base, environ={})
        self.assertFalse(fx.sentinel_exists)
        self.assertNotIn(hook, guard.opened)
        self.assertTrue(any(f.kind == "hook" and f.key == "pre-commit" and f.severity == "review" for f in result.findings))

    def test_environment_config_injection_is_flagged_without_firing(self):
        fx = self.fx
        fx.make_bare_minimum_gitdir()
        fx.write_config("[core]\n\tbare = false\n")
        env = {
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "core.fsmonitor",
            "GIT_CONFIG_VALUE_0": fx.payload_command,
        }
        with Guard():
            result = scan_target(fx.tree, self.ruleset, ceiling=fx.base, environ=env)
        self.assertFalse(fx.sentinel_exists)
        self.assertEqual(verdict_of(result)[1], 1)

    def test_cli_main_under_guard_with_every_sink_never_detonates(self):
        import contextlib
        import io

        from sinkcheck.cli import main

        fx = self.fx
        fx.make_bare_minimum_gitdir()
        include_file = os.path.join(fx.outside, "evil.cfg")
        write_file(include_file, self._payload_cfg())
        fx.write_config(all_sinks_config(self.ruleset, fx.payload_command, include_file.replace("\\", "/")))
        out, err = io.StringIO(), io.StringIO()
        with Guard() as guard, contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["scan", fx.tree, "--ceiling", fx.base])
            code_pf = main(["preflight", fx.tree, "--ceiling", fx.base, "--no-detect", "--agent", "goose=1.44.0"])
        self.assertFalse(fx.sentinel_exists, "CLI DETONATED THE PAYLOAD")
        self.assertEqual((code, code_pf), (1, 1), err.getvalue())
        self.assertFalse(any(os.path.basename(p) in ("payload.py", "SENTINEL") for p in guard.opened))
        out.getvalue().encode("ascii")

    # 8: Phase 3 agent detection reads package.json as data and never runs
    # the agent or any script an installed package ships. -----------------
    def test_agent_detection_never_runs_or_opens_anything_but_package_json(self):
        from sinkcheck import agents
        from sinkcheck.preflight import run_preflight

        fx = self.fx
        fx.make_bare_minimum_gitdir()
        fx.write_config("[core]\n\tbare = false\n")
        pkg = os.path.join(fx.base, "prefix", "lib", "node_modules", "@anthropic-ai", "claude-code")
        write_file(os.path.join(pkg, "package.json"),
                   '{"name": "@anthropic-ai/claude-code", "version": "2.1.252", "bin": {"claude": "cli.py"}, '
                   '"scripts": {"postinstall": "python cli.py"}}')
        write_file(os.path.join(pkg, "cli.py"),
                   "open(%r, 'a').write('detonated')\n" % fx.sentinel.replace("\\", "/"))
        data = agents.load_agents()
        with Guard() as guard:
            pre = run_preflight(fx.tree, self.ruleset, data, ceiling=fx.base,
                                environ={"npm_config_prefix": os.path.join(fx.base, "prefix")}, detect=True)
        self.assertFalse(fx.sentinel_exists, "AGENT DETECTION RAN A PACKAGE SCRIPT")
        self.assertFalse(any(p.endswith("cli.py") for p in guard.opened))
        self.assertTrue(any(r.installs for r in pre.rows))


class BudgetFailClosedGate(unittest.TestCase):
    """Regression tests for the four ways a real critical could be downgraded to
    "needs review" or hidden, each reproducing the attack as it was reported.

    Rules these tests hold the scanner to:
      * a repeated reference to an already-examined file costs nothing;
      * a scan that hit a budget or cap never exits 0, and --fail-on cannot make it 0;
      * a file examined one way (mode, scope) is still examined the other way;
      * pseudo-filesystems are refused by the device a file really lives on,
        never by how its path happens to be spelled.
    """

    def setUp(self):
        self.addCleanup(clear_git_env().stop)
        self.fx = Fixture()
        self.addCleanup(self.fx.cleanup)
        self.ruleset = load_ruleset()
        self.fx.make_bare_minimum_gitdir()

    @staticmethod
    def fwd(path):
        return path.replace("\\", "/")

    def evil_cfg(self):
        return "[core]\n\tfsmonitor = %s\n" % cfg_quote(self.fx.payload_command)

    def scan(self):
        with Guard() as guard:
            result = scan_target(self.fx.tree, self.ruleset, ceiling=self.fx.base, environ={})
            render_text(result)
        self.assertFalse(self.fx.sentinel_exists, "SCANNER DETONATED THE PAYLOAD")
        return result, guard

    def cli(self, *extra):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli_main(["scan", self.fx.tree, "--ceiling", self.fx.base] + list(extra))
        return code, out.getvalue()

    # 1a: 200+ references to one decoy, then the real payload ------------------
    def test_decoy_include_flood_cannot_starve_the_real_include(self):
        o = self.fx.outside
        write_file(os.path.join(o, "decoy.cfg"), "[core]\n\tbare = false\n")
        write_file(os.path.join(o, "evil.cfg"), self.evil_cfg())
        decoy = self.fwd(os.path.join(o, "decoy.cfg"))
        lines = "".join("\tpath = %s\n" % decoy for _ in range(MAX_INCLUDE_FILES + 50))
        self.fx.write_config("[include]\n" + lines + "\tpath = %s\n" % self.fwd(os.path.join(o, "evil.cfg")))
        result, _ = self.scan()
        self.assertEqual(verdict_of(result), ("CRITICAL", 1), "a pile of repeated references hid the real include")
        self.assertFalse(result.incomplete)
        self.assertGreaterEqual(result.dup_includes, MAX_INCLUDE_FILES + 49)
        self.assertEqual(self.cli("--fail-on", "critical")[0], 1)

    # 1b: more DISTINCT decoys than the budget: must fail closed, never exit 0 -
    def test_distinct_decoys_past_the_budget_fail_closed_and_fail_on_cannot_soften_it(self):
        o = self.fx.outside
        lines = []
        for i in range(MAX_INCLUDE_FILES + 5):
            write_file(os.path.join(o, "d%d.cfg" % i), "[core]\n\tbare = false\n")
            lines.append("\tpath = %s\n" % self.fwd(os.path.join(o, "d%d.cfg" % i)))
        write_file(os.path.join(o, "evil.cfg"), self.evil_cfg())
        lines.append("\tpath = %s\n" % self.fwd(os.path.join(o, "evil.cfg")))
        self.fx.write_config("[include]\n" + "".join(lines))
        result, _ = self.scan()
        self.assertEqual(verdict_of(result), ("INCOMPLETE - SCAN DID NOT FINISH", 3))
        self.assertTrue(any("more than" in r for r in result.incomplete))
        for extra in ((), ("--fail-on", "critical")):
            code, out = self.cli(*extra)
            self.assertEqual(code, 3, "an unfinished scan must never exit 0 or 2: %r" % (extra,))
            self.assertIn("VERDICT: INCOMPLETE", out)
            self.assertIn("SCAN INCOMPLETE", out)
        code, out = self.cli("--fail-on", "critical", "--format", "json")
        self.assertEqual(code, 3)
        self.assertTrue(json.loads(out)["incomplete"])

    # 2: work budget burned by filler, payload behind it ----------------------
    def test_work_budget_exhaustion_fails_closed(self):
        o = self.fx.outside
        write_file(os.path.join(o, "evil.cfg"), self.evil_cfg())
        self.fx.write_config(
            "[include]\n\tpath = %s\n[core]\n%s" % (self.fwd(os.path.join(o, "evil.cfg")), "\tbare = false\n" * 60)
        )
        with mock.patch.object(engine, "MAX_TOTAL_ENTRIES", 50):
            result, _ = self.scan()
            code, out = self.cli("--fail-on", "critical")
        self.assertEqual(verdict_of(result)[1], 3)
        self.assertTrue(any("work budget" in r for r in result.incomplete))
        self.assertEqual(code, 3)
        self.assertIn("work budget", out)

    def test_filler_in_sections_nobody_examines_does_not_burn_the_work_budget(self):
        o = self.fx.outside
        write_file(os.path.join(o, "evil.cfg"), self.evil_cfg())
        self.fx.write_config(
            "[zzjunk]\n%s[include]\n\tpath = %s\n" % ("\ta = 1\n" * 60, self.fwd(os.path.join(o, "evil.cfg")))
        )
        with mock.patch.object(engine, "MAX_TOTAL_ENTRIES", 50):
            result, _ = self.scan()
        self.assertEqual(verdict_of(result), ("CRITICAL", 1))
        self.assertFalse(result.incomplete)

    # 3a: .gitmodules read (submodule.* only) first, then included in full ----
    def test_a_file_read_one_way_is_still_read_the_other_way(self):
        base = self.fx.base
        a, b, home = (os.path.join(base, n) for n in ("rootA", "rootB", "home"))
        write_file(os.path.join(a, ".gitmodules"), self.evil_cfg())
        make_gitdir(os.path.join(b, ".git"), "[include]\n\tpath = %s\n" % self.fwd(os.path.join(a, ".gitmodules")))
        os.makedirs(home)
        env = {"HOME": home, "USERPROFILE": home, "GIT_CONFIG_NOSYSTEM": "1"}
        with Guard():
            result = scan_host([a, b], self.ruleset, ceiling=base, environ=env)
        self.assertFalse(self.fx.sentinel_exists)
        hits = [f for f in result.findings if f.kind == "sink" and f.key.lower() == "core.fsmonitor"]
        self.assertTrue(
            any(f.severity == "critical" and f.file.endswith(".gitmodules") for f in hits),
            "the include of a file already read in submodule-only mode was skipped",
        )
        self.assertEqual(verdict_of(result)[1], 1)

    # 3b: file read in host scope (severities softened) then in repo scope ----
    def test_a_file_read_in_host_scope_is_still_read_in_repo_scope(self):
        base = self.fx.base
        home, c = os.path.join(base, "home"), os.path.join(base, "rootC")
        shared = os.path.join(base, "shared.cfg")
        write_file(shared, self.evil_cfg())
        write_file(os.path.join(home, ".gitconfig"), "[include]\n\tpath = %s\n" % self.fwd(shared))
        make_gitdir(os.path.join(c, ".git"), "[include]\n\tpath = %s\n" % self.fwd(shared))
        env = {"HOME": home, "USERPROFILE": home, "GIT_CONFIG_NOSYSTEM": "1"}
        with Guard():
            result = scan_host([c], self.ruleset, ceiling=base, environ=env)
        self.assertFalse(self.fx.sentinel_exists)
        sev = {f.severity for f in result.findings if f.kind == "sink" and f.key.lower() == "core.fsmonitor"}
        self.assertEqual(sev, {"review", "critical"}, "the repo-scope read was skipped because host scope saw the file first")
        self.assertEqual(verdict_of(result)[1], 1)

    # 4: /proc reached without the word /proc at the front --------------------
    @unittest.skipUnless(
        sys.platform.startswith("linux") and os.path.exists("/proc/self/mountinfo") and os.path.exists("/proc/self/status"),
        "needs Linux procfs",
    )
    def test_proc_is_refused_by_the_device_it_lives_on_not_by_its_name(self):
        fx = self.fx
        target = "/proc/self/status"
        link = os.path.join(fx.outside, "link.cfg")
        os.symlink(target, link)
        variants = {
            "dot-dot traversal": (os.path.relpath(target, start=fx.git_dir), target),
            "double leading slash": ("//proc/self/status", target),
            "symlink into proc": (self.fwd(link), link),
        }
        for label, (include_path, must_not_open) in variants.items():
            fx.write_config("[include]\n\tpath = %s\n" % include_path.replace("\\", "/"))
            result, guard = self.scan()
            self.assertTrue(
                any("pseudo-filesystem" in f.note for f in result.findings),
                "%s: procfs file was not refused by device" % label,
            )
            self.assertNotEqual(verdict_of(result)[1], 0, label)
            opened = [p.replace("\\", "/") for p in guard.opened]
            self.assertFalse(any(p.endswith("proc/self/status") for p in opened), "%s: procfs file was opened" % label)
            self.assertNotIn(self.fwd(must_not_open), opened, label)


if __name__ == "__main__":
    unittest.main()
