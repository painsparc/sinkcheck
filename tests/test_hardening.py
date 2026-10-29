"""Regression tests for the findings of the independent Phase 2 review.
Each test names the failure it prevents."""

import os
import threading
import unittest
from unittest import mock

from tests._support import Fixture, Guard, cfg_quote, make_gitdir, write_file

from sinkcheck import engine, safeio
from sinkcheck.engine import MAX_FINDINGS_PER_FILE, MAX_GITDIRS, MAX_INCLUDE_DEPTH, scan_target, verdict_of
from sinkcheck.ruleset import load_ruleset


def can_symlink(fx):
    probe = os.path.join(fx.base, "probe")
    try:
        os.symlink(fx.outside, probe, target_is_directory=True)
    except (OSError, NotImplementedError, AttributeError):
        return False
    return True


class HardeningTests(unittest.TestCase):
    def setUp(self):
        self.fx = Fixture()
        self.addCleanup(self.fx.cleanup)
        self.rs = load_ruleset()

    def scan(self, target=None, **kw):
        kw.setdefault("ceiling", self.fx.base)
        kw.setdefault("environ", {})
        return scan_target(target or self.fx.tree, self.rs, **kw)

    def payload_cfg(self):
        return "[core]\n\tfsmonitor = %s\n" % cfg_quote("/tmp/x")

    def scan_with_timeout(self, seconds=20, **kw):
        box = {}

        def work():
            try:
                box["r"] = self.scan(**kw)
            except BaseException as exc:
                box["e"] = exc

        t = threading.Thread(target=work, daemon=True)
        t.start()
        t.join(seconds)
        self.assertFalse(t.is_alive(), "scanner HUNG")
        if "e" in box:
            raise box["e"]
        return box["r"]

    # B1 -------------------------------------------------------------------
    def test_nul_is_a_safe_hookspath_only_on_windows(self):
        rule = {r.id: r for r in self.rs.rules}["core.hookspath"]
        with mock.patch.object(engine.os, "name", "posix"):
            self.assertTrue(engine.evaluate(rule, "nul")[0], "'nul' is an ordinary relative directory on POSIX")
            self.assertTrue(engine.evaluate(rule, "NUL")[0])
            self.assertFalse(engine.evaluate(rule, "/dev/null")[0])
        with mock.patch.object(engine.os, "name", "nt"):
            self.assertFalse(engine.evaluate(rule, "nul")[0])
            self.assertFalse(engine.evaluate(rule, "NUL")[0])

    # B2 -------------------------------------------------------------------
    def test_empty_dotgit_directory_does_not_mask_the_enclosing_repository(self):
        outer = os.path.join(self.fx.base, "outer")
        make_gitdir(os.path.join(outer, ".git"), self.payload_cfg())
        sub = os.path.join(outer, "sub")
        os.makedirs(os.path.join(sub, ".git"))  # empty: not a valid git directory
        r = self.scan(target=sub)
        self.assertEqual(verdict_of(r)[1], 1, "git would skip the empty .git and use the outer repository")
        self.assertTrue(any("not a valid git directory" in f.note for f in r.findings))

    def test_empty_dotgit_directory_does_not_stop_the_upward_walk(self):
        from sinkcheck.discover import find_enclosing

        outer = os.path.join(self.fx.base, "outer")
        make_gitdir(os.path.join(outer, ".git"))
        mid = os.path.join(outer, "mid")
        os.makedirs(os.path.join(mid, ".git"))
        deep = os.path.join(mid, "deep")
        os.makedirs(deep)
        found = find_enclosing(deep, ceiling=self.fx.base)
        self.assertEqual(os.path.normcase(os.path.realpath(found[0])), os.path.normcase(os.path.realpath(os.path.join(outer, ".git"))))

    # B3 -------------------------------------------------------------------
    def test_worktree_cap_is_reported_not_silent(self):
        make_gitdir(self.fx.git_dir, "[core]\n\tbare = false\n")
        for i in range(MAX_GITDIRS + 2):
            os.makedirs(os.path.join(self.fx.git_dir, "worktrees", "w%04d" % i))
        write_file(os.path.join(self.fx.git_dir, "worktrees", "w%04d" % (MAX_GITDIRS + 1), "config.worktree"), self.payload_cfg())
        r = self.scan()
        self.assertGreaterEqual(verdict_of(r)[1], 1)
        self.assertNotEqual(verdict_of(r), ("NOTHING FOUND", 0))
        self.assertTrue(any("more than" in f.note and "worktrees" in f.note for f in r.findings))

    @unittest.skipIf(os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0), "needs a non-root POSIX user")
    def test_unlistable_modules_subdirectory_is_reported(self):
        make_gitdir(self.fx.git_dir, "[core]\n\tbare = false\n")
        locked = os.path.join(self.fx.git_dir, "modules", "locked")
        os.makedirs(locked)
        os.chmod(locked, 0)
        self.addCleanup(os.chmod, locked, 0o700)
        r = self.scan()
        self.assertEqual(verdict_of(r)[1], 2)
        self.assertTrue(any("could not be listed" in f.note for f in r.findings))

    # M1 -------------------------------------------------------------------
    def test_symlinked_modules_hooks_and_worktrees_are_reported_and_not_followed(self):
        if not can_symlink(self.fx):
            self.skipTest("cannot create symlinks here")
        make_gitdir(self.fx.git_dir, "[core]\n\tbare = false\n")
        evil = os.path.join(self.fx.outside, "evil_modules")
        make_gitdir(os.path.join(evil, "sub"), self.payload_cfg())
        os.symlink(evil, os.path.join(self.fx.git_dir, "modules"), target_is_directory=True)
        hooks_target = os.path.join(self.fx.outside, "hooks_t")
        write_file(os.path.join(hooks_target, "pre-commit"), "#!/bin/sh\n")
        os.symlink(hooks_target, os.path.join(self.fx.git_dir, "hooks"), target_is_directory=True)
        wt_target = os.path.join(self.fx.outside, "wt_t", "w1")
        write_file(os.path.join(wt_target, "config.worktree"), self.payload_cfg())
        os.symlink(os.path.dirname(wt_target), os.path.join(self.fx.git_dir, "worktrees"), target_is_directory=True)
        r = self.scan()
        self.assertEqual(verdict_of(r)[1], 2, "not followed, and never clean")
        self.assertFalse(any(f.severity == "critical" for f in r.findings))
        notes = " ".join(f.note for f in r.findings)
        for word in ("modules is", "hooks is a symbolic link", "worktrees is"):
            self.assertIn(word, notes)
        self.assertFalse(any(f.kind == "hook" for f in r.findings), "hook names leaked from outside the tree")

    # M2 -------------------------------------------------------------------
    def test_nul_and_surrogates_in_paths_are_refused_not_raised(self):
        self.assertEqual(safeio.read_regular_file("a\x00b").status, "error")
        self.assertEqual(safeio.path_kind("a\x00b"), "other")
        self.assertEqual(safeio.read_regular_file("a\udcffb").status in ("error", "missing"), True)
        safeio.path_kind("a\udcffb")

    def test_unexpected_exception_in_one_step_does_not_hide_other_findings(self):
        make_gitdir(self.fx.git_dir, self.payload_cfg())
        write_file(os.path.join(self.fx.tree, "v", "x", "HEAD"), "ref: refs/heads/main\n")
        os.makedirs(os.path.join(self.fx.tree, "v", "x", "objects"))
        os.makedirs(os.path.join(self.fx.tree, "v", "x", "refs"))
        real = engine._collect_attributes

        def boom(*a, **k):
            raise RuntimeError("synthetic")

        with mock.patch.object(engine, "_collect_attributes", boom):
            write_file(os.path.join(self.fx.tree, ".gitattributes"), "* text\n")
            r = self.scan()
        self.assertEqual(verdict_of(r)[1], 1, "the critical finding survives the failed step")
        self.assertTrue(any("internal error (RuntimeError)" in f.note for f in r.findings))
        self.assertIs(engine._collect_attributes, real)

    # M3 -------------------------------------------------------------------
    def test_huge_conditional_and_long_paths_cannot_balloon_the_via_chain(self):
        make_gitdir(self.fx.git_dir, '[includeIf "gitdir:%s"]\n\tpath = i.cfg\n' % ("A" * 5000))
        write_file(os.path.join(self.fx.git_dir, "i.cfg"), self.payload_cfg())
        r = self.scan()
        self.assertEqual(verdict_of(r)[1], 1)
        self.assertTrue(r.findings)
        self.assertLess(max(len(f.via) for f in r.findings), 1100)

    def test_per_file_finding_cap_keeps_criticals_and_says_so(self):
        lines = ["[alias]\n"] + ["\ta%d = !b\n" % i for i in range(MAX_FINDINGS_PER_FILE + 500)]
        lines += ["[core]\n\tfsmonitor = /tmp/x\n"]
        make_gitdir(self.fx.git_dir, "".join(lines))
        r = self.scan()
        self.assertEqual(verdict_of(r)[1], 1)
        self.assertLessEqual(len(r.findings), MAX_FINDINGS_PER_FILE + 5)
        self.assertTrue(any("per-file cap" in f.note for f in r.findings))

    def test_total_cap_suppresses_noncritical_but_never_reads_clean(self):
        with mock.patch.object(engine, "MAX_TOTAL_FINDINGS", 3):
            make_gitdir(self.fx.git_dir, "[alias]\n" + "".join("\ta%d = !b\n" % i for i in range(10)))
            r = self.scan()
        self.assertGreater(r.suppressed, 0)
        self.assertEqual(verdict_of(r)[1], 2)

    # M4 -------------------------------------------------------------------
    def test_file_first_reached_too_deep_is_rescanned_when_reached_shallower(self):
        o = self.fx.outside
        names = ["c%d.cfg" % i for i in range(1, MAX_INCLUDE_DEPTH)]  # c1..c9
        fwd = lambda p: p.replace("\\", "/")
        f_path, g_path = os.path.join(o, "F.cfg"), os.path.join(o, "G.cfg")
        for i, n in enumerate(names):
            nxt = os.path.join(o, names[i + 1]) if i + 1 < len(names) else f_path
            write_file(os.path.join(o, n), "[include]\n\tpath = %s\n" % fwd(nxt))
        write_file(f_path, "[include]\n\tpath = %s\n" % fwd(g_path))
        write_file(g_path, self.payload_cfg())
        make_gitdir(self.fx.git_dir,
                    "[include]\n\tpath = %s\n\tpath = %s\n" % (fwd(os.path.join(o, names[0])), fwd(f_path)))
        r = self.scan()
        self.assertTrue(any("nesting deeper" in f.note for f in r.findings))
        self.assertEqual(verdict_of(r)[1], 1, "G is reachable at depth 2 through the direct include of F")

    def test_conditional_then_unconditional_reach_is_not_lost(self):
        o = self.fx.outside
        shared = os.path.join(o, "shared.cfg").replace("\\", "/")
        write_file(shared, self.payload_cfg())
        make_gitdir(self.fx.git_dir, '[includeIf "gitdir:/nowhere/"]\n\tpath = %s\n[include]\n\tpath = %s\n' % (shared, shared))
        r = self.scan()
        self.assertEqual(verdict_of(r)[1], 1)

    # m1 -------------------------------------------------------------------
    def test_includes_in_gitmodules_are_not_followed(self):
        make_gitdir(self.fx.git_dir, "[core]\n\tbare = false\n")
        write_file(os.path.join(self.fx.outside, "x.cfg"), self.payload_cfg())
        write_file(os.path.join(self.fx.tree, ".gitmodules"),
                   "[include]\n\tpath = %s\n" % os.path.join(self.fx.outside, "x.cfg").replace("\\", "/"))
        r = self.scan()
        self.assertFalse(any(f.severity == "critical" for f in r.findings))

    # m7 -------------------------------------------------------------------
    def test_oversize_attribute_file_is_reported(self):
        make_gitdir(self.fx.git_dir, "[core]\n\tbare = false\n")
        write_file(os.path.join(self.fx.tree, ".gitattributes"), "* text\n" * 50005)
        r = self.scan()
        self.assertTrue(any("attribute file has more than" in f.note for f in r.findings))
        # a cap that cuts a file short means part of it was not examined: incomplete, never review
        self.assertEqual(verdict_of(r)[1], 3)

    # m8 -------------------------------------------------------------------
    def test_malformed_git_config_count_is_review(self):
        make_gitdir(self.fx.git_dir, "[core]\n\tbare = false\n")
        r = self.scan(environ={"GIT_CONFIG_COUNT": "lots"})
        self.assertTrue(any("not an integer" in f.note for f in r.findings))

    # hostile filesystem objects ---------------------------------------------
    @unittest.skipUnless(hasattr(os, "mkfifo"), "no os.mkfifo")
    def test_fifos_in_every_read_position_do_not_hang(self):
        make_gitdir(self.fx.git_dir, "[core]\n\tbare = false\n")
        for rel in ("commondir", "config.worktree", os.path.join("info", "attributes")):
            p = os.path.join(self.fx.git_dir, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            os.mkfifo(p)
        os.mkfifo(os.path.join(self.fx.tree, ".gitmodules"))
        os.mkfifo(os.path.join(self.fx.tree, ".gitattributes"))
        fifo_include = os.path.join(self.fx.outside, "inc.fifo")
        os.mkfifo(fifo_include)
        write_file(self.fx.config_path, "[include]\n\tpath = %s\n" % fifo_include.replace("\\", "/"))
        r = self.scan_with_timeout()
        self.assertEqual(verdict_of(r)[1], 2)

    # UNC and device paths ---------------------------------------------------
    def test_unc_and_device_paths_are_refused_before_any_filesystem_call(self):
        unc = "//attacker.invalid/share/x.cfg"
        with mock.patch.object(safeio.os, "name", "nt"):
            for bad in (unc, "\\\\attacker.invalid\\share\\x", "\\\\.\\pipe\\x", "\\\\?\\C:\\x", "C:relative", "C:\\a\\b:stream"):
                self.assertTrue(safeio.unsafe_path_reason(bad), bad)
            for good in ("C:\\Users\\x", "C:/Users/x", "relative\\path", "dir/file"):
                self.assertEqual(safeio.unsafe_path_reason(good), "", good)
        make_gitdir(self.fx.git_dir, "[include]\n\tpath = %s\n" % unc)
        write_file(os.path.join(self.fx.tree, "sub", ".git"), "gitdir: \\\\attacker.invalid\\share\\r\n")
        with mock.patch.object(safeio.os, "name", "nt"), mock.patch.object(engine.os, "name", "nt"):
            with Guard() as guard:
                r = self.scan()
        self.assertFalse(
            any(p.replace("\\", "/").startswith("//") for p in guard.touched + guard.opened),
            "a UNC path reached the filesystem: %r" % [p for p in guard.touched + guard.opened if p.replace("\\", "/").startswith("//")],
        )
        self.assertTrue(any("refused before any filesystem call" in f.note for f in r.findings))
        self.assertEqual(verdict_of(r)[1], 2)

    def test_pseudo_filesystems_are_identified_by_device_not_by_path_text(self):
        sample = (
            "22 28 0:21 / /sys rw,nosuid,nodev,noexec,relatime shared:7 - sysfs sysfs rw\n"
            "23 28 0:22 / /proc rw,nosuid,nodev,noexec,relatime shared:12 - proc proc rw\n"
            "28 1 259:2 / / rw,relatime shared:1 - ext4 /dev/nvme0n1p2 rw\n"
            "garbage line without separator\n"
            "35 28 0:30 / /tmp rw - tmpfs tmpfs rw\n"
        )
        table = safeio._parse_mountinfo(sample)
        self.assertEqual(table[(0, 22)], {"proc"})
        self.assertEqual(table[(259, 2)], {"ext4"})
        self.assertIn("proc", safeio.classify_device(table, (0, 22)))
        self.assertIn("sysfs", safeio.classify_device(table, (0, 21)))
        self.assertEqual(safeio.classify_device(table, (259, 2)), "")
        self.assertEqual(safeio.classify_device(table, (0, 30)), "", "tmpfs is an ordinary filesystem")
        # unreadable mount table: an anonymous device cannot be vouched for, a real one can
        self.assertTrue(safeio.classify_device(None, (0, 5)))
        self.assertEqual(safeio.classify_device(None, (8, 1)), "")

    def test_path_text_alone_never_decides(self):
        for text in ("/proc/kmsg", "/proc", "/sys/kernel/x", "../../proc/x", "/processing/x", "/tmp/x"):
            self.assertEqual(safeio.unsafe_path_reason(text), "", text)
        # a leading double slash is a UNC path on Windows only (network/device guard, a
        # different rule from the /proc one); on POSIX it is an ordinary path
        if os.name == "nt":
            self.assertNotEqual(safeio.unsafe_path_reason("//proc/x"), "")
        else:
            self.assertEqual(safeio.unsafe_path_reason("//proc/x"), "")


if __name__ == "__main__":
    unittest.main()
