import contextlib
import io
import os
import unittest

from tests._support import Fixture, Guard, cfg_quote, clear_git_env, make_gitdir, write_file

from sinkcheck.cli import main
from sinkcheck.engine import TargetError
from sinkcheck.host import host_config_files, host_verdict, scan_host
from sinkcheck.report import render_text
from sinkcheck.ruleset import load_ruleset


def run_cli(argv, env=None):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


class HostTests(unittest.TestCase):
    def setUp(self):
        self.fx = Fixture()
        self.addCleanup(self.fx.cleanup)
        self.rs = load_ruleset()
        self.home = os.path.join(self.fx.base, "home")
        os.makedirs(self.home)
        self.env = {"HOME": self.home, "USERPROFILE": self.home, "GIT_CONFIG_NOSYSTEM": "1"}

    def gitconfig(self, text):
        write_file(os.path.join(self.home, ".gitconfig"), text)

    def audit(self, roots=(), env=None):
        return scan_host(list(roots), self.rs, ceiling=self.fx.base, environ=env or self.env)

    # locating files --------------------------------------------------------
    def test_global_files_and_overrides_are_located(self):
        files, notes = host_config_files(self.env)
        paths = [f[0] for f in files]
        self.assertIn(os.path.join(self.home, ".gitconfig"), paths)
        self.assertTrue(any("NOSYSTEM" in n for n in notes))
        files, _ = host_config_files({"GIT_CONFIG_GLOBAL": "/x/y", "GIT_CONFIG_SYSTEM": "/x/z", "HOME": self.home})
        self.assertEqual([f[0] for f in files], ["/x/z", "/x/y"])  # overrides replace the defaults
        files, notes = host_config_files({"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "yes"})
        self.assertEqual(files, [])
        self.assertTrue(any("null device" in n for n in notes))

    # verdict vocabulary -----------------------------------------------------
    def test_empty_host_is_nothing_found_with_hardening_hint_only(self):
        r = self.audit()
        self.assertEqual(host_verdict(r), ("NOTHING FOUND", 0))
        self.assertTrue(any(f.kind == "hardening" and f.key == "safe.bareRepository" for f in r.findings))
        self.assertIn("git config --global safe.bareRepository explicit", render_text(r, verdict=host_verdict(r)))

    def test_bare_repository_explicit_removes_the_hint(self):
        self.gitconfig("[safe]\n\tbareRepository = explicit\n")
        r = self.audit()
        self.assertFalse(any(f.kind == "hardening" and f.key == "safe.bareRepository" for f in r.findings))

    def test_global_fsmonitor_command_is_review_not_critical(self):
        self.gitconfig("[core]\n\tfsmonitor = %s\n" % cfg_quote("/usr/bin/watchman-hook"))
        r = self.audit()
        sinks = [f for f in r.findings if f.kind == "sink" and f.key == "core.fsmonitor"]
        self.assertEqual([f.severity for f in sinks], ["review"])
        self.assertIn("applies to every repository", sinks[0].note)
        self.assertEqual(host_verdict(r)[1], 2)

    def test_well_known_tool_values_are_info_in_host_scope_but_stay_listed(self):
        self.gitconfig(
            "[filter \"lfs\"]\n\tclean = git-lfs clean -- %f\n\tsmudge = git-lfs smudge -- %f\n"
            "\tprocess = git-lfs filter-process\n[diff \"astextplain\"]\n\ttextconv = astextplain\n"
        )
        r = self.audit()
        sinks = [f for f in r.findings if f.kind == "sink"]
        self.assertEqual(len(sinks), 4)
        self.assertEqual({f.severity for f in sinks}, {"info"})
        self.assertTrue(all("widely used tool" in f.note for f in sinks))
        self.assertEqual(host_verdict(r)[1], 0)

    def test_lookalike_values_are_not_benign(self):
        self.gitconfig(
            "[filter \"lfs\"]\n\tclean = git-lfs clean -- %f && curl x\n\tsmudge = /tmp/git-lfs smudge -- %f\n"
            "[diff \"astextplain\"]\n\ttextconv = astextplain --evil\n"
        )
        r = self.audit()
        self.assertEqual([f.severity for f in r.findings if f.kind == "sink"], ["review", "review", "review"])
        self.assertEqual(host_verdict(r)[1], 2)

    def test_allowlist_is_exact_and_case_sensitive(self):
        self.gitconfig(
            "[filter \"lfs\"]\n\tclean = \u00a0git-lfs clean -- %f\n\tsmudge = GIT-LFS SMUDGE -- %f\n"
            "[diff \"a\"]\n\ttextconv = ASTEXTPLAIN\n"
        )
        r = self.audit()
        self.assertEqual([f.severity for f in r.findings if f.kind == "sink"], ["review", "review", "review"])

    def test_nul_is_the_null_device_only_on_windows(self):
        files, notes = host_config_files({"GIT_CONFIG_GLOBAL": "nul", "GIT_CONFIG_NOSYSTEM": "1", "HOME": self.home})
        if os.name == "nt":
            self.assertEqual(files, [])
        else:
            self.assertEqual([f[0] for f in files], ["nul"])

    def test_xdg_is_read_before_home_gitconfig_so_home_wins(self):
        xdg = os.path.join(self.home, "xdg")
        write_file(os.path.join(xdg, "git", "config"), "[safe]\n\tbareRepository = explicit\n")
        self.gitconfig("[safe]\n\tbareRepository = all\n")
        env = dict(self.env, XDG_CONFIG_HOME=xdg)
        r = self.audit(env=env)
        self.assertTrue(any(f.kind == "hardening" and f.key == "safe.bareRepository" and f.value == "all" for f in r.findings))

    def test_unlocated_home_is_needs_review_not_clean(self):
        r = self.audit(env={"GIT_CONFIG_NOSYSTEM": "1"})
        self.assertEqual(host_verdict(r)[1], 2)

    def test_benign_values_never_soften_repo_scope(self):
        fx = Fixture()
        self.addCleanup(fx.cleanup)
        fx.make_bare_minimum_gitdir()
        fx.write_config("[filter \"lfs\"]\n\tclean = git-lfs clean -- %f\n")
        from sinkcheck.engine import scan_target
        r = scan_target(fx.tree, self.rs, ceiling=fx.base, environ={})
        self.assertEqual([f.severity for f in r.findings if f.kind == "sink"], ["critical"])

    def test_ordinary_personal_settings_are_info_only(self):
        self.gitconfig("[credential]\n\thelper = manager\n[core]\n\teditor = vim\n\tpager = less\n[alias]\n\tco = !git checkout\n")
        r = self.audit()
        self.assertEqual(host_verdict(r), ("NOTHING FOUND", 0))
        self.assertTrue(any(f.key == "credential.helper" and f.severity == "info" for f in r.findings))

    def test_safe_directory_star_is_honoured_in_global_scope_and_flagged(self):
        self.gitconfig("[safe]\n\tdirectory = *\n")
        r = self.audit()
        star = [f for f in r.findings if f.rule is not None and f.rule.id == "safe.directory.star"]
        self.assertEqual([f.severity for f in star], ["review"])
        self.assertIn("honors", star[0].note)
        self.assertEqual(host_verdict(r)[1], 2)

    def test_global_fsmonitor_false_gets_the_does_not_protect_note(self):
        self.gitconfig("[core]\n\tfsmonitor = false\n")
        r = self.audit()
        hint = [f for f in r.findings if f.kind == "hardening" and f.key == "core.fsmonitor"]
        self.assertEqual(len(hint), 1)
        self.assertIn("does NOT protect", hint[0].note)
        self.assertEqual(hint[0].verification, "two-source")
        self.assertEqual(len(set(hint[0].sources)), 2)

    def test_global_include_chain_is_followed_in_host_scope(self):
        inc = os.path.join(self.home, "work.gitconfig")
        write_file(inc, "[core]\n\tfsmonitor = %s\n" % cfg_quote("/opt/x"))
        self.gitconfig("[include]\n\tpath = %s\n" % inc.replace("\\", "/"))
        r = self.audit()
        s = [f for f in r.findings if f.key == "core.fsmonitor"]
        self.assertEqual([f.severity for f in s], ["review"])
        self.assertIn("include at", s[0].via)

    # roots -----------------------------------------------------------------
    def test_roots_find_nested_repositories_without_calling_them_findings(self):
        code = os.path.join(self.fx.base, "code")
        for name in ("a", "b"):
            make_gitdir(os.path.join(code, name, ".git"), "[core]\n\tbare = false\n")
        r = self.audit(roots=[code])
        self.assertFalse(any(f.severity == "review" for f in r.findings))
        self.assertEqual(host_verdict(r)[1], 0)

    def test_planted_critical_in_a_root_is_critical(self):
        code = os.path.join(self.fx.base, "code")
        make_gitdir(os.path.join(code, "evil", ".git"), "[core]\n\tfsmonitor = %s\n" % cfg_quote("/tmp/x"))
        r = self.audit(roots=[code])
        name, exit_code = host_verdict(r)
        self.assertEqual(exit_code, 1)
        self.assertIn("CRITICAL SINK FOUND", name)

    def test_buried_bare_repo_under_a_root_is_still_flagged(self):
        code = os.path.join(self.fx.base, "code")
        make_gitdir(os.path.join(code, "proj", "vendor", "x"), "[core]\n\tbare = false\n")
        r = self.audit(roots=[code])
        self.assertTrue(any("buried" in f.note for f in r.findings))
        self.assertEqual(host_verdict(r)[1], 2)

    def test_bad_root_is_a_target_error(self):
        with self.assertRaises(TargetError):
            self.audit(roots=[os.path.join(self.fx.base, "nope")])

    def test_environment_is_audited(self):
        env = dict(self.env, GIT_DIR="/elsewhere")
        r = self.audit(env=env)
        self.assertTrue(any(f.kind == "env" and f.key == "GIT_DIR" for f in r.findings))

    # report + cli ------------------------------------------------------------
    def test_report_has_the_standing_lines_and_names_what_was_not_examined(self):
        text = render_text(self.audit(), verdict=("NOTHING FOUND", 0))
        self.assertIn("Unaffiliated:", text)
        self.assertIn("not a clean bill of health", text)
        self.assertIn("installed editor extensions", text)
        text.encode("ascii")

    def test_cli_audit_exit_codes(self):
        code = os.path.join(self.fx.base, "code")
        make_gitdir(os.path.join(code, "e", ".git"), "[core]\n\tfsmonitor = %s\n" % cfg_quote("/tmp/x"))
        # The real user's HOME, XDG_CONFIG_HOME and GIT_* variables must not leak into the result.
        self.addCleanup(clear_git_env().stop)  # restores os.environ wholesale on stop
        os.environ.update({
            "HOME": self.home,
            "USERPROFILE": self.home,
            "XDG_CONFIG_HOME": os.path.join(self.home, "xdg"),
            "GIT_CONFIG_NOSYSTEM": "1",
        })
        self.assertEqual(run_cli(["audit", "--ceiling", self.fx.base])[0], 0)
        c, out, _ = run_cli(["audit", "--root", code, "--ceiling", self.fx.base])
        self.assertEqual(c, 1)
        self.assertIn("VERDICT: CRITICAL SINK FOUND", out)
        self.assertEqual(run_cli(["audit", "--root", os.path.join(self.fx.base, "nope")])[0], 3)

    def test_audit_under_guard_writes_and_runs_nothing(self):
        self.gitconfig("[core]\n\tfsmonitor = %s\n" % cfg_quote(self.fx.payload_command))
        with Guard():
            r = self.audit()
            render_text(r, verdict=host_verdict(r))
        self.assertFalse(self.fx.sentinel_exists)


if __name__ == "__main__":
    unittest.main()
