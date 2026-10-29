import contextlib
import io
import os
import unittest

from tests._support import Fixture, cfg_quote, clear_git_env

from sinkcheck.cli import main


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


class CliTests(unittest.TestCase):
    def setUp(self):
        self.addCleanup(clear_git_env().stop)
        self.fx = Fixture()
        self.addCleanup(self.fx.cleanup)
        self.fx.make_bare_minimum_gitdir()

    def test_exit_0_when_nothing_found(self):
        self.fx.write_config("[core]\n\tbare = false\n")
        code, out, _ = run(["scan", self.fx.tree])
        self.assertEqual(code, 0)
        self.assertIn("VERDICT: NOTHING FOUND", out)

    def test_exit_1_on_critical(self):
        self.fx.write_config("[core]\n\tfsmonitor = %s\n" % cfg_quote("/tmp/x"))
        code, out, _ = run(["scan", self.fx.tree])
        self.assertEqual(code, 1)
        self.assertIn("VERDICT: CRITICAL", out)
        self.assertIn("[CRITICAL]", out)

    def test_exit_2_on_review(self):
        self.fx.write_config("[include]\n\tpath = elsewhere\n")
        code, out, _ = run(["scan", self.fx.tree])
        self.assertEqual(code, 2)
        self.assertIn("VERDICT: NEEDS REVIEW", out)

    def test_exit_3_on_tool_and_usage_errors(self):
        self.assertEqual(run(["scan", os.path.join(self.fx.base, "nope")])[0], 3)
        self.assertEqual(run([])[0], 3)
        self.assertEqual(run(["scan"])[0], 3)
        self.assertEqual(run(["scan", self.fx.tree, "--bogus"])[0], 3)
        self.assertEqual(run(["scan", self.fx.tree, "--ruleset", os.path.join(self.fx.base, "no.json")])[0], 3)

    def test_disclaimer_sits_directly_under_every_verdict(self):
        for text in ("[core]\n\tbare = false\n", "[core]\n\tfsmonitor = x\n", "[include]\n\tpath = y\n"):
            self.fx.write_config(text)
            _, out, _ = run(["scan", self.fx.tree])
            lines = out.splitlines()
            idx = next(i for i, l in enumerate(lines) if l.startswith("VERDICT:"))
            self.assertIn("not a clean bill of health", lines[idx + 1])

    def test_unaffiliated_line_and_not_examined_always_present(self):
        self.fx.write_config("[core]\n\tbare = false\n")
        _, out, _ = run(["scan", self.fx.tree])
        self.assertIn("Unaffiliated:", out)
        self.assertIn("NOT examined by this build:", out)
        self.assertNotIn("NOT the publishable cut", out)

    def test_hostile_values_cannot_inject_into_terminal(self):
        evil = "\x1b[31mRED\x1b]0;title\x07 ‮ reversed ​ zero-width"
        self.fx.write_config("[core]\n\tfsmonitor = %s\n" % cfg_quote(evil))
        code, out, _ = run(["scan", self.fx.tree])
        self.assertEqual(code, 1)
        self.assertNotIn("\x1b", out)
        self.assertNotIn("\x07", out)
        self.assertNotIn("‮", out)
        self.assertNotIn("​", out)
        out.encode("ascii")  # must be pure ASCII

    def test_ceiling_option_is_accepted_and_bad_ceiling_value_is_not_fatal(self):
        self.fx.write_config("[core]\n\tbare = false\n")
        code, _, _ = run(["scan", self.fx.tree, "--ceiling", self.fx.base])
        self.assertEqual(code, 0)
        code, _, _ = run(["scan", self.fx.tree, "--ceiling", os.path.join(self.fx.base, "nope")])
        self.assertEqual(code, 0)

    def test_version_flag(self):
        code, out, _ = run(["--version"])
        self.assertEqual(code, 0)
        self.assertIn("sinkcheck", out)


if __name__ == "__main__":
    unittest.main()
