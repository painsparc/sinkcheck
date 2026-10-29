import contextlib
import io
import json
import os
import subprocess
import sys
import unittest

from tests._support import ROOT, Fixture, Guard, cfg_quote, clear_git_env, snapshot

from sinkcheck.cli import main


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


class OutputTests(unittest.TestCase):
    def setUp(self):
        self.addCleanup(clear_git_env().stop)
        self.fx = Fixture()
        self.addCleanup(self.fx.cleanup)
        self.fx.make_bare_minimum_gitdir()

    def base(self, cmd="scan"):
        a = [cmd, self.fx.tree, "--ceiling", self.fx.base]
        return a + ["--no-detect"] if cmd == "preflight" else a

    def test_json_scan_shape_and_ascii(self):
        evil = "\x1b[31mRED\x1b]0;t\x07 ‮ rev"
        self.fx.write_config("[core]\n\tfsmonitor = %s\n" % cfg_quote(evil))
        code, out, _ = run(self.base() + ["--format", "json"])
        self.assertEqual(code, 1)
        out.encode("ascii")
        d = json.loads(out)
        self.assertEqual(d["schema"], 1)
        self.assertEqual(d["mode"], "scan")
        self.assertEqual(d["verdict"]["name"], "CRITICAL")
        self.assertEqual(d["verdict"]["exit_code"], 1)
        self.assertIn("clean bill of health", d["disclaimer"])
        self.assertIn("Unaffiliated", d["unaffiliated"])
        self.assertTrue(d["not_examined"])
        f = [x for x in d["findings"] if x["rule_id"] == "core.fsmonitor"][0]
        self.assertEqual(f["severity"], "critical")
        self.assertIn(f["evidence"]["verification"], ("two-source", "single-source", "unverified"))
        self.assertNotIn("\x1b", f["value"])
        self.assertNotIn("‮", f["value"])

    def test_json_preflight_and_audit(self):
        self.fx.write_config("[core]\n\tbare = false\n")
        code, out, _ = run(self.base("preflight") + ["--format", "json", "--agent", "qwen-code=0.22.3"])
        d = json.loads(out)
        self.assertEqual(code, 2)
        self.assertEqual(d["mode"], "preflight")
        row = [r for r in d["agents"]["rows"] if r["agent_id"] == "qwen-code"][0]
        self.assertEqual(row["findings"][0]["assessment"]["level"], "affected")
        code, out, _ = run(["audit", "--format", "json", "--ceiling", self.fx.base])
        self.assertEqual(json.loads(out)["mode"], "audit")
        self.assertIn(code, (0, 1, 2))

    def test_fail_on_critical_maps_review_to_zero_without_changing_the_verdict(self):
        self.fx.write_config("[include]\n\tpath = nowhere\n")
        code, out, _ = run(self.base())
        self.assertEqual(code, 2)
        code, out, _ = run(self.base() + ["--fail-on", "critical"])
        self.assertEqual(code, 0)
        self.assertIn("VERDICT: NEEDS REVIEW", out)
        self.assertIn("A needs-review result is not a clean result", out)
        code, out, _ = run(self.base() + ["--fail-on", "critical", "--format", "json"])
        v = json.loads(out)["verdict"]
        self.assertEqual((code, v["name"], v["exit_code"], v["exit_code_before_fail_on"]), (0, "NEEDS REVIEW", 0, 2))

    def test_fail_on_critical_never_maps_critical_or_errors(self):
        self.fx.write_config("[core]\n\tfsmonitor = %s\n" % cfg_quote("/tmp/x"))
        self.assertEqual(run(self.base() + ["--fail-on", "critical"])[0], 1)
        self.assertEqual(run(["scan", os.path.join(self.fx.base, "nope"), "--fail-on", "critical"])[0], 3)

    def test_remediation_text_is_instruction_only(self):
        self.fx.write_config("[core]\n\tfsmonitor = %s\n" % cfg_quote("/tmp/x"))
        _, out, _ = run(self.base())
        self.assertIn("this tool never runs any of it", out)
        self.assertIn("disposable container or VM", out)

    def test_every_mode_leaves_the_tree_untouched_and_touches_no_network(self):
        self.fx.write_config("[core]\n\tfsmonitor = %s\n[include]\n\tpath = x\n" % cfg_quote(self.fx.payload_command))
        before = snapshot(self.fx.base)
        with Guard():
            for argv in (
                self.base(),
                self.base() + ["--format", "json"],
                self.base("preflight") + ["--agent", "goose=1.44.0"],
                ["audit", "--root", self.fx.tree, "--ceiling", self.fx.base],
            ):
                run(argv)
        self.assertEqual(before, snapshot(self.fx.base))
        self.assertFalse(self.fx.sentinel_exists)


class EntrypointTests(unittest.TestCase):
    """Real process, real exit codes. The test harness may use subprocess; the package may not."""

    def setUp(self):
        self.fx = Fixture()
        self.addCleanup(self.fx.cleanup)
        self.fx.make_bare_minimum_gitdir()

    def py(self, *args):
        env = {k: v for k, v in os.environ.items() if not k.upper().startswith("GIT_")}
        return subprocess.run([sys.executable, "-m", "sinkcheck"] + list(args), cwd=ROOT, env=env,
                              capture_output=True, text=True, timeout=120)

    def test_exit_codes_through_a_real_process(self):
        self.fx.write_config("[core]\n\tbare = false\n")
        self.assertEqual(self.py("scan", self.fx.tree, "--ceiling", self.fx.base).returncode, 0)
        self.fx.write_config("[core]\n\tfsmonitor = %s\n" % cfg_quote("/tmp/x"))
        self.assertEqual(self.py("scan", self.fx.tree, "--ceiling", self.fx.base).returncode, 1)
        self.assertEqual(self.py("scan", os.path.join(self.fx.base, "nope")).returncode, 3)
        self.assertEqual(self.py().returncode, 3)

    def test_running_the_tool_imports_no_process_or_network_modules(self):
        code = (
            "import sys, runpy\n"
            "sys.argv = ['sinkcheck', 'scan', %r, '--ceiling', %r]\n"
            "try:\n"
            "    runpy.run_module('sinkcheck', run_name='__main__')\n"
            "except SystemExit:\n"
            "    pass\n"
            "bad = [m for m in ('subprocess', 'socket', 'ssl', 'urllib.request', 'http.client', 'ctypes') if m in sys.modules]\n"
            "print('BAD:' + ','.join(bad))\n"
        ) % (self.fx.tree, self.fx.base)
        self.fx.write_config("[core]\n\tbare = false\n")
        env = {k: v for k, v in os.environ.items() if not k.upper().startswith("GIT_")}
        r = subprocess.run([sys.executable, "-c", code], cwd=ROOT, env=env, capture_output=True, text=True, timeout=120)
        self.assertIn("BAD:\n", r.stdout.replace("\r", "") + "\n", r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main()
