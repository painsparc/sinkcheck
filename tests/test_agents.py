import contextlib
import datetime
import io
import os
import unittest

from tests._support import Fixture, Guard, cfg_quote, clear_git_env, make_gitdir, write_file

from sinkcheck import agents
from sinkcheck.cli import main
from sinkcheck.preflight import preflight_verdict, render_preflight, run_preflight
from sinkcheck.ruleset import load_ruleset


def run_cli(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


class AgentDataTests(unittest.TestCase):
    def setUp(self):
        self.data = agents.load_agents()
        self.by_id = {f.id: f for a in self.data.agents for f in a.findings}

    def test_eight_findings_across_seven_agents(self):
        self.assertEqual(len(self.data.agents), 7)
        manifold = [f for f in self.by_id.values() if any(e.origin == "manifold-disclosure" for e in f.evidence)
                    or f.id == "hermes-fsmonitor"]
        self.assertEqual(len(manifold), 8)
        self.assertIn("hermes-filter-drivers", self.by_id)  # a related fix, not a Manifold finding

    def test_every_finding_cites_evidence_and_is_dated(self):
        for f in self.by_id.values():
            self.assertTrue(f.evidence, f.id)
            self.assertTrue(agents.parse_date(f.status_date), f.id)
            for e in f.evidence:
                self.assertTrue(e.url.startswith("https://"), f.id)

    def test_nothing_after_the_first_disclosure_claims_two_sources(self):
        # Honest labelling: all current rows rest on one origin each in this data set.
        for f in self.by_id.values():
            if f.verification == "two-source":
                self.fail("%s claims two independent origins; add the second origin's evidence deliberately" % f.id)

    def test_unknown_status_rows_are_gated_and_caveated(self):
        for f in self.by_id.values():
            if f.status != "fixed":
                self.assertTrue(f.gate, f.id)
                self.assertIn("UNVERIFIED", f.caveat, f.id)

    def test_ultrareview_is_single_source_and_labelled_unverified(self):
        f = self.by_id["claude-code-ultrareview"]
        self.assertEqual(f.verification, "single-source")
        self.assertIn("UNVERIFIED", f.caveat)
        self.assertTrue(f.gate)

    def test_rejects_bad_data(self):
        import json

        base = os.path.join(os.path.dirname(agents.__file__), "data", "agents.json")
        fx = Fixture()
        self.addCleanup(fx.cleanup)
        with open(base, "rb") as fh:
            raw = json.loads(fh.read().decode("utf-8"))
        raw["agents"][0]["findings"][0]["evidence"][0]["origin"] = "nope"
        p = os.path.join(fx.base, "bad.json")
        with open(p, "w") as fh:
            json.dump(raw, fh)
        with self.assertRaises(agents.AgentsError):
            agents.load_agents(p)
        with self.assertRaises(agents.AgentsError):
            agents.load_agents(os.path.join(fx.base, "missing.json"))


class VersionTests(unittest.TestCase):
    def test_parse_and_compare(self):
        self.assertEqual(agents.parse_version("v2.1.310"), (2, 1, 310))
        self.assertEqual(agents.parse_version("2.1.310-beta.1"), (2, 1, 310, -1))
        self.assertEqual(agents._cmp(agents.parse_version("2.1.196-rc1"), agents.parse_version("2.1.196")), -1)
        self.assertIsNone(agents.parse_version("1.0 anything"))
        self.assertIsNone(agents.parse_version("9" * 5000))
        self.assertIsNone(agents.parse_version("1.2.3\x1b]0;x\x07"))
        self.assertIsNone(agents.parse_version("latest"))
        self.assertIsNone(agents.parse_version(None))
        self.assertEqual(agents._cmp((1, 44), (1, 44, 0)), 0)
        self.assertEqual(agents._cmp((1, 43, 9), (1, 44, 0)), -1)
        self.assertEqual(agents._cmp((2, 0), (1, 99, 99)), 1)


class AssessTests(unittest.TestCase):
    def setUp(self):
        data = agents.load_agents()
        self.f = {x.id: x for a in data.agents for x in a.findings}

    def test_fsmonitor_fix_boundary(self):
        f = self.f["claude-code-fsmonitor"]
        self.assertEqual(agents.assess(f, "2.1.195").level, "affected")
        self.assertEqual(agents.assess(f, "2.1.196").level, "ok")
        self.assertFalse(agents.assess(f, "2.1.196").floors_review)
        self.assertEqual(agents.assess(f, None).level, "version-unknown")

    def test_ultrareview_is_unpatched_and_a_later_version_is_unknown(self):
        f = self.f["claude-code-ultrareview"]
        self.assertEqual(f.status, "unpatched")
        self.assertEqual(agents.assess(f, "2.1.252").level, "affected")
        a = agents.assess(f, "2.1.309")
        self.assertEqual(a.level, "unknown")  # the trust check is not a confirmed fix
        self.assertTrue(a.floors_review)

    def test_codex_names_no_cve_for_manifolds_finding(self):
        f = self.f["codex-fsmonitor"]
        self.assertEqual(f.fixed_in, "")
        self.assertEqual({e.origin for e in f.context},
                         {"openai-cve-2026-19592", "openai-cve-2026-19590", "openai-cve-2026-19593"})
        self.assertEqual(f.verification, "single-source")  # related CVEs are context, not verification

    def test_hermes_boundaries(self):
        fs, flt = self.f["hermes-fsmonitor"], self.f["hermes-filter-drivers"]
        self.assertEqual(agents.assess(fs, "0.21.0").level, "affected")
        self.assertEqual(agents.assess(fs, "0.21.1").level, "ok")
        self.assertEqual(agents.assess(flt, "0.21.5").level, "affected")
        self.assertEqual(agents.assess(flt, "0.21.6").level, "ok")

    def test_unknown_status_rows(self):
        f = self.f["qwen-code-fsmonitor"]
        self.assertEqual(agents.assess(f, "0.19.6").level, "affected")
        self.assertEqual(agents.assess(f, "0.22.3").level, "affected")
        self.assertEqual(agents.assess(f, "0.30.0").level, "unknown")
        self.assertTrue(agents.assess(f, "0.30.0").floors_review)

    def test_fixed_without_version_info_cannot_be_checked(self):
        a = agents.assess(self.f["codex-fsmonitor"], "9.9.9")
        self.assertEqual(a.level, "fixed-no-version-info")
        self.assertTrue(a.floors_review)  # a version that cannot be checked never reads as clean

    def test_prerelease_of_the_fix_version_is_not_fixed(self):
        f = self.f["goose-review"]
        self.assertEqual(agents.assess(f, "1.44.0-rc1").level, "affected")
        self.assertEqual(agents.assess(f, "1.44.0").level, "ok")

    def test_goose_boundary(self):
        f = self.f["goose-review"]
        self.assertEqual(agents.assess(f, "1.43.9").level, "affected")
        self.assertEqual(agents.assess(f, "1.44.0").level, "ok")


class DetectionTests(unittest.TestCase):
    def setUp(self):
        self.fx = Fixture()
        self.addCleanup(self.fx.cleanup)
        self.data = agents.load_agents()

    def test_detects_from_package_json_without_running_anything(self):
        root = os.path.join(self.fx.base, "prefix")
        write_file(
            os.path.join(root, "lib", "node_modules", "@anthropic-ai", "claude-code", "package.json"),
            '{"name": "@anthropic-ai/claude-code", "version": "2.1.252"}',
        )
        found = agents.detect_installed(self.data, {"npm_config_prefix": root})
        self.assertEqual(found["claude-code"][0][0], "2.1.252")

    def test_detection_under_guard_reads_package_json_and_never_runs_the_agent(self):
        """Preflight with detection on, under the runtime Guard (forbidden calls raise).
        A booby-trapped agent binary sits next to its package.json; it must never run,
        and outside the scanned tree the only files opened are package.json files."""
        root = os.path.join(self.fx.base, "prefix")
        pkg = os.path.join(root, "lib", "node_modules", "@anthropic-ai", "claude-code")
        write_file(os.path.join(pkg, "package.json"), '{"name": "@anthropic-ai/claude-code", "version": "2.1.252"}')
        trap = os.path.join(pkg, "cli.js")
        write_file(trap, "require('fs').writeFileSync(%r, 'ran')\n" % self.fx.sentinel)
        bindir = os.path.join(root, "bin")
        write_file(os.path.join(bindir, "claude"), "#!/bin/sh\ntouch %s\n" % cfg_quote(self.fx.sentinel))
        os.chmod(os.path.join(bindir, "claude"), 0o755)
        make_gitdir(os.path.join(self.fx.tree, ".git"), "[core]\n\tbare = false\n")
        rs = load_ruleset()
        env = {"npm_config_prefix": root, "PATH": bindir}
        with Guard() as guard:
            pre = run_preflight(self.fx.tree, rs, self.data, ceiling=self.fx.base, environ=env, detect=True)
            text = render_preflight(pre)
        self.assertFalse(self.fx.sentinel_exists)
        self.assertIn("2.1.252", text)
        tree = os.path.normcase(os.path.realpath(self.fx.tree))
        outside_tree = [p for p in guard.opened
                        if not os.path.normcase(os.path.realpath(p)).startswith(tree)
                        and not p.startswith(os.path.dirname(agents.DEFAULT_PATH))
                        and p != "/proc/self/mountinfo"]  # read once per process for the pseudo-fs check
        self.assertTrue(outside_tree)
        self.assertTrue(all(os.path.basename(p) == "package.json" for p in outside_tree), outside_tree)

    def test_ignores_wrong_name_bad_json_and_non_string_version(self):
        root = os.path.join(self.fx.base, "prefix")
        base = os.path.join(root, "lib", "node_modules")
        write_file(os.path.join(base, "@anthropic-ai", "claude-code", "package.json"), '{"name": "evil", "version": "9.9.9"}')
        write_file(os.path.join(base, "@openai", "codex", "package.json"), "{not json")
        write_file(os.path.join(base, "@qwen-code", "qwen-code", "package.json"), '{"name": "@qwen-code/qwen-code", "version": 5}')
        self.assertEqual(agents.detect_installed(self.data, {"npm_config_prefix": root}), {})

    def test_declared_versions_validate(self):
        got = agents.parse_declared(["goose=1.44.0"], self.data)
        self.assertEqual(got["goose"][0][0], "1.44.0")
        for bad in ("goose", "nope=1.0", "goose=latest"):
            with self.assertRaises(agents.AgentsError):
                agents.parse_declared([bad], self.data)


class PreflightTests(unittest.TestCase):
    def setUp(self):
        self.addCleanup(clear_git_env().stop)
        self.fx = Fixture()
        self.addCleanup(self.fx.cleanup)
        self.fx.make_bare_minimum_gitdir()
        self.fx.write_config("[core]\n\tbare = false\n")
        self.rs = load_ruleset()
        self.data = agents.load_agents()

    def pre(self, declared=None, today=None, detect=False):
        d = agents.parse_declared(declared or [], self.data)
        return run_preflight(self.fx.tree, self.rs, self.data, declared=d, ceiling=self.fx.base,
                             environ={}, today=today, detect=detect)

    def test_clean_tree_no_agent_named_stays_clean_but_says_nothing_was_named(self):
        pre = self.pre()
        self.assertEqual(preflight_verdict(pre), ("NOTHING FOUND", 0))
        self.assertIn("No agent was named or detected", render_preflight(pre))

    def test_clean_tree_with_fixed_goose_is_clean(self):
        self.assertEqual(preflight_verdict(self.pre(["goose=1.44.0"])), ("NOTHING FOUND", 0))

    def test_clean_tree_with_affected_agent_needs_review(self):
        self.assertEqual(preflight_verdict(self.pre(["goose=1.43.0"]))[1], 2)

    def test_unverified_ultrareview_fix_is_never_a_clean_verdict(self):
        pre = self.pre(["claude-code=2.1.310"])
        self.assertEqual(preflight_verdict(pre)[1], 2)
        self.assertIn("UNVERIFIED", render_preflight(pre))

    def test_unknown_status_agent_needs_review(self):
        self.assertEqual(preflight_verdict(self.pre(["grok-build=1.0.13"]))[1], 2)

    def test_patched_agent_never_clears_a_tree_with_findings(self):
        self.fx.write_config("[core]\n\tfsmonitor = %s\n" % cfg_quote("/tmp/x"))
        pre = self.pre(["goose=1.44.0"])
        self.assertEqual(preflight_verdict(pre), ("CRITICAL", 1))
        text = render_preflight(pre)
        self.assertIn("this tree carries: core.fsmonitor", text)
        self.assertIn("does not clear a tree that has findings", text)

    def test_report_is_dated_and_carries_vendor_and_unaffiliated_lines(self):
        text = render_preflight(self.pre(["qwen-code=0.22.3"]))
        self.assertIn("as of 2026-10-29; verify with your vendor", text)
        self.assertIn("Unaffiliated:", text)
        lines = text.splitlines()
        idx = next(i for i, l in enumerate(lines) if l.startswith("VERDICT:"))
        self.assertIn("not a clean bill of health", lines[idx + 1])
        text.encode("ascii")

    def test_stale_table_is_called_out(self):
        far = datetime.date(2027, 6, 1)
        pre = self.pre(today=far)
        self.assertTrue(pre.stale)
        self.assertIn("days old", render_preflight(pre))
        self.assertFalse(self.pre(today=datetime.date(2026, 10, 29)).stale)

    def test_future_dated_table_is_stale(self):
        pre = self.pre(today=datetime.date(2026, 10, 1))
        self.assertTrue(pre.stale)
        self.assertIn("future", render_preflight(pre))

    def test_detection_feeds_the_assessment(self):
        root = os.path.join(self.fx.base, "prefix")
        write_file(
            os.path.join(root, "lib", "node_modules", "@qwen-code", "qwen-code", "package.json"),
            '{"name": "@qwen-code/qwen-code", "version": "0.19.6"}',
        )
        pre = run_preflight(self.fx.tree, self.rs, self.data, ceiling=self.fx.base,
                            environ={"npm_config_prefix": root}, detect=True)
        row = next(r for r in pre.rows if r.agent.id == "qwen-code")
        self.assertEqual(row.installs[0][0], "0.19.6")
        self.assertEqual(preflight_verdict(pre)[1], 2)


class PreflightCliTests(unittest.TestCase):
    def setUp(self):
        self.addCleanup(clear_git_env().stop)
        self.fx = Fixture()
        self.addCleanup(self.fx.cleanup)
        self.fx.make_bare_minimum_gitdir()
        self.fx.write_config("[core]\n\tbare = false\n")

    def test_exit_codes(self):
        base = ["preflight", self.fx.tree, "--no-detect", "--ceiling", self.fx.base]
        self.assertEqual(run_cli(base)[0], 0)
        self.assertEqual(run_cli(base + ["--agent", "goose=1.44.0"])[0], 0)
        self.assertEqual(run_cli(base + ["--agent", "goose=1.0.0"])[0], 2)
        self.fx.write_config("[core]\n\tfsmonitor = %s\n" % cfg_quote("/tmp/x"))
        self.assertEqual(run_cli(base + ["--agent", "goose=1.44.0"])[0], 1)

    def test_bad_agent_arguments_are_tool_errors_not_findings(self):
        base = ["preflight", self.fx.tree, "--no-detect"]
        for bad in ("nope=1.0", "goose", "goose=latest"):
            code, _, err = run_cli(base + ["--agent", bad])
            self.assertEqual(code, 3, bad)
            self.assertIn("sinkcheck: error", err)
        self.assertEqual(run_cli(base + ["--agents-data", os.path.join(self.fx.base, "no.json")])[0], 3)


if __name__ == "__main__":
    unittest.main()
