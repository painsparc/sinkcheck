import json
import os
import unittest

from tests import _support
from tests._support import Fixture, cfg_quote

from sinkcheck.engine import ScanResult, TargetError, evaluate, scan_config_bytes, scan_target, verdict_of
from sinkcheck.ruleset import load_ruleset


def scan_text(text, ruleset=None):
    ruleset = ruleset or load_ruleset()
    result = ScanResult(target="t", ruleset=ruleset)
    scan_config_bytes(text.encode("utf-8"), "cfg", ruleset, result)
    return result


def sev(result, key=None):
    return sorted(f.severity for f in result.findings if key is None or f.key == key)


class EvaluateTests(unittest.TestCase):
    def setUp(self):
        self.rs = load_ruleset()
        self.by_id = {r.id: r for r in self.rs.rules}

    def test_fsmonitor_values(self):
        r = self.by_id["core.fsmonitor"]
        for safe in ("false", "FALSE", "no", "off", "", "true", "yes", "on", "1", "0", "-3", "+7"):
            self.assertFalse(evaluate(r, safe)[0], safe)
        for cmd in ("/tmp/evil.sh", "evil", "1k", "true ", "false ", "0x1", "1.5", "echo hi", "!x"):
            self.assertTrue(evaluate(r, cmd)[0], cmd)
        self.assertFalse(evaluate(r, None)[0])  # bare name = boolean true = builtin daemon

    def test_hookspath_null_device_is_safe(self):
        r = self.by_id["core.hookspath"]
        self.assertFalse(evaluate(r, "/dev/null")[0])
        # 'nul' is the null device only on Windows; see tests/test_hardening.py
        self.assertTrue(evaluate(r, "/tmp/hooks")[0])
        self.assertTrue(evaluate(r, ".githooks")[0])

    def test_bang_and_ext(self):
        self.assertTrue(evaluate(self.by_id["alias.shell"], "!rm -rf x")[0])
        self.assertFalse(evaluate(self.by_id["alias.shell"], "status -s")[0])
        self.assertTrue(evaluate(self.by_id["remote.url.ext"], "ext::sh -c x")[0])
        self.assertTrue(evaluate(self.by_id["remote.url.ext"], "EXT::sh -c x")[0])
        self.assertFalse(evaluate(self.by_id["remote.url.ext"], "https://example.invalid/r.git")[0])

    def test_valueless_command_key_is_forced_review(self):
        hit, force, _ = evaluate(self.by_id["core.sshcommand"], None)
        self.assertTrue(hit)
        self.assertTrue(force)

    def test_pager_safe_values(self):
        r = self.by_id["core.pager"]
        self.assertFalse(evaluate(r, "cat")[0])
        self.assertFalse(evaluate(r, "less")[0])
        self.assertTrue(evaluate(r, "sh -c evil")[0])


class EngineTests(unittest.TestCase):
    def test_clean_config_has_no_findings(self):
        r = scan_text("[core]\n\trepositoryformatversion = 0\n\tbare = false\n[remote \"origin\"]\n\turl = https://example.invalid/r.git\n")
        self.assertEqual(r.findings, [])
        self.assertEqual(verdict_of(r), ("NOTHING FOUND", 0))

    def test_fsmonitor_command_is_critical(self):
        r = scan_text("[core]\n\tfsmonitor = /tmp/x\n")
        self.assertEqual(sev(r, "core.fsmonitor"), ["critical"])
        self.assertEqual(verdict_of(r), ("CRITICAL", 1))

    def test_fsmonitor_false_is_not_a_finding(self):
        self.assertEqual(scan_text("[core]\n\tfsmonitor = false\n").findings, [])

    def test_shadowed_critical_is_downgraded_to_review(self):
        r = scan_text("[core]\n\tfsmonitor = /tmp/x\n\tfsmonitor = false\n")
        self.assertEqual(sev(r, "core.fsmonitor"), ["review"])
        self.assertEqual(verdict_of(r)[1], 2)
        self.assertIn("shadowed", r.findings[0].note)

    def test_later_malicious_value_wins(self):
        r = scan_text("[core]\n\tfsmonitor = false\n\tfsmonitor = /tmp/x\n")
        self.assertEqual(sev(r, "core.fsmonitor"), ["critical"])

    def test_multivalued_not_shadowed(self):
        r = scan_text("[credential]\n\thelper = a\n\thelper = b\n")
        self.assertEqual(sev(r, "credential.helper"), ["review", "review"])

    def test_filter_driver_is_critical(self):
        r = scan_text('[filter "x"]\n\tclean = sh -c evil\n')
        self.assertEqual(verdict_of(r)[1], 1)

    def test_protected_only_is_info(self):
        r = scan_text("[safe]\n\tdirectory = *\n\tbareRepository = all\n[uploadpack]\n\tpackObjectsHook = x\n")
        self.assertEqual(set(sev(r)), {"info"})
        self.assertEqual(verdict_of(r), ("NOTHING FOUND", 0))

    def test_include_is_reported_not_followed(self):
        r = scan_text("[include]\n\tpath = /somewhere/else\n")
        self.assertEqual(sev(r, "include.path"), ["review"])
        self.assertIn("not examined", r.findings[0].note)

    def test_includeif_is_reported(self):
        r = scan_text('[includeIf "gitdir:~/x/"]\n\tpath = y\n')
        self.assertEqual(verdict_of(r)[1], 2)

    def test_parse_error_is_review_never_clean(self):
        r = scan_text('[core]\n\tfsmonitor = "oops\n')
        self.assertEqual(verdict_of(r)[1], 1)  # the entry is still extracted and flagged
        self.assertTrue(any(f.kind == "parse" for f in r.findings))

    def test_sweep_catches_token_hidden_from_parser(self):
        r = scan_text("[core]\n\tbare = false\n# fsmonitor = /tmp/x\n")
        self.assertTrue(any(f.kind == "sweep" for f in r.findings))
        self.assertEqual(verdict_of(r)[1], 2)

    def test_sweep_quiet_when_token_was_parsed(self):
        r = scan_text("[core]\n\tfsmonitor = false\n")
        self.assertEqual(r.findings, [])

    def test_ruleset_is_data_new_sink_needs_no_code(self):
        fx = Fixture()
        self.addCleanup(fx.cleanup)
        base = os.path.join(os.path.dirname(os.path.abspath(_support.__file__)), "..", "sinkcheck", "data", "sinks.json")
        with open(base, "rb") as fh:
            data = json.loads(fh.read().decode("utf-8"))
        data["sinks"].append(
            {
                "id": "synthetic.example", "key": "synthetic.runner", "tier": "A", "match": "command_string",
                "severity": "critical", "sweep": [], "protections": "none",
                "triggers": "synthetic", "reached_by": [], "evidence": [],
            }
        )
        path = os.path.join(fx.base, "extra.json")
        with open(path, "w") as fh:
            json.dump(data, fh)
        rs = load_ruleset(path)
        self.assertEqual(sev(scan_text("[synthetic]\n\trunner = x\n", rs)), ["critical"])
        self.assertEqual(scan_text("[synthetic]\n\trunner = x\n").findings, [])


class TargetTests(unittest.TestCase):
    def setUp(self):
        self.fx = Fixture()
        self.addCleanup(self.fx.cleanup)
        self.rs = load_ruleset()

    def test_not_a_directory_raises(self):
        with self.assertRaises(TargetError):
            scan_target(os.path.join(self.fx.base, "nope"), self.rs, environ={})

    def scan(self):
        return scan_target(self.fx.tree, self.rs, ceiling=self.fx.base, environ={})

    def test_no_repo_at_root_is_needs_review(self):
        r = self.scan()
        self.assertEqual(verdict_of(r)[1], 2)
        self.assertTrue(any(f.kind == "coverage" for f in r.findings))

    def test_dotgit_file_redirect_is_reported_even_when_target_is_missing(self):
        with open(os.path.join(self.fx.tree, ".git"), "w") as fh:
            fh.write("gitdir: ../elsewhere\n")
        r = self.scan()
        self.assertEqual(verdict_of(r)[1], 2)
        self.assertTrue(any("redirects" in f.note for f in r.findings))

    def test_bare_layout_target_is_scanned(self):
        fx = self.fx
        os.makedirs(os.path.join(fx.tree, "objects"))
        os.makedirs(os.path.join(fx.tree, "refs"))
        with open(os.path.join(fx.tree, "HEAD"), "w") as fh:
            fh.write("ref: refs/heads/main\n")
        with open(os.path.join(fx.tree, "config"), "w") as fh:
            fh.write("[core]\n\tfsmonitor = %s\n" % cfg_quote("/tmp/x"))
        r = self.scan()
        self.assertEqual(verdict_of(r)[1], 1)

    def test_missing_config_is_info_only(self):
        self.fx.make_bare_minimum_gitdir()
        r = self.scan()
        self.assertEqual(verdict_of(r), ("NOTHING FOUND", 0))
        self.assertTrue(r.not_examined)


if __name__ == "__main__":
    unittest.main()
