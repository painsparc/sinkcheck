import json
import os
import unittest

from tests import _support
from tests._support import Fixture

from sinkcheck.ruleset import MATCHERS, RulesetError, load_ruleset, verification_for, Evidence


def base_data():
    path = os.path.join(os.path.dirname(os.path.abspath(_support.__file__)), "..", "sinkcheck", "data", "sinks.json")
    with open(path, "rb") as fh:
        return json.loads(fh.read().decode("utf-8"))


class RulesetTests(unittest.TestCase):
    def setUp(self):
        self.fx = Fixture()
        self.addCleanup(self.fx.cleanup)
        self.rs = load_ruleset()
        self.by_id = {r.id: r for r in self.rs.rules}

    def write(self, data):
        path = os.path.join(self.fx.base, "r.json")
        with open(path, "w") as fh:
            json.dump(data, fh)
        return path

    def test_loads_and_has_core_sinks(self):
        self.assertGreaterEqual(len(self.rs.rules), 30)
        for rid in ("core.fsmonitor", "core.hookspath", "filter.clean", "filter.smudge", "diff.textconv", "core.sshcommand"):
            self.assertIn(rid, self.by_id)

    def test_verification_is_computed_from_independent_origins(self):
        self.assertEqual(self.by_id["core.fsmonitor"].verification, "two-source")
        self.assertEqual(self.by_id["core.worktree"].verification, "single-source")
        self.assertEqual(self.by_id["diff.command"].verification, "unverified")

    def test_same_origin_twice_is_still_one_source(self):
        ev = [Evidence("a", "t", "u", "n"), Evidence("a", "t", "u", "n2")]
        self.assertEqual(verification_for(ev), "single-source")

    def test_evidence_urls_are_https(self):
        for r in self.rs.rules:
            for e in r.evidence:
                self.assertTrue(e.url.startswith("https://"), (r.id, e.url))

    def test_every_rule_is_well_formed(self):
        for r in self.rs.rules:
            self.assertIn(r.match, MATCHERS)
            self.assertTrue(r.triggers.strip(), r.id)
            self.assertIn("safe_directory", r.protections)

    def test_protected_only_rules_exist_and_are_marked(self):
        for rid in ("safe.directory", "safe.barerepository", "uploadpack.packobjectshook"):
            self.assertTrue(self.by_id[rid].protected_only, rid)

    def test_rejects_unknown_matcher(self):
        d = base_data()
        d["sinks"][0]["match"] = "does_not_exist"
        with self.assertRaises(RulesetError):
            load_ruleset(self.write(d))

    def test_rejects_duplicate_id(self):
        d = base_data()
        d["sinks"].append(dict(d["sinks"][0]))
        with self.assertRaises(RulesetError):
            load_ruleset(self.write(d))

    def test_rejects_unknown_origin(self):
        d = base_data()
        d["sinks"][0]["evidence"] = [{"origin": "nobody", "note": ""}]
        with self.assertRaises(RulesetError):
            load_ruleset(self.write(d))

    def test_rejects_missing_file_and_bad_json(self):
        with self.assertRaises(RulesetError):
            load_ruleset(os.path.join(self.fx.base, "missing.json"))
        bad = os.path.join(self.fx.base, "bad.json")
        with open(bad, "w") as fh:
            fh.write("{not json")
        with self.assertRaises(RulesetError):
            load_ruleset(bad)


if __name__ == "__main__":
    unittest.main()
