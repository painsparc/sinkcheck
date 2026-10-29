import os
import unittest

from tests._support import Fixture, cfg_quote, make_gitdir, write_file

from sinkcheck import discover
from sinkcheck.attributes import parse_attributes
from sinkcheck.engine import MAX_INCLUDE_FILES, scan_target, verdict_of
from sinkcheck.ruleset import load_ruleset


def kinds(result, kind):
    return [f for f in result.findings if f.kind == kind]


class AttributeParserTests(unittest.TestCase):
    def test_extracts_driver_references(self):
        data = b"# c\n*.bin filter=lfs diff=lfs merge=lfs -text\n*.x -diff\n\"a b\" diff=odd\n[attr]macro filter=m\n"
        refs = parse_attributes(data, "f")
        got = {(r.attr, r.driver, r.pattern, r.line) for r in refs}
        self.assertEqual(
            got,
            {("filter", "lfs", "*.bin", 2), ("diff", "lfs", "*.bin", 2), ("merge", "lfs", "*.bin", 2), ("diff", "odd", "a b", 4)},
        )

    def test_garbage_does_not_raise(self):
        parse_attributes(b"\xff\xfe\x00\"unterminated filter=x\n\n\t\n=\nfilter=\n", "f")


class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.fx = Fixture()
        self.addCleanup(self.fx.cleanup)
        self.rs = load_ruleset()

    def scan(self, **kw):
        kw.setdefault("ceiling", self.fx.base)
        kw.setdefault("environ", {})
        return scan_target(self.fx.tree, self.rs, **kw)

    def payload_cfg(self):
        return "[core]\n\tfsmonitor = %s\n" % cfg_quote("/tmp/x")

    # ancestors ---------------------------------------------------------
    def test_enclosing_repository_is_found_by_searching_upward(self):
        outer = os.path.join(self.fx.base, "outer")
        make_gitdir(os.path.join(outer, ".git"), self.payload_cfg())
        inner = os.path.join(outer, "inner")
        os.makedirs(inner)
        r = scan_target(inner, self.rs, environ={})
        self.assertEqual(verdict_of(r)[1], 1)
        self.assertTrue(any("enclosing" in f.note for f in r.findings))

    def test_ceiling_stops_the_upward_search(self):
        outer = os.path.join(self.fx.base, "outer")
        make_gitdir(os.path.join(outer, ".git"), self.payload_cfg())
        inner = os.path.join(outer, "inner")
        os.makedirs(inner)
        r = scan_target(inner, self.rs, ceiling=outer, environ={})
        self.assertEqual(verdict_of(r)[1], 2)
        self.assertTrue(kinds(r, "coverage"))

    def test_find_enclosing_unit(self):
        outer = os.path.join(self.fx.base, "o")
        make_gitdir(os.path.join(outer, ".git"))
        deep = os.path.join(outer, "a", "b")
        os.makedirs(deep)
        found = discover.find_enclosing(deep)
        self.assertEqual(os.path.normcase(os.path.realpath(found[0])), os.path.normcase(os.path.realpath(os.path.join(outer, ".git"))))
        self.assertIsNone(discover.find_enclosing(deep, ceiling=outer))

    # redirects, worktrees, submodules --------------------------------------
    def test_commondir_config_is_scanned(self):
        common = os.path.join(self.fx.outside, "common.git")
        make_gitdir(common, self.payload_cfg())
        make_gitdir(self.fx.git_dir, "[core]\n\tbare = false\n")
        write_file(os.path.join(self.fx.git_dir, "commondir"), common.replace("\\", "/") + "\n")
        r = self.scan()
        self.assertEqual(verdict_of(r)[1], 1)

    def test_config_worktree_and_linked_worktree_configs_are_scanned(self):
        make_gitdir(self.fx.git_dir, "[core]\n\tbare = false\n")
        write_file(os.path.join(self.fx.git_dir, "config.worktree"), self.payload_cfg())
        r = self.scan()
        self.assertEqual(verdict_of(r)[1], 1)
        write_file(os.path.join(self.fx.git_dir, "config.worktree"), "[core]\n\tbare = false\n")
        write_file(os.path.join(self.fx.git_dir, "worktrees", "w1", "config.worktree"), self.payload_cfg())
        self.assertEqual(verdict_of(self.scan())[1], 1)

    def test_submodule_git_directory_config_is_scanned(self):
        make_gitdir(self.fx.git_dir, "[core]\n\tbare = false\n")
        make_gitdir(os.path.join(self.fx.git_dir, "modules", "sub"), self.payload_cfg())
        self.assertEqual(verdict_of(self.scan())[1], 1)

    def test_gitmodules_ext_url_is_flagged_but_other_keys_are_ignored(self):
        make_gitdir(self.fx.git_dir, "[core]\n\tbare = false\n")
        write_file(
            os.path.join(self.fx.tree, ".gitmodules"),
            '[submodule "a"]\n\tpath = a\n\turl = ext::sh -c x\n[core]\n\tfsmonitor = /tmp/x\n',
        )
        r = self.scan()
        keys = {f.key for f in r.findings if f.kind == "sink"}
        self.assertIn('submodule.a.url', keys)
        self.assertNotIn("core.fsmonitor", keys)  # git does not read core.* from .gitmodules
        self.assertEqual(verdict_of(r)[1], 2)

    def test_nested_gitfile_pointing_inside_tree_is_info(self):
        make_gitdir(self.fx.git_dir, "[core]\n\tbare = false\n")
        make_gitdir(os.path.join(self.fx.git_dir, "modules", "s"), "[core]\n\tbare = false\n")
        write_file(os.path.join(self.fx.tree, "s", ".git"), "gitdir: ../.git/modules/s\n")
        r = self.scan()
        gf = [f for f in kinds(r, "structure") if f.file.endswith(os.path.join("s", ".git"))]
        self.assertTrue(gf)
        self.assertEqual(gf[0].severity, "info")
        self.assertEqual(verdict_of(r)[1], 0)

    def test_malformed_gitfile_is_review(self):
        write_file(os.path.join(self.fx.tree, ".git"), "not a redirect\n")
        self.assertEqual(verdict_of(self.scan())[1], 2)

    # attributes pairing -------------------------------------------------
    def test_attribute_selection_is_recorded_on_the_driver_finding(self):
        make_gitdir(self.fx.git_dir, '[filter "lfsx"]\n\tclean = /tmp/x\n[filter "other"]\n\tsmudge = /tmp/y\n')
        write_file(os.path.join(self.fx.tree, "sub", ".gitattributes"), "*.dat filter=lfsx\n")
        r = self.scan()
        by_driver = {f.driver: f for f in r.findings if f.kind == "sink" and f.rule.attribute == "filter"}
        self.assertIn("SELECTED", by_driver["lfsx"].note)
        self.assertIn("no filter= attribute", by_driver["other"].note)
        self.assertEqual(by_driver["other"].severity, "critical")  # unselected is NOT downgraded

    def test_info_attributes_file_counts(self):
        make_gitdir(self.fx.git_dir, '[diff "d"]\n\ttextconv = /tmp/x\n')
        write_file(os.path.join(self.fx.git_dir, "info", "attributes"), "*.x diff=d\n")
        r = self.scan()
        self.assertTrue(any("SELECTED" in f.note for f in r.findings if f.kind == "sink"))

    def test_core_attributesfile_inside_target_is_read_and_paired(self):
        make_gitdir(self.fx.git_dir, '[core]\n\tattributesFile = .git/evil-attrs\n[filter "evil"]\n\tclean = /tmp/x\n')
        write_file(os.path.join(self.fx.git_dir, "evil-attrs"), "*.dat filter=evil\n")
        r = self.scan()
        drv = [f for f in r.findings if f.kind == "sink" and f.rule.id == "filter.clean"][0]
        self.assertIn("SELECTED", drv.note)
        self.assertIn("evil-attrs", drv.note)
        af = [f for f in r.findings if f.kind == "sink" and f.rule.id == "core.attributesfile"]
        self.assertEqual(len(af), 1)
        self.assertEqual(af[0].severity, "review")
        self.assertIn("inside the target", af[0].note)
        self.assertEqual(verdict_of(r)[1], 1)

    def test_core_attributesfile_outside_target_is_reported_not_read(self):
        outside = os.path.join(self.fx.outside, "attrs")
        write_file(outside, "*.dat filter=evil\n")
        make_gitdir(self.fx.git_dir, '[core]\n\tattributesFile = %s\n[filter "evil"]\n\tclean = /tmp/x\n' % cfg_quote(outside.replace("\\", "/")))
        r = self.scan()
        af = [f for f in r.findings if f.kind == "sink" and f.rule.id == "core.attributesfile"][0]
        self.assertIn("outside the target", af.note)
        drv = [f for f in r.findings if f.kind == "sink" and f.rule.id == "filter.clean"][0]
        self.assertNotIn("SELECTED", drv.note)
        self.assertEqual(drv.severity, "critical")

    def test_core_attributesfile_alone_needs_review(self):
        make_gitdir(self.fx.git_dir, "[core]\n\tattributesFile = .git/a\n")
        self.assertEqual(verdict_of(self.scan())[1], 2)

    def test_attr_tree_is_reported_and_named_on_unpaired_drivers(self):
        make_gitdir(self.fx.git_dir, '[attr]\n\ttree = 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n[filter "evil"]\n\tclean = /tmp/x\n')
        r = self.scan()
        at = [f for f in r.findings if f.kind == "sink" and f.rule.id == "attr.tree"]
        self.assertEqual(len(at), 1)
        self.assertEqual(at[0].severity, "review")
        drv = [f for f in r.findings if f.kind == "sink" and f.rule.id == "filter.clean"][0]
        self.assertIn("attr.tree is set", drv.note)
        self.assertEqual(verdict_of(r)[1], 1)
        self.assertTrue(any("attr.tree" in x for x in r.not_examined))

    def test_attr_tree_alone_needs_review(self):
        make_gitdir(self.fx.git_dir, "[attr]\n\ttree = HEAD\n")
        self.assertEqual(verdict_of(self.scan())[1], 2)

    # includes ------------------------------------------------------------
    def test_missing_include_target_is_info_not_clean_verdict_change(self):
        make_gitdir(self.fx.git_dir, "[include]\n\tpath = nowhere.cfg\n")
        r = self.scan()
        self.assertTrue(any(f.severity == "info" and "not present" in f.note for f in r.findings))
        self.assertEqual(verdict_of(r)[1], 2)  # the include itself still needs a human

    def test_relative_include_resolves_against_the_including_file(self):
        make_gitdir(self.fx.git_dir, "[include]\n\tpath = extra.cfg\n")
        write_file(os.path.join(self.fx.git_dir, "extra.cfg"), self.payload_cfg())
        self.assertEqual(verdict_of(self.scan())[1], 1)

    def test_conditional_include_is_followed_and_labelled(self):
        make_gitdir(self.fx.git_dir, '[includeIf "gitdir:/nowhere/"]\n\tpath = extra.cfg\n')
        write_file(os.path.join(self.fx.git_dir, "extra.cfg"), self.payload_cfg())
        r = self.scan()
        crit = [f for f in r.findings if f.severity == "critical"]
        self.assertTrue(crit)
        self.assertIn("condition not evaluated", crit[0].via)

    def test_other_users_home_and_runtime_prefix_includes_are_unresolved_review(self):
        make_gitdir(self.fx.git_dir, "[include]\n\tpath = ~someone/x\n\tpath = %(prefix)/etc/x\n")
        r = self.scan()
        self.assertEqual(len(kinds(r, "include")), 2)

    def test_include_file_cap_is_reported(self):
        lines = []
        for i in range(MAX_INCLUDE_FILES + 5):
            write_file(os.path.join(self.fx.outside, "i%d.cfg" % i), "[core]\n\tbare = false\n")
            lines.append("\tpath = %s\n" % os.path.join(self.fx.outside, "i%d.cfg" % i).replace("\\", "/"))
        make_gitdir(self.fx.git_dir, "[include]\n" + "".join(lines))
        r = self.scan()
        self.assertTrue(any("more than" in f.note for f in kinds(r, "include")))

    # hooks ---------------------------------------------------------------
    def test_sample_hooks_are_ignored_unknown_names_are_info(self):
        make_gitdir(self.fx.git_dir, "[core]\n\tbare = false\n")
        write_file(os.path.join(self.fx.git_dir, "hooks", "pre-commit.sample"), "#\n")
        write_file(os.path.join(self.fx.git_dir, "hooks", "readme.txt"), "#\n")
        r = self.scan()
        self.assertEqual([f.severity for f in kinds(r, "hook")], ["info"])
        self.assertEqual(verdict_of(r)[1], 0)

    def test_hook_findings_carry_their_evidence_label(self):
        make_gitdir(self.fx.git_dir, "[core]\n\tbare = false\n")
        write_file(os.path.join(self.fx.git_dir, "hooks", "post-checkout"), "#!/bin/sh\n")
        h = kinds(self.scan(), "hook")[0]
        self.assertIn(h.verification, ("two-source", "single-source", "unverified"))

    # environment ---------------------------------------------------------
    def test_environment_variables_are_findings_only_when_set(self):
        make_gitdir(self.fx.git_dir, "[core]\n\tbare = false\n")
        self.assertEqual(kinds(self.scan(), "env"), [])
        r = self.scan(environ={"GIT_DIR": "/elsewhere", "UNRELATED": "x"})
        self.assertEqual([f.key for f in kinds(r, "env")], ["GIT_DIR"])

    # walk bounds ---------------------------------------------------------
    def test_walk_is_bounded_and_says_so(self):
        for i in range(30):
            os.makedirs(os.path.join(self.fx.tree, "d%02d" % i))
        d = discover.walk_tree(self.fx.tree, max_dirs=5)
        self.assertTrue(d.truncated)
        d = discover.walk_tree(self.fx.tree, max_depth=0)
        self.assertTrue(d.truncated)

    def test_symlinked_directories_are_counted_not_followed(self):
        target = os.path.join(self.fx.outside, "linked")
        make_gitdir(target, self.payload_cfg())
        try:
            os.symlink(target, os.path.join(self.fx.tree, "ln"), target_is_directory=True)
        except (OSError, NotImplementedError, AttributeError):
            self.skipTest("cannot create symlinks here")
        make_gitdir(self.fx.git_dir, "[core]\n\tbare = false\n")
        r = self.scan()
        self.assertEqual(verdict_of(r)[1], 0)  # the linked repo was NOT followed
        d = discover.walk_tree(self.fx.tree)
        self.assertEqual(d.symlinked_dirs, 1)

    def test_clean_repository_with_everything_present_is_still_clean(self):
        make_gitdir(self.fx.git_dir, "[core]\n\tbare = false\n[remote \"o\"]\n\turl = https://example.invalid/r.git\n")
        write_file(os.path.join(self.fx.tree, ".gitattributes"), "* text=auto\n")
        write_file(os.path.join(self.fx.tree, ".gitmodules"), '[submodule "a"]\n\tpath = a\n\turl = https://example.invalid/a.git\n')
        write_file(os.path.join(self.fx.git_dir, "hooks", "pre-commit.sample"), "#\n")
        self.assertEqual(verdict_of(self.scan()), ("NOTHING FOUND", 0))


if __name__ == "__main__":
    unittest.main()
