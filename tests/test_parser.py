import unittest

from tests import _support  # noqa: F401  (sets sys.path)

from sinkcheck.gitconfig import key_matches, parse_config_bytes


def parse(text):
    return parse_config_bytes(text.encode("utf-8") if isinstance(text, str) else text)


def one(text):
    r = parse(text)
    assert len(r.entries) == 1, r
    return r.entries[0]


class ParserTests(unittest.TestCase):
    def test_basic(self):
        e = one("[core]\n\tfsmonitor = foo bar\n")
        self.assertEqual((e.section, e.subsection, e.name, e.value, e.line), ("core", None, "fsmonitor", "foo bar", 2))
        self.assertEqual(e.key, "core.fsmonitor")

    def test_case_folding(self):
        e = one("[CORE]\n\tFsMonitor = x\n")
        self.assertEqual(e.key, "core.fsmonitor")

    def test_quoted_subsection_keeps_case(self):
        e = one('[remote "Origin"]\n\turl = ext::x\n')
        self.assertEqual(e.key, "remote.Origin.url")

    def test_subsection_escapes(self):
        e = one('[remote "a\\"b\\\\c"]\n\turl = x\n')
        self.assertEqual(e.subsection, 'a"b\\c')

    def test_legacy_subsection_lowercased(self):
        e = one("[remote.Origin]\n\turl = x\n")
        self.assertEqual(e.subsection, "origin")

    def test_variable_on_header_line(self):
        e = one("[core] fsmonitor = evil\n")
        self.assertEqual((e.key, e.value), ("core.fsmonitor", "evil"))

    def test_bare_name_is_none(self):
        e = one("[core]\n\tbare\n")
        self.assertIsNone(e.value)

    def test_bare_name_before_comment(self):
        e = one("[core]\n\tbare # c\n")
        self.assertIsNone(e.value)

    def test_comments(self):
        self.assertEqual(one("[a]\n\tb = x ; c\n").value, "x")
        self.assertEqual(one("[a]\n\tb = x # c\n").value, "x")
        self.assertEqual(parse("[a]\n# b = y\n; c = z\n").entries, [])

    def test_quotes(self):
        self.assertEqual(one('[a]\n\tb = "x ; y"\n').value, "x ; y")
        self.assertEqual(one('[a]\n\tb = "  lead"\n').value, "  lead")
        self.assertEqual(one("[a]\n\tb = foo   bar\n").value, "foo   bar")
        self.assertEqual(one("[a]\n\tb = trail   \n").value, "trail")
        self.assertEqual(one('[a]\n\tb = "trail  "\n').value, "trail  ")

    def test_escapes(self):
        self.assertEqual(one('[a]\n\tb = "q\\"q"\n').value, 'q"q')
        self.assertEqual(one("[a]\n\tb = x\\ty\n").value, "x\ty")
        self.assertEqual(one("[a]\n\tb = x\\\\y\n").value, "x\\y")
        self.assertEqual(one("[a]\n\tb = x\\ny\n").value, "x\ny")

    def test_continuation_and_line_numbers(self):
        r = parse("[a]\n\tb = one \\\n two\n\tc = z\n")
        self.assertEqual(r.errors, [])
        self.assertEqual(r.entries[0].value, "one  two")
        self.assertEqual(r.entries[0].line, 2)
        self.assertEqual(r.entries[1].line, 4)

    def test_bom_and_crlf(self):
        r = parse(b"\xef\xbb\xbf[core]\r\n\tfsmonitor = x\r\n")
        self.assertEqual(r.errors, [])
        self.assertEqual((r.entries[0].value, r.entries[0].line), ("x", 2))

    def test_multiple_sections_and_duplicates(self):
        r = parse("[a]\n\tb = 1\n[c]\n\td = 2\n[a]\n\tb = 3\n")
        self.assertEqual([e.key for e in r.entries], ["a.b", "c.d", "a.b"])

    def test_empty_value(self):
        self.assertEqual(one("[a]\n\tb =\n").value, "")
        self.assertEqual(one('[a]\n\tb = ""\n').value, "")

    def test_errors_are_reported_not_silenced(self):
        for bad in (
            '[a]\n\tb = "unterminated\n',
            "b = 1\n",
            "[core\n\tb = 1\n",
            "[a]\n\tb = \\q\n",
            "[a]\n\t1bad = x\n",
            '[a "unterminated]\n\tb = 1\n',
            "[a]\n\tb c = 1\n",
        ):
            self.assertTrue(parse(bad).errors, "no error for %r" % bad)

    def test_nul_byte_is_an_error(self):
        self.assertTrue(parse(b"[a]\n\tb = x\x00y\n").errors)

    def test_undecodable_bytes_do_not_crash(self):
        r = parse(b"[a]\n\tb = \xff\xfe\n")
        self.assertEqual(len(r.entries), 1)

    def test_empty_and_whitespace_only(self):
        self.assertEqual(parse("").entries, [])
        self.assertEqual(parse("\n\n   \n").entries, [])

    def test_hostile_garbage_never_raises(self):
        for blob in (b"[" * 5000, b'"' * 5000, b"\\" * 5000, b"[a]\n" + b"b=" * 5000, bytes(range(256)) * 20):
            parse_config_bytes(blob)


class KeyMatchTests(unittest.TestCase):
    def e(self, text):
        return one(text)

    def test_exact(self):
        self.assertTrue(key_matches("core.fsmonitor", self.e("[core]\n\tfsmonitor = x\n")))
        self.assertTrue(key_matches("core.fsMonitor", self.e("[core]\n\tfsmonitor = x\n")))
        self.assertFalse(key_matches("core.fsmonitor", self.e('[core "x"]\n\tfsmonitor = x\n')))

    def test_subsection_wildcard(self):
        self.assertTrue(key_matches("filter.*.clean", self.e('[filter "lfs"]\n\tclean = x\n')))
        self.assertFalse(key_matches("filter.*.clean", self.e("[filter]\n\tclean = x\n")))
        self.assertFalse(key_matches("filter.*.clean", self.e('[filter "lfs"]\n\tsmudge = x\n')))

    def test_name_wildcard(self):
        self.assertTrue(key_matches("alias.*", self.e("[alias]\n\tco = x\n")))
        self.assertFalse(key_matches("alias.*", self.e('[alias "s"]\n\tco = x\n')))

    def test_dotted_subsection(self):
        self.assertTrue(key_matches("credential.*.helper", self.e('[credential "https://a.example/"]\n\thelper = x\n')))

    def test_literal_subsection(self):
        self.assertTrue(key_matches("gpg.ssh.program", self.e('[gpg "ssh"]\n\tprogram = x\n')))
        self.assertFalse(key_matches("gpg.ssh.program", self.e('[gpg "x509"]\n\tprogram = x\n')))


if __name__ == "__main__":
    unittest.main()
