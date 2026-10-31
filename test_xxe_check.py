#!/usr/bin/env python3
"""Tests for xxe-check (stdlib unittest)."""

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import xxe_check as xxe


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = xxe.main(argv)
    return code, out.getvalue(), err.getvalue()


def rules(findings):
    return {f.rule for f in findings}


class DoctypeTests(unittest.TestCase):
    def scan(self, text):
        return xxe.scan_text(text, "t.xml")

    def test_plain_doctype_is_warning(self):
        fs = self.scan("<!DOCTYPE data><data/>")
        self.assertEqual(len(fs), 1)
        self.assertEqual(fs[0].rule, "doctype-declaration")
        self.assertEqual(fs[0].severity, "warning")

    def test_doctype_with_subset_is_warning(self):
        fs = self.scan("<!DOCTYPE d [<!ELEMENT d (#PCDATA)>]><d/>")
        self.assertEqual(rules(fs), {"doctype-declaration"})

    def test_external_doctype_system_is_error(self):
        fs = self.scan('<!DOCTYPE d SYSTEM "http://x/y.dtd"><d/>')
        self.assertEqual(rules(fs), {"external-doctype"})
        self.assertEqual(fs[0].severity, "error")

    def test_external_doctype_public_is_error(self):
        fs = self.scan(
            '<!DOCTYPE d PUBLIC "-//X//DTD//EN" "http://x/y.dtd"><d/>')
        self.assertEqual(rules(fs), {"external-doctype"})

    def test_doctype_case_insensitive(self):
        fs = self.scan("<!doctype d><d/>")
        self.assertEqual(rules(fs), {"doctype-declaration"})

    def test_no_doctype_is_clean(self):
        self.assertEqual(self.scan("<root><a/></root>"), [])

    def test_doctype_inside_comment_ignored(self):
        self.assertEqual(
            self.scan("<!-- <!DOCTYPE d SYSTEM 'http://x'> --><r/>"), [])

    def test_doctype_inside_cdata_ignored(self):
        self.assertEqual(
            self.scan("<r><![CDATA[<!DOCTYPE d SYSTEM 'http://x'>]]>"
                      "</r>"), [])

    def test_unterminated_comment_swallows_rest(self):
        fs = self.scan("<!-- <!DOCTYPE d SYSTEM 'http://x'")
        self.assertEqual(fs, [])

    def test_doctype_line_number(self):
        fs = self.scan("<?xml version='1.0'?>\n\n<!DOCTYPE d><d/>")
        self.assertEqual(fs[0].line, 3)


class EntityTests(unittest.TestCase):
    def scan(self, text):
        return xxe.scan_text(text, "t.xml")

    def test_external_general_entity_in_subset_is_error(self):
        fs = self.scan(
            '<!DOCTYPE d [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
            '<d>&x;</d>')
        self.assertIn("external-general-entity", rules(fs))
        self.assertIn("doctype-declaration", rules(fs))

    def test_external_entity_line_number(self):
        fs = self.scan(
            '<!DOCTYPE d [\n<!ENTITY x SYSTEM "file:///etc/passwd">\n]>'
            '<d/>')
        ent = [f for f in fs if f.rule == "external-general-entity"][0]
        self.assertEqual(ent.line, 2)

    def test_parameter_entity_is_error(self):
        fs = self.scan(
            '<!DOCTYPE d [<!ENTITY % p SYSTEM "http://evil/x.dtd">]><d/>')
        self.assertIn("parameter-entity", rules(fs))
        sev = {f.rule: f.severity for f in fs}
        self.assertEqual(sev["parameter-entity"], "error")

    def test_internal_parameter_entity_flagged(self):
        fs = self.scan('<!DOCTYPE d [<!ENTITY % p "text">]><d/>')
        self.assertEqual(rules(fs), {"doctype-declaration",
                                     "parameter-entity"})

    def test_internal_general_entity_not_flagged(self):
        fs = self.scan('<!DOCTYPE d [<!ENTITY x "hello">]><d>&x;</d>')
        self.assertEqual(rules(fs), {"doctype-declaration"})

    def test_entity_public_is_error(self):
        fs = self.scan(
            '<!DOCTYPE d [<!ENTITY x PUBLIC "-//X//EN" "http://x/e">]>'
            '<d/>')
        self.assertIn("external-general-entity", rules(fs))

    def test_entity_case_insensitive(self):
        fs = self.scan(
            '<!doctype d [<!entity x system "file:///etc/passwd">]><d/>')
        self.assertIn("external-general-entity", rules(fs))

    def test_entity_inside_comment_ignored(self):
        fs = self.scan(
            "<!-- <!ENTITY x SYSTEM 'file:///etc/passwd'> --><r/>")
        self.assertEqual(fs, [])

    def test_entity_with_gt_in_literal(self):
        fs = self.scan(
            '<!DOCTYPE d [<!ENTITY x "a>b">]><d/>')
        self.assertEqual(rules(fs), {"doctype-declaration"})

    def test_external_entity_single_quotes(self):
        fs = self.scan(
            "<!DOCTYPE d [<!ENTITY x SYSTEM 'file:///etc/passwd'>]><d/>")
        self.assertIn("external-general-entity", rules(fs))

    def test_dtd_file_scanned_directly(self):
        # a .dtd external subset: entities at top level, no DOCTYPE
        fs = self.scan('<!ENTITY x SYSTEM "file:///etc/passwd">')
        self.assertEqual(rules(fs), {"external-general-entity"})


class XIncludeTests(unittest.TestCase):
    def scan(self, text):
        return xxe.scan_text(text, "t.xml")

    def test_xinclude_is_warning(self):
        fs = self.scan('<r><xi:include href="file:///etc/passwd"/></r>')
        self.assertEqual(len(fs), 1)
        self.assertEqual(fs[0].rule, "xinclude")
        self.assertEqual(fs[0].severity, "warning")

    def test_xinclude_case_insensitive(self):
        fs = self.scan('<r><XI:INCLUDE href="x"/></r>')
        self.assertEqual(rules(fs), {"xinclude"})

    def test_no_xinclude_is_clean(self):
        self.assertEqual(self.scan('<r><xi_other/></r>'), [])


class FileIterationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def test_directory_recurses_xml(self):
        os.makedirs(os.path.join(self.dir, "sub"))
        for rel in ("a.xml", "sub/b.xml"):
            with open(os.path.join(self.dir, rel), "w",
                      encoding="utf-8") as fh:
                fh.write("<!DOCTYPE d><d/>")
        with open(os.path.join(self.dir, "c.txt"), "w",
                  encoding="utf-8") as fh:
            fh.write("<!DOCTYPE d><d/>")
        found = sorted(xxe.iter_files([self.dir],
                                      xxe.DEFAULT_EXTENSIONS))
        self.assertEqual(len(found), 2)

    def test_explicit_file_any_extension(self):
        p = os.path.join(self.dir, "payload.txt")
        with open(p, "w", encoding="utf-8") as fh:
            fh.write("<!DOCTYPE d><d/>")
        self.assertEqual(list(xxe.iter_files([p],
                                             xxe.DEFAULT_EXTENSIONS)),
                         [p])

    def test_custom_ext(self):
        with open(os.path.join(self.dir, "a.config"), "w",
                  encoding="utf-8") as fh:
            fh.write("<!DOCTYPE d><d/>")
        found = list(xxe.iter_files([self.dir],
                                    xxe.DEFAULT_EXTENSIONS + (".config",)))
        self.assertEqual(len(found), 1)


class CLITests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, content):
        path = os.path.join(self.dir, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        return path

    def test_clean_file_exit_zero(self):
        p = self.write("ok.xml", "<root/>")
        code, out, _ = run([p])
        self.assertEqual(code, 0)
        self.assertIn("clean", out)

    def test_error_exit_one(self):
        p = self.write("bad.xml",
                       '<!DOCTYPE d [<!ENTITY x SYSTEM "file:///e">]>'
                       '<d/>')
        code, out, _ = run([p])
        self.assertEqual(code, 1)
        self.assertIn("external-general-entity", out)

    def test_warning_only_exit_zero_by_default(self):
        p = self.write("w.xml", "<!DOCTYPE d><d/>")
        code, out, _ = run([p])
        self.assertEqual(code, 0)
        self.assertIn("doctype-declaration", out)

    def test_fail_on_warning_exit_one(self):
        p = self.write("w.xml", "<!DOCTYPE d><d/>")
        code, _, _ = run(["--fail-on-warning", p])
        self.assertEqual(code, 1)

    def test_ignore_suppresses_rule(self):
        p = self.write("w.xml", "<!DOCTYPE d><d/>")
        code, out, _ = run(["--ignore", "doctype-declaration", p])
        self.assertEqual(code, 0)
        self.assertIn("clean", out)

    def test_json_output_shape(self):
        p = self.write("bad.xml",
                       '<!DOCTYPE d SYSTEM "http://x/d.dtd"><d/>')
        code, out, _ = run(["--format", "json", p])
        self.assertEqual(code, 1)
        data = json.loads(out)
        self.assertEqual(data["summary"]["errors"], 1)
        self.assertEqual(data["findings"][0]["rule"], "external-doctype")

    def test_directory_scan(self):
        self.write("a.xml", '<!DOCTYPE d SYSTEM "http://x/d.dtd"><d/>')
        self.write("b.xml", "<root/>")
        code, out, _ = run([self.dir])
        self.assertEqual(code, 1)
        self.assertIn("external-doctype", out)

    def test_ext_flag(self):
        self.write("a.config", "<!DOCTYPE d><d/>")
        code, out, _ = run(["--ext", ".config", self.dir])
        self.assertEqual(code, 0)
        self.assertIn("doctype-declaration", out)

    def test_ext_flag_without_dot(self):
        self.write("a.config", "<!DOCTYPE d><d/>")
        code, out, _ = run(["--ext", "config", self.dir])
        self.assertIn("doctype-declaration", out)

    def test_missing_file_exit_two(self):
        code, _, err = run(["/nonexistent/nope.xml"])
        self.assertEqual(code, 2)
        self.assertIn("cannot read", err)

    def test_text_output_counts(self):
        p = self.write(
            "mix.xml",
            '<!DOCTYPE d [<!ENTITY x SYSTEM "file:///e">]><d/>')
        code, out, _ = run([p])
        self.assertEqual(code, 1)
        self.assertIn("1 error(s), 1 warning(s)", out)

    def test_multiple_files(self):
        p1 = self.write("a.xml", "<!DOCTYPE d><d/>")
        p2 = self.write("b.xml",
                        '<!DOCTYPE d SYSTEM "http://x/d.dtd"><d/>')
        code, out, _ = run([p1, p2])
        self.assertEqual(code, 1)
        self.assertIn("doctype-declaration", out)
        self.assertIn("external-doctype", out)

    def test_findings_carry_line_numbers(self):
        p = self.write("l.xml", "<?xml version='1.0'?>\n\n<!DOCTYPE d>"
                                 "<d/>")
        code, out, _ = run([p])
        self.assertIn(":3 [", out)


if __name__ == "__main__":
    unittest.main()
