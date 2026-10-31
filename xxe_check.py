#!/usr/bin/env python3
"""xxe-check - scan XML files for the declarations that enable XXE.

XML External Entity (XXE, CWE-611) happens when a parser resolves
entities or DTDs from attacker-controlled URIs - reading local files
(file:///etc/passwd), reaching internal services (SSRF), or exhausting
resources. The OWASP XXE Prevention Cheat Sheet's general guidance is to
disable DTDs whenever possible and reject DOCTYPE declarations, and to
keep XInclude disabled unless explicitly required.

xxe-check lexically scans XML files and flags:

- doctype-declaration (warning): any <!DOCTYPE - review against the
  OWASP guidance to reject DTDs.
- external-general-entity (error): <!ENTITY name SYSTEM/PUBLIC "uri">
- parameter-entity (error): <!ENTITY % ...> (blind XXE / external DTDs)
- external-doctype (error): <!DOCTYPE root SYSTEM/PUBLIC "uri">
- xinclude (warning): <xi:include - loads resources outside DTD control

Comments (<!-- ... -->) and CDATA sections are skipped so payloads
quoted inside them are not flagged. The scan is lexical, not a full XML
parse; that heuristic is documented in the README.

Pure standard library.

Sources:
- OWASP XXE Prevention Cheat Sheet:
  https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html
- CWE-611: Improper Restriction of XML External Entity Reference:
  https://cwe.mitre.org/data/definitions/611.html
"""

import argparse
import json
import os
import sys

DEFAULT_EXTENSIONS = (".xml", ".xsd", ".xsl", ".xslt", ".svg", ".wsdl",
                      ".rss", ".atom")


class Finding:
    def __init__(self, path, line, rule, severity, message):
        self.path = path
        self.line = line
        self.rule = rule
        self.severity = severity
        self.message = message

    def as_dict(self):
        return {
            "file": self.path,
            "line": self.line,
            "rule": self.rule,
            "severity": self.severity,
            "message": self.message,
        }


def _line_of(text, pos):
    return text.count("\n", 0, pos) + 1


def _skip_quoted(text, i):
    """i points at an opening quote; return index past the closing one."""
    q = text[i]
    j = text.find(q, i + 1)
    return len(text) if j == -1 else j + 1


def _read_decl(text, i):
    """i points at '<' of a <!DOCTYPE or <!ENTITY. Return (decl, end)
    where decl is the full declaration text, honoring [ ... ] subsets
    and quoted literals so a '>' inside them does not end it early."""
    j = i
    depth = 0
    while j < len(text):
        c = text[j]
        if c in "\"'":
            j = _skip_quoted(text, j)
            continue
        if c == "[":
            depth += 1
        elif c == "]":
            depth = max(0, depth - 1)
        elif c == ">" and depth == 0:
            return text[i:j + 1], j + 1
        j += 1
    return text[i:], len(text)


def _has_external_id(decl):
    upper = " " + decl.upper() + " "
    return " SYSTEM " in upper or " PUBLIC " in upper


def _scan_region(text, start, end, path, findings):
    """Lexically scan text[start:end] (absolute offsets) for DTD/XInclude
    constructs. Comments and CDATA are skipped; a DOCTYPE internal
    subset is recursed into so its <!ENTITY declarations are checked
    individually."""
    emit = findings.append
    i = start
    while i < end:
        if text.startswith("<!--", i):
            j = text.find("-->", i + 4)
            i = end if j == -1 or j + 3 > end else j + 3
        elif text.startswith("<![CDATA[", i):
            j = text.find("]]>", i + 9)
            i = end if j == -1 or j + 3 > end else j + 3
        elif text.upper().startswith("<!DOCTYPE", i):
            # header runs to '[' (internal subset) or '>' honoring quotes
            j = i + len("<!DOCTYPE")
            while j < end and text[j] not in "[>":
                if text[j] in "\"'":
                    j = _skip_quoted(text, j)
                else:
                    j += 1
            header = text[i:j]
            line = _line_of(text, i)
            if _has_external_id(header):
                emit(Finding(path, line, "external-doctype", "error",
                             "<!DOCTYPE with SYSTEM/PUBLIC loads an "
                             "external DTD; OWASP recommends rejecting "
                             "DOCTYPE declarations and disabling "
                             "external DTD loading (XXE, CWE-611)."))
            else:
                emit(Finding(path, line, "doctype-declaration", "warning",
                             "<!DOCTYPE present: the OWASP XXE "
                             "Prevention Cheat Sheet recommends "
                             "disabling DTDs whenever possible and "
                             "rejecting DOCTYPE declarations."))
            if j < end and text[j] == "[":
                k = j + 1
                depth = 1
                while k < end and depth:
                    if text[k] in "\"'":
                        k = _skip_quoted(text, k)
                        continue
                    if text[k] == "[":
                        depth += 1
                    elif text[k] == "]":
                        depth -= 1
                    k += 1
                _scan_region(text, j + 1, k - 1, path, findings)
                gt = text.find(">", k)
                i = end if gt == -1 or gt >= end else gt + 1
            else:
                i = j + 1
        elif text.upper().startswith("<!ENTITY", i):
            decl, i2 = _read_decl(text, i)
            i2 = min(i2, end)
            line = _line_of(text, i)
            head = decl[len("<!ENTITY"):].lstrip()
            if head.startswith("%"):
                emit(Finding(path, line, "parameter-entity", "error",
                             "parameter entity <!ENTITY %% ...> enables "
                             "the external-DTD tricks used by blind XXE "
                             "(CWE-611)."))
            elif _has_external_id(decl):
                emit(Finding(path, line, "external-general-entity",
                             "error",
                             "external general entity (SYSTEM/PUBLIC "
                             "URI): classic XXE - a parser resolving it "
                             "can read local files or reach internal "
                             "services (CWE-611)."))
            # internal-only general entities expand locally; no finding
            i = i2
        elif text[i:i + 11].lower() == "<xi:include":
            emit(Finding(path, _line_of(text, i), "xinclude", "warning",
                         "<xi:include: OWASP recommends keeping XInclude "
                         "disabled unless explicitly required - it "
                         "loads resources independently of DTD "
                         "controls."))
            i += 11
        else:
            i += 1


def scan_text(text, path):
    findings = []
    _scan_region(text, 0, len(text), path, findings)
    return findings


def iter_files(paths, extensions):
    for p in paths:
        if os.path.isdir(p):
            for root, dirs, names in os.walk(p):
                dirs.sort()
                for name in sorted(names):
                    if name.lower().endswith(extensions):
                        yield os.path.join(root, name)
        else:
            yield p


def build_parser():
    p = argparse.ArgumentParser(
        prog="xxe-check",
        description="Scan XML files for DOCTYPE/entity/XInclude "
                    "declarations that enable XXE (CWE-611), per the "
                    "OWASP XXE Prevention Cheat Sheet.")
    p.add_argument("paths", nargs="+",
                   help="XML files or directories (directories are "
                        "scanned recursively for XML-like extensions)")
    p.add_argument("--ext", action="append", default=[],
                   metavar=".EXT",
                   help="extra file extension to include in directory "
                        "scans (repeatable)")
    p.add_argument("--ignore", action="append", default=[], metavar="RULE",
                   help="suppress a rule by name (repeatable)")
    p.add_argument("--fail-on-warning", action="store_true",
                   help="exit 1 when only warnings are present")
    p.add_argument("--format", choices=["text", "json"], default="text",
                   help="output format (default: text)")
    return p


def format_text(results):
    lines = []
    errors = warnings = 0
    for path, findings in results:
        for f in findings:
            lines.append("%s:%d [%s] %s: %s" % (
                f.path, f.line, f.severity, f.rule, f.message))
            if f.severity == "error":
                errors += 1
            else:
                warnings += 1
    if errors or warnings:
        lines.append("xxe-check: %d error(s), %d warning(s)" % (
            errors, warnings))
    else:
        lines.append("xxe-check: clean")
    return "\n".join(lines), errors, warnings


def main(argv=None):
    args = build_parser().parse_args(argv)
    ignore = set(args.ignore)
    exts = DEFAULT_EXTENSIONS + tuple(
        e if e.startswith(".") else "." + e for e in args.ext)
    results = []
    for path in iter_files(args.paths, exts):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError as exc:
            print("xxe-check: cannot read %s: %s" % (path, exc),
                  file=sys.stderr)
            return 2
        findings = [f for f in scan_text(text, path)
                    if f.rule not in ignore]
        results.append((path, findings))

    text_out, errors, warnings = format_text(results)
    if args.format == "json":
        print(json.dumps({
            "findings": [f.as_dict() for _, fs in results for f in fs],
            "summary": {"files": len(results), "errors": errors,
                        "warnings": warnings},
        }, indent=2))
    else:
        print(text_out)
    if errors:
        return 1
    if args.fail_on_warning and warnings:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
