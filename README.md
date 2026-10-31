# xxe-check

A CI scanner that flags the XML declarations which enable XXE attacks
(XML External Entity injection, [CWE-611](https://cwe.mitre.org/data/definitions/611.html)).
When a parser resolves entities or DTDs from attacker-controlled URIs it
can read local files (`file:///etc/passwd`), reach internal services
(SSRF), or exhaust resources.

The OWASP [XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
gives the general guidance this tool encodes: "Disable document type
definitions (DTDs) whenever possible. Reject DOCTYPE declarations if the
parser supports it", and "Keep XInclude disabled unless explicitly
required; it can load resources independently of DTDs."

## What it flags

| Rule | Severity | Why |
|---|---|---|
| `external-general-entity` | error | `<!ENTITY x SYSTEM/PUBLIC "uri">` - the classic XXE vector; a resolving parser can read local files or make internal requests (CWE-611). |
| `parameter-entity` | error | `<!ENTITY % ...>` - parameter entities enable the external-DTD tricks used by blind/out-of-band XXE. |
| `external-doctype` | error | `<!DOCTYPE root SYSTEM/PUBLIC "uri">` loads an external DTD; OWASP recommends disabling external DTD loading. |
| `doctype-declaration` | warning | Any `<!DOCTYPE`; OWASP recommends rejecting DOCTYPE declarations when the parser allows it. Legitimate DTD use exists - suppress with `--ignore doctype-declaration`. |
| `xinclude` | warning | `<xi:include` loads resources independently of DTD controls; OWASP recommends keeping XInclude disabled unless required. |

Internal-only general entities (`<!ENTITY x "text">`) expand locally and
are not flagged.

## Usage

```sh
python3 xxe_check.py config.xml src/
python3 xxe_check.py --ext .config assets/
python3 xxe_check.py --ignore doctype-declaration schema.xsd
python3 xxe_check.py --fail-on-warning --format json xml/
```

- Directories are scanned recursively for `.xml .xsd .xsl .xslt .svg
  .wsdl .rss .atom`; add more with `--ext`. Files passed explicitly are
  scanned whatever their extension (including `.dtd` external subsets).
- Exit code `0` clean, `1` on errors (or warnings with
  `--fail-on-warning`), `2` on unreadable input.

Example output:

```
payload.xml:3 [error] external-general-entity: external general entity (SYSTEM/PUBLIC URI): classic XXE - a parser resolving it can read local files or reach internal services (CWE-611).
xxe-check: 1 error(s), 0 warning(s)
```

## Scope and method

The scan is **lexical**, not a full XML parse: it walks the bytes,
skipping `<!-- comments -->` and `<![CDATA[ ... ]]>` so quoted payloads
inside them are not flagged, and honors quoted literals and `[ ... ]`
subsets when finding declaration ends. Malformed XML may confuse the
scanner; that is the documented heuristic. It detects the presence of
dangerous declarations in files - it does not assess whether a specific
parser/runtime would resolve them (parser defaults differ; the OWASP
cheat sheet's per-language guidance covers configuration).

No dependencies beyond the Python 3 standard library. CI runs the test
suite on Ubuntu and Windows against Python 3.9 and 3.13.

## Sources

- [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html) -
  guidance to disable DTDs, reject DOCTYPE declarations, and keep
  XInclude disabled; impact summary (local file exposure, SSRF,
  resource exhaustion).
- [CWE-611: Improper Restriction of XML External Entity Reference](https://cwe.mitre.org/data/definitions/611.html) -
  weakness definition and consequences (file read via `file://` URIs,
  SSRF via `http://` URIs, DoS via large or recursive resources).

## License

MIT
