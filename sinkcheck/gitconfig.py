"""A git configuration file parser that treats the file strictly as data.

It never calls git. It is deliberately conservative: where git's own
behaviour is unclear to us, it records a parse error instead of guessing,
and the engine turns parse errors into "needs review", never into a clean
result.

Syntax handled (git-config file format):
  * [section], [section "subsection"], legacy [section.subsection]
  * a variable may follow a header on the same line
  * name = value, bare name (boolean true), comments with # or ;
  * double-quoted spans, escapes \\\\ \\" \\n \\t \\b, backslash-newline
    continuation, CRLF line endings, UTF-8 BOM
"""

from dataclasses import dataclass, field

_WS = " \t\r\f\v"
_NAME_START = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
_NAME_CHARS = _NAME_START | set("0123456789-")
_SECTION_CHARS = _NAME_CHARS | {"."}
_ESCAPES = {"t": "\t", "b": "\b", "n": "\n", "\\": "\\", '"': '"'}


@dataclass(frozen=True)
class Entry:
    section: str
    subsection: object  # str or None
    name: str
    value: object  # str or None (None = bare name, boolean true)
    line: int

    @property
    def key(self):
        parts = [self.section]
        if self.subsection is not None:
            parts.append(self.subsection)
        parts.append(self.name)
        return ".".join(parts)


@dataclass(frozen=True)
class ParseError:
    line: int
    message: str


@dataclass
class ParseResult:
    entries: list = field(default_factory=list)
    errors: list = field(default_factory=list)


def parse_config_bytes(data):
    text = data.decode("utf-8", errors="surrogateescape")
    if text.startswith("﻿"):
        text = text[1:]
    text = text.replace("\r\n", "\n")
    result = ParseResult()
    if "\x00" in text:
        result.errors.append(ParseError(0, "NUL byte in file; git would reject it"))

    n = len(text)
    i = 0
    line = 1
    section = None
    subsection = None

    def skip_to_eol(pos):
        while pos < n and text[pos] != "\n":
            pos += 1
        return pos

    while i < n:
        c = text[i]
        if c == "\n":
            line += 1
            i += 1
            continue
        if c in _WS:
            i += 1
            continue
        if c in "#;":
            i = skip_to_eol(i)
            continue

        if c == "[":
            i += 1
            start = i
            while i < n and text[i] in _SECTION_CHARS:
                i += 1
            raw_name = text[start:i]
            if not raw_name:
                result.errors.append(ParseError(line, "empty section name"))
                i = skip_to_eol(i)
                continue
            sub = None
            name = raw_name
            if "." in raw_name:
                name, _, legacy = raw_name.partition(".")
                sub = legacy.lower()
            if i < n and text[i] in _WS:
                while i < n and text[i] in _WS:
                    i += 1
                if i < n and text[i] == '"':
                    if sub is not None:
                        result.errors.append(ParseError(line, "mixed legacy and quoted subsection"))
                    i += 1
                    buf = []
                    closed = False
                    while i < n:
                        ch = text[i]
                        if ch == "\n":
                            break
                        if ch == "\\":
                            i += 1
                            if i >= n or text[i] == "\n":
                                break
                            buf.append(text[i])
                            i += 1
                            continue
                        if ch == '"':
                            closed = True
                            i += 1
                            break
                        buf.append(ch)
                        i += 1
                    if not closed:
                        result.errors.append(ParseError(line, "unterminated subsection quote"))
                        i = skip_to_eol(i)
                        continue
                    sub = "".join(buf)
                else:
                    result.errors.append(ParseError(line, "unexpected text in section header"))
                    i = skip_to_eol(i)
                    continue
            if i < n and text[i] == "]":
                i += 1
                section = name.lower()
                subsection = sub
                continue
            result.errors.append(ParseError(line, "section header not closed with ]"))
            i = skip_to_eol(i)
            continue

        if c in _NAME_START:
            start = i
            var_line = line
            while i < n and text[i] in _NAME_CHARS:
                i += 1
            var_name = text[start:i].lower()
            while i < n and text[i] in " \t":
                i += 1
            if section is None:
                result.errors.append(ParseError(var_line, "variable outside any section"))
                i = skip_to_eol(i)
                continue
            if i >= n or text[i] in "\n#;":
                result.entries.append(Entry(section, subsection, var_name, None, var_line))
                continue
            if text[i] != "=":
                result.errors.append(ParseError(var_line, "unexpected text after variable name"))
                i = skip_to_eol(i)
                continue
            i += 1
            while i < n and text[i] in " \t":
                i += 1
            buf = []
            trail = []
            in_quote = False
            bad = None
            while i < n:
                ch = text[i]
                if ch == "\n":
                    if in_quote:
                        bad = "unterminated double quote in value"
                    break
                if ch == "\\":
                    i += 1
                    if i >= n:
                        bad = "backslash at end of file"
                        break
                    nxt = text[i]
                    if nxt == "\n":
                        line += 1
                        i += 1
                        continue
                    if nxt not in _ESCAPES:
                        bad = "unknown escape sequence in value"
                        i += 1
                        continue
                    buf.extend(" " * len(trail))
                    trail = []
                    buf.append(_ESCAPES[nxt])
                    i += 1
                    continue
                if ch == '"':
                    in_quote = not in_quote
                    i += 1
                    continue
                if not in_quote and ch in "#;":
                    i = skip_to_eol(i)
                    break
                if not in_quote and ch in _WS:
                    trail.append(ch)
                    i += 1
                    continue
                # git collapses each unquoted whitespace char before a
                # non-space char to a single space
                buf.extend(" " * len(trail))
                trail = []
                buf.append(ch)
                i += 1
            if in_quote and bad is None:
                bad = "unterminated double quote in value"
            if bad:
                result.errors.append(ParseError(var_line, bad))
            result.entries.append(Entry(section, subsection, var_name, "".join(buf), var_line))
            continue

        result.errors.append(ParseError(line, "unexpected character; git would reject this line"))
        i = skip_to_eol(i)

    return result


def key_matches(pattern, entry):
    """Match a ruleset key pattern against an entry.

    Patterns:
      "core.fsmonitor"   section.name, entry must have no subsection
      "alias.*"          section.* : any variable name, no subsection
      "filter.*.clean"   section.*.name : any subsection
      "remote.origin.url" a literal subsection
    """
    first = pattern.find(".")
    last = pattern.rfind(".")
    if first == -1:
        return False
    if first == last:
        sec, nm = pattern[:first], pattern[first + 1 :]
        if entry.subsection is not None or entry.section != sec.lower():
            return False
        return nm == "*" or entry.name == nm.lower()
    sec, mid, nm = pattern[:first], pattern[first + 1 : last], pattern[last + 1 :]
    if entry.section != sec.lower() or entry.name != nm.lower() or entry.subsection is None:
        return False
    if mid == "*":
        return True
    return entry.subsection == mid
