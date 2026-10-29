"""Parse gitattributes files as data, extracting only the references that
select a driver defined in git config: filter=, diff=, merge=.

A driver defined in config is inert until an attribute selects it for a
path. Attributes can come from the same untrusted tree, so this module does
not downgrade anything; it only records the pairing as evidence.
"""

from dataclasses import dataclass

MAX_LINES = 50000
KINDS = ("filter", "diff", "merge")


@dataclass(frozen=True)
class AttrRef:
    file: str
    line: int
    pattern: str
    attr: str
    driver: str


def parse_attributes(data, path):
    text = data.decode("utf-8", errors="replace")
    refs = []
    for lineno, raw in enumerate(text.split("\n"), 1):
        if lineno > MAX_LINES:
            break
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("[attr]"):
            continue
        if line.startswith('"'):
            end = line.find('"', 1)
            if end == -1:
                continue
            pattern, rest = line[1:end], line[end + 1 :]
        else:
            parts = line.split(None, 1)
            pattern = parts[0]
            rest = parts[1] if len(parts) > 1 else ""
        for tok in rest.split():
            for kind in KINDS:
                prefix = kind + "="
                if tok.startswith(prefix) and len(tok) > len(prefix):
                    refs.append(AttrRef(path, lineno, pattern, kind, tok[len(prefix):]))
    return refs
