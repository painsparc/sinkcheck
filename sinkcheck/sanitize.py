"""Make untrusted text safe to print.

Values and paths come from a repository we do not trust. Printing them raw
lets a repo inject terminal escape sequences, bidi overrides or zero-width
characters into our report. Everything that is not printable ASCII is
escaped. Backslashes are left alone so Windows paths stay readable.
"""

DEFAULT_LIMIT = 200


def safe_text(value, limit=DEFAULT_LIMIT):
    if value is None:
        return "(no value)"
    out = []
    for ch in str(value):
        o = ord(ch)
        if 0x20 <= o <= 0x7E:
            out.append(ch)
        elif 0xDC80 <= o <= 0xDCFF:
            # undecodable byte preserved by surrogateescape
            out.append("\\x%02x" % (o - 0xDC00))
        elif o < 0x100:
            out.append("\\x%02x" % o)
        elif o < 0x10000:
            out.append("\\u%04x" % o)
        else:
            out.append("\\U%08x" % o)
    text = "".join(out)
    if limit is not None and len(text) > limit:
        extra = len(text) - limit
        text = text[:limit] + "...(+%d more chars)" % extra
    return text
