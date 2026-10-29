"""Plain-text report. Every value taken from the scanned tree is passed
through sanitize.safe_text before it is printed."""

from . import __version__, BUILD_PHASE, PUBLISHABLE
from .engine import SEVERITY_RANK, verdict_of
from .sanitize import safe_text

DISCLAIMER = (
    "A clean scan is not a clean bill of health: this tool reads configuration "
    "as data and covers only the places listed under 'Examined'. It cannot see "
    "what it does not read, and the sink list is not exhaustive."
)
UNAFFILIATED = (
    "Unaffiliated: this tool is not affiliated with, endorsed by, or sponsored "
    "by any vendor or project named in this output."
)
INTERIM = (
    "Interim, partial, instruction only (this tool never runs it): pass "
    "-c core.fsmonitor=false -c core.hooksPath=<null device> on each git call. "
    "That neutralises two sinks, not the class. Opening an unfamiliar tree in a "
    "disposable container or VM covers the rest."
)

STEPS = (
    "What to do (instructions only; this tool never runs any of it): do not attach an agent to this "
    "tree or run git in it; read the flagged file(s) in a plain text editor; if you did not write a "
    "flagged setting, discard the tree or copy only the files you need into a fresh directory."
)
HOST_STEPS = (
    "What to do (instructions only; this tool never runs any of it): read each flagged setting and "
    "keep the ones you set on purpose. For one you do not recognise, remove it yourself with "
    "git config --global --unset <key> (or edit the file named above), then re-run this audit."
)

HOST_CRITICAL_STEPS = (
    "What to do (instructions only; this tool never runs any of it): a critical finding in the audit comes "
    "from a repository under --root or from an environment variable, not from your global configuration. "
    "For a repository: do not attach an agent to it or run git in it; read the flagged file in a plain text "
    "editor; if you did not write the setting, discard it. For an environment variable: unset it yourself in "
    "the shell or profile that sets it. Review-level items from your own configuration are listed separately "
    "above; keep the ones you set on purpose."
)

EXAMINED_CAP = 40

_VERIFICATION = {
    "two-source": "two cited sources (counted by distinct origin; independence not verified)",
    "single-source": "SINGLE SOURCE - unverified beyond it",
    "unverified": "UNVERIFIED - no source cited for this sink's behaviour",
}


def _count(findings, sev):
    return sum(1 for f in findings if f.severity == sev)


def render_text(result, verdict=None, extra=None, note=None):
    """verdict: optional (name, code) overriding the scan's own verdict (the
    pre-flight mode folds agent status in). extra: optional callable taking
    the shared source_ref function and returning more lines, printed after
    the findings and before the verdict."""
    name, _code = verdict if verdict is not None else verdict_of(result)
    rs = result.ruleset
    lines = []
    out = lines.append

    out("sinkcheck %s | git config execution-sink scan" % __version__)
    if not PUBLISHABLE:
        out("build: phase %d of 6 - NOT the publishable cut; coverage is partial" % BUILD_PHASE)
    out("target:  %s" % safe_text(result.target, None))
    out("ruleset: sinks.json v%s, %s, %d rules" % (rs.ruleset_version, rs.ruleset_date, len(rs.rules)))
    for c in result.context:
        out("scope:   %s" % safe_text(c, None))
    out("")
    out("Examined:")
    if result.examined:
        for item in result.examined[:EXAMINED_CAP]:
            out("  - %s" % safe_text(item, None))
        if len(result.examined) > EXAMINED_CAP:
            out("  - ... and %d more" % (len(result.examined) - EXAMINED_CAP))
    else:
        out("  - nothing was readable")
    out("NOT examined by this build:")
    for item in result.not_examined:
        out("  - %s" % item)
    out("")

    findings = sorted(
        result.findings,
        key=lambda f: (SEVERITY_RANK[f.severity], f.file, f.line, f.key),
    )
    out(
        "FINDINGS: %d critical, %d needs-review, %d info"
        % (_count(findings, "critical"), _count(findings, "review"), _count(findings, "info"))
    )
    if result.suppressed:
        out("  (%d further lower-severity findings are not listed: total cap reached)" % result.suppressed)
    sources = []

    def source_ref(url):
        if url not in sources:
            sources.append(url)
        return sources.index(url) + 1

    for f in findings:
        out("")
        label = {"critical": "CRITICAL", "review": "REVIEW", "info": "INFO"}[f.severity]
        title = f.rule.key if f.rule is not None else (f.key or f.kind)
        out("[%s] %s  (%s)" % (label, safe_text(title), f.kind))
        loc = safe_text(f.file, None)
        if f.line:
            loc += ":%d" % f.line
        if loc:
            out("  where:    %s" % loc)
        if f.kind == "sink":
            out("  key:      %s" % safe_text(f.key))
            out("  value:    %s" % safe_text(f.value))
        elif f.value:
            out("  value:    %s" % safe_text(f.value))
        r = f.rule
        if r is not None and f.kind == "sink":
            if r.reached_by:
                out("  fires on: %s" % ", ".join(r.reached_by))
            out("  why:      %s" % r.triggers)
            out("  git's own protections:")
            out("    safe.directory: %s" % r.protections.get("safe_directory", ""))
            out("    protocol.*.allow: %s" % r.protections.get("protocol", ""))
            if r.protections.get("note"):
                out("    note: %s" % r.protections["note"])
        if f.via:
            out("  via:      %s" % safe_text(f.via, None))
        if r is not None:
            refs = ", ".join("[%d]" % source_ref(e.url) for e in r.evidence)
            out("  evidence: %s%s" % (_VERIFICATION[r.verification], (" " + refs) if refs else ""))
        elif f.verification:
            refs = ", ".join("[%d]" % source_ref(u) for u in f.sources)
            out("  evidence: %s%s" % (_VERIFICATION[f.verification], (" " + refs) if refs else ""))
        if f.note:
            out("  note:     %s" % safe_text(f.note, None))

    if extra is not None:
        for line in extra(source_ref):
            out(line)

    if sources:
        out("")
        out("Sources:")
        for i, url in enumerate(sources, 1):
            out("  [%d] %s" % (i, url))

    if result.incomplete:
        out("")
        out("SCAN INCOMPLETE: a limit was reached and part of the input was NOT examined. This is not a clean result.")
        for reason in result.incomplete[:10]:
            out("  - %s" % safe_text(reason, None))
        if len(result.incomplete) > 10:
            out("  - ... and %d more" % (len(result.incomplete) - 10))

    out("")
    out("VERDICT: %s" % name)
    out(DISCLAIMER)
    if _code == 3 and result.incomplete:
        out(
            "The scan hit a limit and stopped examining part of the input, so it cannot say the tree is clean. "
            "Do not attach an agent to this tree or run git in it until you have read the files named above "
            "yourself (instructions only; this tool never runs any of it). --fail-on does not change this result."
        )
    if _code in (1, 2):
        if result.target == "this host":
            out(HOST_CRITICAL_STEPS if _code == 1 else HOST_STEPS)
        elif verdict_of(result)[1] in (1, 2):
            out(STEPS)
            out(INTERIM)
        else:
            out(
                "The tree had no findings in what was examined; the verdict is held at needs-review "
                "by the agent status above (affected, unknown or unverified)."
            )
    out(UNAFFILIATED)
    out("exit code: 0 nothing found | 1 critical finding | 2 needs review | 3 scan incomplete or tool error (never a clean result)")
    if note:
        out(note)
    return "\n".join(lines) + "\n"
