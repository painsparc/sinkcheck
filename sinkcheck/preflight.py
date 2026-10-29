"""Pre-flight mode: the repository scan joined with per-agent patch status.

The question this answers is "should I attach this agent to this tree
right now". The agent table can only add caution: a patched agent never
clears a tree that has findings, and nothing here turns a tree verdict
into a safer one.
"""

import datetime
import os
from dataclasses import dataclass, field

from .agents import assess, detect_installed, parse_date
from .engine import scan_target, verdict_of
from .report import _VERIFICATION, render_text
from .sanitize import safe_text


@dataclass
class AgentRow:
    agent: object
    installs: list  # [(version_text, source)]
    assessments: list = field(default_factory=list)  # [(finding, version_text, Assessment)]


@dataclass
class PreflightResult:
    scan: object
    data: object
    rows: list
    age_days: int
    stale: bool
    detected_any: bool


def run_preflight(target, ruleset, data, declared=None, ceiling=None, environ=None, today=None, detect=True):
    environ = os.environ if environ is None else environ
    scan = scan_target(target, ruleset, ceiling=ceiling, environ=environ)
    scan.not_examined = [x for x in scan.not_examined if "patch status" not in x]
    found = detect_installed(data, environ) if detect else {}
    declared = declared or {}
    rows = []
    for agent in data.agents:
        installs = list(declared.get(agent.id, []))
        for item in found.get(agent.id, []):
            if item not in installs:
                installs.append(item)
        row = AgentRow(agent=agent, installs=installs)
        for f in agent.findings:
            if installs:
                for ver, _src in installs:
                    row.assessments.append((f, ver, assess(f, ver)))
            else:
                row.assessments.append((f, None, None))
        rows.append(row)
    today = today or datetime.date.today()
    d = parse_date(data.data_date)
    age = (today - d).days
    return PreflightResult(
        scan=scan,
        data=data,
        rows=rows,
        age_days=age,
        stale=age > data.stale_after_days or age < 0,
        detected_any=any(r.installs for r in rows),
    )


def preflight_verdict(pre):
    name, code = verdict_of(pre.scan)
    if code == 0:
        for row in pre.rows:
            for _f, _v, a in row.assessments:
                if a is not None and a.floors_review:
                    return "NEEDS REVIEW", 2
    return name, code


def _tree_hits(scan, finding):
    keys = set(finding.sinks)
    hits = []
    for f in scan.findings:
        if f.kind == "sink" and f.severity in ("critical", "review") and f.rule is not None and f.rule.key in keys:
            if f.rule.key not in hits:
                hits.append(f.rule.key)
    return hits


def _agent_lines(pre, source_ref):
    lines = ["", "AGENT STATUS (as of %s; verify with your vendor)" % pre.data.data_date]
    if pre.stale and pre.age_days < 0:
        lines.append("  WARNING: this status table is dated in the future (clock or data error). Treat every row as stale.")
    elif pre.stale:
        lines.append(
            "  WARNING: this status table is %d days old (limit %d). Treat every row as stale."
            % (pre.age_days, pre.data.stale_after_days)
        )
    lines.append("  %s" % safe_text(pre.data.note, None))
    if not pre.detected_any:
        lines.append(
            "  No agent was named or detected. Detection reads npm package.json files only and "
            "misses everything else; pass --agent ID=VERSION to check the one you use."
        )
    for row in pre.rows:
        lines.append("")
        if row.installs:
            vers = ", ".join("%s (%s)" % (safe_text(v), safe_text(s, None)) for v, s in row.installs)
            lines.append("  %s - installed: %s" % (row.agent.name, vers))
        else:
            lines.append("  %s - not detected / not named" % row.agent.name)
        for f, ver, a in row.assessments:
            refs = ", ".join("[%d]" % source_ref(e.url) for e in f.evidence)
            lines.append("    path:     %s" % safe_text(f.path, None))
            lines.append(
                "    status:   %s at %s (%s%s)"
                % (f.status.upper() if f.status != "fixed" else "reported fixed", safe_text(f.status_date, None), _VERIFICATION[f.verification], (" " + refs) if refs else "")
            )
            lines.append("    detail:   %s" % safe_text(f.detail, None))
            if f.context:
                lines.append(
                    "    related (not counted as verification): %s"
                    % ", ".join("[%d]" % source_ref(e.url) for e in f.context)
                )
            if f.caveat:
                lines.append("    caveat:   %s" % safe_text(f.caveat, None))
            if a is not None:
                lines.append("    yours:    %s" % safe_text(a.text, None))
            hits = _tree_hits(pre.scan, f)
            if hits:
                lines.append("    this tree carries: %s (the sink behind this path)" % ", ".join(hits))
    lines.append("")
    lines.append(
        "  A fixed agent does not clear a tree that has findings: other paths and other agents remain, "
        "and the sink list is not exhaustive."
    )
    return lines


def render_preflight(pre, note=None):
    verdict = preflight_verdict(pre)
    return render_text(pre.scan, verdict=verdict, extra=lambda ref: _agent_lines(pre, ref), note=note)
