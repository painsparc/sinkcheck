"""Machine-readable output. Same facts as the text report, same sanitizing:
every string that came from the scanned tree or the host passes through
safe_text, so the JSON is pure ASCII and carries no terminal-control or
bidirectional characters even if a consumer prints it raw."""

import json

from . import BUILD_PHASE, PUBLISHABLE, __version__
from .report import DISCLAIMER, UNAFFILIATED
from .sanitize import safe_text

SCHEMA = 1


def _s(value):
    return None if value is None else safe_text(value, None)


def _finding(f):
    r = f.rule
    d = {
        "severity": f.severity,
        "kind": f.kind,
        "rule_id": r.id if r is not None else None,
        "key": _s(f.key),
        "file": _s(f.file),
        "line": f.line or None,
        "value": _s(f.value) if isinstance(f.value, str) else None,
        "note": _s(f.note),
        "via": _s(f.via),
        "driver": _s(f.driver) or None,
    }
    if r is not None:
        d["evidence"] = {"verification": r.verification, "sources": [e.url for e in r.evidence]}
        if f.kind == "sink":
            d["fires_on"] = list(r.reached_by)
            d["why"] = r.triggers
    elif f.verification:
        d["evidence"] = {"verification": f.verification, "sources": list(f.sources)}
    return d


def result_to_dict(result, verdict, mode, exit_code=None, fail_on="review"):
    rs = result.ruleset
    name, code = verdict
    out = {
        "tool": "sinkcheck",
        "version": __version__,
        "schema": SCHEMA,
        "mode": mode,
        "build": {"phase": BUILD_PHASE, "publishable": PUBLISHABLE},
        "target": _s(result.target),
        "ruleset": {"version": rs.ruleset_version, "date": rs.ruleset_date, "rules": len(rs.rules)},
        "scope": [_s(c) for c in result.context],
        "examined": [_s(e) for e in result.examined],
        "not_examined": list(result.not_examined),
        "counts": {
            "critical": sum(1 for f in result.findings if f.severity == "critical"),
            "review": sum(1 for f in result.findings if f.severity == "review"),
            "info": sum(1 for f in result.findings if f.severity == "info"),
            "suppressed": result.suppressed,
        },
        "incomplete": [_s(r) for r in result.incomplete],
        "findings": [_finding(f) for f in result.findings],
        "verdict": {
            "name": name,
            "exit_code": code if exit_code is None else exit_code,
            "exit_code_before_fail_on": code,
            "fail_on": fail_on,
        },
        "disclaimer": DISCLAIMER,
        "unaffiliated": UNAFFILIATED,
    }
    return out


def preflight_to_dict(pre, verdict, exit_code=None, fail_on="review"):
    out = result_to_dict(pre.scan, verdict, "preflight", exit_code=exit_code, fail_on=fail_on)
    rows = []
    for row in pre.rows:
        entry = {
            "agent_id": row.agent.id,
            "name": row.agent.name,
            "installs": [{"version": _s(v), "source": _s(s)} for v, s in row.installs],
            "findings": [],
        }
        for f, ver, a in row.assessments:
            entry["findings"].append({
                "id": f.id,
                "path": f.path,
                "status": f.status,
                "status_date": f.status_date,
                "fixed_in": f.fixed_in or None,
                "last_vulnerable": f.last_vulnerable or None,
                "detail": f.detail,
                "caveat": f.caveat or None,
                "verification": f.verification,
                "sources": [e.url for e in f.evidence],
                "related_sources": [e.url for e in f.context],
                "assessed_version": _s(ver),
                "assessment": None if a is None else {"level": a.level, "text": _s(a.text), "floors_review": a.floors_review},
            })
        rows.append(entry)
    out["agents"] = {
        "data_version": pre.data.data_version,
        "data_date": pre.data.data_date,
        "age_days": pre.age_days,
        "stale": pre.stale,
        "note": pre.data.note,
        "rows": rows,
    }
    return out


def dumps(obj):
    return json.dumps(obj, indent=2, sort_keys=False, ensure_ascii=True) + "\n"
