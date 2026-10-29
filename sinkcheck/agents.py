"""Per-agent patch status: a dated, sourced data file plus version detection
that reads files as data. Nothing here runs an agent or asks one for its
version: invoking an agent binary would be exactly the kind of action this
package exists to avoid, so versions come from the user (--agent ID=VERSION)
or from package.json files in well-known global install locations.
"""

import json
import os
import re
from dataclasses import dataclass, field

from .ruleset import Evidence, verification_for
from .safeio import path_kind, read_regular_file

DEFAULT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "agents.json")
STATUSES = ("fixed", "unknown", "unpatched")
_VERSION_RE = re.compile(r"v?([0-9]{1,9}(?:\.[0-9]{1,9}){0,7})([-+._~]?[A-Za-z][0-9A-Za-z.+_~-]{0,40})?")


class AgentsError(Exception):
    pass


@dataclass(frozen=True)
class AgentFinding:
    id: str
    path: str
    sinks: tuple
    status: str
    fixed_in: str
    last_vulnerable: str
    status_date: str
    detail: str
    caveat: str
    gate: bool
    evidence: tuple
    verification: str
    context: tuple = ()  # related sources that do NOT count toward verification


@dataclass(frozen=True)
class Agent:
    id: str
    name: str
    npm_packages: tuple
    findings: tuple


@dataclass
class AgentData:
    data_version: int
    data_date: str
    stale_after_days: int
    note: str
    agents: list = field(default_factory=list)
    path: str = ""


def _need(obj, key, where):
    if key not in obj:
        raise AgentsError("%s: missing required field %r" % (where, key))
    return obj[key]


def load_agents(path=None):
    path = path or DEFAULT_PATH
    try:
        with open(path, "rb") as fh:
            raw = json.loads(fh.read().decode("utf-8"))
    except (OSError, ValueError) as exc:
        raise AgentsError("cannot load agent data %s: %s" % (path, exc.__class__.__name__))
    if _need(raw, "schema_version", "agents") != 1:
        raise AgentsError("unsupported agent data schema_version")
    origins = _need(raw, "origins", "agents")
    data = AgentData(
        data_version=_need(raw, "data_version", "agents"),
        data_date=_need(raw, "data_date", "agents"),
        stale_after_days=int(raw.get("stale_after_days", 30)),
        note=raw.get("note", ""),
        path=path,
    )
    if parse_date(data.data_date) is None:
        raise AgentsError("agents: data_date must be YYYY-MM-DD")
    seen = set()
    for a in _need(raw, "agents", "agents"):
        aid = _need(a, "id", "agent")
        if aid in seen:
            raise AgentsError("duplicate agent id %r" % aid)
        seen.add(aid)
        findings = []
        for f in _need(a, "findings", "agent %r" % aid):
            fid = _need(f, "id", "agent %r" % aid)
            status = _need(f, "status", fid)
            if status not in STATUSES:
                raise AgentsError("%s: bad status %r" % (fid, status))
            if parse_date(_need(f, "status_date", fid)) is None:
                raise AgentsError("%s: status_date must be YYYY-MM-DD" % fid)
            for vkey in ("fixed_in", "last_vulnerable"):
                if f.get(vkey) and parse_version(f[vkey]) is None:
                    raise AgentsError("%s: %s is not a version" % (fid, vkey))
            ev = []
            for e in f.get("evidence", []):
                oid = _need(e, "origin", fid)
                if oid not in origins:
                    raise AgentsError("%s: unknown evidence origin %r" % (fid, oid))
                ev.append(Evidence(oid, origins[oid].get("title", oid), origins[oid].get("url", ""), e.get("note", "")))
            ctx = []
            for e in f.get("context_evidence", []):
                oid = _need(e, "origin", fid)
                if oid not in origins:
                    raise AgentsError("%s: unknown context origin %r" % (fid, oid))
                ctx.append(Evidence(oid, origins[oid].get("title", oid), origins[oid].get("url", ""), e.get("note", "")))
            findings.append(
                AgentFinding(
                    id=fid,
                    path=f.get("path", ""),
                    sinks=tuple(f.get("sinks", [])),
                    status=status,
                    fixed_in=f.get("fixed_in", ""),
                    last_vulnerable=f.get("last_vulnerable", ""),
                    status_date=f["status_date"],
                    detail=f.get("detail", ""),
                    caveat=f.get("caveat", ""),
                    gate=bool(f.get("gate", False)),
                    evidence=tuple(ev),
                    verification=verification_for(ev),
                    context=tuple(ctx),
                )
            )
        data.agents.append(
            Agent(
                id=aid,
                name=_need(a, "name", "agent %r" % aid),
                npm_packages=tuple(a.get("detect", {}).get("npm_packages", [])),
                findings=tuple(findings),
            )
        )
    return data


def parse_date(text):
    m = re.match(r"([0-9]{4})-([0-9]{2})-([0-9]{2})\Z", text or "")
    if not m:
        return None
    import datetime

    try:
        return datetime.date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
    except ValueError:
        return None


def parse_version(text):
    """Return a tuple of ints, or None. A letter suffix ('-beta', 'rc1') marks
    a pre-release and sorts BELOW the plain release, so a pre-release of the
    fix version is never treated as fixed. Anything else after the numbers
    (spaces, junk, over-long numbers) is not a version."""
    if not isinstance(text, str):
        return None
    m = _VERSION_RE.fullmatch(text.strip())
    if not m:
        return None
    nums = tuple(int(p) for p in m.group(1).split("."))
    return nums + (-1,) if m.group(2) else nums


def _cmp(a, b):
    n = max(len(a), len(b))
    a = a + (0,) * (n - len(a))
    b = b + (0,) * (n - len(b))
    return (a > b) - (a < b)


@dataclass(frozen=True)
class Assessment:
    level: str  # ok | affected | unknown | version-unknown | fixed-no-version-info
    text: str
    floors_review: bool  # True: this row alone keeps the pre-flight from reading as clean


def assess(finding, version_text):
    """Compare one installed version string with one finding. version_text
    may be None (not known)."""
    v = parse_version(version_text) if version_text else None
    fixed = parse_version(finding.fixed_in) if finding.fixed_in else None
    last = parse_version(finding.last_vulnerable) if finding.last_vulnerable else None

    if finding.status == "fixed":
        if fixed is None:
            return Assessment(
                "fixed-no-version-info",
                "reported fixed; the fixed-in version was not established, so your version (%s) cannot be checked" % version_text if version_text else "reported fixed; the fixed-in version was not established, so your version cannot be checked",
                bool(version_text),
            )
        if v is None:
            return Assessment("version-unknown", "reported fixed in %s; your version is not known" % finding.fixed_in, True)
        if _cmp(v, fixed) >= 0:
            return Assessment(
                "ok",
                "your version (%s) is at or above %s, the version reported to carry the fix" % (version_text, finding.fixed_in),
                finding.gate,
            )
        return Assessment(
            "affected",
            "your version (%s) is BELOW %s, where the fix is reported" % (version_text, finding.fixed_in),
            True,
        )

    # status unknown / unpatched: no fix version is known.
    if v is None:
        return Assessment("version-unknown", "no fix known; your version is not known", True)
    if last is not None and _cmp(v, last) <= 0:
        return Assessment(
            "affected",
            "your version (%s) is at or below %s, a version confirmed vulnerable, and no fix is known" % (version_text, finding.last_vulnerable),
            True,
        )
    return Assessment(
        "unknown",
        "your version (%s) is newer than the last version tested (%s); whether it is fixed is not known" % (version_text, finding.last_vulnerable or "none"),
        True,
    )


def _node_roots(environ):
    roots = []
    home = environ.get("HOME") or environ.get("USERPROFILE") or ""
    appdata = environ.get("APPDATA") or ""
    prefix = environ.get("npm_config_prefix") or environ.get("NPM_CONFIG_PREFIX") or ""
    if prefix:
        roots += [os.path.join(prefix, "lib", "node_modules"), os.path.join(prefix, "node_modules")]
    if appdata:
        roots.append(os.path.join(appdata, "npm", "node_modules"))
    if home:
        roots += [
            os.path.join(home, ".npm-global", "lib", "node_modules"),
            os.path.join(home, ".local", "lib", "node_modules"),
        ]
        nvm = os.path.join(home, ".nvm", "versions", "node")
        if path_kind(nvm) in ("dir", "symlink-dir"):
            try:
                with os.scandir(nvm) as it:
                    for e in sorted(it, key=lambda x: x.name)[:50]:
                        roots.append(os.path.join(e.path, "lib", "node_modules"))
            except OSError:
                pass
    roots += ["/usr/local/lib/node_modules", "/usr/lib/node_modules", "/opt/homebrew/lib/node_modules"]
    seen, out = set(), []
    for r in roots:
        k = os.path.normcase(r)
        if k not in seen:
            seen.add(k)
            out.append(r)
    return out


def detect_installed(data, environ):
    """Return {agent_id: [(version_text, source_path), ...]}. Reads
    package.json files only. Best effort: agents that are not npm packages
    are never detected here."""
    found = {}
    roots = _node_roots(environ)
    for agent in data.agents:
        for pkg in agent.npm_packages:
            for root in roots:
                pj = os.path.join(root, *pkg.split("/"), "package.json")
                r = read_regular_file(pj, max_bytes=256 * 1024)
                if r.status != "ok":
                    continue
                try:
                    obj = json.loads(r.data.decode("utf-8", errors="replace"))
                except ValueError:
                    continue
                if not isinstance(obj, dict) or obj.get("name") != pkg or not isinstance(obj.get("version"), str):
                    continue
                found.setdefault(agent.id, []).append((obj["version"], pj))
    return found


def parse_declared(items, data):
    """['claude-code=2.1.252', ...] -> {id: [(version, 'declared on the command line')]}"""
    ids = {a.id for a in data.agents}
    out = {}
    for item in items or []:
        if "=" not in item:
            raise AgentsError("--agent expects ID=VERSION, got %r" % item)
        aid, ver = item.split("=", 1)
        aid, ver = aid.strip(), ver.strip()
        if aid not in ids:
            raise AgentsError("unknown agent id %r; known ids: %s" % (aid, ", ".join(sorted(ids))))
        if parse_version(ver) is None:
            raise AgentsError("not a version: %r" % ver)
        out.setdefault(aid, []).append((ver, "declared on the command line"))
    return out
