"""Load and validate the sink ruleset. The ruleset is data (data/sinks.json).

The only logic keyed by the data is the small fixed set of named matchers
in engine.py. New sinks that reuse a matcher are a pure data change.
"""

import json
import os
from dataclasses import dataclass, field

MATCHERS = ("command_string", "bool_or_command", "bang_prefix", "ext_url", "value_in", "any_value", "include")
SEVERITIES = ("critical", "review", "info")
DEFAULT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "sinks.json")


class RulesetError(Exception):
    pass


@dataclass(frozen=True)
class Evidence:
    origin: str
    title: str
    url: str
    note: str


@dataclass(frozen=True)
class Rule:
    id: str
    key: str
    tier: str
    match: str
    severity: str
    protected_only: bool
    multivalued: bool
    safe_values: tuple
    hit_values: tuple
    sweep: tuple
    protections: dict
    triggers: str
    reached_by: tuple
    evidence: tuple
    verification: str  # two-source | single-source | unverified
    attribute: str = ""  # "filter" | "diff" | "merge": gitattributes key that selects this driver
    host_severity: str = ""  # severity when the setting is in global/system config; "" = derived
    host_benign_values: tuple = ()  # exact, case-sensitive values of well-known tools; info in host scope only


@dataclass
class Ruleset:
    schema_version: int
    ruleset_version: int
    ruleset_date: str
    rules: list = field(default_factory=list)
    path: str = ""
    hooks: dict = field(default_factory=dict)  # hook file name -> operations that fire it
    hooks_verification: str = "unverified"
    hooks_evidence: tuple = ()
    environment: list = field(default_factory=list)  # [{name, severity, effect}]


def _need(obj, key, where):
    if key not in obj:
        raise RulesetError("%s: missing required field %r" % (where, key))
    return obj[key]


def verification_for(evidence):
    origins = {e.origin for e in evidence}
    if len(origins) >= 2:
        return "two-source"
    if len(origins) == 1:
        return "single-source"
    return "unverified"


def load_ruleset(path=None):
    path = path or DEFAULT_PATH
    try:
        with open(path, "rb") as fh:
            raw = json.loads(fh.read().decode("utf-8"))
    except (OSError, ValueError) as exc:
        raise RulesetError("cannot load ruleset %s: %s" % (path, exc.__class__.__name__))

    if _need(raw, "schema_version", "ruleset") != 1:
        raise RulesetError("unsupported ruleset schema_version")
    origins = _need(raw, "origins", "ruleset")
    protections = _need(raw, "protections", "ruleset")
    rs = Ruleset(
        schema_version=raw["schema_version"],
        ruleset_version=_need(raw, "ruleset_version", "ruleset"),
        ruleset_date=_need(raw, "ruleset_date", "ruleset"),
        path=path,
    )
    hooks = raw.get("hooks", {})
    if not isinstance(hooks, dict) or not all(isinstance(v, str) for v in hooks.values()):
        raise RulesetError("hooks must map hook name to a description string")
    rs.hooks = dict(hooks)
    hev = []
    for e in raw.get("hooks_evidence", []):
        oid = _need(e, "origin", "hooks_evidence")
        if oid not in origins:
            raise RulesetError("hooks_evidence: unknown origin %r" % oid)
        hev.append(Evidence(oid, origins[oid].get("title", oid), origins[oid].get("url", ""), e.get("note", "")))
    rs.hooks_verification = verification_for(hev)
    rs.hooks_evidence = tuple(hev)
    for env in raw.get("environment", []):
        if _need(env, "severity", "environment") not in SEVERITIES:
            raise RulesetError("environment: bad severity for %r" % env.get("name"))
        rs.environment.append({"name": _need(env, "name", "environment"), "severity": env["severity"], "effect": env.get("effect", "")})
    seen = set()
    for idx, s in enumerate(_need(raw, "sinks", "ruleset")):
        where = "sinks[%d]" % idx
        rid = _need(s, "id", where)
        where = "sink %r" % rid
        if rid in seen:
            raise RulesetError("%s: duplicate id" % where)
        seen.add(rid)
        match = _need(s, "match", where)
        if match not in MATCHERS:
            raise RulesetError("%s: unknown matcher %r" % (where, match))
        severity = _need(s, "severity", where)
        if severity not in SEVERITIES:
            raise RulesetError("%s: bad severity %r" % (where, severity))
        if s.get("host_severity", "") not in ("",) + SEVERITIES:
            raise RulesetError("%s: bad host_severity" % where)
        hb = s.get("host_benign_values", [])
        if not isinstance(hb, list) or not all(isinstance(v, str) and v for v in hb):
            raise RulesetError("%s: host_benign_values must be a list of non-empty strings" % where)
        if s.get("attribute", "") not in ("", "filter", "diff", "merge"):
            raise RulesetError("%s: bad attribute" % where)
        if match == "value_in" and not s.get("hit_values"):
            raise RulesetError("%s: value_in needs hit_values" % where)
        prot_key = _need(s, "protections", where)
        if prot_key not in protections:
            raise RulesetError("%s: unknown protections %r" % (where, prot_key))
        key = _need(s, "key", where)
        if "." not in key:
            raise RulesetError("%s: key needs section.name form" % where)
        ev = []
        for e in s.get("evidence", []):
            oid = _need(e, "origin", where)
            if oid not in origins:
                raise RulesetError("%s: unknown evidence origin %r" % (where, oid))
            ev.append(Evidence(oid, origins[oid].get("title", oid), origins[oid].get("url", ""), e.get("note", "")))
        rs.rules.append(
            Rule(
                id=rid,
                key=key,
                tier=_need(s, "tier", where),
                match=match,
                severity=severity,
                protected_only=bool(s.get("protected_only", False)),
                multivalued=bool(s.get("multivalued", False)),
                safe_values=tuple(v.lower() for v in s.get("safe_values", [])),
                hit_values=tuple(v.lower() for v in s.get("hit_values", [])),
                sweep=tuple(t.lower() for t in s.get("sweep", [])),
                protections=protections[prot_key],
                triggers=_need(s, "triggers", where),
                reached_by=tuple(s.get("reached_by", [])),
                evidence=tuple(ev),
                verification=verification_for(ev),
                attribute=s.get("attribute", ""),
                host_severity=s.get("host_severity", ""),
                host_benign_values=tuple(s.get("host_benign_values", [])),
            )
        )
    return rs
