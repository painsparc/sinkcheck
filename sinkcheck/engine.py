"""Detection core. Applies the data ruleset to parsed configuration.

Hard rules for this module (see tests/test_00_detonation_gate.py):
  * no subprocess, no os.system, no git, no network, no writes;
  * every file read goes through safeio.read_regular_file;
  * directories are inspected with lstat/stat/scandir only, and a path
    taken from the scanned tree is vetted by safeio.unsafe_path_reason
    before any call that could touch the network or raise ValueError;
  * nothing named by the scanned tree is ever executed or opened for
    anything but a capped, regular-file read;
  * every limit that cuts the scan short produces a finding, so a
    truncated scan can never read as clean.
"""

import os
import re
from dataclasses import dataclass, field
from itertools import islice

from .attributes import MAX_LINES as MAX_ATTR_LINES, parse_attributes
from .discover import MAX_DIR_ENTRIES, find_enclosing, looks_like_gitdir, walk_tree
from .gitconfig import Entry, key_matches, parse_config_bytes
from .safeio import path_kind, read_regular_file, unsafe_path_reason
from .sanitize import safe_text

SEVERITY_RANK = {"critical": 0, "review": 1, "info": 2}
_BOOL_WORDS = ("true", "yes", "on")
_INT_RE = re.compile(r"[+-]?[0-9]+\Z")
_WINDOWS_ONLY_SAFE = ("nul",)  # a safe_value that is the null device only on Windows

MAX_INCLUDE_DEPTH = 10  # git's own limit
MAX_INCLUDE_FILES = 200
MAX_GITDIRS = 500
MAX_ENV_CONFIG = 100
MAX_FINDINGS_PER_FILE = 1000
MAX_TOTAL_FINDINGS = 5000
MAX_TOTAL_ENTRIES = 2000000
CLIP = 120

# What this build does NOT look at. The report prints this list next to the
# verdict, plus anything a cap or an unreadable directory cut short.
NOT_EXAMINED = [
    "the contents of hook files (only their presence and names are reported)",
    "attribute files outside the target (a core.attributesFile that points outside it, global and system)",
    "the tree object named by attr.tree (git objects are not read, so the attributes it carries are not known)",
    "conditions of includeIf (every conditional include is followed and flagged, none is evaluated)",
    "submodules that are not present in the target",
]


class TargetError(Exception):
    pass


def _clip(text, n=CLIP):
    if text is None:
        return None
    return text if len(text) <= n else text[:n] + "..."


def _clip_tail(text, n=1000):
    return text if len(text) <= n else "..." + text[-n:]


@dataclass
class Finding:
    severity: str  # critical | review | info
    kind: str  # sink | parse | read | sweep | coverage | structure | include | hook | env | hardening | limit
    key: str = ""
    file: str = ""
    line: int = 0
    value: object = None
    note: str = ""
    rule: object = None
    driver: str = ""  # subsection of a filter/diff/merge driver, for attribute pairing
    via: str = ""  # include chain that led to this file
    verification: str = ""  # for findings without a rule (hooks)
    sources: tuple = ()  # evidence URLs for findings without a rule


@dataclass
class ScanResult:
    target: str
    ruleset: object
    gitdir: object = None
    findings: list = field(default_factory=list)
    examined: list = field(default_factory=list)
    not_examined: list = field(default_factory=lambda: list(NOT_EXAMINED))
    context: list = field(default_factory=list)
    ceiling: object = None
    seen_configs: dict = field(default_factory=dict)  # (realpath, read mode, scope) -> shallowest include depth scanned
    examined_real: set = field(default_factory=set)  # realpaths already listed under Examined
    incomplete: list = field(default_factory=list)  # reasons a budget or cap cut the scan short
    dup_includes: int = 0  # include references to already-examined files, not read again
    gitdirs_done: set = field(default_factory=set)
    include_files: int = 0
    attr_refs: list = field(default_factory=list)
    counts: dict = field(default_factory=dict)
    host_entries: list = field(default_factory=list)  # [(Entry, path)] from global/system config
    current_root: str = ""  # the directory scan_root is examining now
    suppressed: int = 0  # lower-severity findings dropped by the total cap
    entries_processed: int = 0

    def add(self, finding):
        if len(self.findings) >= MAX_TOTAL_FINDINGS and finding.severity != "critical":
            self.suppressed += 1
            return
        self.findings.append(finding)

    def count(self, name, n=1):
        self.counts[name] = self.counts.get(name, 0) + n

    def limit(self, note, file="", kind="coverage", line=0, value=None, via=""):
        """A budget or cap was hit, so something was NOT examined. This marks the
        whole scan incomplete: the verdict becomes a hard INCOMPLETE state (exit 3)
        unless a critical finding already decided it, and --fail-on cannot soften it."""
        note = _clip(note, 300)
        if note not in self.incomplete and len(self.incomplete) < 20:
            self.incomplete.append(note)
        self.add(Finding("review", kind, file=_clip(file, 300), line=line, value=value, via=via, note=note))


def _is_safe_value(rule, low):
    return low in rule.safe_values and (low not in _WINDOWS_ONLY_SAFE or os.name == "nt")


def evaluate(rule, value):
    """Return (hit, force_review, note) for a rule against one value."""
    if value is None:
        if rule.match in ("any_value", "include"):
            return True, False, ""
        if rule.match == "bool_or_command":
            return False, False, ""
        return (
            True,
            True,
            "setting has no value; git would not run it as written, "
            "but a parser difference is possible",
        )
    low = value.lower()
    m = rule.match
    if m == "command_string":
        if value == "" or _is_safe_value(rule, low):
            return False, False, ""
        return True, False, ""
    if m == "bool_or_command":
        if _is_safe_value(rule, low) or low in _BOOL_WORDS or _INT_RE.match(low):
            return False, False, ""
        return True, False, ""
    if m == "bang_prefix":
        return value.startswith("!"), False, ""
    if m == "ext_url":
        return low.startswith("ext::"), False, ""
    if m == "value_in":
        return low in rule.hit_values, False, ""
    return True, False, ""  # any_value, include


def _entry_identity(entry):
    return (entry.section, entry.subsection, entry.name)


HOST_DEFAULT = {"critical": "review", "review": "info", "info": "info"}


def _rules_by_section(ruleset):
    idx = getattr(ruleset, "_by_section", None)
    if idx is None:
        idx = {}
        for r in ruleset.rules:
            idx.setdefault(r.key.split(".", 1)[0].lower(), []).append(r)
        ruleset._by_section = idx
    return idx


def _apply_rules(entries, path, ruleset, result, via="", only_prefix=None, scope="repo"):
    """scope: 'repo' (planted-tree semantics), 'host' (global/system config:
    a protected scope that applies to every repository you open) or 'env'
    (GIT_CONFIG_* variables: also protected)."""
    protected_scope = scope != "repo"
    by_section = _rules_by_section(ruleset)
    # only settings in a section some rule looks at cost work, so junk lines cannot burn the budget cheaply
    result.entries_processed += sum(1 for e in entries if e.section in by_section)
    if result.entries_processed > MAX_TOTAL_ENTRIES:
        if not result.counts.get("entry_budget"):
            result.count("entry_budget")
        result.limit("work budget of %d settings exhausted; this file and everything scanned after it was not examined" % MAX_TOTAL_ENTRIES, file=path)
        return
    last_line = {}
    for e in entries:
        last_line[_entry_identity(e)] = e.line
    for e in entries:
        for rule in by_section.get(e.section, ()):
            if only_prefix and not rule.key.lower().startswith(only_prefix):
                continue
            if not key_matches(rule.key, e):
                continue
            hit, force_review, note = evaluate(rule, e.value)
            if not hit:
                continue
            severity = rule.severity
            notes = [note] if note else []
            if rule.protected_only and not protected_scope:
                severity = "info"
                notes.append("git ignores this variable in repo-local config")
            elif scope == "env":
                notes.append("set through the environment, which is a protected scope: git honors it")
            elif scope == "host":
                severity = rule.host_severity or HOST_DEFAULT.get(rule.severity, rule.severity)
                if severity != "info" and e.value is not None and e.value in rule.host_benign_values:
                    severity = "info"
                    notes.append(
                        "exact value of a widely used tool (listed in the ruleset as host-benign); it still "
                        "runs for every repository you open, and assumes that program on your PATH is the real one"
                    )
                if severity != "info":
                    notes.append(
                        "set in your own global/system configuration, which applies to every repository "
                        "you open, including untrusted ones; confirm you set it"
                    )
                if rule.protected_only:
                    notes.append("git honors this variable in this scope")
            elif not rule.multivalued and rule.match != "include" and last_line[_entry_identity(e)] != e.line:
                if severity == "critical":
                    severity = "review"
                notes.append(
                    "shadowed by a later assignment at line %d; inert only if this "
                    "parse matches git's" % last_line[_entry_identity(e)]
                )
            if force_review and severity == "critical":
                severity = "review"
            if rule.id == "core.attributesfile" and scope == "repo":
                notes.append(_follow_attributes_file(e.value, result))
            result.add(
                Finding(
                    severity,
                    "sink",
                    key=_clip(e.key, 300),
                    file=path,
                    line=e.line,
                    value=_clip(e.value, 400),
                    note="; ".join(n for n in notes if n),
                    rule=rule,
                    driver=_clip((e.subsection or ""), 300) if rule.attribute and e.subsection is not None else "",
                    via=via,
                )
            )


def scan_config_bytes(data, path, ruleset, result, via="", only_prefix=None, follow=None, scope="repo"):
    """Evaluate one config file's bytes. Appends findings to result and
    returns the ParseResult. When follow is given it is called as
    follow(entry, rule) for each include entry; otherwise includes are
    reported but not followed."""
    parsed = parse_config_bytes(data)
    for err in parsed.errors:
        result.add(
            Finding(
                "review",
                "parse",
                file=path,
                line=err.line,
                via=via,
                note="parse error: %s. Git may read this file differently than this tool does." % err.message,
            )
        )

    before = len(result.findings)
    _apply_rules(parsed.entries, path, ruleset, result, via=via, only_prefix=only_prefix, scope=scope)
    if scope == "host":
        result.host_entries.extend((e, path) for e in parsed.entries)

    new = result.findings[before:]
    if len(new) > MAX_FINDINGS_PER_FILE:
        keep = sorted(new, key=lambda f: SEVERITY_RANK[f.severity])[:MAX_FINDINGS_PER_FILE]
        dropped = len(new) - len(keep)
        del result.findings[before:]
        result.findings.extend(keep)
        result.add(Finding("review", "coverage", file=path, via=via,
                           note="%d more findings in this file are not listed (per-file cap %d); every critical finding is kept first"
                                % (dropped, MAX_FINDINGS_PER_FILE)))
    for f in result.findings[before:]:
        if f.rule is not None and f.rule.match == "include":
            f.note = "; ".join(
                n for n in (f.note, "include target is followed by this build" if follow else "include target not examined in this mode") if n
            )

    if follow is not None:
        for e in parsed.entries:
            for rule in _rules_by_section(ruleset).get(e.section, ()):
                if rule.match == "include" and key_matches(rule.key, e):
                    follow(e, rule)
                    break

    # Defence in depth against parser differentials: a distinctive sink
    # name present in the raw bytes but not parsed as a setting.
    lowered = data.decode("utf-8", errors="replace").lower()
    parsed_names = {e.name for e in parsed.entries}
    for rule in ruleset.rules:
        if only_prefix and not rule.key.lower().startswith(only_prefix):
            continue
        for token in rule.sweep:
            if token in lowered and token not in parsed_names:
                result.add(
                    Finding(
                        "review",
                        "sweep",
                        key=rule.key,
                        file=path,
                        via=via,
                        note=(
                            "the text %r appears in the file but was not parsed as a setting "
                            "(comment, value text, or a difference between this parser and git's)" % token
                        ),
                        rule=rule,
                    )
                )
    return parsed


def _refused(result, path, what, via=""):
    reason = unsafe_path_reason(path)
    if reason:
        result.add(Finding("review", "coverage", file=_clip(path, 300), via=via,
                           note="%s refused before any filesystem call: %s; not examined" % (what, reason)))
        return True
    return False


def _config_key(path, only_prefix, scope):
    """Identity of one examination: the resolved file, HOW it is read (a .gitmodules
    read keeps only submodule.* settings, an include read keeps everything) and the
    scope it is read in (host and repo scopes grade severities differently). A file
    examined one way must not stop it being examined another way."""
    try:
        real = os.path.normcase(os.path.realpath(path))
    except (OSError, ValueError):
        real = os.path.normcase(os.path.abspath(path))
    return (real, only_prefix or "", scope)


def scan_config_file(path, ruleset, result, label, via="", depth=0, optional=False, only_prefix=None, scope="repo"):
    r = read_regular_file(path)
    if r.status == "missing":
        if not optional:
            result.add(Finding("info", "read", file=path, via=via, note="%s not present" % label))
        return
    if r.status != "ok":
        result.add(
            Finding(
                "review",
                "read",
                file=_clip(path, 300),
                via=via,
                note="%s was not read: %s %s. Nothing in it was examined." % (label, r.status, r.detail),
            )
        )
        return
    key = _config_key(path, only_prefix, scope)
    prev = result.seen_configs.get(key)
    if prev is not None and depth >= prev:
        result.dup_includes += 1
        return
    result.seen_configs[key] = depth
    if key[0] not in result.examined_real:
        result.examined_real.add(key[0])
        result.examined.append("%s (%s)" % (path, label))
    if r.is_symlink:
        result.add(
            Finding(
                "review",
                "structure",
                file=path,
                via=via,
                note="%s is a symbolic link; it was read through the link" % label,
            )
        )

    follow = None
    if not only_prefix:  # git does not process includes in .gitmodules

        def follow(entry, rule):
            _follow_include(entry, rule, path, ruleset, result, via, depth, scope)

    scan_config_bytes(r.data, path, ruleset, result, via=via, only_prefix=only_prefix, follow=follow, scope=scope)


def _follow_include(entry, rule, base_path, ruleset, result, via, depth, scope="repo"):
    raw = entry.value
    if raw is None or raw == "":
        return
    here = "%s:%d" % (_clip(base_path, 300), entry.line)
    conditional = ""
    if entry.section == "includeif":
        conditional = ' (conditional: includeIf "%s", condition not evaluated)' % _clip(entry.subsection or "")
    chain = _clip_tail((via + " > " if via else "") + "include at " + here + conditional)

    def note(text):
        result.add(Finding("review", "include", file=_clip(base_path, 300), line=entry.line, value=_clip(raw, 400), via=via, note=text))

    if raw.startswith("%(prefix)/"):
        note("include path uses the runtime-prefix form; it was not resolved")
        return
    if raw.startswith("~/") or raw == "~":
        try:
            target = os.path.expanduser(raw)
        except Exception:
            target = "~"
        if target.startswith("~"):
            note("home directory could not be expanded; include not examined")
            return
    elif raw.startswith("~"):
        note("include path names another user's home; it was not resolved")
        return
    elif os.path.isabs(raw):
        target = raw
    else:
        target = os.path.join(os.path.dirname(base_path), raw)

    if _refused(result, target, "include target", via=via):
        return
    # a repeated reference to a file already examined is free: it must not spend the file budget
    # (otherwise a pile of decoy references starves the one real include behind them)
    prev = result.seen_configs.get(_config_key(target, None, scope))
    if prev is not None and depth + 1 >= prev:
        result.dup_includes += 1
        return
    if depth + 1 > MAX_INCLUDE_DEPTH:
        result.limit("include nesting deeper than %d; this target and anything below it was not examined" % MAX_INCLUDE_DEPTH,
                     file=base_path, kind="include", line=entry.line, value=_clip(raw, 400), via=via)
        return
    if result.include_files >= MAX_INCLUDE_FILES:
        result.limit("more than %d included files; this target was not examined" % MAX_INCLUDE_FILES,
                     file=base_path, kind="include", line=entry.line, value=_clip(raw, 400), via=via)
        return
    result.include_files += 1
    scan_config_file(target, ruleset, result, "included config", via=chain, depth=depth + 1, scope=scope)


def _inside(child, parent):
    try:
        c = os.path.normcase(os.path.realpath(child))
        p = os.path.normcase(os.path.realpath(parent))
        return os.path.commonpath([c, p]) == p
    except (ValueError, OSError):
        return False


def _resolve_from(base_dir, text):
    return text if os.path.isabs(text) else os.path.join(base_dir, text)


def _collect_attributes(path, result, label):
    r = read_regular_file(path)
    if r.status == "missing":
        return
    if r.status != "ok":
        result.add(Finding("review", "read", file=_clip(path, 300),
                           note="%s was not read: %s %s. Nothing in it was examined." % (label, r.status, r.detail)))
        return
    if r.data.count(b"\n") > MAX_ATTR_LINES:
        result.limit("attribute file has more than %d lines; only the first %d were read, so driver pairing may be incomplete"
                     % (MAX_ATTR_LINES, MAX_ATTR_LINES), file=path)
    result.attr_refs.extend(parse_attributes(r.data, path))
    result.count(label)


def _follow_attributes_file(value, result):
    """core.attributesFile set in repository config. git opens a relative value
    from the top of the work tree; this reads it only when it resolves inside the
    scanned target. Returns a note for the finding."""
    if not value:
        return "empty value; nothing to read"
    if value.startswith("~"):
        return "names a file under a home directory, outside the target; it was not read, so drivers it selects are unknown"
    root = result.current_root or result.target
    path = _resolve_from(root, value)
    if not _inside(path, root):
        return "names a file outside the target; it was not read, so drivers it selects are unknown"
    if _refused(result, path, "core.attributesFile target"):
        return "the named file was refused; not read"
    _collect_attributes(path, result, "core.attributesFile file(s) inside the target")
    return ("names a file inside the target, which was read and paired with drivers "
            "(resolved from the target root, as git does when run from the top of the work tree)")


def _list_dir(path, cap, result, what):
    """Bounded, sorted listing. Returns entries or None (with a finding)."""
    try:
        with os.scandir(path) as it:
            entries = list(islice(it, cap + 1))
    except (OSError, ValueError) as exc:
        result.add(Finding("review", "read", file=_clip(path, 300), note="%s not listed: %s" % (what, exc.__class__.__name__)))
        return None
    if len(entries) > cap:
        entries = entries[:cap]
        result.limit("%s has more than %d entries; only the first %d were examined" % (what, cap, cap), file=path)
    return sorted(entries, key=lambda e: e.name)


def _scan_hooks(hooks_dir, ruleset, result):
    k = path_kind(hooks_dir)
    if k == "missing":
        return
    if k == "symlink-dir":
        result.add(Finding("review", "structure", file=hooks_dir,
                           note="hooks is a symbolic link to a directory; it was NOT followed, so the hooks it points at were not listed"))
        return
    if k != "dir":
        result.add(Finding("review", "structure", file=hooks_dir, note="hooks is not a directory; not examined"))
        return
    entries = _list_dir(hooks_dir, MAX_DIR_ENTRIES, result, "hooks directory")
    if entries is None:
        return
    result.examined.append("%s (hooks directory, names only)" % hooks_dir)
    sources = tuple(e.url for e in ruleset.hooks_evidence)
    for e in entries:
        if e.name.endswith(".sample"):
            continue
        kind = path_kind(e.path)
        if e.name in ruleset.hooks:
            exec_note = ""
            if os.name != "nt":
                try:
                    if not (os.stat(e.path).st_mode & 0o111):
                        exec_note = "; not marked executable, so git on this platform would skip it"
                except (OSError, ValueError):
                    pass
            else:
                exec_note = "; executable bit is not meaningful on this platform, so assume it can run"
            result.add(Finding(
                "review", "hook", key=e.name, file=e.path, value=kind,
                note="hook present; fires on: %s%s" % (ruleset.hooks[e.name], exec_note),
                verification=ruleset.hooks_verification, sources=sources,
            ))
        else:
            result.add(Finding("info", "hook", key=_clip(e.name, 300), file=e.path, value=kind,
                               note="file in hooks directory whose name is not a hook git runs"))


def _handle_gitfile(path, ruleset, result, is_root):
    r = read_regular_file(path, max_bytes=4096)
    if r.status != "ok":
        result.add(Finding("review", "read", file=_clip(path, 300),
                           note=".git file was not read: %s %s" % (r.status, r.detail)))
        return
    text = r.data.decode("utf-8", errors="replace")
    first = text.split("\n", 1)[0].rstrip("\r")
    if not first.startswith("gitdir:"):
        result.add(Finding("review", "structure", file=path, value=_clip(first, 400),
                           note=".git is a file but does not start with 'gitdir:'; git would reject it, this tool cannot tell why"))
        return
    ref = first[len("gitdir:"):].strip()
    target = _resolve_from(os.path.dirname(path), ref)
    if _refused(result, target, "git directory redirect"):
        return
    inside = _inside(target, result.current_root or result.target)
    sev = "review" if (is_root or not inside) else "info"
    note = ".git is a file that redirects git to another directory"
    if not inside:
        note += "; that directory is OUTSIDE the scanned tree"
    result.add(Finding(sev, "structure", file=path, value=_clip(ref, 400), note=note))
    tk = path_kind(target)
    if tk in ("dir", "symlink-dir"):
        _scan_gitdir(target, ruleset, result, "redirected git directory")
    else:
        result.add(Finding("review", "structure", file=path, value=_clip(ref, 400),
                           note="redirect target is not a directory (%s); nothing was examined there" % tk))


def _scan_gitdir(gitdir, ruleset, result, label):
    if _refused(result, gitdir, "git directory"):
        return
    try:
        real = os.path.normcase(os.path.realpath(gitdir))
    except (OSError, ValueError):
        real = os.path.normcase(os.path.abspath(gitdir))
    if real in result.gitdirs_done:
        return
    if len(result.gitdirs_done) >= MAX_GITDIRS:
        if not result.counts.get("gitdir_cap"):
            result.count("gitdir_cap")
        result.limit("more than %d git directories; the rest were not examined" % MAX_GITDIRS, file=gitdir)
        return
    result.gitdirs_done.add(real)
    if result.gitdir is None:
        result.gitdir = gitdir

    scan_config_file(os.path.join(gitdir, "config"), ruleset, result, label + " config")
    scan_config_file(os.path.join(gitdir, "config.worktree"), ruleset, result, label + " worktree config", optional=True)

    cd = os.path.join(gitdir, "commondir")
    r = read_regular_file(cd, max_bytes=4096)
    if r.status == "ok":
        ref = r.data.decode("utf-8", errors="replace").split("\n", 1)[0].strip()
        common = _resolve_from(gitdir, ref)
        result.add(Finding("review", "structure", file=cd, value=_clip(ref, 400),
                           note="commondir redirects to a shared git directory whose configuration also applies"))
        if not _refused(result, common, "commondir target"):
            ck = path_kind(common)
            if ck in ("dir", "symlink-dir"):
                _scan_gitdir(common, ruleset, result, "common git directory")
            else:
                result.add(Finding("review", "structure", file=cd, value=_clip(ref, 400),
                                   note="commondir target is not a directory (%s); nothing was examined there" % ck))
    elif r.status != "missing":
        result.add(Finding("review", "read", file=_clip(cd, 300), note="commondir was not read: %s %s" % (r.status, r.detail)))

    wt = os.path.join(gitdir, "worktrees")
    wk = path_kind(wt)
    if wk == "dir":
        entries = _list_dir(wt, MAX_GITDIRS, result, "worktrees directory")
        for e in entries or []:
            ek = path_kind(e.path)
            if ek == "dir":
                scan_config_file(os.path.join(e.path, "config.worktree"), ruleset, result, "linked-worktree config", optional=True)
            else:
                result.add(Finding("review", "structure", file=_clip(e.path, 300),
                                   note="entry in worktrees/ is not a plain directory (%s); not examined" % ek))
    elif wk != "missing":
        result.add(Finding("review", "structure", file=wt,
                           note="worktrees is %s; it was NOT followed, so linked-worktree configuration was not examined" % wk))

    _scan_hooks(os.path.join(gitdir, "hooks"), ruleset, result)
    _collect_attributes(os.path.join(gitdir, "info", "attributes"), result, "info/attributes file(s)")

    modules = os.path.join(gitdir, "modules")
    mk = path_kind(modules)
    if mk == "dir":
        sub = walk_tree(modules)
        for p, _lbl in sub.gitdirs:
            _scan_gitdir(p, ruleset, result, "submodule git directory")
        for gf in sub.gitfiles:
            _handle_gitfile(gf, ruleset, result, is_root=False)
        for p, err in sub.unreadable:
            result.add(Finding("review", "coverage", file=_clip(p, 300),
                               note="directory under modules/ could not be listed (%s); nothing below it was examined" % err))
        if sub.truncated:
            result.limit(sub.truncated, file=modules)
    elif mk != "missing":
        result.add(Finding("review", "structure", file=modules,
                           note="modules is %s; it was NOT followed, so submodule git directories were not examined" % mk))


def _scan_environment(ruleset, result, environ):
    names = {k.upper() if os.name == "nt" else k: k for k in environ}
    for item in ruleset.environment:
        real = names.get(item["name"].upper() if os.name == "nt" else item["name"])
        if real is None:
            continue
        result.add(Finding(item["severity"], "env", key=item["name"], value=_clip(environ[real], 400), note=item["effect"]))
    count_key = names.get("GIT_CONFIG_COUNT")
    if count_key is None:
        return
    try:
        n = int(environ[count_key])
    except ValueError:
        result.add(Finding("review", "env", key="GIT_CONFIG_COUNT", value=_clip(environ[count_key], 400),
                           note="GIT_CONFIG_COUNT is not an integer; its key/value pairs were not examined"))
        return
    entries = []
    for i in range(max(0, min(n, MAX_ENV_CONFIG))):
        k = environ.get("GIT_CONFIG_KEY_%d" % i)
        v = environ.get("GIT_CONFIG_VALUE_%d" % i)
        if not k or "." not in k:
            continue
        section, rest = k.split(".", 1)
        if "." in rest:
            sub, name = rest.rsplit(".", 1)
        else:
            sub, name = None, rest
        entries.append(Entry(section.lower(), sub, name.lower(), v, i))
    _apply_rules(entries, "(environment GIT_CONFIG_KEY_n/VALUE_n)", ruleset, result, scope="env")
    if n > MAX_ENV_CONFIG:
        result.add(Finding("review", "env", key="GIT_CONFIG_COUNT", value=str(n),
                           note="only the first %d key/value pairs were examined" % MAX_ENV_CONFIG))


def _pair_attributes(result):
    by = {}
    for ref in result.attr_refs:
        by.setdefault((ref.attr, ref.driver), []).append(ref)
    attr_tree = any(f.kind == "sink" and f.rule is not None and f.rule.id == "attr.tree" and f.severity != "info"
                    for f in result.findings)
    for f in result.findings:
        if f.kind != "sink" or f.rule is None or not f.rule.attribute or not f.driver:
            continue
        refs = by.get((f.rule.attribute, f.driver))
        if refs:
            first = refs[0]
            extra = "" if len(refs) == 1 else " (+%d more)" % (len(refs) - 1)
            f.note = "; ".join(n for n in (f.note, "SELECTED: %s=%s is set for pattern %s at %s:%d%s" % (
                first.attr, _clip(first.driver), _clip(first.pattern), _clip(first.file, 300), first.line, extra)) if n)
        else:
            f.note = "; ".join(n for n in (f.note, "no %s= attribute selecting this driver was found in the attribute files examined; "
                                            "one outside the examined set could still select it" % f.rule.attribute) if n)
            if attr_tree:
                f.note += ("; attr.tree is set in this configuration, and the tree it names was not read, "
                           "so it may be what selects this driver")


def require_directory(target):
    if unsafe_path_reason(target) or path_kind(target) not in ("dir", "symlink-dir"):
        raise TargetError("target is not a usable directory: %s" % safe_text(target))


def _safely(result, where, fn, *args, **kwargs):
    """Run one examination step. An unexpected exception becomes a finding
    and the scan continues, so one hostile object cannot suppress findings
    elsewhere. AssertionError is re-raised so the test Guard still bites."""
    try:
        return fn(*args, **kwargs)
    except AssertionError:
        raise
    except Exception as exc:
        result.add(Finding("review", "coverage", file=_clip(str(where), 300),
                           note="internal error (%s) while examining this; it was not examined" % exc.__class__.__name__))
        return None


def scan_root(result, target, ruleset, ceiling=None, expect_nested=False):
    """Examine one directory into an existing ScanResult. expect_nested: the
    caller is auditing a container of many repositories (host audit), so a
    nested repository is normal and is not itself a finding."""
    ruleset = ruleset or result.ruleset
    result.current_root = target
    root_found = False

    dotgit = os.path.join(target, ".git")
    dk = path_kind(dotgit)
    if dk in ("dir", "symlink-dir"):
        if looks_like_gitdir(dotgit):
            root_found = True
            if dk == "symlink-dir":
                result.add(Finding("review", "structure", file=dotgit, note=".git is a symbolic link to a directory"))
            _safely(result, dotgit, _scan_gitdir, dotgit, ruleset, result, "repo-local")
        else:
            result.add(Finding(
                "review", "structure", file=dotgit,
                note=".git is a directory but not a valid git directory (HEAD, objects and refs are required); "
                     "git skips it and keeps searching upward. Its config is scanned anyway in case this tool's check differs from git's",
            ))
            _safely(result, dotgit, _scan_gitdir, dotgit, ruleset, result, "invalid .git directory")
    elif dk in ("file", "symlink-file"):
        root_found = True
        _safely(result, dotgit, _handle_gitfile, dotgit, ruleset, result, True)
    elif dk in ("other", "symlink-other"):
        result.add(Finding("review", "structure", file=dotgit, note=".git is neither a regular file nor a directory"))
    else:
        if looks_like_gitdir(target):
            root_found = True
            _safely(result, target, _scan_gitdir, target, ruleset, result, "repo-local (bare layout)")

    if not root_found:
        enc = find_enclosing(target, ceiling)
        if enc is not None:
            path, how = enc
            result.add(Finding("info" if expect_nested else "review", "structure", file=path,
                               note="the target is not a repository root; git run here would use the enclosing repository found by searching upward"))
            if how == "gitfile":
                _safely(result, path, _handle_gitfile, path, ruleset, result, True)
            else:
                _safely(result, path, _scan_gitdir, path, ruleset, result, "enclosing repository")
            root_found = True

    disc = walk_tree(target)
    result.context.append("directories walked: %d; symlinked directories not followed: %d" % (disc.dirs_visited, disc.symlinked_dirs))
    for p, lbl in disc.gitdirs:
        if lbl.startswith("buried") or (lbl.startswith("nested") and not expect_nested):
            result.add(Finding("review", "structure", file=p,
                               note="%s inside the target; git treats a directory shaped like this as a repository, and it travels with a plain clone" % lbl))
        _safely(result, p, _scan_gitdir, p, ruleset, result, lbl)
    for gf in disc.gitfiles:
        if os.path.normcase(os.path.abspath(gf)) != os.path.normcase(os.path.abspath(dotgit)):
            _safely(result, gf, _handle_gitfile, gf, ruleset, result, False)
    for a in disc.attribute_files:
        _safely(result, a, _collect_attributes, a, result, ".gitattributes file(s) in the working tree")
    for m in disc.gitmodules:
        _safely(result, m, scan_config_file, m, ruleset, result, ".gitmodules", optional=True, only_prefix="submodule.")
    for p, err in disc.unreadable:
        result.add(Finding("review", "coverage", file=_clip(p, 300), note="directory could not be listed (%s); nothing below it was examined" % err))
    if disc.truncated:
        result.limit(disc.truncated, file=target)

    if not root_found and not disc.gitdirs and not disc.gitfiles:
        result.add(Finding(
            "info" if expect_nested else "review", "coverage", file=target,
            note="no git directory found at the target root or by searching upward%s. "
                 "Nothing about git configuration was examined" % (
                     " (stopped at the ceiling %s)" % ceiling if ceiling else ""),
        ))


def finish_scan(result, ruleset, ceiling=None, environ=None):
    """Steps that run once per ScanResult, after every root has been examined."""
    environ = os.environ if environ is None else environ
    _scan_environment(ruleset, result, environ)
    _pair_attributes(result)

    if result.dup_includes:
        result.add(Finding("info", "include",
                           note="%d reference(s) to configuration files that were already examined were not read again" % result.dup_includes))
    for name, n in sorted(result.counts.items()):
        if name not in ("gitdir_cap", "entry_budget"):
            result.examined.append("%d %s" % (n, name))
    if ceiling:
        result.context.append("upward search stopped at ceiling: %s" % ceiling)
    else:
        result.context.append("upward search for an enclosing repository: unrestricted")


def scan_target(target, ruleset, ceiling=None, environ=None):
    require_directory(target)
    result = ScanResult(target=target, ruleset=ruleset, ceiling=ceiling)
    result.not_examined.append("your global and system git configuration (the audit command examines them)")
    result.not_examined.append("which agents you run and their patch status (the preflight command adds this)")
    scan_root(result, target, ruleset, ceiling=ceiling)
    finish_scan(result, ruleset, ceiling=ceiling, environ=environ)
    return result


def verdict_of(result):
    """Return (name, exit_code). Exit codes: 0 nothing found, 1 critical, 2 needs review,
    3 the scan did not finish (a budget or cap was hit). A critical finding still wins (it
    is non-zero and more specific); otherwise an unfinished scan is its own hard state,
    never 0 and never softened by --fail-on."""
    sev = {f.severity for f in result.findings}
    if "critical" in sev:
        return "CRITICAL", 1
    if result.incomplete:
        return "INCOMPLETE - SCAN DID NOT FINISH", 3
    if "review" in sev or result.suppressed:
        return "NEEDS REVIEW", 2
    return "NOTHING FOUND", 0
