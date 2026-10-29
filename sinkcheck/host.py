"""Host audit: the same engine pointed at your own machine.

It reads, as data, the global and system git configuration (and anything
they include), optionally walks directories you name for repositories, and
looks at GIT_* environment variables. Verdict wording differs from a scan of
an untrusted tree: a command string in your own global configuration is
usually something you put there, so it is reported for confirmation, not
as an attack.

Read-only. It never edits a config file, never runs git, and the hardening
commands it prints are instructions for you to run if you choose to.
"""

import os

from .engine import (
    Finding,
    ScanResult,
    finish_scan,
    require_directory,
    scan_config_file,
    scan_root,
    verdict_of,
)

_TRUE_WORDS = ("1", "true", "yes", "on")

HARDEN_BARE = (
    "safe.bareRepository is not 'explicit' in global/system configuration (value seen: %s). "
    "With 'explicit', git refuses a bare repository it merely discovers, which is the route that "
    "survives a plain git clone. Instruction only, this tool never runs it: "
    "git config --global safe.bareRepository explicit . "
    "Trade-off: running git inside a bare repository then needs --git-dir. Needs a git version that "
    "has the setting (introduced in 2.38.0 per the cited advisory; single-source)."
)
HARDEN_FSMONITOR_FALSE = (
    "core.fsmonitor is set to false in your global configuration. That does NOT protect you from a "
    "repository's own config: configuration sources are read in order and a later (repository-local) "
    "value overrides an earlier (global) one (git-config(1), FILES: \"The files are read in the order "
    "given above, with last value found taking precedence over values read earlier\"; Pro Git, "
    "Customizing Git: values in .git/config trump those in the system file). A per-call override is "
    "the usual way to outrank repository config: git -c core.fsmonitor=false <command> . That "
    "per-call precedence is not covered by those two citations."
)


FSMONITOR_PRECEDENCE_SOURCES = (
    "https://git-scm.com/docs/git-config",  # git-config(1), FILES section
    "https://git-scm.com/book/en/v2/Customizing-Git-Git-Configuration",  # Pro Git
)


def _is_null_device(value):
    # "nul" is the null device only on Windows; on POSIX it is an ordinary relative path.
    if value in ("/dev/null", os.devnull):
        return True
    return os.name == "nt" and value.strip().lower() == "nul"


def _home(environ):
    home = environ.get("HOME")
    if not home and environ.get("HOMEDRIVE") and environ.get("HOMEPATH"):
        home = environ["HOMEDRIVE"] + environ["HOMEPATH"]
    return home or environ.get("USERPROFILE") or ""


def host_config_files(environ):
    """Return (files, notes). files: [(path, label, explicit)]; notes: what was skipped and why."""
    files, notes = [], []
    home = _home(environ)

    # system
    if environ.get("GIT_CONFIG_NOSYSTEM", "").strip().lower() in _TRUE_WORDS:
        notes.append("system config skipped: GIT_CONFIG_NOSYSTEM is set")
    elif environ.get("GIT_CONFIG_SYSTEM"):
        v = environ["GIT_CONFIG_SYSTEM"]
        if _is_null_device(v):
            notes.append("system config disabled: GIT_CONFIG_SYSTEM is the null device")
        else:
            files.append((v, "system config (GIT_CONFIG_SYSTEM)", True))
    else:
        cands = ["/etc/gitconfig", "/usr/local/etc/gitconfig", "/opt/homebrew/etc/gitconfig"]
        for var, rel in (
            ("PROGRAMFILES", os.path.join("Git", "etc", "gitconfig")),
            ("ProgramFiles(x86)", os.path.join("Git", "etc", "gitconfig")),
            ("PROGRAMDATA", os.path.join("Git", "config")),
            ("LOCALAPPDATA", os.path.join("Programs", "Git", "etc", "gitconfig")),
        ):
            base = environ.get(var)
            if base:
                cands.append(os.path.join(base, rel))
        for c in cands:
            files.append((c, "system config", False))
        notes.append("system config locations are best-effort; an install in an unusual place is not found")

    # global
    if environ.get("GIT_CONFIG_GLOBAL"):
        v = environ["GIT_CONFIG_GLOBAL"]
        if _is_null_device(v):
            notes.append("global config disabled: GIT_CONFIG_GLOBAL is the null device")
        else:
            files.append((v, "global config (GIT_CONFIG_GLOBAL)", True))
    else:
        # git reads the XDG file first and ~/.gitconfig after it, so the later one wins
        xdg = environ.get("XDG_CONFIG_HOME") or (os.path.join(home, ".config") if home else "")
        if xdg:
            files.append((os.path.join(xdg, "git", "config"), "global config (XDG)", False))
        if home:
            files.append((os.path.join(home, ".gitconfig"), "global config", False))
        if not home and not environ.get("XDG_CONFIG_HOME"):
            notes.append("no home directory found in the environment; global config was not located")
    return files, notes


def _last_value(result, key):
    last = None
    for e, _path in result.host_entries:
        if e.key.lower() == key:
            last = e.value
    return last


def _hardening(result, ruleset):
    by_id = {r.id: r for r in ruleset.rules}
    bare = by_id.get("safe.barerepository")
    val = _last_value(result, "safe.barerepository")
    if val is not None and val.strip().lower() == "explicit":
        result.context.append("hardening: safe.bareRepository=explicit is set")
    else:
        result.add(Finding(
            "info", "hardening", key="safe.bareRepository",
            value=("(not set)" if val is None else val),
            note=HARDEN_BARE % ("not set" if val is None else val),
            rule=bare,
        ))
    fs = _last_value(result, "core.fsmonitor")
    if fs is not None and fs.strip().lower() in ("false", "no", "off", "0"):
        result.add(Finding(
            "info", "hardening", key="core.fsmonitor", value=fs, note=HARDEN_FSMONITOR_FALSE,
            verification="two-source", sources=FSMONITOR_PRECEDENCE_SOURCES,
        ))


def scan_host(roots, ruleset, ceiling=None, environ=None):
    environ = os.environ if environ is None else environ
    for r in roots:
        require_directory(r)
    result = ScanResult(target="this host", ruleset=ruleset, ceiling=ceiling)
    result.not_examined.extend([
        "running processes, installed editor extensions, and any agent's own settings",
        "other users' git configuration",
        "repositories outside the directories you named with --root",
        "which agents you run and their patch status (the preflight command adds this)",
    ])
    files, notes = host_config_files(environ)
    for n in notes:
        result.context.append(n)
        if "global config was not located" in n:
            result.add(Finding("review", "coverage", file="(global config)", note=n + "; git may still find one through the account database, so this audit did not examine it"))
    for path, label, explicit in files:
        scan_config_file(path, ruleset, result, label, optional=not explicit, scope="host")
    if not roots:
        result.context.append("no --root given: only host-level configuration and environment were examined")
    for r in roots:
        scan_root(result, r, ruleset, ceiling=ceiling, expect_nested=True)
    finish_scan(result, ruleset, ceiling=ceiling, environ=environ)
    _hardening(result, ruleset)
    return result


def host_verdict(result):
    """(name, exit code). Same exit codes as every other mode; the wording
    says what the finding means for a host."""
    name, code = verdict_of(result)
    if code == 3:
        return name, 3
    if code == 1:
        return "CRITICAL SINK FOUND - see where each one is", 1
    if code == 2:
        return "NEEDS REVIEW", 2
    return "NOTHING FOUND", 0
