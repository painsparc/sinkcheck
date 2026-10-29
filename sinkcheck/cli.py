"""Command line entry. Exit codes:

  0  nothing found in what was examined
  1  at least one critical finding
  2  needs review
  3  the scan did not complete: a tool or usage error, or a budget/cap was hit so part of
     the input was not examined (never read 3 as clean)

argparse's own usage exit (2) is overridden so it cannot be mistaken for
"needs review", and any unexpected exception becomes 3, never 0 or 1.

--fail-on critical (for CI that only wants to fail on criticals) maps exit 2
to 0. The verdict printed and the JSON verdict name are NOT changed, a note
says the mapping happened, and exit 3 (incomplete scan or error) is never mapped:
a needs-review result is not a clean one, only a quieter exit code, and a scan
that did not finish never exits 0.
"""

import argparse
import sys

from . import __version__
from .agents import AgentsError, load_agents, parse_declared
from .engine import TargetError, scan_target, verdict_of
from .host import host_verdict, scan_host
from .jsonout import dumps, preflight_to_dict, result_to_dict
from .preflight import preflight_verdict, render_preflight, run_preflight
from .report import render_text
from .ruleset import RulesetError, load_ruleset
from .sanitize import safe_text


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        sys.stderr.write("sinkcheck: usage error: %s\n" % message)
        raise SystemExit(3)


def _common(sp):
    sp.add_argument("--ruleset", default=None, help="alternate sinks.json (data file)")
    sp.add_argument("--ceiling", default=None,
                    help="stop the upward search for an enclosing repository below this directory "
                         "(same meaning as GIT_CEILING_DIRECTORIES)")
    sp.add_argument("--format", choices=("text", "json"), default="text", help="output format (default: text)")
    sp.add_argument("--fail-on", choices=("review", "critical"), default="review",
                    help="'critical' makes a needs-review result exit 0 (the verdict text is unchanged)")


def build_parser():
    p = _Parser(prog="sinkcheck", description="Read-only scan for git configuration execution sinks.")
    p.add_argument("--version", action="version", version="sinkcheck " + __version__)
    sub = p.add_subparsers(dest="command")
    sub.required = True

    s = sub.add_parser("scan", help="scan one directory (never runs git)")
    s.add_argument("path", help="directory to scan")
    _common(s)

    f = sub.add_parser("preflight", help="scan one directory and join it with per-agent patch status")
    f.add_argument("path", help="directory to scan")
    _common(f)
    f.add_argument("--agent", action="append", default=[], metavar="ID=VERSION",
                   help="state which agent and version you will attach (repeatable); versions are never "
                        "obtained by running an agent")
    f.add_argument("--agents-data", default=None, help="alternate agents.json (data file)")
    f.add_argument("--no-detect", action="store_true", help="do not look for installed agents on disk")

    a = sub.add_parser("audit", help="audit this machine: global/system git config, environment, and chosen directories")
    _common(a)
    a.add_argument("--root", action="append", default=[], metavar="DIR",
                   help="a directory to search for repositories (repeatable)")
    return p


def _emit(text):
    sys.stdout.write(text.encode("ascii", "backslashreplace").decode("ascii"))


def _map_exit(code, fail_on):
    if fail_on == "critical" and code == 2:
        return 0
    return code


def _fail_note(name, code, mapped, fail_on):
    if mapped == code:
        return None
    return (
        "NOTE: --fail-on %s: the exit code is %d although the verdict above is %s. "
        "A needs-review result is not a clean result." % (fail_on, mapped, name)
    )


def main(argv=None):
    try:
        args = build_parser().parse_args(argv)
        ruleset = load_ruleset(args.ruleset)
        fmt, fail_on = args.format, args.fail_on

        if args.command == "scan":
            result = scan_target(args.path, ruleset, ceiling=args.ceiling)
            name, code = verdict_of(result)
            mapped = _map_exit(code, fail_on)
            if fmt == "json":
                _emit(dumps(result_to_dict(result, (name, code), "scan", exit_code=mapped, fail_on=fail_on)))
            else:
                _emit(render_text(result, note=_fail_note(name, code, mapped, fail_on)))
            return mapped

        if args.command == "preflight":
            data = load_agents(args.agents_data)
            declared = parse_declared(args.agent, data)
            pre = run_preflight(args.path, ruleset, data, declared=declared, ceiling=args.ceiling,
                                detect=not args.no_detect)
            name, code = preflight_verdict(pre)
            mapped = _map_exit(code, fail_on)
            if fmt == "json":
                _emit(dumps(preflight_to_dict(pre, (name, code), exit_code=mapped, fail_on=fail_on)))
            else:
                _emit(render_preflight(pre, note=_fail_note(name, code, mapped, fail_on)))
            return mapped

        if args.command == "audit":
            result = scan_host(args.root, ruleset, ceiling=args.ceiling)
            name, code = host_verdict(result)
            mapped = _map_exit(code, fail_on)
            if fmt == "json":
                _emit(dumps(result_to_dict(result, (name, code), "audit", exit_code=mapped, fail_on=fail_on)))
            else:
                _emit(render_text(result, verdict=(name, code), note=_fail_note(name, code, mapped, fail_on)))
            return mapped

        raise SystemExit(3)
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 3
        return 0 if code == 0 else 3
    except (TargetError, RulesetError, AgentsError) as exc:
        sys.stderr.write("sinkcheck: error: %s\n" % safe_text(str(exc), None))
        return 3
    except Exception as exc:  # a crash must never read as clean or as a finding
        sys.stderr.write("sinkcheck: internal error (%s); the scan did not complete\n" % exc.__class__.__name__)
        return 3


if __name__ == "__main__":
    sys.exit(main())
