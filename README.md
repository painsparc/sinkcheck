# sinkcheck

Read-only pre-flight check for git configuration execution sinks: settings in
a repository's own git configuration that make git run a command, which coding
agents trigger when they run git (for example `git status`) to gather context.

Python 3.9+, standard library only. No network, no telemetry, no branding.

## Background

On 1 September 2026 Manifold Security disclosed GitSpawn: eight findings
across seven AI coding agents, all in one class of bug. A repository can tell
git to run a command, and coding agents run git constantly to gather context,
without asking. In the main case, a repository's own `.git/config` sets
`core.fsmonitor` to a command, and the agent's routine `git status` executes
it, as the user, outside the agent's sandbox. On several agents it ran before
the user had accepted a trust prompt, or before they had even authenticated.

### How it reaches you

Cloning a malicious repository does not, on its own, deliver this. Cloning
builds a fresh `.git/config` on your machine; the remote's is not copied.

The usual delivery path is a directory that travels with its `.git` folder
intact: a zipped project, a shared or synced folder, a USB stick, an
attachment.

One known path does survive cloning. Git will not let you commit a directory
named `.git`, but it will let you commit a directory laid out like a bare
repository, with its own `HEAD`, `objects`, `refs` and `config`. Run git from
inside that directory, or from anywhere beneath it, and git uses that config.
From the root of the clone, it does not. Justin Steven documented this "buried
bare repository" technique in 2022 (OVE-20210718-0001).

### What protects you, and what does not

Each of these was reproduced on git 2.43.0 with a harmless marker payload.

- **A global `core.fsmonitor=false` does not protect you.** Git reads system,
  then global, then repository configuration, and the last value wins, as the
  FILES section of git-config(1) documents. A repository that sets
  `core.fsmonitor` overrides your global `false`.
- **A per-command override works, for one key.** `git -c core.fsmonitor=
  status` and `git -c core.fsmonitor=false status` both stopped the payload.
- **`safe.bareRepository=explicit` stops the buried-bare-repository path, and
  only that path.** It did nothing against a repository delivered with its
  `.git` folder. It is opt-in in current releases. A patch series on the git
  mailing list proposes making `explicit` the default in Git 3.0; that is a
  proposal, not a decision.
- **`safe.directory` rarely helps here.** It checks who owns the repository.
  You own anything you have just unzipped, so it does not trigger. On a shared
  or network drive the owner may be someone else, and then it does block.

### More than `core.fsmonitor`

`core.fsmonitor` gets the attention because it fires on the quietest thing an
agent does, refreshing the index. Other settings can run commands too, and
some only in certain conditions:

- **`core.hooksPath`** redirects hooks to a directory the repository controls.
  A `post-index-change` hook ran when `git status` rewrote the index, which it
  does in a freshly unpacked tree. It does not fire on every `git status`.
- **Filter drivers** (`clean`, `smudge`, `process`) run when git processes the
  content of a path that attributes assign to them. Attributes can come from
  `.gitattributes`, `.git/info/attributes`, `core.attributesFile` and
  `attr.tree`. CVE-2026-19593 describes `attr.tree` combined with a configured
  filter driver, in Codex Desktop.
- **Diff `textconv` drivers** run when a diff touches a matching path.
- **`core.pager`** only runs when git's output goes to a terminal.

There is no complete list. A great many git configuration options can run
commands, and annotating each one risks missing some (Jeff King, git mailing
list, 2017, quoted in Steven's advisory). Treat any checklist, including this
tool, as incomplete.

Sources for every sink are in `sinkcheck/data/sinks.json`, with an evidence
label per sink: *two cited sources*, *single source*, or *unverified*.
The label is computed from distinct evidence origins, not typed in; it counts
separate citations and does not prove they are independent of each other.

## Use

    python -m sinkcheck scan PATH                 # one directory
    python -m sinkcheck preflight PATH --agent claude-code=2.1.310
    python -m sinkcheck audit --root ~/code       # this machine

All three take `--format json`, `--ceiling DIR` (stop the upward search for
an enclosing repository, like `GIT_CEILING_DIRECTORIES`) and
`--fail-on critical` (CI: exit 0 on needs-review; the verdict text and JSON
verdict are unchanged and a note says so).

**Exit codes:** `0` nothing found, `1` critical, `2` needs review, `3` the scan
did not finish: a tool or usage error, or a budget or cap was hit (too many
included files, too much to read, too many git directories, a directory walk
cut short) so part of the input was not examined. Exit 3 is its own hard
state: `--fail-on critical` never turns it into 0, and a repeated include of a
file already examined does not spend the budget. If a critical finding was
already made, exit 1 still wins, and the report says the scan was incomplete.

**scan** examines the target's repository the way git finds it: `.git`
(directory or `gitdir:` redirect), bare-layout directories buried anywhere in
the tree, enclosing repositories found by searching upward, `commondir`,
`config.worktree`, linked worktrees, submodule git directories, the
`include.path` / `includeIf` chain, hook file names, attribute files paired
with filter/diff/merge drivers (`.gitattributes`, `info/attributes`, and a
`core.attributesFile` that points inside the target), `attr.tree` and
`core.attributesFile` themselves, `.gitmodules`, and `GIT_*` environment
variables.

**preflight** adds a dated, sourced per-agent patch table. Versions come from
`--agent ID=VERSION` or from global npm `package.json` files; agents not
installed through npm need the flag. An agent is never run to ask its version. A patched agent never
clears a tree that has findings, and an unverified or unknown agent status
holds the verdict at needs-review.

**audit** reads your global and system git config (and their includes),
the environment, and any `--root` directories. A command in your own global
config is reported for confirmation, not as an attack. Exact values of widely
used tools (the git-lfs filter commands, `astextplain`) are listed as info
instead of needs-review; they are never hidden. It prints hardening
commands as instructions; it never runs them.

## What it guarantees, and how that is tested

It never invokes git or any process, never opens a socket, never writes,
deletes or renames anything, and never opens a path that is not a regular
file. Configuration is parsed as data. Paths taken from the scanned tree are
vetted before any filesystem call (UNC and device paths, NUL bytes, `/proc`).
Every limit that cuts a scan short produces a finding, so a truncated scan is
never reported as clean. Report text and JSON are ASCII-only; hostile values
cannot inject terminal control or bidirectional characters.

`python tools/run_gate.py` runs the **detonation gate** first and alone:
fixtures whose payload appends a line to a file outside the tree (through
include chains, buried bare repos, `.git` redirects, hooks, the environment,
and the CLI itself) must never produce that file, and a positive control
(`git status` on the fixture, run after the scan) proves the payload is live.
An AST check bans process, network, git-binding and write APIs in the
package. The full suite follows. git must be installed to run the gate.

## Limits

A clean scan is not a clean bill of health. The sink list is not exhaustive,
and no complete list exists. Not
examined: hook file contents, attribute files outside the target, `includeIf`
conditions (every conditional include is followed and flagged), submodules
not present, running processes, editor extensions, and an agent's own
settings. The agent table is a snapshot dated in its file; the tool warns
when it is more than 30 days old. Details in `docs/THREAT_MODEL.md` and
`docs/RULESET.md`.

### Known limits (named, not guessed)

These came out of an independent review. They are listed as the reviewer
reported them. Where the reviewer was not certain, this says so, and none of
them has been tested here on the platform concerned.

Windows:

- **Junctions.** The directory walk may descend into NTFS junctions, because a
  junction may not report itself as a symbolic link. The directory-count and
  depth caps bound the walk, and hitting a cap makes the scan incomplete
  (exit 3). Not confirmed against every Python version.
- **Reparse points to network paths.** The UNC check looks at the path text
  only. A symlink or junction whose target is `\\server\share` is followed by
  the operating system, and the NT-namespace spelling `\??\UNC\...` is not
  refused by text.
- **Reserved device names.** `CON`, `COM1`, `NUL` and forms with trailing dots
  or spaces are not refused by name. Safety rests on the file being reported as
  a non-regular file before it is opened; not confirmed for every device name.
- **Aliases of `.git` and `.gitmodules`.** Names such as `.GIT`, `GIT~1`,
  `.git.` and `.git ` are matched case-sensitively and exactly, so a nested
  gitfile written one of those ways is not recognised on case-insensitive or
  8.3-aware filesystems. Directory forms are still caught by their contents.

Any platform:

- **`attr.tree` contents are not read.** `attr.tree` makes git take
  attributes from a tree object (see CVE-2026-19593, above). sinkcheck does
  not read git objects, so it reports `attr.tree` as needs-review and notes on
  every unpaired driver that the tree may select it, but it cannot say which
  paths or drivers the tree selects.
- **`core.attributesFile` outside the target is not read.** A value under `~`
  or outside the scanned directory is reported, not followed. A relative value
  is resolved from the target root, as git does when run from the top of the
  work tree; git run from elsewhere could resolve it differently.
- **Pairing is evidence, not a filter.** A driver defined in repository config
  is critical whether or not an attribute selecting it was found, because
  attributes can come from places this build does not read.

- **Linked-worktree directories.** A directory holding only `HEAD` and a
  `commondir` file may not be recognised as a git directory (the reviewer was
  about 70% sure git resolves `objects` and `refs` through `commondir`).
- **Pseudo-filesystem refusal is Linux only.** It uses the Linux mount table.
  It is not done on macOS or Windows, and directory listings are not guarded.
- **Host includes keep host severity.** A file included from your global or
  system config is graded as host configuration even if its target sits inside
  an untrusted tree.
- **Shared caps in `audit`.** The include, git-directory and entry budgets are
  shared across every `--root`, so a very large tree can end the audit
  incomplete (exit 3, never silent).
- **Symlinked `.gitmodules` / `.gitattributes`** are not listed. Whether git
  reads a symlinked `.gitmodules` in the worktree is not established here.
- **`--ruleset` and `--agents-data`** are opened with an ordinary read; point
  them only at regular files.
- **Fail-open when the mount table is unreadable on Linux.** If
  `/proc/self/mountinfo` cannot be read, only files on anonymous devices are
  refused.

## Demo

git cannot store a nested `.git` directory in a commit, so the demo is a
script, not a folder. `python demo/make_demo.py DEST` writes a throwaway
repository whose config sets `core.fsmonitor` to a harmless payload (it only
writes `fired.txt` next to DEST). It never runs git. Scan it with
`python -m sinkcheck scan DEST`. Do not run git, an editor's git integration
or an AI coding agent inside DEST; that is exactly what would fire the payload.

## CI

`docs/ci.yml.example` is a GitHub Actions workflow (Linux, Windows, macOS; Python 3.9 and 3.12) that runs the detonation gate, then the full suite, then a self-scan. To use it, copy it to `.github/workflows/ci.yml`.

## Unaffiliated

This project is not affiliated with, endorsed by, or sponsored by any vendor
or project named in it.
