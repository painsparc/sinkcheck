# Threat model

## What is defended against

A repository tree you did not write carries a git configuration value that
makes git execute a command when an agent (or you) runs ordinary read
commands in it. The scanner finds those values without ever causing them to
run.

## Delivery paths

| Path | Survives `git clone`? | Covered |
|---|---|---|
| Archive, shared drive or USB copy with `.git` intact | not applicable (no clone) | yes: `.git/config`, `config.worktree`, linked worktrees, `commondir`, `modules/` |
| `.git` file redirecting with `gitdir:` | no | yes: target followed, flagged when outside the tree |
| Buried bare repository (HEAD, objects, refs in a subdirectory) | yes | yes: found by walking the tree, reported as a finding |
| Enclosing repository above the target | n/a | yes: upward search, bounded by `--ceiling` |
| `include.path` / `includeIf` chain | with the config that carries it | yes: followed (depth 10, 200 files, cycle-safe) |
| `.gitattributes` selecting a config-defined driver | attributes travel with a clone | yes: paired with `filter`, `diff`, `merge` drivers |
| Hooks in the hooks directory | only if the git dir travels | names reported, contents never read |
| `GIT_*` environment | no | yes |

## Non-detonation (the central property)

Nothing in the package runs a process or git, opens a socket, writes, or
opens a non-regular file. Mechanisms: stat-before-open, `O_NONBLOCK` plus
fstat identity check, size caps, path vetting before any filesystem call,
no following of symlinked `modules`/`hooks`/`worktrees`, bounded walks, and
an exception boundary per examination step. These are enforced by the
detonation gate, a runtime Guard (forbidden calls raise; opened and touched
paths are recorded) and an AST ban list.

## Out of scope

Anything that needs executing, interpreting or network-checking something:
hook contents, scripts a filter points to, remote advisories. Runtime
monitoring is a different product. Windows junctions are not distinguished
from directories; walks are bounded instead.

## Budgets fail closed

Every cap (included files, include depth, git directories, entries examined,
directory-walk limits, attribute-file size) marks the whole scan incomplete.
An incomplete scan exits 3 unless a critical finding already decided it, and
`--fail-on` cannot change that. Repeated references to a file already examined
are free, files are re-examined when reached in a different read mode or scope,
and only settings in sections some rule looks at count toward the work budget,
so filler cannot be used to starve the real payload. Pseudo-filesystems (proc,
sysfs and similar) are refused by the filesystem a file really lives on, never
by how its path is spelled.

## Known approximations

- The bare-repository test accepts any non-missing `objects` and `refs`, as
  git's own check is permissive; it may over-report.
- `includeIf` conditions are not evaluated; all are followed and labelled.
- Shadowing (a later value overriding an earlier one) is judged per file only.
- Agent status is single-sourced after 1 September 2026 and labelled so.
