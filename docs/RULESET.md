# Ruleset format (sinkcheck/data/sinks.json)

The ruleset is data. Adding a sink that reuses an existing matcher needs no
code change; the detonation gate generates a config that sets every rule to a
live payload, so a new rule is covered automatically.

Top level: `schema_version`, `ruleset_version`, `ruleset_date`, `origins`
(id -> title, url), `protections` (named descriptions of git's own
protections), `hooks` (hook name -> operations that fire it),
`hooks_evidence`, `environment` (GIT_* names with severity and effect),
`sinks`.

Each sink: `id`, `key` (`section.name`, `section.*`, `section.*.name`),
`tier` (A passive, B user or network initiated, C structural), `match`,
`severity` (`critical` | `review` | `info`), `protections`, `triggers`,
`reached_by`, `evidence` (list of `{origin, note}`), optional `safe_values`,
`hit_values`, `sweep` (raw-text tokens for the parser-differential check),
`protected_only` (git honors it only in system/global/command scope),
`host_benign_values` (exact, case-sensitive, byte-for-byte values (no trimming) of widely used tools, such as the git-lfs filter commands; in `audit` only, a match is reported as info with a note and is never hidden; repo scans ignore it),
`multivalued`, `attribute` (`filter` | `diff` | `merge`), `host_severity`.

Matchers: `command_string`, `bool_or_command`, `bang_prefix`, `ext_url`,
`value_in`, `any_value`, `include`. `nul` in `safe_values` counts only on
Windows.

Verification label is computed: two or more distinct `origin` ids =
*two independent sources*; one = *single source*; none = *unverified*. Two
mirrors of one upstream are one origin. Never add a second origin unless it
is genuinely independent.

Agent status lives in `sinkcheck/data/agents.json` with the same rules, plus
`context_evidence` for related sources that do not count as verification and
`gate` to hold a verdict at needs-review while a status is unverified.
