"""sinkcheck: read-only pre-flight scan for git configuration execution sinks.

Design invariants (enforced by tests/test_00_detonation_gate.py):

* This package never invokes git, never spawns any subprocess, and never
  imports a git binding. Configuration files are parsed as data.
* Nothing is written, no network is touched, no telemetry exists.
* A path that is not a regular file is never opened.
"""

__version__ = "1.0.1"

# Phase 6 build: all six phases complete. Agent status rows are
# single-sourced and labelled as such; see README.
# (nothing further is pending in this file).
BUILD_PHASE = 6
PUBLISHABLE = True
