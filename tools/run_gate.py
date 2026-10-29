"""Run the detonation gate FIRST and alone; abort everything if it fails.

    python tools/run_gate.py              gate, then the rest of the suite
    python tools/run_gate.py --gate-only  gate only

Exit status: 0 = gate green (and suite green unless --gate-only), 1 otherwise.
The gate deliberately runs `git status` once on a throwaway fixture in a temp
directory as a positive control. Its payload only appends a line to a file
next to itself. git must be installed.
"""

import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run(args):
    return subprocess.call([sys.executable, "-m", "unittest"] + args, cwd=ROOT)


def main(argv):
    print("=== DETONATION GATE ===", flush=True)
    if run(["-v", "tests.test_00_detonation_gate"]) != 0:
        print("\nGATE FAILED. Nothing ships. Do not run or distribute this build.", flush=True)
        return 1
    print("\nGATE GREEN.", flush=True)
    if "--gate-only" in argv:
        return 0
    print("\n=== FULL SUITE ===", flush=True)
    if run(["discover", "-s", "tests", "-t", ".", "-v"]) != 0:
        print("\nSUITE FAILED (gate was green).", flush=True)
        return 1
    print("\nGATE GREEN, SUITE GREEN.", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
