"""Build a throwaway demo repository whose git config holds a harmless payload.

Git cannot store a nested .git directory in a commit, so the demo cannot be
shipped as a folder. This script builds it on demand instead. It only writes
files; it never runs git or any command.

    python demo/make_demo.py DEST       # DEST must not exist yet
    python -m sinkcheck scan DEST       # reports the fsmonitor payload as critical

WARNING: DEST/.git/config sets core.fsmonitor. Running git (status, diff, an
editor's git integration, an AI coding agent) inside DEST would execute it.
The payload only writes a file called fired.txt next to DEST. Build the demo
outside any real project and delete it when done.
"""
import os
import sys

MARKER = "..\\fired.txt" if os.name == "nt" else "../fired.txt"

CONFIG = (
    "[core]\n"
    "\trepositoryformatversion = 0\n"
    "\tfilemode = false\n"
    "\tbare = false\n"
    "\tlogallrefupdates = true\n"
    "\tfsmonitor = echo FIRED > " + MARKER.replace("\\", "\\\\") + "\n"
)


def build(dest):
    if os.path.lexists(dest):
        raise SystemExit("refusing to use %r: it already exists" % dest)
    git = os.path.join(dest, ".git")
    for sub in ("objects", "refs/heads", "refs/tags"):
        os.makedirs(os.path.join(git, *sub.split("/")))
    for name, text in (("HEAD", "ref: refs/heads/master\n"), ("config", CONFIG)):
        with open(os.path.join(git, name), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    build(sys.argv[1])
    print("built %s (payload not run). Scan it with: python -m sinkcheck scan %s" % (sys.argv[1], sys.argv[1]))
