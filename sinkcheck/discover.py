"""Find every place git could take a repository, config, attributes or
modules file from, using only directory listings and lstat/stat.

Nothing here opens a file. Symlinked directories are counted, never
followed. Traversal is bounded.

Why the walk looks for bare-looking directories: git treats any directory
containing HEAD, objects and refs as a repository, with no ".git" name
involved. Such a directory commits and clones as ordinary files, so it is
the one carrier of a malicious config that survives `git clone`. Git's own
test accepts objects/refs that merely exist and are accessible, so this
check accepts any non-missing entry for them.
"""

import os
from dataclasses import dataclass, field
from itertools import islice

from .safeio import path_kind

MAX_DIRS = 100000
MAX_DEPTH = 100
MAX_DIR_ENTRIES = 20000


@dataclass
class Discovery:
    gitdirs: list = field(default_factory=list)  # (path, label)
    gitfiles: list = field(default_factory=list)  # paths of ".git" files
    attribute_files: list = field(default_factory=list)
    gitmodules: list = field(default_factory=list)
    dirs_visited: int = 0
    symlinked_dirs: int = 0
    unreadable: list = field(default_factory=list)  # (path, error class)
    truncated: str = ""


def looks_like_gitdir(path):
    return (
        path_kind(os.path.join(path, "HEAD")) in ("file", "symlink-file", "symlink-other")
        and path_kind(os.path.join(path, "objects")) != "missing"
        and path_kind(os.path.join(path, "refs")) != "missing"
    )


def walk_tree(root, max_dirs=MAX_DIRS, max_depth=MAX_DEPTH):
    d = Discovery()
    stack = [(root, 0)]
    while stack:
        dirpath, depth = stack.pop()
        if d.dirs_visited >= max_dirs:
            d.truncated = "directory limit of %d reached; remaining directories were not examined" % max_dirs
            break
        d.dirs_visited += 1
        try:
            with os.scandir(dirpath) as it:
                entries = list(islice(it, MAX_DIR_ENTRIES + 1))
        except (OSError, ValueError) as exc:
            d.unreadable.append((dirpath, exc.__class__.__name__))
            continue
        if len(entries) > MAX_DIR_ENTRIES:
            entries = entries[:MAX_DIR_ENTRIES]
            d.truncated = d.truncated or "a directory has more than %d entries; only the first %d were examined (%s)" % (
                MAX_DIR_ENTRIES, MAX_DIR_ENTRIES, dirpath)
        entries.sort(key=lambda e: e.name)

        names = {e.name for e in entries}
        if "HEAD" in names and "objects" in names and "refs" in names:
            head = next(e for e in entries if e.name == "HEAD")
            try:
                head_ok = head.is_file() or head.is_symlink()
            except OSError:
                head_ok = False
            if head_ok:
                label = "git directory at the target root" if depth == 0 else "buried bare repository"
                d.gitdirs.append((dirpath, label))

        for e in entries:
            name = e.name
            try:
                is_symlink = e.is_symlink()
                is_dir = e.is_dir(follow_symlinks=False)
                is_file = e.is_file(follow_symlinks=False)
            except OSError:
                continue
            if name == ".git":
                if is_dir:
                    d.gitdirs.append((e.path, "repository" if depth == 0 else "nested repository"))
                elif is_symlink and path_kind(e.path) == "symlink-dir":
                    d.gitdirs.append((e.path, "symlinked .git directory"))
                else:
                    d.gitfiles.append(e.path)
                continue
            if name == ".gitattributes" and is_file:
                d.attribute_files.append(e.path)
            elif name == ".gitmodules" and is_file:
                d.gitmodules.append(e.path)
            if is_dir:
                if depth + 1 > max_depth:
                    d.truncated = d.truncated or "depth limit of %d reached; deeper directories were not examined" % max_depth
                    continue
                stack.append((e.path, depth + 1))
            elif is_symlink and path_kind(e.path) == "symlink-dir":
                d.symlinked_dirs += 1
    return d


def find_enclosing(start, ceiling=None):
    """Walk upward from start the way git does, returning
    (path, 'gitdir' | 'gitfile') for the nearest enclosing repository, or
    None. A directory equal to the ceiling, and everything above it, is not
    examined (the same meaning as GIT_CEILING_DIRECTORIES)."""
    cur = os.path.realpath(start)
    ceil = os.path.normcase(os.path.realpath(ceiling)) if ceiling else None
    while True:
        parent = os.path.dirname(cur)
        if parent == cur:
            return None
        if ceil and os.path.normcase(parent) == ceil:
            return None
        k = path_kind(os.path.join(parent, ".git"))
        if k in ("dir", "symlink-dir") and looks_like_gitdir(os.path.join(parent, ".git")):
            return os.path.join(parent, ".git"), "gitdir"
        # An invalid .git directory is skipped by git, which keeps climbing.
        if k in ("file", "symlink-file"):
            return os.path.join(parent, ".git"), "gitfile"
        if looks_like_gitdir(parent):
            return parent, "gitdir"
        cur = parent
