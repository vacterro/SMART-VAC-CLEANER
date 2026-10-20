#!/usr/bin/env python3
"""Dependency-free filesystem helpers shared by the main module and analyze_caches.

This module imports nothing from the standard library beyond os/pathlib/stat, so
analyze_caches.py can reuse get_size() without forcing the GUI stack
(customtkinter, tkinter, pystray, PIL) to load.
"""


import os
import stat
from pathlib import Path


def _is_reparse(st: os.stat_result) -> bool:
    """T-207: True when the lstat'ed object is a symlink, junction, mount point
    or any other reparse point -- an entry whose follow would leave the tree
    being sized. On Windows, DirEntry.is_dir(follow_symlinks=False) is NOT
    enough: a junction answers True there and its target would be silently
    folded into the reported size. The reparse attribute and the POSIX link
    mode are checked together, always on a no-follow stat."""
    if stat.S_ISLNK(st.st_mode):
        return True
    return bool(getattr(st, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def get_size(path: Path) -> int:
    """Total byte size of a file or directory tree (iterative, no recursion).

    Symlinks, junctions and any other reparse points are never followed: root
    or nested, they contribute 0 bytes (T-207). Unreadable entries count as 0
    bytes. The reported number therefore only ever covers real files inside
    the tree the caller named, so discovery sizing can never report or imply a
    deletion outside that tree.
    """
    try:
        root_st = os.lstat(path)
    except (OSError, ValueError):
        return 0
    if _is_reparse(root_st):
        return 0
    if not stat.S_ISDIR(root_st.st_mode):
        return root_st.st_size if stat.S_ISREG(root_st.st_mode) else 0
    total = 0
    stack = [path]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as scan:
                for entry in scan:
                    try:
                        st = entry.stat(follow_symlinks=False)
                    except OSError:
                        continue  # vanished or unreadable: count nothing
                    if _is_reparse(st):
                        continue  # T-207: link/junction/reparse, never followed
                    if stat.S_ISREG(st.st_mode):
                        total += st.st_size
                    elif stat.S_ISDIR(st.st_mode):
                        stack.append(Path(entry.path))
        except OSError:
            pass  # expected: dir may be inaccessible
    return total
