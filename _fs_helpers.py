#!/usr/bin/env python3
"""Dependency-free filesystem helpers shared by the main module and analyze_caches.

This module imports nothing from the standard library beyond os/pathlib, so
analyze_caches.py can reuse get_size() without forcing the GUI stack
(customtkinter, tkinter, pystray, PIL) to load.
"""


import os
from pathlib import Path


def get_size(path: Path) -> int:
    """Total byte size of a file or directory tree (iterative, no recursion).

    Symlinks are not followed. Unreadable entries count as 0 bytes.
    """
    if not path.exists():
        return 0
    try:
        if path.is_file():
            return path.stat().st_size
    except OSError:
        return 0
    total = 0
    stack = [path]
    while stack:
        current = stack.pop()
        try:
            for entry in os.scandir(current):
                if entry.is_file(follow_symlinks=False):
                    try:
                        total += entry.stat().st_size
                    except OSError:
                        pass  # expected: file may be locked during scan
                elif entry.is_dir(follow_symlinks=False) and not entry.is_symlink():
                    stack.append(Path(entry.path))
        except (PermissionError, OSError):
            pass  # expected: dir may be inaccessible
    return total
