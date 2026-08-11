"""Cache discovery analyzer (STRICTLY read-only, T-142).

Scans %LOCALAPPDATA%/%APPDATA% for cache-like folders over a size threshold
and prints the biggest. This is DISCOVERY only: findings are never fed into any
deletion allowlist. Missing/empty env roots are skipped explicitly (never the
cwd), symlinks/junctions/reparse points are refused, and token-boundary name
matching avoids the worst substring false positives.
"""
import os
import stat
import sys
from collections import deque
from pathlib import Path

from _fs_helpers import get_size

_KNOWN_CACHE_WORDS = frozenset({
    "cache", "caches", "temp", "tmp", "logs", "log", "crash", "crashes",
    "crashpad", "dumps", "minidumps", "gpucache", "shadercache", "webcache",
    "thumbnailcache", "cache2", "startupcache", "updater",
})

_MIN_BYTES = 5 * 1024 * 1024  # > 5 MB
_MAX_DEPTH = 3


def _root_env(name: str) -> Path | None:
    """Canonical existing directory from an env var, or None (fail closed).

    An empty/missing env value must NOT resolve to the cwd (T-142): the
    analyzer would otherwise scan an arbitrary tree the user never asked about.
    """
    raw = os.environ.get(name)
    if not raw:
        return None
    p = Path(raw).expanduser()
    try:
        p = p.resolve()
    except OSError:
        return None
    if not p.exists() or not p.is_dir():
        return None
    return p


def _is_link(path: Path) -> bool:
    try:
        st = path.lstat()
    except OSError:
        return True  # unknown state -> refuse
    if stat.S_ISLNK(st.st_mode):
        return True
    return bool(os.name == "nt" and (getattr(st, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT))


def _name_matches_token_boundary(name_lower: str) -> bool:
    """Token-boundary matching: a known word must appear as a whole token.

    'webcache' matches; 'mycacheous-app' does not; a bare substring like 'temp'
    inside 'attempt' is NOT a hit. Known words that are already concatenations
    (gpucache, cache2, ...) match as suffixes/tokens.
    """
    tokens = set(name_lower.replace("-", " ").replace("_", " ").replace(".", " ").split())
    if tokens & _KNOWN_CACHE_WORDS:
        return True
    # compound concatenated names: 'webcache', 'thumbnailcache', 'startupcache', 'cache2', 'gpucache'
    return any(name_lower.endswith(k) for k in ("webcache", "thumbnailcache", "startupcache", "cache2", "gpucache", "shadercache", "crashpad", "minidumps"))


def _scan(base: Path, verbose: bool) -> list[tuple[str, int]]:
    found: list[tuple[str, int]] = []
    if _is_link(base):
        if verbose:
            print(f"[skip] {base}: root is a symlink/reparse point")
        return found
    q: deque[tuple[Path, int]] = deque([(base, 0)])
    while q:
        cur, depth = q.popleft()  # T-142: deque, not list.pop(0) (O(n) -> O(1))
        if depth > _MAX_DEPTH:
            continue
        try:
            for item in cur.iterdir():
                if _is_link(item):
                    if verbose:
                        print(f"[skip] {item}: symlink/reparse point")
                    continue
                if not item.is_dir():
                    continue
                if _name_matches_token_boundary(item.name.lower()):
                    sz = get_size(item)
                    if sz > _MIN_BYTES:
                        found.append((str(item), sz))
                else:
                    q.append((item, depth + 1))
        except (PermissionError, OSError) as exc:
            if verbose:
                print(f"[skip] {cur}: {exc}")
    return found


def main() -> None:
    verbose = "-v" in sys.argv or "--verbose" in sys.argv
    bases = [b for b in (_root_env("LOCALAPPDATA"), _root_env("APPDATA")) if b is not None]
    if not bases:
        print("No LOCALAPPDATA/APPDATA set; nothing to scan (never falls back to cwd).")
        return
    found: list[tuple[str, int]] = []
    for base in bases:
        found.extend(_scan(base, verbose))
    found.sort(key=lambda x: x[1], reverse=True)
    for p, sz in found[:40]:
        print(f"{sz / (1024 * 1024):8.1f} MB  {p}")


if __name__ == "__main__":
    main()
