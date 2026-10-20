"""T-207: size discovery must never fold a reparse target into the reported tree.

Owned native fixtures only (mklink /J junctions, no user data). A 7-byte cache
with a nested junction to a 6-MiB sibling must still size 7 bytes and must
produce no analyzer finding; a linked root is refused; normal file/directory
sizing is unchanged. Discovery is read-only: nothing outside the named tree is
read, mutated or reported.
"""

import os
import stat
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

import analyze_caches as vac_analyze
from _fs_helpers import get_size

SIBLING_MIB = 6


def _junction(link: Path, target: Path) -> bool:
    """Create a native junction (needs no elevation); False when the OS refuses."""
    r = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)],
                       capture_output=True, text=True, check=False)
    return r.returncode == 0 and link.is_dir()


def _write(path: Path, size: int) -> None:
    path.write_bytes(b"x" * size)


class TestSizeNoFollowBoundary(unittest.TestCase):
    """get_size(): links/junctions/reparse points contribute nothing."""

    def test_plain_file_and_dir_sizing_unchanged(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root / "a.txt", 3)
            (root / "sub").mkdir()
            _write(root / "sub" / "b.bin", 4)
            self.assertEqual(get_size(root / "a.txt"), 3)
            self.assertEqual(get_size(root), 7)

    def test_junction_root_refused(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            outside = root / "outside"
            outside.mkdir()
            _write(outside / "big.bin", SIBLING_MIB * 1024 * 1024)
            link = root / "link"
            if not _junction(link, outside):
                self.skipTest("mklink /J unavailable")
            self.assertEqual(get_size(link), 0, "a linked root must size 0, never the target tree")

    def test_nested_junction_not_followed(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            cache = root / "Cache"
            cache.mkdir()
            _write(cache / "index.bin", 7)
            sibling = root / "sibling"
            sibling.mkdir()
            _write(sibling / "payload.bin", SIBLING_MIB * 1024 * 1024)
            if not _junction(cache / "mirror", sibling):
                self.skipTest("mklink /J unavailable")
            self.assertEqual(get_size(cache), 7, "the junction target must not be folded into the size")

    def test_symlink_entry_skipped_when_supported(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            cache = root / "Cache"
            cache.mkdir()
            _write(cache / "index.bin", 7)
            outside = root / "outside_owner.bin"
            _write(outside, SIBLING_MIB * 1024 * 1024)
            link = cache / "mirror"
            try:
                link.symlink_to(outside, target_is_directory=False)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks not supported on this host")
            try:
                self.assertEqual(get_size(cache), 7)
            finally:
                link.unlink(missing_ok=True)
            self.assertEqual(outside.stat().st_size, SIBLING_MIB * 1024 * 1024)

    def test_missing_and_unreadable_stay_zero(self):
        self.assertEqual(get_size(Path("Z:/__GARBAGE__")), 0)


class TestAnalyzerJunctionDiscovery(unittest.TestCase):
    """analyze_caches._scan(): junction targets never become findings."""

    def test_nested_junction_produces_no_finding(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            cache = root / "Cache"
            cache.mkdir()
            _write(cache / "index.bin", 7)
            sibling = root / "sibling"
            sibling.mkdir()
            _write(sibling / "payload.bin", SIBLING_MIB * 1024 * 1024)
            if not _junction(cache / "mirror", sibling):
                self.skipTest("mklink /J unavailable")
            sibling_before = sibling.joinpath("payload.bin").stat()
            found = vac_analyze._scan(root, verbose=False)
            self.assertEqual(found, [], "a cache that only looks large through a junction is not a finding")
            self.assertEqual(sibling.joinpath("payload.bin").stat(), sibling_before,
                             "discovery stays read-only")

    def test_real_cache_still_discovered(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            cache = root / "Cache"
            cache.mkdir()
            _write(cache / "big.bin", SIBLING_MIB * 1024 * 1024)
            found = vac_analyze._scan(root, verbose=False)
            self.assertTrue(any(str(cache) == p for p, _ in found), "real oversized caches are still found")
            self.assertEqual(next(sz for p, sz in found if p == str(cache)), SIBLING_MIB * 1024 * 1024)

    def test_junction_root_refused(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            real = root / "real"
            real.mkdir()
            (real / "Cache").mkdir()
            _write(real / "Cache" / "big.bin", SIBLING_MIB * 1024 * 1024)
            link = root / "link"
            if not _junction(link, real):
                self.skipTest("mklink /J unavailable")
            self.assertEqual(vac_analyze._scan(link, verbose=False), [],
                             "a linked scan root is refused, never traversed")


class TestNoFollowStatContract(unittest.TestCase):
    """The refusal is a no-follow stat on every level, not a name check."""

    def test_helper_is_true_for_junction_and_plain_dir(self):
        from _fs_helpers import _is_reparse

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            real = root / "real"
            real.mkdir()
            link = root / "link"
            if not _junction(link, real):
                self.skipTest("mklink /J unavailable")
            self.assertTrue(_is_reparse(os.lstat(link)))
            self.assertFalse(_is_reparse(os.lstat(real)))
            self.assertTrue(stat.S_ISDIR(os.lstat(real).st_mode))


if __name__ == "__main__":
    unittest.main()
