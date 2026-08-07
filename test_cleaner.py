#!/usr/bin/env python3
"""Unit tests for _SMART_VAC_CLEANER.py core functions."""

import hashlib
import json
import logging
import os
import queue
import re
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from typing import ClassVar
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _SMART_VAC_CLEANER as vac


class TestByteFormatting(unittest.TestCase):

    def test_bytes(self):
        self.assertEqual(vac.fmt(0), "0 B")
        self.assertEqual(vac.fmt(1023), "1023 B")

    def test_kb(self):
        self.assertEqual(vac.fmt(1024), "1 KB")
        self.assertEqual(vac.fmt(2048), "2 KB")

    def test_mb(self):
        self.assertEqual(vac.fmt(vac.BYTES_PER_MB), "1.0 MB")

    def test_gb(self):
        self.assertEqual(vac.fmt(vac.BYTES_PER_GB), "1.00 GB")
        self.assertEqual(vac.fmt(int(2.5 * vac.BYTES_PER_GB)), "2.50 GB")


class TestIsAppRunning(unittest.TestCase):

    def test_match(self):
        self.assertTrue(vac.is_app_running("cent", {"chrome.exe"}))
        self.assertFalse(vac.is_app_running("firefox", {"chrome.exe"}))

    def test_no_match_empty(self):
        self.assertFalse(vac.is_app_running("telegram", set()))

    def test_unknown_group(self):
        self.assertFalse(vac.is_app_running("nope", {"chrome.exe"}))


class TestConfigPersistence(unittest.TestCase):

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.tmp_config = Path(self.tmp_dir.name) / "cleaner_config.json"
        self.cm = patch.object(vac, "CONFIG_FILE", self.tmp_config)
        self.cm.start()

    def tearDown(self):
        self.cm.stop()
        self.tmp_dir.cleanup()

    def test_load_no_file(self):
        result = vac.load_config()
        self.assertIn("custom_rules", result)
        self.assertIn("portable_roots", result)
        self.assertIn("lang", result)

    def test_load_creates_config_file(self):
        vac.load_config()
        self.assertTrue(self.tmp_config.exists())

    def test_save_and_load_roundtrip(self):
        data = {"custom_rules": [{"path": "D:\\Apps\\TestApp", "pattern": "*.log"}]}
        vac.save_config(data)
        loaded = vac.load_config()
        self.assertEqual(loaded["custom_rules"], data["custom_rules"])

    def test_load_corrupted(self):
        self.tmp_config.write_text("{corrupt}", encoding="utf-8")
        result = vac.load_config()
        self.assertEqual(result["custom_rules"], [])

    def test_load_migrates_dead_profiles_key(self):
        self.tmp_config.write_text(
            '{"custom_rules": [{"path": "D:\\\\x", "pattern": "*"}], "portable_roots": ["D:\\\\p"], "profiles": {"Default": {}}}',
            encoding="utf-8")
        result = vac.load_config()
        self.assertNotIn("profiles", result)
        self.assertEqual(result["custom_rules"][0]["path"], "D:\\x")
        migrated = json.loads(self.tmp_config.read_text(encoding="utf-8"))
        self.assertNotIn("profiles", migrated)

    def test_save_atomic(self):
        vac.save_config({"custom_rules": []})
        self.assertTrue(self.tmp_config.exists())
        tmp = self.tmp_config.with_suffix(".json.tmp")
        self.assertFalse(tmp.exists())

    def test_window_geometry_default(self):
        result = vac.load_config()
        self.assertIn("window_geometry", result)
        self.assertEqual(result["window_geometry"], "")

    def test_window_geometry_roundtrip(self):
        vac.save_config({"custom_rules": [], "window_geometry": "1024x768+10+20"})
        loaded = vac.load_config()
        self.assertEqual(loaded["window_geometry"], "1024x768+10+20")

    def test_parse_geometry_valid(self):
        self.assertEqual(vac.parse_geometry("1280x720-5+10"), "1280x720-5+10")

    def test_parse_geometry_empty_or_garbage(self):
        self.assertEqual(vac.parse_geometry(""), "960x640")
        self.assertEqual(vac.parse_geometry("garbage"), "960x640")

    def test_parse_geometry_without_offsets(self):
        self.assertEqual(vac.parse_geometry("1280x720"), "1280x720")

    def test_parse_geometry_clamps_minimum(self):
        self.assertEqual(vac.parse_geometry("400x300+0+0"), "800x500+0+0")


class TestPortableRootPolicy(unittest.TestCase):
    """T-096: no hardcoded personal portable roots; fresh default is empty."""

    def test_fresh_default_roots_empty(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(vac, "CONFIG_FILE", Path(tmp) / "cleaner_config.json"):
            self.assertEqual(vac.load_config()["portable_roots"], [])

    def test_configured_roots_round_trip_intact(self):
        """Existing user-configured roots must survive a load/rewrite cycle."""
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / "cleaner_config.json"
            cfg.write_text(json.dumps({
                "portable_roots": ["D:\\Portable\\Apps", "E:\\Tools\\Portable"],
                "custom_rules": [], "exclude_patterns": [], "exclude_paths": [],
            }), encoding="utf-8")
            with patch.object(vac, "CONFIG_FILE", cfg):
                data = vac.load_config()
                self.assertEqual(data["portable_roots"], ["D:\\Portable\\Apps", "E:\\Tools\\Portable"])

    def test_source_has_no_personal_drive_constants(self):
        src = Path(vac.__file__).read_text(encoding="utf-8")
        self.assertNotIn("___VAC", src)
        self.assertNotIn("__SAVE_G", src)
        self.assertNotIn("PRIMARY_ROOT", src)
        self.assertNotIn("BACKUP_ROOTS", src)


class TestUserAppdataTargets(unittest.TestCase):

    def test_new_safe_targets_present(self):
        names = [d for _, d, _ in vac.USER_APPDATA_TARGETS]
        for expected in ["Brave Cache", "Brave Code Cache", "Brave GPU Cache",
                         "Chrome Code Cache", "Edge Code Cache", "Calibre Cache",
                         "fontconfig Cache", "qBittorrent Logs", "Claude CLI Cache",
                         "FreeFileSync Logs"]:
            self.assertIn(expected, names)

    def test_targets_are_path_desc_owner_triples(self):
        for p, d, owner in vac.USER_APPDATA_TARGETS:
            self.assertIsInstance(p, Path)
            self.assertIsInstance(d, str)
            self.assertTrue(d)
            if owner is not None:
                self.assertIn(owner, vac.APP_PROCESSES)

    def test_every_target_owned_or_process_agnostic(self):
        """T-092: no implicit owner=None escape hatch. Every entry is either
        owned by a verified process group or explicitly PROCESS_AGNOSTIC."""
        for p, d, owner in vac.USER_APPDATA_TARGETS:
            ok = (owner is not None and owner in vac.APP_PROCESSES) or d in vac.PROCESS_AGNOSTIC_TARGETS
            self.assertTrue(ok, f"{d}: owner={owner} not in APP_PROCESSES and not PROCESS_AGNOSTIC")

    def test_targets_no_duplicate_paths(self):
        paths = [str(p.resolve()) for p, _, _ in vac.USER_APPDATA_TARGETS]
        self.assertEqual(len(paths), len(set(paths)))

    def test_freefilesync_target_is_explicit_logs_child(self):
        """P0-1: never point a cache target at an app/config root."""
        for p, d, _ in vac.USER_APPDATA_TARGETS:
            if d == "FreeFileSync Logs":
                self.assertTrue(str(p).lower().endswith(os.path.join("freefilesync", "logs")) or
                                str(p).lower().endswith(os.path.join("freefilesync", "logs").replace("\\", "/")))
                return
        self.fail("FreeFileSync Logs target missing")

    def test_broad_app_roots_quarantined(self):
        """P0-6: whole app/profile/config roots must not be deletion targets."""
        raw = [str(p).lower() for p, _, _ in vac.USER_APPDATA_TARGETS]
        for banned in ["cef", "davinci resolve welcome", "perdriverversion"]:
            for p in raw:
                self.assertNotIn(banned, p.split(os.sep)[-2:], banned)
        # Razer Service Worker whole-root target removed
        for p, d, _ in vac.USER_APPDATA_TARGETS:
            if d.startswith("Razer"):
                self.assertFalse(p.name.lower() == "service worker", "whole SW root target")


class TestSafetyGuard(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.guard = vac.SafetyGuard(self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def test_inside_allowed(self):
        p = self.root / "sub" / "dir" / "f.txt"
        p.parent.mkdir(parents=True)
        ok, _ = self.guard.is_safe(p)
        self.assertTrue(ok)

    def test_outside_blocked(self):
        ok, reason = self.guard.is_safe(Path(tempfile.gettempdir()))
        self.assertFalse(ok)
        self.assertIn("Outside", reason)

    def test_root_blocked(self):
        ok, _reason = self.guard.is_safe(self.root)
        self.assertFalse(ok)

    def test_never_delete_blocked(self):
        name = next(iter(vac.NEVER_DELETE_NAMES))
        p = self.root / "sub" / name
        p.parent.mkdir(parents=True)
        p.touch()
        ok, _ = self.guard.is_safe(p)
        self.assertFalse(ok)

    def test_dotdot_blocked(self):
        ok, _ = self.guard.is_safe(self.root / ".." / "x.txt")
        self.assertFalse(ok)

    def test_system_root_allows_shallow(self):
        guard = vac.SafetyGuard(self.root, is_system_root=True)
        p = self.root / "a" / "b"
        p.mkdir(parents=True)
        ok, _ = guard.is_safe(p)
        self.assertTrue(ok)


class TestGetRunningProcesses(unittest.TestCase):

    @patch("_SMART_VAC_CLEANER.subprocess.run")
    def test_parses_output(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout='"chrome.exe","1234","Console"\r\n"firefox.exe","5678","Console"\r\n',
            returncode=0)
        procs = vac.get_running_processes()
        self.assertEqual(procs, {"chrome.exe", "firefox.exe"})

    @patch("_SMART_VAC_CLEANER.subprocess.run")
    def test_parses_quoted_csv_image_names(self, mock_run):
        """tasklist csv rows may carry quotes; csv.reader must handle them (P1-8)."""
        mock_run.return_value = MagicMock(
            stdout='"chrome.exe, x64","1234","Console"\r\n',
            returncode=0)
        procs = vac.get_running_processes()
        self.assertEqual(procs, {"chrome.exe, x64"})

    @patch("_SMART_VAC_CLEANER.subprocess.run")
    def test_failure_returns_none_fail_closed(self, mock_run):
        """Exception => UNKNOWN (None), never an empty 'nothing runs' set (P1-8)."""
        mock_run.side_effect = OSError("fail")
        self.assertIsNone(vac.get_running_processes())

    @patch("_SMART_VAC_CLEANER.subprocess.run")
    def test_nonzero_exit_returns_none(self, mock_run):
        """Nonzero tasklist exit => UNKNOWN (None), never 'nothing runs'."""
        mock_run.return_value = MagicMock(stdout="", returncode=1)
        self.assertIsNone(vac.get_running_processes())

    @patch("_SMART_VAC_CLEANER.subprocess.run")
    def test_empty_output(self, mock_run):
        mock_run.return_value = MagicMock(stdout="", returncode=0)
        self.assertEqual(vac.get_running_processes(), set())

    def test_is_app_running_unknown_blocks(self):
        """Real process group + UNKNOWN snapshot => treated as running (fail closed)."""
        self.assertTrue(vac.is_app_running("brave", None))
        self.assertTrue(vac.is_app_running("chrome", None))

    def test_is_app_running_general_never_blocks(self):
        self.assertFalse(vac.is_app_running("general", None))
        self.assertFalse(vac.is_app_running("general", {"chrome.exe"}))


class TestGetSize(unittest.TestCase):

    def test_file(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"x" * 777)
            path = Path(f.name)
        try:
            self.assertEqual(vac.get_size(path), 777)
        finally:
            path.unlink(missing_ok=True)

    def test_dir_sum(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a.txt").write_text("hello")
            (root / "b.txt").write_text("world")
            self.assertEqual(vac.get_size(root), 10)

    def test_nonexistent(self):
        self.assertEqual(vac.get_size(Path("Z:/__GARBAGE__")), 0)


class TestLogger(unittest.TestCase):

    def test_counts_start_zero(self):
        log = vac.Logger(log_file=None, dry_run=True)
        self.assertEqual(log.n_deleted, 0)
        self.assertEqual(log.n_errors, 0)

    def test_deleted_tracks(self):
        log = vac.Logger(log_file=None, dry_run=True)
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"x" * 500)
            path = Path(f.name)
        try:
            log.deleted(path, 500, "test")
            self.assertEqual(log.bytes_freed, 500)
            self.assertEqual(log.n_deleted, 1)
        finally:
            path.unlink(missing_ok=True)

    def test_summary_no_crash(self):
        vac.Logger(log_file=None, dry_run=True).summary()


class TestNumberedRegex(unittest.TestCase):

    def test_matches(self):
        m = vac.PortableCleaner._NUMBERED_RE.match("backup (2)")
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), "backup")

    def test_matches_single(self):
        m = vac.PortableCleaner._NUMBERED_RE.match("backup (1)")
        self.assertIsNotNone(m)  # regex matches any number, filter is in sweep_numbered_copies

    def test_no_match_plain(self):
        self.assertIsNone(vac.PortableCleaner._NUMBERED_RE.match("backup"))


class TestConstants(unittest.TestCase):

    def test_never_delete_critical(self):
        for name in ("login data", "bookmarks", "cookies"):
            self.assertIn(name, vac.NEVER_DELETE_NAMES)

    def test_min_path_parts(self):
        self.assertGreaterEqual(vac.MIN_PATH_PARTS, 3)

    def test_chromium_dirs_populated(self):
        self.assertTrue(len(vac.CHROMIUM_PROFILE_DIRS) > 5)


class TestExclusions(unittest.TestCase):
    """Tests for exclusion list logic."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_exclude_pattern_matches(self):
        """fnmatch pattern excludes matching files."""
        guard = vac.SafetyGuard(self.root, exclude_patterns=["*.tmp", "cache*"])
        p = self.root / "sub" / "file.tmp"
        p.parent.mkdir(parents=True); p.touch()
        ok, reason = guard.is_safe(p)
        self.assertFalse(ok)
        self.assertIn("exclude pattern", reason)

    def test_exclude_pattern_no_match(self):
        """Non-matching pattern does not block."""
        guard = vac.SafetyGuard(self.root, exclude_patterns=["*.tmp"])
        p = self.root / "sub" / "dir" / "keep.txt"
        p.parent.mkdir(parents=True); p.touch()
        ok, _ = guard.is_safe(p)
        self.assertTrue(ok)

    def test_exclude_path_exact(self):
        """Exact excluded path is blocked."""
        excl = self.root / "sub" / "protected"
        excl.mkdir(parents=True)
        guard = vac.SafetyGuard(self.root, exclude_paths=[str(excl)])
        child = excl / "child.txt"
        child.touch()
        ok, reason = guard.is_safe(child)
        self.assertFalse(ok)
        self.assertIn("under excluded path", reason)

    def test_exclude_path_not_blocking_outside(self):
        """Path outside excluded dir is not blocked."""
        excl = self.root / "excluded"
        excl.mkdir(parents=True)
        guard = vac.SafetyGuard(self.root, exclude_paths=[str(excl)])
        other = self.root / "other" / "keep.txt"
        other.parent.mkdir(); other.touch()
        ok, _ = guard.is_safe(other)
        self.assertTrue(ok)


class TestBlacklist(unittest.TestCase):
    """Tests for path blacklist protection (P1-10: roots + descendants)."""

    @staticmethod
    def _non_c_drive_path(*parts):
        """An absolute path on the cwd's drive (non-C: on this machine), away from the repo."""
        drive = os.path.splitdrive(os.getcwd())[0] or "D:"
        return Path(drive + os.sep, ".__vac_safety_test__", *parts)

    def test_windir_blocked(self):
        self.assertTrue(vac.is_path_blacklisted(Path(os.environ.get("windir", r"C:\Windows"))))

    def test_windir_children_blocked(self):
        self.assertTrue(vac.is_path_blacklisted(Path(os.environ.get("windir", r"C:\Windows")) / "Temp"))

    def test_program_files_blocked(self):
        self.assertTrue(vac.is_path_blacklisted(Path(os.environ.get("ProgramFiles", r"C:\Program Files"))))

    def test_program_files_children_blocked(self):
        """P1-10: descendants of Program Files must be rejected."""
        self.assertTrue(vac.is_path_blacklisted(
            Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Google" / "Chrome" / "Application"))

    def test_program_files_x86_children_blocked(self):
        self.assertTrue(vac.is_path_blacklisted(
            Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Microsoft" / "Edge"))

    def test_userprofile_children_blocked(self):
        """Docs say USERPROFILE is rejected; descendants follow (P1-10)."""
        self.assertTrue(vac.is_path_blacklisted(
            Path(os.environ.get("USERPROFILE", r"C:\Users")) / "AppData" / "Local"))

    def test_cleaner_dir_blocked(self):
        self.assertTrue(vac.is_path_blacklisted(vac.SCRIPT_PATH.parent))
        self.assertTrue(vac.is_path_blacklisted(vac.BASE_DIR / "sub" / "child"))

    def test_regular_dir_allowed(self):
        self.assertFalse(vac.is_path_blacklisted(self._non_c_drive_path("cache")))

    def test_custom_rule_blacklisted_skipped(self):
        """CustomCleaner skips blacklisted rules without touching them."""
        log = vac.Logger(log_file=None, dry_run=True)
        rule = {"path": os.environ.get("windir", r"C:\Windows"), "pattern": "*"}
        cleaner = vac.CustomCleaner(True, log, [rule])
        self.assertEqual(cleaner.run_all(), 0)
        self.assertEqual(log.n_deleted, 0)


class TestPortableSweep(unittest.TestCase):
    """Tests for PortableCleaner sweep logic (tempdir only)."""

    def _cleaner(self, root):
        log = vac.Logger(log_file=None, dry_run=False)
        guard = vac.SafetyGuard(root)
        return vac.PortableCleaner(False, log, guard, root, vac.DEFAULT_THREADS, None), log

    def _deep_root(self, tmp):
        root = Path(tmp) / "sweep" / "target_root"
        root.mkdir(parents=True)
        return root

    def test_numbered_copies_junk_base_only(self):
        """P0-2: numbered cleanup is explicit junk-only; unknown bases are kept."""
        with tempfile.TemporaryDirectory() as tmp:
            root = self._deep_root(tmp)
            for name in ["cache", "cache (1)", "cache (2)", "cache (3)"]:
                p = root / name
                p.mkdir()
                (p / "x.txt").write_text("x")
            cleaner, log = self._cleaner(root)
            cleaner.sweep_numbered_copies(root, "app")
            self.assertTrue((root / "cache").exists())
            self.assertTrue((root / "cache (1)").exists())
            self.assertFalse((root / "cache (2)").exists())
            self.assertFalse((root / "cache (3)").exists())
            self.assertEqual(log.n_deleted, 2)

    def test_numbered_copies_non_junk_kept(self):
        """P0-2: 'app (2)' (not proven junk) survives the sweep."""
        with tempfile.TemporaryDirectory() as tmp:
            root = self._deep_root(tmp)
            for name in ["app", "app (1)", "app (2)", "app (3)"]:
                p = root / name
                p.mkdir()
                (p / "x.txt").write_text("x")
            cleaner, log = self._cleaner(root)
            cleaner.sweep_numbered_copies(root, "app")
            self.assertTrue((root / "app (2)").exists())
            self.assertTrue((root / "app (3)").exists())
            self.assertEqual(log.n_deleted, 0)

    def test_numbered_copies_protected_profile_names_survive(self):
        """P0-2: protected user data with a numbered suffix survives the sweep."""
        protected = ["Cookies (2)", "Network Persistent State (2)", "Bookmarks (2)",
                     "History (2)", "History (3)", "Login Data (2)", "Preferences (8)",
                     "Affiliation Database (2)"]
        with tempfile.TemporaryDirectory() as tmp:
            root = self._deep_root(tmp)
            for name in protected:
                (root / name).write_text("secrets")
            cleaner, log = self._cleaner(root)
            cleaner.sweep_numbered_copies(root, "app")
            for name in protected:
                self.assertTrue((root / name).exists(), name)
            self.assertEqual(log.n_deleted, 0)

    def test_name_variants_protect_numbered_names(self):
        """P0-2: every runtime-lost protected name must map into NEVER_DELETE_NAMES."""
        for name in ["cookies (2)", "network persistent state (2)", "bookmarks (2)",
                     "history (2)", "history (3)", "login data (2)", "preferences (8)",
                     "affiliation database (2)", "affiliation database-journal",
                     "trusted_vault.pb", "passkey_enclave_state",
                     "global settings.xml", "lastrun.ffs_real",
                     "cookies-journal", "session storage", "databases"]:
            variants = vac._name_variants(name.lower())
            self.assertTrue(any(v in vac.NEVER_DELETE_NAMES for v in variants), name)

    def test_name_variants_compound_fixed_point(self):
        """T-097: compound 'numbered + journal tail' names reduce to the base."""
        for name in ["cookies (2)-journal", "login data (3)-wal", "history (2)-shm",
                     "bookmarks (4)-old", "preferences (2)-journal",
                     "network persistent state (3)-wal", "affiliation database (2)-journal"]:
            variants = vac._name_variants(name.lower())
            self.assertIn(name.lower(), variants, name)
            base = re.sub(r" \(\d+\)", "", re.sub(r"-(?:journal|wal|shm|old|bak)$", "", name)).lower()
            self.assertIn(base, variants, name)
            self.assertTrue(any(v in vac.NEVER_DELETE_NAMES for v in variants), name)

    def test_name_variants_no_fuzzy_substrings(self):
        """T-097: only mechanical suffix rules; no substring guessing."""
        for name in ["cache", "code cache", "gpucache", "logs", "cache (2)"]:
            variants = vac._name_variants(name.lower())
            self.assertFalse(any(v in vac.NEVER_DELETE_NAMES for v in variants), name)

    def test_numbered_copies_skipped_when_running(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._deep_root(tmp)
            p = root / "cache (2)"
            p.mkdir()
            (p / "x.txt").write_text("x")
            cleaner, log = self._cleaner(root)
            with patch.object(vac, "is_app_running", return_value=True):
                cleaner.sweep_numbered_copies(root, "app")
            self.assertTrue(p.exists())
            self.assertEqual(log.n_deleted, 0)

    def test_old_opera_versions_keep_latest(self):
        # Environment-independent: the opera gate must not depend on whether
        # Opera happens to be running on the machine right now.
        with tempfile.TemporaryDirectory() as tmp:
            root = self._deep_root(tmp)
            for ver in ["120.0.1.0", "120.0.2.0", "121.0.3.0"]:
                (root / ver).mkdir()
            cleaner, log = self._cleaner(root)
            with patch.object(vac, "is_app_running", return_value=False):
                cleaner._clean_old_opera_versions(root)
            self.assertFalse((root / "120.0.1.0").exists())
            self.assertFalse((root / "120.0.2.0").exists())
            self.assertTrue((root / "121.0.3.0").exists())
            self.assertEqual(log.n_deleted, 2)

    def test_universal_cache_sweep_verified_owner(self):
        """T-098: discovered cache under a verified portable app dir is swept."""
        with tempfile.TemporaryDirectory() as tmp:
            root = self._deep_root(tmp)
            cache = root / "_CENT" / "User Data" / "Default" / "Cache"
            keep = root / "_CENT" / "User Data" / "Config"
            cache.mkdir(parents=True)
            keep.mkdir(parents=True)
            (cache / "junk.bin").write_bytes(b"x" * 100)
            (keep / "settings.ini").write_text("keep")
            cleaner, log = self._cleaner(root)
            with patch.object(vac, "get_running_processes", return_value=set()):
                cleaner.clean_universal_caches()
            self.assertFalse((cache / "junk.bin").exists())
            self.assertTrue(keep.exists())
            self.assertGreater(log.n_deleted, 0)

    def test_universal_cache_sweep_unknown_owner_skipped_in_delete(self):
        """T-098: a discovered cache with no verified owner is NEVER deleted."""
        with tempfile.TemporaryDirectory() as tmp:
            root = self._deep_root(tmp)
            cache = root / "App" / "Cache"
            cache.mkdir(parents=True)
            (cache / "junk.bin").write_bytes(b"x" * 100)
            cleaner, log = self._cleaner(root)
            with patch.object(vac, "get_running_processes", return_value=set()):
                cleaner.clean_universal_caches()
            self.assertTrue((cache / "junk.bin").exists(), "unknown-owner cache must survive in delete mode")
            self.assertEqual(log.n_deleted, 0)

    def test_universal_cache_owner_resolution(self):
        """T-098: _universal_owner_for maps known portable app dirs."""
        with tempfile.TemporaryDirectory() as tmp:
            root = self._deep_root(tmp)
            cleaner, _ = self._cleaner(root)
            self.assertEqual(cleaner._universal_owner_for(root / "_CENT" / "x" / "Cache"), "cent")
            self.assertEqual(cleaner._universal_owner_for(root / "_TG" / "tdata" / "cache"), "telegram")
            self.assertEqual(cleaner._universal_owner_for(root / "__SOFT" / "_BRAVE" / "data" / "Cache"), "brave")
            self.assertIsNone(cleaner._universal_owner_for(root / "UnknownApp" / "Cache"))

    def test_chromium_profile_protects_login_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._deep_root(tmp)
            profile = root / "Default"
            (profile / "Cache").mkdir(parents=True)
            (profile / "Cache" / "f").write_text("x")
            (profile / "Login Data").write_text("secrets")
            cleaner, _ = self._cleaner(root)
            cleaner._clean_chromium_profile(profile, "chromium")
            self.assertFalse((profile / "Cache").exists())
            self.assertTrue((profile / "Login Data").exists())


class TestPathHardening(unittest.TestCase):
    """Tests for path normalization / anti-drift layers."""

    def test_slash_style_unified(self):
        self.assertEqual(
            str(vac.normalize_path(r"C:\Users\me\AppData\Local\Cache")),
            str(vac.normalize_path("C:/Users/me/AppData/Local/Cache/")))

    def test_dot_segments_collapsed(self):
        self.assertEqual(
            str(vac.normalize_path(r"C:\Users\me\AppData\..\AppData\Local")),
            str(vac.normalize_path(r"C:\Users\me\AppData\Local")))

    def test_trailing_separator_collapsed(self):
        self.assertEqual(
            str(vac.normalize_path("C:\\Tools\\Portable\\")),
            str(vac.normalize_path(r"C:\Tools\Portable")))

    def test_env_var_expansion(self):
        self.assertEqual(
            str(vac.normalize_path(r"%LOCALAPPDATA%\Cache")),
            str(vac.normalize_path(os.environ.get("LOCALAPPDATA", r"C:\nope") + r"\Cache")))

    def test_quotes_stripped(self):
        self.assertEqual(
            str(vac.normalize_path('"D:\\Apps\\X"')),
            str(vac.normalize_path("D:\\Apps\\X")))

    def test_relative_rejected(self):
        self.assertIsNone(vac.normalize_path("Portable\\Cache"))

    def test_empty_and_garbage_rejected(self):
        self.assertIsNone(vac.normalize_path(""))
        self.assertIsNone(vac.normalize_path('   '))
        self.assertIsNone(vac.normalize_path("D:\\bad\x01path"))

    def test_roots_dedupe(self):
        valid, rejected = vac.sanitize_roots([
            "D:\\Portable\\", "D:/Portable", r"D:\Portable\..\Portable", "D:\\Other"])
        self.assertEqual(valid, [str(vac.normalize_path("D:\\Portable")), str(vac.normalize_path("D:\\Other"))])
        self.assertEqual(rejected, [])

    def test_roots_nested_rejected(self):
        valid, rejected = vac.sanitize_roots(["D:\\Apps", "D:\\Apps\\Extra"])
        self.assertEqual(len(valid), 1)
        self.assertTrue(any("nested" in r for r in rejected))

    def test_roots_blacklisted_rejected(self):
        valid, rejected = vac.sanitize_roots([os.environ.get("windir", r"C:\Windows"), "D:\\Clean"])
        self.assertEqual(valid, [str(vac.normalize_path("D:\\Clean"))])
        self.assertTrue(any("blacklisted" in r for r in rejected))

    def test_load_config_normalizes_user_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / "cleaner_config.json"
            cfg.write_text(json.dumps({
                "portable_roots": ["D:\\Portable\\", "D:/Portable"],
                "custom_rules": [{"path": "C:\\Windows\\System32", "pattern": "*"},
                                 {"path": r"D:\App\Logs", "pattern": "*.log"}],
                "exclude_paths": ["D:\\Keep\\"],
            }), encoding="utf-8")
            with patch.object(vac, "CONFIG_FILE", cfg):
                data = vac.load_config()
                self.assertEqual(len(data["portable_roots"]), 1)  # deduped
                self.assertEqual(data["portable_roots"], [str(vac.normalize_path(r"D:\Portable"))])
                self.assertEqual(len(data["custom_rules"]), 1)  # Windows rule dropped
                self.assertEqual(data["custom_rules"][0]["path"], str(vac.normalize_path(r"D:\App\Logs")))
                self.assertEqual(data["exclude_paths"], [str(vac.normalize_path(r"D:\Keep"))])


class TestCLIFunctions(unittest.TestCase):
    """Tests for CLI mode functions."""

    def test_background_clean_argv_frozen(self):
        with patch.object(vac.sys, "frozen", True, create=True):
            argv = vac.background_clean_argv()
        self.assertEqual(argv[0], vac.sys.executable)
        for flag in ("--cli", "--all", "--delete", "--hidden"):
            self.assertIn(flag, argv)

    def test_background_clean_argv_pythonw(self):
        with patch.object(vac.sys, "frozen", False, create=True):
            argv = vac.background_clean_argv()
        self.assertTrue(str(argv[0]).endswith("pythonw.exe"))
        self.assertIn("--cli", argv)
        self.assertIn("--delete", argv)
        self.assertIn("--hidden", argv)

    def test_default_strings_have_run_bg(self):
        self.assertIn("run_bg", vac.DEFAULT_STRINGS)
        self.assertTrue(vac.DEFAULT_STRINGS["run_bg"])

    def test_calculate_target_sizes_empty(self):
        """Returns empty dict when no targets enabled."""
        result = vac.calculate_target_sizes({})
        self.assertIsInstance(result, dict)

    def test_calculate_target_sizes_nonexistent(self):
        """Returns empty dict when targets don't exist on disk."""
        enabled = {"System Temp": True, "User Temp": True}
        result = vac.calculate_target_sizes(enabled)
        # Paths may or may not exist — should return dict regardless
        self.assertIsInstance(result, dict)
        for k, v in result.items():
            self.assertIsInstance(k, str)
            self.assertIsInstance(v, int)

    def test_cli_status_no_crash(self):
        """cli_status() prints without raising."""
        try:
            vac.cli_status()
        except SystemExit:
            self.fail("cli_status() raised SystemExit")

    @patch("_SMART_VAC_CLEANER.argparse.ArgumentParser.parse_args")
    def test_main_dry_run_default(self, mock_parse):
        """No flags = dry_run=True, no CLI categories."""
        mock_parse.return_value = MagicMock(
            dry_run=False, delete=False,
            portable=False, system=False, custom=False, all=False,
            cli=False, status=False, analyze_caches=False, hidden=False, sys_targets="",
            exclude="", install_task=False, time="09:00",
        )
        # main() should go to GUI path (App()), not CLI
        with patch.object(vac, "App") as mock_app, patch.object(vac, "cli_status"):
            vac.main()
            mock_app.assert_called_once()

    @patch("_SMART_VAC_CLEANER.argparse.ArgumentParser.parse_args")
    def test_main_status_flag(self, mock_parse):
        """--status calls cli_status()."""
        mock_parse.return_value = MagicMock(
            dry_run=False, delete=False,
            portable=False, system=False, custom=False, all=False,
            cli=False, status=True, hidden=False, sys_targets="",
            exclude="", install_task=False, time="09:00",
        )
        with patch.object(vac, "cli_status") as mock_status:
            vac.main()
            mock_status.assert_called_once()

    @patch("_SMART_VAC_CLEANER.argparse.ArgumentParser.parse_args")
    def test_main_analyze_caches_flag(self, mock_parse):
        """--analyze-caches calls analyze_caches.main()."""
        mock_parse.return_value = MagicMock(
            dry_run=False, delete=False,
            portable=False, system=False, custom=False, all=False,
            cli=False, status=False, analyze_caches=True, hidden=False, sys_targets="",
            exclude="", install_task=False, time="09:00",
        )
        with patch("analyze_caches.main") as mock_analyze:
            vac.main()
            mock_analyze.assert_called_once()

    @patch("_SMART_VAC_CLEANER.argparse.ArgumentParser.parse_args")
    def test_main_portable_flag(self, mock_parse):
        """--portable without --delete runs dry-run."""
        mock_parse.return_value = MagicMock(
            dry_run=False, delete=False,
            portable=True, system=False, custom=False, all=False,
            cli=False, status=False, analyze_caches=False, hidden=False, sys_targets="",
            exclude="", install_task=False, time="09:00",
        )
        with patch.object(vac, "run_cleaning_job") as mock_job, patch.object(vac, "Logger"):
            vac.main()
            args, _ = mock_job.call_args
            self.assertTrue(args[0])  # dry_run is True by default

    @patch("_SMART_VAC_CLEANER.argparse.ArgumentParser.parse_args")
    def test_main_delete_flag(self, mock_parse):
        """--delete overrides dry-run to False."""
        mock_parse.return_value = MagicMock(
            dry_run=False, delete=True,
            portable=True, system=True, custom=True, all=False,
            cli=False, status=False, analyze_caches=False, hidden=False, sys_targets="",
            exclude="", install_task=False, time="09:00",
        )
        with patch.object(vac, "run_cleaning_job") as mock_job, patch.object(vac, "Logger"):
            vac.main()
            args, _ = mock_job.call_args
            self.assertFalse(args[0])  # dry_run = False with --delete

    @patch("_SMART_VAC_CLEANER.argparse.ArgumentParser.parse_args")
    def test_main_explicit_dry_run_with_delete(self, mock_parse):
        """--dry-run --delete = dry_run=True (explicit flag wins)."""
        mock_parse.return_value = MagicMock(
            dry_run=True, delete=True,
            portable=True, system=False, custom=False, all=False,
            cli=False, status=False, analyze_caches=False, hidden=False, sys_targets="",
            exclude="", install_task=False, time="09:00",
        )
        with patch.object(vac, "run_cleaning_job") as mock_job, patch.object(vac, "Logger"):
            vac.main()
            args, _ = mock_job.call_args
            self.assertTrue(args[0])  # explicit --dry-run wins

    @patch("_SMART_VAC_CLEANER.argparse.ArgumentParser.parse_args")
    def test_main_hidden_flag(self, mock_parse):
        """--hidden with --portable hides console and runs job."""
        mock_parse.return_value = MagicMock(
            dry_run=False, delete=True,
            portable=True, system=False, custom=False, all=False,
            cli=False, status=False, analyze_caches=False, hidden=True, sys_targets="",
            exclude="", install_task=False, time="09:00",
        )
        with patch.object(vac, "run_cleaning_job") as mock_job, patch.object(vac, "Logger"), patch.object(vac, "_hide_console") as mock_hide:
            vac.main()
            mock_hide.assert_called_once()
            self.assertTrue(mock_job.called)


class TestI18n(unittest.TestCase):

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.tmp_strings = Path(self.tmp_dir.name) / "strings"
        self.tmp_strings.mkdir()
        (self.tmp_strings / "ru.json").write_text(
            '{"clean": "Очистить", "stop": "Стоп"}', encoding="utf-8")
        self.cm = patch.object(vac, "STRINGS_DIR", self.tmp_strings)
        self.cm.start()

    def tearDown(self):
        self.cm.stop()
        self.tmp_dir.cleanup()

    def test_unknown_lang_falls_back_to_english(self):
        s = vac.load_strings("xx")
        self.assertEqual(s["clean"], "Clean")
        self.assertEqual(s["confirm_title"], "Confirm DELETE")

    def test_translated_lang_overrides(self):
        s = vac.load_strings("ru")
        self.assertEqual(s["clean"], "Очистить")
        self.assertEqual(s["stop"], "Стоп")
        self.assertEqual(s["window_title"], "Smart VAC Cleaner")

    def test_missing_file_falls_back_to_english(self):
        s = vac.load_strings("et")
        self.assertEqual(s["clean"], "Clean")


def snapshot_tree(root: Path) -> dict:
    """Relpath -> (size, sha256) for every file under root (sorted)."""
    snap = {}
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            p = Path(dirpath) / name
            rel = str(p.relative_to(root))
            snap[rel] = (p.stat().st_size, hashlib.sha256(p.read_bytes()).hexdigest())
    return {k: snap[k] for k in sorted(snap)}


class _ExplodeMutations:
    """Context manager: every filesystem mutation primitive raises AssertionError."""

    _PATCH_TARGETS: ClassVar[list[str]] = [
        "pathlib.Path.unlink",
        "pathlib.Path.rmdir",
        "pathlib.Path.chmod",
        "os.remove",
        "os.rmdir",
        "shutil.rmtree",
    ]

    def _resolve(self, dotted):
        obj = __import__(dotted.split(".", 1)[0])
        for part in dotted.split(".")[1:]:
            obj = getattr(obj, part)
        return obj

    def __enter__(self):
        self._patches = []
        for target in self._PATCH_TARGETS:
            holder = self._resolve(target.rsplit(".", 1)[0])
            attr = target.rsplit(".", 1)[1]
            orig = getattr(holder, attr)
            self._patches.append((holder, attr, orig))
            def _boom(*a, _t=target, **k):
                raise AssertionError(f"dry-run MUST NOT mutate: {_t} called")
            setattr(holder, attr, _boom)
        return self

    def __exit__(self, *exc):
        for holder, attr, orig in self._patches:
            setattr(holder, attr, orig)
        return False


class TestDryRunPurity(unittest.TestCase):
    """T-090: dry-run is physically read-only (planning never mutates)."""

    def _make(self):
        """Return (TemporaryDirectory, root). Caller must .cleanup() after the context."""
        return tempfile.TemporaryDirectory()

    def test_repro_regression_dir(self):
        """The T-090 reproduction: dry-run must leave file+dir untouched."""
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp) / "app"
            t.mkdir()
            (t / "a.bin").write_bytes(b"x" * 100)
            log = vac.Logger(log_file=None, dry_run=True)
            c = vac.CleanerEngine(True, log, vac.SafetyGuard(Path(tmp), is_system_root=True), Path(tmp))
            c._del_dir(t, "app")
            self.assertTrue((t / "a.bin").exists())
            self.assertTrue(t.exists())

    def _tripwire(self, body):
        tmp = tempfile.TemporaryDirectory()
        try:
            with _ExplodeMutations():
                body(Path(tmp.name))
        finally:
            tmp.cleanup()

    def test_tripwire_del_file(self):
        def body(root):
            f = root / "f.bin"
            f.write_bytes(b"x" * 10)
            log = vac.Logger(log_file=None, dry_run=True)
            c = vac.CleanerEngine(True, log, vac.SafetyGuard(root, is_system_root=True), root)
            freed = c._del_file(f, "f")
            self.assertEqual(freed, 10)
            self.assertTrue(f.exists())
        self._tripwire(body)

    def test_tripwire_del_dir(self):
        def body(root):
            app = root / "app"
            (app / "deep" / "sub").mkdir(parents=True)
            (app / "a.bin").write_bytes(b"x" * 50)
            (app / "deep" / "b.bin").write_bytes(b"y" * 30)
            (app / "deep" / "sub" / "c.txt").write_text("hello")
            log = vac.Logger(log_file=None, dry_run=True)
            c = vac.CleanerEngine(True, log, vac.SafetyGuard(root, is_system_root=True), root)
            freed = c._del_dir(app, "app")
            self.assertEqual(freed, 85)
            self.assertTrue((app / "deep" / "sub" / "c.txt").exists())
        self._tripwire(body)

    def test_tripwire_del_dir_contents(self):
        def body(root):
            target = root / "junk"
            target.mkdir()
            for i in range(6):
                (target / f"f{i}.bin").write_bytes(b"x" * 10)
            log = vac.Logger(log_file=None, dry_run=True)
            c = vac.CleanerEngine(True, log, vac.SafetyGuard(root, is_system_root=True), root)
            freed = c._del_dir_contents(target, "junk")
            self.assertEqual(freed, 60)
            for i in range(6):
                self.assertTrue((target / f"f{i}.bin").exists())
        self._tripwire(body)

    def test_tripwire_portable_cleaner(self):
        def body(root):
            profile = root / "_CENT" / "User Data" / "Default"
            (profile / "Cache").mkdir(parents=True)
            (profile / "Cache" / "data_0").write_bytes(b"x" * 20)
            (profile / "Login Data").write_text("secrets")
            log = vac.Logger(log_file=None, dry_run=True)
            with patch.object(vac, "get_running_processes", return_value=set()):
                c = vac.PortableCleaner(True, log, vac.SafetyGuard(root, is_system_root=True), root)
                c.run_all()
            self.assertTrue((profile / "Cache" / "data_0").exists())
            self.assertTrue((profile / "Login Data").exists())
        self._tripwire(body)

    def test_tripwire_system_cleaner(self):
        def body(root):
            target = root / "Cache"
            target.mkdir()
            (target / "f.bin").write_bytes(b"x" * 20)
            targets = {k: False for k in vac.SYSTEM_TARGET_DEFAULTS}
            targets["FreeFileSync Logs"] = True
            with patch.object(vac, "USER_APPDATA_TARGETS", [(target, "FreeFileSync Logs", "freefilesync")]):
                log = vac.Logger(log_file=None, dry_run=True)
                with patch.object(vac, "get_running_processes", return_value=set()):
                    c = vac.SystemCleaner(True, log, targets=targets)
                    c.run_all()
            self.assertTrue((target / "f.bin").exists())
        self._tripwire(body)

    def test_tripwire_custom_cleaner(self):
        def body(root):
            (root / "keep").mkdir()
            (root / "keep" / "f.bin").write_bytes(b"x" * 20)
            rules = [{"path": str(root), "pattern": "*"}]
            log = vac.Logger(log_file=None, dry_run=True)
            c = vac.CustomCleaner(True, log, rules)
            c.run_all()
            self.assertTrue((root / "keep" / "f.bin").exists())
        self._tripwire(body)

    def test_tripwire_cli_all(self):
        """--all --dry-run --delete: zero mutation calls end to end."""
        def body(root):
            portable = root / "portable"
            (portable / "_CENT" / "User Data" / "Default" / "Cache").mkdir(parents=True)
            (portable / "_CENT" / "User Data" / "Default" / "Cache" / "data_0").write_bytes(b"x" * 20)
            safe_defaults = {k: False for k in vac.SYSTEM_TARGET_DEFAULTS}
            try:
                with patch.object(vac, "SYSTEM_TARGET_DEFAULTS", safe_defaults), \
                     patch.object(vac, "BASE_DIR", root), \
                     patch.object(vac, "load_config", return_value={
                         "portable_roots": [str(portable)], "custom_rules": [],
                         "exclude_patterns": [], "exclude_paths": []}), \
                     patch.object(vac, "get_running_processes", return_value=set()), \
                     patch("_SMART_VAC_CLEANER.argparse.ArgumentParser.parse_args") as mock_parse:
                    mock_parse.return_value = MagicMock(
                        dry_run=True, delete=True, portable=False, system=False,
                        custom=False, all=True, cli=True, status=False,
                        analyze_caches=False, hidden=False, sys_targets="", exclude="",
                        install_task=False, time="09:00")
                    vac.main()
            finally:
                logger = logging.getLogger("vac_cleaner")
                for h in logger.handlers[:]:
                    try:
                        h.close()
                    except Exception:  # noqa: BLE001, S110 - log-handler close is best effort
                        pass
            self.assertTrue((portable / "_CENT" / "User Data" / "Default" / "Cache" / "data_0").exists())
        self._tripwire(body)

    def test_byte_identical_snapshot_across_cleaners(self):
        """T-090: before/after trees are byte-identical after every dry-run path."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            portable = root / "portable"
            (portable / "_CENT" / "User Data" / "Default" / "Cache").mkdir(parents=True)
            (portable / "_CENT" / "User Data" / "Default" / "Cache" / "data_0").write_bytes(b"x" * 25)
            (portable / "_CENT" / "User Data" / "Default" / "Login Data (2)").write_text("secrets")
            appdata = root / "appdata"
            (appdata / "Cache" / "deep").mkdir(parents=True)
            (appdata / "Cache" / "deep" / "f.bin").write_bytes(b"y" * 40)
            custom = root / "custom"
            (custom / "logs").mkdir(parents=True)
            (custom / "logs" / "x.log").write_text("log")

            before = snapshot_tree(root)

            with patch.object(vac, "get_running_processes", return_value=set()):
                # _del_file
                f = appdata / "Cache" / "deep" / "f.bin"
                c = vac.CleanerEngine(True, vac.Logger(log_file=None, dry_run=True),
                                      vac.SafetyGuard(root, is_system_root=True), root)
                c._del_file(f, "f")
                # _del_dir
                c2 = vac.CleanerEngine(True, vac.Logger(log_file=None, dry_run=True),
                                       vac.SafetyGuard(root, is_system_root=True), root)
                c2._del_dir(appdata / "Cache" / "deep", "deep")
                # _del_dir_contents
                c3 = vac.CleanerEngine(True, vac.Logger(log_file=None, dry_run=True),
                                       vac.SafetyGuard(root, is_system_root=True), root)
                c3._del_dir_contents(custom / "logs", "logs")
                # PortableCleaner
                vac.PortableCleaner(True, vac.Logger(log_file=None, dry_run=True),
                                    vac.SafetyGuard(portable, is_system_root=True), portable).run_all()
                # CustomCleaner
                vac.CustomCleaner(True, vac.Logger(log_file=None, dry_run=True),
                                  [{"path": str(custom), "pattern": "*.log"}]).run_all()
                # SystemCleaner with a patched appdata target
                targets = {k: False for k in vac.SYSTEM_TARGET_DEFAULTS}
                targets["FreeFileSync Logs"] = True
                with patch.object(vac, "USER_APPDATA_TARGETS", [(appdata / "Cache", "FreeFileSync Logs", "freefilesync")]):
                    vac.SystemCleaner(True, vac.Logger(log_file=None, dry_run=True), targets=targets).run_all()

            after = snapshot_tree(root)
            self.assertEqual(before, after)


class TestSafetyInvariants(unittest.TestCase):
    """Hardening regressions: P0-1/3/4, P1-9/11/12/13, T-090/091."""

    def test_deep_junk_sweep_installs_active_guard(self):
        """T-091: Deep C must switch the ACTIVE guard to C:\\ so candidates are
        not rejected against a stale AppData target root."""
        tmp = tempfile.TemporaryDirectory()
        try:
            root = Path(tmp.name)
            loc = root / "LocalAppData"
            (loc / "GitHub CLI").mkdir(parents=True)
            cleaner = vac.SystemCleaner(False, vac.Logger(log_file=None, dry_run=False))
            prior = root / "NarrowStaleApp"
            prior.mkdir()
            cleaner.guard = vac.SafetyGuard(prior, is_system_root=True)  # stale guard
            with patch.dict(os.environ, {"LOCALAPPDATA": str(loc), "APPDATA": str(root / "Roaming")}):
                cleaner._deep_junk_sweep()
            # The sweep must install C:\ as the ACTIVE guard (not keep a local guard).
            self.assertEqual(cleaner.guard.base_root, Path("C:\\").resolve())
            # A candidate under C:\ is now valid under the active guard: it must
            # NOT be rejected as "Outside TARGET ROOT" the way the stale narrow
            # guard rejected Yandex/GitHub-CLI candidates in the runtime log.
            candidate = Path(os.environ.get("windir", r"C:\Windows")) / "Temp" / "x.tmp"
            ok, reason = cleaner.guard.is_safe(candidate)
            self.assertTrue(ok, reason)
            # Regression against the runtime failure mode: a C:\-rooted candidate
            # that sits outside the STALE guard's root must not be blocked.
            self.assertNotIn("Outside TARGET ROOT", reason)
        finally:
            tmp.cleanup()

    def test_deep_junk_sweep_guard_respects_exclusions(self):
        """T-091: the installed C:\\ guard keeps the engine exclusions."""
        cleaner = vac.SystemCleaner(True, vac.Logger(log_file=None, dry_run=True),
                                    exclude_patterns=["*.secret"])
        cleaner._deep_junk_sweep()
        self.assertEqual(cleaner.guard.base_root, Path("C:\\").resolve())
        self.assertIn("*.secret", cleaner.guard.exclude_patterns)

    def test_deep_junk_no_generic_bak_deletion(self):
        """T-099: *.bak rollback artifacts must NOT be auto-deleted."""
        tmp = tempfile.TemporaryDirectory()
        try:
            root = Path(tmp.name)
            loc = root / "LocalAppData"
            (loc / "Yandex" / "Yandex.Disk.2").mkdir(parents=True)
            bak = loc / "Yandex" / "Yandex.Disk.2" / "settings.bak"
            bak.write_text("rollback")
            (loc / "AnthropicClaude").mkdir()
            asar = loc / "AnthropicClaude" / "app.asar.bak"
            asar.write_text("rollback")
            roaming = root / "Roaming"
            (roaming / "FastPrompter").mkdir(parents=True)
            fbak = roaming / "FastPrompter" / "conf.bak"
            fbak.write_text("rollback")
            cleaner = vac.SystemCleaner(False, vac.Logger(log_file=None, dry_run=False))
            with patch.dict(os.environ, {"LOCALAPPDATA": str(loc), "APPDATA": str(roaming)}):
                cleaner._deep_junk_sweep()
            self.assertTrue(bak.exists(), "Yandex.Disk *.bak must survive (T-099)")
            self.assertTrue(asar.exists(), "Claude app.asar.bak must survive (T-099)")
            self.assertTrue(fbak.exists(), "FastPrompter *.bak must survive (T-099)")
        finally:
            tmp.cleanup()

    def _engine(self, root, exclusions=()):
        log = vac.Logger(log_file=None, dry_run=False)
        cleaner = vac.CleanerEngine(False, log, vac.SafetyGuard(root, is_system_root=True), root,
                                    vac.DEFAULT_THREADS, None,
                                    exclude_patterns=[exclusions[0]] if exclusions else None,
                                    exclude_paths=[exclusions[1]] if len(exclusions) > 1 else None)
        return cleaner, log

    def test_exclusions_inherited_by_engine_guard(self):
        """P0-3: engine exclusions reach the guard the engine actually uses."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pattern = "*.secret"
            cleaner, _ = self._engine(root, (pattern,))
            self.assertIn(pattern, cleaner.guard.exclude_patterns)

    def test_system_cleaner_guards_carry_exclusions(self):
        """P0-3: SystemCleaner's per-target guards inherit exclusions."""
        with tempfile.TemporaryDirectory() as tmp:
            excl_path = Path(tmp) / "keep"
            excl_path.mkdir()
            cleaner = vac.SystemCleaner(True, vac.Logger(log_file=None, dry_run=True),
                                        exclude_patterns=["*.tmp"], exclude_paths=[str(excl_path)])
            cleaner._set_guard(Path(tmp))
            ok, _ = cleaner.guard.is_safe(excl_path / "x.bin")
            self.assertFalse(ok)
            ok2, _ = cleaner.guard.is_safe(Path(tmp) / "other" / "f.tmp")
            self.assertFalse(ok2)

    def test_custom_cleaner_guards_carry_exclusions(self):
        """P0-3: CustomCleaner per-rule guards inherit exclusions."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            excl = root / "keep"
            excl.mkdir()
            rules = [{"path": str(root), "pattern": "*"}]
            cleaner = vac.CustomCleaner(True, vac.Logger(log_file=None, dry_run=True), rules,
                                        exclude_paths=[str(excl)])
            cleaner.run_all()
            self.assertTrue(excl.exists())
            self.assertIn(str(excl.resolve()), [str(p) for p in cleaner.guard.exclude_paths])

    def test_deep_junk_guard_carries_exclusions(self):
        """P0-3: _deep_junk_sweep guard inherits exclusions."""
        cleaner = vac.SystemCleaner(True, vac.Logger(log_file=None, dry_run=True),
                                    exclude_patterns=["*.secret"])
        guard = cleaner.make_guard(Path("C:\\"))
        self.assertIn("*.secret", guard.exclude_patterns)

    def test_excluded_descendant_two_levels_survives(self):
        """P0-4: excluded subtree 2+ levels deep survives a dir delete."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "app"
            keep = target / "sub" / "inner" / "keep"
            keep.mkdir(parents=True)
            (target / "junk.txt").write_text("x")
            cleaner, _ = self._engine(root, exclusions=("", str(keep)))
            freed = cleaner._del_dir(target, "app")
            self.assertTrue(keep.exists())
            self.assertTrue((target / "sub" / "inner").exists())
            self.assertFalse((target / "junk.txt").exists())
            self.assertGreater(freed, 0)

    def test_never_delete_nested_in_deletable_dir_survives(self):
        """P0-4: a never-delete file nested inside a deletable dir survives."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "app"
            (target / "deep" / "sub").mkdir(parents=True)
            (target / "deep" / "sub" / "Login Data").write_text("secrets")
            (target / "deep" / "junk.bin").write_bytes(b"x" * 100)
            cleaner, _ = self._engine(root)
            cleaner._del_dir(target, "app")
            self.assertTrue((target / "deep" / "sub" / "Login Data").exists())
            self.assertFalse((target / "deep" / "junk.bin").exists())

    def test_freefilesync_regression(self):
        """P0-1: sweeping the explicit Logs child never touches config/state files."""
        with tempfile.TemporaryDirectory() as tmp:
            ffs = Path(tmp)
            (ffs / "Logs").mkdir(parents=True)
            (ffs / "Logs" / "run_2026.log").write_text("log")
            (ffs / "GlobalSettings.xml").write_text("cfg")
            (ffs / "LastRun.ffs_real").write_text("state")
            targets = {k: False for k in vac.SYSTEM_TARGET_DEFAULTS}
            targets["FreeFileSync Logs"] = True
            with patch.object(vac, "USER_APPDATA_TARGETS", [(ffs / "Logs", "FreeFileSync Logs", "freefilesync")]), \
                 patch.object(vac, "get_running_processes", return_value=set()):
                cleaner = vac.SystemCleaner(False, vac.Logger(log_file=None, dry_run=False), targets=targets)
                cleaner.run_all()
            self.assertFalse((ffs / "Logs" / "run_2026.log").exists())
            self.assertTrue((ffs / "GlobalSettings.xml").exists())
            self.assertTrue((ffs / "LastRun.ffs_real").exists())

    def test_owner_running_skips_target(self):
        """P1-9: app-owned system target is skipped when the owner runs."""
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "Cache"
            target.mkdir()
            (target / "f.bin").write_bytes(b"x" * 10)
            targets = {k: False for k in vac.SYSTEM_TARGET_DEFAULTS}
            targets["Discord Cache"] = True
            with patch.object(vac, "USER_APPDATA_TARGETS", [(target, "Discord Cache", "discord")]), \
                 patch.object(vac, "get_running_processes", return_value={"discord.exe"}):
                cleaner = vac.SystemCleaner(False, vac.Logger(log_file=None, dry_run=False), targets=targets)
                cleaner.run_all()
            self.assertTrue(target.exists())

    def test_owner_unknown_skips_target(self):
        """P1-9: UNKNOWN process state skips app-owned targets (fail closed)."""
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "Cache"
            target.mkdir()
            (target / "f.bin").write_bytes(b"x" * 10)
            targets = {k: False for k in vac.SYSTEM_TARGET_DEFAULTS}
            targets["Discord Cache"] = True
            with patch.object(vac, "USER_APPDATA_TARGETS", [(target, "Discord Cache", "discord")]), \
                 patch.object(vac, "get_running_processes", return_value=None):
                cleaner = vac.SystemCleaner(False, vac.Logger(log_file=None, dry_run=False), targets=targets)
                cleaner.run_all()
            self.assertTrue(target.exists())

    def test_symlink_never_followed_or_deleted(self):
        """P1-11: symlinks are refused by the guard and the delete primitives."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            outside = Path(tmp) / "outside"
            outside.mkdir()
            (outside / "target.txt").write_text("data")
            link = root / "link"
            try:
                link.symlink_to(outside, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks not supported on this environment")
            guard = vac.SafetyGuard(root)
            ok, _ = guard.is_safe(link)
            self.assertFalse(ok)
            log = vac.Logger(log_file=None, dry_run=False)
            cleaner = vac.CleanerEngine(False, log, vac.SafetyGuard(root), root)
            self.assertEqual(cleaner._del_dir(link, "link"), 0)
            self.assertTrue(link.exists())
            self.assertTrue((outside / "target.txt").exists())

    @unittest.skipUnless(os.name == "nt", "Windows junction only")
    def test_junction_never_followed_or_deleted(self):
        """P1-11: junctions/reparse points are refused like symlinks."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            outside = Path(tmp) / "outside"
            outside.mkdir()
            (outside / "target.txt").write_text("data")
            junction = root / "junction"
            rc = os.system(f'mklink /J "{junction}" "{outside}"')
            if rc != 0:
                self.skipTest("mklink failed")
            guard = vac.SafetyGuard(root)
            ok, _ = guard.is_safe(junction)
            self.assertFalse(ok)
            self.assertTrue(vac.is_link(junction))
            log = vac.Logger(log_file=None, dry_run=False)
            cleaner = vac.CleanerEngine(False, log, vac.SafetyGuard(root), root)
            self.assertEqual(cleaner._del_dir(junction, "junction"), 0)
            self.assertTrue(junction.exists())
            self.assertTrue((outside / "target.txt").exists())

    def test_failed_delete_not_counted(self):
        """P1-12: a failed unlink inflates no counters and frees no bytes."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            f = root / "f.bin"
            f.write_bytes(b"x" * 500)
            log = vac.Logger(log_file=None, dry_run=False)
            cleaner = vac.CleanerEngine(False, log, vac.SafetyGuard(root), root)
            with patch.object(Path, "unlink", side_effect=PermissionError):
                freed = cleaner._del_file(f, "f")
            self.assertEqual(freed, 0)
            self.assertEqual(log.n_deleted, 0)
            self.assertEqual(log.bytes_freed, 0)
            self.assertTrue(f.exists())

    def test_del_dir_counts_only_after_delete(self):
        """P1-12: _del_dir with a failing unlink logs skipped, counts nothing."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "app"
            target.mkdir()
            (target / "a.bin").write_bytes(b"x" * 100)
            log = vac.Logger(log_file=None, dry_run=False)
            cleaner = vac.CleanerEngine(False, log, vac.SafetyGuard(root), root)
            with patch.object(Path, "unlink", side_effect=PermissionError):
                freed = cleaner._del_dir(target, "app")
            self.assertEqual(freed, 0)
            self.assertEqual(log.n_deleted, 0)
            self.assertEqual(log.bytes_freed, 0)
            self.assertTrue((target / "a.bin").exists())

    def test_cancel_stops_later_deletions(self):
        """P1-13: once cancelled, remaining candidates are never deleted."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "app"
            target.mkdir()
            for i in range(5):
                (target / f"f{i}.bin").write_bytes(b"x" * 10)
            log = vac.Logger(log_file=None, dry_run=False)
            cancel = threading.Event()
            cancel.set()
            cleaner = vac.CleanerEngine(False, log, vac.SafetyGuard(root), root, cancel_event=cancel)
            with self.assertRaises(vac.CancelJobException):
                cleaner._del_dir(target, "app")
            remaining = [p for p in target.iterdir()]
            self.assertEqual(len(remaining), 5)
            self.assertEqual(log.n_deleted, 0)

    def test_cancel_mid_dir_contents(self):
        """P1-13: _del_dir_contents raises on cancel before destructive work."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "app"
            target.mkdir()
            (target / "a.bin").write_bytes(b"x" * 10)
            log = vac.Logger(log_file=None, dry_run=False)
            cancel = threading.Event()
            cancel.set()
            cleaner = vac.CleanerEngine(False, log, vac.SafetyGuard(root, is_system_root=True), root, cancel_event=cancel)
            with self.assertRaises(vac.CancelJobException):
                cleaner._del_dir_contents(target, "app")
            self.assertTrue((target / "a.bin").exists())
            self.assertEqual(log.n_deleted, 0)

    def test_cancel_after_plan_before_apply_deletes_nothing(self):
        """T-094/D: cancellation between discovery and mutation must not
        leave a partially-deleted tree or bogus counters."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "app"
            (target / "deep").mkdir(parents=True)
            for i in range(3):
                (target / f"f{i}.bin").write_bytes(b"x" * 10)
            (target / "deep" / "g.bin").write_bytes(b"y" * 20)
            log = vac.Logger(log_file=None, dry_run=False)
            cancel = threading.Event()
            cleaner = vac.CleanerEngine(False, log, vac.SafetyGuard(root, is_system_root=True), root, cancel_event=cancel)
            plan = cleaner._plan_tree(target, "app")  # discovery done, cancel not yet set
            self.assertEqual(plan["bytes"], 50)
            cancel.set()  # cancel between plan and apply
            with self.assertRaises(vac.CancelJobException):
                cleaner._del_dir(target, "app")
            self.assertTrue((target / "f0.bin").exists())
            self.assertTrue((target / "deep" / "g.bin").exists())
            self.assertEqual(log.n_deleted, 0)
            self.assertEqual(log.bytes_freed, 0)


class TestAllowlistShrink(unittest.TestCase):
    """P0-5: browser allowlists must not contain account/security/session state."""

    def test_sw_database_removed(self):
        self.assertNotIn("Database", vac.CHROMIUM_SW_SUBDIRS)

    def test_profile_state_files_removed(self):
        for name in ["passkey_enclave_state", "trusted_vault.pb", "Affiliation Database",
                     "BrowsingTopicsState", "SharedStorage", "InterestGroups",
                     "DownloadMetadata", "PrivateAggregation"]:
            self.assertNotIn(name, vac.CHROMIUM_PROFILE_FILES, name)

    def test_userdata_state_dirs_removed(self):
        for name in ["Safe Browsing", "PKIMetadata", "OnDeviceHeadSuggestModel",
                     "OptimizationHints", "AutofillStates", "MEIPreload",
                     "CertificateRevocation", "Webstore Downloads"]:
            self.assertNotIn(name, vac.CHROMIUM_USERDATA_DIRS, name)

    def test_variations_removed(self):
        self.assertNotIn("Variations", vac.CHROMIUM_USERDATA_FILES)

    def test_brave_no_p3aconfig(self):
        src = Path(vac.__file__).read_text(encoding="utf-8")
        self.assertNotIn("P3AConfig", src)

    def test_firefox_session_state_protected_not_targeted(self):
        """P0-5: Firefox session/state dirs are protected names, not cleanup targets."""
        for name in ["sessionstore-backups", "security_state", "datareporting"]:
            self.assertIn(name, vac.NEVER_DELETE_NAMES, name)


class TestCLISemantics(unittest.TestCase):
    """P1-7 --all semantics, P2-14 --sys-targets validation, P0-3 CLI exclusions, T-067 argv."""

    def test_defaults_keep_risky_targets_off(self):
        self.assertFalse(vac.SYSTEM_TARGET_DEFAULTS["Recycle Bin"])
        self.assertFalse(vac.SYSTEM_TARGET_DEFAULTS["DNS Cache"])
        self.assertFalse(vac.SYSTEM_TARGET_DEFAULTS["Windows Update Cache"])
        self.assertTrue(vac.SYSTEM_TARGET_DEFAULTS["System Temp"])

    def test_dead_targets_removed(self):
        for name in ["Windows Prefetch", "Windows Logs", "Yarn Cache", "Battle.net Cache",
                     "Epic Games Cache", "Steam AppCache", "Steam DepotCache", "Steam Logs"]:
            self.assertNotIn(name, vac.SYSTEM_TARGET_DEFAULTS, name)

    @patch("_SMART_VAC_CLEANER.argparse.ArgumentParser.parse_args")
    def test_all_uses_safe_defaults(self, mock_parse):
        """P1-7: --all must NOT flip risky targets on."""
        mock_parse.return_value = MagicMock(
            dry_run=True, delete=False,
            portable=False, system=False, custom=False, all=True,
            cli=True, status=False, analyze_caches=False, hidden=False,
            sys_targets="", exclude="", install_task=False, time="09:00",
        )
        captured = {}
        def fake_job(dry_run, run_portable, run_system, run_custom, log, max_threads, sys_targets, cancel_event=None, exclude_patterns=None, exclude_paths=None, progress=None):
            captured["sys_targets"] = sys_targets
        with patch.object(vac, "run_cleaning_job", side_effect=fake_job), patch.object(vac, "Logger"):
            vac.main()
        self.assertFalse(captured["sys_targets"]["Recycle Bin"])
        self.assertFalse(captured["sys_targets"]["DNS Cache"])
        self.assertFalse(captured["sys_targets"]["Windows Update Cache"])

    @patch("_SMART_VAC_CLEANER.argparse.ArgumentParser.parse_args")
    def test_unknown_sys_target_errors(self, mock_parse):
        mock_parse.return_value = MagicMock(
            dry_run=True, delete=False,
            portable=False, system=False, custom=False, all=True,
            cli=True, status=False, analyze_caches=False, hidden=False,
            sys_targets="Nope,Recycle Bin", exclude="", install_task=False, time="09:00",
        )
        with patch.object(vac, "Logger"), self.assertRaises(SystemExit) as cm:
            vac.main()
        self.assertEqual(cm.exception.code, 2)

    @patch("_SMART_VAC_CLEANER.argparse.ArgumentParser.parse_args")
    def test_cli_merges_config_and_cli_excludes(self, mock_parse):
        """P0-3: CLI passes config.exclude_patterns PLUS --exclude additions."""
        mock_parse.return_value = MagicMock(
            dry_run=True, delete=False,
            portable=True, system=False, custom=False, all=False,
            cli=True, status=False, analyze_caches=False, hidden=False,
            sys_targets="", exclude="*.tmp", install_task=False, time="09:00",
        )
        captured = {}
        def fake_job(dry_run, run_portable, run_system, run_custom, log, max_threads, sys_targets, cancel_event=None, exclude_patterns=None, exclude_paths=None, progress=None):
            captured["patterns"] = exclude_patterns
            captured["paths"] = exclude_paths
        with patch.object(vac, "run_cleaning_job", side_effect=fake_job), \
             patch.object(vac, "Logger"), \
             patch.object(vac, "load_config", return_value={"portable_roots": [], "custom_rules": [],
                                                             "exclude_patterns": ["*.db"], "exclude_paths": ["D:\\Keep"]}):
            vac.main()
        self.assertIn("*.tmp", captured["patterns"])
        self.assertIn("*.db", captured["patterns"])
        self.assertIn("D:\\Keep", captured["paths"])

    def test_clean_argv_canonical(self):
        """T-067: one canonical argv builder drives background + scheduled."""
        argv = vac.background_clean_argv()
        self.assertEqual(argv, vac.clean_argv())
        cmd = vac.scheduled_task_command()
        for flag in ("--cli", "--all", "--delete", "--hidden"):
            self.assertIn(flag, cmd)
        # list2cmdline quoting round-trips back to the argv
        self.assertEqual(vac.subprocess.list2cmdline(argv), cmd)


class TestGuiThreadBoundary(unittest.TestCase):
    """T-093/094: worker/timer/tray threads never call Tk; shutdown waits for the worker."""

    class _Stub:
        def configure(self, *a, **k):
            return None

        def insert(self, *a, **k):
            return None

        def see(self, *a, **k):
            return None

        def set(self, *a, **k):
            return None

    @staticmethod
    def _fake_app(after_mode="record"):
        app = object.__new__(vac.App)
        app.log_queue = queue.Queue()
        app.cancel_event = threading.Event()
        app.sys_targets = dict(vac.SYSTEM_TARGET_DEFAULTS)
        app.config = {"exclude_patterns": [], "exclude_paths": [], "auto_clean_interval_hours": 0}
        app.progress = vac.ProgressTracker()
        app._clean_in_progress = False
        app._close_pending = False
        app._job_done_event = threading.Event()
        app._worker_thread = None
        app._clean_timer = None
        app.text_log = TestGuiThreadBoundary._Stub()
        app.dash_stats = TestGuiThreadBoundary._Stub()
        app.dash_bar = TestGuiThreadBoundary._Stub()
        app.dash_cat_container = TestGuiThreadBoundary._Stub()
        app.dash_cat_widgets = {}
        app.T = {"cancelled": "cancelled"}
        if after_mode == "boom":
            def boom(*a, **k):
                raise AssertionError("worker thread called Tk after()")
            app.after = boom
        else:
            app._after_calls = []
            def record(delay, fn):
                app._after_calls.append(fn)
                return len(app._after_calls)
            app.after = record
        app.quit = lambda: None
        app.destroy = lambda: None
        return app

    def test_worker_log_never_calls_after(self):
        app = self._fake_app(after_mode="boom")
        app._log("hello")  # must not touch Tk
        self.assertEqual(app.log_queue.get_nowait(), "hello")

    def test_run_job_worker_signals_event_only(self):
        app = self._fake_app(after_mode="boom")
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(vac, "BASE_DIR", Path(tmp)), \
             patch.object(vac, "run_cleaning_job", side_effect=vac.CancelJobException("stop")):
            try:
                app._run_job()
            finally:
                logger = logging.getLogger("vac_cleaner")
                for h in logger.handlers[:]:
                    try:
                        h.close()
                    except Exception:  # noqa: BLE001, S110 - best effort
                        pass
        self.assertTrue(app._job_done_event.is_set())
        self.assertEqual(app.log_queue.get_nowait(), "cancelled")

    def test_auto_clean_timer_only_enqueues(self):
        app = self._fake_app(after_mode="boom")
        app._clean_in_progress = False
        app._auto_clean_trigger()
        self.assertEqual(app.log_queue.get_nowait(), app._AUTO_CLEAN_MARKER)

    def test_close_pending_waits_for_worker(self):
        """T-094: destroy must not fire while a worker is still alive."""
        app = self._fake_app(after_mode="record")
        entered = threading.Event()
        release = threading.Event()

        def slow_worker():
            entered.set()
            release.wait(timeout=10)

        app._worker_thread = threading.Thread(target=slow_worker, daemon=True)
        app._worker_thread.start()
        entered.wait(timeout=5)
        app._close_pending = True
        app._poll_main()  # worker still alive -> no destroy, poller re-scheduled
        self.assertTrue(app._after_calls, "poller must reschedule while worker alive")
        app._after_calls.clear()
        release.set()
        app._worker_thread.join(timeout=10)
        app._poll_main()  # worker dead -> destroy fires, no reschedule
        self.assertFalse(app._after_calls, "poller must stop after destroy path")

    def test_full_exit_impl_refuses_live_worker(self):
        app = self._fake_app()
        entered = threading.Event()
        release = threading.Event()

        def slow_worker():
            entered.set()
            release.wait(timeout=10)

        app._worker_thread = threading.Thread(target=slow_worker, daemon=True)
        app._worker_thread.start()
        entered.wait(timeout=5)
        app._full_exit_impl()  # must refuse while alive
        self.assertTrue(app._worker_thread.is_alive())
        release.set()
        app._worker_thread.join(timeout=10)
        app._full_exit_impl()
        self.assertFalse(app._worker_thread.is_alive())


class TestWindowsUpdateTransaction(unittest.TestCase):
    """T-095: wuauserv stop/clean/restore is transaction-safe."""

    def _mock_run(self, calls, stop_rc=0):
        def fake_run(argv, *a, **k):
            calls.append(list(argv[:2]))
            if argv[0] == "net" and argv[1] == "stop":
                return MagicMock(returncode=stop_rc)
            if argv[0] == "net" and argv[1] == "start":
                return MagicMock(returncode=0)
            raise AssertionError(f"unexpected subprocess: {argv}")
        return fake_run

    def test_stop_failure_skips_deletion(self):
        c = vac.SystemCleaner(False, vac.Logger(log_file=None, dry_run=False))
        calls = []
        with patch.object(vac.subprocess, "run", side_effect=self._mock_run(calls, stop_rc=5)), \
             patch.object(c, "_service_state", return_value="RUNNING"), \
             patch.object(c, "_del_dir_contents", side_effect=AssertionError("must not delete")):
            freed = c._clean_windows_update_cache(Path("C:\\x"))
        self.assertEqual(freed, 0)

    def test_stop_unverified_skips_deletion(self):
        """Service still not stopped after 'net stop' => deletion skipped."""
        c = vac.SystemCleaner(False, vac.Logger(log_file=None, dry_run=False))
        calls = []
        with patch.object(vac.subprocess, "run", side_effect=self._mock_run(calls)), \
             patch.object(c, "_service_state", side_effect=["RUNNING", "RUNNING"]), \
             patch.object(c, "_del_dir_contents", side_effect=AssertionError("must not delete")):
            freed = c._clean_windows_update_cache(Path("C:\\x"))
        self.assertEqual(freed, 0)

    def test_cancellation_restores_service(self):
        c = vac.SystemCleaner(False, vac.Logger(log_file=None, dry_run=False))
        calls = []
        with patch.object(vac.subprocess, "run", side_effect=self._mock_run(calls)), \
             patch.object(c, "_service_state", side_effect=["RUNNING", "STOPPED"]), \
             patch.object(c, "_del_dir_contents", side_effect=vac.CancelJobException("x")), \
             self.assertRaises(vac.CancelJobException):
            c._clean_windows_update_cache(Path("C:\\x"))
        self.assertEqual([a[1] for a in calls], ["stop", "start"])

    def test_deletion_exception_restores_service(self):
        c = vac.SystemCleaner(False, vac.Logger(log_file=None, dry_run=False))
        calls = []
        with patch.object(vac.subprocess, "run", side_effect=self._mock_run(calls)), \
             patch.object(c, "_service_state", side_effect=["RUNNING", "STOPPED"]), \
             patch.object(c, "_del_dir_contents", side_effect=OSError("boom")), \
             self.assertRaises(OSError):
            c._clean_windows_update_cache(Path("C:\\x"))
        self.assertEqual([a[1] for a in calls], ["stop", "start"])

    def test_originally_stopped_never_started(self):
        c = vac.SystemCleaner(False, vac.Logger(log_file=None, dry_run=False))
        calls = []
        with patch.object(vac.subprocess, "run", side_effect=self._mock_run(calls)), \
             patch.object(c, "_service_state", return_value="STOPPED"), \
             patch.object(c, "_del_dir_contents", return_value=10):
            freed = c._clean_windows_update_cache(Path("C:\\x"))
        self.assertEqual(freed, 10)
        self.assertEqual(calls, [])

    def test_unknown_state_skips(self):
        c = vac.SystemCleaner(False, vac.Logger(log_file=None, dry_run=False))
        calls = []
        with patch.object(vac.subprocess, "run", side_effect=self._mock_run(calls)), \
             patch.object(c, "_service_state", return_value=None), \
             patch.object(c, "_del_dir_contents", side_effect=AssertionError("must not delete")):
            freed = c._clean_windows_update_cache(Path("C:\\x"))
        self.assertEqual(freed, 0)
        self.assertEqual(calls, [])

    def test_dry_run_zero_service_mutation(self):
        c = vac.SystemCleaner(True, vac.Logger(log_file=None, dry_run=True))
        targets = {k: False for k in vac.SYSTEM_TARGET_DEFAULTS}
        targets["Windows Update Cache"] = True
        c.targets = targets
        with patch.object(vac.subprocess, "run", side_effect=AssertionError("dry-run service mutation")), \
             patch.object(vac, "get_running_processes", return_value=set()):
            c.run_all()


class TestGuiSystemTargets(unittest.TestCase):
    """T-105: GUI opt-in for risky system targets via System Targets dialog."""

    def _app(self):
        return TestGuiThreadBoundary._fake_app(None)

    def test_gui_defaults_match_safe_defaults(self):
        """App starts with SYSTEM_TARGET_DEFAULTS: risky targets OFF."""
        app = self._app()
        self.assertEqual(app.sys_targets, vac.SYSTEM_TARGET_DEFAULTS)
        self.assertFalse(app.sys_targets["Recycle Bin"])
        self.assertFalse(app.sys_targets["DNS Cache"])
        self.assertFalse(app.sys_targets["Windows Update Cache"])

    def test_run_job_passes_gui_sys_targets(self):
        """Opt-in via dialog reaches run_cleaning_job unchanged."""
        app = self._app()
        app.sys_targets = dict(vac.SYSTEM_TARGET_DEFAULTS)
        app.sys_targets["Recycle Bin"] = True
        captured = {}
        def fake_job(dry_run, run_portable, run_system, run_custom, log, max_threads, sys_targets, cancel_event=None, exclude_patterns=None, exclude_paths=None, progress=None):
            captured["sys_targets"] = sys_targets
        with patch.object(vac, "run_cleaning_job", side_effect=fake_job), \
             patch.object(vac, "Logger"):
            app._run_job()
        self.assertTrue(captured["sys_targets"]["Recycle Bin"])
        self.assertFalse(captured["sys_targets"]["DNS Cache"])
        self.assertFalse(captured["sys_targets"]["Windows Update Cache"])

    def test_gui_defaults_never_auto_enable_risky(self):
        """A fresh GUI run passes only safe defaults, even with --all semantics."""
        app = self._app()
        captured = {}
        def fake_job(dry_run, run_portable, run_system, run_custom, log, max_threads, sys_targets, cancel_event=None, exclude_patterns=None, exclude_paths=None, progress=None):
            captured["sys_targets"] = sys_targets
        with patch.object(vac, "run_cleaning_job", side_effect=fake_job), \
             patch.object(vac, "Logger"):
            app._run_job()
        self.assertFalse(captured["sys_targets"]["Recycle Bin"])
        self.assertFalse(captured["sys_targets"]["DNS Cache"])
        self.assertFalse(captured["sys_targets"]["Windows Update Cache"])


class TestI18nSymmetry(unittest.TestCase):
    """i18n key-set guards (no fixture patching — reads real strings dir)."""

    def test_no_dead_default_strings(self):
        """Every DEFAULT_STRINGS key is referenced in source (no dead i18n)."""
        src = Path(vac.__file__).read_text(encoding="utf-8")
        refs = set(re.findall(r'self\.T\[["\'](\w+)["\']\]', src))
        dead = set(vac.DEFAULT_STRINGS) - refs
        self.assertEqual(dead, set())

    def test_locale_key_sets_match_default(self):
        """ru/et/ded carry exactly the DEFAULT_STRINGS key set (no drift)."""
        en = set(vac.DEFAULT_STRINGS)
        for lang in ("ru", "et", "ded"):
            path = vac.STRINGS_DIR / f"{lang}.json"
            d = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(set(d), en, lang)


if __name__ == "__main__":
    unittest.main()
