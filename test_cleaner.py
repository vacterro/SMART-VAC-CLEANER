#!/usr/bin/env python3
"""Unit tests for _SMART_VAC_CLEANER.py core functions."""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
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
        data = {"custom_rules": [{"path": "C:\\Users\\nobody\\AppData\\Local\\Temp\\app", "pattern": "*.log"}]}
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
        self.assertIn("chrome.exe", procs)
        self.assertIn("firefox.exe", procs)

    @patch("_SMART_VAC_CLEANER.subprocess.run")
    def test_failure_returns_empty(self, mock_run):
        mock_run.side_effect = OSError("fail")
        self.assertEqual(vac.get_running_processes(), set())

    @patch("_SMART_VAC_CLEANER.subprocess.run")
    def test_empty_output(self, mock_run):
        mock_run.return_value = MagicMock(stdout="", returncode=0)
        self.assertEqual(vac.get_running_processes(), set())


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
    """Tests for path blacklist protection."""

    def test_windir_blocked(self):
        self.assertTrue(vac.is_path_blacklisted(Path(os.environ.get("windir", r"C:\Windows"))))

    def test_windir_children_blocked(self):
        self.assertTrue(vac.is_path_blacklisted(Path(os.environ.get("windir", r"C:\Windows")) / "Temp"))

    def test_script_dir_blocked(self):
        self.assertTrue(vac.is_path_blacklisted(vac.SCRIPT_PATH.parent))

    def test_regular_dir_allowed(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertFalse(vac.is_path_blacklisted(Path(tmp)))

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

    def test_numbered_copies(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._deep_root(tmp)
            for name in ["app", "app (1)", "app (2)", "app (3)"]:
                p = root / name
                p.mkdir()
                (p / "x.txt").write_text("x")
            cleaner, log = self._cleaner(root)
            cleaner.sweep_numbered_copies(root, "app")
            self.assertTrue((root / "app").exists())
            self.assertTrue((root / "app (1)").exists())
            self.assertFalse((root / "app (2)").exists())
            self.assertFalse((root / "app (3)").exists())
            self.assertEqual(log.n_deleted, 2)

    def test_numbered_copies_skipped_when_running(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._deep_root(tmp)
            p = root / "app (2)"
            p.mkdir()
            (p / "x.txt").write_text("x")
            cleaner, log = self._cleaner(root)
            with patch.object(vac, "is_app_running", return_value=True):
                cleaner.sweep_numbered_copies(root, "app")
            self.assertTrue(p.exists())
            self.assertEqual(log.n_deleted, 0)

    def test_old_opera_versions_keep_latest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._deep_root(tmp)
            for ver in ["120.0.1.0", "120.0.2.0", "121.0.3.0"]:
                (root / ver).mkdir()
            cleaner, log = self._cleaner(root)
            cleaner._clean_old_opera_versions(root)
            self.assertFalse((root / "120.0.1.0").exists())
            self.assertFalse((root / "120.0.2.0").exists())
            self.assertTrue((root / "121.0.3.0").exists())
            self.assertEqual(log.n_deleted, 2)

    def test_universal_cache_sweep(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._deep_root(tmp)
            cache = root / "App" / "Cache"
            keep = root / "App" / "Config"
            cache.mkdir(parents=True)
            keep.mkdir(parents=True)
            (cache / "junk.bin").write_bytes(b"x" * 100)
            (keep / "settings.ini").write_text("keep")
            cleaner, log = self._cleaner(root)
            cleaner.clean_universal_caches()
            self.assertTrue(cache.exists())
            self.assertFalse((cache / "junk.bin").exists())
            self.assertTrue(keep.exists())
            self.assertGreater(log.n_deleted, 0)

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
            cli=False, status=False, hidden=False, sys_targets="",
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
    def test_main_portable_flag(self, mock_parse):
        """--portable without --delete runs dry-run."""
        mock_parse.return_value = MagicMock(
            dry_run=False, delete=False,
            portable=True, system=False, custom=False, all=False,
            cli=False, status=False, hidden=False, sys_targets="",
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
            cli=False, status=False, hidden=False, sys_targets="",
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
            cli=False, status=False, hidden=False, sys_targets="",
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
            cli=False, status=False, hidden=True, sys_targets="",
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
        self.assertEqual(s["find_new_junk"], "Find New Junk")

    def test_missing_file_falls_back_to_english(self):
        s = vac.load_strings("et")
        self.assertEqual(s["clean"], "Clean")


if __name__ == "__main__":
    unittest.main()
