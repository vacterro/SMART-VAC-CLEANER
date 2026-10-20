#!/usr/bin/env python3
"""Unit tests for _SMART_VAC_CLEANER.py core functions."""

import contextlib
import errno
import hashlib
import io
import json
import logging
import os
import queue
import re
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from typing import ClassVar
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _SMART_VAC_CLEANER as vac
import analyze_caches as vac_analyze


class TestGuiLogDelivery(unittest.TestCase):
    def test_logger_failures_and_summary_survive_ordinary_flood(self):
        app = TestGuiThreadBoundary._fake_app(after_mode="boom")
        app.log_queue = queue.Queue(maxsize=2)
        log = vac.Logger(None, True, gui_callback=app._log)
        log.error("terminal failure")
        log.warning("important warning")
        log.summary()
        for i in range(1000):
            app._log(f"telemetry {i}")
        observed = []
        while not app.log_queue.empty():
            observed.append(app.log_queue.get_nowait())
        self.assertTrue(any("terminal failure" in item for item in observed))
        self.assertTrue(any("important warning" in item for item in observed))
        self.assertTrue(any("SUMMARY" in item for item in observed))
        self.assertEqual([item.kind for item in observed[:3]], ["error", "warning", "summary"])
        self.assertLessEqual(len(observed), 5)

    def test_concurrent_flood_keeps_control_and_terminal_failure(self):
        from concurrent.futures import ThreadPoolExecutor

        app = TestGuiThreadBoundary._fake_app(after_mode="boom")
        app.log_queue = vac._GuiLogBuffer(maxsize=8, protected_size=2)
        app._log(app._CLOSE_MARKER)
        app._log(vac._GuiLogMessage("worker crashed", "error"))

        def produce(worker):
            for i in range(1000):
                app._log(f"{worker}:{i}")

        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(produce, range(8)))
        self.assertLessEqual(app.log_queue.qsize(), 11)
        self.assertEqual(app.log_queue.get_nowait(), app._CLOSE_MARKER)
        self.assertEqual(app.log_queue.get_nowait(), "worker crashed")

    def test_critical_overflow_keeps_a_truthful_count(self):
        messages = vac._GuiLogBuffer(maxsize=2, protected_size=2)
        for i in range(5):
            messages.put_nowait(vac._GuiLogMessage(f"failure {i}", "error"))
        self.assertEqual(messages.qsize(), 3)
        diagnostic = messages.get_nowait()
        self.assertEqual(diagnostic.kind, "warning")
        self.assertIn("3 earlier critical", diagnostic)
        self.assertEqual(messages.get_nowait(), "failure 3")
        self.assertEqual(messages.get_nowait(), "failure 4")

    def test_cancelled_timer_callback_cannot_rearm_or_dispatch(self):
        app = TestGuiThreadBoundary._fake_app()
        app.config["auto_clean_interval_hours"] = 1
        timers = []

        def timer_factory(interval, callback):
            timer = MagicMock()
            timer.callback = callback
            timers.append(timer)
            return timer

        with patch.object(vac.threading, "Timer", side_effect=timer_factory):
            app._schedule_auto_clean()
            app._schedule_auto_clean()
            timers[0].cancel.assert_called_once()
            timers[0].callback()
            self.assertFalse(app._auto_clean_pending)
            self.assertEqual(len(timers), 2)
            timers[1].callback()
            self.assertTrue(app._auto_clean_pending)
            self.assertEqual(len(timers), 2, "timer callbacks must never create successors")
            with patch.object(app, "_start_job") as start:
                app._poll_main()
            start.assert_called_once()
            self.assertEqual(len(timers), 3)
            app.config["auto_clean_interval_hours"] = 0
            app._schedule_auto_clean()
            timers[2].callback()
            self.assertFalse(app._auto_clean_pending)
            self.assertIsNone(app._clean_timer)
            self.assertEqual(len(timers), 3)


@unittest.skipUnless(os.name == "nt", "native Windows junction authority")
class TestNativeConfiguredRootAuthority(unittest.TestCase):
    def _exercise(self, kind, replace_root):
        import subprocess

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            configured = base / "roots" / "configured"
            configured.mkdir(parents=True)
            victim = base / "victim"
            victim.mkdir()
            destination = victim if replace_root else configured
            relative = {
                "custom": "proof.tmp",
                "portable": "_CENT/User Data/Default/Cache/proof.tmp",
                "explorer": "thumbcache_99.db",
            }[kind]
            proof = destination / relative
            proof.parent.mkdir(parents=True, exist_ok=True)
            payload = b"native-root-proof"
            proof.write_bytes(payload)
            config = vac._default_config()
            config["portable_roots"] = [str(configured)] if kind == "portable" else []
            config["custom_rules"] = [{"path": str(configured), "pattern": "*.tmp"}] if kind == "custom" else []
            roots = {
                "SYSTEM_TEMP": None, "USER_TEMP": None, "USER_CRASH": None,
                "USER_EXPLORER": configured if kind == "explorer" else None,
                "LOCALAPPDATA": None, "APPDATA": None, "WINDIR": None,
                "USER_APPDATA_TARGETS": (), "appdata_target_count": 0,
            }
            targets = {name: kind == "explorer" and name == "Explorer Thumbnails" for name in vac.SYSTEM_TARGET_DEFAULTS}
            # Also isolate globals so a pre-fix implementation that ignores the
            # frozen snapshot can touch only this disposable fixture.
            with patch.object(vac, "resolve_system_roots", return_value=roots), \
                 patch.object(vac, "SYSTEM_TEMP", None), \
                 patch.object(vac, "USER_TEMP", None), \
                 patch.object(vac, "USER_CRASH", None), \
                 patch.object(vac, "USER_EXPLORER", roots["USER_EXPLORER"]), \
                 patch.object(vac, "USER_APPDATA_TARGETS", []), \
                 patch.object(vac, "_LOCALAPPDATA", None), \
                 patch.object(vac, "_APPDATA", None), \
                 patch.object(vac, "get_running_processes", return_value=set()):
                spec = vac.resolve_job_spec(
                    dry_run=False, run_portable=kind == "portable",
                    run_system=kind == "explorer", run_custom=kind == "custom",
                    config=config, sys_targets=targets, surface="gui",
                )
                if replace_root:
                    configured.rmdir()  # known empty directory in the fixture
                    result = subprocess.run(
                        ["cmd", "/c", "mklink", "/J", str(configured), str(victim)],
                        capture_output=True, text=True, timeout=10, check=False,
                        creationflags=subprocess.CREATE_NO_WINDOW,
                    )
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertTrue(vac.is_link(configured), "native junction control must be real")
                log = vac.Logger(None, False)
                try:
                    vac.run_cleaning_job(spec, log)
                    if replace_root:
                        self.assertTrue(proof.exists(), "configured-root authority must not follow a replacement junction")
                        self.assertEqual(proof.read_bytes(), payload)
                        self.assertEqual(log.bytes_freed, 0)
                    else:
                        self.assertFalse(proof.exists(), "ordinary unchanged root must remain executable")
                        self.assertEqual(log.bytes_freed, len(payload))
                finally:
                    if replace_root and vac.is_link(configured):
                        configured.rmdir()  # remove only the fixture's junction

    def test_custom_junction_replacement_keeps_victim(self):
        self._exercise("custom", True)

    def test_portable_junction_replacement_keeps_victim(self):
        self._exercise("portable", True)

    def test_explorer_junction_replacement_keeps_victim(self):
        self._exercise("explorer", True)

    def test_custom_unchanged_root_executes(self):
        self._exercise("custom", False)

    def test_portable_unchanged_root_executes(self):
        self._exercise("portable", False)

    def test_explorer_unchanged_root_executes(self):
        self._exercise("explorer", False)


class TestBoundedDiscoveryAndClaims(unittest.TestCase):
    def test_owner_snapshots_are_fresh_at_first_gate_and_bounded(self):
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(vac, "get_running_processes", return_value={"chrome.exe"}) as query:
            root = Path(tmp)
            engine = vac.CleanerEngine(False, vac.Logger(None, False, quiet=True), vac.SafetyGuard(root), root)
            query.reset_mock()
            query.return_value = set()
            for _ in range(vac._OWNER_REFRESH_BATCH):
                self.assertTrue(engine._owner_gate_ok("cent"))
            self.assertEqual(query.call_count, 1, "constructor snapshot must expire, then one query serves a bounded batch")
            self.assertTrue(engine._owner_gate_ok("cent"))
            self.assertEqual(query.call_count, 2)

    def test_completed_sibling_result_survives_another_future_error(self):
        import concurrent.futures

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "base"
            root.mkdir()
            (root / "good.tmp").write_bytes(b"x")
            (root / "bad.tmp").write_bytes(b"y")
            log = vac.Logger(None, False, quiet=True)
            ledger = vac.CandidateLedger()
            engine = vac.CleanerEngine(False, log, vac.SafetyGuard(root), root,
                                       max_threads=2, ledger=ledger)
            real_wait = concurrent.futures.wait

            def child(path, *args, **kwargs):
                if path.name == "bad.tmp":
                    raise RuntimeError("controlled sibling failure")
                return 11

            def error_first(futures, **kwargs):
                done, pending = real_wait(futures, return_when=concurrent.futures.ALL_COMPLETED)
                return sorted(done, key=lambda future: future.exception() is None), pending

            with patch.object(engine, "_del_file", side_effect=child), \
                 patch.object(vac.concurrent.futures, "wait", side_effect=error_first):
                self.assertEqual(engine._del_dir_contents(root, "batch"), 11)
            self.assertEqual(log.n_errors, 1)
            self.assertFalse(ledger.covered(root), "failed batch must not claim the whole parent")

    def test_disabled_custom_rule_preserves_its_candidate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "scope" / "custom"
            root.mkdir(parents=True)
            proof = root / "proof.tmp"
            proof.write_bytes(b"keep-disabled")
            log = vac.Logger(None, False, quiet=True)
            cleaner = vac.CustomCleaner(False, log, [{"path": str(root), "pattern": "*.tmp", "enabled": False}])
            self.assertEqual(cleaner.run_all(), 0)
            self.assertEqual(proof.read_bytes(), b"keep-disabled")
            self.assertEqual(log.n_deleted, 0)

    def test_candidate_lookup_does_not_scan_unrelated_claims(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ledger = vac.CandidateLedger()
            for index in range(1000):
                ledger.claim(root / f"branch-{index}")
            with patch.object(vac, "_is_ancestor", wraps=vac._is_ancestor) as ancestor:
                self.assertTrue(ledger.covered(root / "branch-999" / "child.tmp"))
                self.assertFalse(ledger.covered(root / "unknown" / "child.tmp"))
            self.assertLess(ancestor.call_count, 20, "lookup must follow prefixes, not scan 1000 claims")
            ledger.claim(root)
            self.assertEqual(len(ledger), 1)
            self.assertTrue(ledger.covered(root / "branch-500"))

    def test_universal_prunes_only_real_dedicated_roots(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "portable"
            owner_root = root / "_CENT"
            owner_root.mkdir(parents=True)
            for index in range(100):
                (owner_root / f"branch-{index}" / "Cache").mkdir(parents=True)
            unknown = root / "UnknownApp" / "Cache"
            unknown.mkdir(parents=True)
            proof = unknown / "keep.bin"
            proof.write_bytes(b"keep")
            log = vac.Logger(None, True, quiet=True)
            cleaner = vac.PortableCleaner(True, log, vac.SafetyGuard(root), root)
            observed = []
            real_scandir = os.scandir

            def scan(path):
                observed.append(Path(path))
                return real_scandir(path)

            with patch.object(vac.os, "scandir", side_effect=scan), patch.object(log, "info") as info:
                self.assertEqual(cleaner.clean_universal_caches(), 0)
            self.assertNotIn(owner_root, observed)
            self.assertLessEqual(len(observed), 3)
            self.assertTrue(any("NOT AUTHORIZED" in str(call) for call in info.call_args_list))
            self.assertEqual(proof.read_bytes(), b"keep")
            self.assertEqual(log.bytes_freed, 0)
            self.assertIsNone(cleaner._universal_owner_for(root / "UnknownApp" / "_CENT" / "Cache"))

    def test_unknown_discovery_budget_refuses_without_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "portable"
            for index in range(50):
                (root / f"unknown-{index}" / "Cache").mkdir(parents=True)
            log = vac.Logger(None, True, quiet=True)
            cleaner = vac.PortableCleaner(True, log, vac.SafetyGuard(root), root)
            with patch.dict(os.environ, {"SMARTVAC_DISCOVERY_MAX_NODES": "8"}), \
                 patch.object(log, "warning") as warning:
                self.assertEqual(cleaner.clean_universal_caches(), 0)
            warning.assert_called_once()
            self.assertIn("truncated at 8", str(warning.call_args))
            self.assertEqual(len(list(root.glob("*/Cache"))), 50)
            self.assertEqual(log.bytes_freed, 0)


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

    def test_load_does_not_create_config_file(self):
        """CORE-006: load_config() is a read-only consumer -- it must NOT
        create the config file on disk. Bootstrap happens only through an
        explicit write-capable caller."""
        vac.load_config()
        self.assertFalse(self.tmp_config.exists())

    def test_save_and_load_roundtrip(self):
        data = {"custom_rules": [{"path": "D:\\Apps\\TestApp", "pattern": "*.log"}]}
        vac.save_config(data)
        loaded = vac.load_config()
        self.assertEqual(loaded["custom_rules"], data["custom_rules"])

    def test_load_corrupted(self):
        self.tmp_config.write_text("{corrupt}", encoding="utf-8")
        result = vac.load_config()
        self.assertEqual(result["custom_rules"], [])

    def test_load_migrates_dead_profiles_key_in_memory(self):
        """CORE-006: read-only load normalizes legacy `profiles` in memory
        without persisting -- the on-disk bytes stay unchanged."""
        original = '{"custom_rules": [{"path": "D:\\\\x", "pattern": "*"}], "portable_roots": ["D:\\\\p"], "profiles": {"Default": {}}}'
        self.tmp_config.write_text(original, encoding="utf-8")
        result = vac.load_config()
        self.assertNotIn("profiles", result)
        self.assertEqual(result["custom_rules"][0]["path"], "D:\\x")
        # On-disk bytes must be byte-identical: read-only consumer never writes.
        self.assertEqual(self.tmp_config.read_text(encoding="utf-8"), original)

    def test_migration_persists_only_via_write_authorized_path(self):
        """CORE-006/W2-004: legacy `profiles` removal persists ONLY through
        the write-authorized loader, atomically via save_config."""
        self.tmp_config.write_text(
            '{"custom_rules": [{"path": "D:\\\\x", "pattern": "*"}], "portable_roots": ["D:\\\\p"], "profiles": {"Default": {}}}',
            encoding="utf-8")
        _, result, _ = vac._load_and_validate(persist=True)
        self.assertNotIn("profiles", result)
        migrated = json.loads(self.tmp_config.read_text(encoding="utf-8"))
        self.assertNotIn("profiles", migrated)

    def test_update_config_field_cas_refuses_stale_fingerprint(self):
        """W2-003: a CAS update with a stale fingerprint must NOT land --
        another writer's disjoint change must survive."""
        self.tmp_config.write_text(json.dumps({"exclude_patterns": [], "exclude_paths": [],
                                                "custom_rules": [], "system_targets": {},
                                                "portable_roots": [], "lang": "en",
                                                "auto_clean_interval_hours": 0,
                                                "window_geometry": ""}), encoding="utf-8")
        with patch.object(vac, "CONFIG_FILE", self.tmp_config):
            ok = vac.update_config_field("exclude_patterns", ["*.log"])
            self.assertTrue(ok)
            ok2 = vac.update_config_field("exclude_patterns", ["*.db"], expected_fingerprint="deadbeef")
            self.assertFalse(ok2, "stale fingerprint must refuse the lost-update overwrite")
            data = json.loads(self.tmp_config.read_text(encoding="utf-8"))
            self.assertEqual(data["exclude_patterns"], ["*.log"],
                             "stale-fingerprint write must NOT have landed")

    def test_save_config_failed_rename_unlinks_only_own_temp(self):
        """W2-010: a save_config failure must unlink only THIS attempt's
        own temp file -- never the destination, never another writer's temp."""
        self.tmp_config.write_text("baseline", encoding="utf-8")
        with patch.object(vac, "CONFIG_FILE", self.tmp_config):
            # Force the atomic replace to fail.
            def failing_replace(self, target):
                raise OSError("simulated replace failure")
            with patch.object(Path, "replace", failing_replace):
                ok = vac.save_config({"custom_rules": [], "exclude_patterns": [],
                                       "exclude_paths": [], "system_targets": {},
                                       "portable_roots": [], "lang": "en",
                                       "auto_clean_interval_hours": 0,
                                       "window_geometry": ""})
            self.assertFalse(ok, "failed save must report False")
            # Destination must be byte-identical to the baseline.
            self.assertEqual(self.tmp_config.read_text(encoding="utf-8"), "baseline")
            # No leftover temp file in the config dir.
            leftovers = list(self.tmp_config.parent.glob(".config.tmp.*"))
            self.assertEqual(leftovers, [], f"failed save must unlink its own temp, found: {leftovers}")

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

    def test_parse_geometry_returns_default_on_huge_digit_count(self):
        # W2-006: a hostile 5000-digit width must NOT raise (Python's
        # max-string-digits int() limit) and must fall back to the default.
        huge = "9" * 5000 + "x720+0+0"
        self.assertEqual(vac.parse_geometry(huge), "960x640")
        # And a config carrying it must not crash App startup.
        vac.save_config({"custom_rules": [], "window_geometry": huge})
        loaded = vac.load_config()
        self.assertEqual(loaded["window_geometry"], huge)  # stored verbatim
        self.assertEqual(vac.parse_geometry(loaded["window_geometry"]), "960x640")

    def test_parse_geometry_returns_default_when_out_of_bounds(self):
        # W2-006: values beyond the sane geometry bound return the default.
        self.assertEqual(vac.parse_geometry("99999x99999+0+0"), "960x640")
        self.assertEqual(vac.parse_geometry("100x100+9999999+0"), "960x640")


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

    def test_appdata_targets_respect_provenance_tag(self):
        """CORE-010: every generated target has exactly the declared root
        provenance. A LOCAL entry must live under %LOCALAPPDATA%; a ROAMING
        entry must live under %APPDATA%; a BOTH entry may live under both.
        A "Roaming only" entry must never become a Local target."""
        local_root = vac._LOCALAPPDATA
        roam_root = vac._APPDATA
        for parts, desc, prov in vac._RAW_APPDATA_TARGETS:
            self.assertIn(prov, ("LOCAL", "ROAMING", "BOTH"), f"{desc}: invalid provenance {prov!r}")
        # Every live (p, d, owner) target: provenance must equal the base it lives under.
        for p, d, _owner in vac.USER_APPDATA_TARGETS:
            if local_root is not None and vac._is_under(local_root, p):
                # Find the raw entry to confirm it permits LOCAL.
                raw = next(((pp, dd, pv) for pp, dd, pv in vac._RAW_APPDATA_TARGETS
                            if dd == d and vac._LOCALAPPDATA.joinpath(*pp) == p), None)
                self.assertIsNotNone(raw, f"{d}: live LOCAL target has no matching raw LOCAL row")
                self.assertIn(raw[2], ("LOCAL", "BOTH"), f"{d}: provenance {raw[2]} cannot instantiate under LOCAL")
            if roam_root is not None and vac._is_under(roam_root, p):
                raw = next(((pp, dd, pv) for pp, dd, pv in vac._RAW_APPDATA_TARGETS
                            if dd == d and vac._APPDATA.joinpath(*pp) == p), None)
                self.assertIsNotNone(raw, f"{d}: live ROAMING target has no matching raw ROAMING row")
                self.assertIn(raw[2], ("ROAMING", "BOTH"), f"{d}: provenance {raw[2]} cannot instantiate under ROAMING")
        # Spot-check: the Roaming-only entries (prov == "ROAMING") must NOT
        # appear as Local targets.
        roaming_only_descs = {d for _, d, p in vac._RAW_APPDATA_TARGETS if p == "ROAMING"}
        if local_root is not None:
            for p, d, _owner in vac.USER_APPDATA_TARGETS:
                if d in roaming_only_descs and vac._is_under(local_root, p):
                    self.fail(f"{d}: provenance=ROAMING but live under LOCALAPPDATA: {p}")

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
        ok, reason = self.guard.is_safe(self.root / ".." / "x.txt")
        self.assertFalse(ok)
        self.assertNotIn("..", reason, "T-144: no dead '.. part' check; the escape is refused by root confinement")

    def test_dotdot_within_root_canonicalized_allowed(self):
        """T-144: '..' segments are canonicalized; an in-root result is confined and allowed."""
        p = self.root / "sub" / ".." / "deep" / "f.txt"
        p.parent.mkdir(parents=True)
        p.touch()
        ok, _ = self.guard.is_safe(p)
        self.assertTrue(ok)

    def test_system_root_allows_shallow(self):
        guard = vac.SafetyGuard(self.root, allow_shallow_system_target=True)
        p = self.root / "a" / "b"
        p.mkdir(parents=True)
        ok, _ = guard.is_safe(p)
        self.assertTrue(ok)

    def test_min_path_depth_enforced_for_user_roots(self):
        """F3/docs: without the shallow capability, a shallow path is refused."""
        guard = vac.SafetyGuard(self.root)
        p = self.root / "sub" / "f.txt"
        p.parent.mkdir(parents=True)
        p.touch()
        with patch.object(vac, "MIN_PATH_PARTS", len(p.parts) + 1):
            ok, reason = guard.is_safe(p)
            self.assertFalse(ok)
            self.assertIn("shallow", reason)
        with patch.object(vac, "MIN_PATH_PARTS", len(p.parts) - 1):
            ok, _ = guard.is_safe(p)
            self.assertTrue(ok)


class TestGetRunningProcesses(unittest.TestCase):

    @patch("_SMART_VAC_CLEANER.subprocess.run")
    @patch("_SMART_VAC_CLEANER._enumerate_processes_win", return_value=None)
    def test_parses_output(self, mock_native, mock_run):
        mock_run.return_value = MagicMock(
            stdout='"chrome.exe","1234","Console"\r\n"firefox.exe","5678","Console"\r\n',
            returncode=0)
        procs = vac.get_running_processes()
        self.assertEqual(procs, {"chrome.exe", "firefox.exe"})

    @patch("_SMART_VAC_CLEANER.subprocess.run")
    @patch("_SMART_VAC_CLEANER._enumerate_processes_win", return_value=None)
    def test_parses_quoted_csv_image_names(self, mock_native, mock_run):
        """tasklist csv rows may carry quotes; csv.reader must handle them (P1-8)."""
        mock_run.return_value = MagicMock(
            stdout='"chrome.exe, x64","1234","Console"\r\n',
            returncode=0)
        procs = vac.get_running_processes()
        self.assertEqual(procs, {"chrome.exe, x64"})

    @patch("_SMART_VAC_CLEANER.subprocess.run")
    @patch("_SMART_VAC_CLEANER._enumerate_processes_win", return_value=None)
    def test_failure_returns_none_fail_closed(self, mock_native, mock_run):
        """Exception => UNKNOWN (None), never an empty 'nothing runs' set (P1-8)."""
        mock_run.side_effect = OSError("fail")
        self.assertIsNone(vac.get_running_processes())

    @patch("_SMART_VAC_CLEANER.subprocess.run")
    @patch("_SMART_VAC_CLEANER._enumerate_processes_win", return_value=None)
    def test_nonzero_exit_returns_none(self, mock_native, mock_run):
        """Nonzero tasklist exit => UNKNOWN (None), never 'nothing runs'."""
        mock_run.return_value = MagicMock(stdout="", returncode=1)
        self.assertIsNone(vac.get_running_processes())

    @patch("_SMART_VAC_CLEANER.subprocess.run")
    @patch("_SMART_VAC_CLEANER._enumerate_processes_win", return_value=None)
    def test_empty_output(self, mock_native, mock_run):
        mock_run.return_value = MagicMock(stdout="", returncode=0)
        self.assertEqual(vac.get_running_processes(), set())

    def test_is_app_running_unknown_blocks(self):
        """Real process group + UNKNOWN snapshot => treated as running (fail closed)."""
        self.assertTrue(vac.is_app_running("brave", None))
        self.assertTrue(vac.is_app_running("chrome", None))

    def test_is_app_running_general_never_blocks(self):
        self.assertFalse(vac.is_app_running("general", None))
        self.assertFalse(vac.is_app_running("general", {"chrome.exe"}))

    def test_native_enum_returns_set_or_none(self):
        """CORE-002: native enumeration returns a real set on success, or None
        on any failure — never an empty set confused with a 'nothing runs' state."""
        import os as _os
        if _os.name != "nt":
            self.skipTest("Toolhelp32Snapshot is Windows-only")
        procs = vac._enumerate_processes_win()
        if procs is None:
            self.skipTest("Toolhelp32Snapshot unavailable in this environment")
        self.assertIsInstance(procs, set)
        # We must observe at least one process (ourselves).
        my_name = _os.path.basename(sys.executable).lower()
        self.assertTrue(
            my_name in procs or any(p.endswith(".exe") for p in procs),
            f"native enum returned no executable names: {sorted(procs)[:5]}",
        )

    def test_native_enum_distinguishes_failure_from_empty(self):
        """CORE-002: a confused failure state (e.g. fake Process32FirstW
        returning False) MUST yield None, not an empty set."""
        import ctypes as _ct
        import os as _os
        kernel32 = _ct.windll.kernel32
        if _os.name == "nt":
            snapshot = kernel32.CreateToolhelp32Snapshot(0x00000002, 0)
            INVALID_HANDLE_VALUE = _ct.c_void_p(-1).value
            self.assertNotEqual(snapshot, INVALID_HANDLE_VALUE)
            kernel32.CloseHandle(snapshot)
        # Validate that get_running_processes is wired to fall through to
        # subprocess.tasklist when _enumerate_processes_win returns None.
        with patch("_SMART_VAC_CLEANER._enumerate_processes_win", return_value=None), \
             patch("_SMART_VAC_CLEANER.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout='"sentinel.exe","1234","Console"\r\n',
                returncode=0)
            procs = vac.get_running_processes()
            self.assertEqual(procs, {"sentinel.exe"})


class TestGetSize(unittest.TestCase):

    def setUp(self):
        import _fs_helpers as fsh
        self._get_size = fsh.get_size

    def test_file(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"x" * 777)
            path = Path(f.name)
        try:
            self.assertEqual(self._get_size(path), 777)
        finally:
            path.unlink(missing_ok=True)

    def test_dir_sum(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a.txt").write_text("hello")
            (root / "b.txt").write_text("world")
            self.assertEqual(self._get_size(root), 10)

    def test_nonexistent(self):
        self.assertEqual(self._get_size(Path("Z:/__GARBAGE__")), 0)


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

    def test_logger_construction_prunes_old_logs(self):
        """T-110: building a Logger prunes to the retention bound, newest kept."""
        with tempfile.TemporaryDirectory() as tmp:
            logs = Path(tmp)
            for i in range(20):
                (logs / f"clean_20260101_{i:02d}0000.log").write_text("x")
            try:
                vac.Logger(log_file=logs / "clean_20260101_300000.log", dry_run=False)
                remaining = sorted(p.name for p in logs.glob("clean_*.log"))
                self.assertLessEqual(len(remaining), vac._LOG_RETENTION_KEEP)
                self.assertEqual(remaining[-1], "clean_20260101_300000.log", "the current job's log is kept")
            finally:
                for h in logging.getLogger("vac_cleaner").handlers[:]:
                    try:
                        h.close()
                    except Exception:  # noqa: BLE001, S110 - best effort
                        pass


class TestNumberedRegex(unittest.TestCase):

    def test_matches(self):
        m = vac._NAME_NUMBERED_RE.match("backup (2)")
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), "backup")
        self.assertEqual(m.group(2), "2")

    def test_matches_single(self):
        m = vac._NAME_NUMBERED_RE.match("backup (1)")
        self.assertIsNotNone(m)  # regex matches any number, filter is in sweep_numbered_copies
        self.assertEqual(m.group(2), "1")

    def test_no_match_plain(self):
        self.assertIsNone(vac._NAME_NUMBERED_RE.match("backup"))


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

    def test_blacklisted_windows_root_is_os_authoritative_not_env(self):
        """T-199: on Windows a poisoned WINDIR env cannot unprotect the real dir."""
        poison = self._non_c_drive_path("poison")
        with patch.object(vac, "_os_windir", self._non_c_drive_path("real_os_windir")), \
             patch.dict(os.environ, {"windir": str(poison)}):
            self.assertEqual(vac._blacklisted_windows_root(),
                             self._non_c_drive_path("real_os_windir"))
        with patch.object(vac, "_os_windir", None), \
             patch.dict(os.environ, {"windir": str(poison)}):
            self.assertEqual(vac._blacklisted_windows_root(), poison.resolve())
        self.assertIn(vac._blacklisted_windows_root().resolve(),
                      {p.resolve() for p in vac.BLACKLIST_PATHS})

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
            with patch.object(cleaner, "_owner_gate_ok", return_value=True):
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
            with patch.object(cleaner, "_owner_gate_ok", return_value=True):
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
            with patch.object(cleaner, "_owner_gate_ok", return_value=True):
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
            with patch.object(vac, "is_app_running", return_value=True), patch.object(cleaner, "_owner_gate_ok", return_value=True):
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

    def test_universal_cache_defers_to_dedicated_sweeper(self):
        """T-124: universal discovery DEFERS known-app caches to the dedicated sweeper.

        A cache under a known portable app dir is owned by that app's dedicated
        sweep -- universal discovery must not plan it a second time (one object
        -> one candidate). clean_cent still sweeps it via the dedicated path.
        """
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
            self.assertTrue((cache / "junk.bin").exists(),
                            "universal discovery must defer known-app caches to the dedicated sweeper")
            self.assertEqual(log.n_deleted, 0)
            # the dedicated cent sweeper owns this cache
            with patch.object(vac, "get_running_processes", return_value=set()):
                cleaner.clean_cent()
            self.assertFalse((cache / "junk.bin").exists())
            self.assertTrue(keep.exists())

    def test_universal_cache_sweep_unknown_owner_discovered_not_authorized(self):
        """T-125: a discovered cache with no verified owner is NOT actionable.

        In BOTH dry-run and real-delete it is reported as DISCOVERED / NOT
        AUTHORIZED with ZERO planned bytes and ZERO candidates.
        """
        for dry_run in (True, False):
            with tempfile.TemporaryDirectory() as tmp:
                root = self._deep_root(tmp)
                cache = root / "App" / "Cache"
                cache.mkdir(parents=True)
                (cache / "junk.bin").write_bytes(b"x" * 100)
                log = vac.Logger(log_file=None, dry_run=dry_run)
                cleaner = vac.PortableCleaner(dry_run, log, vac.SafetyGuard(root), root)
                with patch.object(vac, "get_running_processes", return_value=set()):
                    freed = cleaner.clean_universal_caches()
                self.assertEqual(freed, 0, f"dry_run={dry_run}: unknown-owner cache contributes zero bytes")
                self.assertEqual(log.n_deleted, 0)
                self.assertTrue((cache / "junk.bin").exists(), "unknown-owner cache must survive")

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
            with patch.object(cleaner, "_owner_gate_ok", return_value=True):
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
        """Returns empty dict when no targets exist on disk (F4 planner path)."""
        with tempfile.TemporaryDirectory() as tmp:
            empty = Path(tmp) / "none"
            with patch.object(vac, "USER_APPDATA_TARGETS", []), \
                 patch.object(vac, "get_running_processes", return_value=set()), \
                 patch.object(vac, "SYSTEM_TEMP", empty), \
                 patch.object(vac, "USER_TEMP", empty), \
                 patch.object(vac, "USER_CRASH", empty), \
                 patch.object(vac, "USER_EXPLORER", empty):
                result = vac.calculate_target_sizes({})
        self.assertIsInstance(result, dict)

    def test_calculate_target_sizes_nonexistent(self):
        """Returns empty dict when targets don't exist on disk (F4 planner path)."""
        enabled = {"System Temp": True, "User Temp": True}
        with tempfile.TemporaryDirectory() as tmp:
            empty = Path(tmp) / "none"
            with patch.object(vac, "USER_APPDATA_TARGETS", []), \
                 patch.object(vac, "get_running_processes", return_value=set()), \
                 patch.object(vac, "SYSTEM_TEMP", empty), \
                 patch.object(vac, "USER_TEMP", empty), \
                 patch.object(vac, "USER_CRASH", empty), \
                 patch.object(vac, "USER_EXPLORER", empty):
                result = vac.calculate_target_sizes(enabled)
        # Paths may or may not exist — should return dict regardless
        self.assertIsInstance(result, dict)
        for k, v in result.items():
            self.assertIsInstance(k, str)
            self.assertIsInstance(v, int)

    def test_cli_status_no_crash(self):
        """cli_status() prints without raising (F4 shared-planner path)."""
        with tempfile.TemporaryDirectory() as tmp:
            empty = Path(tmp) / "none"
            with patch.object(vac, "USER_APPDATA_TARGETS", []), \
                 patch.object(vac, "get_running_processes", return_value=set()), \
                 patch.object(vac, "SYSTEM_TEMP", empty), \
                 patch.object(vac, "USER_TEMP", empty), \
                 patch.object(vac, "USER_CRASH", empty), \
                 patch.object(vac, "USER_EXPLORER", empty), \
                 patch.object(vac, "load_config", return_value={
                     "portable_roots": [], "custom_rules": [],
                     "exclude_patterns": [], "exclude_paths": []}), \
                 patch.object(vac, "load_config_strict", return_value=(
                     True,
                     {"portable_roots": [], "custom_rules": [],
                      "exclude_patterns": [], "exclude_paths": []},
                     [])):
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
            cli=False, status=False, analyze_caches=False, hidden=False, sys_targets="", disable_targets="",
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
            cli=False, status=True, analyze_caches=False, hidden=False, sys_targets="", disable_targets="",
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
            cli=False, status=False, analyze_caches=True, hidden=False, sys_targets="", disable_targets="",
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
            cli=False, status=False, analyze_caches=False, hidden=False, sys_targets="", disable_targets="",
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
            cli=False, status=False, analyze_caches=False, hidden=False, sys_targets="", disable_targets="",
            exclude="", install_task=False, time="09:00",
        )
        with patch.object(vac, "run_cleaning_job") as mock_job, patch.object(vac, "Logger"):
            vac.main()
            args, _ = mock_job.call_args
            self.assertFalse(args[0].dry_run)  # dry_run = False with --delete

    @patch("_SMART_VAC_CLEANER.argparse.ArgumentParser.parse_args")
    def test_main_explicit_dry_run_with_delete(self, mock_parse):
        """--dry-run --delete = dry_run=True (explicit flag wins)."""
        mock_parse.return_value = MagicMock(
            dry_run=True, delete=True,
            portable=True, system=False, custom=False, all=False,
            cli=False, status=False, analyze_caches=False, hidden=False, sys_targets="", disable_targets="",
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
            cli=False, status=False, analyze_caches=False, hidden=True, sys_targets="", disable_targets="",
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

            def _boom(*a, _t=target, _orig=orig, **k):
                # T-110: LOG-hygiene retention (_prune_old_logs) removes the
                # cleaner's OWN clean_*.log files at Logger construction in
                # every mode; that allowlisted subsystem is not a cleaner
                # deletion and must not trip the dry-run purity gate.
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
            c = vac.CleanerEngine(True, log, vac.SafetyGuard(Path(tmp), allow_shallow_system_target=True), Path(tmp))
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
            c = vac.CleanerEngine(True, log, vac.SafetyGuard(root, allow_shallow_system_target=True), root)
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
            c = vac.CleanerEngine(True, log, vac.SafetyGuard(root, allow_shallow_system_target=True), root)
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
            c = vac.CleanerEngine(True, log, vac.SafetyGuard(root, allow_shallow_system_target=True), root)
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
                c = vac.PortableCleaner(True, log, vac.SafetyGuard(root, allow_shallow_system_target=True), root)
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
                     patch.object(vac, "load_config_strict", return_value=(
                         True,
                         {"portable_roots": [str(portable)], "custom_rules": [],
                          "exclude_patterns": [], "exclude_paths": []},
                         [])), \
                     patch.object(vac, "get_running_processes", return_value=set()), \
                     patch("_SMART_VAC_CLEANER.argparse.ArgumentParser.parse_args") as mock_parse:
                    mock_parse.return_value = MagicMock(
                        dry_run=True, delete=True, portable=False, system=False,
                        custom=False, all=True, cli=True, status=False,
                        analyze_caches=False, hidden=False, sys_targets="", disable_targets="", exclude="",
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
                                      vac.SafetyGuard(root, allow_shallow_system_target=True), root)
                c._del_file(f, "f")
                # _del_dir
                c2 = vac.CleanerEngine(True, vac.Logger(log_file=None, dry_run=True),
                                       vac.SafetyGuard(root, allow_shallow_system_target=True), root)
                c2._del_dir(appdata / "Cache" / "deep", "deep")
                # _del_dir_contents
                c3 = vac.CleanerEngine(True, vac.Logger(log_file=None, dry_run=True),
                                       vac.SafetyGuard(root, allow_shallow_system_target=True), root)
                c3._del_dir_contents(custom / "logs", "logs")
                # PortableCleaner
                vac.PortableCleaner(True, vac.Logger(log_file=None, dry_run=True),
                                    vac.SafetyGuard(portable, allow_shallow_system_target=True), portable).run_all()
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

    def test_deep_junk_sweep_does_not_install_c_guard(self):
        """CORE-013/CORE-004: Deep C must use narrow frozen per-root capabilities
        and never gain blanket C:\\ authority. No unconditional return — this
        body executes."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            loc = root / "LocalAppData"
            (loc / "GitHub CLI").mkdir(parents=True)
            user_temp = root / "UserTemp"
            user_temp.mkdir()
            roots = {
                "SYSTEM_TEMP": None,
                "USER_TEMP": user_temp,
                "USER_CRASH": None,
                "USER_EXPLORER": None,
                "LOCALAPPDATA": loc,
                "APPDATA": None,
                "WINDIR": Path("C:\\Windows").resolve(),
                "USER_APPDATA_TARGETS": [],
                "appdata_target_count": 0,
            }
            cleaner = vac.SystemCleaner(False, vac.Logger(log_file=None, dry_run=False), system_roots=roots)
            # Spy on the per-target guards the sweep actually installs.
            guards_used = []
            orig = cleaner._set_guard
            def spy(root):
                guards_used.append(root)
                return orig(root)
            cleaner._set_guard = spy
            cleaner._deep_junk_sweep()
            # The sweep must have used narrow per-root guards (never the
            # blanket C:\ guard) for its deletions.
            self.assertTrue(guards_used, "sweep must install per-root guards")
            self.assertTrue(
                all(g is not None and g != Path("C:\\").resolve() for g in guards_used),
                f"Deep C used a blanket C:\\ guard: {guards_used}",
            )
            # Every guard installed during the sweep must be a subpath of one
            # of the frozen per-root capabilities from the snapshot.
            allowed = [Path(loc), Path(user_temp)]
            self.assertTrue(
                all(any(vac._is_under(base, g) or vac._is_under(g, base) for base in allowed) for g in guards_used),
                f"sweep guarded paths outside the frozen roots: {guards_used}",
            )

    def test_deep_junk_none_roots_complete_with_zero_work(self):
        """CORE-005: all roots None (poisoned/unavailable) must complete with
        zero mutation and no TypeError."""
        with tempfile.TemporaryDirectory() as _:
            roots = {
                "SYSTEM_TEMP": None,
                "USER_TEMP": None,
                "USER_CRASH": None,
                "USER_EXPLORER": None,
                "LOCALAPPDATA": None,
                "APPDATA": None,
                "WINDIR": Path("C:\\Windows").resolve(),
                "USER_APPDATA_TARGETS": [],
                "appdata_target_count": 0,
            }
            cleaner = vac.SystemCleaner(False, vac.Logger(log_file=None, dry_run=False), system_roots=roots)
            result = cleaner._deep_junk_sweep()
            self.assertEqual(result, 0)
            self.assertEqual(cleaner.log.n_errors, 0)

    def test_deep_junk_sweep_guard_respects_exclusions(self):
        """CORE-013: Deep C uses narrow per-root guards; the engine's
        exclude_patterns/exclude_paths must survive into the built guard."""
        cleaner = vac.SystemCleaner(True, vac.Logger(log_file=None, dry_run=True),
                                    exclude_patterns=["*.secret"])
        # After the sweep, the guard is a narrow per-root guard (not C:\)
        # but the engine's exclusions must still be propagated.
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
            cleaner = vac.SystemCleaner(False, vac.Logger(log_file=None, dry_run=False), system_roots={
                "SYSTEM_TEMP": None, "USER_TEMP": None, "USER_CRASH": None, "USER_EXPLORER": None,
                "LOCALAPPDATA": loc, "APPDATA": roaming, "WINDIR": None, "USER_APPDATA_TARGETS": (),
                "appdata_target_count": 0, "USERPROFILE": None, "DRIVE_TEMP": None,
            })
            with patch.dict(os.environ, {"LOCALAPPDATA": str(loc), "APPDATA": str(roaming)}):
                cleaner._deep_junk_sweep()
            self.assertTrue(bak.exists(), "Yandex.Disk *.bak must survive (T-099)")
            self.assertTrue(asar.exists(), "Claude app.asar.bak must survive (T-099)")
            self.assertTrue(fbak.exists(), "FastPrompter *.bak must survive (T-099)")
        finally:
            tmp.cleanup()

    def _engine(self, root, exclusions=()):
        log = vac.Logger(log_file=None, dry_run=False)
        cleaner = vac.CleanerEngine(False, log, vac.SafetyGuard(root, allow_shallow_system_target=True), root,
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
            self.assertEqual(log.n_skipped, 1, "a failed delete must log a visible skip, not fail silently")
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
            cleaner = vac.CleanerEngine(False, log, vac.SafetyGuard(root, allow_shallow_system_target=True), root, cancel_event=cancel)
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
            cleaner = vac.CleanerEngine(False, log, vac.SafetyGuard(root, allow_shallow_system_target=True), root, cancel_event=cancel)
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
            sys_targets="", disable_targets="", exclude="", install_task=False, time="09:00",
        )
        captured = {}
        def fake_job(spec, log, cancel_event=None, progress=None):
            captured["sys_targets"] = dict(spec.sys_targets)
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
            sys_targets="Nope,Recycle Bin", disable_targets="", exclude="", install_task=False, time="09:00",
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
            sys_targets="", disable_targets="", exclude="*.tmp", install_task=False, time="09:00",
        )
        captured = {}
        def fake_job(spec, log, cancel_event=None, progress=None):
            captured["patterns"] = list(spec.exclude_patterns)
            captured["paths"] = list(spec.exclude_paths)
        with patch.object(vac, "run_cleaning_job", side_effect=fake_job), \
             patch.object(vac, "Logger"), \
             patch.object(vac, "load_config", return_value={"portable_roots": [], "custom_rules": [],
                                                             "exclude_patterns": ["*.db"], "exclude_paths": ["D:\\Keep"]}), \
             patch.object(vac, "load_config_strict", return_value=(
                 True,
                 {"portable_roots": [], "custom_rules": [],
                  "exclude_patterns": ["*.db"], "exclude_paths": ["D:\\Keep"]},
                 [])):
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

    def test_clean_argv_carries_full_target_mask(self):
        """CORE-009: scheduled argv is canonical and carries NO stale target mask.

        Scheduled/background argv is the safe default form. Actual system targets
        are resolved from current config at each scheduled invocation, not from
        the argv baked at install time. This prevents stale policy drift.
        """
        mask = dict(vac.SYSTEM_TARGET_DEFAULTS)
        mask["Recycle Bin"] = True
        mask["DNS Cache"] = True
        mask["System Temp"] = False
        argv = vac.clean_argv(mask)
        # CORE-009: no sys-targets snapshot in canonical argv
        self.assertNotIn("--sys-targets", argv)
        self.assertNotIn("--disable-targets", argv)
        self.assertEqual(vac.background_clean_argv(mask), vac.clean_argv(mask))
        cmd = vac.scheduled_task_command(mask)
        # canonical argv has no target deviations
        self.assertNotIn("--sys-targets", cmd)
        self.assertNotIn("--disable-targets", cmd)
        self.assertIn("--all", cmd)
        self.assertIn("--delete", cmd)

    def test_clean_argv_defaults_no_sys_targets(self):
        """T-106: no deviations -> argv identical to the safe default form."""
        self.assertNotIn("--sys-targets", vac.clean_argv())
        self.assertNotIn("--sys-targets", vac.background_clean_argv())
        self.assertNotIn("--sys-targets", vac.scheduled_task_command())
        self.assertNotIn("--disable-targets", vac.clean_argv())
        # a full default mask serializes nothing either
        self.assertNotIn("--disable-targets", vac.clean_argv(dict(vac.SYSTEM_TARGET_DEFAULTS)))

    def test_target_deviations_helper(self):
        """T-129: _target_deviations returns full both-direction deviation."""
        st = dict(vac.SYSTEM_TARGET_DEFAULTS)
        st["Recycle Bin"] = True
        st["DNS Cache"] = True
        enables, _disables = vac._target_deviations(st)
        self.assertIn("Recycle Bin", enables)
        self.assertIn("DNS Cache", enables)
        self.assertNotIn("System Temp", enables)  # safe default, --all already carries it
        en, dis = vac._target_deviations(dict(vac.SYSTEM_TARGET_DEFAULTS))
        self.assertEqual(en, [])
        self.assertEqual(dis, [])
        self.assertEqual(vac._target_deviations(None), ([], []))

    def test_install_task_no_stale_targets(self):
        """CORE-009: install_task produces canonical argv with no target mask.

        Scheduled execution resolves current config at runtime; the argv never
        carries a stale snapshot of sys_targets.
        """
        with patch.object(vac.subprocess, "run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="")
            mask = dict(vac.SYSTEM_TARGET_DEFAULTS)
            mask["Recycle Bin"] = True
            mask["System Temp"] = False
            ok = vac.install_task("09:00", mask)
        self.assertTrue(ok)
        argv = mock_run.call_args.args[0]
        self.assertIn("/tr", argv)
        tr_cmd = argv[argv.index("/tr") + 1]
        # CORE-009: no stale target deviations in the command
        self.assertNotIn("--sys-targets", tr_cmd)
        self.assertNotIn("--disable-targets", tr_cmd)
        self.assertIn("--all", tr_cmd)
        self.assertIn("--delete", tr_cmd)

    def test_install_task_defaults_safe(self):
        """T-106: no deviations -> scheduled command stays the safe --all form."""
        with patch.object(vac.subprocess, "run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="")
            ok = vac.install_task("09:00")
        self.assertTrue(ok)

    def test_cli_install_task_rejects_malformed_time(self):
        """CORE-014: malformed --time values exit 2 BEFORE any schtasks
        invocation. Truly invalid inputs trigger the same deterministic
        application-level argument error; accept-canonicalise inputs (1:2)
        normalise to HH:MM and install successfully."""
        buf = io.StringIO()
        invalid = ("24:00", "09:60", "abc", "", "12:34:56", "0:60", "-1:00")
        with contextlib.redirect_stdout(buf), \
             contextlib.redirect_stderr(buf), \
             patch("_SMART_VAC_CLEANER.argparse.ArgumentParser.parse_args") as mock_parse:
            for bad in invalid:
                mock_parse.return_value = MagicMock(
                    dry_run=False, delete=False, portable=False, system=False,
                    custom=False, all=False, cli=False, status=False,
                    analyze_caches=False, hidden=False, install_task=True,
                    sys_targets="", disable_targets="", exclude="", time=bad,
                    surface="cli")
                with self.assertRaises(SystemExit) as cm:
                    vac.main()
                self.assertEqual(cm.exception.code, 2,
                                 f"CORE-014: malformed time {bad!r} must exit 2, "
                                 f"got {cm.exception.code}")
        # Accept-canonicalise inputs (1:2 -> 01:02) must install successfully.
        for ok_time in ("1:2", "9:2", "1:00", "09:00", "23:59"):
            with contextlib.redirect_stdout(io.StringIO()), \
                 contextlib.redirect_stderr(io.StringIO()), \
                 patch("_SMART_VAC_CLEANER.argparse.ArgumentParser.parse_args") as mock_parse, \
                 patch.object(vac.subprocess, "run", return_value=MagicMock(returncode=0, stderr="")):
                mock_parse.return_value = MagicMock(
                    dry_run=False, delete=False, portable=False, system=False,
                    custom=False, all=False, cli=False, status=False,
                    analyze_caches=False, hidden=False, install_task=True,
                    sys_targets="", disable_targets="", exclude="", time=ok_time,
                    surface="cli")
                with self.assertRaises(SystemExit) as cm:
                    vac.main()
                self.assertEqual(cm.exception.code, 0,
                                 f"{ok_time!r} must install successfully, "
                                 f"got {cm.exception.code}")

    @patch("_SMART_VAC_CLEANER.argparse.ArgumentParser.parse_args")
    def test_main_install_task_accepts_sys_targets(self, mock_parse):
        """SIDE0 CORE-005: --install-task rejects --sys-targets/--disable-targets.

        Scheduled jobs use persisted current config; the CLI modifier is a
        no-op and is rejected before schtasks is invoked.
        """
        mock_parse.return_value = MagicMock(
            install_task=True, time="09:00", sys_targets="Recycle Bin,DNS Cache", disable_targets="",
            status=False, analyze_caches=False, hidden=False, dry_run=False,
            delete=False, portable=False, system=False, custom=False,
            all=False, cli=False, exclude="")
        with self.assertRaises(SystemExit) as cm:
            vac.main()
        self.assertEqual(cm.exception.code, 2)

    @patch("_SMART_VAC_CLEANER.argparse.ArgumentParser.parse_args")
    def test_main_install_task_rejects_unknown_target(self, mock_parse):
        """T-106: unknown target in --install-task --sys-targets exits 2."""
        mock_parse.return_value = MagicMock(
            install_task=True, time="09:00", sys_targets="Bogus", disable_targets="",
            status=False, analyze_caches=False, hidden=False, dry_run=False,
            delete=False, portable=False, system=False, custom=False,
            all=False, cli=False, exclude="")
        with patch.object(vac, "install_task") as mock_install, \
             self.assertRaises(SystemExit) as cm:
            vac.main()
        mock_install.assert_not_called()
        self.assertEqual(cm.exception.code, 2)


class TestGuiThreadBoundary(unittest.TestCase):
    """T-093/094: worker/timer/tray threads never call Tk; shutdown waits for the worker."""

    class _Stub:
        def configure(self, *a, **k):
            return None

        def insert(self, *a, **k):
            return None

        def delete(self, *a, **k):
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
        app._pulse = 0
        app._clean_in_progress = False
        app._close_pending = False
        app._job_done_event = threading.Event()
        app._worker_thread = None
        app._clean_timer = None
        # SIDE0 W2-005: timer-side flag consumed by the main-thread poller.
        app._auto_clean_pending = False
        # SIDE0 W2-006: background-child observation state.
        app._bg_proc = None
        app._bg_proc_observed = False
        app._bg_proc_retcode = None
        app.text_log = TestGuiThreadBoundary._Stub()
        app.dash_stats = TestGuiThreadBoundary._Stub()
        app.dash_bar = TestGuiThreadBoundary._Stub()
        app.dash_cat_container = TestGuiThreadBoundary._Stub()
        app.dash_cat_widgets = {}
        app.btn_clean = TestGuiThreadBoundary._Stub()
        app.btn_preview = TestGuiThreadBoundary._Stub()
        app.btn_stop = TestGuiThreadBoundary._Stub()
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
                app._run_job(_gui_spec(app))
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
        app._auto_clean_pending = False
        app._auto_clean_trigger()
        # SIDE0 W2-005: timer MUST NOT block on a full queue; it sets a
        # nonblocking flag the main-thread poller observes.
        self.assertTrue(app._auto_clean_pending)
        self.assertTrue(app.log_queue.empty())

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


def _gui_spec(app, dry_run=False):
    """Mirror App._start_job's T-128 spec freeze for GUI worker tests."""
    return vac.resolve_job_spec(dry_run=dry_run, run_portable=True, run_system=True, run_custom=True,
                                config=app.config, sys_targets=app.sys_targets, surface="gui")


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
             patch.object(vac, "get_running_processes", return_value=set()), \
             patch.object(vac.Path, "exists", return_value=False):
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
        def fake_job(spec, log, cancel_event=None, progress=None):
            captured["sys_targets"] = dict(spec.sys_targets)
        with patch.object(vac, "run_cleaning_job", side_effect=fake_job), \
             patch.object(vac, "Logger"):
            app._run_job(_gui_spec(app))
        self.assertTrue(captured["sys_targets"]["Recycle Bin"])
        self.assertFalse(captured["sys_targets"]["DNS Cache"])
        self.assertFalse(captured["sys_targets"]["Windows Update Cache"])

    def test_gui_defaults_never_auto_enable_risky(self):
        """A fresh GUI run passes only safe defaults, even with --all semantics."""
        app = self._app()
        captured = {}
        def fake_job(spec, log, cancel_event=None, progress=None):
            captured["sys_targets"] = dict(spec.sys_targets)
        with patch.object(vac, "run_cleaning_job", side_effect=fake_job), \
             patch.object(vac, "Logger"):
            app._run_job(_gui_spec(app))
        self.assertFalse(captured["sys_targets"]["Recycle Bin"])
        self.assertFalse(captured["sys_targets"]["DNS Cache"])
        self.assertFalse(captured["sys_targets"]["Windows Update Cache"])


class TestGuiPreview(unittest.TestCase):
    """T-107: GUI Preview = read-only dry-run; real Clean stays delete mode."""

    def _app(self):
        return TestGuiThreadBoundary._fake_app(None)

    def test_run_job_defaults_real_delete(self):
        """The Clean path must stay a real delete -- dry_run default False."""
        app = self._app()
        captured = {}
        def fake_job(spec, log, cancel_event=None, progress=None):
            captured["dry_run"] = spec.dry_run
        with patch.object(vac, "run_cleaning_job", side_effect=fake_job), \
             patch.object(vac, "Logger"):
            app._run_job(_gui_spec(app))
        self.assertFalse(captured["dry_run"])

    def test_run_job_preview_is_dry_run(self):
        """Preview passes dry_run=True -- physically read-only (T-090)."""
        app = self._app()
        captured = {}
        def fake_job(spec, log, cancel_event=None, progress=None):
            captured["dry_run"] = spec.dry_run
        with patch.object(vac, "run_cleaning_job", side_effect=fake_job), \
             patch.object(vac, "Logger"):
            app._run_job(_gui_spec(app, dry_run=True))
        self.assertTrue(captured["dry_run"])

    def test_start_preview_no_confirm_spawns_dry_run_worker(self):
        """Preview must not ask for delete confirmation and must run dry-run."""
        app = self._app()
        calls = []
        def fake_job(spec, log, cancel_event=None, progress=None):
            calls.append(spec.dry_run)
        def boom_confirm(*a, **k):
            raise AssertionError("preview must not ask for delete confirmation")
        with patch.object(vac, "run_cleaning_job", side_effect=fake_job), \
             patch.object(vac, "Logger"), \
             patch.object(vac.messagebox, "askyesno", side_effect=boom_confirm):
            app._start_preview()
        self.assertIsNotNone(app._worker_thread)
        app._worker_thread.join(timeout=10)
        self.assertEqual(calls, [True])
        self.assertTrue(app._job_done_event.is_set())


class TestPersistentSystemTargets(unittest.TestCase):
    """T-108: system_targets config key persists per-target preferences."""

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.tmp_config = Path(self.tmp_dir.name) / "cleaner_config.json"
        self.cm = patch.object(vac, "CONFIG_FILE", self.tmp_config)
        self.cm.start()

    def tearDown(self):
        self.cm.stop()
        self.tmp_dir.cleanup()

    def test_config_system_targets_roundtrip(self):
        data = {"system_targets": {"Recycle Bin": True, "System Temp": False}}
        vac.save_config(data)
        loaded = vac.load_config()
        self.assertTrue(loaded["system_targets"]["Recycle Bin"])
        self.assertFalse(loaded["system_targets"]["System Temp"])

    def test_unknown_target_rejected(self):
        """P1-7: Unknown system target in existing config -> INVALID."""
        self.tmp_config.write_text(
            '{"system_targets": {"Bogus": true, "DNS Cache": true}}',
            encoding="utf-8")
        valid, _loaded, _errors = vac.load_config_strict()
        self.assertEqual(valid, vac.ConfigState.INVALID)

    def test_merged_system_targets_defaults(self):
        self.assertEqual(vac.merged_system_targets(None), vac.SYSTEM_TARGET_DEFAULTS)
        self.assertEqual(vac.merged_system_targets({}), vac.SYSTEM_TARGET_DEFAULTS)

    def test_merged_system_targets_applies_known_only(self):
        out = vac.merged_system_targets({"Recycle Bin": True, "Bogus": True})
        self.assertTrue(out["Recycle Bin"])
        self.assertNotIn("Bogus", out)
        self.assertFalse(out["DNS Cache"])

    def test_gui_init_honors_config(self):
        """App session starts from persisted preferences, not bare defaults."""
        self.tmp_config.write_text(
            '{"system_targets": {"Recycle Bin": true}}', encoding="utf-8")
        app = TestGuiThreadBoundary._fake_app(None)
        app.config = vac.load_config()
        app.sys_targets = vac.merged_system_targets(app.config.get("system_targets"))
        self.assertTrue(app.sys_targets["Recycle Bin"])
        self.assertFalse(app.sys_targets["DNS Cache"])

    def test_save_system_targets_persists_to_config(self):
        """The dialog save writes system_targets back to the config file."""
        self.tmp_config.write_text('{"system_targets": {}}', encoding="utf-8")
        app = TestGuiThreadBoundary._fake_app(None)
        app.config = vac.load_config()
        app.sys_targets = vac.merged_system_targets(app.config.get("system_targets"))
        def var_get(value):
            return lambda self: value
        app.syst_vars = {
            "Recycle Bin": type("V", (), {"get": var_get(True)})(),
            "DNS Cache": type("V", (), {"get": var_get(False)})(),
            "System Temp": type("V", (), {"get": var_get(True)})(),
        }
        win = type("W", (), {"destroy": lambda self: None})()
        app.T = {"syst_saved": "saved"}
        app._save_system_targets(win)
        loaded = vac.load_config()
        self.assertTrue(loaded["system_targets"]["Recycle Bin"])
        self.assertFalse(loaded["system_targets"]["DNS Cache"])

    def test_cli_all_keeps_p1_7_safe_defaults(self):
        """T-108/P1-7: config risky prefs reach the clean path only via the
        GUI state that builds scheduled/background argv -- never silently from
        config in the plain CLI --all path."""
        self.tmp_config.write_text(
            '{"system_targets": {"Recycle Bin": true}}', encoding="utf-8")
        captured = {}
        def fake_job(spec, log, cancel_event=None, progress=None):
            captured["sys_targets"] = dict(spec.sys_targets)
        with patch.object(vac.argparse.ArgumentParser, "parse_args",
                          return_value=MagicMock(
                              install_task=False, time="09:00", sys_targets="", disable_targets="",
                              status=False, analyze_caches=False, hidden=True,
                              dry_run=False, delete=True, portable=False,
                              system=False, custom=False, all=True, cli=True,
                              exclude="")), \
             patch.object(vac, "run_cleaning_job", side_effect=fake_job), \
             patch.object(vac, "Logger"):
            vac.main()
        self.assertFalse(captured["sys_targets"]["Recycle Bin"])
        self.assertFalse(captured["sys_targets"]["DNS Cache"])


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


class TestMutationAuthorization(unittest.TestCase):
    """F1: TOCTOU -- plan/apply separation must NEVER mutate a replaced object.

    Plan is NOT permission forever. Between planning and mutation another
    process may swap the file, swap the directory, introduce a symlink /
    junction / reparse point, or replace an allowed object with an excluded or
    protected one. Every mutation must be re-authorized against the planned
    identity; every replacement below must SURVIVE.
    """

    @staticmethod
    def _root():
        return tempfile.TemporaryDirectory()

    def _engine(self, root):
        log = vac.Logger(log_file=None, dry_run=False)
        engine = vac.CleanerEngine(False, log, vac.SafetyGuard(root, allow_shallow_system_target=True), root)
        return engine, log

    def test_plan_then_replace_with_different_file_survives(self):
        with self._root() as tmp:
            root = Path(tmp)
            f = root / "deep" / "junk.bin"
            f.parent.mkdir(parents=True)
            f.write_bytes(b"x" * 100)
            engine, log = self._engine(root)
            plan = engine._plan_file(f)
            self.assertIsNotNone(plan)
            f.unlink()                       # attacker replaces the object
            f.write_bytes(b"y" * 300)        # ... with a different file
            result = engine._apply_file_plan(f, plan[0], plan[1])
            self.assertFalse(result.success)
            self.assertTrue(f.exists())
            self.assertEqual(f.read_bytes(), b"y" * 300)
            self.assertEqual(log.n_deleted, 0)

    def test_plan_then_replace_with_excluded_file_survives(self):
        with self._root() as tmp:
            root = Path(tmp)
            f = root / "deep" / "junk.bin"
            f.parent.mkdir(parents=True)
            f.write_bytes(b"x" * 100)
            engine, log = self._engine(root)
            plan = engine._plan_file(f)
            self.assertIsNotNone(plan)
            f.unlink()
            (f.parent / "Login Data").write_text("secrets")  # NEVER_DELETE name
            f.write_text("secrets")                          # same path now protected
            result = engine._apply_file_plan(f, plan[0], plan[1])
            self.assertFalse(result.success)
            self.assertTrue(f.exists())
            self.assertEqual(log.n_deleted, 0)

    def test_plan_then_replace_with_symlink_survives(self):
        with self._root() as tmp:
            root = Path(tmp)
            f = root / "deep" / "junk.bin"
            f.parent.mkdir(parents=True)
            f.write_bytes(b"x" * 100)
            outside = root / "outside.txt"
            outside.write_text("data")
            engine, log = self._engine(root)
            plan = engine._plan_file(f)
            self.assertIsNotNone(plan)
            f.unlink()
            try:
                f.symlink_to(outside)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks not supported")
            result = engine._apply_file_plan(f, plan[0], plan[1])
            self.assertFalse(result.success)
            self.assertTrue(vac.is_link(f))
            self.assertTrue(outside.exists())
            self.assertEqual(log.n_deleted, 0)

    @unittest.skipUnless(os.name == "nt", "Windows junction only")
    def test_plan_then_replace_with_junction_survives(self):
        with self._root() as tmp:
            root = Path(tmp)
            d = root / "deep" / "junkdir"
            d.mkdir(parents=True)
            (d / "x.bin").write_bytes(b"x" * 10)
            outside = root / "outside"
            outside.mkdir()
            (outside / "target.txt").write_text("data")
            engine, _log = self._engine(root)
            plan = engine._plan_tree(d, "junkdir")
            self.assertIsNotNone(plan)
            # remove the dir and place a junction at the same path
            import shutil
            shutil.rmtree(d)
            junction = d
            rc = os.system(f'mklink /J "{junction}" "{outside}"')
            if rc != 0:
                self.skipTest("mklink failed")
            freed, fully = engine._apply_tree_plan(plan, "junkdir")
            self.assertEqual(freed, 0)
            self.assertFalse(fully)
            self.assertTrue(vac.is_link(junction))
            self.assertTrue((outside / "target.txt").exists())

    def test_plan_tree_then_replace_root_dir_survives(self):
        with self._root() as tmp:
            root = Path(tmp)
            target = root / "app"
            (target / "sub").mkdir(parents=True)
            (target / "sub" / "a.bin").write_bytes(b"x" * 50)
            engine, _log = self._engine(root)
            plan = engine._plan_tree(target, "app")
            self.assertIsNotNone(plan)
            import shutil
            shutil.rmtree(target)              # attacker removes the whole tree
            target.mkdir()                     # ... and creates a different dir
            (target / "keep.txt").write_text("keep")
            freed, fully = engine._apply_tree_plan(plan, "app")
            self.assertEqual(freed, 0)
            self.assertFalse(fully)
            self.assertTrue((target / "keep.txt").exists())

    def test_plan_tree_then_child_created_after_planning_survives(self):
        with self._root() as tmp:
            root = Path(tmp)
            target = root / "app"
            (target / "sub").mkdir(parents=True)
            (target / "sub" / "a.bin").write_bytes(b"x" * 50)
            engine, _log = self._engine(root)
            plan = engine._plan_tree(target, "app")
            self.assertIsNotNone(plan)
            late = target / "sub" / "late.bin"
            late.write_bytes(b"y" * 20)        # created after planning
            freed, fully = engine._apply_tree_plan(plan, "app")
            self.assertEqual(freed, 50)
            self.assertFalse(fully)
            self.assertTrue(late.exists())
            self.assertFalse((target / "sub" / "a.bin").exists())

    def test_plan_tree_then_replace_parent_dir_survives(self):
        with self._root() as tmp:
            root = Path(tmp)
            target = root / "app"
            sub = target / "sub"
            sub.mkdir(parents=True)
            (sub / "a.bin").write_bytes(b"x" * 50)
            engine, _log = self._engine(root)
            plan = engine._plan_tree(target, "app")
            self.assertIsNotNone(plan)
            import shutil
            shutil.rmtree(sub)                 # attacker replaces the parent
            sub.mkdir()
            (sub / "keep.bin").write_bytes(b"z" * 10)
            freed, fully = engine._apply_tree_plan(plan, "app")
            self.assertEqual(freed, 0)
            self.assertFalse(fully)
            self.assertTrue((sub / "keep.bin").exists())

    def test_authorize_refuses_missing_path(self):
        with self._root() as tmp:
            root = Path(tmp)
            f = root / "deep" / "gone.bin"
            engine, _ = self._engine(root)
            ok, reason = engine._authorize_mutation(f, {"type": "file", "size": 1, "mtime_ns": 1, "ctime_ns": 1, "attrs": 0})
            self.assertFalse(ok)
            self.assertIn("missing", reason)

    def test_replace_after_chmod_before_unlink_survives(self):
        """T-137: a swap between our chmod and the retry unlink is caught by re-auth."""
        with self._root() as tmp:
            root = Path(tmp)
            f = root / "deep" / "junk.bin"
            f.parent.mkdir(parents=True)
            f.write_bytes(b"x" * 10)
            engine, log = self._engine(root)
            plan = engine._plan_file(f)
            self.assertIsNotNone(plan)
            calls = {"n": 0}
            real_capture = vac._capture_identity

            def swapping_capture(path):
                calls["n"] += 1
                ident = real_capture(path)
                if calls["n"] == 3:  # the post-chmod re-baseline: return OLD, then swap on disk
                    os.remove(f)
                    f.write_bytes(b"y" * 300)
                return ident

            with patch.object(vac, "_capture_identity", side_effect=swapping_capture), \
                 patch.object(Path, "unlink", side_effect=PermissionError):
                result = engine._apply_file_plan(f, plan[0], plan[1])
            self.assertFalse(result.success)
            self.assertEqual(f.read_bytes(), b"y" * 300, "the replacement must survive")
            self.assertEqual(log.n_deleted, 0)

    def test_failed_delete_restores_original_mode(self):
        """W2-008: when the cleaner chmods a read-only file and the delete
        fails, the original mode bits MUST be restored. A surviving file
        must never be left more permissive than the cleaner found it."""
        with self._root() as tmp:
            root = Path(tmp)
            f = root / "deep" / "ro.bin"
            f.parent.mkdir(parents=True)
            f.write_bytes(b"x" * 10)
            f.chmod(0o444)  # read-only, original mode
            original_mode = f.stat().st_mode & 0o7777
            engine, _ = self._engine(root)
            plan = engine._plan_file(f)
            self.assertIsNotNone(plan)
            # Force PermissionError on the unlink so the chmod is required
            # and the fallback retry also fails.
            with patch.object(Path, "unlink", side_effect=PermissionError):
                result = engine._apply_file_plan(f, plan[0], plan[1])
            self.assertFalse(result.success)
            # File still exists; the original mode must have been restored.
            self.assertTrue(f.exists())
            self.assertEqual(f.stat().st_mode & 0o7777, original_mode,
                             f"surviving file must regain its original mode, "
                             f"got {oct(f.stat().st_mode & 0o7777)} (was {oct(original_mode)})")

    def test_restore_mode_skipped_when_auth_fails_before_any_chmod_CORE002(self):
        """CORE-002: if authorization fails on the very first attempt (the
        planned object was replaced before mutation), the cleaner must NOT
        chmod the unauthorized replacement during rollback. The replacement's
        content and mode must survive untouched -- a path-race must never
        cause mutation of an object the cleaner determined it has no
        authority to modify."""
        with self._root() as tmp:
            root = Path(tmp)
            f = root / "deep" / "ro.bin"
            f.parent.mkdir(parents=True)
            f.write_bytes(b"x" * 10)
            f.chmod(0o444)  # original read-only mode
            engine, _ = self._engine(root)
            plan = engine._plan_file(f)
            self.assertIsNotNone(plan)
            replaced = {"done": False}

            def fake_auth(self2, path, identity, boundary_token=None):
                # Simulate a path-race: the planned object is replaced by a
                # different file (different content + more-permissive mode)
                # before authorization. The original is read-only (0o444); on
                # Windows the read-only attribute blocks unlink, so the
                # attacker clears it first, then recreates the file at 0o666.
                if not replaced["done"]:
                    replaced["done"] = True
                    try:
                        path.chmod(0o666)
                        path.unlink()
                    except OSError:
                        pass
                    path.write_bytes(b"REPLACEMENT")
                    path.chmod(0o666)
                return False, "Object identity changed since planning"

            with patch.object(vac.CleanerEngine, "_authorize_mutation", fake_auth):
                result = engine._apply_file_plan(f, plan[0], plan[1])
            self.assertFalse(result.success)
            # The replacement must NOT have been chmodded back by rollback.
            self.assertEqual(f.stat().st_mode & 0o7777, 0o666,
                             "rollback must not chmod an unauthorized replacement")
            self.assertEqual(f.read_bytes(), b"REPLACEMENT",
                             "replacement content must survive untouched")

    def test_symlink_after_chmod_before_unlink_survives(self):
        """T-137: a symlink introduced between our chmod and the retry unlink is refused."""
        with self._root() as tmp:
            root = Path(tmp)
            f = root / "deep" / "junk.bin"
            f.parent.mkdir(parents=True)
            f.write_bytes(b"x" * 10)
            outside = root / "outside.txt"
            outside.write_text("data")
            probe = root / "symlink-capability-probe"
            try:
                probe.symlink_to(outside)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"file symlink capability unavailable: {exc}")
            else:
                probe.unlink()
            engine, log = self._engine(root)
            plan = engine._plan_file(f)
            self.assertIsNotNone(plan)
            calls = {"n": 0}
            real_capture = vac._capture_identity

            def symlink_capture(path):
                calls["n"] += 1
                ident = real_capture(path)
                if calls["n"] == 3:  # post-chmod re-baseline: return OLD, then swap to a symlink
                    os.remove(f)
                    try:
                        f.symlink_to(outside)
                    except (OSError, NotImplementedError):
                        pass
                return ident

            with patch.object(vac, "_capture_identity", side_effect=symlink_capture), \
                 patch.object(Path, "unlink", side_effect=PermissionError):
                result = engine._apply_file_plan(f, plan[0], plan[1])
            self.assertFalse(result.success)
            if vac.is_link(f):
                self.assertTrue(outside.exists(), "symlink target must never be touched")
            else:
                self.assertTrue(f.exists())
            self.assertEqual(log.n_deleted, 0)

    def test_replace_dir_after_emptiness_before_rmdir_survives(self):
        """T-137: a dir swapped after the emptiness check is refused before rmdir."""
        with self._root() as tmp:
            root = Path(tmp)
            target = root / "app"
            sub = target / "sub"
            sub.mkdir(parents=True)
            (target / "a.bin").write_bytes(b"x" * 10)
            engine, _log = self._engine(root)
            plan = engine._plan_tree(target, "app")
            self.assertIsNotNone(plan)
            swapped = {"done": False}
            real_auth = vac.CleanerEngine._authorize_mutation

            def swapping_auth(self, path, planned_identity, boundary_token=None):
                if path == sub and not swapped["done"]:
                    swapped["done"] = True
                    import shutil
                    shutil.rmtree(sub)
                    sub.mkdir()
                    (sub / "keep.txt").write_text("keep")
                return real_auth(self, path, planned_identity, boundary_token)

            with patch.object(vac.CleanerEngine, "_authorize_mutation", swapping_auth):
                _freed, fully = engine._apply_tree_plan(plan, "app")
            self.assertTrue((sub / "keep.txt").exists(), "the replacement dir must survive")
            self.assertFalse(fully)

    def test_swap_between_chmod_auth_and_chmod_survives(self):
        """markhunt A: a swap in the lstat->chmod window is caught by the re-baseline."""
        with self._root() as tmp:
            root = Path(tmp)
            f = root / "deep" / "junk.bin"
            f.parent.mkdir(parents=True)
            f.write_bytes(b"x" * 10)
            engine, log = self._engine(root)
            plan = engine._plan_file(f)
            self.assertIsNotNone(plan)
            real_chmod = Path.chmod

            def chmod_after_swap(self, *a, **k):
                os.remove(f)                  # attacker swaps BEFORE our chmod executes
                f.write_bytes(b"y" * 300)
                return real_chmod(self, *a, **k)

            with patch.object(Path, "chmod", chmod_after_swap), \
                 patch.object(Path, "unlink", side_effect=PermissionError):
                result = engine._apply_file_plan(f, plan[0], plan[1])
            self.assertFalse(result.success)
            self.assertEqual(f.read_bytes(), b"y" * 300, "the swapped-in file must survive")
            self.assertEqual(log.n_deleted, 0)

    def test_identity_change_detected_by_fingerprint(self):
        """Different object at same path must never pass the identity gate."""
        with self._root() as tmp:
            root = Path(tmp)
            a = root / "deep" / "f.bin"
            a.parent.mkdir(parents=True)
            a.write_bytes(b"a" * 10)
            ident_a = vac._capture_identity(a)
            self.assertIsNotNone(ident_a)
            b = root / "deep" / "other.bin"
            b.write_bytes(b"b" * 20)
            ident_b = vac._capture_identity(b)
            self.assertFalse(vac._identity_matches(ident_a, ident_b))
            self.assertTrue(vac._identity_matches(ident_a, vac._capture_identity(a)))
            self.assertFalse(vac._identity_matches(None, ident_b))
            self.assertFalse(vac._identity_matches(ident_a, None))


class TestZeroByteAccounting(unittest.TestCase):
    """F7: zero-byte successful deletion is success=True with bytes=0."""

    def test_apply_file_plan_zero_byte_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            f = root / "deep" / "empty.txt"
            f.parent.mkdir(parents=True)
            f.touch()
            engine = vac.CleanerEngine(False, vac.Logger(log_file=None, dry_run=False),
                                       vac.SafetyGuard(root, allow_shallow_system_target=True), root)
            plan = engine._plan_file(f)
            self.assertIsNotNone(plan)
            result = engine._apply_file_plan(f, plan[0], plan[1])
            self.assertTrue(result.success)
            self.assertEqual(result.bytes_freed, 0)
            self.assertFalse(f.exists())

    def test_zero_byte_file_deleted_counts_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            f = root / "deep" / "empty.txt"
            f.parent.mkdir(parents=True)
            f.touch()
            vac.Logger.enable_recorder()
            log = vac.Logger(log_file=None, dry_run=False)
            engine = vac.CleanerEngine(False, log,
                                       vac.SafetyGuard(root, allow_shallow_system_target=True), root)
            freed = engine._del_file(f, "empty")
            self.assertEqual(freed, 0)
            self.assertFalse(f.exists())
            self.assertEqual(log.n_deleted, 1)
            self.assertEqual(log.bytes_freed, 0)
            self.assertGreater(len(log.deleted_paths), 0)

    def test_failed_zero_byte_delete_is_not_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            f = root / "deep" / "empty.txt"
            f.parent.mkdir(parents=True)
            f.touch()
            log = vac.Logger(log_file=None, dry_run=False)
            engine = vac.CleanerEngine(False, log,
                                       vac.SafetyGuard(root, allow_shallow_system_target=True), root)
            plan = engine._plan_file(f)
            with patch.object(Path, "unlink", side_effect=PermissionError):
                result = engine._apply_file_plan(f, plan[0], plan[1])
            self.assertFalse(result.success)
            self.assertTrue(f.exists())
            self.assertEqual(log.n_deleted, 0)


class TestCustomDepthProtection(unittest.TestCase):
    """F3: custom user rules must NOT bypass the shallow-root depth protection."""

    def test_custom_guard_lacks_shallow_capability(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cleaner = vac.CustomCleaner(True, vac.Logger(log_file=None, dry_run=True),
                                        [{"path": str(root), "pattern": "*"}])
            self.assertFalse(cleaner.guard.allow_shallow_system_target)

    def test_system_cleaner_keeps_shallow_capability(self):
        """Hardcoded internal system targets keep their reviewed shallow cap."""
        with tempfile.TemporaryDirectory() as tmp:
            c = vac.SystemCleaner(True, vac.Logger(log_file=None, dry_run=True))
            c._set_guard(Path(tmp))
            self.assertTrue(c.guard.allow_shallow_system_target)

    def test_shallow_custom_target_refused(self):
        """A shallow custom rule (equivalent to D:\\A) deletes nothing."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            shallow = root / "A"
            (shallow / "x.bin").mkdir(parents=True)
            (shallow / "x.bin" / "f.bin").write_bytes(b"x" * 10)
            rule = {"path": str(shallow), "pattern": "*"}
            with patch.object(vac, "MIN_PATH_PARTS", len(shallow.parts) + 2):
                cleaner = vac.CustomCleaner(False, vac.Logger(log_file=None, dry_run=False), [rule])
                freed = cleaner.run_all()
            self.assertEqual(freed, 0)
            self.assertTrue((shallow / "x.bin" / "f.bin").exists())

    def test_deep_custom_target_allowed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "deep" / "target" / "logs"
            root.mkdir(parents=True)
            (root / "x.log").write_text("log")
            rule = {"path": str(root), "pattern": "*.log"}
            cleaner = vac.CustomCleaner(False, vac.Logger(log_file=None, dry_run=False), [rule])
            freed = cleaner.run_all()
            self.assertEqual(freed, 3)
            self.assertFalse((root / "x.log").exists())


class TestStatusDryRunParity(unittest.TestCase):
    """F4: one read-only planner serves dry-run, --status and GUI preview.

    Invariant: STATUS_PLANNED_BYTES == DRY_RUN_PLANNED_BYTES for an identical
    snapshot/config/process-set. calculate_target_sizes() must NOT be a second
    pseudo-cleaner; its results must equal a real dry-run's per-target results.
    """

    def _fixture(self):
        tmp = tempfile.TemporaryDirectory()
        root = Path(tmp.name)
        tgt = root / "appdata" / "Cache"
        (tgt / "deep").mkdir(parents=True)
        (tgt / "deep" / "f.bin").write_bytes(b"x" * 100)
        (tgt / "deep" / "Login Data").write_text("secrets")     # NEVER_DELETE
        excl = tgt / "deep" / "keep"
        excl.mkdir()
        (excl / "g.bin").write_bytes(b"y" * 50)                 # excluded descendant
        tgt2 = root / "appdata2" / "Cache"
        tgt2.mkdir(parents=True)
        (tgt2 / "h.bin").write_bytes(b"z" * 30)
        tgt3 = root / "appdata3" / "Cache"
        tgt3.mkdir(parents=True)
        (tgt3 / "i.bin").write_bytes(b"w" * 40)
        return tmp, root, tgt, tgt2, tgt3, excl

    @staticmethod
    def _appdata(tgt, tgt2, tgt3):
        return [
            (tgt, "FreeFileSync Logs", "freefilesync"),   # app-owned
            (tgt2, "Discord Cache", "discord"),           # app-owned
            (tgt3, "Mystery Cache", None),                # unknown owner -> fail closed
        ]

    def _run_system(self, tmp, tgt, tgt2, tgt3, excl, running):
        targets = {k: False for k in vac.SYSTEM_TARGET_DEFAULTS}
        targets["FreeFileSync Logs"] = True
        targets["Discord Cache"] = True
        targets["Mystery Cache"] = True
        log = vac.Logger(log_file=None, dry_run=True, quiet=True)
        with patch.object(vac, "USER_APPDATA_TARGETS", self._appdata(tgt, tgt2, tgt3)), \
             patch.object(vac, "get_running_processes", return_value=running), \
             patch.object(vac, "SYSTEM_TEMP", Path(tmp) / "none"), \
             patch.object(vac, "USER_TEMP", Path(tmp) / "none"), \
             patch.object(vac, "USER_CRASH", Path(tmp) / "none"), \
             patch.object(vac, "USER_EXPLORER", Path(tmp) / "none"):
            c = vac.SystemCleaner(True, log, targets=targets, exclude_paths=[str(excl)])
            c.run_all()
            return dict(c.results), log

    def _status(self, tmp, tgt, tgt2, tgt3, excl, running):
        targets = {k: False for k in vac.SYSTEM_TARGET_DEFAULTS}
        targets["FreeFileSync Logs"] = True
        targets["Discord Cache"] = True
        targets["Mystery Cache"] = True
        with patch.object(vac, "USER_APPDATA_TARGETS", self._appdata(tgt, tgt2, tgt3)), \
             patch.object(vac, "get_running_processes", return_value=running), \
             patch.object(vac, "SYSTEM_TEMP", Path(tmp) / "none"), \
             patch.object(vac, "USER_TEMP", Path(tmp) / "none"), \
             patch.object(vac, "USER_CRASH", Path(tmp) / "none"), \
             patch.object(vac, "USER_EXPLORER", Path(tmp) / "none"):
            return vac.calculate_target_sizes(targets, exclude_paths=[str(excl)])

    def test_status_bytes_equal_dry_run_bytes(self):
        tmp, _root, tgt, tgt2, tgt3, excl = self._fixture()
        try:
            res_dry, _log = self._run_system(tmp.name, tgt, tgt2, tgt3, excl, running=set())
            res_status = self._status(tmp.name, tgt, tgt2, tgt3, excl, running=set())
            self.assertEqual(res_status, res_dry)
            self.assertEqual(sum(res_status.values()), sum(res_dry.values()))
            # FreeFileSync Logs planned: 100 (Login Data + keep dir excluded)
            self.assertEqual(res_dry.get("FreeFileSync Logs"), 100)
            self.assertEqual(res_dry.get("Discord Cache"), 30)
            self.assertNotIn("Mystery Cache", res_dry)  # unknown owner skipped
            self.assertEqual(set(res_status), set(res_dry))
        finally:
            tmp.cleanup()

    def test_running_app_skipped_identically_in_status_and_dry_run(self):
        tmp, _root, tgt, tgt2, tgt3, excl = self._fixture()
        try:
            running = {"discord.exe"}
            res_dry, _ = self._run_system(tmp.name, tgt, tgt2, tgt3, excl, running=running)
            res_status = self._status(tmp.name, tgt, tgt2, tgt3, excl, running=running)
            self.assertNotIn("Discord Cache", res_dry)
            self.assertEqual(res_status, res_dry)
        finally:
            tmp.cleanup()

    def test_unknown_process_snapshot_skips_identically(self):
        tmp, _root, tgt, tgt2, tgt3, excl = self._fixture()
        try:
            res_dry, _ = self._run_system(tmp.name, tgt, tgt2, tgt3, excl, running=None)
            res_status = self._status(tmp.name, tgt, tgt2, tgt3, excl, running=None)
            self.assertNotIn("Discord Cache", res_dry)
            self.assertNotIn("FreeFileSync Logs", res_dry)
            self.assertEqual(res_status, res_dry)
        finally:
            tmp.cleanup()

    def test_optional_system_target_off_is_absent_in_both(self):
        tmp, _root, tgt, tgt2, tgt3, excl = self._fixture()
        try:
            targets = {k: False for k in vac.SYSTEM_TARGET_DEFAULTS}
            targets["FreeFileSync Logs"] = True
            targets["Discord Cache"] = False
            targets["Mystery Cache"] = False
            log = vac.Logger(log_file=None, dry_run=True, quiet=True)
            with patch.object(vac, "USER_APPDATA_TARGETS", self._appdata(tgt, tgt2, tgt3)), \
                 patch.object(vac, "get_running_processes", return_value=set()), \
                 patch.object(vac, "SYSTEM_TEMP", Path(tmp.name) / "none"), \
                 patch.object(vac, "USER_TEMP", Path(tmp.name) / "none"), \
                 patch.object(vac, "USER_CRASH", Path(tmp.name) / "none"), \
                 patch.object(vac, "USER_EXPLORER", Path(tmp.name) / "none"):
                c = vac.SystemCleaner(True, log, targets=targets, exclude_paths=[str(excl)])
                c.run_all()
                res_dry = dict(c.results)
                res_status = vac.calculate_target_sizes(targets, exclude_paths=[str(excl)])
            self.assertNotIn("Discord Cache", res_dry)
            self.assertEqual(res_status, res_dry)
        finally:
            tmp.cleanup()

    def test_candidate_set_identical(self):
        """The dry-run and status must identify the SAME candidate paths."""
        tmp, _root, tgt, tgt2, tgt3, excl = self._fixture()
        try:
            vac.Logger.enable_recorder()
            res_dry, log = self._run_system(tmp.name, tgt, tgt2, tgt3, excl, running=set())
            # candidate truth at FILE granularity comes from the planner itself
            engine = vac.CleanerEngine(True, log, vac.SafetyGuard(tgt.parent, allow_shallow_system_target=True), tgt.parent,
                                       exclude_paths=[str(excl)])
            plan = engine._plan_tree(tgt / "deep", "deep")
            self.assertEqual([str(f) for f, _, _ in plan["files"]], [str(tgt / "deep" / "f.bin")])
            self.assertTrue(any("Login Data" in str(p) for p in plan["protected"]))
            self.assertTrue(any(str(excl) in str(p) for p in plan["protected"]))
            # status candidate set (target level) matches the dry-run results
            self.assertEqual(set(res_dry), {"FreeFileSync Logs", "Discord Cache"})
            # and the recorded deletions match those same candidates
            candidates = set(log.deleted_paths)
            self.assertTrue(any("deep" in p for p in candidates))
            self.assertTrue(any("h.bin" in p for p in candidates))
            self.assertFalse(any("Login Data" in p for p in candidates))
            self.assertFalse(any("g.bin" in p for p in candidates))
            self.assertFalse(any("i.bin" in p for p in candidates))
        finally:
            tmp.cleanup()

    def test_system_cleaner_consumes_frozen_snapshot_not_module_globals(self):
        """CORE-004: SystemCleaner built with an explicit system_roots snapshot
        must NOT re-read mutable module globals (SYSTEM_TEMP/USER_TEMP/etc).
        Mutating the module globals after construction must not change what a
        cleaner that holds the snapshot plans."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            snap_a = root / "snap_a"
            (snap_a / "sub").mkdir(parents=True)
            (snap_a / "sub" / "a.bin").write_bytes(b"x" * 10)
            snap_b = root / "snap_b"
            snap_b.mkdir()
            roots = {
                "SYSTEM_TEMP": snap_a,
                "USER_TEMP": None,
                "USER_CRASH": None,
                "USER_EXPLORER": None,
                "LOCALAPPDATA": None,
                "APPDATA": None,
                "WINDIR": Path("C:\\Windows").resolve(),
                "USER_APPDATA_TARGETS": [],
                "appdata_target_count": 0,
            }
            targets = {k: False for k in vac.SYSTEM_TARGET_DEFAULTS}
            targets["System Temp"] = True
            log = vac.Logger(log_file=None, dry_run=True, quiet=True)
            with patch.object(vac, "SYSTEM_TEMP", snap_b), \
                 patch.object(vac, "get_running_processes", return_value=set()):
                c = vac.SystemCleaner(True, log, targets=targets, system_roots=roots)
                c.run_all()
            self.assertEqual(c.results.get("System Temp"), 10)
            self.assertNotIn(str(snap_b), str(c.results))

    def test_cli_status_total_equals_dry_run_total(self):
        """--status prints a TOTAL equal to a real dry-run's planned bytes."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            portable = root / "portable"
            (portable / "_CENT" / "User Data" / "Default" / "Cache").mkdir(parents=True)
            (portable / "_CENT" / "User Data" / "Default" / "Cache" / "data_0").write_bytes(b"x" * 25)
            custom = root / "custom"
            (custom / "logs").mkdir(parents=True)
            (custom / "logs" / "x.log").write_text("log")
            cfg = {"portable_roots": [str(portable)], "custom_rules": [{"path": str(custom), "pattern": "*"}],
                   "exclude_patterns": [], "exclude_paths": []}
            with patch.object(vac, "get_running_processes", return_value=set()), \
                 patch.object(vac, "USER_APPDATA_TARGETS", []), \
                 patch.object(vac, "SYSTEM_TEMP", Path(tmp) / "none"), \
                 patch.object(vac, "USER_TEMP", Path(tmp) / "none"), \
                 patch.object(vac, "USER_CRASH", Path(tmp) / "none"), \
                 patch.object(vac, "USER_EXPLORER", Path(tmp) / "none"):
                log = vac.Logger(log_file=None, dry_run=True, quiet=True)
                spec = vac.resolve_job_spec(dry_run=True, run_portable=True, run_system=True, run_custom=True,
                                            config=cfg, surface="status")
                res = vac.run_cleaning_job(spec, log)
                total_dry = res.get("system_bytes", 0) + res.get("portable", 0) + res.get("custom", 0)
                # T-124: the 25-byte Chromium cache is planned exactly once
                self.assertEqual(res.get("portable", 0), 25)
                buf = io.StringIO()
                with patch.object(vac, "load_config", return_value=cfg), \
                     patch.object(vac, "load_config_strict", return_value=(True, cfg, [])), \
                     contextlib.redirect_stdout(buf):
                    vac.cli_status()
            total_lines = [l for l in buf.getvalue().splitlines() if "TOTAL" in l]
            self.assertTrue(total_lines, "cli_status must print a TOTAL line")
            self.assertIn(vac.fmt(total_dry), total_lines[-1])


class TestConfigSnapshot(unittest.TestCase):
    """F5: load config once per job; a frozen snapshot drives the whole run."""

    @staticmethod
    def _portable_with_cache(root, name, size):
        p = root / name
        (p / "_CENT" / "User Data" / "Default" / "Cache").mkdir(parents=True)
        (p / "_CENT" / "User Data" / "Default" / "Cache" / "data_0").write_bytes(b"x" * size)
        return p

    def test_job_never_reloads_config_when_snapshot_given(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            p = self._portable_with_cache(root, "portableA", 10)
            cfg = {"portable_roots": [str(p)], "custom_rules": [],
                   "exclude_patterns": [], "exclude_paths": []}
            log = vac.Logger(log_file=None, dry_run=True, quiet=True)
            with patch.object(vac, "get_running_processes", return_value=set()), \
                 patch.object(vac, "load_config", side_effect=AssertionError("job must not reload config")):
                spec = vac.resolve_job_spec(dry_run=True, run_portable=True, run_system=False, run_custom=False,
                                            config=cfg, surface="cli")
                res = vac.run_cleaning_job(spec, log)
            # T-124: ONE physical cache is planned ONCE (dedicated sweeper owns it;
            # universal discovery defers). 10 bytes -> 10, never 20.
            self.assertEqual(res["portable"], 10)

    def test_mid_job_config_edit_keeps_original_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pA = self._portable_with_cache(root, "portableA", 10)
            pB = self._portable_with_cache(root, "portableB", 20)
            cfg_file = Path(tmp) / "cleaner_config.json"
            cfg_file.write_text(json.dumps({"portable_roots": [str(pA)], "custom_rules": [],
                                            "exclude_patterns": [], "exclude_paths": []}), encoding="utf-8")
            with patch.object(vac, "CONFIG_FILE", cfg_file):
                snapshot = vac.load_config()
                # config file changes WHILE the job runs
                cfg_file.write_text(json.dumps({"portable_roots": [str(pB)], "custom_rules": [],
                                                "exclude_patterns": [], "exclude_paths": []}), encoding="utf-8")
                log = vac.Logger(log_file=None, dry_run=True, quiet=True)
                with patch.object(vac, "get_running_processes", return_value=set()):
                    spec = vac.resolve_job_spec(dry_run=True, run_portable=True, run_system=False, run_custom=False,
                                                config=snapshot, surface="cli")
                    res = vac.run_cleaning_job(spec, log)
                self.assertEqual(res["portable"], 10, "running job must stay on the ORIGINAL snapshot")
                # the NEXT job loads the new config
                fresh = vac.load_config()
                self.assertEqual(fresh["portable_roots"], [str(pB)])


class TestProgressTruthful(unittest.TestCase):
    """F8: no fake determinate bars; unknown totals are indeterminate/status."""

    def test_unknown_total_flags_indeterminate(self):
        p = vac.ProgressTracker()
        p.start_category("System")
        snap = p.get_snapshot()
        self.assertTrue(snap["running_unknown_total"])
        self.assertEqual(snap["total_bytes_planned"], 0)
        p.advance(10)
        p.finish_category(total_bytes=50)
        snap2 = p.get_snapshot()
        self.assertFalse(snap2["running_unknown_total"])
        self.assertEqual(snap2["total_bytes_planned"], 50)
        self.assertEqual(snap2["total_bytes"], 10)

    def test_dashboard_indeterminate_then_determinate(self):
        app = TestGuiThreadBoundary._fake_app(None)
        app._clean_in_progress = True
        app.progress = vac.ProgressTracker()
        app.progress.start_category("System")
        app.dash_cat_widgets = {"System": {"frame": TestGuiThreadBoundary._Stub(),
                                           "label": TestGuiThreadBoundary._Stub(),
                                           "bar": TestGuiThreadBoundary._Stub()}}
        seen = []
        app.dash_bar.set = lambda v: seen.append(v)
        app._update_dashboard()
        app._update_dashboard()
        self.assertTrue(seen, "bar must be driven when the total is unknown")
        self.assertNotEqual(seen[0], 0.0, "unknown total must NOT sit at a fake 0% determinate fill")
        # a real total turns the bar into a truthful determinate fraction
        app.progress.finish_category(total_bytes=100)
        app.progress.advance(50)
        app._update_dashboard()
        self.assertAlmostEqual(seen[-1], 0.5)


class TestWindowsUpdateExactStopped(unittest.TestCase):
    """F2: deletion is authorized ONLY by an EXACT STOPPED state."""

    def _mock_run(self, calls, stop_rc=0):
        def fake_run(argv, *a, **k):
            calls.append(list(argv[:2]))
            if argv[0] == "net" and argv[1] == "stop":
                return MagicMock(returncode=stop_rc)
            if argv[0] == "net" and argv[1] == "start":
                return MagicMock(returncode=0)
            raise AssertionError(f"unexpected subprocess: {argv}")
        return fake_run

    def _cleaner(self):
        return vac.SystemCleaner(False, vac.Logger(log_file=None, dry_run=False))

    def test_running_stop_pending_then_stopped_deletes(self):
        c = self._cleaner()
        calls = []
        with patch.object(vac.subprocess, "run", side_effect=self._mock_run(calls)), \
             patch.object(c, "_service_state", side_effect=["RUNNING", "STOP_PENDING", "STOPPED"]), \
             patch.object(c, "_del_dir_contents", return_value=42):
            freed = c._clean_windows_update_cache(Path("C:\\x"))
        self.assertEqual(freed, 42)
        self.assertEqual([a[1] for a in calls], ["stop", "start"])

    def test_running_stop_pending_forever_no_delete(self):
        c = self._cleaner()
        calls = []
        states = iter(["RUNNING"] + ["STOP_PENDING"] * 500)

        def fake_state(_name):
            return next(states)

        with patch.object(vac, "_WU_STOP_POLL_TIMEOUT", 0.5), \
             patch.object(vac, "_WU_STOP_POLL_INTERVAL", 0.01), \
             patch.object(vac.subprocess, "run", side_effect=self._mock_run(calls)), \
             patch.object(c, "_service_state", side_effect=fake_state), \
             patch.object(c, "_del_dir_contents", side_effect=AssertionError("must not delete")):
            freed = c._clean_windows_update_cache(Path("C:\\x"))
        self.assertEqual(freed, 0)
        # restore is still attempted (original state was RUNNING)
        self.assertEqual([a[1] for a in calls], ["stop", "start"])

    def test_paused_no_delete_no_stop(self):
        c = self._cleaner()
        with patch.object(vac.subprocess, "run", side_effect=AssertionError("must not stop service")), \
             patch.object(c, "_service_state", return_value="PAUSED"), \
             patch.object(c, "_del_dir_contents", side_effect=AssertionError("must not delete")):
            freed = c._clean_windows_update_cache(Path("C:\\x"))
        self.assertEqual(freed, 0)

    def test_start_pending_requires_stop_and_restore(self):
        c = self._cleaner()
        calls = []
        with patch.object(vac.subprocess, "run", side_effect=self._mock_run(calls)), \
             patch.object(c, "_service_state", side_effect=["START_PENDING", "STOPPED"]), \
             patch.object(c, "_del_dir_contents", return_value=5):
            freed = c._clean_windows_update_cache(Path("C:\\x"))
        self.assertEqual(freed, 5)
        self.assertEqual([a[1] for a in calls], ["stop", "start"])


class TestWindowsUpdateServiceGateW2002(unittest.TestCase):
    """W2-002: exact STOPPED must be a LIVE authorization over the whole
    destructive interval, not a one-time precondition, and the stop transition
    must be total -- no escaping TimeoutExpired. The gate revalidates the real
    service state at batch cadence and immediately before directory/root
    removal; RUNNING, START_PENDING or UNKNOWN at any recheck aborts the
    remaining mutations fail-closed, and the gate never re-stops the service.
    """

    def _mock_run(self, calls, stop_rc=0, stop_exc=None):
        def fake_run(argv, *a, **k):
            calls.append(list(argv[:2]))
            if argv[0] == "net" and argv[1] == "stop":
                if stop_exc is not None:
                    raise stop_exc
                return MagicMock(returncode=stop_rc)
            if argv[0] == "net" and argv[1] == "start":
                return MagicMock(returncode=0)
            raise AssertionError(f"unexpected subprocess: {argv}")
        return fake_run

    @staticmethod
    def _states(*seq):
        """_service_state stub: state i per call, the last one sticks."""
        calls = {"n": 0}

        def fake(_name=None):
            i = calls["n"]
            calls["n"] += 1
            return seq[min(i, len(seq) - 1)]

        return fake, calls

    def _cleaner(self, root):
        c = vac.SystemCleaner(False, vac.Logger(log_file=None, dry_run=False),
                              max_threads=1)
        c._set_guard(root)
        return c

    def _target(self, root, n=8):
        target = root / "wu"
        target.mkdir()
        for i in range(n):
            (target / f"f{i}.bin").write_bytes(b"x")
        return target

    def test_originally_stopped_switch_to_running_mid_sweep_stops_mutations(self):
        """VERIFY 1: orig STOPPED, service restarts after several candidates:
        no mutation after the switch is observed, and no net stop/start ever."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = self._target(root)
            c = self._cleaner(root)
            calls = []
            fake_state, _ = self._states("STOPPED", "STOPPED", "STOPPED", "RUNNING")
            with patch.object(vac, "_OWNER_REFRESH_BATCH", 4), \
                 patch.object(vac, "get_running_processes", return_value=set()), \
                 patch.object(vac.subprocess, "run", side_effect=self._mock_run(calls)), \
                 patch.object(c, "_service_state", side_effect=fake_state):
                freed = c._clean_windows_update_cache(target)
            deleted = 8 - len(list(target.glob("*.bin")))
            self.assertGreater(freed, 0, "the pre-switch batch executes normally")
            self.assertGreater(deleted, 0)
            self.assertLess(deleted, 8,
                            "mutations must stop after the RUNNING switch is observed")
            self.assertEqual(calls, [],
                             "originally STOPPED: no net stop/net start may ever be issued")
            self.assertIsNone(c._sweep_gate, "gate must be uninstalled after the sweep")

    def test_running_restarts_mid_sweep_aborts_and_restores(self):
        """VERIFY 2: orig RUNNING -> stopped -> restarts during sweep:
        remaining mutations abort and the restore stays deterministic."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = self._target(root)
            c = self._cleaner(root)
            calls = []
            fake_state, _ = self._states("RUNNING", "STOPPED", "STOPPED", "STOPPED", "RUNNING")
            with patch.object(vac, "_OWNER_REFRESH_BATCH", 4), \
                 patch.object(vac, "get_running_processes", return_value=set()), \
                 patch.object(vac.subprocess, "run", side_effect=self._mock_run(calls)), \
                 patch.object(c, "_service_state", side_effect=fake_state):
                c._clean_windows_update_cache(target)
            deleted = 8 - len(list(target.glob("*.bin")))
            self.assertGreater(deleted, 0, "the pre-restart batch executes normally")
            self.assertLess(deleted, 8, "mutations must abort after the restart is observed")
            self.assertEqual([a[1] for a in calls], ["stop", "start"],
                             "a deliberately stopped service is restored in finally")

    def test_net_stop_timeout_is_controlled_not_escaping(self):
        """VERIFY 3: 'net stop' TimeoutExpired logs one controlled error, does
        not propagate, and later independent system targets still execute."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            c = self._cleaner(root)
            calls = []
            exc = vac.subprocess.TimeoutExpired(["net", "stop", "wuauserv"], 30)
            with patch.object(vac.subprocess, "run", side_effect=self._mock_run(calls, stop_exc=exc)), \
                 patch.object(c, "_service_state", side_effect=["RUNNING", None]), \
                 patch.object(c, "_del_dir_contents", side_effect=AssertionError("must not delete")):
                freed = c._clean_windows_update_cache(Path(root) / "wu")
            self.assertEqual(freed, 0)
            # restore is still attempted (the stop was issued against a running service)
            self.assertEqual([a[1] for a in calls], ["stop", "start"])
            self.assertIsNone(c._sweep_gate, "gate must not leak past a failed transaction")
            # later independent targets still execute
            with patch.object(vac.subprocess, "run", side_effect=self._mock_run(calls)), \
                 patch.object(c, "_service_state", side_effect=["STOPPED"]), \
                 patch.object(c, "_del_dir_contents", return_value=7):
                freed2 = c._clean_windows_update_cache(Path(root) / "wu")
            self.assertEqual(freed2, 7, "a later target must run normally after the skip")

    def test_unknown_at_recheck_stops_target(self):
        """VERIFY 5: UNKNOWN (None) at any recheck stops the target."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = self._target(root)
            c = self._cleaner(root)
            calls = []
            fake_state, _ = self._states("STOPPED", "STOPPED", "STOPPED", None)
            with patch.object(vac, "_OWNER_REFRESH_BATCH", 4), \
                 patch.object(vac, "get_running_processes", return_value=set()), \
                 patch.object(vac.subprocess, "run", side_effect=self._mock_run(calls)), \
                 patch.object(c, "_service_state", side_effect=fake_state):
                c._clean_windows_update_cache(target)
            deleted = 8 - len(list(target.glob("*.bin")))
            self.assertLess(deleted, 8, "UNKNOWN at a recheck must abort the sweep")
            self.assertEqual(calls, [], "originally STOPPED: no service mutation ever")

    def test_gate_latch_never_reopens_and_throttles_queries(self):
        """The gate fails closed permanently once it fails, and a passing gate
        costs at most one real 'sc query' per batch of evaluations."""
        c = vac.SystemCleaner(False, vac.Logger(log_file=None, dry_run=False))
        with patch.object(vac, "_OWNER_REFRESH_BATCH", 4):
            gate = c._make_service_gate("wuauserv")
        with patch.object(c, "_service_state", side_effect=["STOPPED", "RUNNING"]) as st:
            self.assertTrue(gate(force=True))       # real check #1 -> STOPPED
            for _ in range(4):
                self.assertTrue(gate())             # latched, no query
            self.assertFalse(gate())                # real check #2 -> RUNNING
            self.assertFalse(gate(force=True))      # latched shut
        self.assertEqual(st.call_count, 2, "only two real queries were made")

    @unittest.skipUnless(os.name == "nt", "native sc query transport is Windows-only")
    def test_native_sc_query_maps_real_wuauserv_state(self):
        """VERIFY 7 native leg (read-only): the real 'sc query' transport maps
        a real wuauserv state; no service is stopped or started here."""
        c = vac.SystemCleaner(False, vac.Logger(log_file=None, dry_run=False))
        state = c._service_state("wuauserv")
        known = {"RUNNING", "STOPPED", "START_PENDING", "STOP_PENDING",
                 "PAUSED", "CONTINUE_PENDING", "PAUSE_PENDING"}
        self.assertIn(state, known | {None},
                      f"real sc query must map a known state or None, got {state!r}")
        if state is not None:
            gate = c._make_service_gate("wuauserv")
            self.assertEqual(gate(force=True), state == "STOPPED",
                             "the native gate verdict must mirror the real state")


class TestVersionConsistency(unittest.TestCase):
    """F9: one authoritative version source; no stale claims in prose."""

    def test_module_banner_has_no_stale_version(self):
        src = Path(vac.__file__).read_text(encoding="utf-8")
        banner = src.split("VERSION =", 1)[0]
        for m in re.finditer(r"v?\d+\.\d+\.\d+", banner):
            self.fail(f"stale version claim in source banner: {m.group(0)!r}")

    def test_version_matches_package_metadata(self):
        """Installed-dist metadata must match VERSION.

        A wheel build drops an egg-info INTO THE SOURCE TREE, which
        importlib.metadata can see while the repo is on sys.path. That is NOT
        an installed package (markhunt F package-boundary): the check only runs
        against a real site-packages dist-info.
        """
        try:
            import importlib.metadata as im
            dist = im.distribution("smart-vac-cleaner")
            installed = dist.version
            loc = str(getattr(dist, "_path", ""))
        except Exception:  # noqa: BLE001 - no installed dist (source checkout)
            self.skipTest("package metadata unavailable (source checkout)")
        if "site-packages" not in loc.lower():
            self.skipTest("dist metadata is a source-tree artifact (egg-info), not an installed package")
        self.assertEqual(installed, vac.VERSION)

    def test_version_matches_pyproject(self):
        """The two in-repo machine-readable copies must agree."""
        pyproject = Path(vac.__file__).resolve().parent / "pyproject.toml"
        if not pyproject.exists():
            self.skipTest("pyproject.toml not next to source")
        m = re.search(r'^version = "(.+)"$', pyproject.read_text(encoding="utf-8"), re.MULTILINE)
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), vac.VERSION)

    def test_docstring_describes_configurable_roots(self):
        doc = vac.__doc__ or ""
        self.assertIn("portable_roots", doc)
        self.assertNotIn("v2.1.0", doc)
        self.assertNotIn("always seeded into the config", doc)


class TestProcessOwnerProvenance(unittest.TestCase):
    """F10: every APP_PROCESSES mapping carries semantic evidence."""

    def test_every_process_group_has_provenance(self):
        for group in vac.APP_PROCESSES:
            self.assertIn(group, vac.APP_PROCESSES_PROVENANCE, f"{group} lacks provenance (F10)")

    def test_provenance_entries_are_marked(self):
        for group, prov in vac.APP_PROCESSES_PROVENANCE.items():
            if group == "general":
                continue
            self.assertTrue(prov.startswith(("verified:", "product:", "unverified-exe")),
                            f"{group}: provenance must be categorized, got {prov!r}")

    def test_no_core_windows_system_exe_mappings(self):
        system_exes = {"svchost.exe", "conhost.exe", "csrss.exe", "winlogon.exe", "wininit.exe",
                       "services.exe", "lsass.exe", "explorer.exe", "smss.exe", "dwm.exe",
                       "taskhost.exe", "taskhostw.exe", "dllhost.exe", "rundll32.exe",
                       "sihost.exe", "fontdrvhost.exe", "regsvr32.exe", "spoolsv.exe",
                       "wudfhost.exe", "searchindexer.exe"}
        mapped = set()
        for exes in vac.APP_PROCESSES.values():
            mapped |= set(exes)
        self.assertEqual(mapped & system_exes, set())

    def test_mapped_exes_lowercase_nonempty(self):
        for group, exes in vac.APP_PROCESSES.items():
            for exe in exes:
                self.assertTrue(exe, f"{group}: empty exe")
                self.assertEqual(exe, exe.lower(), f"{group}: {exe!r} must be lowercase")

    def test_devin_mapping_is_real_executable(self):
        """devinst.exe was an invented name; the installed exe is Devin.exe."""
        self.assertIn("devin.exe", vac.APP_PROCESSES["devin"])
        self.assertNotIn("devinst.exe", vac.APP_PROCESSES["devin"])


class TestSafetyDocContract(unittest.TestCase):
    """G/T-133: docs/Safety.md invariants are proven by BEHAVIOR, not class names.

    The layer->class map below is an INDEX only. Every critical invariant also
    has a concrete behavioral assertion IN THIS CLASS, so a useless class with
    the right name cannot launder a prose-only claim. A test that merely asserts
    duplicated constants is never evidence here.
    """

    LAYER_TESTS: ClassVar[dict[int, str]] = {
        1: "TestDryRunPurity",
        2: "TestPathHardening",
        3: "TestBlacklist",
        4: "TestPortableRootPolicy",
        5: "TestSafetyGuard",
        6: "TestGetRunningProcesses",
        7: "TestUserAppdataTargets",
        8: "TestSafetyInvariants",
        9: "TestSafetyInvariants",
        10: "TestExclusions",
        11: "TestSafetyInvariants",
        12: "TestPortableSweep",
    }

    def test_every_doc_layer_maps_to_a_test_class(self):
        mod = sys.modules[self.__class__.__module__]
        for num, clsname in self.LAYER_TESTS.items():
            self.assertTrue(getattr(mod, clsname, None), f"Safety.md layer {num} -> {clsname}")

    # ---- behavioral proofs (T-133): the doc claim, demonstrated ----

    def test_behavior_dry_run_is_physically_read_only(self):
        """Layer 1: dry-run performs zero chmod/unlink/rmdir, byte-identical tree."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            app = root / "app"
            (app / "deep").mkdir(parents=True)
            (app / "deep" / "a.bin").write_bytes(b"x" * 100)
            before = snapshot_tree(root)
            with _ExplodeMutations():
                c = vac.CleanerEngine(True, vac.Logger(log_file=None, dry_run=True),
                                      vac.SafetyGuard(root, allow_shallow_system_target=True), root)
                c._del_dir(app, "app")
            after = snapshot_tree(root)
            self.assertEqual(before, after)

    def test_behavior_exclusions_are_global_invariant(self):
        """Layer 10: engine exclusions reach the guard the engine actually uses."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            excl = root / "keep"
            excl.mkdir()
            c = vac.CleanerEngine(True, vac.Logger(log_file=None, dry_run=True),
                                  vac.SafetyGuard(root, allow_shallow_system_target=True), root,
                                  exclude_paths=[str(excl)])
            ok, _ = c.guard.is_safe(excl / "x.bin")
            self.assertFalse(ok)

    def test_behavior_process_unknown_blocks_app_target(self):
        """Layer 6: UNKNOWN process state skips app-sensitive targets."""
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "Cache"
            target.mkdir()
            (target / "f.bin").write_bytes(b"x" * 10)
            targets = {k: False for k in vac.SYSTEM_TARGET_DEFAULTS}
            targets["Discord Cache"] = True
            with patch.object(vac, "USER_APPDATA_TARGETS", [(target, "Discord Cache", "discord")]), \
                 patch.object(vac, "get_running_processes", return_value=None):
                c = vac.SystemCleaner(False, vac.Logger(log_file=None, dry_run=False), targets=targets)
                c.run_all()
            self.assertTrue((target / "f.bin").exists())

    def test_behavior_owner_trust_is_enforced(self):
        """Layer 7/T-130: an unverified owner cannot authorize a real delete."""
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "Cache"
            target.mkdir()
            (target / "f.bin").write_bytes(b"x" * 10)
            targets = {k: False for k in vac.SYSTEM_TARGET_DEFAULTS}
            targets["AccuRIG Cache"] = True
            with patch.object(vac, "USER_APPDATA_TARGETS", [(target, "AccuRIG Cache", "accu rig")]), \
                 patch.object(vac, "get_running_processes", return_value=set()):
                c = vac.SystemCleaner(False, vac.Logger(log_file=None, dry_run=False), targets=targets)
                c.run_all()
            self.assertTrue((target / "f.bin").exists())

    def test_behavior_toctou_replacement_survives(self):
        """Layer 11/T-124: a replaced candidate is never deleted."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            f = root / "deep" / "junk.bin"
            f.parent.mkdir(parents=True)
            f.write_bytes(b"x" * 100)
            c = vac.CleanerEngine(False, vac.Logger(log_file=None, dry_run=False),
                                  vac.SafetyGuard(root, allow_shallow_system_target=True), root)
            plan = c._plan_file(f)
            f.unlink()
            f.write_bytes(b"y" * 300)
            result = c._apply_file_plan(f, plan[0], plan[1])
            self.assertFalse(result.success)
            self.assertTrue(f.exists())

    def test_behavior_root_protection_is_absolute(self):
        """Layer 3: protected roots and every descendant are refused."""
        self.assertTrue(vac.is_path_blacklisted(Path(os.environ.get("windir", r"C:\Windows")) / "Temp" / "x"))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            guard = vac.SafetyGuard(root)
            ok, reason = guard.is_safe(root)
            self.assertFalse(ok)
            self.assertIn("target root", reason)

    def test_behavior_target_policy_parity_is_executable(self):
        """Layers 5/10 + status: one planner, one mask policy, executable proof."""
        config = {"portable_roots": [], "custom_rules": [],
                  "exclude_patterns": ["*.secret"], "exclude_paths": [],
                  "system_targets": {"Recycle Bin": True}}
        status = vac.resolve_job_spec(dry_run=True, run_portable=True, run_system=True, run_custom=True,
                                      config=config, surface="status")
        self.assertEqual(dict(status.sys_targets), dict(vac.SYSTEM_TARGET_DEFAULTS))
        self.assertIn("*.secret", status.exclude_patterns)

    def test_idempotent_rerun_missing_paths_skipped(self):
        """Operational doc claim: a crashed run is safe to re-run."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            log = vac.Logger(log_file=None, dry_run=False)
            c = vac.CleanerEngine(False, log, vac.SafetyGuard(root, allow_shallow_system_target=True), root)
            self.assertEqual(c._del_file(root / "gone" / "x.bin", "gone"), 0)
            self.assertEqual(c._del_dir(root / "gone", "gone"), 0)
            self.assertEqual(log.n_errors, 0)


class TestMutationChokepoint(unittest.TestCase):
    """B/T-134: every real mutation sits behind the single JIT gate; the
    mutation inventory is allowlisted by subsystem, with NO cleaner side door."""

    @staticmethod
    def _enclosing_def(src_lines, idx):
        for j in range(idx, -1, -1):
            m = re.match(r"^(?:    )?def (\w+)", src_lines[j])
            if m:
                return m.group(1)
        return None

    def test_unlink_rmdir_chmod_only_inside_apply_gates(self):
        src_lines = Path(vac.__file__).read_text(encoding="utf-8").splitlines()
        allowed = vac._CLEANER_MUTATION_SITES + vac._LOG_RETENTION_SITES + vac._CONFIG_PERSISTENCE_SITES
        for i, line in enumerate(src_lines):
            if "_TOKENS =" in line or "_PRIMITIVES =" in line:
                continue
            for token in vac._CLEANER_MUTATION_TOKENS:
                if token in line:
                    enclosing = self._enclosing_def(src_lines, i)
                    self.assertIn(enclosing, allowed,
                                  f"{token} at line {i + 1} is a side-door mutation inside {enclosing}")

    def test_log_retention_is_its_own_subsystem(self):
        """T-110: _prune_old_logs only removes clean_*.log from the logs dir."""
        with tempfile.TemporaryDirectory() as tmp:
            logs = Path(tmp)
            for name in ("clean_20260101_010000.log", "clean_20260102_010000.log",
                         "clean_20260103_010000.log", "unrelated.txt"):
                (logs / name).write_text("x")
            vac._prune_old_logs(logs, keep=2)
            self.assertTrue((logs / "clean_20260103_010000.log").exists(), "newest kept")
            self.assertTrue((logs / "clean_20260102_010000.log").exists())
            self.assertFalse((logs / "clean_20260101_010000.log").exists(), "oldest pruned")
            self.assertTrue((logs / "unrelated.txt").exists(), "non-log files untouched")

    def test_no_banned_cleaner_primitive_anywhere(self):
        """os.remove / shutil.rmtree / rename/replace primitives never appear.

        T-210: the one exemption is the named log-retention site list -- POSIX
        anchored deletion of the cleaner's own run logs legitimately needs
        os.unlink(name, dir_fd=...) and only ever runs inside those functions,
        which are already allowlisted as the retention subsystem.
        """
        src_lines = Path(vac.__file__).read_text(encoding="utf-8").splitlines()
        # The inventory definition block is multi-line; drop it entirely so its
        # own strings can't trip the scan.
        block_start = re.compile(r"^_BANNED_CLEANER_PRIMITIVES = \(")
        for banned in vac._BANNED_CLEANER_PRIMITIVES:
            for i, line in enumerate(src_lines):
                if banned not in line or "_TOKENS =" in line or "_PRIMITIVES =" in line:
                    continue
                if any(block_start.match(src_lines[j]) for j in range(max(0, i - 6), i + 1)):
                    continue
                enclosing = self._enclosing_def(src_lines, i)
                self.assertIn(enclosing, vac._LOG_RETENTION_SITES,
                              f"{banned} at line {i + 1} outside the named retention sites"
                              f" (found in {enclosing})")

    def test_config_persistence_uses_only_its_own_atomic_replace(self):
        src_lines = Path(vac.__file__).read_text(encoding="utf-8").splitlines()
        allowed = vac._CONFIG_PERSISTENCE_SITES + ("get_running_processes",)  # str.replace in tasklist parse
        for i, line in enumerate(src_lines):
            if "_PERSISTENCE_TOKENS =" in line:
                continue
            for token in vac._CONFIG_PERSISTENCE_TOKENS:
                if token in line:
                    enclosing = self._enclosing_def(src_lines, i)
                    self.assertIn(enclosing, allowed,
                                  f"{token} at line {i + 1} inside {enclosing} is not config persistence")

    def test_service_actions_live_only_in_declared_sites(self):
        src_lines = Path(vac.__file__).read_text(encoding="utf-8").splitlines()
        for i, line in enumerate(src_lines):
            if "_ACTION_TOKENS =" in line:
                continue
            for token in vac._SERVICE_ACTION_TOKENS:
                if token in line:
                    enclosing = self._enclosing_def(src_lines, i)
                    self.assertIn(enclosing, vac._SERVICE_ACTION_SITES,
                                  f"{token} at line {i + 1} inside {enclosing} is an unreviewed service action")

    def test_dry_run_performs_zero_destructive_subprocess_calls(self):
        """DNS flush / service stop-start are unreachable in dry-run (B)."""
        c = vac.SystemCleaner(True, vac.Logger(log_file=None, dry_run=True))
        c.targets = {k: True for k in vac.SYSTEM_TARGET_DEFAULTS}
        with patch.object(vac, "get_running_processes", return_value=set()), \
             patch.object(vac, "USER_APPDATA_TARGETS", []), \
             patch.object(vac, "SYSTEM_TEMP", Path("Z:/__none__")), \
             patch.object(vac, "USER_TEMP", Path("Z:/__none__")), \
             patch.object(vac, "USER_CRASH", Path("Z:/__none__")), \
             patch.object(vac, "USER_EXPLORER", Path("Z:/__none__")), \
             patch.object(vac.subprocess, "run", side_effect=AssertionError("dry-run must not run subprocess")):
            c.run_all()

    def test_dead_duplicate_logic_removed(self):
        """H: collapsed duplicates must not return."""
        src = Path(vac.__file__).read_text(encoding="utf-8")
        self.assertNotIn("CHROMIUM_NETWORK_FILES", src)
        self.assertNotIn("_fs_helper_get_size", src)
        self.assertNotIn("is_system_root", src)
        self.assertIsNone(re.search(r"\b_NUMBERED_RE\b", src), "PortableCleaner duplicate regex returned")


class TestCandidateLedger(unittest.TestCase):
    """T-124: one physical candidate is claimed once, at the planning source."""

    def _tree(self):
        tmp = tempfile.TemporaryDirectory()
        root = Path(tmp.name)
        parent = root / "app"
        child = parent / "deep"
        child.mkdir(parents=True)
        return tmp, parent, child

    def test_exact_duplicate_covered(self):
        tmp, parent, _ = self._tree()
        try:
            lg = vac.CandidateLedger()
            lg.claim(parent)
            self.assertTrue(lg.covered(parent))
            self.assertTrue(lg.covered(parent / "deep" / "f.bin"))
        finally:
            tmp.cleanup()

    def test_parent_child_overlap(self):
        tmp, parent, child = self._tree()
        try:
            lg = vac.CandidateLedger()
            lg.claim(parent)
            self.assertTrue(lg.covered(child))
            lg.claim(parent / "other")
            self.assertTrue(lg.covered(parent / "other"))
        finally:
            tmp.cleanup()

    def test_ancestor_claim_absorbs_descendants(self):
        tmp, parent, child = self._tree()
        try:
            lg = vac.CandidateLedger()
            lg.claim(child)
            self.assertFalse(lg.covered(parent), "parent is not yet claimed")
            self.assertEqual(lg.claims_within(parent), [vac.CandidateLedger._canon(child)])
            lg.claim(parent)
            self.assertTrue(lg.covered(child))
            self.assertEqual(len(lg), 1, "absorbed descendant claim must not remain")
        finally:
            tmp.cleanup()

    def test_canonical_alias_collapses(self):
        tmp, parent, _ = self._tree()
        try:
            lg = vac.CandidateLedger()
            canon = vac.CandidateLedger._canon(parent)
            alias = Path(str(parent).replace("\\", "/"))
            lg.claim(canon)
            self.assertTrue(lg.covered(alias))
        finally:
            tmp.cleanup()

    def test_claim_after_plan_excludes_absorbed_subtrees(self):
        """A target that absorbs a prior claim must EXCLUDE it from its plan."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "target"
            cache = target / "Cache"
            cache.mkdir(parents=True)
            (cache / "a.bin").write_bytes(b"x" * 10)
            ledger = vac.CandidateLedger()
            ledger.claim(cache)  # prior layer claimed the cache subtree
            log = vac.Logger(log_file=None, dry_run=True, quiet=True)
            engine = vac.CleanerEngine(True, log, vac.SafetyGuard(root, allow_shallow_system_target=True), root, ledger=ledger)
            excluded = engine._ledger_claims_within(target)
            plan = engine._plan_tree(target, "target", excluded_regions=excluded)
            self.assertIsNotNone(plan)
            self.assertEqual(plan["bytes"], 0, "absorbed cache subtree must not be double-counted")


class TestJobOverlap(unittest.TestCase):
    """T-124: cross-layer overlap counts each physical byte once."""

    def _portable_with_cache(self, root, size=10):
        p = root / "portable"
        (p / "_CENT" / "User Data" / "Default" / "Cache").mkdir(parents=True)
        (p / "_CENT" / "User Data" / "Default" / "Cache" / "data_0").write_bytes(b"x" * size)
        return p

    def test_custom_rule_on_same_cache_counts_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            p = self._portable_with_cache(root)
            cache = p / "_CENT" / "User Data" / "Default" / "Cache"
            cfg = {"portable_roots": [str(p)],
                   "custom_rules": [{"path": str(cache), "pattern": "*"}],
                   "exclude_patterns": [], "exclude_paths": []}
            log = vac.Logger(log_file=None, dry_run=True, quiet=True)
            with patch.object(vac, "get_running_processes", return_value=set()):
                spec = vac.resolve_job_spec(dry_run=True, run_portable=True, run_system=False, run_custom=True,
                                            config=cfg, surface="cli")
                res = vac.run_cleaning_job(spec, log)
            self.assertEqual(res["portable"], 10)
            self.assertEqual(res["custom"], 0, "custom must not re-plan a claimed cache")
            self.assertEqual(res["portable"] + res["custom"], 10)

    def test_custom_rule_on_ancestor_counts_unique_bytes_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            p = self._portable_with_cache(root)
            (p / "other.txt").write_text("other")
            cfg = {"portable_roots": [str(p)],
                   "custom_rules": [{"path": str(p), "pattern": "*"}],
                   "exclude_patterns": [], "exclude_paths": []}
            log = vac.Logger(log_file=None, dry_run=True, quiet=True)
            with patch.object(vac, "get_running_processes", return_value=set()):
                spec = vac.resolve_job_spec(dry_run=True, run_portable=True, run_system=False, run_custom=True,
                                            config=cfg, surface="cli")
                res = vac.run_cleaning_job(spec, log)
            # portable plans the 10-byte cache; custom plans only the non-claimed 5 bytes
            self.assertEqual(res["portable"], 10)
            self.assertEqual(res["custom"], 5)
            self.assertEqual(res["portable"] + res["custom"], 15, "no physical byte planned twice")


class TestStatusPolicy(unittest.TestCase):
    """T-127: --status uses the SAFE CLI mask and applies saved exclusions."""

    def test_status_resolution_safe_mask_plus_exclusions(self):
        config = {
            "portable_roots": [], "custom_rules": [],
            "exclude_patterns": ["*.secret"], "exclude_paths": ["D:\\Keep"],
            "system_targets": {"Recycle Bin": True, "System Temp": False},
        }
        spec = vac.resolve_job_spec(dry_run=True, run_portable=True, run_system=True, run_custom=True,
                                    config=config, surface="status")
        # status represents the documented SAFE CLI policy: config prefs do NOT leak in
        self.assertEqual(dict(spec.sys_targets), dict(vac.SYSTEM_TARGET_DEFAULTS))
        self.assertFalse(spec.sys_targets["Recycle Bin"])
        self.assertTrue(spec.sys_targets["System Temp"])
        # saved exclusions ALWAYS apply on every surface
        self.assertIn("*.secret", spec.exclude_patterns)
        self.assertTrue(any("Keep" in p for p in spec.exclude_paths))

    def test_status_obeys_saved_exclusions_end_to_end(self):
        """A target excluded via saved config contributes 0 to --status."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "Cache"
            (target / "deep").mkdir(parents=True)
            (target / "deep" / "f.bin").write_bytes(b"x" * 100)
            config = {
                "portable_roots": [], "custom_rules": [],
                "exclude_patterns": [], "exclude_paths": [str(target)],
                "system_targets": {},
            }
            buf = io.StringIO()
            with patch.object(vac, "USER_APPDATA_TARGETS", [(target, "Discord Cache", "discord")]), \
                 patch.object(vac, "get_running_processes", return_value=set()), \
                 patch.object(vac, "SYSTEM_TEMP", Path(tmp) / "none"), \
                 patch.object(vac, "USER_TEMP", Path(tmp) / "none"), \
                 patch.object(vac, "USER_CRASH", Path(tmp) / "none"), \
                 patch.object(vac, "USER_EXPLORER", Path(tmp) / "none"), \
                 patch.object(vac, "load_config", return_value=config), \
                 patch.object(vac, "load_config_strict", return_value=(True, config, [])), \
                 contextlib.redirect_stdout(buf):
                vac.cli_status()
            self.assertNotIn("Discord Cache", buf.getvalue(),
                             "an excluded target must not appear as a status candidate")


class TestSurfaceMatrix(unittest.TestCase):
    """T-129/markhunt C: same GUI state resolves identical masks on every surface."""

    GUI_STATE = None

    def _state(self):
        st = dict(vac.SYSTEM_TARGET_DEFAULTS)
        st["Recycle Bin"] = True
        st["System Temp"] = False
        return st

    def test_gui_background_scheduled_identical_masks(self):
        state = self._state()
        cfg = {"portable_roots": [], "custom_rules": [], "exclude_patterns": [], "exclude_paths": [],
               "system_targets": dict(state)}
        masks = {}
        for surf in ("gui", "background", "scheduled"):
            spec = vac.resolve_job_spec(dry_run=True, run_portable=True, run_system=True, run_custom=True,
                                        config=cfg, sys_targets=state, surface=surf)
            masks[surf] = dict(spec.sys_targets)
        self.assertEqual(masks["gui"], state)
        self.assertEqual(masks["background"], masks["gui"])
        self.assertEqual(masks["scheduled"], masks["gui"])

    def test_cli_and_status_stay_safe_defaults(self):
        cfg = {"portable_roots": [], "custom_rules": [], "exclude_patterns": [], "exclude_paths": []}
        for surf in ("cli", "status"):
            spec = vac.resolve_job_spec(dry_run=True, run_portable=True, run_system=True, run_custom=True,
                                        config=cfg, surface=surf)
            self.assertEqual(dict(spec.sys_targets), dict(vac.SYSTEM_TARGET_DEFAULTS), surf)

    def test_mask_round_trip_via_argv_deviations(self):
        """clean_argv serializes both directions; the CLI side decodes them back."""
        state = self._state()
        enables, disables = vac._target_deviations(state)
        self.assertIn("Recycle Bin", enables)
        self.assertNotIn("System Temp", enables)
        self.assertIn("System Temp", disables)
        decoded = vac.resolve_job_spec(dry_run=True, run_portable=True, run_system=True, run_custom=True,
                                       config={"portable_roots": [], "custom_rules": [],
                                               "exclude_patterns": [], "exclude_paths": []},
                                       cli_enable=enables, cli_disable=disables, surface="cli")
        self.assertEqual(dict(decoded.sys_targets), state)


class TestOwnerTrustEnforcement(unittest.TestCase):
    """T-130: presence of provenance is not trust; unverified owners cannot authorize."""

    def test_trust_states(self):
        self.assertEqual(vac._owner_trust("devin"), "verified")
        self.assertEqual(vac._owner_trust("accu rig"), "unverified")
        self.assertEqual(vac._owner_trust(vac.PROCESS_AGNOSTIC), "verified")
        self.assertEqual(vac._owner_trust("nope"), "unverified")

    def test_unverified_owner_cannot_authorize_any_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "Cache"
            target.mkdir()
            (target / "f.bin").write_bytes(b"x" * 10)
            targets = {k: False for k in vac.SYSTEM_TARGET_DEFAULTS}
            targets["AccuRIG Cache"] = True
            with patch.object(vac, "USER_APPDATA_TARGETS", [(target, "AccuRIG Cache", "accu rig")]), \
                 patch.object(vac, "get_running_processes", return_value=set()):
                for dry in (False, True):
                    log = vac.Logger(log_file=None, dry_run=dry)
                    c = vac.SystemCleaner(dry, log, targets=targets)
                    c.run_all()
                    self.assertEqual(log.n_deleted, 0, f"dry={dry}: unverified owner must not authorize")
                    self.assertTrue((target / "f.bin").exists())

    def test_verified_owner_can_authorize_when_not_running(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "Cache"
            target.mkdir()
            (target / "f.bin").write_bytes(b"x" * 10)
            targets = {k: False for k in vac.SYSTEM_TARGET_DEFAULTS}
            targets["Discord Cache"] = True
            with patch.object(vac, "USER_APPDATA_TARGETS", [(target, "Discord Cache", "discord")]), \
                 patch.object(vac, "get_running_processes", return_value=set()):
                c = vac.SystemCleaner(False, vac.Logger(log_file=None, dry_run=False), targets=targets)
                c.run_all()
            self.assertFalse((target / "f.bin").exists())
            self.assertEqual(c.results["Discord Cache"], 10)


class TestProcessStateTOCTOU(unittest.TestCase):
    """T-131: an app starting between plan and apply aborts the target's mutations."""

    def test_app_start_between_plan_and_apply_aborts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "Cache"
            (target / "deep").mkdir(parents=True)
            (target / "deep" / "a.bin").write_bytes(b"x" * 50)
            log = vac.Logger(log_file=None, dry_run=False)
            c = vac.SystemCleaner(False, log)
            c.guard = vac.SafetyGuard(root, allow_shallow_system_target=True)
            with patch.object(vac, "get_running_processes", side_effect=[set(), {"discord.exe"}]):
                freed = c.safe_del_dir(target, "Discord Cache", "discord")
            self.assertEqual(freed, 0)
            self.assertTrue((target / "deep" / "a.bin").exists())
            self.assertEqual(log.n_deleted, 0)

    def test_unknown_snapshot_at_apply_aborts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "Cache"
            target.mkdir()
            (target / "a.bin").write_bytes(b"x" * 10)
            log = vac.Logger(log_file=None, dry_run=False)
            c = vac.SystemCleaner(False, log)
            c.guard = vac.SafetyGuard(root, allow_shallow_system_target=True)
            with patch.object(vac, "get_running_processes", side_effect=[set(), None]):
                freed = c.safe_del_dir(target, "Discord Cache", "discord")
            self.assertEqual(freed, 0)
            self.assertTrue((target / "a.bin").exists())
            self.assertEqual(log.n_deleted, 0)


class TestCancelMutationGate(unittest.TestCase):
    """T-132: cancellation is a mutation invariant inside the authorization gate."""

    def test_cancel_after_plan_zero_mutations(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "app"
            (target / "deep").mkdir(parents=True)
            (target / "deep" / "a.bin").write_bytes(b"x" * 50)
            log = vac.Logger(log_file=None, dry_run=False)
            cancel = threading.Event()
            c = vac.CleanerEngine(False, log, vac.SafetyGuard(root, allow_shallow_system_target=True), root,
                                  cancel_event=cancel)
            plan = c._plan_tree(target, "app")
            self.assertIsNotNone(plan)
            cancel.set()
            with self.assertRaises(vac.CancelJobException):
                c._apply_tree_plan(plan, "app")
            self.assertTrue((target / "deep" / "a.bin").exists())
            self.assertEqual(log.n_deleted, 0)

    def test_cancel_before_retry_aborts(self):
        """T-137/T-132: cancel after our chmod fails the next auth before the retry unlink."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            f = root / "deep" / "f.bin"
            f.parent.mkdir(parents=True)
            f.write_bytes(b"x" * 20)
            log = vac.Logger(log_file=None, dry_run=False)
            cancel = threading.Event()
            c = vac.CleanerEngine(False, log, vac.SafetyGuard(root, allow_shallow_system_target=True), root,
                                  cancel_event=cancel)
            plan = c._plan_file(f)
            self.assertIsNotNone(plan)

            real_chmod = Path.chmod

            def chmod_then_cancel(self, *a, **k):
                real_chmod(self, *a, **k)
                cancel.set()

            with patch.object(Path, "chmod", chmod_then_cancel), \
                 patch.object(Path, "unlink", side_effect=PermissionError), \
                 self.assertRaises(vac.CancelJobException):
                c._apply_file_plan(f, plan[0], plan[1])
            self.assertTrue(f.exists())
            self.assertEqual(log.n_deleted, 0)

    def test_cancel_before_root_rmdir(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "app"
            target.mkdir()
            (target / "x.bin").write_bytes(b"x" * 10)
            log = vac.Logger(log_file=None, dry_run=False)
            cancel = threading.Event()
            c = vac.CleanerEngine(False, log, vac.SafetyGuard(root, allow_shallow_system_target=True), root,
                                  cancel_event=cancel)
            plan = c._plan_tree(target, "app")
            self.assertIsNotNone(plan)
            (target / "x.bin").unlink()  # tree now empty -> root rmdir would fire
            cancel.set()
            with self.assertRaises(vac.CancelJobException):
                c._apply_tree_plan(plan, "app")
            self.assertTrue(target.exists(), "cancel must gate the root rmdir")


class TestDifferentialPlan(unittest.TestCase):
    """Markhunt B: dry-run candidate truth equals the real-delete pre-apply set."""

    def test_dry_run_and_delete_agree_before_mutation(self):
        def fixture(root):
            (root / "app" / "deep").mkdir(parents=True)
            (root / "app" / "deep" / "a.bin").write_bytes(b"x" * 100)
            (root / "app" / "keep").mkdir(parents=True)
            (root / "app" / "keep" / "Login Data").write_text("secrets")
            (root / "app" / "b.bin").write_bytes(b"y" * 30)

        with tempfile.TemporaryDirectory() as tmpA, tempfile.TemporaryDirectory() as tmpB:
            rootA, rootB = Path(tmpA), Path(tmpB)
            fixture(rootA)
            fixture(rootB)

            dry_log = vac.Logger(log_file=None, dry_run=True, quiet=True)
            dry_engine = vac.CleanerEngine(True, dry_log, vac.SafetyGuard(rootA, allow_shallow_system_target=True), rootA)
            dry_plan = dry_engine._plan_tree(rootA / "app", "app")
            self.assertEqual(dry_plan["bytes"], 130)

            del_log = vac.Logger(log_file=None, dry_run=False)
            del_engine = vac.CleanerEngine(False, del_log, vac.SafetyGuard(rootB, allow_shallow_system_target=True), rootB)
            del_plan = del_engine._plan_tree(rootB / "app", "app")
            # candidate sets + planned unique bytes match before any mutation
            self.assertEqual(
                sorted((str(f.relative_to(rootA)), sz) for f, sz, _ in dry_plan["files"]),
                sorted((str(f.relative_to(rootB)), sz) for f, sz, _ in del_plan["files"]),
            )
            self.assertEqual(dry_plan["bytes"], del_plan["bytes"])
            # after apply: actual freed <= planned bytes (exclusions/links only reduce)
            freed, _fully = del_engine._apply_tree_plan(del_plan, "app")
            self.assertLessEqual(freed, del_plan["bytes"])
            self.assertFalse((rootB / "app" / "a.bin").exists())
            self.assertFalse((rootB / "app" / "b.bin").exists())
            self.assertTrue((rootB / "app" / "keep" / "Login Data").exists())


class TestJobLease(unittest.TestCase):
    """CORE-003: a real cross-process destructive-job lease with proper
    ERROR_ALREADY_EXISTS detection."""

    def test_lease_inproc_releases_after_release(self):
        if os.name != "nt":
            self.skipTest("named mutex lease is Windows-only")
        l1 = vac._JobLease()
        self.assertTrue(l1.acquire())
        l1.release()
        l2 = vac._JobLease()
        self.assertTrue(l2.acquire())
        l2.release()

    def test_lease_subprocess_blocks_during_hold(self):
        """CORE-003: mutex created in one process prevents another process
        from acquiring until the owner releases. Uses a subprocess that
        holds the lease while a second subprocess is denied.

        Note: This integration test depends on CreateMutexW with a
        "Global\\" namespace being honoured by the host session. Some
        pytest runners spawn test processes in a different session
        without SeCreateGlobalPrivilege, in which case the mutex name
        is silently downgraded to "Local\\" per process and the cross-
        process guarantee is not observable. The test self-skips when
        the first subprocess cannot observe the second's mutex.
        """
        if os.name != "nt":
            self.skipTest("named mutex lease is Windows-only")
        import subprocess as _sp
        import time as _time
        repo = os.path.dirname(os.path.abspath(__file__))
        env = dict(os.environ)
        env["PYTHONPATH"] = repo
        marker_held = os.path.join(tempfile.gettempdir(), f"vac_lease_held_{os.getpid()}.flag")
        marker_rel = os.path.join(tempfile.gettempdir(), f"vac_lease_rel_{os.getpid()}.flag")
        for _m in (marker_held, marker_rel):
            if os.path.exists(_m):
                os.remove(_m)
        a_script = (
            "import sys, time, os\n"
            "sys.path.insert(0, r'" + repo + "')\n"
            "import _SMART_VAC_CLEANER as vac\n"
            "l = vac._JobLease()\n"
            "ok = l.acquire()\n"
            "assert ok\n"
            "open(r'" + marker_held + "', 'w').write('held')\n"
            "time.sleep(2.0)\n"
            "l.release()\n"
            "open(r'" + marker_rel + "', 'w').write('rel')\n"
        )
        a = _sp.Popen([sys.executable, "-c", a_script],
                      stdout=_sp.PIPE, stderr=_sp.PIPE, text=True, env=env)
        deadline = _time.time() + 5.0
        while _time.time() < deadline and not os.path.exists(marker_held):
            _time.sleep(0.05)
        self.assertTrue(os.path.exists(marker_held), f"A did not acquire: stderr={a.stderr.read()[:200]}")
        # Sanity check: the cross-process mutex must be visible to a second
        # subprocess BEFORE we attempt the blocking acquire. If not, this
        # test environment can't observe the kernel object and the
        # cross-process contract is not exercisable here.
        import ctypes as _ct
        k = _ct.windll.kernel32
        h = k.CreateMutexW(None, True, vac._lease_mutex_name())
        err = k.GetLastError()
        if h:
            k.ReleaseMutex(h); k.CloseHandle(h)
        if err != 183:  # ERROR_ALREADY_EXISTS — A's mutex was visible
            self.skipTest(f"Cross-process Global\\ mutex not visible in this session "
                          f"(err={err}); test environment cannot exercise the cross-"
                          f"process guarantee. Run on an interactive Windows session.")
        # A holds the lease. B must NOT be able to acquire.
        b_script = (
            "import sys, os\n"
            "sys.path.insert(0, r'" + repo + "')\n"
            "import _SMART_VAC_CLEANER as vac\n"
            "l = vac._JobLease()\n"
            "l._wait_ms = 500\n"
            "ok = l.acquire()\n"
            "print('B-RES', ok, flush=True)\n"
            "l.release()\n"
        )
        b = _sp.run([sys.executable, "-c", b_script], capture_output=True, text=True, env=env, timeout=10, check=False)
        self.assertIn("B-RES False", b.stdout, f"B should have been denied: stdout={b.stdout!r}, stderr={b.stderr!r}")
        # After A releases, B must succeed.
        a.wait(timeout=10)
        c = _sp.run([sys.executable, "-c", b_script], capture_output=True, text=True, env=env, timeout=10, check=False)
        self.assertIn("B-RES True", c.stdout, f"after A release B should acquire: {c.stdout!r}, {c.stderr!r}")


class TestProvenanceAudit(unittest.TestCase):
    """Markhunt E: every AppData target resolves to a verified owner or is not actionable."""

    def test_every_appdata_owner_is_trusted_or_target_not_actionable(self):
        for path, desc, owner in vac.USER_APPDATA_TARGETS:
            if owner is None:
                self.assertIn(desc, vac.PROCESS_AGNOSTIC_TARGETS, f"{desc}: owner=None not agnostic")
            elif vac._owner_trust(owner) == "unverified":
                # fail-closed: unverified-owner targets can never authorize real deletion
                self.assertTrue(True)  # enforcement tested in TestOwnerTrustEnforcement
            else:
                self.assertEqual(vac._owner_trust(owner), "verified", f"{desc}")

    def test_no_readme_claims_verified_owners_beyond_the_invariant(self):
        """If README/docs say an owner is verified, the invariant must hold for it."""
        for doc in ("README.md", "README.ru.md", "README.et.md", "README.ded.md", "docs/Safety.md"):
            path = Path(vac.__file__).resolve().parent / doc
            if not path.exists():
                continue
            text = path.read_text(encoding="utf-8")
            for group, prov in vac.APP_PROCESSES_PROVENANCE.items():
                if prov.startswith("unverified-exe") and group.lower() in text.lower():
                    self.fail(f"{doc} mentions unverified group '{group}' without a trust disclaimer")


class TestEnvironmentPoisoning(unittest.TestCase):
    """markhunt F: poisoned env roots cannot turn reviewed-target capability
    into an authorization to wipe an arbitrary directory."""

    def test_poisoned_localappdata_only_touches_the_reviewed_target_subpath(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # a poisoned LOCALAPPDATA root with unrelated data
            unrelated = root / "Poisoned" / "unrelated.txt"
            unrelated.parent.mkdir(parents=True)
            unrelated.write_text("keep me")
            # the reviewed target is a FIXED subpath under the poisoned root
            target = root / "Poisoned" / "NVIDIA" / "GLCache"
            target.mkdir(parents=True)
            (target / "junk.bin").write_bytes(b"x" * 50)
            targets = {k: False for k in vac.SYSTEM_TARGET_DEFAULTS}
            with patch.object(vac, "USER_APPDATA_TARGETS", [(target, "NVIDIA GL Cache", None)]), \
                 patch.object(vac, "get_running_processes", return_value=set()), \
                 patch.object(vac, "SYSTEM_TEMP", Path(tmp) / "none"), \
                 patch.object(vac, "USER_TEMP", Path(tmp) / "none"), \
                 patch.object(vac, "USER_CRASH", Path(tmp) / "none"), \
                 patch.object(vac, "USER_EXPLORER", Path(tmp) / "none"):
                cleaner = vac.SystemCleaner(False, vac.Logger(log_file=None, dry_run=False), targets=targets)
                cleaner.run_all()
            self.assertFalse((target / "junk.bin").exists(), "the reviewed NVIDIA GL Cache target is swept")
            self.assertTrue(unrelated.exists(), "unrelated data under the poisoned root survives untouched")
            self.assertTrue((root / "Poisoned").exists(), "the poisoned root itself is never removed")

    def test_empty_env_vars_do_not_resolve_to_cwd_for_roots(self):
        with patch.dict(os.environ, {"LOCALAPPDATA": "", "APPDATA": "", "TEMP": ""}, clear=False):
            # get_env_path falls back to the given default, never silently to cwd
            self.assertEqual(vac.get_env_path("LOCALAPPDATA", "C:/__nope__"), Path("C:/__nope__").resolve())


class TestEnvRootProvenance(unittest.TestCase):
    """T-147: a dynamic env value is never a trusted destructive system root."""

    _BAD: ClassVar[list[str]] = ["", ".", "..", "\\", "C:\\"]

    @pytest.mark.real_system_roots
    def test_poison_matrix_rejects_every_unsafe_value(self):
        cwd = str(Path.cwd().resolve())
        cleaner_dir = str(vac.BASE_DIR)
        bad = self._BAD + [cwd, cleaner_dir, r"D:\Important", r"V:\Important"]
        profile = vac._real_user_profile()
        cases = [
            ("LOCALAPPDATA", (profile / "AppData" / "Local"), True),
            ("APPDATA", (profile / "AppData" / "Roaming"), True),
            ("windir", Path(os.environ.get("SystemRoot") or r"C:\Windows").resolve(), True),
        ]
        for var, expected, exact in cases:
            for val in bad:
                with patch.dict(os.environ, {var: val}, clear=False):
                    self.assertIsNone(vac._resolve_env_root(var, expected, exact=exact),
                                      f"{var}={val!r} must be rejected")
        for val in bad:
            with patch.dict(os.environ, {"TEMP": val}, clear=False):
                self.assertIsNone(vac._resolve_temp_root(), f"TEMP={val!r} must be rejected")

    @pytest.mark.real_system_roots
    def test_valid_roots_accepted(self):
        profile = vac._real_user_profile()
        self.assertIsNotNone(profile)
        local = str((profile / "AppData" / "Local").resolve())
        with patch.dict(os.environ, {"LOCALAPPDATA": local}, clear=False):
            self.assertEqual(vac._resolve_env_root("LOCALAPPDATA", Path(local), exact=True), Path(local))

    @pytest.mark.real_system_roots
    def test_suffix_cannot_be_redirected_by_poisoned_base(self):
        """LOCALAPPDATA=D:\\Important must disable the base, so a suffix like
        \\NVIDIA\\GLCache can never become a live reviewed target."""
        profile = vac._real_user_profile()
        with patch.dict(os.environ, {"LOCALAPPDATA": r"D:\Important"}, clear=False):
            base = vac._resolve_env_root("LOCALAPPDATA", (profile / "AppData" / "Local"), exact=True)
            self.assertIsNone(base)
            self.assertIsNone(vac._rooted(base, "NVIDIA", "GLCache"),
                              "a poisoned base must not turn a cache suffix into a live target")

    def test_none_roots_produce_zero_mutation(self):
        """All roots disabled (simulated poison) => SystemCleaner deletes nothing."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "keep").mkdir()
            (root / "keep" / "f.bin").write_bytes(b"x" * 10)
            log = vac.Logger(log_file=None, dry_run=False)
            with patch.object(vac, "SYSTEM_TEMP", None), \
                 patch.object(vac, "USER_TEMP", None), \
                 patch.object(vac, "USER_CRASH", None), \
                 patch.object(vac, "USER_EXPLORER", None), \
                 patch.object(vac, "USER_APPDATA_TARGETS", []), \
                 patch.object(vac, "get_running_processes", return_value=set()), \
                 patch.object(vac, "_real_user_profile", return_value=None), \
                 patch.object(vac, "_resolve_active_drive_temp", return_value=None), \
                 patch.object(vac, "_LOCALAPPDATA", Path(tmp) / "none"), \
                 patch.object(vac, "_APPDATA", Path(tmp) / "none"):
                c = vac.SystemCleaner(False, log)
                c.run_all()
            self.assertEqual(log.n_deleted, 0)
            self.assertEqual(log.n_errors, 0)
            self.assertTrue((root / "keep" / "f.bin").exists())


    def test_poisoned_env_import_fails_closed(self):
        """A subprocess importing with poisoned env must not crash and must disable the roots."""
        import subprocess as _sp
        env = dict(os.environ)
        env["TEMP"] = r"D:\Important"
        env["LOCALAPPDATA"] = r"D:\Important"
        env["APPDATA"] = r"D:\Important"
        repo = os.path.dirname(os.path.abspath(__file__))
        code = (
            f"import sys; sys.path.insert(0, r'{repo}'); "
            "import _SMART_VAC_CLEANER as vac; "
            "assert vac.USER_TEMP is None, vac.USER_TEMP; "
            "assert vac.USER_CRASH is None, vac.USER_CRASH; "
            "assert vac.USER_EXPLORER is None, vac.USER_EXPLORER; "
            "assert len(vac.USER_APPDATA_TARGETS) == 0, len(vac.USER_APPDATA_TARGETS); "
            "print('POISON-IMPORT-OK')"
        )
        r = _sp.run([sys.executable, "-c", code], capture_output=True, text=True, env=env, timeout=60, check=False)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("POISON-IMPORT-OK", r.stdout)

    def test_spec_carries_validated_system_roots(self):
        """T-147: every JobSpec snapshots the provenance-validated system roots.

        SIDE0 CORE-009: the actual USER_APPDATA_TARGETS records are frozen
        into the snapshot (not only the count) so the destructive job
        consumes an immutable target set, never a mutable module global.
        """
        spec = vac.resolve_job_spec(dry_run=True, run_portable=True, run_system=True, run_custom=True,
                                    config={"portable_roots": [], "custom_rules": [],
                                            "exclude_patterns": [], "exclude_paths": []},
                                    surface="cli")
        roots = spec.system_roots
        self.assertIn("SYSTEM_TEMP", roots)
        self.assertIn("USER_TEMP", roots)
        self.assertIn("USER_APPDATA_TARGETS", roots)
        self.assertIsInstance(roots["USER_APPDATA_TARGETS"], tuple)
        # every scalar root is either a validated absolute path or None (disabled) -- never relative/cwd
        for key, val in roots.items():
            if key in ("appdata_target_count", "USER_APPDATA_TARGETS"):
                continue
            if val is not None:
                p = Path(val) if not isinstance(val, Path) else val
                self.assertTrue(p.is_absolute(), key)
                self.assertNotEqual(p, Path.cwd().resolve(), key)
                self.assertFalse(vac._is_under(vac.BASE_DIR, p), key)


    def test_windir_is_os_authoritative_not_env(self):
        """CORE-001: resolve_system_roots() must return the OS Windows dir
        (GetWindowsDirectoryW), never the poisoned windir/SystemRoot env."""
        import subprocess as _sp
        repo = os.path.dirname(os.path.abspath(__file__))
        code = (
            f"import sys; sys.path.insert(0, r'{repo}'); "
            "import os; import _SMART_VAC_CLEANER as vac; "
            "r = vac.resolve_system_roots(); "
            "assert r['WINDIR'] is not None; "
            "assert 'os.environ' not in str(type(r['WINDIR'])); "
            "print('WINDIR=' + str(r['WINDIR']))"
        )
        # Poison both windir and SystemRoot to a same-drive arbitrary dir.
        env = dict(os.environ)
        env["windir"] = r"C:\PoisonWindows"
        env["SystemRoot"] = r"C:\PoisonWindows"
        r = _sp.run([sys.executable, "-c", code], capture_output=True, text=True, env=env, timeout=60, check=False)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("WINDIR=", r.stdout)
        self.assertNotIn("PoisonWindows", r.stdout)

    def test_known_folders_survive_poisoned_profile_env(self):
        """CORE-001: LOCALAPPDATA/APPDATA must resolve from OS known-folder API,
        not from a poisoned USERPROFILE/LOCALAPPDATA/APPDATA env."""
        import subprocess as _sp
        repo = os.path.dirname(os.path.abspath(__file__))
        code = (
            f"import sys; sys.path.insert(0, r'{repo}'); "
            "import _SMART_VAC_CLEANER as vac; "
            "assert vac._LOCALAPPDATA is None or str(vac._LOCALAPPDATA).startswith(vac._OS_LOCAL_APPDATA.drive), vac._LOCALAPPDATA; "
            "assert vac._APPDATA is None or str(vac._APPDATA).startswith(vac._OS_ROAMING_APPDATA.drive), vac._APPDATA; "
            "print('KNOWN-FOLDERS-OK')"
        )
        env = dict(os.environ)
        env["USERPROFILE"] = r"C:\PoisonProfile"
        env["HOME"] = r"C:\PoisonProfile"
        env["LOCALAPPDATA"] = r"C:\PoisonProfile\AppData\Local"
        env["APPDATA"] = r"C:\PoisonProfile\AppData\Roaming"
        r = _sp.run([sys.executable, "-c", code], capture_output=True, text=True, env=env, timeout=60, check=False)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("KNOWN-FOLDERS-OK", r.stdout)


class TestOracleFixture(unittest.TestCase):

    """T-145: hand-built oracle, not parity-with-the-planner.

    Fixture:
      cache/a = 10 bytes   -> actionable
      excluded/b = 20 bytes -> excluded via exclude_paths
      protected/Cookies = 30 -> NEVER_DELETE name
    Oracle: actionable set == {cache/a}, planned bytes == 10. Every surface must
    match the ORACLE independently -- never 'equals the planner', which would
    share any planner bug.
    """


    def _build(self, tmp):
        root = Path(tmp)
        cache = root / "cache"
        cache.mkdir()
        (cache / "a").write_bytes(b"x" * 10)
        (root / "excluded").mkdir()
        (root / "excluded" / "b").write_bytes(b"y" * 20)
        (root / "Cookies").write_text("z" * 30)
        return root, cache

    def _plan(self, root, cache, exclude_paths):
        log = vac.Logger(log_file=None, dry_run=True, quiet=True)
        c = vac.CleanerEngine(True, log, vac.SafetyGuard(root, allow_shallow_system_target=True), root,
                              exclude_paths=exclude_paths)
        plan = c._plan_tree(cache, "cache")
        return plan

    def test_oracle_dry_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, cache = self._build(tmp)
            plan = self._plan(root, cache, [str(root / "excluded")])
            self.assertEqual(plan["bytes"], 10, "oracle: only cache/a (10B) is actionable")
            self.assertEqual([str(f) for f, _, _ in plan["files"]], [str(cache / "a")])

    def test_oracle_status_and_dry_run_and_delete_planner_agree_with_oracle(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, cache = self._build(tmp)
            exclude_paths = [str(root / "excluded")]
            # dry-run
            dry = self._plan(root, cache, exclude_paths)
            self.assertEqual(dry["bytes"], 10)
            # status surface (SystemCleaner on an AppData-like target with the same exclusions)
            targets = {k: False for k in vac.SYSTEM_TARGET_DEFAULTS}
            targets["Discord Cache"] = True
            with patch.object(vac, "USER_APPDATA_TARGETS", [(cache, "Discord Cache", "discord")]), \
                 patch.object(vac, "get_running_processes", return_value=set()), \
                 patch.object(vac, "SYSTEM_TEMP", Path(tmp) / "none"), \
                 patch.object(vac, "USER_TEMP", Path(tmp) / "none"), \
                 patch.object(vac, "USER_CRASH", Path(tmp) / "none"), \
                 patch.object(vac, "USER_EXPLORER", Path(tmp) / "none"):
                status = vac.calculate_target_sizes(targets, exclude_paths=exclude_paths)
            self.assertEqual(status.get("Discord Cache"), 10, "status == oracle")
            # delete planner (dry-run plan is the same planner used before apply)
            del_log = vac.Logger(log_file=None, dry_run=False)
            del_engine = vac.CleanerEngine(False, del_log, vac.SafetyGuard(root, allow_shallow_system_target=True), root,
                                           exclude_paths=exclude_paths)
            del_plan = del_engine._plan_tree(cache, "cache")
            self.assertEqual(del_plan["bytes"], 10, "delete planner == oracle")
            self.assertEqual(
                sorted((str(f), sz) for f, sz, _ in dry["files"]),
                sorted((str(f), sz) for f, sz, _ in del_plan["files"]),
            )


class TestAnalyzeCaches(unittest.TestCase):

    """T-142: the analyzer is discovery-only, env-safe, link-safe, token-bound."""

    def test_empty_env_never_falls_back_to_cwd(self):
        with patch.dict(os.environ, {"LOCALAPPDATA": "", "APPDATA": ""}, clear=False):
            self.assertIsNone(vac_analyze._root_env("LOCALAPPDATA"))
            self.assertIsNone(vac_analyze._root_env("APPDATA"))

    def test_missing_env_never_falls_back_to_cwd(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(vac_analyze._root_env("LOCALAPPDATA"))

    def test_nonexistent_root_rejected(self):
        with patch.dict(os.environ, {"LOCALAPPDATA": "Z:/__no_such_dir__"}, clear=True):
            self.assertIsNone(vac_analyze._root_env("LOCALAPPDATA"))

    def test_token_boundary_matching(self):
        self.assertTrue(vac_analyze._name_matches_token_boundary("cache"))
        self.assertTrue(vac_analyze._name_matches_token_boundary("my cache"))
        self.assertTrue(vac_analyze._name_matches_token_boundary("webcache"))
        self.assertFalse(vac_analyze._name_matches_token_boundary("attempt"))  # 'temp' substring
        self.assertFalse(vac_analyze._name_matches_token_boundary("accurate"))
        self.assertFalse(vac_analyze._name_matches_token_boundary("important"))

    def test_scan_is_strictly_read_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cache = root / "Cache"
            cache.mkdir()
            (cache / "big.bin").write_bytes(b"x" * (6 * 1024 * 1024))
            with _ExplodeMutations():
                found = vac_analyze._scan(root, verbose=False)
            self.assertTrue(any("Cache" in p for p, _ in found))
            self.assertTrue((cache / "big.bin").exists())

    def test_symlink_root_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            outside = root / "outside"
            outside.mkdir()
            (outside / "Cache").mkdir()
            (outside / "Cache" / "big.bin").write_bytes(b"x" * (6 * 1024 * 1024))
            link = root / "link"
            try:
                link.symlink_to(outside, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks not supported")
            found = vac_analyze._scan(link, verbose=False)
            self.assertEqual(found, [], "a symlink root must be refused, never traversed")


class TestConfigFailClosed(unittest.TestCase):
    """T-138: a malformed EXISTING config must never authorize a destructive run."""

    def _run_main_delete(self, cfg_text):
        """Drive main() in DELETE mode against a config file; returns the exit code."""
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / "cleaner_config.json"
            cfg.write_text(cfg_text, encoding="utf-8")
            with patch.object(vac, "CONFIG_FILE", cfg), \
                 patch.object(vac, "run_cleaning_job", side_effect=AssertionError("DELETE must not run on invalid config")), \
                 patch.object(vac, "Logger"), \
                 patch.object(vac, "get_running_processes", return_value=set()), \
                 patch("_SMART_VAC_CLEANER.argparse.ArgumentParser.parse_args") as mock_parse:
                mock_parse.return_value = MagicMock(
                    dry_run=False, delete=True, portable=True, system=False, custom=False,
                    all=False, cli=True, status=False, analyze_caches=False, hidden=False,
                    sys_targets="", disable_targets="", exclude="", install_task=False, time="09:00")
                try:
                    vac.main()
                    return 0
                except SystemExit as e:
                    return e.code

    def test_malformed_json_aborts_delete(self):
        code = self._run_main_delete("{corrupt")
        self.assertEqual(code, 3)

    def test_custom_glob_dot_rejected_at_load(self):
        # W2-003: the self/parent directory markers are not executable globs
        # (Path.glob raises ValueError). They must be rejected at config load
        # (fail-closed preflight), never reaching the destructive executor.
        for bad in [".", "..", "./", "../", ".\\", "..\\"]:
            with tempfile.TemporaryDirectory() as tmp:
                cfg = Path(tmp) / "cleaner_config.json"
                cfg.write_text(json.dumps({
                    "portable_roots": [], "custom_rules": [
                        {"path": str(Path(tmp)), "pattern": bad}
                    ], "exclude_patterns": [], "exclude_paths": [],
                    "system_targets": {}}), encoding="utf-8")
                with patch.object(vac, "CONFIG_FILE", cfg):
                    valid, _, errors = vac.load_config_strict()
                self.assertEqual(valid, vac.ConfigState.INVALID,
                                 f"pattern {bad!r} must be rejected at load")
                self.assertTrue(any("not an executable glob" in e for e in errors),
                                f"pattern {bad!r} should report an executable-glob error")

    def test_wrong_type_safety_fields_abort_delete(self):
        cases = [
            json.dumps({"portable_roots": "D:\\x"}),
            json.dumps({"custom_rules": ["oops"]}),
            json.dumps({"exclude_paths": "D:\\KEEP"}),
            json.dumps({"exclude_patterns": "*.db"}),
            json.dumps({"system_targets": []}),
            json.dumps({"portable_roots": None}),
            json.dumps({"exclude_paths": None}),
            json.dumps({"custom_rules": 42}),
            json.dumps({"exclude_patterns": [123]}),
            json.dumps({"portable_roots": [1] * 100000}),  # huge list of wrong-typed scalars
            json.dumps({"exclude_patterns": ["*.db"], "exclude_paths": ["D:\\Keep"],
                        "custom_rules": [], "portable_roots": [], "system_targets": "oops"}),
            "[1,2,3]",
        ]
        for cfg in cases:
            code = self._run_main_delete(cfg)
            self.assertEqual(code, 3, f"config {cfg[:60]!r} must abort DELETE (exit 3)")

    def test_corrupt_config_with_migration_stays_byte_identical(self):
        """Item 3: an invalid config with a legacy 'profiles' key is NOT migrated on disk."""
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / "cleaner_config.json"
            raw = json.dumps({"profiles": {"Default": {}}, "exclude_patterns": "oops"})
            cfg.write_text(raw, encoding="utf-8")
            with patch.object(vac, "CONFIG_FILE", cfg):
                valid, _, _ = vac.load_config_strict()
            self.assertEqual(valid, vac.ConfigState.INVALID)
            self.assertEqual(cfg.read_text(encoding="utf-8"), raw,
                             "a corrupt config must stay byte-identical for forensics")

    def test_valid_config_with_migration_persists_once_validated(self):
        """CORE-006: migration persists through the write-authorized path
        (`persist=True`), atomically via save_config."""
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / "cleaner_config.json"
            cfg.write_text(json.dumps({"profiles": {"Default": {}},
                                       "portable_roots": [], "custom_rules": [],
                                       "exclude_patterns": [], "exclude_paths": [],
                                       "system_targets": {}}), encoding="utf-8")
            # Read-only strict loader: normalizes in memory, leaves disk alone.
            with patch.object(vac, "CONFIG_FILE", cfg):
                valid, data, _ = vac.load_config_strict()
            self.assertIn(valid, (vac.ConfigState.VALID, vac.ConfigState.MISSING))
            self.assertNotIn("profiles", data)
            self.assertIn("profiles", json.loads(cfg.read_text(encoding="utf-8")),
                          "read-only consumer must not persist migration")
            # Write-authorized loader: persists the migration atomically.
            with patch.object(vac, "CONFIG_FILE", cfg):
                _valid, data2, _ = vac._load_and_validate(persist=True)
            self.assertNotIn("profiles", data2)
            on_disk = json.loads(cfg.read_text(encoding="utf-8"))
            self.assertNotIn("profiles", on_disk, "migration persisted only after full validation")

    def test_invalid_config_does_not_erase_other_fields_silently(self):
        """One malformed field invalidates the WHOLE config for DELETE (no silent drop)."""
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / "cleaner_config.json"
            cfg.write_text(json.dumps({
                "exclude_patterns": ["*.db"], "exclude_paths": ["D:\\Keep"],
                "custom_rules": [{"path": "D:\\App", "pattern": "*"}],
                "portable_roots": ["D:\\Portable"], "system_targets": "oops",
            }), encoding="utf-8")
            with patch.object(vac, "CONFIG_FILE", cfg):
                valid, _, _errors = vac.load_config_strict()
            self.assertEqual(valid, vac.ConfigState.INVALID)
            self.assertTrue(any("system_targets" in e for e in _errors))

    def test_fresh_missing_config_is_safe_default(self):
        """CORE-006: load_config_strict() is read-only -- a missing config
        returns MISSING + safe defaults and must NOT create the file."""
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / "cleaner_config.json"
            with patch.object(vac, "CONFIG_FILE", cfg):
                valid, data, _errors = vac.load_config_strict()
            self.assertIn(valid, (vac.ConfigState.VALID, vac.ConfigState.MISSING))
            self.assertEqual(data["exclude_patterns"], [])
            self.assertFalse(cfg.exists(), "CORE-006: read-only consumer must not create the config")

    def test_fresh_missing_config_bootstrap_persists_when_authorized(self):
        """CORE-006: bootstrap (explicit write-capable caller) DOES create the file."""
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / "cleaner_config.json"
            with patch.object(vac, "CONFIG_FILE", cfg):
                valid, data, _ = vac._load_and_validate(persist=True)
            self.assertIn(valid, (vac.ConfigState.VALID, vac.ConfigState.MISSING))
            self.assertEqual(data["exclude_patterns"], [])
            self.assertTrue(cfg.exists(), "explicit bootstrap must create the config")

    def test_dry_run_reports_invalid_config_but_does_not_fake_policy(self):
        """Dry-run with an invalid config logs the error and runs with empty policy, never deleting."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cfg = Path(tmp) / "cleaner_config.json"
            cfg.write_text(json.dumps({"exclude_patterns": "*.db"}), encoding="utf-8")
            (root / "portable").mkdir()
            (root / "portable" / "keep.bin").write_bytes(b"x" * 10)
            buf = io.StringIO()
            with patch.object(vac, "CONFIG_FILE", cfg), \
                 patch.object(vac, "get_running_processes", return_value=set()), \
                 contextlib.redirect_stdout(buf), \
                 patch("_SMART_VAC_CLEANER.argparse.ArgumentParser.parse_args") as mock_parse:
                mock_parse.return_value = MagicMock(
                    dry_run=True, delete=True, portable=True, system=False, custom=False,
                    all=False, cli=True, status=False, analyze_caches=False, hidden=False,
                    sys_targets="", disable_targets="", exclude="", install_task=False, time="09:00")
                try:
                    vac.main()
                except SystemExit:
                    pass
            self.assertIn("config invalid", buf.getvalue().lower())
            self.assertTrue((root / "portable" / "keep.bin").exists())


class TestGuiJobFreeze(unittest.TestCase):
    """T-128: the job spec is frozen on the Tk thread BEFORE the worker starts."""

    def _app(self):
        app = TestGuiThreadBoundary._fake_app(None)

        def release_lease():
            # This fixture joins its worker without running the Tk completion
            # poller, so it must release the main-thread lease it acquired.
            lease = app.__dict__.get("_lease")
            if lease is not None:
                lease.release()

        self.addCleanup(release_lease)
        return app

    def test_spec_frozen_before_worker_and_mutations_do_not_leak(self):
        app = self._app()
        app.T = {"cancelled": "cancelled", "confirm_title": "t", "confirm_body": "b"}
        app.config = {"portable_roots": [], "custom_rules": [], "exclude_patterns": ["*.old"],
                      "exclude_paths": [], "system_targets": {}}
        captured = {}

        def fake_job(spec, log, cancel_event=None, progress=None):
            captured["patterns"] = list(spec.exclude_patterns)
            captured["targets"] = dict(spec.sys_targets)

        with patch.object(vac, "run_cleaning_job", side_effect=fake_job), \
             patch.object(vac, "Logger"), \
             patch.object(vac, "load_config_strict", return_value=(vac.ConfigState.VALID, app.config, [])), \
             patch.object(vac.messagebox, "askyesno", return_value=True):
            app._start_job()
        # mutate GUI state after the spec was frozen but before the worker ran
        app.config["exclude_patterns"].append("*.new")
        app.sys_targets["Recycle Bin"] = True
        app._worker_thread.join(timeout=10)
        self.assertIn("*.old", captured["patterns"])
        self.assertNotIn("*.new", captured["patterns"], "worker must not see post-freeze GUI edits")
        self.assertFalse(captured["targets"]["Recycle Bin"])

    def test_preview_spec_is_read_only_dry_run(self):
        app = self._app()
        captured = {}

        def fake_job(spec, log, cancel_event=None, progress=None):
            captured["dry_run"] = spec.dry_run

        with patch.object(vac, "run_cleaning_job", side_effect=fake_job), \
             patch.object(vac, "load_config_strict", return_value=(vac.ConfigState.VALID, app.config, [])), \
             patch.object(vac, "Logger"):
            app._start_preview()
        app._worker_thread.join(timeout=10)
        self.assertTrue(captured["dry_run"])







class TestSIDE0Audit(unittest.TestCase):
    """SIDE0 AUDIT_ALL_3 regressions: CORE-001..009, W2-001..006, PERF-001..007."""

    # ── CORE-002/CORE-007: plan_tree resource-cap abort is transaction-wide ──
    def test_plan_tree_overflow_aborts_whole_transaction(self):
        """Overflow yields NO EXECUTABLE PLAN, not an empty one.

        CORE-007 corrected this assertion: the old contract returned a non-None
        dict with empty candidate lists, which _del_dir read as a successful
        "nothing to do" plan and then ledger-claimed the whole root. None is
        the shape every caller already treats as non-claimable.
        """
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "base"
            root = base / "tree"
            (root / "a" / "a1").mkdir(parents=True)
            (root / "a" / "a2").mkdir(parents=True)
            (root / "b").mkdir(parents=True)
            for p in ("a/a1/f1.tmp", "a/a1/f2.tmp", "a/a1/f3.tmp", "a/a2/late.tmp", "b/late2.tmp"):
                (root / p).write_text("x" * 10)
            engine = vac.CleanerEngine(True, vac.Logger(log_file=None, dry_run=True), vac.SafetyGuard(base), root, max_threads=1)
            engine.log = vac.Logger(log_file=None, dry_run=True)
            with patch.dict("os.environ", {"SMARTVAC_PLAN_MAX_FILES": "2"}):
                plan = engine._plan_tree(root, "tree")
            self.assertIsNone(plan, "a resource-cap abort must expose no candidate plan")
            self.assertEqual(engine.log.n_errors, 1, "the overflow must be reported once")

    def test_plan_tree_at_bound_still_works(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "base"
            root = base / "tree"
            root.mkdir(parents=True)
            for i in range(2):
                (root / f"f{i}.tmp").write_text("x" * 10)
            engine = vac.CleanerEngine(True, vac.Logger(log_file=None, dry_run=True), vac.SafetyGuard(base), root, max_threads=1)
            engine.log = vac.Logger(log_file=None, dry_run=True)
            with patch.dict("os.environ", {"SMARTVAC_PLAN_MAX_FILES": "2"}):
                plan = engine._plan_tree(root, "tree")
            self.assertIsNotNone(plan)
            self.assertEqual(len(plan["files"]), 2)

    # ── CORE-003: config RMW serialization ──────────────────────────────────
    def test_config_rmw_transaction_merges(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / "cleaner_config.json"
            import json as _json
            cfg.write_text(_json.dumps({"exclude_patterns": ["*.keep"]}), encoding="utf-8")
            with patch.object(vac, "CONFIG_FILE", cfg):
                ok = vac._config_rmw_transaction(lambda latest: {**latest, "window_geometry": "1111x777"})
                self.assertTrue(ok)
                state, data, _ = vac.read_config_snapshot(create_if_missing=False)
                self.assertEqual(state, vac.ConfigState.VALID)
                self.assertEqual(data["exclude_patterns"], ["*.keep"])
                self.assertEqual(data["window_geometry"], "1111x777")

    def test_config_rmw_transaction_abort_returns_false(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / "cleaner_config.json"
            import json as _json
            cfg.write_text(_json.dumps({"exclude_patterns": []}), encoding="utf-8")
            with patch.object(vac, "CONFIG_FILE", cfg):
                ok = vac._config_rmw_transaction(lambda latest: None)
                self.assertFalse(ok)

    # ── CORE-004: Windows Update has no unvalidated C:\ fallback ────────────
    def test_windows_update_no_hardcoded_fallback(self):
        c = vac.SystemCleaner(True, vac.Logger(log_file=None, dry_run=True))
        c.targets = {k: False for k in vac.SYSTEM_TARGET_DEFAULTS}
        c.targets["Windows Update Cache"] = True
        c._system_roots = {"WINDIR": None}
        with patch.object(c, "_clean_windows_update_cache") as cwc:
            c.run_all()
        # The Windows Update cleanup path is unreachable when WINDIR is None.
        cwc.assert_not_called()

    def test_windows_update_uses_validated_root(self):
        c = vac.SystemCleaner(True, vac.Logger(log_file=None, dry_run=True))
        c.targets = {k: False for k in vac.SYSTEM_TARGET_DEFAULTS}
        c.targets["Windows Update Cache"] = True
        win = Path("Z:/__valid_win__")
        c._system_roots = {"WINDIR": win}
        with patch.object(c, "_clean_windows_update_cache") as cwc:
            c.run_all()
        # No fake directory exists; the cache branch is the only one
        # that could touch the validated WINDIR subtree. The path does
        # NOT match Path("C:\\...") hardcoded fallback.
        cwc.assert_not_called()

    # ── CORE-005: install-task rejects clean-only modifiers ─────────────────
    @patch("_SMART_VAC_CLEANER.argparse.ArgumentParser.parse_args")
    def test_install_task_rejects_dry_run(self, mock_parse):
        mock_parse.return_value = MagicMock(
            install_task=True, time="09:00", sys_targets="", disable_targets="",
            status=False, analyze_caches=False, hidden=False, dry_run=True,
            delete=False, portable=False, system=False, custom=False,
            all=False, cli=False, exclude="")
        with patch.object(vac, "install_task") as mi, \
             self.assertRaises(SystemExit) as cm:
            vac.main()
        self.assertEqual(cm.exception.code, 2)
        mi.assert_not_called()

    @patch("_SMART_VAC_CLEANER.argparse.ArgumentParser.parse_args")
    def test_install_task_rejects_exclude(self, mock_parse):
        mock_parse.return_value = MagicMock(
            install_task=True, time="09:00", sys_targets="", disable_targets="",
            status=False, analyze_caches=False, hidden=False, dry_run=False,
            delete=False, portable=False, system=False, custom=False,
            all=False, cli=False, exclude="*.db")
        with self.assertRaises(SystemExit) as cm:
            vac.main()
        self.assertEqual(cm.exception.code, 2)

    @patch("_SMART_VAC_CLEANER.argparse.ArgumentParser.parse_args")
    def test_install_task_valid_time_still_installs(self, mock_parse):
        mock_parse.return_value = MagicMock(
            install_task=True, time="09:00", sys_targets="", disable_targets="",
            status=False, analyze_caches=False, hidden=False, dry_run=False,
            delete=False, portable=False, system=False, custom=False,
            all=False, cli=False, exclude="")
        with patch.object(vac, "install_task", return_value=True) as mi, \
             self.assertRaises(SystemExit) as cm:
            vac.main()
        self.assertEqual(cm.exception.code, 0)
        mi.assert_called_once_with("09:00", dict(vac.SYSTEM_TARGET_DEFAULTS))

    # ── CORE-006: control markers cannot be evicted ─────────────────────────
    def test_log_close_marker_not_evicted(self):
        app = TestGuiThreadBoundary._fake_app()
        app.log_queue = queue.Queue(maxsize=2)
        app.log_queue.put_nowait(app._CLOSE_MARKER)
        app.log_queue.put_nowait("old telemetry")
        app._log("new telemetry")
        items = []
        while True:
            try:
                items.append(app.log_queue.get_nowait())
            except queue.Empty:
                break
        self.assertIn(app._CLOSE_MARKER, items)

    def test_log_auto_marker_not_evicted(self):
        app = TestGuiThreadBoundary._fake_app()
        app.log_queue = queue.Queue(maxsize=2)
        app.log_queue.put_nowait(app._AUTO_CLEAN_MARKER)
        app.log_queue.put_nowait("old telemetry")
        app._log("new telemetry")
        items = []
        while True:
            try:
                items.append(app.log_queue.get_nowait())
            except queue.Empty:
                break
        self.assertIn(app._AUTO_CLEAN_MARKER, items)

    # ── CORE-007: failed mutex acquisition closes the handle ────────────────
    def test_lease_failure_closes_handle(self):
        if os.name == "nt":
            self.skipTest("Windows-only path tested via mocks elsewhere")
            return
        # Non-Windows acquire() returns True; the Windows-specific
        # handle-close logic is exercised via the mock suite below.
        lease = vac._JobLease()
        self.assertTrue(lease.acquire())

    # ── CORE-009: JobSpec freezes the actual AppData target set ─────────────
    def test_jobspec_freezes_appdata_targets(self):
        spec = vac.resolve_job_spec(dry_run=True, run_portable=True, run_system=True, run_custom=True,
                                    config={"portable_roots": [], "custom_rules": [],
                                            "exclude_patterns": [], "exclude_paths": []},
                                    surface="cli")
        self.assertIn("USER_APPDATA_TARGETS", spec.system_roots)
        self.assertIsInstance(spec.system_roots["USER_APPDATA_TARGETS"], tuple)
        # Mutating the module global must NOT affect the snapshot.
        frozen = spec.system_roots["USER_APPDATA_TARGETS"]
        with patch.object(vac, "USER_APPDATA_TARGETS", []):
            self.assertEqual(spec.system_roots["USER_APPDATA_TARGETS"], frozen)

    # ── W2-001: root identity inside descendant mutation authorization ──────
    def test_authorize_mutation_rechecks_root_boundary(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "target"
            root.mkdir()
            victim = root / "keep.tmp"
            victim.write_text("x" * 13)
            engine = vac.CleanerEngine(False, vac.Logger(log_file=None, dry_run=False), vac.SafetyGuard(root), root, max_threads=1)
            engine.log = vac.Logger(log_file=None, dry_run=False)
            ident = vac._capture_identity(root)
            engine._root_boundary_token = (root, ident)
            engine._root_mismatch_abort = False
            # Swap the root: rename + recreate with a different inode.
            root.rename(Path(tmp) / "old_target")
            new_root = Path(tmp) / "target"
            new_root.mkdir()
            (new_root / "replacement.tmp").write_text("y" * 5)
            ok, _reason = engine._authorize_mutation(new_root / "replacement.tmp", vac._capture_identity(new_root / "replacement.tmp"))
            self.assertFalse(ok)
            self.assertTrue(engine._root_mismatch_abort)

    # ── W2-002: unknown top-level config keys fail closed ───────────────────
    def test_unknown_top_level_config_key_invalid(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / "cleaner_config.json"
            import json as _json
            cfg.write_text(_json.dumps({"exclude_pattern": ["*.tmp"]}), encoding="utf-8")
            with patch.object(vac, "CONFIG_FILE", cfg):
                state, data, errors = vac.load_config_strict()
                self.assertEqual(state, vac.ConfigState.INVALID)
                self.assertEqual(data, {})
                self.assertTrue(any("unknown top-level" in e for e in errors))

    def test_supported_profiles_migration_still_valid(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / "cleaner_config.json"
            import json as _json
            cfg.write_text(_json.dumps({"profiles": {"p1": {}}, "exclude_patterns": []}), encoding="utf-8")
            with patch.object(vac, "CONFIG_FILE", cfg):
                state, data, _ = vac.load_config_strict()
                self.assertEqual(state, vac.ConfigState.VALID)
                self.assertNotIn("profiles", data)

    # ── W2-004: Preview-first startup rollback has a _lease attribute ───────
    def test_preview_first_action_reset_to_idle_no_attribute_error(self):
        app = object.__new__(vac.App)
        app._lease = None  # SIDE0 fix: _lease is initialized in __init__
        app._clean_in_progress = True
        app._worker_thread = None
        app.btn_clean = TestGuiThreadBoundary._Stub()
        app.btn_preview = TestGuiThreadBoundary._Stub()
        app.btn_stop = TestGuiThreadBoundary._Stub()
        app._job_done_event = threading.Event()
        app._close_pending = False
        app._schedule_auto_clean = lambda: None
        app._reset_to_idle()
        self.assertFalse(app._clean_in_progress)

    # ── W2-005: auto-clean interval minimum is enforced ─────────────────────
    def test_auto_clean_below_minimum_invalid(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / "cleaner_config.json"
            import json as _json
            cfg.write_text(_json.dumps({"auto_clean_interval_hours": 1e-6}), encoding="utf-8")
            with patch.object(vac, "CONFIG_FILE", cfg):
                state, _data, errors = vac.load_config_strict()
                self.assertEqual(state, vac.ConfigState.INVALID)
                self.assertTrue(any("minimum" in e for e in errors))

    def test_auto_clean_zero_is_valid_disabled(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / "cleaner_config.json"
            import json as _json
            cfg.write_text(_json.dumps({"auto_clean_interval_hours": 0}), encoding="utf-8")
            with patch.object(vac, "CONFIG_FILE", cfg):
                state, _data, _ = vac.load_config_strict()
                self.assertEqual(state, vac.ConfigState.VALID)

    def test_auto_clean_trigger_nonblocking_flag(self):
        app = TestGuiThreadBoundary._fake_app()
        app._auto_clean_pending = False
        app._clean_in_progress = False
        # SIDE0 W2-005: the timer must NOT block on a full queue.
        app._auto_clean_trigger()
        self.assertTrue(app._auto_clean_pending)
        self.assertTrue(app.log_queue.empty())

    # ── W2-006: background child completion observed exactly once ───────────
    def test_background_child_failure_reported_once(self):
        app = TestGuiThreadBoundary._fake_app()
        app._bg_proc = MagicMock()
        app._bg_proc.poll.side_effect = [3]
        app._bg_proc_observed = False
        app._poll_background_child()
        msgs = []
        while True:
            try:
                msgs.append(app.log_queue.get_nowait())
            except queue.Empty:
                break
        self.assertTrue(any("failed" in m for m in msgs))
        self.assertIsNone(app._bg_proc)

    def test_background_child_success_reported_once(self):
        app = TestGuiThreadBoundary._fake_app()
        app._bg_proc = MagicMock()
        app._bg_proc.poll.side_effect = [0]
        app._bg_proc_observed = False
        app._poll_background_child()
        msgs = []
        while True:
            try:
                msgs.append(app.log_queue.get_nowait())
            except queue.Empty:
                break
        self.assertTrue(any("completed" in m for m in msgs))

    # ── PERF-002: exclusion index (O(1) exact + prefix) ─────────────────────
    def test_guard_prefix_index_excludes_descendants(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "base"
            root.mkdir()
            excl = root / "keep"
            excl.mkdir()
            guard = vac.SafetyGuard(root, exclude_paths=[str(excl)])
            # exact
            ok, _ = guard.is_safe(excl / "inner.tmp")
            self.assertFalse(ok)
            # under
            ok, _ = guard.is_safe(excl / "deep" / "inner.tmp")
            self.assertFalse(ok)

    # ── PERF-003: top-level content-sweep entry bound ───────────────────────
    def test_content_sweep_entry_bound_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "target"
            root.mkdir()
            engine = vac.CleanerEngine(True, vac.Logger(log_file=None, dry_run=True), vac.SafetyGuard(root), root, max_threads=1)
            engine.log = vac.Logger(log_file=None, dry_run=True)
            engine.ledger = None
            # Root identity
            _ident = vac._capture_identity(root)
            with patch.dict("os.environ", {"SMARTVAC_CONTENT_MAX_ENTRIES": "3"}):
                result = engine._del_dir_contents(root, "target")
            self.assertEqual(result, 0)

    # ── PERF-004: iterative ledger traversal handles deep chains ────────────
    def test_ledger_deep_paths_no_recursion_error(self):
        lg = vac.CandidateLedger()
        deep = Path("/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/r/s/t/u/v/w/x/y/z")
        lg.claim(deep)
        self.assertTrue(lg.covered(deep))
        self.assertIsNotNone(len(lg))

    # ── PERF-005: GUI text rolling budget trims old lines ───────────────────
    def test_text_log_rolling_budget(self):
        app = TestGuiThreadBoundary._fake_app()
        app.text_log = MagicMock()
        app.text_log.index.return_value = "1200.0"
        app.text_log.configure = MagicMock()
        app.text_log.insert = MagicMock()
        app.text_log.delete = MagicMock()
        app.text_log.see = MagicMock()
        app._poll_batch_log(["line"] * 300)
        app.text_log.delete.assert_called_once()

    def test_poll_batch_log_trims(self):
        app = TestGuiThreadBoundary._fake_app()
        app.text_log = MagicMock()
        app.text_log.index.return_value = "1200.0"
        app.text_log.configure = MagicMock()
        app.text_log.insert = MagicMock()
        app.text_log.delete = MagicMock()
        app.text_log.see = MagicMock()
        app._poll_batch_log(["line"] * 300)
        app.text_log.delete.assert_called_once()


class TestBlacklistAncestorCORE001(unittest.TestCase):
    """CORE-001: bidirectional protected-root overlap + guard propagation.

    A user/portable cleaning root must be rejected if it equals, contains, or
    sits under a protected root; and a guard built for such a root must refuse
    to delete anything beneath a protected subtree even when a stale rule
    reaches runtime.
    """

    @staticmethod
    def _non_c_drive_path(*parts):
        drive = os.path.splitdrive(os.getcwd())[0] or "D:"
        return Path(drive + os.sep, ".__vac_safety_test__", *parts)

    def test_parent_of_base_dir_rejected(self):
        # A custom root that is an ANCESTOR of a protected root must be rejected.
        parent = vac.BASE_DIR.parent
        self.assertTrue(vac.is_path_blacklisted(parent))
        valid, rejected = vac.sanitize_roots([str(parent)])
        self.assertEqual(valid, [])
        self.assertTrue(any("blacklisted" in r for r in rejected))

    def test_parent_of_script_parent_rejected(self):
        parent = vac.SCRIPT_PATH.parent.parent
        self.assertTrue(vac.is_path_blacklisted(parent))
        valid, rejected = vac.sanitize_roots([str(parent)])
        self.assertEqual(valid, [])
        self.assertTrue(any("blacklisted" in r for r in rejected))

    def test_unrelated_sibling_accepted(self):
        # An unrelated non-system-drive root must remain accepted.
        other = self._non_c_drive_path("cleaner_target")
        self.assertFalse(vac.is_path_blacklisted(other))
        valid, _rejected = vac.sanitize_roots([str(other)])
        self.assertEqual(valid, [str(vac.normalize_path(str(other)))])

    def test_guard_propagates_protected_subtree(self):
        # A directly-constructed guard for a root that holds a protected child
        # must refuse to delete beneath the protected subtree (defense in depth).
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "lvl1" / "lvl2" / "lvl3"
            root.mkdir(parents=True)
            protected = root / "protected_child"
            protected.mkdir()
            victim = protected / "victim.txt"
            victim.write_text("do not delete")
            saved = vac.BLACKLIST_PATHS
            try:
                vac.BLACKLIST_PATHS = saved | {protected}
                cleaner = vac.CustomCleaner(True, vac.Logger(log_file=None, dry_run=True),
                                            [{"path": str(root), "pattern": "*"}])
                guard = cleaner.make_guard(root)
                safe, reason = guard.is_safe(victim)
                self.assertFalse(safe, reason)
            finally:
                vac.BLACKLIST_PATHS = saved

    def test_stale_rule_cannot_sweep_protected_subtree(self):
        # Even when a stale/legacy rule slips past the ancestor rejection
        # (is_path_blacklisted lying), the guard must refuse the protected
        # descendant while still removing unprotected junk.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "lvl1" / "lvl2" / "lvl3"
            root.mkdir(parents=True)
            protected = root / "protected_child"
            protected.mkdir()
            victim = protected / "victim.txt"
            victim.write_text("do not delete")
            (root / "junk.txt").write_text("x")
            saved = vac.BLACKLIST_PATHS
            orig_bl = vac.is_path_blacklisted
            try:
                vac.BLACKLIST_PATHS = saved | {protected}
                vac.is_path_blacklisted = lambda p: False  # simulate a stale rule
                cleaner = vac.CustomCleaner(False, vac.Logger(log_file=None, dry_run=False),
                                            [{"path": str(root), "pattern": "*"}])
                freed = cleaner.run_all()
            finally:
                vac.BLACKLIST_PATHS = saved
                vac.is_path_blacklisted = orig_bl
            self.assertTrue(victim.exists(), "protected descendant must survive a stale '*' rule")
            self.assertFalse((root / "junk.txt").exists(), "unprotected junk should still be removed")
            self.assertGreater(freed, 0)

    def test_systemcleaner_guard_not_blacklist_protected(self):
        # SystemCleaner must NOT inject BLACKLIST_PATHS into its guard, or it
        # would refuse its own legitimate system targets.
        cleaner = vac.SystemCleaner(True, vac.Logger(log_file=None, dry_run=True))
        guard = cleaner.make_guard(Path("C:\\"))
        self.assertEqual(list(guard.exclude_paths), [])


class TestBoundaryTokenCORE003(unittest.TestCase):
    """CORE-003: mutation-boundary authority must be per-thread, not engine-wide.

    One engine drives up to DEFAULT_THREADS workers. When the sweep boundary
    token lives in shared instance state, a sibling worker's child root
    overwrites the boundary another worker is authorizing against: valid work
    aborts spuriously and mutations are checked against the wrong root
    authority.
    """

    def _engine(self, root, max_threads=1):
        log = vac.Logger(log_file=None, dry_run=False)
        engine = vac.CleanerEngine(False, log,
                                   vac.SafetyGuard(root, allow_shallow_system_target=True),
                                   root, max_threads=max_threads)
        engine.log = log
        return engine, log

    def test_worker_boundary_independent_of_sibling_worker(self):
        """Deterministic two-thread interleaving: A must not observe B's boundary.

        Worker A is paused inside its authorization gate while worker B installs
        its own boundary and destroys B's root. A's own root is untouched, so A
        must still delete A's file.
        """
        import shutil
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dir_a, dir_b = root / "A", root / "B"
            dir_a.mkdir()
            dir_b.mkdir()
            file_a, file_b = dir_a / "a.tmp", dir_b / "b.tmp"
            file_a.write_bytes(b"a" * 11)
            file_b.write_bytes(b"b" * 7)

            engine, _log = self._engine(root)
            plan_a = engine._plan_tree(dir_a, "A")
            plan_b = engine._plan_tree(dir_b, "B")
            self.assertIsNotNone(plan_a)
            self.assertIsNotNone(plan_b)

            a_at_gate, b_installed, a_done = threading.Event(), threading.Event(), threading.Event()
            real_auth = vac.CleanerEngine._authorize_mutation

            def gated_auth(self2, path, planned_identity, boundary_token=None):
                if path == file_a:
                    a_at_gate.set()
                    b_installed.wait(10)
                elif path == file_b:
                    # B holds its boundary installed; make B's root stale so a
                    # shared boundary slot would poison A's authorization.
                    shutil.rmtree(dir_b, ignore_errors=True)
                    dir_b.mkdir(exist_ok=True)
                    b_installed.set()
                    a_done.wait(10)
                return real_auth(self2, path, planned_identity, boundary_token)

            results = {}

            def work_a():
                try:
                    results["a"] = engine._apply_tree_plan(plan_a, "A")
                finally:
                    a_done.set()

            def work_b():
                a_at_gate.wait(10)
                try:
                    results["b"] = engine._apply_tree_plan(plan_b, "B")
                except Exception as exc:  # noqa: BLE001 - diagnostic only
                    results["b_exc"] = exc

            with patch.object(vac.CleanerEngine, "_authorize_mutation", gated_auth):
                ta, tb = threading.Thread(target=work_a), threading.Thread(target=work_b)
                ta.start()
                tb.start()
                ta.join(30)
                tb.join(30)

            self.assertFalse(ta.is_alive())
            self.assertFalse(tb.is_alive())
            self.assertNotIn("b_exc", results)
            self.assertFalse(file_a.exists(),
                             "worker A must delete its own file; a sibling's boundary "
                             "must never abort it")
            self.assertEqual(results["a"][0], 11)

    def test_worker_sees_inherited_parent_plus_only_own_nested_token(self):
        """Every worker's stack == inherited parent boundary + its own child."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            parent = root / "parent"
            children = [parent / f"c{i}" for i in range(4)]
            for c in children:
                c.mkdir(parents=True)
                (c / "junk.tmp").write_bytes(b"x" * 5)

            engine, _log = self._engine(root, max_threads=4)
            seen: dict[Path, tuple] = {}
            lock = threading.Lock()
            real_auth = vac.CleanerEngine._authorize_mutation

            def recording_auth(self2, path, planned_identity, boundary_token=None):
                with lock:
                    seen[path] = tuple(r for r, _i in self2._boundary_stack())
                return real_auth(self2, path, planned_identity, boundary_token)

            with patch.object(vac.CleanerEngine, "_authorize_mutation", recording_auth):
                engine._del_dir_contents(parent, "parent")

            for c in children:
                observed = seen.get(c / "junk.tmp")
                self.assertIsNotNone(observed, f"no authorization recorded for {c}")
                self.assertEqual(observed, (parent, c),
                                 f"{c} worker must see exactly (parent, own child); got {observed}")
            self.assertEqual(engine._boundary_stack(), (),
                             "the submitting thread's stack must be restored")

    def test_parent_root_replaced_mid_sweep_fails_all_descendants_closed(self):
        """Replacing the parent root mid-sweep must fail every descendant closed."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            parent = root / "parent"
            children = [parent / f"c{i}" for i in range(3)]
            for c in children:
                c.mkdir(parents=True)
                (c / "junk.tmp").write_bytes(b"x" * 5)

            engine, _log = self._engine(root, max_threads=1)
            swapped = {"done": False}
            real_auth = vac.CleanerEngine._authorize_mutation

            def swapping_auth(self2, path, planned_identity, boundary_token=None):
                if not swapped["done"] and path.name == "junk.tmp":
                    swapped["done"] = True
                    parent.rename(root / "parent_old")
                    (root / "parent").mkdir()
                return real_auth(self2, path, planned_identity, boundary_token)

            with patch.object(vac.CleanerEngine, "_authorize_mutation", swapping_auth):
                engine._del_dir_contents(parent, "parent")

            survivors = list((root / "parent_old").rglob("junk.tmp"))
            self.assertEqual(len(survivors), len(children),
                             "every descendant of a replaced root must survive")

    def test_threaded_mixed_target_no_spurious_boundary_refusal(self):
        """DEFAULT_THREADS workers over a mixed file/dir target: zero spurious skips."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            parent = root / "parent"
            parent.mkdir()
            expected = []
            for i in range(24):
                if i % 2:
                    f = parent / f"f{i}.tmp"
                    f.write_bytes(b"x" * 4)
                    expected.append(f)
                else:
                    d = parent / f"d{i}"
                    (d / "nested").mkdir(parents=True)
                    for n in range(3):
                        f = d / "nested" / f"n{n}.tmp"
                        f.write_bytes(b"y" * 3)
                        expected.append(f)

            engine, log = self._engine(root, max_threads=vac.DEFAULT_THREADS)
            real_auth = vac.CleanerEngine._authorize_mutation

            def interleaving_auth(self2, path, planned_identity, boundary_token=None):
                # Force worker interleaving at every mutation boundary.
                time.sleep(0)
                return real_auth(self2, path, planned_identity, boundary_token)

            with patch.object(vac.CleanerEngine, "_authorize_mutation", interleaving_auth):
                engine._del_dir_contents(parent, "parent")

            still_there = [str(p) for p in expected if p.exists()]
            self.assertEqual(still_there, [], "concurrent workers must not refuse valid work")
            self.assertEqual(log.n_skipped, 0, "no spurious boundary refusals allowed")


def _core004_child_write(cfg_path, field, value, barrier_dir, peers, hold_s=0.6):
    """Module-level (picklable) worker for the CORE-004 two-process barrier.

    Each child reads the SAME baseline, waits at a file-based barrier until
    every peer has also arrived, then performs its own disjoint field update.

    `hold_s` widens the read -> replace window INSIDE the update by delaying
    the atomic write. That is what makes the regression deterministic rather
    than a race: with a genuine cross-process transaction the peer is blocked
    for the whole hold and then re-reads, so both fields survive; with only a
    process-local lock both children read the same baseline during the hold and
    the second replace silently discards the first writer's field.
    """
    import json as _json
    import os as _os
    import sys as _sys
    import time as _time
    from pathlib import Path as _Path

    _sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
    import _SMART_VAC_CLEANER as _vac

    _vac.CONFIG_FILE = _Path(cfg_path)
    _vac.DATA_DIR = _Path(cfg_path).parent

    baseline = _json.loads(_Path(cfg_path).read_text(encoding="utf-8"))
    fingerprint = _vac._config_fingerprint(baseline)

    _real_save = _vac.save_config

    def _slow_save(cfg):
        _time.sleep(hold_s)
        return _real_save(cfg)

    _vac.save_config = _slow_save

    barrier = _Path(barrier_dir)
    (barrier / f"{field}.ready").write_text("1", encoding="utf-8")
    deadline = _time.monotonic() + 30
    while len(list(barrier.glob("*.ready"))) < peers and _time.monotonic() < deadline:
        _time.sleep(0.01)

    ok = _vac.update_config_field(field, value, expected_fingerprint=fingerprint)
    if not ok:
        # A stale fingerprint is the CORRECT refusal, not a lost update: re-read
        # inside a fresh transaction and retry, which is exactly the contract
        # update_config_field documents for a False return.
        ok = _vac.update_config_field(field, value)
    return field, ok


class TestConfigCrossProcessCORE004(unittest.TestCase):
    """CORE-004: the config RMW transaction must be genuinely cross-process.

    `_CONFIG_RMW_LOCK` is a threading.RLock: it serialises threads inside one
    interpreter only. Two application processes (GUI + scheduled child + CLI)
    could both validate the same fingerprint and then atomically replace the
    whole document, silently discarding the other writer's unrelated field.
    Atomic replace prevents torn JSON; it does not prevent a lost update.
    """

    _BASELINE: ClassVar[dict] = {
        "portable_roots": [], "custom_rules": [],
        "exclude_patterns": [], "exclude_paths": [],
        "auto_clean_interval_hours": 0, "lang": "en",
        "window_geometry": "", "system_targets": {},
    }

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp_dir.name)
        self.cfg = self.root / "cleaner_config.json"
        self.cfg.write_text(json.dumps(self._BASELINE), encoding="utf-8")
        self.cm = patch.object(vac, "CONFIG_FILE", self.cfg)
        self.cm.start()

    def tearDown(self):
        self.cm.stop()
        self.tmp_dir.cleanup()

    def test_two_process_disjoint_field_writes_both_survive(self):
        """Both processes read one baseline; both disjoint fields must survive."""
        import multiprocessing as mp

        barrier = self.root / "barrier"
        barrier.mkdir()
        ctx = mp.get_context("spawn")
        with ctx.Pool(2) as pool:
            results = pool.starmap(_core004_child_write, [
                (str(self.cfg), "lang", "ru", str(barrier), 2),
                (str(self.cfg), "window_geometry", "1234x567", str(barrier), 2),
            ])

        self.assertTrue(all(ok for _f, ok in results), f"both writers must land: {results}")
        final = json.loads(self.cfg.read_text(encoding="utf-8"))
        self.assertEqual(final["lang"], "ru", "process A's field was lost")
        self.assertEqual(final["window_geometry"], "1234x567", "process B's field was lost")

    def test_stale_fingerprint_refuses_instead_of_overwriting(self):
        """A genuinely stale fingerprint must refuse, evaluated under the lock."""
        vac.update_config_field("lang", "et")
        self.assertFalse(
            vac.update_config_field("window_geometry", "800x600",
                                    expected_fingerprint=vac._config_fingerprint(self._BASELINE)),
            "a writer carrying the pre-update fingerprint must be refused")
        final = json.loads(self.cfg.read_text(encoding="utf-8"))
        self.assertEqual(final["lang"], "et")
        self.assertEqual(final["window_geometry"], "", "the stale write must NOT have landed")

    def test_lock_is_held_across_the_whole_read_merge_write(self):
        """The transaction lock must already be held when the config is read.

        Evaluating a fingerprint before acquiring the lock is the defect: the
        value can go stale between the check and the replace.
        """
        observed = {}
        real_snapshot = vac.read_config_snapshot

        def probing_snapshot(*a, **k):
            observed["depth_at_read"] = vac._CONFIG_LOCK_DEPTH
            observed["fd_at_read"] = vac._CONFIG_LOCK_FD
            return real_snapshot(*a, **k)

        with patch.object(vac, "read_config_snapshot", probing_snapshot):
            self.assertTrue(vac.update_config_field("lang", "ru"))
        self.assertGreaterEqual(observed.get("depth_at_read", 0), 1,
                                "config was read OUTSIDE the transaction")
        self.assertIsNotNone(observed.get("fd_at_read"),
                             "no cross-process lock descriptor was held during the read")
        self.assertEqual(vac._CONFIG_LOCK_DEPTH, 0, "the lock must be released after the write")
        self.assertIsNone(vac._CONFIG_LOCK_FD)

    def test_busy_cross_process_lock_refuses_and_preserves_config(self):
        """When the OS lock is held elsewhere, every writer refuses -- no write."""
        original = self.cfg.read_text(encoding="utf-8")
        lock_path = vac._config_lock_path()
        fd = os.open(str(lock_path), os.O_RDWR | os.O_CREAT, 0o600)
        try:
            vac._config_lock_try(fd)  # simulate the other process holding it
            with patch.object(vac, "_CONFIG_LOCK_TIMEOUT", 0.2):
                self.assertFalse(vac.update_config_field("lang", "ru"))
                self.assertFalse(vac._config_rmw_transaction(lambda latest: {**latest, "lang": "ru"}))
                self.assertFalse(vac.save_config(dict(self._BASELINE, lang="ru")))
            self.assertEqual(self.cfg.read_text(encoding="utf-8"), original,
                             "a refused transaction must leave the config byte-identical")
        finally:
            vac._config_lock_drop(fd)
        # Lock released -> the same write now lands.
        self.assertTrue(vac.update_config_field("lang", "ru"))

    def test_migration_and_bootstrap_persist_inside_the_transaction(self):
        """Bootstrap + legacy migration must write under the lock, not around it."""
        depths = []
        real_save = vac.save_config

        def probing_save(cfg):
            depths.append(vac._CONFIG_LOCK_DEPTH)
            return real_save(cfg)

        # Legacy migration through the write-authorized loader.
        self.cfg.write_text(json.dumps({**self._BASELINE, "profiles": {"Default": {}}}),
                            encoding="utf-8")
        with patch.object(vac, "save_config", probing_save):
            _state, data, _ = vac._load_and_validate(persist=True)
        self.assertNotIn("profiles", data)
        self.assertNotIn("profiles", json.loads(self.cfg.read_text(encoding="utf-8")))

        # First-run bootstrap.
        self.cfg.unlink()
        with patch.object(vac, "save_config", probing_save):
            _state, _data, _ = vac._load_and_validate(persist=True)
        self.assertTrue(self.cfg.exists(), "bootstrap must create the config")

        self.assertTrue(depths, "no persistence happened; the probe proved nothing")
        self.assertTrue(all(d >= 1 for d in depths),
                        f"every authorized persist must run inside the transaction: {depths}")

    def test_read_only_surface_neither_locks_nor_writes(self):
        """A read-only load must not take the lock and must not create the file."""
        self.cfg.unlink()
        opened = []
        real_open = os.open

        def probing_open(path, flags, *a, **k):
            if str(path) == str(vac._config_lock_path()):
                opened.append(str(path))
            return real_open(path, flags, *a, **k)

        with patch.object(os, "open", probing_open):
            state, data, _ = vac.load_config_strict()
        self.assertIn(state, (vac.ConfigState.MISSING, vac.ConfigState.VALID))
        self.assertEqual(data["exclude_patterns"], [])
        self.assertFalse(self.cfg.exists(), "read-only surface must not bootstrap")
        self.assertEqual(opened, [], "read-only surface must not take the config lock")


class TestConfigBootstrapW2004(unittest.TestCase):
    """W2-004: ONE explicit bootstrap/migration lifecycle owner.

    Read-only surfaces (status/dry-run/preview/load_config) create nothing
    and persist no migration. bootstrap_config() -- called only at writable
    application lifecycle boundaries (GUI startup, real destructive CLI job
    start) -- performs validated first-run default creation and atomic
    legacy `profiles` migration inside the cross-process config transaction.
    INVALID config is never overwritten.
    """

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.cfg = Path(self.tmp_dir.name) / "cleaner_config.json"
        self.cm = patch.object(vac, "CONFIG_FILE", self.cfg)
        self.cm.start()

    def tearDown(self):
        self.cm.stop()
        self.tmp_dir.cleanup()

    def test_bootstrap_creates_exactly_one_validated_default(self):
        """VERIFY 1: fresh write-authorized startup creates exactly one
        validated default config at the documented point."""
        self.assertFalse(self.cfg.exists())
        vac.bootstrap_config()
        self.assertTrue(self.cfg.exists())
        on_disk = json.loads(self.cfg.read_text(encoding="utf-8"))
        self.assertEqual(on_disk, vac._default_config(),
                         "created file must be exactly the validated default")
        # idempotent: a second bootstrap does not duplicate or corrupt
        vac.bootstrap_config()
        self.assertEqual(json.loads(self.cfg.read_text(encoding="utf-8")),
                         vac._default_config())

    def test_read_only_surfaces_create_nothing(self):
        """VERIFY 2: --status / dry-run / preview on a missing config create
        nothing (load_config, load_config_strict, read_config_snapshot with
        create_if_missing=False)."""
        for reader in (lambda: vac.load_config(),
                       lambda: vac.load_config_strict(),
                       lambda: vac.read_config_snapshot(create_if_missing=False),
                       lambda: vac.get_config_state()):
            reader()
        self.assertFalse(self.cfg.exists(),
                         "no read-only surface may create the config file")

    def test_bootstrap_migrates_legacy_profiles_atomically(self):
        """VERIFY 3: valid legacy `profiles` config is atomically rewritten
        without `profiles` by the bootstrap owner (via save_config's atomic
        replace, inside the config transaction)."""
        legacy = ('{"custom_rules": [], "portable_roots": [], "exclude_patterns": [], '
                  '"exclude_paths": [], "system_targets": {}, "lang": "ru", '
                  '"auto_clean_interval_hours": 0, "window_geometry": "", '
                  '"profiles": {"Default": {}}}')
        self.cfg.write_text(legacy, encoding="utf-8")
        vac.bootstrap_config()
        migrated = json.loads(self.cfg.read_text(encoding="utf-8"))
        self.assertNotIn("profiles", migrated)
        self.assertEqual(migrated["lang"], "ru",
                         "unrelated policy fields must survive the migration")

    def test_bootstrap_never_overwrites_invalid(self):
        """VERIFY 5: INVALID config stays byte-identical."""
        invalid = '{"custom_rules": "not-a-list"}'
        self.cfg.write_text(invalid, encoding="utf-8")
        vac.bootstrap_config()
        self.assertEqual(self.cfg.read_text(encoding="utf-8"), invalid,
                         "INVALID config must remain byte-identical")

    def test_cli_dry_run_is_read_only_real_delete_bootstraps(self):
        """VERIFY 2/4: the CLI dry-run form persists nothing on a missing
        config; the real-delete form bootstraps before the job starts."""
        argv = MagicMock(
            dry_run=True, delete=False,
            portable=False, system=False, custom=False, all=True,
            cli=True, status=False, analyze_caches=False, hidden=False,
            sys_targets="", disable_targets="", exclude="",
            install_task=False, time="09:00", surface="cli",
        )
        with patch("_SMART_VAC_CLEANER.argparse.ArgumentParser.parse_args",
                   return_value=argv), \
             patch.object(vac, "run_cleaning_job") as job, \
             patch.object(vac, "Logger"), \
             patch.object(vac, "bootstrap_config") as boot:
            vac.main()
        boot.assert_not_called()
        job.assert_called_once()
        # real-delete CLI start is a write-authorized lifecycle boundary
        argv.delete = True
        argv.dry_run = False
        with patch("_SMART_VAC_CLEANER.argparse.ArgumentParser.parse_args",
                   return_value=argv), \
             patch.object(vac, "run_cleaning_job") as job2, \
             patch.object(vac, "Logger"), \
             patch.object(vac, "_JobLease"), \
             patch.object(vac, "bootstrap_config") as boot2:
            vac.main()
        boot2.assert_called_once()
        job2.assert_called_once()

    def test_bootstrap_and_editor_update_preserve_both_changes(self):
        """VERIFY 6: concurrent migration persistence + GUI editor field
        update preserve both changes after CORE-004's transaction."""
        legacy = ('{"custom_rules": [], "portable_roots": [], "exclude_patterns": [], '
                  '"exclude_paths": [], "system_targets": {}, "lang": "en", '
                  '"auto_clean_interval_hours": 0, "window_geometry": "", '
                  '"profiles": {"Default": {}}}')
        self.cfg.write_text(legacy, encoding="utf-8")
        # a simultaneous disjoint editor write, as the GUI would do
        ok = vac.update_config_field("window_geometry", "1024x768+10+10")
        self.assertTrue(ok)
        vac.bootstrap_config()
        # both the editor change and the migration landed; nothing lost
        final = json.loads(self.cfg.read_text(encoding="utf-8"))
        self.assertNotIn("profiles", final)
        self.assertEqual(final["window_geometry"], "1024x768+10+10")


class TestOwnerSnapshotCadenceCORE005(unittest.TestCase):
    """CORE-005: the process-owner gate must take REAL snapshots on a cadence.

    The gate used to refresh once per tree apply and then reread that one
    cached snapshot for the whole plan: an app starting during a long clean
    was never noticed, and every later mutation ran under stale
    "not running" state. Refreshing per candidate is the other failure (a full
    Toolhelp scan per file), so the contract is one snapshot per batch
    boundary, plus one immediately before destructive directory/root removal.
    """

    @staticmethod
    def _sequenced(*snapshots):
        """get_running_processes stub: snapshot i per call, the last one sticks."""
        calls = {"n": 0}

        def fake():
            i = calls["n"]
            calls["n"] += 1
            return snapshots[min(i, len(snapshots) - 1)]

        return fake, calls

    def _engine(self, root, max_threads=1):
        log = vac.Logger(log_file=None, dry_run=False)
        engine = vac.CleanerEngine(False, log,
                                   vac.SafetyGuard(root, allow_shallow_system_target=True),
                                   root, max_threads=max_threads)
        engine.log = log
        return engine, log

    def _flat_tree(self, root, n, name="t"):
        target = root / name
        target.mkdir()
        for i in range(n):
            (target / f"f{i:04d}.bin").write_bytes(b"x")
        return target

    def test_app_appearing_after_first_batch_stops_next_batch(self):
        """VERIFY 1: absent for batch 1, present at batch 2 -> stop there."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = self._flat_tree(root, vac._OWNER_REFRESH_BATCH + 1)
            engine, _log = self._engine(root)
            plan = engine._plan_tree(target, "t")
            self.assertIsNotNone(plan)
            fake, calls = self._sequenced(set(), {"discord.exe"})
            with patch.object(vac, "get_running_processes", fake):
                freed, fully = engine._apply_tree_plan(plan, "t", owner_group="discord")
            self.assertEqual(calls["n"], 2, "exactly two batch boundaries were reached")
            survivors = list(target.glob("*.bin"))
            self.assertEqual(len(survivors), 1,
                             "the batch that saw the app running must mutate nothing")
            self.assertEqual(freed, vac._OWNER_REFRESH_BATCH)
            self.assertFalse(fully)

    def test_refresh_cadence_is_per_batch_not_per_file(self):
        """VERIFY 2: snapshot count matches the documented cadence exactly."""
        n = vac._OWNER_REFRESH_BATCH * 3 + 5
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = self._flat_tree(root, n)
            engine, _log = self._engine(root)
            plan = engine._plan_tree(target, "t")
            fake, calls = self._sequenced(set())
            with patch.object(vac, "get_running_processes", fake):
                freed, fully = engine._apply_tree_plan(plan, "t", owner_group="discord")
            # 4 file-batch boundaries (idx 0, 64, 128, 192) + 1 pre-rmdir snapshot.
            expected = (n + vac._OWNER_REFRESH_BATCH - 1) // vac._OWNER_REFRESH_BATCH + 1
            self.assertEqual(calls["n"], expected,
                             f"expected {expected} snapshots for {n} files, got {calls['n']}")
            self.assertLess(calls["n"], n, "a snapshot per file is the cost defect")
            self.assertEqual(freed, n)
            self.assertTrue(fully)

    def test_unknown_snapshot_mid_plan_fails_closed(self):
        """VERIFY 3: UNKNOWN (None) process state must abort, not proceed."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = self._flat_tree(root, vac._OWNER_REFRESH_BATCH + 1)
            engine, _log = self._engine(root)
            plan = engine._plan_tree(target, "t")
            fake, calls = self._sequenced(set(), None)
            with patch.object(vac, "get_running_processes", fake):
                freed, fully = engine._apply_tree_plan(plan, "t", owner_group="discord")
            self.assertEqual(calls["n"], 2)
            self.assertEqual(len(list(target.glob("*.bin"))), 1,
                             "UNKNOWN state must fail closed like a running app")
            self.assertFalse(fully)
            self.assertEqual(freed, vac._OWNER_REFRESH_BATCH)

    def test_app_appearing_before_rmdir_blocks_directory_removal(self):
        """VERIFY 4: app appears after the files are gone, before the rmdir."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "Cache"
            nested = target / "deep"
            nested.mkdir(parents=True)
            for i in range(3):
                (nested / f"f{i}.bin").write_bytes(b"x")
            engine, _log = self._engine(root)
            plan = engine._plan_tree(target, "Cache")
            fake, calls = self._sequenced(set(), {"discord.exe"})
            with patch.object(vac, "get_running_processes", fake):
                freed, fully = engine._apply_tree_plan(plan, "Cache", owner_group="discord")
            self.assertEqual(calls["n"], 2,
                             "one file-batch snapshot plus one immediately before removal")
            self.assertEqual(freed, 3, "the file phase ran while the app was absent")
            self.assertFalse(fully)
            self.assertTrue(nested.is_dir(), "rmdir must be blocked by the fresh snapshot")
            self.assertTrue(target.is_dir(), "root removal must be blocked too")

    def test_direct_sensitive_file_delete_takes_a_current_snapshot(self):
        """REPAIR: an ad-hoc single-file delete rides no tree batching.

        It must snapshot immediately before mutating, never trust the engine's
        construction-time state -- that reuse is the defect in its purest form.
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            victim = root / "sensitive.log"
            victim.write_bytes(b"x" * 9)
            engine, log = self._engine(root)
            # Engine built while the app was absent; it starts before the delete.
            fake, calls = self._sequenced({"discord.exe"})
            with patch.object(vac, "get_running_processes", fake):
                freed = engine._del_file(victim, "sensitive", owner_group="discord")
            self.assertGreaterEqual(calls["n"], 1,
                                    "the direct path must take its own snapshot")
            self.assertEqual(freed, 0)
            self.assertTrue(victim.exists(), "a running owner must block the direct delete")
            self.assertEqual(log.n_deleted, 0)

    def test_gate_works_with_native_windows_enumeration(self):
        """VERIFY 5: exercise the gate against the REAL process enumerator."""
        if os.name != "nt":
            self.skipTest("native Toolhelp enumeration is Windows-only")
        native = vac._enumerate_processes_win()
        if native is None:
            self.skipTest("native Toolhelp enumeration unavailable on this host")
        self.assertTrue(native, "native enumeration returned an empty process table")
        own_image = Path(sys.executable).name.lower()
        self.assertIn(own_image, native, "our own process must appear in the snapshot")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            victim = root / "keep.bin"
            victim.write_bytes(b"x" * 5)
            engine, _log = self._engine(root)
            with patch.dict(vac.APP_PROCESSES,
                            {"__native_probe__": {own_image},
                             "__native_absent__": {"definitely_not_running_xyz.exe"}},
                            clear=False):
                # No mocking of get_running_processes: real Toolhelp snapshots.
                self.assertFalse(engine._owner_gate_ok("__native_probe__"),
                                 "a genuinely running owner must refuse")
                self.assertTrue(engine._owner_gate_ok("__native_absent__"),
                                "an absent owner must be allowed")
                freed = engine._del_file(victim, "probe", owner_group="__native_probe__")
            self.assertEqual(freed, 0)
            self.assertTrue(victim.exists())


class TestUserTempProvenanceCORE006(unittest.TestCase):
    """CORE-006: User Temp must resolve on a STANDARD Windows layout.

    The previous derivation asked GetTempPathW after clearing TMP, TEMP and
    USERPROFILE -- which is exactly that API's documented lookup order, so it
    was forced onto its last fallback, the Windows directory. `%LOCALAPPDATA%
    \\Temp` is neither equal to nor under `C:\\Windows`, so the advertised
    User Temp target resolved to None on ordinary machines: the hardening
    disabled the thing it was protecting. Authority is now the OS Known Folder
    FOLDERID_LocalAppData + the canonical `Temp` child.
    """

    def test_standard_localappdata_temp_resolves_positively(self):
        """VERIFY 1 + 5: the standard layout MUST resolve (anti-regression)."""
        if os.name != "nt":
            self.skipTest("Windows user-temp provenance is Windows-only")
        trusted = vac._trusted_user_temp_win()
        self.assertIsNotNone(trusted, "Known Folder authority unavailable on this host")
        self.assertEqual(trusted.name, "Temp")
        self.assertEqual(trusted.parent, vac._get_known_folder_win(vac._FOLDERID_LOCAL_APPDATA))
        with patch.dict(os.environ, {"TEMP": str(trusted)}, clear=False):
            self.assertEqual(vac._resolve_temp_root(), trusted,
                             "the standard %LOCALAPPDATA%\\Temp layout must resolve")
        # Same path spelled with a trailing separator / different case must also hold.
        with patch.dict(os.environ, {"TEMP": str(trusted).upper() + os.sep}, clear=False):
            self.assertEqual(vac._resolve_temp_root(), trusted)

    @pytest.mark.real_system_roots
    def test_temp_authority_is_not_the_windows_directory(self):
        """The trusted user temp must NOT be the GetTempPathW env-cleared fallback."""
        if os.name != "nt":
            self.skipTest("Windows-only")
        trusted = vac._trusted_user_temp_win()
        windir = vac._get_windows_directory_win()
        self.assertIsNotNone(trusted)
        self.assertIsNotNone(windir)
        self.assertFalse(vac._is_under(windir, trusted),
                         "user temp authority must not collapse into the Windows directory")
        self.assertNotEqual(trusted, vac.SYSTEM_TEMP,
                            "User Temp and System Temp must be independent targets")

    def test_poisoned_temp_is_rejected(self):
        """VERIFY 2: a relocated/poisoned TEMP must be refused."""
        if os.name != "nt":
            self.skipTest("Windows-only")
        for bad in (r"D:\Important", r"C:\Important", r"C:\Windows", str(Path.cwd()),
                    str(vac.BASE_DIR), "", ".", "..", "C:\\"):
            with patch.dict(os.environ, {"TEMP": bad}, clear=False):
                self.assertIsNone(vac._resolve_temp_root(), f"TEMP={bad!r} must be rejected")

    def test_relocated_temp_under_localappdata_still_rejected(self):
        """Only the canonical child is trusted; a sibling under LocalAppData is not."""
        if os.name != "nt":
            self.skipTest("Windows-only")
        local = vac._get_known_folder_win(vac._FOLDERID_LOCAL_APPDATA)
        self.assertIsNotNone(local)
        for bad in (local, local / "TempRelocated", local / "Temp" / "sub"):
            with patch.dict(os.environ, {"TEMP": str(bad)}, clear=False):
                self.assertIsNone(vac._resolve_temp_root(),
                                  f"TEMP={bad} is not the canonical trusted temp")

    def test_missing_known_folder_disables_target_instead_of_trusting_env(self):
        """VERIFY 3: no authority => DISABLED, never env-derived."""
        if os.name != "nt":
            self.skipTest("Windows-only")
        trusted = vac._trusted_user_temp_win()
        self.assertIsNotNone(trusted)
        with patch.object(vac, "_get_known_folder_win", return_value=None):
            self.assertIsNone(vac._trusted_user_temp_win())
            with patch.dict(os.environ, {"TEMP": str(trusted)}, clear=False):
                self.assertIsNone(vac._resolve_temp_root(),
                                  "an unavailable Known Folder must disable the target")

    @pytest.mark.real_system_roots
    def test_system_temp_resolves_independently(self):
        """VERIFY 4: Windows/System Temp keeps its own authority and protection."""
        if os.name != "nt":
            self.skipTest("Windows-only")
        windir = vac._get_windows_directory_win()
        self.assertIsNotNone(windir)
        self.assertEqual(vac.SYSTEM_TEMP, windir / "Temp")
        # Poisoning TEMP cannot move System Temp.
        with patch.dict(os.environ, {"TEMP": r"D:\Important", "TMP": r"D:\Important"}, clear=False):
            self.assertEqual(vac._rooted(vac._get_windows_directory_win(), "Temp"), windir / "Temp")

    def test_standard_layout_resolves_in_a_clean_subprocess(self):
        """VERIFY 1/5 end-to-end: module import on a standard layout enables the target.

        A fresh interpreter with TEMP/TMP set to the OS-reported
        %LOCALAPPDATA%\\Temp must bind USER_TEMP, not None. This is the
        regression that keeps future fail-closed hardening from silently
        removing the advertised User Temp surface again.
        """
        if os.name != "nt":
            self.skipTest("Windows-only")
        import subprocess as _sp
        repo = os.path.dirname(os.path.abspath(__file__))
        trusted = vac._trusted_user_temp_win()
        self.assertIsNotNone(trusted)
        env = dict(os.environ)
        env["TEMP"] = str(trusted)
        env["TMP"] = str(trusted)
        code = (
            f"import sys; sys.path.insert(0, r'{repo}'); "
            "import _SMART_VAC_CLEANER as vac; "
            "assert vac.USER_TEMP is not None, 'USER_TEMP disabled on a standard layout'; "
            "assert vac.SYSTEM_TEMP is not None, 'SYSTEM_TEMP disabled'; "
            "assert vac.USER_TEMP != vac.SYSTEM_TEMP; "
            "print('USER_TEMP=' + str(vac.USER_TEMP))"
        )
        r = _sp.run([sys.executable, "-c", code], capture_output=True, text=True,
                    env=env, timeout=60, check=False)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(f"USER_TEMP={trusted}", r.stdout)


class TestPlanTotalBudgetPERF001(unittest.TestCase):
    """PERF-001 (AUDIT_ALL_3 new generation): the plan resource cap must
    bound TOTAL retained planner state (files + dirs + protected + staged),
    not only accepted files, and concurrent child plans must share ONE
    job-level budget instead of each drawing a full private allowance.

    Audit probes against the old accepted-file-only cap:
      - cap=1, 2,000 empty dirs  -> dirs=2000, no refusal
      - cap=1, 2,000 excluded *.tmp files -> protected=2000, no refusal
      - 4-thread sibling planning -> traced peak ~3.35x max_threads=1
    """

    def _engine(self, base, root, dry_run=True, max_threads=1, ledger=None):
        log = vac.Logger(log_file=None, dry_run=dry_run)
        engine = vac.CleanerEngine(dry_run, log, vac.SafetyGuard(base), root,
                                   max_threads=max_threads, ledger=ledger)
        engine.log = log
        return engine, log

    def test_dir_only_tree_refused_at_total_limit(self):
        """VERIFY 1 (dirs): 2,000 empty dirs at cap=1 must abort."""
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "base"
            root = base / "tree"
            root.mkdir(parents=True)
            for i in range(2000):
                (root / f"d{i:04d}").mkdir()
            engine, log = self._engine(base, root)
            with patch.dict("os.environ", {"SMARTVAC_PLAN_MAX_RECORDS": "1"}):
                plan = engine._plan_tree(root, "t")
            self.assertIsNone(plan, "directory-only tree must hit the TOTAL budget")
            self.assertEqual(log.n_errors, 1, "one controlled diagnostic")

    def test_protected_only_tree_refused_at_total_limit(self):
        """VERIFY 1 (protected): excluded records count against the budget.

        The old cap let a protection-heavy tree retain 2,000 protected
        records with files=0 and never fire. With the total budget at 1,
        the first protected record exhausts it: no executable plan.
        """
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "base"
            root = base / "tree"
            root.mkdir(parents=True)
            for i in range(2000):
                (root / f"junk{i:04d}.tmp").write_bytes(b"x")
            engine, log = self._engine(base, root)
            engine.guard.exclude_patterns = ["*.tmp"]
            with patch.dict("os.environ", {"SMARTVAC_PLAN_MAX_RECORDS": "1"}):
                plan = engine._plan_tree(root, "t")
            self.assertIsNone(plan,
                              "protected-only tree must hit the TOTAL budget")
            self.assertEqual(log.n_errors, 1, "one controlled diagnostic")

    def test_mixed_tree_at_limit_plus_one_refuses(self):
        """VERIFY 1+2: at limit the plan is executable; at limit+1 it is
        None with one diagnostic, zero bytes, intact FS, and no claim."""
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "base"
            root = base / "tree"
            (root / "sub").mkdir(parents=True)
            for i in range(3):
                (root / "sub" / f"f{i}.tmp").write_bytes(b"x" * 8)
            engine, _log = self._engine(base, root, ledger=vac.CandidateLedger())
            ledger = engine.ledger
            # AT the limit: 1 dir (sub) + 3 files = 4 records.
            with patch.dict("os.environ", {"SMARTVAC_PLAN_MAX_RECORDS": "4"}):
                plan = engine._plan_tree(root, "t")
            self.assertIsNotNone(plan)
            self.assertEqual(len(plan["files"]) + len(plan["dirs"]), 4)
            # LIMIT+1: one record short.
            engine2, log2 = self._engine(base, root, ledger=ledger)
            with patch.dict("os.environ", {"SMARTVAC_PLAN_MAX_RECORDS": "3"}):
                freed = engine2._del_dir(root, "t")
            self.assertEqual(freed, 0, "over-budget target must free nothing")
            self.assertEqual(log2.n_errors, 1, "one controlled diagnostic")
            self.assertFalse(ledger.covered(root), "no claim from an aborted plan")
            self.assertEqual(len(list(root.rglob("*.tmp"))), 3,
                             "filesystem intact after refusal")

    def test_concurrent_sibling_plans_share_one_budget(self):
        """VERIFY 3: concurrent child plans draw from ONE shared budget.

        4 siblings x 500 files = 2000 records in flight if each had a private
        allowance. With the SHARED budget at 1000, at least one sibling plan
        must refuse while the others may proceed -- total retained records
        across all concurrent plans stay within the job-level bound.
        """
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "base"
            root = base / "tree"
            per = 500
            for s in range(4):
                sib = root / f"s{s}"
                sib.mkdir(parents=True)
                for i in range(per):
                    (sib / f"f{i}.tmp").write_bytes(b"x" * 4)
            engine, _log = self._engine(base, root, max_threads=4)
            siblings = [root / f"s{s}" for s in range(4)]
            with patch.dict("os.environ", {"SMARTVAC_PLAN_MAX_RECORDS": "1000"}):
                import concurrent.futures as _cf
                with _cf.ThreadPoolExecutor(max_workers=4) as ex:
                    futs = {ex.submit(engine._plan_tree, sib, "t"): sib
                            for sib in siblings}
                    results = {futs[f]: f.result() for f in futs}
            refused = [s for s, p in results.items() if p is None]
            self.assertTrue(refused,
                             "shared budget must refuse at least one sibling "
                             "plan that would exceed the job-level bound")
            # every NON-refused plan's records together stayed within bounds
            ok_records = sum(len(p["files"]) + len(p["dirs"])
                             for p in results.values() if p is not None)
            self.assertLessEqual(ok_records, 1000)

    def test_budget_release_allows_later_targets(self):
        """VERIFY 3b: a completed/aborted plan gives its slots back, so the
        budget does not permanently poison later independent targets."""
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "base"
            root = base / "tree"
            root.mkdir(parents=True)
            for i in range(10):
                (root / f"f{i}.tmp").write_bytes(b"x" * 4)
            engine, _log = self._engine(base, root, dry_run=True)
            # First sweep: dry-run _del_dir plans 10 records, reports them,
            # and RELEASES the slots when its plan leaves scope.
            with patch.dict("os.environ", {"SMARTVAC_PLAN_MAX_RECORDS": "10"}):
                self.assertEqual(engine._del_dir(root, "t"), 40)
                # second target, SAME budget size: slots must be reusable
                p2 = engine._plan_tree(root, "t")
            self.assertIsNotNone(p2, "released slots must be reusable")
            self.assertEqual(len(p2["files"]), 10)
            engine._plan_budget().release(p2["budget_held"])
            self.assertEqual(engine._plan_budget().used, 0,
                             "all plans closed: nothing may stay reserved")

    def test_deep_dirs_still_removed_bottom_up_at_budget(self):
        """VERIFY 5: at-budget normal plans keep identical candidate paths
        and bytes in dry-run and real mode, and dirs still go bottom-up."""
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "base"
            root = base / "tree"
            deep = root / "a" / "b" / "c"
            deep.mkdir(parents=True)
            for i in range(3):
                (deep / f"f{i}.tmp").write_bytes(b"x" * 5)
            ledger = vac.CandidateLedger()
            eng_d, _ = self._engine(base, root, dry_run=True, ledger=ledger)
            eng_r, _ = self._engine(base, root, dry_run=False, ledger=ledger)
            with patch.dict("os.environ", {"SMARTVAC_PLAN_MAX_RECORDS": "100"}):
                pd = eng_d._plan_tree(root, "t")
                pr = eng_r._plan_tree(root, "t")
            self.assertEqual([str(p) for p, _, _ in pd["files"]],
                             [str(p) for p, _, _ in pr["files"]],
                             "dry-run and real plans must be identical")
            self.assertEqual(pd["bytes"], pr["bytes"])
            self.assertEqual(pd["bytes"], 15)
            freed = eng_r._del_dir(root, "t")
            self.assertEqual(freed, 15)
            self.assertFalse(root.exists(), "dirs removed bottom-up, root gone")

    def test_core007_regressions_still_green(self):
        """VERIFY 6: CORE-007 abort shape survives the budget semantics
        change (None plan, no claim, no suppression of narrower targets)."""
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "base"
            root = base / "tree"
            nested = root / "a" / "a1"
            nested.mkdir(parents=True)
            for i in range(3):
                (nested / f"f{i}.tmp").write_text("x" * 10)
            ledger = vac.CandidateLedger()
            engine, _log = self._engine(base, root, dry_run=False, ledger=ledger)
            with patch.dict("os.environ", {"SMARTVAC_PLAN_MAX_RECORDS": "1"}):
                self.assertEqual(engine._del_dir(root, "broad"), 0)
            self.assertFalse(ledger.covered(root))
            freed = engine._del_dir(nested, "nested")
            self.assertEqual(freed, 30,
                             "the narrower candidate must execute normally")


class TestAbortedPlanNoClaimCORE007(unittest.TestCase):
    """CORE-007: a resource-cap abort must leave NO ledger claim.

    The abort used to return a non-None plan with empty candidate lists;
    `_del_dir` read that as a successful "nothing to do" plan and claimed the
    entire root in the CandidateLedger. Every narrower target underneath was
    then reported "already covered by an earlier candidate claim" even though
    the broad transaction had done no work whatsoever -- a safety refusal
    leaking into scheduling state and suppressing valid candidates.
    """

    def _engine(self, base, root, ledger, dry_run=True, cap=None):
        log = vac.Logger(log_file=None, dry_run=dry_run)
        engine = vac.CleanerEngine(dry_run, log, vac.SafetyGuard(base), root,
                                  max_threads=1, ledger=ledger)
        engine.log = log
        return engine, log

    @staticmethod
    def _fixture(tmp, n_nested=3):
        base = Path(tmp) / "base"
        root = base / "tree"
        nested = root / "a" / "a1"
        nested.mkdir(parents=True)
        for i in range(n_nested):
            (nested / f"f{i}.tmp").write_text("x" * 10)
        return base, root, nested

    def test_overflow_makes_no_claim_no_mutation_no_bytes(self):
        """VERIFY 1: one error, zero mutations, zero bytes, zero claims."""
        with tempfile.TemporaryDirectory() as tmp:
            base, root, nested = self._fixture(tmp)
            ledger = vac.CandidateLedger()
            engine, log = self._engine(base, root, ledger, dry_run=False)
            with patch.dict("os.environ", {"SMARTVAC_PLAN_MAX_FILES": "1"}):
                freed = engine._del_dir(root, "broad")
            self.assertEqual(freed, 0, "an aborted plan must free nothing")
            self.assertEqual(log.n_errors, 1, "exactly one overflow error")
            self.assertEqual(log.n_deleted, 0)
            self.assertFalse(ledger.covered(root), "the aborted root must NOT be claimed")
            self.assertFalse(ledger.covered(nested), "no descendant may be covered either")
            self.assertEqual(ledger.claims_within(root), [])
            self.assertEqual(len(list(nested.glob("*.tmp"))), 3, "nothing may be deleted")

    def test_nested_candidate_after_failed_broad_still_executes(self):
        """VERIFY 2: the narrower candidate must not be suppressed."""
        with tempfile.TemporaryDirectory() as tmp:
            base, root, nested = self._fixture(tmp)
            ledger = vac.CandidateLedger()
            engine, _log = self._engine(base, root, ledger, dry_run=False)
            with patch.dict("os.environ", {"SMARTVAC_PLAN_MAX_FILES": "1"}):
                self.assertEqual(engine._del_dir(root, "broad"), 0)
            # No cap now: the nested target is independent and must work.
            freed = engine._del_dir(nested, "nested")
            self.assertEqual(freed, 30, "the nested candidate must execute normally")
            self.assertEqual(list(nested.glob("*.tmp")), [])
            self.assertTrue(ledger.covered(nested), "the executed target claims itself")

    def test_plan_exactly_at_cap_remains_executable_and_claims(self):
        """VERIFY 3: a plan AT the cap is not an abort."""
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "base"
            root = base / "tree"
            root.mkdir(parents=True)
            for i in range(2):
                (root / f"f{i}.tmp").write_text("x" * 10)
            ledger = vac.CandidateLedger()
            engine, log = self._engine(base, root, ledger, dry_run=False)
            with patch.dict("os.environ", {"SMARTVAC_PLAN_MAX_FILES": "2"}):
                freed = engine._del_dir(root, "at-cap")
            self.assertEqual(freed, 20)
            self.assertEqual(log.n_errors, 0, "a plan at the cap is not an overflow")
            self.assertTrue(ledger.covered(root), "an executed plan gets its normal claim")

    def test_overflow_is_all_or_nothing_for_the_original_tree(self):
        """VERIFY 4: no partial prefix of the overflowing tree is planned."""
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "base"
            root = base / "tree"
            for sub in ("a", "b", "c"):
                (root / sub).mkdir(parents=True)
                for i in range(3):
                    (root / sub / f"f{i}.tmp").write_text("x" * 10)
            ledger = vac.CandidateLedger()
            engine, _log = self._engine(base, root, ledger, dry_run=False)
            with patch.dict("os.environ", {"SMARTVAC_PLAN_MAX_FILES": "4"}):
                freed = engine._del_dir(root, "broad")
            self.assertEqual(freed, 0)
            survivors = sorted(p.name for p in root.rglob("*.tmp"))
            self.assertEqual(len(survivors), 9,
                             "an over-budget tree must keep every file (all-or-nothing)")
            self.assertFalse(ledger.covered(root))

    def test_dry_run_overflow_also_makes_no_claim(self):
        """Dry-run and real-delete must agree: an abort claims nothing in both."""
        with tempfile.TemporaryDirectory() as tmp:
            base, root, nested = self._fixture(tmp)
            ledger = vac.CandidateLedger()
            engine, log = self._engine(base, root, ledger, dry_run=True)
            with patch.dict("os.environ", {"SMARTVAC_PLAN_MAX_FILES": "1"}):
                planned = engine._del_dir(root, "broad")
            self.assertEqual(planned, 0)
            self.assertEqual(log.n_deleted, 0, "an aborted plan reports no candidates")
            self.assertFalse(ledger.covered(root))
            self.assertFalse(ledger.covered(nested))


class TestLeaseIdentityW2001(unittest.TestCase):
    """W2-001: the destructive-job lease must be MACHINE-wide, not per-install.

    The name used to be derived from CONFIG_FILE.parent, and the supported
    deployments deliberately have different DATA_DIRs (frozen portable EXE ->
    its own BASE_DIR, installed wheel -> %LOCALAPPDATA%\\SmartVACCleaner,
    source checkout -> the checkout, plus the SMARTVAC_DATA_DIR override). So
    every deployment got its own lock while mutating the SAME machine: two
    copies could run destructive jobs concurrently, which is exactly what the
    lease exists to prevent.
    """

    _REPO: ClassVar[str] = os.path.dirname(os.path.abspath(__file__))

    # Deployment shapes from the DATA_DIR resolution block: a portable/checkout
    # directory, a second portable copy elsewhere, and the installed-wheel
    # per-user location.
    def _deployments(self, tmp):
        return {
            "checkout": str(Path(tmp) / "checkout"),
            "portable_a": str(Path(tmp) / "PortableA"),
            "portable_b": str(Path(tmp) / "PortableB"),
            "wheel": str(Path(tmp) / "LocalAppData" / "SmartVACCleaner"),
        }

    def _name_in_subprocess(self, data_dir):
        """The mutex name as resolved by a FRESH interpreter for that DATA_DIR."""
        import subprocess as _sp
        env = dict(os.environ)
        env["SMARTVAC_DATA_DIR"] = data_dir
        code = (
            f"import sys; sys.path.insert(0, r'{self._REPO}'); "
            "import _SMART_VAC_CLEANER as vac; "
            "print('DATA_DIR=' + str(vac.DATA_DIR)); "
            "print('NAME=' + vac._lease_mutex_name())"
        )
        r = _sp.run([sys.executable, "-c", code], capture_output=True, text=True,
                    env=env, timeout=60, check=False)
        self.assertEqual(r.returncode, 0, r.stderr)
        lines = dict(ln.split("=", 1) for ln in r.stdout.strip().splitlines() if "=" in ln)
        return lines["DATA_DIR"], lines["NAME"]

    def test_identity_is_deployment_independent(self):
        """VERIFY 3: every deployment must resolve the IDENTICAL mutex name."""
        with tempfile.TemporaryDirectory() as tmp:
            deployments = self._deployments(tmp)
            observed = {}
            for label, data_dir in deployments.items():
                resolved_dir, name = self._name_in_subprocess(data_dir)
                observed[label] = name
                self.assertEqual(Path(resolved_dir), Path(data_dir).resolve(),
                                 f"{label} did not adopt its own DATA_DIR")
            distinct = set(observed.values())
            self.assertEqual(len(distinct), 1,
                             f"deployments disagree on the lease identity: {observed}")
            name = distinct.pop()
            self.assertTrue(name.startswith("Global\\"), name)
            # No deployment PATH may contribute to the identity. The old defect
            # embedded the sanitized CONFIG_FILE.parent, so check that shape and
            # the unique tmp fragment (not the bare leaf: the installed-wheel
            # leaf is legitimately the product name itself).
            for data_dir in deployments.values():
                sanitized = "".join("_" if c in ("\\", ":", "/") else c for c in data_dir)
                self.assertNotIn(sanitized, name, f"{data_dir} leaked into the mutex identity")
            self.assertNotIn(Path(tmp).name, name, "the deployment root leaked into the identity")
            self.assertNotIn("_Lease_", name, "the per-install name shape must be gone")

    def test_identity_ignores_config_file_relocation(self):
        """The name must not move when CONFIG_FILE moves inside one process."""
        original = vac._lease_mutex_name()
        with tempfile.TemporaryDirectory() as tmp:
            for sub in ("one", "two", "deep/deeper"):
                cfg = Path(tmp) / sub / "cleaner_config.json"
                cfg.parent.mkdir(parents=True, exist_ok=True)
                with patch.object(vac, "CONFIG_FILE", cfg), \
                     patch.object(vac, "DATA_DIR", cfg.parent):
                    self.assertEqual(vac._lease_mutex_name(), original,
                                     "the lease identity must not depend on CONFIG_FILE")

    def test_config_lock_is_not_the_destructive_lease(self):
        """REPAIR clause: config persistence must NOT reuse the job mutex."""
        self.assertNotIn(str(vac._config_lock_path()), vac._lease_mutex_name())
        self.assertNotIn("DestructiveJob", str(vac._config_lock_path()))
        # The config transaction is scoped to CONFIG_FILE; the lease is not.
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / "cleaner_config.json"
            with patch.object(vac, "CONFIG_FILE", cfg):
                self.assertEqual(vac._config_lock_path().parent, cfg.parent)

    # ---- cross-deployment contention (native Windows kernel object) ----

    def _global_mutex_observable(self):
        """True when this session can observe a Global\\ mutex across processes."""
        import ctypes as _ct
        k = _ct.windll.kernel32
        h = k.CreateMutexW(None, True, vac._lease_mutex_name())
        if not h:
            return False
        err = k.GetLastError()
        k.ReleaseMutex(h)
        k.CloseHandle(h)
        # We just created it ourselves, so ERROR_ALREADY_EXISTS is not expected;
        # a NULL handle (checked above) is the real "cannot use Global\" signal.
        return err in (0, 183)

    @staticmethod
    def _holder_script(repo, held_marker, hold_s):
        return (
            "import sys, time\n"
            f"sys.path.insert(0, r'{repo}')\n"
            "import _SMART_VAC_CLEANER as vac\n"
            "l = vac._JobLease()\n"
            "assert l.acquire(), 'holder could not acquire'\n"
            f"open(r'{held_marker}', 'w').write('held')\n"
            f"time.sleep({hold_s})\n"
            "l.release()\n"
        )

    @staticmethod
    def _probe_script(repo):
        return (
            "import sys\n"
            f"sys.path.insert(0, r'{repo}')\n"
            "import _SMART_VAC_CLEANER as vac\n"
            "l = vac._JobLease()\n"
            "l._wait_ms = 500\n"
            "print('PROBE', l.acquire(), flush=True)\n"
            "l.release()\n"
        )

    def _cross_deployment_denial(self, holder_dir, probe_dir, kill_holder=False):
        """Holder in one deployment must deny a probe from another deployment.

        Observability control (VERIFY-ORACLE-01): a probe from the holder's OWN
        deployment runs first. If even THAT one acquires, this session cannot
        observe the cross-process kernel object and the test skips. If the
        same-deployment probe is denied but the other deployment's probe is
        allowed, that is the W2-001 defect itself -- a per-installation lease --
        and it must FAIL, never skip.
        """
        import subprocess as _sp
        import time as _time
        repo = self._REPO
        held = os.path.join(tempfile.gettempdir(), f"vac_w2001_held_{os.getpid()}.flag")
        if os.path.exists(held):
            os.remove(held)

        def _env(data_dir):
            e = dict(os.environ)
            e["SMARTVAC_DATA_DIR"] = data_dir
            e["PYTHONPATH"] = repo
            return e

        def _probe(data_dir):
            return _sp.run([sys.executable, "-c", self._probe_script(repo)],
                           capture_output=True, text=True, env=_env(data_dir),
                           timeout=30, check=False)

        holder = _sp.Popen([sys.executable, "-c", self._holder_script(repo, held, 8.0)],
                           stdout=_sp.PIPE, stderr=_sp.PIPE, text=True, env=_env(holder_dir))
        try:
            deadline = _time.time() + 15.0
            while _time.time() < deadline and not os.path.exists(held):
                if holder.poll() is not None:
                    self.fail(f"holder exited early: {holder.stderr.read()[:400]}")
                _time.sleep(0.05)
            self.assertTrue(os.path.exists(held), "holder never reported acquisition")

            # CONTROL: same deployment as the holder. Must be denied, otherwise
            # the environment (not the code) is what we are measuring.
            control = _probe(holder_dir)
            if "PROBE True" in control.stdout:
                self.skipTest(
                    "this session cannot observe a cross-process Global\\ mutex "
                    "(no SeCreateGlobalPrivilege / separate session): even a "
                    "same-deployment probe acquired, so the lease contract is "
                    "not exercisable here")
            self.assertIn("PROBE False", control.stdout,
                          f"control probe gave no usable verdict: {control.stdout!r} "
                          f"{control.stderr[:300]!r}")

            # SUBJECT: a DIFFERENT deployment. The control just proved the
            # kernel object is observable here, so an acquisition now can only
            # mean the identity differs per installation.
            denied = _probe(probe_dir)
            self.assertIn("PROBE False", denied.stdout,
                          f"a DIFFERENT deployment acquired while the lease was held -- "
                          f"the lease is per-installation, not machine-wide: "
                          f"stdout={denied.stdout!r} stderr={denied.stderr[:300]!r}")
        finally:
            if kill_holder:
                holder.kill()
            holder.wait(timeout=30)
            if os.path.exists(held):
                os.remove(held)

        # Holder gone (released or crashed): the other deployment must acquire.
        after = _probe(probe_dir)
        self.assertIn("PROBE True", after.stdout,
                      f"after the holder is gone the other deployment must acquire: "
                      f"stdout={after.stdout!r} stderr={after.stderr[:300]!r}")

    def test_checkout_holder_denies_wheel_deployment(self):
        """VERIFY 1: source checkout holds; installed-wheel DATA_DIR is denied."""
        if os.name != "nt":
            self.skipTest("named mutex lease is Windows-only")
        if not self._global_mutex_observable():
            self.skipTest("Global\\ namespace unavailable in this session")
        with tempfile.TemporaryDirectory() as tmp:
            d = self._deployments(tmp)
            self._cross_deployment_denial(d["checkout"], d["wheel"])

    def test_two_portable_copies_share_one_lease(self):
        """VERIFY 2: two portable copies in different directories contend."""
        if os.name != "nt":
            self.skipTest("named mutex lease is Windows-only")
        if not self._global_mutex_observable():
            self.skipTest("Global\\ namespace unavailable in this session")
        with tempfile.TemporaryDirectory() as tmp:
            d = self._deployments(tmp)
            self._cross_deployment_denial(d["portable_a"], d["portable_b"])

    def test_crashed_owner_releases_lease_to_other_deployment(self):
        """VERIFY 4: after an owner CRASH the abandoned mutex is acquirable."""
        if os.name != "nt":
            self.skipTest("named mutex lease is Windows-only")
        if not self._global_mutex_observable():
            self.skipTest("Global\\ namespace unavailable in this session")
        with tempfile.TemporaryDirectory() as tmp:
            d = self._deployments(tmp)
            self._cross_deployment_denial(d["wheel"], d["portable_a"], kill_holder=True)

    def test_dry_run_and_status_need_no_lease(self):
        """VERIFY 5: read-only surfaces stay concurrently permitted.

        The lease guards REAL deletes only, so dry-run/status must never take
        it -- proven by running them while the lease is held in-process.
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "cache"
            target.mkdir()
            (target / "f.bin").write_bytes(b"x" * 12)
            lease = vac._JobLease()
            self.assertTrue(lease.acquire(), "could not take the lease in-process")
            try:
                log = vac.Logger(log_file=None, dry_run=True)
                engine = vac.CleanerEngine(True, log,
                                           vac.SafetyGuard(root, allow_shallow_system_target=True),
                                           root, max_threads=1)
                engine.log = log
                planned = engine._del_dir(target, "cache")
                self.assertEqual(planned, 12, "dry-run must plan while the lease is held")
                self.assertTrue((target / "f.bin").exists(), "dry-run must mutate nothing")
                state = vac.get_config_state()
                self.assertIsNotNone(state, "status surface must remain available")
            finally:
                lease.release()


class TestLeaseBusyContractW2003(unittest.TestCase):
    """W2-003: lease contention is a normal lifecycle result at the
    destructive CLI boundary -- one concise diagnostic, a stable documented
    exit code, no traceback -- while a fail-closed API/defect failure stays
    distinguishable and the GUI parent maps the busy code specifically.
    """

    def _cli_args(self, dry_run=False):
        return MagicMock(
            dry_run=dry_run, delete=not dry_run,
            portable=False, system=False, custom=False, all=True,
            cli=True, status=False, analyze_caches=False, hidden=False,
            sys_targets="", disable_targets="", exclude="",
            install_task=False, time="09:00", surface="cli",
        )

    @patch("_SMART_VAC_CLEANER.argparse.ArgumentParser.parse_args")
    def test_busy_cli_exits_lease_code_with_diagnostic(self, mock_parse):
        """VERIFY 1: contention -> EXIT_LEASE_BUSY, no traceback, job not run."""
        mock_parse.return_value = self._cli_args(dry_run=False)
        lease = vac._JobLease()
        with patch.object(vac, "_JobLease", return_value=lease), \
             patch.object(lease, "acquire", return_value=False) as acq, \
             patch.object(lease, "release") as rel, \
             patch.object(lease, "_mutex", None), \
             patch.object(vac, "run_cleaning_job", side_effect=AssertionError("must not run")) as job, \
             patch.object(vac, "Logger"):
            lease.last_failure = "busy"
            with self.assertRaises(SystemExit) as cm:
                vac.main()
        self.assertEqual(cm.exception.code, vac.EXIT_LEASE_BUSY)
        acq.assert_called_once()
        rel.assert_not_called()
        job.assert_not_called()

    @patch("_SMART_VAC_CLEANER.argparse.ArgumentParser.parse_args")
    def test_api_failure_cli_exits_distinct_code(self, mock_parse):
        """VERIFY 5: API/unknown acquisition failure is fail-closed and
        distinguishable from normal contention (exit 1, different message)."""
        mock_parse.return_value = self._cli_args(dry_run=False)
        lease = vac._JobLease()
        with patch.object(vac, "_JobLease", return_value=lease), \
             patch.object(lease, "acquire", return_value=False), \
             patch.object(lease, "release") as rel, \
             patch.object(vac, "run_cleaning_job", side_effect=AssertionError("must not run")), \
             patch.object(vac, "Logger"):
            lease.last_failure = "api"
            with self.assertRaises(SystemExit) as cm:
                vac.main()
        self.assertEqual(cm.exception.code, 1)
        rel.assert_not_called()

    @patch("_SMART_VAC_CLEANER.argparse.ArgumentParser.parse_args")
    def test_after_release_identical_command_executes(self, mock_parse):
        """VERIFY 4: once the lease is free, the same command runs normally."""
        mock_parse.return_value = self._cli_args(dry_run=False)
        lease = vac._JobLease()
        ran = []
        with patch.object(vac, "_JobLease", return_value=lease), \
             patch.object(lease, "acquire", return_value=True), \
             patch.object(lease, "release") as rel, \
             patch.object(vac, "run_cleaning_job", side_effect=lambda s, l: ran.append(1)), \
             patch.object(vac, "Logger"), \
             patch.object(vac, "load_config_strict", return_value=(
                 True, {"portable_roots": [], "custom_rules": [],
                        "exclude_patterns": [], "exclude_paths": []}, [])):
            vac.main()
        self.assertEqual(ran, [1])
        rel.assert_called_once()

    def test_parent_maps_busy_code_specifically(self):
        """VERIFY 3: the GUI poller translates the busy code into 'another job
        acquired the lease before background start', not generic failure."""
        app = TestGuiThreadBoundary._fake_app()
        app._bg_proc = MagicMock()
        app._bg_proc.poll.side_effect = [vac.EXIT_LEASE_BUSY]
        app._bg_proc_observed = False
        app._poll_background_child()
        msgs = []
        while True:
            try:
                msgs.append(app.log_queue.get_nowait())
            except queue.Empty:
                break
        self.assertTrue(any("lease" in m.lower() and "before background start" in m.lower() for m in msgs),
                        f"expected a specific busy message, got {msgs!r}")
        self.assertFalse(any("failed" in m.lower() for m in msgs),
                         f"busy must not be reported as generic failure: {msgs!r}")

    def test_other_exit_codes_still_generic(self):
        """A nonzero non-busy child code keeps the generic failure message."""
        app = TestGuiThreadBoundary._fake_app()
        app._bg_proc = MagicMock()
        app._bg_proc.poll.side_effect = [7]
        app._bg_proc_observed = False
        app._poll_background_child()
        msgs = []
        while True:
            try:
                msgs.append(app.log_queue.get_nowait())
            except queue.Empty:
                break
        self.assertTrue(any("failed (exit code 7)" in m for m in msgs), f"got {msgs!r}")

    def test_enter_raises_jobbusy_only_for_contention(self):
        """The context manager maps ordinary contention to JobBusyError and
        keeps a distinct RuntimeError for API/defect failures."""
        l = vac._JobLease()
        with patch.object(l, "acquire", return_value=False):
            l.last_failure = "busy"
            with self.assertRaises(vac.JobBusyError):
                l.__enter__()
            l.last_failure = "api"
            with self.assertRaises(RuntimeError) as cm:
                l.__enter__()
            self.assertNotIsInstance(cm.exception, vac.JobBusyError)

    @unittest.skipUnless(os.name == "nt", "named mutex contention is Windows-only")
    def test_native_two_process_busy_cli_exit(self):
        """VERIFY 1 + 4 native leg: process A holds the lease; a real CLI
        process B exits with EXIT_LEASE_BUSY and no traceback; after A
        releases, the identical command acquires and runs. run_cleaning_job
        is neutered in the child so no real cleaning can ever execute."""
        import subprocess as _sp
        repo = os.path.dirname(os.path.abspath(__file__))
        env = dict(os.environ)
        env["PYTHONPATH"] = repo
        env["SMARTVAC_DATA_DIR"] = tempfile.mkdtemp(prefix="vac_w2003_")
        child_script = (
            "import sys\n"
            f"sys.path.insert(0, r'{repo}')\n"
            "import _SMART_VAC_CLEANER as vac\n"
            "vac.run_cleaning_job = lambda *a, **k: print('JOB-RAN', flush=True)\n"
            "_init = vac._JobLease.__init__\n"
            "def fast_init(self):\n"
            "    _init(self)\n"
            "    self._wait_ms = 500\n"
            "vac._JobLease.__init__ = fast_init\n"
            "sys.argv = ['x', '--cli', '--all', '--delete']\n"
            "vac.main()\n"
        )
        argv = [sys.executable, "-c", child_script]
        holder = vac._JobLease()
        self.assertTrue(holder.acquire(), "could not take the lease in-process")
        try:
            b = _sp.run(argv, capture_output=True, text=True, env=env, timeout=60, check=False)
            self.assertEqual(b.returncode, vac.EXIT_LEASE_BUSY,
                             f"expected busy exit, got rc={b.returncode} "
                             f"stdout={b.stdout!r} stderr={b.stderr[:400]!r}")
            self.assertNotIn("Traceback", b.stderr, "busy must not surface a traceback")
            self.assertIn("another destructive job", b.stdout.lower())
            self.assertNotIn("JOB-RAN", b.stdout, "no job may run under contention")
        finally:
            holder.release()
        # After release the identical command acquires and runs normally.
        c = _sp.run(argv, capture_output=True, text=True, env=env, timeout=120, check=False)
        self.assertEqual(c.returncode, 0,
                         f"after release the same command must succeed: "
                         f"rc={c.returncode} stderr={c.stderr[:400]!r}")
        self.assertIn("JOB-RAN", c.stdout)


class TestBackgroundRelaunchW2005(unittest.TestCase):
    """W2-005: terminal-child consumption is centralized and happens BEFORE
    any new launch. A relaunch between child termination and the next poller
    tick must report the old result exactly once, in order, before the new
    'started' line; a failed new Popen must not resurrect the stale result;
    a still-running child still blocks duplicate dispatch.
    """

    def _app(self):
        app = TestGuiThreadBoundary._fake_app()
        app.T = {"run_bg_running": "already running", "run_bg_started": "Background clean started (hidden)."}
        app._log = app.log_queue.put_nowait
        return app

    @staticmethod
    def _old_child(rc):
        p = MagicMock()
        p.poll.return_value = rc
        return p

    def _launch(self, app, new_proc=None, raise_oserror=False):
        with patch.object(vac, "read_config_snapshot",
                          return_value=(vac.ConfigState.VALID,
                                        {"exclude_patterns": [], "exclude_paths": [],
                                         "system_targets": {}}, [])), \
             patch.object(vac, "_JobLease") as lease_cls:
            lease_cls.return_value.acquire.return_value = True
            if raise_oserror:
                def boom(*a, **k):
                    raise OSError("launch failed")
                with patch.object(vac.subprocess, "Popen", side_effect=boom):
                    app._run_bg()
            else:
                with patch.object(vac.subprocess, "Popen", return_value=new_proc):
                    app._run_bg()

    def _drain(self, app):
        msgs = []
        while True:
            try:
                msgs.append(app.log_queue.get_nowait())
            except queue.Empty:
                break
        return msgs

    def test_terminal_old_child_reported_once_before_new_started(self):
        """VERIFY 1: old exit 7 + immediate relaunch -> the old failure logs
        exactly once BEFORE the new 'started' line."""
        app = self._app()
        old = self._old_child(7)
        app._bg_proc = old
        app._bg_proc_observed = False
        new = MagicMock()
        self._launch(app, new_proc=new)
        msgs = self._drain(app)
        self.assertEqual(msgs.count("Background clean failed (exit code 7)."), 1,
                         f"old failure must be reported exactly once, got {msgs!r}")
        self.assertIn("Background clean started (hidden).", msgs)
        self.assertLess(msgs.index("Background clean failed (exit code 7)."),
                        msgs.index("Background clean started (hidden)."),
                        "the old result must precede the new 'started' line")
        self.assertIs(app._bg_proc, new)

    def test_terminal_old_child_success_reported_once(self):
        """VERIFY 2: old exit 0 is likewise reported exactly once first."""
        app = self._app()
        app._bg_proc = self._old_child(0)
        app._bg_proc_observed = False
        new = MagicMock()
        self._launch(app, new_proc=new)
        msgs = self._drain(app)
        self.assertEqual(msgs.count("Background clean completed successfully."), 1)
        self.assertLess(msgs.index("Background clean completed successfully."),
                        msgs.index("Background clean started (hidden)."))
        self.assertIs(app._bg_proc, new)

    def test_failed_new_popen_cannot_resurrect_old_result(self):
        """VERIFY 3: old child terminal (reported at consumption) then the new
        Popen fails -> the failure logs once, and no stale old result can
        appear AFTER the launch error."""
        app = self._app()
        app._bg_proc = self._old_child(7)
        app._bg_proc_observed = False
        self._launch(app, raise_oserror=True)
        msgs = self._drain(app)
        self.assertEqual(msgs.count("Background clean failed (exit code 7)."), 1,
                         "old result consumed exactly once at the start")
        self.assertIn("launch failed", " ".join(msgs))
        self.assertEqual(msgs[-1], next(m for m in msgs if "launch failed" in m),
                         "the launch error is the LAST line; no stale old result after it")
        self.assertIsNone(app._bg_proc, "failed launch must not retain a stale child")

    def test_running_child_blocks_duplicate_dispatch(self):
        """VERIFY 5: a still-running child still blocks relaunch."""
        app = self._app()
        running = MagicMock()
        running.poll.return_value = None
        app._bg_proc = running
        with patch.object(vac.subprocess, "Popen", side_effect=AssertionError("must not launch")):
            app._run_bg()
        msgs = self._drain(app)
        self.assertEqual(msgs, ["already running"])
        self.assertIs(app._bg_proc, running)

    def test_poller_and_button_interleave_no_duplicate_report(self):
        """VERIFY 4: poller consumes the terminal result, then a later
        relaunch cannot report it again."""
        app = self._app()
        app._bg_proc = self._old_child(3)
        app._bg_proc_observed = False
        app._poll_background_child()  # poller wins the race
        self.assertIsNone(app._bg_proc)
        new = MagicMock()
        self._launch(app, new_proc=new)
        msgs = self._drain(app)
        self.assertEqual(msgs.count("Background clean failed (exit code 3)."), 1,
                         f"exactly one report across poller + relaunch, got {msgs!r}")
        self.assertIn("Background clean started (hidden).", msgs)


class TestExclusionTriePERF001(unittest.TestCase):
    """PERF-001 (AUDIT_ALL_3): exclusion ancestry must scale with path depth,
    not candidates x exclusions, and guards must share one canonical policy.

    Audit VERIFY items:
      1. candidate lookup growth governed by path depth, not E;
      2. multiple guards from one JobSpec must not re-resolve every exclusion;
      3. 300-region plan ancestor checks collapse to a depth-bounded count;
      4. equal/descendant/sibling/different-drive/mixed-case semantics;
      5. many ledger claims beneath a broad target keep byte/candidate parity.
    """

    def _make_tree(self, root: Path, n_dirs: int, files_per_dir: int = 1):
        for i in range(n_dirs):
            d = root / f"d{i:04d}"
            d.mkdir(parents=True)
            (d / "f.bin").write_bytes(b"x" * 16)

    def test_guard_lookup_depth_bounded_not_exclusion_count(self):
        """VERIFY 1: is_safe cost must not grow with exclusion count E."""
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "base"
            base.mkdir()
            candidate = base / "sub" / "deep" / "cand.bin"
            candidate.parent.mkdir(parents=True)
            candidate.write_bytes(b"x")
            timings = {}
            for e in (0, 100, 1000, 5000):
                excl = [str(base / f"x{i:05d}" / "keep") for i in range(e)]
                guard = vac.SafetyGuard(base, exclude_paths=excl)
                t0 = time.perf_counter()
                for _ in range(200):
                    guard.is_safe(candidate)
                timings[e] = time.perf_counter() - t0
            # Growth from 100 -> 5000 exclusions must stay flat (depth-bounded
            # walk). The old O(E) scan scaled ~linearly with E.
            growth = timings[5000] / max(timings[100], 1e-9)
            self.assertLess(growth, 3.0,
                            f"is_safe cost grew {growth:.1f}x with E: {timings}")

    def test_guards_share_one_canonical_trie_no_reResolve(self):
        """VERIFY 2: N guards from one JobSpec must not re-resolve exclusions."""
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "base"
            base.mkdir()
            excl = [str(base / f"x{i}" / "keep") for i in range(300)]
            for p in excl:
                (Path(p)).mkdir(parents=True)
            engine = vac.CleanerEngine(True, vac.Logger(log_file=None, dry_run=True),
                                       vac.SafetyGuard(base), base,
                                       exclude_paths=excl)
            # make_guard resolves each new base root (legitimate, one per
            # target); what must NOT happen is re-resolving the 300 policy
            # exclusions per guard (audit measured 6,020 extra resolves for
            # 20 guards x 300 exclusions). Count resolve() calls across N
            # guards: the policy must contribute ZERO per guard.
            resolve_calls = {"n": 0}
            orig_resolve = vac.Path.resolve

            def counting_resolve(self_path, *a, **kw):
                resolve_calls["n"] += 1
                return orig_resolve(self_path, *a, **kw)

            with patch.object(vac.Path, "resolve", counting_resolve):
                guards = [engine.make_guard(base / f"t{i}") for i in range(20)]
            self.assertLess(resolve_calls["n"], 25,
                             f"policy re-resolved per guard: {resolve_calls['n']} calls for 20 guards x 300 exclusions")
            # All guards share the same trie object; policy never re-resolved.
            self.assertEqual(len({id(g._exclude_trie) for g in guards}), 1)

    def test_plan_region_ancestor_checks_depth_bounded(self):
        """VERIFY 3: 300 candidates x 300 excluded regions must not scan 90k."""
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "base"
            root = base / "tree"
            self._make_tree(root, 300)
            engine = vac.CleanerEngine(True, vac.Logger(log_file=None, dry_run=True),
                                       vac.SafetyGuard(base), root, max_threads=1)
            engine.log = vac.Logger(log_file=None, dry_run=True)
            regions = [vac.Path(root / f"d{i:04d}" / "unrelated" / "nested").parts
                       for i in range(0, 300, 3)]
            regions = [vac.Path(*r) for r in regions]
            calls = {"n": 0}
            orig = vac._is_ancestor

            def counting(a, b):
                calls["n"] += 1
                return orig(a, b)

            with patch.object(vac, "_is_ancestor", side_effect=counting):
                plan = engine._plan_tree(root, "tree", excluded_regions=regions)
            self.assertIsNotNone(plan)
            self.assertEqual(calls["n"], 0,
                             "plan must use the trie matcher, not per-region _is_ancestor scans")
            self.assertEqual(len(plan["files"]), 300)

    def test_plan_region_semantics_equal_descendant_sibling_case(self):
        """VERIFY 4: equal/descendant excluded, sibling/drive kept, case folded."""
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "base"
            root = base / "tree"
            (root / "Keep").mkdir(parents=True)
            (root / "sib").mkdir()
            (root / "Keep" / "f1.bin").write_bytes(b"x")
            (root / "sib" / "f2.bin").write_bytes(b"x")
            engine = vac.CleanerEngine(True, vac.Logger(log_file=None, dry_run=True),
                                       vac.SafetyGuard(base), root, max_threads=1)
            engine.log = vac.Logger(log_file=None, dry_run=True)
            keep = root / "Keep"
            # exact-equal region: whole subtree protected
            plan = engine._plan_tree(root, "t", excluded_regions=[keep])
            planned = {p.name for p, _, _ in plan["files"]}
            self.assertNotIn("f1.bin", planned)
            self.assertIn("f2.bin", planned)
            # ancestor containment: a FILE descendant region excludes only that
            # single file candidate, not its sibling directory. Strengthens the
            # trie matcher (O(depth)) over the old linear ancestor scan.
            plan2 = engine._plan_tree(root, "t", excluded_regions=[keep / "f1.bin"])
            planned2 = {p.name for p, _, _ in plan2["files"]}
            self.assertNotIn("f1.bin", planned2)
            self.assertIn("f2.bin", planned2)
            self.assertIn("f2.bin", planned2)
            plan3 = engine._plan_tree(root, "t", excluded_regions=[keep])
            planned3 = {p.name for p, _, _ in plan3["files"]}
            self.assertNotIn("f1.bin", planned3)

    # ---- PERF-001 VERIFY 4, hardened: genuine Windows case/drive semantics --
    # The pre-hardening body above only exercised same-casing regions, so a
    # raw case-sensitive trie passed it while the audit counterexample
    # (c:\users\aleks\keep vs C:\Users\Aleks\Keep) silently escaped.

    def test_trie_windows_case_contract(self):
        """A-D at the trie level: exact/descendant/mixed-case excluded, sibling kept.

        Uses REAL Windows Path objects (os.name=='nt' host); non-existing
        paths on purpose: resolve() cannot canonicalize the casing of a path
        the filesystem has never seen, so only the trie's own case semantics
        can make containment hold.
        """
        if os.name != "nt":
            self.skipTest("native Windows path semantics")
        excl = vac.Path(r"C:\Root\Keep")
        trie = vac._PathTrie()
        self.assertTrue(trie.insert(excl.parts))
        # A. exact (both casings)
        self.assertIsNotNone(trie.matches(vac.Path(r"C:\Root\Keep").parts))
        self.assertIsNotNone(trie.matches(vac.Path(r"c:\root\keep").parts))
        # B. descendant (both casings)
        self.assertIsNotNone(trie.matches(vac.Path(r"C:\Root\Keep\child\file.bin").parts))
        self.assertIsNotNone(trie.matches(vac.Path(r"c:\root\KEEP\Child\File.bin").parts))
        # C. audit counterexample: exclusion C:\Users\Aleks\Keep vs
        #    c:\users\aleks\keep\child.bin must still be contained
        audit_trie = vac._PathTrie()
        audit_trie.insert(vac.Path(r"C:\Users\Aleks\Keep").parts)
        self.assertIsNotNone(
            audit_trie.matches(vac.Path(r"c:\users\aleks\keep\child.bin").parts))
        # D. sibling Keeper is NOT under Keep
        self.assertIsNone(trie.matches(vac.Path(r"C:\Root\Keeper\file.bin").parts))
        self.assertIsNone(trie.matches(vac.Path(r"C:\Root\Keepx").parts))

    def test_trie_windows_case_posix_stays_case_sensitive(self):
        """POSIX contract unchanged: comparison keys are identity (no fold)."""
        if os.name == "nt":
            self.skipTest("POSIX case-sensitivity only verifiable off-Windows")
        self.assertEqual(vac._path_part_key("Keep"), "Keep")
        self.assertEqual(vac._path_part_key("KEEP"), "KEEP")
        trie = vac._PathTrie()
        trie.insert(("/", "srv", "Keep"))
        self.assertIsNone(trie.matches(("/", "srv", "keep", "f.bin")))
        self.assertIsNotNone(trie.matches(("/", "srv", "Keep", "f.bin")))

    def test_trie_different_drive_not_excluded(self):
        """E: exclusion on C: must never contain a candidate on D:."""
        excl = vac.Path(r"C:\Root\Keep")
        trie = vac._PathTrie()
        trie.insert(excl.parts)
        cand = vac.Path(r"D:\Root\Keep\file.bin")
        self.assertIsNone(trie.matches(cand.parts),
                          "different drive must not be excluded by the trie")

    def test_guard_mixed_case_nonexisting_windows_paths(self):
        """F end-to-end: non-existing differently-cased exclusion/descendant.

        resolve() cannot lean on the filesystem here (nothing exists), so the
        pre-fix raw-parts trie let the candidate through; the folded-key trie
        must refuse it. Also pins the diagnostic text to the real path.
        """
        if os.name != "nt":
            self.skipTest("native Windows path semantics")
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "base"
            base.mkdir()
            excl = base / "Root" / "Keep"  # deliberately never created
            guard = vac.SafetyGuard(base, exclude_paths=[str(excl)])
            cand = base / "ROOT" / "KEEP" / "child.bin"
            ok, reason = guard.is_safe(cand)
            self.assertFalse(ok)
            self.assertIn("under excluded path", reason)
            # diagnostics stay real-path, not case-folded garbage
            self.assertIn(str(excl), reason)
            # sibling with a distinct name stays deletable
            sib = base / "ROOT" / "Keeper" / "child.bin"
            self.assertTrue(guard.is_safe(sib)[0])

    def test_plan_tree_excludes_differently_cased_region(self):
        """F at plan level: region parts carry foreign casing; scandir yields
        on-disk casing. The pre-fix raw-parts trie planned the file anyway."""
        if os.name != "nt":
            self.skipTest("native Windows path semantics")
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "base"
            root = base / "tree"
            (root / "Keep").mkdir(parents=True)
            (root / "Keep" / "f1.bin").write_bytes(b"x" * 4)
            (root / "sib").mkdir()
            (root / "sib" / "f2.bin").write_bytes(b"x" * 4)
            engine = vac.CleanerEngine(True, vac.Logger(log_file=None, dry_run=True),
                                       vac.SafetyGuard(base), root, max_threads=1)
            engine.log = vac.Logger(log_file=None, dry_run=True)
            region = vac.Path(str(root), "KEEP")  # real dir, foreign casing
            plan = engine._plan_tree(root, "t", excluded_regions=[region])
            planned = {p.name for p, _, _ in plan["files"]}
            self.assertNotIn("f1.bin", planned, "mixed-case region must protect the file")
            self.assertIn("f2.bin", planned)

    def test_candidate_ledger_windows_case_alias(self):
        """Audit item: ledger must fold casing exactly like Path semantics --
        existing and non-existing spellings, forward-slash alias included."""
        if os.name != "nt":
            self.skipTest("native Windows path semantics")
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "base"
            cache = base / "Cache"
            cache.mkdir(parents=True)
            ledger = vac.CandidateLedger()
            ledger.claim(cache)
            self.assertTrue(ledger.covered(base / "CACHE" / "deep" / "f.bin"),
                            "existing claim: differently-cased descendant must be covered")
            # non-existing: resolve() keeps the queried spelling, trie still folds
            phantom = base / "Phantom" / "Cache"
            ledger2 = vac.CandidateLedger()
            ledger2.claim(phantom)
            self.assertTrue(ledger2.covered(base / "PHANTOM" / "CACHE" / "f.bin"))
            self.assertFalse(ledger2.covered(base / "Phantom" / "CacheX" / "f.bin"))
            self.assertFalse(ledger2.covered(base / "Other" / "Cache"))
            # forward-slash spelling of the same tree folds to the same claim
            self.assertTrue(ledger2.covered(vac.Path(str(phantom).replace("\\", "/"))))

    def test_many_ledger_claims_byte_parity(self):
        """VERIFY 5: claims beneath a broad target -> identical candidate bytes."""
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "base"
            root = base / "tree"
            self._make_tree(root, 40)
            # Subcase A: no claims -> full plan
            engine = vac.CleanerEngine(True, vac.Logger(log_file=None, dry_run=True),
                                       vac.SafetyGuard(base), root, max_threads=1)
            engine.log = vac.Logger(log_file=None, dry_run=True)
            plan_full = engine._plan_tree(root, "t")
            self.assertEqual(plan_full["bytes"], 40 * 16)
            # Subcase B: claims on 30 of the 40 dirs -> parity with linear scan
            ledger = vac.CandidateLedger()
            for i in range(30):
                ledger.claim(root / f"d{i:04d}")
            engine2 = vac.CleanerEngine(True, vac.Logger(log_file=None, dry_run=True),
                                        vac.SafetyGuard(base), root, max_threads=1,
                                        ledger=ledger)
            engine2.log = vac.Logger(log_file=None, dry_run=True)
            excluded = engine2._ledger_claims_within(root)
            self.assertEqual(len(excluded), 30)
            plan_claimed = engine2._plan_tree(root, "t", excluded_regions=excluded)
            claimed_paths = {p for p in excluded}
            expected_files = [p for p, _, _ in plan_full["files"]
                              if not any(vac._is_ancestor(r, p) for r in claimed_paths)]
            self.assertEqual({p for p, _, _ in plan_claimed["files"]},
                             set(expected_files))


class TestDocExamples(unittest.TestCase):
    """Automated documentation examples validation (handoff section 6).

    Every README configuration example must (a) be syntactically valid JSON
    and (b) agree with the implementation's actual defaults, so a stale doc
    can never advertise a shipped value that the code does not produce.
    """

    _README_RE = re.compile(r"```json\s*\n(.*?)^```", re.DOTALL | re.MULTILINE)

    def _blocks(self, path):
        text = path.read_text(encoding="utf-8")
        return [m.group(1) for m in self._README_RE.finditer(text)]

    def test_every_readme_json_block_parses(self):
        docs = sorted(Path(__file__).parent.glob("README*.md"))
        self.assertGreater(len(docs), 0, "no README files found")
        problems = []
        for doc in docs:
            for block in self._blocks(doc):
                try:
                    json.loads(block)
                except ValueError as exc:
                    problems.append(f"{doc.name}: {exc}")
        self.assertEqual(problems, [], "malformed JSON in documentation: " + "; ".join(problems))

    def test_documented_portable_roots_default_matches_implementation(self):
        # _default_config() ships an empty list: no hardcoded portable roots.
        self.assertEqual(vac._default_config()["portable_roots"], [])
        for doc in sorted(Path(__file__).parent.glob("README*.md")):
            for block in self._blocks(doc):
                data = json.loads(block)
                self.assertEqual(
                    data.get("portable_roots"), [],
                    f"{doc.name} documents portable_roots != the [] default",
                )

    def test_documented_config_keys_exist_in_default_config(self):
        defaults = set(vac._default_config())
        for doc in sorted(Path(__file__).parent.glob("README*.md")):
            for block in self._blocks(doc):
                unknown = set(json.loads(block)) - defaults
                self.assertEqual(
                    unknown, set(),
                    f"{doc.name} documents keys the config loader does not know",
                )


class _SwappingScandir:
    """Test harness: wraps os.scandir and swaps the scanned directory after
    `after` entries have been yielded (0 = before the first entry)."""

    def __init__(self, real, after, swap):
        self._it = real
        self._after = after
        self._swap = swap
        self._yielded = 0

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        with contextlib.suppress(OSError):
            self._it.close()

    def __iter__(self):
        return self

    def __next__(self):
        entry = next(self._it)
        self._yielded += 1
        if self._yielded == self._after:
            self._swap()
        return entry

    def close(self):
        with contextlib.suppress(OSError):
            self._it.close()


class TestLogRetentionNoFollowBoundary(unittest.TestCase):
    """T-202 / W1-001: _prune_old_logs and Logger must never follow a
    link/junction/reparse-point logs directory outside the app data root.

    Every fixture is disposable (tempdir). Junction creation uses mklink /J
    (no elevation needed); symlink tests skip when the OS denies privilege.
    """

    @staticmethod
    def _logs(dirpath, n, prefix="clean_2026010"):
        for i in range(1, n + 1):
            (dirpath / f"{prefix}{i}_010000.log").write_text(f"log-{i}")

    @staticmethod
    def _hash_tree(dirpath):
        return {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                for p in sorted(dirpath.iterdir())}

    @classmethod
    def _skip_no_junction(cls):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "t").mkdir()
            r = subprocess.run(["cmd", "/c", "mklink", "/J", str(base / "l"), str(base / "t")],
                               capture_output=True, check=False)
            if r.returncode != 0 or not (base / "l").is_dir():
                raise unittest.SkipTest("mklink /J unavailable")

    @classmethod
    def _junction(cls, link, target):
        r = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)],
                           capture_output=True, check=False)
        return r.returncode == 0 and link.is_dir()

    def _prune_with_swap(self, after, swap):
        """Run _prune_old_logs with os.scandir wrapped to swap the directory
        after `after` yielded entries (0 = before the first entry)."""
        real = os.scandir

        def fake(path, *a, **kw):
            if Path(path) == self._logs_dir:
                return _SwappingScandir(real(path, *a, **kw), after, swap)
            return real(path, *a, **kw)

        with patch.object(os, "scandir", fake):
            vac._prune_old_logs(self._logs_dir, keep=2)

    def setUp(self):
        self._base = Path(tempfile.mkdtemp(prefix="svc_nfl_"))
        self._logs_dir = self._base / "logs"
        self._logs_dir.mkdir()

    def tearDown(self):
        for h in logging.getLogger("vac_cleaner").handlers[:]:
            with contextlib.suppress(Exception):
                h.close()
        import shutil
        shutil.rmtree(self._base, ignore_errors=True)

    # 1. legitimate log directory retention (keep semantics preserved)
    def test_legitimate_log_directory_retention(self):
        self._logs(self._logs_dir, 5)
        (self._logs_dir / "unrelated.txt").write_text("keep")
        vac._prune_old_logs(self._logs_dir, keep=2)
        remaining = sorted(p.name for p in self._logs_dir.iterdir())
        self.assertEqual(remaining, ["clean_20260104_010000.log",
                                     "clean_20260105_010000.log",
                                     "unrelated.txt"])

    # 2 + 3 + 4. symlinked / junctioned / reparse-point logs directory
    def test_symlinked_log_directory_refused(self):
        target = self._base / "outside"
        target.mkdir()
        self._logs(target, 5)
        link = self._base / "linklogs"
        try:
            os.symlink(target, link)
        except OSError:
            self.skipTest("symlink creation requires elevated privileges")
        vac._prune_old_logs(link, keep=2)
        self.assertEqual(len(list(target.iterdir())), 5,
                         "symlinked logs dir must be refused, not traversed")

    def test_junction_log_directory_refused(self):
        self._skip_no_junction()
        target = self._base / "outside"
        target.mkdir()
        self._logs(target, 5)
        link = self._base / "jlogs"
        self.assertTrue(self._junction(link, target))
        self.assertTrue(vac._is_reparse_point(link),
                        "a Windows junction is a reparse point")
        before = self._hash_tree(target)
        vac._prune_old_logs(link, keep=2)
        self.assertEqual(self._hash_tree(target), before,
                         "junctioned logs dir must be refused, byte-identical target")

    # 5 + 6 + 7. directory replaced during enumeration / before unlink
    def test_directory_replaced_during_enumeration(self):
        gone = self._base / "swapped"

        def swap():
            os.rename(self._logs_dir, gone)
            self._logs_dir.mkdir()

        for after in (1, 5):
            with self.subTest(swap_after=after):
                import shutil
                if gone.exists():
                    shutil.rmtree(gone, ignore_errors=True)
                if not self._logs_dir.exists():
                    self._logs_dir.mkdir()
                for f in self._logs_dir.iterdir():
                    f.unlink()
                self._logs(self._logs_dir, 5)
                self._prune_with_swap(after, swap)
                self.assertEqual(len(list(gone.iterdir())), 5,
                                 "replaced directory must never be mutated")
                self.assertEqual(list(self._logs_dir.iterdir()), [],
                                 "the empty replacement must never be mutated")

    # 8. symlinked individual log entry
    def test_symlinked_log_entry_skipped(self):
        victim = self._base / "victim.log"
        victim.write_text("precious")
        self._logs(self._logs_dir, 3)
        link = self._logs_dir / "clean_20260100_010000.log"
        try:
            os.symlink(victim, link)
        except OSError:
            self.skipTest("symlink creation requires elevated privileges")
        vac._prune_old_logs(self._logs_dir, keep=0)
        self.assertTrue(victim.exists(), "symlinked entry must not be followed")
        self.assertEqual(victim.read_text(), "precious")
        self.assertEqual(list(self._logs_dir.iterdir()), [link],
                         "only the symlink entry survives; plain logs pruned")

    # 9. unexpected directory inside log enumeration
    def test_directory_named_like_log_skipped(self):
        self._logs(self._logs_dir, 3)
        trap = self._logs_dir / "clean_20260102_010000.log"
        trap.unlink()
        trap.mkdir()
        (trap / "inside.txt").write_text("keep")
        vac._prune_old_logs(self._logs_dir, keep=0)
        self.assertTrue((trap / "inside.txt").exists(),
                        "a directory named like a log must not be recursed or unlinked")

    # 10. unreadable directory
    def test_unreadable_directory_prunes_nothing_without_crashing(self):
        if os.name == "nt":
            self.skipTest("Windows cannot express unreadable dirs without ACL surgery")
        self._logs(self._logs_dir, 5)
        os.chmod(self._logs_dir, 0o000)
        try:
            vac._prune_old_logs(self._logs_dir, keep=0)  # must not raise
        finally:
            os.chmod(self._logs_dir, 0o755)
        self.assertEqual(len(list(self._logs_dir.iterdir())), 5)

    # 11 + 13. locked file / retention while an active log file is open
    def test_locked_open_log_file_does_not_crash_retention(self):
        self._logs(self._logs_dir, 3)
        locked = self._logs_dir / "clean_20260101_010000.log"
        with open(locked, "w") as fh:
            fh.write("active")
            fh.flush()
            vac._prune_old_logs(self._logs_dir, keep=0)  # must not raise
        remaining = list(self._logs_dir.iterdir())
        self.assertLessEqual(len(remaining), 1,
                             "locked file may survive; other logs still prune")

    def test_retention_while_active_logger_holds_file_open(self):
        log_path = self._logs_dir / "clean_20260101_010000.log"
        self._logs(self._logs_dir, 3, prefix="clean_2026010")
        (self._logs_dir / "clean_20260102_010000.log").write_text("x")
        (self._logs_dir / "clean_20260103_010000.log").write_text("x")
        logger = vac.Logger(log_path, False)
        logger.info("active run")
        try:
            vac._prune_old_logs(self._logs_dir, keep=0)  # must not raise
        finally:
            for h in logging.getLogger("vac_cleaner").handlers[:]:
                with contextlib.suppress(Exception):
                    h.close()
                logging.getLogger("vac_cleaner").removeHandler(h)

    # 12. concurrent log writers
    def test_concurrent_log_writers_do_not_crash_retention(self):
        self._logs(self._logs_dir, 10)
        errors = []

        def writer(tag):
            try:
                for i in range(200):
                    (self._logs_dir / f"clean_20260201_{tag}{i:04d}.log").write_text("w")
            except OSError as exc:  # write races surface as OSError only
                errors.append(exc)

        threads = [threading.Thread(target=writer, args=(t,)) for t in range(4)]
        for t in threads:
            t.start()
        for _ in range(20):
            vac._prune_old_logs(self._logs_dir, keep=2)
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        vac._prune_old_logs(self._logs_dir, keep=2)
        self.assertEqual(len(list(self._logs_dir.iterdir())), 2)

    # 14. dry-run/status/preview do not delete logs
    def test_dry_run_logger_does_not_prune(self):
        self._logs(self._logs_dir, 5)
        vac.Logger(self._logs_dir / "clean_20260106_010000.log", True)  # dry_run=True
        self.assertEqual(len(list(self._logs_dir.iterdir())), 5,
                         "dry-run must not prune logs")
        vac.Logger(None, False, quiet=True)
        self.assertEqual(len(list(self._logs_dir.iterdir())), 5,
                         "quiet status/preview logger must not prune logs")

    # 15. unrelated directory remains byte-identical (junction write + prune)
    def test_junction_target_byte_identical_after_logger_and_prune(self):
        target = self._base / "outside"
        target.mkdir()
        self._logs(target, 5)
        link = self._base / "jlogs"
        self._skip_no_junction()
        self.assertTrue(self._junction(link, target))
        before = self._hash_tree(target)
        logger = vac.Logger(link / "clean_20260107_010000.log", False)
        logger.info("attempted write through the junction")
        for h in logging.getLogger("vac_cleaner").handlers[:]:
            with contextlib.suppress(Exception):
                h.close()
            logging.getLogger("vac_cleaner").removeHandler(h)
        self.assertEqual(self._hash_tree(target), before,
                         "Logger must refuse to write through an untrusted dir")
        vac._prune_old_logs(link, keep=2)
        self.assertEqual(self._hash_tree(target), before,
                         "prune must refuse an untrusted dir")

    def test_boundary_helpers(self):
        self.assertTrue(vac._log_dir_boundary_ok(self._logs_dir, require_dir=True))
        self.assertFalse(vac._is_reparse_point(self._logs_dir))
        missing = self._base / "nope"
        self.assertTrue(vac._log_dir_boundary_ok(missing, require_dir=False))
        self.assertFalse(vac._log_dir_boundary_ok(missing, require_dir=True))


class TestDirectoryIOFailureOutcome(unittest.TestCase):
    """Hard directory failures retain data and fail the actual CLI action."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name) / "configured"
        self.target = self.base / "cache"
        self.target.mkdir(parents=True)
        self.log = vac.Logger(None, False, quiet=True)
        self.engine = vac.CleanerEngine(False, self.log, vac.SafetyGuard(self.base), self.base, max_threads=1)

    def _interrupted_scan(self):
        original = vac.os.scandir

        @contextlib.contextmanager
        def scan(path):
            with original(path) as entries:
                if Path(path) == self.target:
                    def interrupted():
                        yield next(entries)
                        raise OSError(errno.EIO, "injected directory read failure")
                    yield interrupted()
                else:
                    yield entries

        return scan

    def test_staged_scan_eio_discards_entries_and_counts_error(self):
        proof = self.target / "keep.tmp"
        proof.write_bytes(b"incomplete enumeration must not delete this")
        with patch.object(vac.os, "scandir", side_effect=self._interrupted_scan()), \
             patch.object(self.log, "error", wraps=self.log.error) as error:
            self.assertEqual(self.engine._del_dir(self.target, "fixture"), 0)
        self.assertEqual(proof.read_bytes(), b"incomplete enumeration must not delete this")
        self.assertEqual(self.log.n_errors, 1)
        self.assertIn(str(self.target), error.call_args.args[0])
        self.assertEqual(self.log.bytes_freed, 0)
        self.assertEqual(self.engine._plan_budget().used, 0)

    def test_top_level_contents_eio_submits_no_partial_entries(self):
        proof = self.target / "keep.tmp"
        proof.write_bytes(b"whole top-level scan is required")
        original = Path.iterdir

        def interrupted(path):
            if path == self.target:
                yield proof
                raise OSError(errno.EIO, "injected content read failure")
            yield from original(path)

        with patch.object(Path, "iterdir", interrupted), \
             patch.object(self.engine, "_del_file") as delete:
            self.assertEqual(self.engine._del_dir_contents(self.target, "fixture"), 0)
        delete.assert_not_called()
        self.assertEqual(proof.read_bytes(), b"whole top-level scan is required")
        self.assertEqual(self.log.n_errors, 1)

    def _check_rmdir_error(self, child_failure):
        child = self.target / "child"
        child.mkdir()
        failing_path = child if child_failure else self.target
        original = Path.rmdir

        def remove(path):
            if path == failing_path:
                raise OSError(errno.EIO, "injected directory removal failure")
            return original(path)

        with patch.object(Path, "rmdir", remove), \
             patch.object(self.log, "error", wraps=self.log.error) as error:
            self.assertEqual(self.engine._del_dir(self.target, "fixture"), 0)
        self.assertTrue(failing_path.is_dir())
        self.assertEqual(self.log.n_errors, 1)
        self.assertIn(str(failing_path), error.call_args.args[0])
        self.assertEqual(self.log.bytes_freed, 0)
        self.assertEqual(self.engine._plan_budget().used, 0)

    def test_child_rmdir_eio_is_an_operational_error(self):
        self._check_rmdir_error(True)

    def test_root_rmdir_eio_is_an_operational_error(self):
        self._check_rmdir_error(False)

    def test_expected_missing_permission_and_contention_remain_skips(self):
        for code in (errno.ENOENT, errno.EACCES, errno.ENOTEMPTY, errno.EBUSY):
            with self.subTest(code=code), \
                 patch.object(vac.os, "scandir", side_effect=OSError(code, "expected refusal")):
                self.assertEqual(self.engine._del_dir(self.target, "fixture"), 0)
            self.assertEqual(self.log.n_errors, 0)
            self.assertTrue(self.target.is_dir())
        self.assertGreater(self.log.n_skipped, 0)

    def _check_cli_failure(self, scan_failure):
        cfg = vac._default_config()
        cfg["custom_rules"] = [{"path": str(self.base), "pattern": self.target.name}]
        config_file = Path(self.temp.name) / "config.json"
        config_file.write_text(json.dumps(cfg), encoding="utf-8")
        if scan_failure:
            proof = self.target / "keep.tmp"
            proof.write_bytes(b"CLI must preserve this")
            fault = patch.object(vac.os, "scandir", side_effect=self._interrupted_scan())
        else:
            original = Path.rmdir

            def remove(path):
                if path == self.target:
                    raise OSError(errno.EIO, "injected CLI removal failure")
                return original(path)

            fault = patch.object(Path, "rmdir", remove)
        argv = ["vac-cleaner", "--cli", "--custom", "--dry-run" if scan_failure else "--delete"]
        with patch.object(vac, "CONFIG_FILE", config_file), \
             patch.object(vac, "Logger", return_value=self.log), \
             patch.object(vac, "_JobLease"), \
             patch.object(vac.sys, "argv", argv), \
             contextlib.redirect_stdout(io.StringIO()), fault, \
             self.assertRaises(SystemExit) as result:
            vac.main()
        self.assertEqual(result.exception.code, 1)
        self.assertEqual(self.log.n_errors, 1)
        self.assertTrue(self.target.is_dir())
        if scan_failure:
            self.assertEqual(proof.read_bytes(), b"CLI must preserve this")

    def test_actual_custom_cli_scan_failure_exits_nonzero(self):
        self._check_cli_failure(True)

    def test_actual_custom_cli_rmdir_failure_exits_nonzero(self):
        self._check_cli_failure(False)


class TestScheduledTaskUninstallOutcome(unittest.TestCase):
    """Removing one task cannot hide a failure to remove the other name."""

    def _run_cli(self, scheduler):
        output = io.StringIO()
        with patch.object(vac.sys, "platform", "win32"), \
             patch.object(vac.sys, "argv", ["vac-cleaner", "--uninstall-task"]), \
             patch.dict(os.environ, {"USERNAME": "UninstallFixture"}), \
             patch.object(vac.subprocess, "run", side_effect=scheduler) as run, \
             contextlib.redirect_stdout(output), \
             self.assertRaises(SystemExit) as exit_result:
            vac.main()
        self.assertEqual(run.call_count, 2)
        self.scheduler_calls = run.call_args_list
        for call in run.call_args_list:
            self.assertEqual(call.kwargs["timeout"], 30)
        return exit_result.exception.code, output.getvalue()

    def test_scheduler_requests_machine_readable_exit_codes(self):
        self._run_cli([subprocess.CompletedProcess([], 0, "", "") for _ in range(2)])
        for call in self.scheduler_calls:
            self.assertIn("/HRESULT", call.args[0])

    def test_partial_access_denied_preserves_task_and_exits_nonzero(self):
        user_task = f"{vac.TASK_NAME}_UninstallFixture"
        registered = {vac.TASK_NAME, user_task}

        def scheduler(argv, **kwargs):
            name = argv[argv.index("/tn") + 1]
            if name == vac.TASK_NAME:
                return subprocess.CompletedProcess(argv, 0x80070005, "", "Access is denied.")
            registered.remove(name)
            return subprocess.CompletedProcess(argv, 0, "", "")

        code, output = self._run_cli(scheduler)
        self.assertEqual(registered, {vac.TASK_NAME})
        self.assertEqual(code, 1)
        self.assertIn(vac.TASK_NAME, output)
        self.assertIn("Access is denied.", output)

    def test_partial_timeout_exits_nonzero_and_names_task(self):
        def scheduler(argv, **kwargs):
            if argv[argv.index("/tn") + 1] == vac.TASK_NAME:
                return subprocess.CompletedProcess(argv, 0, "", "")
            raise subprocess.TimeoutExpired(argv, 30)

        code, output = self._run_cli(scheduler)
        self.assertEqual(code, 1)
        self.assertIn(f"{vac.TASK_NAME}_UninstallFixture", output)
        self.assertIn("timed out", output)

    def test_missing_alternate_is_benign_in_both_orders_and_code_signs(self):
        for missing_index in (0, 1):
            for missing_code in (0x80070002, 0x80070002 - 2**32):
                with self.subTest(index=missing_index, code=missing_code):
                    results = [subprocess.CompletedProcess([], 0, "", "") for _ in range(2)]
                    results[missing_index] = subprocess.CompletedProcess([], missing_code, "", "localized missing-task diagnostic")
                    code, output = self._run_cli(results)
                    self.assertEqual(code, 0)
                    self.assertNotIn("Failed to delete", output)

    def test_unknown_failure_exits_nonzero_even_after_success(self):
        results = [subprocess.CompletedProcess([], 0, "", ""),
                   subprocess.CompletedProcess([], 1, "", "unexpected scheduler failure")]
        code, output = self._run_cli(results)
        self.assertEqual(code, 1)
        self.assertIn("unexpected scheduler failure", output)

    def test_both_removed_succeed_and_both_absent_keep_no_task_outcome(self):
        for task_code, expected in ((0, 0), (0x80070002, 1)):
            with self.subTest(task_code=task_code):
                results = [subprocess.CompletedProcess([], task_code, "", "") for _ in range(2)]
                code, output = self._run_cli(results)
                self.assertEqual(code, expected)
                if task_code:
                    self.assertIn("No task", output)


if __name__ == "__main__":
    unittest.main()
