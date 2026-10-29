"""T-213: Cleanup rules regression tests for SMART_VAC_CLEANER.

Verifies the 5 targeted cleanup rules:
1. .tmp.driveupload Google Drive cache
2. .9router-build build cache
3. user-root stray node_modules
4. test sandboxes ctx-fixtures, testfb, CamoSetup
5. active system TEMP / _TEMP_ test fixtures older than 24h (stale fixtures deleted,
   fresh fixtures <24h and non-fixture files preserved).
"""

import os
import time
from pathlib import Path

import pytest

import _SMART_VAC_CLEANER as vac


@pytest.fixture
def isolated_roots(tmp_path):
    """Provides a completely isolated mock system roots environment."""
    user_temp = tmp_path / "UserTemp"
    user_temp.mkdir()
    system_temp = tmp_path / "SystemTemp"
    system_temp.mkdir()
    drive_temp = tmp_path / "DriveTemp"
    drive_temp.mkdir()
    loc = tmp_path / "LocalAppData"
    loc.mkdir()
    roam = tmp_path / "Roaming"
    roam.mkdir()
    user_prof = tmp_path / "UserProfile"
    user_prof.mkdir()

    roots = {
        "SYSTEM_TEMP": system_temp,
        "USER_TEMP": user_temp,
        "USER_CRASH": None,
        "USER_EXPLORER": None,
        "LOCALAPPDATA": loc,
        "APPDATA": roam,
        "WINDIR": None,
        "USER_APPDATA_TARGETS": (),
        "appdata_target_count": 0,
        "USERPROFILE": user_prof,
        "DRIVE_TEMP": drive_temp,
    }
    return roots


def _make_cleaner(roots, dry_run=False):
    log = vac.Logger(log_file=None, dry_run=dry_run)
    return vac.SystemCleaner(dry_run, log, system_roots=roots)


@pytest.mark.parametrize("running", [None, set(), {"drivefs.exe"}])
@pytest.mark.parametrize("dry_run", [False, True])
def test_tmp_driveupload_cache_preserved(isolated_roots, monkeypatch, running, dry_run):
    """Rule 1 (T-216 corrected): .tmp.driveupload Google Drive upload staging is
    NEVER auto-deleted, regardless of age, process snapshot, or root location.

    Upload completion is UNKNOWN; old staging may hold unsynchronized user data.
    All four registered roots are covered: user temp, drive temp, Local
    Google\\DriveFS, and user profile.
    """
    monkeypatch.setattr(vac, "get_running_processes", lambda: running)
    u_temp = isolated_roots["USER_TEMP"]
    d_temp = isolated_roots["DRIVE_TEMP"]
    prof = isolated_roots["USERPROFILE"]
    loc = isolated_roots["LOCALAPPDATA"]
    drivefs = loc / "Google" / "DriveFS"
    drivefs.mkdir(parents=True)

    old_time = time.time() - 90000
    target_dir1 = u_temp / ".tmp.driveupload"
    target_dir1.mkdir()
    (target_dir1 / "chunk.bin").write_bytes(b"data")
    os.utime(target_dir1 / "chunk.bin", (old_time, old_time))
    os.utime(target_dir1, (old_time, old_time))

    target_file1 = d_temp / ".tmp.driveupload"
    target_file1.write_bytes(b"meta")
    os.utime(target_file1, (old_time, old_time))

    target_dir2 = drivefs / ".tmp.driveupload"
    target_dir2.mkdir()
    (target_dir2 / "sub.dat").write_bytes(b"sub")
    os.utime(target_dir2 / "sub.dat", (old_time, old_time))
    os.utime(target_dir2, (old_time, old_time))

    target_dir3 = prof / ".tmp.driveupload"
    target_dir3.mkdir()
    os.utime(target_dir3, (old_time, old_time))

    nested = target_dir1 / "upload.part"
    nested.write_bytes(b"partial")
    os.utime(nested, (old_time, old_time))

    empty_staging = u_temp / ".tmp.driveupload_empty"
    empty_staging.mkdir()

    cleaner = _make_cleaner(isolated_roots, dry_run=dry_run)
    freed = cleaner._deep_junk_sweep()

    assert target_dir1.exists()
    assert (target_dir1 / "chunk.bin").exists()
    assert target_file1.exists()
    assert target_dir2.exists()
    assert (target_dir2 / "sub.dat").exists()
    assert target_dir3.exists()
    assert nested.exists()
    assert empty_staging.exists()
    assert freed == 0, "No upload staging bytes may be reclaimed automatically"


def test_tmp_driveupload_preserved_when_drivefs_running(isolated_roots, monkeypatch):
    """T-216: even when drivefs process enumeration fails/returns UNKNOWN,
    staging data survives; when drivefs IS reported running, still survives.
    This closes the UNKNOWN-process-snapshot-as-no-drive regression.
    """
    monkeypatch.setattr(vac, "get_running_processes", lambda: {"drivefs.exe"})
    u_temp = isolated_roots["USER_TEMP"]
    old_time = time.time() - 90000
    staging = u_temp / ".tmp.driveupload"
    staging.mkdir()
    (staging / "upload.part").write_bytes(b"frag")
    os.utime(staging / "upload.part", (old_time, old_time))
    os.utime(staging, (old_time, old_time))

    cleaner = _make_cleaner(isolated_roots)
    freed = cleaner._deep_junk_sweep()
    assert staging.exists()
    assert (staging / "upload.part").exists()
    assert freed == 0


def test_9router_build_cache_cleaned(isolated_roots):
    """Rule 2: .9router-build build cache in profile, temp, drive temp, and local appdata."""
    prof = isolated_roots["USERPROFILE"]
    u_temp = isolated_roots["USER_TEMP"]
    d_temp = isolated_roots["DRIVE_TEMP"]
    loc = isolated_roots["LOCALAPPDATA"]

    target1 = prof / ".9router-build"
    target1.mkdir()
    (target1 / "cache.json").write_text("{}")
    os.utime(target1, (time.time() - 90000, time.time() - 90000))
    for p in target1.rglob("*"):
        os.utime(p, (time.time() - 90000, time.time() - 90000))

    target2 = u_temp / ".9router-build"
    target2.mkdir()
    os.utime(target2, (time.time() - 90000, time.time() - 90000))

    target3 = d_temp / ".9router-build"
    target3.mkdir()
    os.utime(target3, (time.time() - 90000, time.time() - 90000))

    target4 = loc / ".9router-build"
    target4.mkdir()
    os.utime(target4, (time.time() - 90000, time.time() - 90000))

    cleaner = _make_cleaner(isolated_roots)
    cleaner._deep_junk_sweep()

    assert not target1.exists()
    assert not target2.exists()
    assert not target3.exists()
    assert not target4.exists()
    assert prof.exists(), "UserProfile itself must never be removed"


def test_user_root_stray_node_modules_cleaned(isolated_roots):
    """Rule 3: user-root stray node_modules deleted, while UserProfile root survives."""
    prof = isolated_roots["USERPROFILE"]
    nm = prof / "node_modules"
    nm.mkdir()
    pkg = nm / "lodash"
    pkg.mkdir()
    (pkg / "index.js").write_text("module.exports = {};")

    # Important user file in profile must not be touched
    keep = prof / "important.txt"
    keep.write_text("keep me")

    cleaner = _make_cleaner(isolated_roots)
    cleaner._deep_junk_sweep()

    assert nm.exists(), "User-root node_modules is potentially intentional user data and must survive"
    assert prof.exists(), "UserProfile root must survive"
    assert keep.exists(), "User files in UserProfile must survive"


def test_test_sandboxes_cleaned(isolated_roots):
    """Rule 4: test sandboxes ctx-fixtures, testfb, CamoSetup in temp roots."""
    u_temp = isolated_roots["USER_TEMP"]
    d_temp = isolated_roots["DRIVE_TEMP"]
    s_temp = isolated_roots["SYSTEM_TEMP"]

    old_time = time.time() - 90000
    sb1 = u_temp / "ctx-fixtures-run1"
    sb1.mkdir()
    (sb1 / "fixture.log").write_text("log")
    os.utime(sb1, (old_time, old_time))
    for p in sb1.rglob("*"):
        os.utime(p, (old_time, old_time))

    sb2 = d_temp / "testfb-run"
    sb2.mkdir()
    os.utime(sb2, (old_time, old_time))

    sb3 = s_temp / "CamoSetup_sandbox"
    sb3.mkdir()
    os.utime(sb3, (old_time, old_time))

    cleaner = _make_cleaner(isolated_roots)
    cleaner._deep_junk_sweep()

    assert not sb1.exists()
    assert not sb2.exists()
    assert not sb3.exists()


def test_active_temp_test_fixtures_age_filter(isolated_roots, monkeypatch):
    """Rule 5: fixtures older than 24h are deleted, fresh fixtures (<24h) and non-fixtures survive."""
    # No pytest/agent worker runs in this test, so the AGE rule is what decides
    # here. The running-worker refusal is proven by its own test below.
    monkeypatch.setattr(vac, "get_running_processes", lambda: set())
    now = time.time()
    old_time = now - 90000  # 25 hours ago (>24h)
    fresh_time = now - 3600  # 1 hour ago (<24h)

    d_temp = isolated_roots["DRIVE_TEMP"]
    u_temp = isolated_roots["USER_TEMP"]

    # Old fixtures (> 24h) -> must be deleted
    stale_pytest = d_temp / "pytest-worker-stale"
    stale_pytest.mkdir()
    os.utime(stale_pytest, (old_time, old_time))

    stale_audapack = d_temp / "audapack_test_runtime_123"
    stale_audapack.mkdir()
    os.utime(stale_audapack, (old_time, old_time))

    stale_audit = u_temp / "audit_checks_abc"
    stale_audit.mkdir()
    os.utime(stale_audit, (old_time, old_time))

    # Fresh fixtures (< 24h) -> MUST SURVIVE
    fresh_pytest = d_temp / "pytest-worker-fresh"
    fresh_pytest.mkdir()
    os.utime(fresh_pytest, (fresh_time, fresh_time))

    fresh_audit = u_temp / "audit_checks_fresh"
    fresh_audit.mkdir()
    os.utime(fresh_audit, (fresh_time, fresh_time))

    # Non-fixture files/dirs (> 24h) -> MUST SURVIVE (no test keyword)
    old_doc = d_temp / "notes_from_yesterday.txt"
    old_doc.write_text("notes")
    os.utime(old_doc, (old_time, old_time))

    old_app_dir = u_temp / "latest.log"
    old_app_dir.write_text("latest log")
    os.utime(old_app_dir, (old_time, old_time))

    # Old directory containing a fresh file -> MUST SURVIVE (A/B)
    stale_with_fresh = d_temp / "pytest-stale-with-fresh"
    stale_with_fresh.mkdir()
    os.utime(stale_with_fresh, (old_time, old_time))
    fresh_child = stale_with_fresh / "fresh.txt"
    fresh_child.write_text("fresh")
    # parent mtime stays old

    cleaner = _make_cleaner(isolated_roots)
    cleaner._deep_junk_sweep()

    # Assert old fixtures deleted
    assert not stale_pytest.exists(), "Stale pytest fixture must be deleted"
    assert not stale_audapack.exists(), "Stale audapack test fixture must be deleted"
    assert not stale_audit.exists(), "Stale audit fixture must be deleted"

    # Assert fresh fixtures and non-fixture items survive
    assert fresh_pytest.exists(), "Fresh pytest fixture (<24h) must survive"
    assert fresh_audit.exists(), "Fresh audit fixture (<24h) must survive"
    assert old_doc.exists(), "Non-fixture document must survive"
    assert old_app_dir.exists(), "latest.log must survive"
    assert stale_with_fresh.exists(), "Old dir with fresh child must survive"
    assert fresh_child.exists(), "Fresh child data must survive"


def test_running_pytest_worker_refuses_stale_pytest_fixture(isolated_roots, monkeypatch):
    """A live pytest worker owns pytest-* fixtures: they are NOT authorized."""
    old_time = time.time() - 90000
    d_temp = isolated_roots["DRIVE_TEMP"]
    stale_pytest = d_temp / "pytest-worker-stale"
    stale_pytest.mkdir()
    os.utime(stale_pytest, (old_time, old_time))
    stale_audit = d_temp / "audit_checks_abc"
    stale_audit.mkdir()
    os.utime(stale_audit, (old_time, old_time))
    monkeypatch.setattr(
        vac, "get_running_processes", lambda: {r"c:\python311\scripts\pytest.exe"}
    )

    cleaner = _make_cleaner(isolated_roots)
    cleaner._deep_junk_sweep()

    assert stale_pytest.exists(), "A live pytest worker owns the fixture; it must survive"
    assert not stale_audit.exists(), "An unrelated stale fixture is still cleaned"


def test_locked_or_recently_written_fixture_is_active_work(isolated_roots, monkeypatch):
    """A fixture holding a lock or a very recent write is active work."""
    monkeypatch.setattr(vac, "get_running_processes", lambda: set())
    old_time = time.time() - 90000
    d_temp = isolated_roots["DRIVE_TEMP"]
    locked = d_temp / "pytest-worker-locked"
    locked.mkdir()
    (locked / "worker.lock").write_text("locked")
    os.utime(locked, (old_time, old_time))
    os.utime(locked / "worker.lock", (old_time, old_time))
    recent = d_temp / "audit_checks_recent"
    recent.mkdir()
    os.utime(recent, (old_time, old_time))
    (recent / "live.bin").write_text("live")

    cleaner = _make_cleaner(isolated_roots)
    cleaner._deep_junk_sweep()

    assert locked.exists(), "A fixture with a lock file is active work and must survive"
    assert (locked / "worker.lock").exists(), "The lock file itself must survive"
    assert recent.exists(), "A fixture with a very recent write is active work and must survive"


def test_resolve_system_roots_exposes_userprofile_and_drive_temp():
    """CORE root snapshot includes validated USERPROFILE and DRIVE_TEMP."""
    roots = vac.resolve_system_roots()
    assert "USERPROFILE" in roots
    assert "DRIVE_TEMP" in roots

    if roots["USERPROFILE"] is not None:
        p = Path(roots["USERPROFILE"])
        assert p.is_absolute()
        assert not vac._is_under(vac.BASE_DIR, p)

    if roots["DRIVE_TEMP"] is not None:
        p = Path(roots["DRIVE_TEMP"])
        assert p.is_absolute()
        assert not vac._is_under(vac.BASE_DIR, p)
