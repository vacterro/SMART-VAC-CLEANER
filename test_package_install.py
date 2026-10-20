#!/usr/bin/env python3
"""F6/T-140 clean-install smoke test for the wheel contract.

Proves that `pip install .` works OUTSIDE the repository, not only as a source
checkout:

  1. build the wheel (--no-deps)
  2. create a clean venv (system-site-packages so the heavy GUI deps are
     visible without re-downloading them -- the wheel's OWN files still come
     from the wheel)
  3. pip install the wheel
  4. point the INSTALLED cleaner at a temp fixture via SMARTVAC_DATA_DIR
     (T-139 resolver) and run:
        vac-cleaner --help
        vac-cleaner --status
        a dry-run that MUST plan the 64-byte fixture exactly once
  5. prove the imported modules/locales come from the installed wheel, not the
     repository or the global environment, by running from a cwd outside the
     repo and asserting the module paths live inside the venv site-packages.

The PyInstaller exe is a SEPARATE contract (build_exe.ps1 / build-exe.yml).

Run:  python test_package_install.py
Exit code 0 = smoke OK.

W2-006 (AUDIT_ALL_3 RUN_ID acb-mtk1nqt0): the installed dry-run MUST plan a
real candidate. Production is_path_blacklisted() refuses portable roots on
the Windows installation drive, so the fixture is created on a permitted
non-system drive when one exists. If no permitted drive is available the
sub-check FAILS the smoke instead of silently skipping -- the release gate
must never pass without exercising the installed candidate planner
(AUDIT VERIFY items 1 and 2).
"""
import os
import subprocess
import sys
import tempfile
import venv
from pathlib import Path


def run(cmd, cwd=None, check=True, env=None):
    r = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd, check=False, env=env)
    if check and r.returncode != 0:
        print(r.stdout)
        print(r.stderr)
        raise SystemExit(f"FAILED: {' '.join(map(str, cmd))}")
    return r


def _candidate_volume_candidates() -> list[str | None]:
    """W2-006: deterministic permitted-fixture volume selection.

    Production is_path_blacklisted() (CORE-001) rejects any portable root
    that equals/contains a protected root: C:\\, windir, USERPROFILE, Program
    Files (both), SCRIPT_PATH.parent and BASE_DIR. On a single-drive host
    (GitHub windows-latest) EVERY temp fixture is a descendant of C:\\ and
    would be refused, which is exactly why the old harness grew a skip
    branch. A non-system FIXED drive cannot collide with any protected root
    of the installed subprocess (its SCRIPT_PATH.parent/BASE_DIR live on the
    system drive), so it is the permitted surface. Drives are tried in sorted
    order; the Windows drive is excluded; removable/network drives are not
    candidates. Non-Windows hosts accept the temp dir as-is (no drive
    blacklist concept there).
    """
    if os.name != "nt":
        return [None]
    import ctypes
    kernel32 = ctypes.windll.kernel32
    kernel32.GetWindowsDirectoryW.restype = ctypes.c_int
    kernel32.GetWindowsDirectoryW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint]
    buf = ctypes.create_unicode_buffer(260)
    if kernel32.GetWindowsDirectoryW(buf, 260) == 0:
        raise SystemExit(
            "W2-006: cannot determine the Windows installation drive "
            "(GetWindowsDirectoryW failed); refusing to guess a fixture volume"
        )
    system_drive = str(Path(buf.value).resolve().drive).upper()
    drives: list[str] = []
    mask = kernel32.GetLogicalDrives()
    for i in range(26):
        if mask >> i & 1:
            letter = f"{chr(65 + i)}:"
            if letter.upper() == system_drive:
                continue
            if kernel32.GetDriveTypeW(ctypes.c_wchar_p(letter + "\\")) == 3:  # DRIVE_FIXED
                drives.append(letter)
    return sorted(drives)


def main() -> int:
    root = Path(__file__).resolve().parent
    tmp = Path(tempfile.mkdtemp(prefix="vac_pkg_test_"))
    print(f"workdir: {tmp}")

    wheel_dir = tmp / "wheel"
    wheel_dir.mkdir()
    venv_dir = tmp / "venv"

    # 1. build the wheel
    run([sys.executable, "-m", "pip", "wheel", "--no-deps", "-w", str(wheel_dir), str(root)])
    wheels = list(wheel_dir.glob("*.whl"))
    if len(wheels) != 1:
        raise SystemExit(f"expected exactly one wheel, got {wheels}")
    wheel = wheels[0]

    # inspect the wheel contents directly: the required modules + locales must be in it
    import zipfile
    with zipfile.ZipFile(wheel) as z:
        names = z.namelist()
    for probe in ("_SMART_VAC_CLEANER.py", "_fs_helpers.py", "analyze_caches.py",
                  "strings/ru.json", "strings/et.json", "strings/ded.json"):
        if not any(n.endswith(probe) for n in names):
            raise SystemExit(f"wheel missing {probe}")
    print("wheel contents verified (3 modules + 3 locales)")

    # 2. clean venv (system-site-packages: GUI deps visible, wheel still fresh)
    venv.create(venv_dir, with_pip=True, system_site_packages=True)
    if os.name == "nt":
        py = venv_dir / "Scripts" / "python.exe"
    else:
        py = venv_dir / "bin" / "python"
    if not py.exists():
        raise SystemExit(f"venv python not created: {py}")

    # 3. install the wheel (no deps: provided by system site-packages)
    run([str(py), "-m", "pip", "install", "--no-deps", str(wheel)])

    # 4a. --help
    run([str(py), "-m", "_SMART_VAC_CLEANER", "--help"], cwd=str(tmp))

    # 4b. --status (read-only planner)
    run([str(py), "-m", "_SMART_VAC_CLEANER", "--status"], cwd=str(tmp))

    # 4c. point the INSTALLED cleaner at a temp fixture (T-139 resolver) and run
    #     a dry-run that MUST plan the 64-byte fixture exactly once.
    # W2-006 (AUDIT_ALL_3 acb-mtk1nqt0): the old code placed the fixture under
    # tempfile.mkdtemp() and SKIPPED the candidate-planning assertion whenever
    # the fixture shared the Windows installation drive, so on the majority of
    # Windows hosts (and on GitHub windows-latest runners) the release gate
    # passed green with its core assertion never exercised. The fixture now
    # lives on a deterministic permitted fixed drive (see
    # _candidate_volume_candidates); if no such drive exists the smoke FAILS
    # closed instead of degrading to a skip. The production blacklist contract
    # is never weakened.

    planned_on = None
    fixture = None
    fixture_before = None
    last_error = None
    import json as _json
    import re
    for volume in _candidate_volume_candidates():
        base = tmp if volume is None else Path(volume + "\\") / "vac_pkg_test_w2006"
        base.mkdir(parents=True, exist_ok=True)
        cand_fixture = base / "fixture"
        cand_cache = cand_fixture / "portable" / "_CENT" / "User Data" / "Default" / "Cache"
        cand_cache.mkdir(parents=True, exist_ok=True)
        (cand_cache / "data_0").write_bytes(b"x" * 64)
        cfg = cand_fixture / "cleaner_config.json"
        # W2-006: the MANDATORY planned-candidate surface is a custom rule on
        # the fixture cache dir. The portable _CENT root additionally proves
        # sanitize_roots accepts a non-system-drive root, but its planning is
        # owner-gated (cent == chrome.exe, line 1 APP_PROCESSES), so on a host
        # with the browser open it legitimately plans zero -- that must never
        # gate the smoke. The custom rule has no process gate
        # (owner_group=PROCESS_AGNOSTIC), so "Items acted >= 1" is a
        # deterministic mandatory contract on every permitted volume.
        cfg.write_text(_json.dumps({
            "portable_roots": [str(cand_fixture / "portable")],
            "custom_rules": [{"path": str(cand_cache), "pattern": "*"}],
            "exclude_patterns": [], "exclude_paths": [],
        }), encoding="utf-8")
        cand_before = (cand_cache / "data_0").read_bytes()
        env = dict(os.environ)
        env["SMARTVAC_DATA_DIR"] = str(cand_fixture)
        dry = run(
            [str(py), "-m", "_SMART_VAC_CLEANER", "--custom", "--dry-run", "--delete"],
            cwd=str(tmp),
            env=env,
            check=False,
        )
        acted_match = re.search(r"Items acted\s*:\s*(\d+)", dry.stdout)
        if dry.returncode == 0 and "[DRY-RUN]" in dry.stdout and acted_match and int(acted_match.group(1)) >= 1:
            fixture = cand_fixture
            planned_on = str(cand_fixture)
            fixture_before = cand_before
            break
        last_error = SystemExit(
            f"fixture volume {volume or 'TEMP'} rejected: "
            f"rc={dry.returncode} stdout snippet: {dry.stdout[:500]} stderr: {dry.stderr[:300]}"
        )
    if fixture is None:
        raise last_error or SystemExit(
            "W2-006: no permitted fixture volume exists; the installed-planner "
            "contract cannot be exercised and the package job must FAIL rather "
            "than pass with the candidate assertion skipped"
        )
    print(f"fixture planned on permitted volume: {planned_on}")
    cache = fixture / "portable" / "_CENT" / "User Data" / "Default" / "Cache"
    # CORE-006/W2-007: the subprocess itself planned the fixture (>=1 item,
    # proven by the loop above); the candidate-planning assertion is MANDATORY
    # and can no longer take a skip branch.
    if not (cache / "data_0").exists() or (cache / "data_0").read_bytes() != fixture_before:
        raise SystemExit("FAILED: dry-run mutated the fixture")
    print("installed subprocess dry-run completed; fixture byte-identical")

    # 5. import helpers + localization WITHOUT the repo on the path; prove the
    #    module/locale resources come from the INSTALLED wheel (venv site-packages).
    sitepk = str(venv_dir / ("Lib" if os.name == "nt" else "lib") /
                 ("site-packages" if os.name == "nt" else f"python{sys.version_info[0]}.{sys.version_info[1]}/site-packages"))
    import_check = (
        "import _SMART_VAC_CLEANER as vac, _fs_helpers as fsh, analyze_caches\n"
        "from pathlib import Path\n"
        "for m in (vac, fsh, analyze_caches):\n"
        "    f = Path(m.__file__).resolve()\n"
        f"    assert str(f).startswith(r'{sitepk}'), (m.__name__, f)\n"
        "et = vac.load_strings('et')\n"
        "assert et['clean'] != vac.DEFAULT_STRINGS['clean'], 'locale file NOT found'\n"
        "print('IMPORT-FROM-WHEEL-OK', Path(vac.__file__).parent)\n"
    )
    import_check_file = tmp / "import_check.py"
    import_check_file.write_text(import_check, encoding="utf-8")
    r = run([str(py), str(import_check_file)], cwd=str(tmp))
    if "IMPORT-FROM-WHEEL-OK" not in r.stdout:
        raise SystemExit("FAILED: modules/locales not resolved from the installed wheel")
    print("imports + locales resolved from the installed wheel (not the repo/global)")

    print("PACKAGE-SMOKE-OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
