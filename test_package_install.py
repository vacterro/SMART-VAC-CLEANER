#!/usr/bin/env python3
"""F6 clean-install smoke test for the wheel contract.

Proves that `pip install .` works OUTSIDE the repository, not only as a source
checkout:

  1. build the wheel (--no-deps)
  2. create a clean venv (system-site-packages so the heavy GUI deps are
     visible without re-downloading them -- the wheel's OWN files still come
     from the wheel)
  3. pip install the wheel
  4. run:
       vac-cleaner --help
       vac-cleaner --status
       a safe dry-run against a temp fixture
  5. import the helper module and the localization resources from a cwd that
     is NOT the repository, and prove the locale file really came from the
     wheel (a translated key must differ from the English default)

The PyInstaller exe is a SEPARATE contract (build_exe.ps1 / build-exe.yml).

Run:  python test_package_install.py
Exit code 0 = smoke OK.
"""
import os
import subprocess
import sys
import tempfile
import venv
from pathlib import Path


def run(cmd, cwd=None, check=True):
    r = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd, check=False)
    if check and r.returncode != 0:
        print(r.stdout)
        print(r.stderr)
        raise SystemExit(f"FAILED: {' '.join(map(str, cmd))}")
    return r


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

    # 4c. safe dry-run against a temp fixture (portable root with a cache)
    fixture = tmp / "fixture"
    cache = fixture / "portable" / "_CENT" / "User Data" / "Default" / "Cache"
    cache.mkdir(parents=True)
    (cache / "data_0").write_bytes(b"x" * 64)
    cfg = fixture / "cleaner_config.json"
    cfg.write_text(
        f'{{"portable_roots": ["{fixture / "portable"}"], "custom_rules": [],'
        f' "exclude_patterns": [], "exclude_paths": []}}',
        encoding="utf-8",
    )
    dry = run(
        [str(py), "-m", "_SMART_VAC_CLEANER", "--portable", "--dry-run", "--delete"],
        cwd=str(fixture),
    )
    if not (cache / "data_0").exists():
        raise SystemExit("FAILED: dry-run mutated the fixture")
    if "[DRY-RUN]" not in dry.stdout:
        raise SystemExit("FAILED: dry-run did not report planned items")

    # 5. import helpers + localization WITHOUT the repo on the path
    code = (
        "import _SMART_VAC_CLEANER as vac; "
        "import _fs_helpers as fsh; "
        "import analyze_caches; "
        "assert hasattr(vac, 'VERSION'); "
        "assert callable(fsh.get_size); "
        "et = vac.load_strings('et'); "
        "assert set(et) == set(vac.DEFAULT_STRINGS), 'locale key set drifted'; "
        "assert et['clean'] != vac.DEFAULT_STRINGS['clean'], 'locale file NOT found: loaded English defaults'; "
        "print('IMPORT-OK et.clean =', et['clean'])"
    )
    run([str(py), "-c", code], cwd=str(tmp))

    print("PACKAGE-SMOKE-OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
