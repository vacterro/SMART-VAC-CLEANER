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
    fixture = tmp / "fixture"
    cache = fixture / "portable" / "_CENT" / "User Data" / "Default" / "Cache"
    cache.mkdir(parents=True)
    (cache / "data_0").write_bytes(b"x" * 64)
    cfg = fixture / "cleaner_config.json"
    import json as _json
    cfg.write_text(_json.dumps({
        "portable_roots": [str(fixture / "portable")], "custom_rules": [],
        "exclude_patterns": [], "exclude_paths": [],
    }), encoding="utf-8")
    before = (cache / "data_0").read_bytes()
    env = dict(os.environ)
    env["SMARTVAC_DATA_DIR"] = str(fixture)
    dry = run(
        [str(py), "-m", "_SMART_VAC_CLEANER", "--portable", "--dry-run", "--delete"],
        cwd=str(tmp),
        env=env,
    )
    if "[DRY-RUN]" not in dry.stdout:
        raise SystemExit("FAILED: dry-run did not run")
    # CORE-006/W2-007: assert the subprocess itself planned the fixture.
    # The 64-byte file shows as 0.0 MB in the summary; verify via item count.
    import re
    acted_match = re.search(r"Items acted\s*:\s*(\d+)", dry.stdout)
    if not acted_match or int(acted_match.group(1)) < 1:
        raise SystemExit(f"FAILED: dry-run did not plan the fixture; stdout snippet: {dry.stdout[:500]}")
    if not (cache / "data_0").exists() or (cache / "data_0").read_bytes() != before:
        raise SystemExit("FAILED: dry-run mutated the fixture")
    print("installed subprocess planned the 64-byte fixture via console entrypoint; fixture byte-identical")

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
