"""Exercise the shipped executable against a disposable permitted fixture."""

import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path

from test_package_install import _candidate_volume_candidates


def run(executable, args, env, cwd):
    result = subprocess.run(
        [str(executable), *args], cwd=cwd, env=env, capture_output=True,
        text=True, errors="replace", timeout=120, check=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if result.returncode:
        raise RuntimeError(f"EXE {' '.join(args)} exited {result.returncode}: {result.stdout}\n{result.stderr}")
    return result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("executable", type=Path)
    args = parser.parse_args()
    executable = args.executable.resolve(strict=True)
    expected_version = Path(__file__).with_name("VERSION").read_text(encoding="utf-8").strip()
    fixture = None
    for volume in _candidate_volume_candidates():
        try:
            fixture = tempfile.TemporaryDirectory(prefix="smartvac_frozen_", dir=f"{volume}\\" if volume else None)
            break
        except OSError:
            continue
    if fixture is None:
        raise RuntimeError("No permitted fixed volume for the mandatory EXE fixture; smoke cannot be skipped")
    with fixture as temporary:
        root = Path(temporary)
        data = root / "data"
        data.mkdir()
        target = root / "layer" / "scope" / "custom"
        target.mkdir(parents=True)
        proof = target / "proof.bin"
        payload = b"x" * (2 * 1024 * 1024)
        proof.write_bytes(payload)
        config = data / "cleaner_config.json"
        config.write_text(json.dumps({"custom_rules": [{"path": str(target), "pattern": "*"}]}), encoding="utf-8")
        before_config = config.read_bytes()
        expected_digest = hashlib.sha256(payload).hexdigest()
        env = dict(os.environ, SMARTVAC_DATA_DIR=str(data))
        help_text = run(executable, ["--help"], env, root)
        if f"v{expected_version}" not in help_text or "--uninstall-task" not in help_text:
            raise RuntimeError("Frozen help/version or CLI entrypoints missing")
        preview = run(executable, ["--cli", "--custom", "--dry-run"], env, root)
        if not re.search(r"\[DRY-RUN\]\s+2\.00 MB", preview) or str(config).lower() not in preview.lower() or str(target).lower() not in preview.lower():
            raise RuntimeError(f"Frozen preview did not plan the mandatory 2 MiB candidate: {preview}")
        if hashlib.sha256(proof.read_bytes()).hexdigest() != expected_digest or config.read_bytes() != before_config:
            raise RuntimeError("Frozen preview mutated its fixture or config")
        if any(path.name.endswith(".lock") for path in data.iterdir()):
            raise RuntimeError("Frozen preview created a config lock sidecar")
        deleted = run(executable, ["--cli", "--custom", "--delete"], env, root)
        if proof.exists() or not re.search(r"\[DELETED\]\s+2\.00 MB", deleted):
            raise RuntimeError(f"Frozen delete did not execute the verified candidate: {deleted}")
        if target.exists() is False:
            raise RuntimeError("Frozen custom-file rule removed its root")
        print(f"FROZEN-SMOKE-OK version={expected_version} preview=read-only delete=2097152 bytes fixture={target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
