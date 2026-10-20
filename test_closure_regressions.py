"""Behavioral regressions from the final convergence audit."""

import errno
import json
from pathlib import Path

import pytest

import _SMART_VAC_CLEANER as vac


@pytest.fixture
def file_case(tmp_path):
    root = tmp_path / "configured"
    root.mkdir()
    candidate = root / "proof.tmp"
    candidate.write_bytes(b"preserve candidate on metadata failure")
    log = vac.Logger(None, True, quiet=True)
    engine = vac.CleanerEngine(True, log, vac.SafetyGuard(root), root, max_threads=1)
    return root, candidate, log, engine


@pytest.mark.parametrize("operation", ["plan", "authorize", "apply"])
@pytest.mark.parametrize("error_code", [errno.EIO, errno.ENOSPC, errno.ENOENT, errno.EACCES])
def test_file_metadata_errors_are_classified(file_case, monkeypatch, operation, error_code):
    _root, candidate, log, engine = file_case
    identity = vac._capture_identity(candidate)
    original = Path.lstat

    def unreadable(path, *args, **kwargs):
        if path == candidate:
            raise OSError(error_code, "injected candidate metadata failure")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "lstat", unreadable)
    if operation == "plan":
        assert engine._plan_file(candidate) is None
    elif operation == "authorize":
        allowed, _reason = engine._authorize_mutation(candidate, identity)
        assert not allowed
    else:
        assert not engine._apply_file_plan(candidate, identity["size"], identity).success
    assert candidate.read_bytes() == b"preserve candidate on metadata failure"
    assert log.bytes_freed == 0
    if error_code in (errno.EIO, errno.ENOSPC):
        assert log.n_errors == 1
    else:
        assert log.n_errors == 0


def test_actual_file_metadata_error_makes_custom_cli_fail(file_case, monkeypatch, tmp_path):
    root, candidate, log, _engine = file_case
    cfg = vac._default_config()
    cfg["custom_rules"] = [{"path": str(root), "pattern": "*.tmp"}]
    config = tmp_path / "config.json"
    config.write_text(json.dumps(cfg), encoding="utf-8")
    original = Path.lstat

    def unreadable(path, *args, **kwargs):
        if path == candidate:
            raise OSError(errno.EIO, "injected CLI metadata failure")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "lstat", unreadable)
    monkeypatch.setattr(vac, "CONFIG_FILE", config)
    monkeypatch.setattr(vac, "Logger", lambda *args, **kwargs: log)
    monkeypatch.setattr(vac.sys, "argv", ["vac-cleaner", "--cli", "--custom", "--dry-run"])
    with pytest.raises(SystemExit) as result:
        vac.main()
    assert result.value.code == 1
    assert log.n_errors == 1
    assert candidate.read_bytes() == b"preserve candidate on metadata failure"
