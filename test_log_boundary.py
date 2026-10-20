"""T-211: Logger run-log creation must be exclusive and no-follow.

Drives the real Logger constructor with disposable fixtures only; no user log is
ever touched. Privileged OS primitives (symlink/hardlink creation) are probed
once and their tests skip when the platform refuses them.
"""

import errno
import os
from pathlib import Path

import pytest

import _SMART_VAC_CLEANER as vac


def _can_symlink():
    try:
        target = Path(__file__).parent / ".t211_symlink_probe_target"
        link = Path(__file__).parent / ".t211_symlink_probe_link"
        os.symlink(target, link)
        os.unlink(link)
        target.unlink(missing_ok=True)
        return True
    except OSError as exc:
        if exc.errno in (errno.EPERM, errno.EACCES, getattr(errno, "WSAEACCES", 13), 1314):
            return False
        return False


def _can_hardlink():
    try:
        base = Path(__file__).parent / ".t211_link_probe_base"
        link = Path(__file__).parent / ".t211_link_probe_hard"
        base.write_bytes(b"x")
        os.link(base, link)
        os.unlink(link)
        base.unlink()
        return True
    except OSError:
        return False


can_symlink = pytest.mark.skipif(not _can_symlink(), reason="symlink creation not permitted on this host")
can_hardlink = pytest.mark.skipif(not _can_hardlink(), reason="hardlink creation not permitted on this host")


def _flush(log):
    for handler in log._log.handlers:
        handler.flush()


def _logs_dir(tmp_path):
    logs = tmp_path / "logs"
    logs.mkdir()
    return logs


def _sentinel(path, content):
    path.write_bytes(content)


@can_symlink
def test_pre_existing_symlinked_destination_is_refused(tmp_path):
    logs = _logs_dir(tmp_path)
    outside = tmp_path / "outside.log"
    _sentinel(outside, b"external owner data\n")
    dest = logs / "clean_20261015_101010.log"
    os.symlink(outside, dest)

    log = vac.Logger(dest, False)
    log.info("PROBE")

    assert outside.read_bytes() == b"external owner data\n"
    assert dest.is_symlink()  # never followed or replaced


@can_hardlink
def test_pre_existing_hardlinked_destination_is_refused(tmp_path):
    logs = _logs_dir(tmp_path)
    outside = tmp_path / "outside.log"
    _sentinel(outside, b"external owner data\n")
    dest = logs / "clean_20261015_101010.log"
    os.link(outside, dest)

    log = vac.Logger(dest, False)
    log.info("PROBE")

    assert outside.read_bytes() == b"external owner data\n"
    assert dest.stat().st_nlink == 2  # link intact, nothing appended through it


def test_pre_existing_plain_destination_is_refused(tmp_path):
    logs = _logs_dir(tmp_path)
    dest = logs / "clean_20261015_101010.log"
    _sentinel(dest, b"foreign owner data\n")

    log = vac.Logger(dest, False)
    log.info("PROBE")

    assert dest.read_bytes() == b"foreign owner data\n"


def test_fresh_run_log_is_created_exclusively(tmp_path):
    logs = _logs_dir(tmp_path)
    dest = logs / "clean_20261015_101010.log"

    log = vac.Logger(dest, False)
    log.info("PROBE")
    _flush(log)

    assert dest.is_file()
    assert b"PROBE" in dest.read_bytes()


@can_symlink
def test_linked_logs_directory_is_refused(tmp_path):
    real_logs = tmp_path / "real_logs"
    real_logs.mkdir()
    link_logs = tmp_path / "link_logs"
    os.symlink(real_logs, link_logs)
    dest = link_logs / "clean_20261015_101010.log"

    log = vac.Logger(dest, False)
    log.info("PROBE")

    assert not dest.exists()
    assert list(real_logs.iterdir()) == []


def test_concurrent_logger_construction_is_safe(tmp_path):
    logs = _logs_dir(tmp_path)
    first = vac.Logger(logs / "clean_20261015_101010.log", False)
    second = vac.Logger(logs / "clean_20261015_101011.log", False)
    first.info("FIRST")
    second.info("SECOND")
    _flush(first)
    _flush(second)

    assert (logs / "clean_20261015_101010.log").is_file()
    assert (logs / "clean_20261015_101011.log").is_file()


def test_second_logger_same_name_is_refused_not_appended(tmp_path):
    logs = _logs_dir(tmp_path)
    dest = logs / "clean_20261015_101010.log"
    first = vac.Logger(dest, False)
    first.info("FIRST")
    _flush(first)
    size_after_first = dest.stat().st_size

    second = vac.Logger(dest, False)
    second.info("SECOND")
    _flush(second)

    assert dest.stat().st_size == size_after_first
    assert b"SECOND" not in dest.read_bytes()
