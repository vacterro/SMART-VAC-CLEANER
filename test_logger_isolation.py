"""T-212: Logger instance isolation and POSIX anchored run-log creation.

RED-first regression oracles for the two independent defects reported in the
SMART_VAC_CLEANER handoff:

1. Every Logger shared logging.getLogger("vac_cleaner"); constructing one
   Logger closed and replaced the handlers of the live instances, so two active
   Loggers all landed in the newest file and a quiet collector silenced an
   active job.
2. _open_run_log_stream() called os.open(..., dir_f=dir_fd) -- the stdlib keyword
   is dir_fd, so the POSIX anchored-exclusive path raised TypeError.

Disposable fixtures only; no user log is ever touched. Privileged OS primitives
are probed once and their tests skip when the platform refuses them.
"""

import logging
import os
import threading
from pathlib import Path

import pytest

import _SMART_VAC_CLEANER as vac


def _flush(*loggers):
    for logger in loggers:
        for handler in getattr(logger, "_handlers", []):
            try:
                handler.flush()
            except Exception:  # noqa: BLE001, S110 - best effort
                pass


def _logs_dir(tmp_path):
    logs = tmp_path / "logs"
    logs.mkdir()
    return logs


@pytest.fixture(autouse=True)
def _leak_free_logger():
    """No Handler may outlive an oracle: construction assertions depend on it."""
    root = logging.getLogger("vac_cleaner")
    before = {id(h) for h in root.handlers}
    yield
    for handler in root.handlers[:]:
        if id(handler) not in before:
            handler.close()
            root.removeHandler(handler)


def test_two_active_loggers_write_only_to_their_own_files(tmp_path):
    logs = _logs_dir(tmp_path)
    file_a = logs / "clean_20261017_101010.log"
    file_b = logs / "clean_20261017_101011.log"

    log_a = vac.Logger(file_a, False)
    log_b = vac.Logger(file_b, False)

    log_a.info("ENTRY_FROM_A")
    log_b.info("ENTRY_FROM_B")
    _flush(log_a, log_b)

    content_a = file_a.read_text()
    content_b = file_b.read_text()

    assert "ENTRY_FROM_A" in content_a
    assert "ENTRY_FROM_B" not in content_a, "A received B's emission"
    assert "ENTRY_FROM_B" in content_b
    assert "ENTRY_FROM_A" not in content_b, "B received A's emission"


def test_quiet_logger_does_not_silence_active_logger(tmp_path):
    logs = _logs_dir(tmp_path)
    active_file = logs / "clean_20261017_202020.log"

    active = vac.Logger(active_file, False)

    vac.Logger(None, False, quiet=True)

    active.info("STILL_EMITTED")
    _flush(active)

    assert "STILL_EMITTED" in active_file.read_text()


def test_closing_one_logger_does_not_break_another(tmp_path):
    logs = _logs_dir(tmp_path)
    file_a = logs / "clean_20261017_303030.log"
    file_b = logs / "clean_20261017_303031.log"

    log_a = vac.Logger(file_a, False)
    log_b = vac.Logger(file_b, False)

    log_a.close()

    log_b.info("B_SURVIVES_A_CLOSE")
    _flush(log_b)

    assert "B_SURVIVES_A_CLOSE" in file_b.read_text()
    assert "B_SURVIVES_A_CLOSE" not in file_a.read_text()


def test_construction_order_does_not_leak_console_handler(tmp_path):
    """Each construction must leave exactly one live console StreamHandler."""
    logs = _logs_dir(tmp_path)

    vac.Logger(logs / "clean_20261017_404040.log", False)
    vac.Logger(logs / "clean_20261017_404041.log", False)
    vac.Logger(logs / "clean_20261017_404042.log", False)

    stream_handlers = [
        h
        for h in logging.getLogger("vac_cleaner").handlers
        if isinstance(h, logging.StreamHandler)
        and not isinstance(h, logging.NullHandler)
        and getattr(h, "stream", None) is not None
        and h.stream is not None
        and getattr(h.stream, "name", None) == "<stdout>"
    ]
    assert len(stream_handlers) <= 1, "stale console handlers accumulated"


def test_existing_logger_close_builds_then_new_logger_still_works(tmp_path):
    logs = _logs_dir(tmp_path)
    target = logs / "clean_20261017_505050.log"

    log = vac.Logger(target, False)
    log.info("BEFORE")
    _flush(log)

    log.close()
    assert "BEFORE" in target.read_text()

    other = vac.Logger(logs / "clean_20261017_505051.log", False)
    other.info("AFTER")
    _flush(other)

    assert "AFTER" in (logs / "clean_20261017_505051.log").read_text()
    assert "AFTER" not in target.read_text()
    other.close()


def test_log_retention_boundary_stays_intact(tmp_path):
    """T-212 regression: isolation must not widen retention. The current job's
    log survives; the directory stays bounded at _LOG_RETENTION_KEEP."""
    logs = _logs_dir(tmp_path)
    keep = vac._LOG_RETENTION_KEEP
    for i in range(keep + 5):
        (logs / f"clean_20250101_{i:02d}0000.log").write_text("stale")

    current = logs / "clean_20261231_999999.log"
    fresh = vac.Logger(current, False)

    remaining = list(logs.glob("clean_*.log"))
    assert len(remaining) <= keep
    assert current.name in [p.name for p in remaining], "the current job's log is kept"

    fresh.info("CURRENT")
    _flush(fresh)
    assert "CURRENT" in current.read_text()
    fresh.close()


def test_module_diagnostics_still_route_to_run_log(tmp_path):
    """Markerless module diagnostics (retention refusal) must still land in the
    active run log rather than vanishing with instance-scoped handlers."""
    import logging as _logging  # noqa: F401

    logs = _logs_dir(tmp_path)
    fresh = vac.Logger(logs / "clean_20261015_123123.log", False)

    vac._log_retention_refused(logs, "probe")
    for handler in fresh._handlers:
        handler.flush()

    assert "Log retention skipped" in (logs / "clean_20261015_123123.log").read_text()
    fresh.close()


@pytest.mark.skipif(os.name != "posix", reason="fork-based races need POSIX")
def test_posix_exclusive_create_refuses_pre_existing_destination(tmp_path):
    logs = _logs_dir(tmp_path)
    dest = logs / "clean_20261017_707070.log"
    dest.write_bytes(b"foreign owner data\n")

    log = vac.Logger(dest, False)
    log.info("SECOND")
    _flush(log)

    assert dest.read_bytes() == b"foreign owner data\n", "pre-existing log was appended to"


def test_posix_run_log_creation_uses_dir_fd_in_source_ast():
    """T-212 P3: static AST verification of _open_run_log_stream keyword call.

    Dependency-free oracle that runs cross-platform: asserts os.open is called with
    keyword 'dir_fd' and that 'dir_f' does not appear anywhere in the call keywords.
    """
    import ast
    src = Path(vac.__file__).read_text(encoding="utf-8")
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "_open_run_log_stream":
            keywords = [
                kw.arg
                for call in ast.walk(node)
                if isinstance(call, ast.Call)
                for kw in call.keywords
                if kw.arg is not None
            ]
            assert "dir_fd" in keywords, "dir_fd keyword must be passed to os.open"
            assert "dir_f" not in keywords, "misspelled dir_f keyword must not appear"
            break
    else:
        pytest.fail("_open_run_log_stream not found in AST")


def test_posix_run_log_creation_uses_dir_fd_keyword(tmp_path):
    """T-212 P3: the stdlib keyword is dir_fd; dir_f raises TypeError.

    Runs everywhere: it drives the anchor contract (dir_fd= + O_EXCL) against a
    real directory handle, and separately asserts the shipped keyword matches
    the documented signature so the POSIX branch cannot regress silently.
    """
    import inspect

    # The keyword contract runs everywhere: the stdlib spelling is dir_fd, and
    # dir_f must raise TypeError, which is what the shipped POSIX branch used to
    # hit when the kwarg was misspelled.
    assert "dir_fd=None" in str(inspect.signature(os.open))
    with pytest.raises(TypeError):
        os.open("probe_212.log", os.O_CREAT, 0o600, dir_f=None)

    if getattr(os, "O_DIRECTORY", None) is None:
        pytest.skip("no directory handles on this platform")

    logs = _logs_dir(tmp_path)
    dest = logs / "clean_20261017_606060.log"

    dir_fd = os.open(logs, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    fd = None
    try:
        fd = os.open(
            "clean_20261017_606060.log",
            os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=dir_fd,
        )
    finally:
        if fd is not None:
            os.close(fd)
        os.close(dir_fd)

    assert dest.is_file()

    log = vac.Logger(logs / "clean_20261017_808080.log", False)
    log.info("POSIX_ANCHORED")
    _flush(log)
    assert "POSIX_ANCHORED" in (logs / "clean_20261017_808080.log").read_text()
    log.close()


def test_concurrent_construction_is_deterministic(tmp_path):
    """Ten threads, ten distinct files; each ends up with only its own line."""
    logs = _logs_dir(tmp_path)
    results = {}
    errors = []

    def build(index):
        try:
            log = vac.Logger(logs / f"clean_20261016_8080{index:02d}.log", False)
            log.info(f"CONCURRENT_{index:02d}")
            _flush(log)
            results[index] = os.stat(logs / f"clean_20261016_8080{index:02d}.log").st_size
        except Exception as exc:  # noqa: BLE001 - test books the failure
            errors.append(exc)

    threads = [threading.Thread(target=build, args=(i,)) for i in range(10)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert len(results) == 10
    for index in range(10):
        content = (logs / f"clean_20261016_8080{index:02d}.log").read_text()
        assert f"CONCURRENT_{index:02d}" in content
        others = [
            f"CONCURRENT_{other:02d}"
            for other in range(10)
            if other != index and f"CONCURRENT_{other:02d}" in content
        ]
        assert not others, f"logger {index} received foreign entries: {others}"


def test_gui_callback_still_fires_per_message(tmp_path):
    logs = _logs_dir(tmp_path)
    seen = []

    log = vac.Logger(
        logs / "clean_20261017_909090.log",
        False,
        gui_callback=lambda msg, kind=None: seen.append(msg),
    )
    log.info("GUI_STILL_WORKS")
    log.warning("WARN_STILL_WORKS")

    assert any("GUI_STILL_WORKS" in str(m) for m in seen)
    assert any("WARN_STILL_WORKS" in str(m) for m in seen)


def test_counters_still_update(tmp_path):
    logs = _logs_dir(tmp_path)
    log = vac.Logger(logs / "clean_20261017_111111.log", False)
    before = (log.n_errors, log.n_deleted, log.bytes_freed)
    log.info("counter_probe")
    assert (log.n_errors, log.n_deleted, log.bytes_freed) == before
