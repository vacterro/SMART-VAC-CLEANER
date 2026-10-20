"""Hermetic test environment (T-216).

Two invariants for every test in this repository:

1. NO TEST TOUCHES REAL USER DATA. The destructive sweeper resolves its
   system roots from module globals, so a test that builds a ``SystemCleaner``
   without an explicit ``system_roots`` snapshot would sweep the OPERATOR's
   real TEMP / APPDATA / Windows directory. The same holds for the writable
   data root (config file, run logs), which in a source checkout is the
   project directory itself.
2. EVERY DESTRUCTIVE TEST USES AN ISOLATED TEMPORARY ROOT. A session-scoped
   tripwire refuses any real deletion outside a disposable fixture created
   during the session, so a regression that reaches the operator's files
   fails the suite instead of quietly deleting them.

Read-only provenance tests that must observe the real OS-resolved roots are
marked ``real_system_roots``; they never mutate anything.
"""

import tempfile
from pathlib import Path

import pytest

import _SMART_VAC_CLEANER as vac

# Module globals holding a validated real system root.
_ROOT_GLOBALS = (
    "SYSTEM_TEMP",
    "USER_TEMP",
    "USER_CRASH",
    "USER_EXPLORER",
    "_LOCALAPPDATA",
    "_APPDATA",
)

# Resolvers that read the real OS state at call time.
_ROOT_RESOLVERS = (
    "_real_user_profile",
    "_resolve_active_drive_temp",
    "_get_windows_directory_win",
)

# Disposable roots created during this session. A real deletion is only
# allowed inside one of them.
_DISPOSABLE_ROOTS: list[Path] = []

# Every isolation breach seen in this session. The engine may swallow the
# assertion as an operational error, so the session end also fails the run.
_BREACHES: list[str] = []


def _record_breach(message: str) -> None:
    _BREACHES.append(message)


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "real_system_roots: read-only provenance test that must observe the real "
        "OS-resolved system roots (never destructive)",
    )


def _register_disposable(path) -> None:
    try:
        _DISPOSABLE_ROOTS.append(Path(path).resolve())
    except OSError:
        pass


def _is_disposable(path) -> bool:
    try:
        target = Path(path).resolve()
    except OSError:
        return False
    for root in _DISPOSABLE_ROOTS:
        if target == root or _is_under(root, target):
            return True
    return False


def _is_under(base: Path, target: Path) -> bool:
    try:
        target.relative_to(base)
        return True
    except ValueError:
        return False


@pytest.fixture(scope="session", autouse=True)
def _disposable_root_registry(tmp_path_factory):
    """Register every fixture root the session may delete inside."""
    _register_disposable(tmp_path_factory.getbasetemp())
    original_mkdtemp = tempfile.mkdtemp
    original_init = tempfile.TemporaryDirectory.__init__

    def mkdtemp(*args, **kwargs):
        path = original_mkdtemp(*args, **kwargs)
        _register_disposable(path)
        return path

    def temporary_directory_init(self, *args, **kwargs):
        original_init(self, *args, **kwargs)
        _register_disposable(self.name)

    tempfile.mkdtemp = mkdtemp
    tempfile.TemporaryDirectory.__init__ = temporary_directory_init
    try:
        yield
    finally:
        tempfile.mkdtemp = original_mkdtemp
        tempfile.TemporaryDirectory.__init__ = original_init
    if _BREACHES:
        raise AssertionError(
            "test isolation breaches (a real deletion outside a disposable fixture):\n  "
            + "\n  ".join(_BREACHES)
        )


@pytest.fixture(autouse=True)
def _hermetic_system_roots(request, monkeypatch):
    """No test may reach the real system roots implicitly."""
    if request.node.get_closest_marker("real_system_roots"):
        return
    for name in _ROOT_GLOBALS:
        monkeypatch.setattr(vac, name, None, raising=False)
    for name in _ROOT_RESOLVERS:
        monkeypatch.setattr(vac, name, lambda: None, raising=False)


@pytest.fixture(autouse=True)
def _hermetic_data_root(monkeypatch, tmp_path):
    """Config file and run logs never land in the operator's project."""
    data_dir = tmp_path / "data_root"
    data_dir.mkdir()
    monkeypatch.setattr(vac, "DATA_DIR", data_dir, raising=False)
    monkeypatch.setattr(vac, "CONFIG_FILE", data_dir / "cleaner_config.json", raising=False)
    monkeypatch.setattr(vac, "LOGS_DIR", data_dir / "logs", raising=False)


@pytest.fixture(autouse=True)
def _deletion_tripwire(monkeypatch):
    """A real deletion outside a disposable fixture fails the test."""
    original_del_file = vac.CleanerEngine._del_file
    original_apply_tree_plan = vac.CleanerEngine._apply_tree_plan

    def del_file(self, path, desc, owner_group=None):
        if not self.dry_run and not _is_disposable(path):
            message = f"real deletion outside a disposable fixture: {path}"
            _record_breach(message)
            raise AssertionError(message)
        return original_del_file(self, path, desc, owner_group)

    def apply_tree_plan(self, plan, desc, owner_group=None):
        if not self.dry_run and not _is_disposable(plan["root"]):
            message = f"real tree deletion outside a disposable fixture: {plan['root']}"
            _record_breach(message)
            raise AssertionError(message)
        return original_apply_tree_plan(self, plan, desc, owner_group)

    monkeypatch.setattr(vac.CleanerEngine, "_del_file", del_file, raising=True)
    monkeypatch.setattr(vac.CleanerEngine, "_apply_tree_plan", apply_tree_plan, raising=True)
