"""Live acceptance criteria for SRC-001 (September 2026 audit generation)."""

import contextlib
import copy
import itertools
import json
import os
import subprocess
import sys
import threading
import weakref
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import _SMART_VAC_CLEANER as vac
import test_cleaner as support


@pytest.fixture
def policy(tmp_path, monkeypatch):
    config_file = tmp_path / "cleaner_config.json"
    config = vac._default_config()
    config["portable_roots"] = []
    config["custom_rules"] = []
    config_file.write_text(json.dumps(config), encoding="utf-8")
    monkeypatch.setattr(vac, "CONFIG_FILE", config_file)
    return config_file, config


def editor(config):
    app = support.TestGuiThreadBoundary._fake_app()
    app.config = copy.deepcopy(config)
    app.T.update(exc_saved="exclusions saved", syst_saved="targets saved")
    app.exclude_patterns = list(config["exclude_patterns"])
    app.exclude_paths = list(config["exclude_paths"])
    app.syst_vars = {name: MagicMock(get=MagicMock(return_value=value))
                     for name, value in vac.SYSTEM_TARGET_DEFAULTS.items()}
    return app


def save_editor(app, kind, window, paths=()):
    if kind == "exclusions":
        app._save_exclusions(window, MagicMock(get=MagicMock(return_value="*.keep")),
                             MagicMock(get=MagicMock(return_value=paths)))
    else:
        app._save_system_targets(window)


@pytest.mark.parametrize("field,value", [
    ("exclude_patterns", "*.tmp"), ("exclude_paths", ["relative"]),
    ("portable_roots", "not-a-list"), ("system_targets", {"UNKNOWN": True}),
    ("custom_rules", "not-a-list"),
    ("auto_clean_interval_hours", -1), ("unknown_policy_key", True),
])
def test_post_merge_invalid_policy_preserves_valid_bytes(policy, field, value):
    config_file, _config = policy
    original = config_file.read_bytes()
    assert not vac._config_rmw_transaction(lambda latest: {**latest, field: value})
    assert config_file.read_bytes() == original
    assert vac.load_config_strict()[0] == vac.ConfigState.VALID


def test_rmw_returns_distinct_validation_and_lock_failures(policy):
    invalid = vac._config_rmw_transaction(
        lambda latest: {**latest, "exclude_patterns": 42}, detailed=True)
    assert not invalid and invalid.reason == "invalid_candidate"
    assert "exclude_patterns" in invalid.message
    with patch.object(vac, "_config_transaction", side_effect=TimeoutError("writer busy")):
        busy = vac._config_rmw_transaction(lambda latest: latest, detailed=True)
    assert not busy and busy.reason == "lock_timeout"
    assert "writer busy" in busy.message


@pytest.mark.parametrize("kind", ["exclusions", "targets"])
def test_editor_explains_busy_writer_without_closing(policy, kind):
    config_file, config = policy
    original = config_file.read_bytes()
    app, window = editor(config), MagicMock()
    with patch.object(vac, "_config_transaction", side_effect=TimeoutError("writer busy")):
        save_editor(app, kind, window)
    window.destroy.assert_not_called()
    assert config_file.read_bytes() == original
    assert "writer is busy" in app.log_queue.get_nowait()


@pytest.mark.parametrize("kind", ["exclusions", "targets"])
@pytest.mark.parametrize("active", ["foreground", "worker", "background", "unknown_background"])
def test_open_policy_editor_cannot_save_during_frozen_generation(policy, kind, active):
    config_file, config = policy
    app, window = editor(config), MagicMock()
    original = config_file.read_bytes()
    before = copy.deepcopy(app.config)
    if active == "foreground":
        app._clean_in_progress = True
    elif active == "worker":
        app._worker_thread = MagicMock(is_alive=MagicMock(return_value=True))
    else:
        app._bg_proc = MagicMock()
        app._bg_proc.poll.side_effect = OSError("unobservable child") if active == "unknown_background" else [None]
    save_editor(app, kind, window)
    window.destroy.assert_not_called()
    assert config_file.read_bytes() == original
    assert app.config == before
    assert "Stop or wait" in app.log_queue.get_nowait()
    # A terminal observation restores the same editor's ability to save.
    app._clean_in_progress = False
    app._worker_thread = None
    app._bg_proc = MagicMock(poll=MagicMock(return_value=0))
    save_editor(app, kind, window)
    window.destroy.assert_called_once()
    assert vac.load_config_strict()[0] == vac.ConfigState.VALID


def test_ordinary_exclusion_save_normalizes_and_closes_once(policy, tmp_path):
    _config_file, config = policy
    app, window = editor(config), MagicMock()
    exclusion = tmp_path / "ordinary" / ".." / "keep"
    save_editor(app, "exclusions", window, [str(exclusion)])
    window.destroy.assert_called_once()
    state, saved, _errors = vac.load_config_strict()
    assert state == vac.ConfigState.VALID
    assert saved["exclude_paths"] == [str(exclusion.resolve())]
    assert app.config["exclude_paths"] == saved["exclude_paths"]


@pytest.mark.skipif(os.name != "nt", reason="native Windows junction")
def test_junction_exclusion_save_keeps_dialog_and_policy(policy, tmp_path):
    config_file, config = policy
    ordinary, junction = tmp_path / "ordinary", tmp_path / "junction"
    ordinary.mkdir()
    created = subprocess.run(["cmd", "/c", "mklink", "/J", str(junction), str(ordinary)],
                             capture_output=True, timeout=10, check=False,
                             creationflags=subprocess.CREATE_NO_WINDOW)
    assert created.returncode == 0, created.stdout + created.stderr
    try:
        assert vac.is_link(junction)
        app, window = editor(config), MagicMock()
        original = config_file.read_bytes()
        save_editor(app, "exclusions", window, [str(junction)])
        window.destroy.assert_not_called()
        assert config_file.read_bytes() == original
        assert app.config == config
        assert vac.load_config_strict()[0] == vac.ConfigState.VALID
        assert "Invalid exclusion path" in app.log_queue.get_nowait()
    finally:
        junction.rmdir()


FAMILIES = {"clean": ["--cli", "--all"], "status": ["--status"],
            "analyze": ["--analyze-caches"], "install": ["--install-task"],
            "uninstall": ["--uninstall-task"], "gui": []}
MODIFIERS = {"--dry-run": [], "--delete": [], "--hidden": [],
             "--sys-targets": ["Explorer Thumbnails"], "--disable-targets": ["User Temp"],
             "--exclude": ["*.keep"], "--time": ["23:00"], "--surface": ["scheduled"]}


def invoke(argv, config):
    """Observe every side-effect boundary without cleaning or scheduling."""
    names = ["bootstrap_config", "load_config_strict", "cli_status", "install_task",
             "uninstall_task", "_hide_console", "Logger", "_JobLease", "run_cleaning_job", "App"]
    with contextlib.ExitStack() as stack:
        mocks = {name: stack.enter_context(patch.object(vac, name)) for name in names}
        mocks["load_config_strict"].return_value = (vac.ConfigState.VALID, config, [])
        mocks["bootstrap_config"].return_value = (vac.ConfigState.VALID, config, [])
        mocks["Logger"].return_value.n_errors = 0
        analyzer = stack.enter_context(patch.object(support.vac_analyze, "main"))
        stack.enter_context(patch.object(sys, "argv", ["vac-cleaner", *argv]))
        try:
            vac.main()
            code = 0
        except SystemExit as exc:
            code = exc.code
    return code, mocks, analyzer


@pytest.mark.parametrize("family,modifier", itertools.product(FAMILIES, MODIFIERS))
def test_cli_modifier_ownership_matrix(policy, family, modifier):
    _config_file, config = policy
    allowed = family == "clean" and modifier != "--time" or family == "install" and modifier == "--time"
    code, boundaries, analyzer = invoke([*FAMILIES[family], modifier, *MODIFIERS[modifier]], config)
    assert code == (0 if allowed else 2)
    if not allowed:
        for boundary in boundaries.values():
            boundary.assert_not_called()
        analyzer.assert_not_called()


@pytest.mark.parametrize("family", ["status", "analyze", "install", "uninstall"])
@pytest.mark.parametrize("selector", ["--cli", "--portable", "--system", "--custom", "--all"])
def test_cli_clean_selectors_conflict_before_side_effects(policy, family, selector):
    _config_file, config = policy
    code, boundaries, analyzer = invoke([*FAMILIES[family], selector], config)
    assert code == 2
    for boundary in boundaries.values():
        boundary.assert_not_called()
    analyzer.assert_not_called()


@pytest.mark.parametrize("first,second", itertools.combinations([name for name in FAMILIES if name != "gui"], 2))
def test_cli_conflicting_action_families_have_no_effects(policy, first, second):
    _config_file, config = policy
    code, boundaries, analyzer = invoke([*FAMILIES[first], *FAMILIES[second]], config)
    assert code == 2
    for boundary in boundaries.values():
        boundary.assert_not_called()
    analyzer.assert_not_called()


@pytest.mark.parametrize("family", FAMILIES)
def test_cli_help_is_read_only_for_every_family(policy, family):
    _config_file, config = policy
    code, boundaries, analyzer = invoke([*FAMILIES[family], "--help"], config)
    assert code == 0
    for boundary in boundaries.values():
        boundary.assert_not_called()
    analyzer.assert_not_called()


@pytest.mark.parametrize("modifier", ["--sys-targets", "--disable-targets"])
def test_unknown_destructive_target_never_enters_bootstrap(policy, modifier):
    config_file, config = policy
    config_file.unlink()  # explicitly owned disposable fixture
    code, boundaries, analyzer = invoke(["--cli", "--all", "--delete", modifier, "UNKNOWN"], config)
    assert code == 2
    for boundary in boundaries.values():
        boundary.assert_not_called()
    analyzer.assert_not_called()
    assert not config_file.exists()
    assert not config_file.with_name(config_file.name + ".lock").exists()


def test_first_valid_delete_bootstraps_but_invalid_config_survives(policy):
    config_file, _config = policy
    with patch.object(sys, "argv", ["vac-cleaner", "--cli", "--custom", "--delete"]), \
         patch.object(vac, "run_cleaning_job") as job, patch.object(vac, "Logger") as logger, \
         patch.object(vac, "_JobLease"):
        logger.return_value.n_errors = 0
        config_file.unlink()
        vac.main()
        assert config_file.exists()
        assert vac.load_config_strict()[0] == vac.ConfigState.VALID
        job.assert_called_once()
        job.reset_mock()
        config_file.write_bytes(b'{"exclude_patterns": 42}')
        before = config_file.read_bytes()
        with pytest.raises(SystemExit, match="3"):
            vac.main()
        assert config_file.read_bytes() == before
        job.assert_not_called()


def test_disabling_timer_discards_pending_firing():
    app = support.TestGuiThreadBoundary._fake_app()
    app.config["auto_clean_interval_hours"] = 1
    with patch.object(vac.threading, "Timer") as timer, patch.object(app, "_start_job") as start:
        app._schedule_auto_clean()
        timer.call_args.args[1]()
        assert app._auto_clean_pending
        app.config["auto_clean_interval_hours"] = 0
        app._schedule_auto_clean()
        app._poll_main()
    start.assert_not_called()
    assert app._clean_timer is None


@pytest.mark.parametrize("outcome", ["busy", "declined"])
def test_auto_clean_rearms_after_skipped_attempt(outcome):
    app = support.TestGuiThreadBoundary._fake_app()
    app.config["auto_clean_interval_hours"] = 1
    app._clean_in_progress = outcome == "busy"
    with patch.object(vac.threading, "Timer") as timer, patch.object(app, "_start_job", return_value=None) as start:
        app._schedule_auto_clean()
        timer.call_args.args[1]()
        app._poll_main()
    start.assert_called_once()
    assert timer.call_count == 2


def test_firing_callback_cannot_publish_timer_during_main_thread_rearm():
    app = support.TestGuiThreadBoundary._fake_app()
    app.config["auto_clean_interval_hours"] = 1
    timers = []
    reached, release = threading.Event(), threading.Event()

    def make_timer(_interval, callback):
        timer = MagicMock()
        timer.callback = callback
        if timers:
            reached.set()
            assert release.wait(5)
        timers.append(timer)
        return timer

    with patch.object(vac.threading, "Timer", side_effect=make_timer):
        app._schedule_auto_clean()

        def fire_while_constructing():
            assert reached.wait(5)
            timers[0].callback()
            release.set()

        thread = threading.Thread(target=fire_while_constructing)
        thread.start()
        app._schedule_auto_clean()
        thread.join(5)
        assert not thread.is_alive()
    assert len(timers) == 2
    timers[0].cancel.assert_called_once()
    timers[1].cancel.assert_not_called()
    assert app._clean_timer is timers[1]


def test_superseded_callback_cannot_dispatch_a_pending_old_generation():
    app = support.TestGuiThreadBoundary._fake_app()
    app.config["auto_clean_interval_hours"] = 1
    with patch.object(vac.threading, "Timer") as timer, patch.object(app, "_start_job") as start:
        app._schedule_auto_clean()
        old_generation = app._auto_clean_generation
        app._schedule_auto_clean()
        # A callback paused after its guard check may publish after replacement.
        app._auto_clean_pending_generation = old_generation
        app._auto_clean_pending = True
        app._poll_main()
    start.assert_not_called()
    assert timer.call_count == 2


@pytest.mark.skipif(os.name != "nt", reason="native Windows junction")
def test_root_swap_during_canonicalization_is_refused(tmp_path):
    root, victim = tmp_path / "configured", tmp_path / "victim"
    root.mkdir()
    victim.mkdir()
    proof = victim / "proof.tmp"
    proof.write_bytes(b"establishment victim")
    canonicalize = vac.SafetyGuard._canon

    def swap(path):
        root.rename(tmp_path / "original")
        created = subprocess.run(["cmd", "/c", "mklink", "/J", str(root), str(victim)],
                                 capture_output=True, timeout=10, check=False,
                                 creationflags=subprocess.CREATE_NO_WINDOW)
        assert created.returncode == 0, created.stdout + created.stderr
        return canonicalize(path)

    try:
        with patch.object(vac.SafetyGuard, "_canon", staticmethod(swap)):
            guard = vac.SafetyGuard(root)
        assert guard._root_blocked
        assert not guard.is_safe(root / "proof.tmp")[0]
        assert proof.read_bytes() == b"establishment victim"
    finally:
        if vac.is_link(root):
            root.rmdir()


def engine_for(base, *, dry_run=True, exclusions=()):
    logger = vac.Logger(None, dry_run)
    return vac.CleanerEngine(dry_run, logger, vac.SafetyGuard(base), base,
                             max_threads=1, exclude_patterns=list(exclusions),
                             ledger=vac.CandidateLedger())


@pytest.mark.parametrize("kind", ["file", "directory"])
def test_root_replaced_after_guard_refuses_direct_mutations(tmp_path, kind):
    root = tmp_path / "configured"
    root.mkdir()
    engine = engine_for(root, dry_run=False)
    root.rename(tmp_path / "original")
    target = root / "cache"
    target.mkdir(parents=True)
    proof = target / "proof.tmp"
    proof.write_bytes(b"replacement root must survive")
    freed = engine._del_file(proof, "audit") if kind == "file" else engine._del_dir(target, "audit")
    assert freed == 0
    assert engine.log.bytes_freed == 0
    assert proof.read_bytes() == b"replacement root must survive"
    assert not engine.ledger.covered(target)


@pytest.mark.parametrize("shape", ["files", "directories", "protected", "mixed"])
def test_total_record_budget_exact_boundary_and_zero_claim(tmp_path, monkeypatch, shape):
    root = tmp_path / "configured" / "tree"
    root.mkdir(parents=True)
    if shape == "directories":
        for index in range(3):
            (root / f"dir{index}").mkdir()
    else:
        for index in range(3):
            suffix = ".keep" if shape == "protected" or shape == "mixed" and index == 0 else ".tmp"
            (root / f"file{index}{suffix}").write_bytes(b"fixture")
    engine = engine_for(root.parent, dry_run=False, exclusions=["*.keep"])
    monkeypatch.setenv("SMARTVAC_PLAN_MAX_RECORDS", "3")
    plan = engine._plan_tree(root, "audit")
    assert plan is not None
    assert sum(len(plan[key]) for key in ("files", "dirs", "protected")) == 3
    engine._release_plan_budget(plan)
    before = {path.relative_to(root): path.read_bytes() for path in root.rglob("*") if path.is_file()}
    monkeypatch.setenv("SMARTVAC_PLAN_MAX_RECORDS", "2")
    assert engine._del_dir(root, "audit") == 0
    assert engine.log.n_errors == 1
    assert engine.log.bytes_freed == 0
    assert not engine.ledger.covered(root)
    assert engine._plan_budget().used == 0
    assert {path.relative_to(root): path.read_bytes() for path in root.rglob("*") if path.is_file()} == before


@pytest.mark.parametrize("workers", [4, 12])
def test_concurrent_retained_plans_respect_job_budget(tmp_path, monkeypatch, workers):
    roots = []
    for sibling in range(workers):
        root = tmp_path / "configured" / f"sibling{sibling}"
        root.mkdir(parents=True)
        roots.append(root)
        for index in range(50):
            (root / f"file{index}.tmp").write_bytes(b"plan")
    engine = engine_for(tmp_path / "configured")
    monkeypatch.setenv("SMARTVAC_PLAN_MAX_RECORDS", "100")
    with ThreadPoolExecutor(max_workers=workers) as pool:
        plans = list(pool.map(lambda root: engine._plan_tree(root, "audit"), roots))
    assert any(plan is None for plan in plans)
    retained = sum(plan["budget_held"] for plan in plans if plan is not None)
    assert retained == engine._plan_budget().used <= 100
    for plan in plans:
        if plan is not None:
            engine._release_plan_budget(plan)
    assert engine._plan_budget().used == 0
    assert len(list((tmp_path / "configured").rglob("*.tmp"))) == 50 * workers


def test_aborted_plans_release_records_before_slow_error_reporting(tmp_path, monkeypatch):
    roots = []
    for sibling in range(3):
        root = tmp_path / "configured" / f"sibling{sibling}"
        root.mkdir(parents=True)
        roots.append(root)
        for index in range(60):
            (root / f"file{index}.tmp").write_bytes(b"bounded")
    engine = engine_for(tmp_path / "configured")
    monkeypatch.setenv("SMARTVAC_PLAN_MAX_RECORDS", "50")
    references = []
    identify = vac._identity_from_stat

    class Identity(dict):
        pass

    def track(observed):
        identity = identify(observed)
        if identity is not None and identity["type"] == "file":
            identity = Identity(identity)
            references.append(weakref.ref(identity))
        return identity

    condition, release = threading.Condition(), threading.Event()
    waiting = 0

    def slow_error(_message):
        nonlocal waiting
        with condition:
            waiting += 1
            condition.notify_all()
        assert release.wait(10), "diagnostic barrier was not released"

    with patch.object(vac, "_identity_from_stat", side_effect=track), \
         patch.object(engine.log, "error", side_effect=slow_error), \
         ThreadPoolExecutor(max_workers=3) as pool:
        futures = []
        try:
            for root in roots:
                futures.append(pool.submit(engine._plan_tree, root, "audit"))
                with condition:
                    assert condition.wait_for(lambda: waiting == len(futures), timeout=5)
            # Once aborted, no candidate identity may stay behind a diagnostic.
            assert sum(reference() is not None for reference in references) == 0
        finally:
            release.set()
        assert all(future.result() is None for future in futures)
    assert engine._plan_budget().used == 0
    assert len(list((tmp_path / "configured").rglob("*.tmp"))) == 180


def test_native_planning_reuses_one_file_observation(tmp_path):
    root = tmp_path / "configured" / "cache"
    root.mkdir(parents=True)
    candidates = {root / f"file{index}.tmp" for index in range(1000)}
    for path in candidates:
        path.write_bytes(b"metadata")
    engine = engine_for(root.parent)
    original_lstat = Path.lstat
    observations = []

    def observe(path, *args, **kwargs):
        if path in candidates:
            observations.append(path)
        return original_lstat(path, *args, **kwargs)

    with patch.object(Path, "lstat", observe), \
         patch.object(vac, "is_link", wraps=vac.is_link) as links, \
         patch.object(vac, "_capture_identity", wraps=vac._capture_identity) as identities:
        plan = engine._plan_tree(root, "audit")
    assert plan is not None
    assert {path for path, _size, _identity in plan["files"]} == candidates
    assert plan["bytes"] == 8000
    assert all(identity == vac._capture_identity(path) for path, _size, identity in plan["files"])
    assert links.call_count < 10
    assert identities.call_count < 10
    if os.name == "nt":
        assert len(observations) == 1000
    engine._release_plan_budget(plan)


def test_planning_disappearance_and_apply_replacement_fail_closed(tmp_path):
    root = tmp_path / "configured" / "cache"
    root.mkdir(parents=True)
    proof = root / "proof.tmp"
    proof.write_bytes(b"planned")
    engine = engine_for(root.parent, dry_run=False)
    original_lstat = Path.lstat

    def disappeared(path, *args, **kwargs):
        if path == proof:
            raise FileNotFoundError("entry vanished during observation")
        return original_lstat(path, *args, **kwargs)

    with patch.object(Path, "lstat", disappeared):
        plan = engine._plan_tree(root, "audit")
    assert plan is not None and not plan["files"]
    assert root in plan["protected"]
    engine._release_plan_budget(plan)
    size, identity = engine._plan_file(proof)
    proof.write_bytes(b"changed after planning")
    with patch.object(engine, "_authorize_mutation", wraps=engine._authorize_mutation) as authorize:
        result = engine._apply_file_plan(proof, size, identity)
    assert not result.success and result.bytes_freed == 0
    authorize.assert_called()
    assert proof.read_bytes() == b"changed after planning"


@pytest.mark.parametrize("backlog", [1000, 8000, 32000])
def test_ordinary_producers_never_rotate_protected_backlog(backlog):
    app = support.TestGuiThreadBoundary._fake_app()
    app.log_queue = vac._GuiLogBuffer(maxsize=16, protected_size=backlog)
    for index in range(backlog):
        app._log(vac._GuiLogMessage(f"failure {index}", "error"))
    with patch.object(app.log_queue, "get_nowait", wraps=app.log_queue.get_nowait) as gets, \
         patch.object(app.log_queue, "put_nowait", wraps=app.log_queue.put_nowait) as puts:
        for index in range(1000):
            app._log(f"ordinary {index}")
    assert gets.call_count == 0 and puts.call_count == 1000
    assert app.log_queue.qsize() == backlog + 16
    assert app.log_queue.get_nowait() == "failure 0"


def test_saturated_channels_keep_controls_and_pending_auto_clean():
    app = support.TestGuiThreadBoundary._fake_app()
    app.log_queue = vac._GuiLogBuffer(maxsize=2, protected_size=2)
    app.config["auto_clean_interval_hours"] = 1
    for index in range(1000):
        app._log(str(index))
        app._log(vac._GuiLogMessage(f"failure {index}", "error"))
    assert app.log_queue.qsize() == 5
    app.cancel_event.set()
    with patch.object(vac.threading, "Timer"), patch.object(app, "_start_job") as start:
        app._auto_clean_trigger()
        app._poll_main()
        start.assert_called_once()
    for _index in range(1000):
        app._log(app._CLOSE_MARKER)
    with patch.object(app, "_on_close") as close:
        app._poll_main()
        close.assert_called_once()
    assert app.cancel_event.is_set()
    assert app.log_queue.qsize() <= 5


@pytest.mark.parametrize("branches", [2000, 5000])
def test_universal_prunes_owned_tree_but_discovers_adjacent_unknown(tmp_path, branches):
    root = tmp_path / "portable"
    for index in range(branches):
        (root / "_CENT" / f"branch{index}" / "Cache").mkdir(parents=True)
    unknown = root / "copy_CENT" / "Cache"
    unknown.mkdir(parents=True)
    proof = unknown / "keep.tmp"
    proof.write_bytes(b"unknown owner")
    cleaner = vac.PortableCleaner(False, vac.Logger(None, False), vac.SafetyGuard(root), root)
    visited, messages = [], []
    scandir = vac.os.scandir

    def scan(path):
        visited.append(Path(path))
        return scandir(path)

    with patch.object(vac.os, "scandir", side_effect=scan), \
         patch.object(cleaner.log, "info", side_effect=messages.append):
        assert cleaner.clean_universal_caches() == 0
    assert root / "_CENT" not in visited
    assert root / "copy_CENT" in visited
    assert any("NOT AUTHORIZED" in message and "copy_CENT" in message for message in messages)
    assert proof.read_bytes() == b"unknown owner"
    assert cleaner.log.bytes_freed == 0


def test_universal_budget_exhaustion_warns_once_and_mutates_nothing(tmp_path, monkeypatch):
    root = tmp_path / "portable"
    for index in range(100):
        folder = root / f"unknown{index}" / "Cache"
        folder.mkdir(parents=True)
        (folder / "keep.tmp").write_bytes(b"unknown owner")
    cleaner = vac.PortableCleaner(False, vac.Logger(None, False), vac.SafetyGuard(root), root)
    monkeypatch.setenv("SMARTVAC_DISCOVERY_MAX_NODES", "10")
    with patch.object(cleaner.log, "warning") as warnings:
        assert cleaner.clean_universal_caches() == 0
    warnings.assert_called_once()
    assert "truncated at 10 entries" in warnings.call_args.args[0]
    assert len(list(root.rglob("keep.tmp"))) == 100
    assert cleaner.log.bytes_freed == 0
