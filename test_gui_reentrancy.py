"""T-209: GUI destructive-launch reentrancy through modal dialogs.

Isolated fixtures drive the real App launch/lifecycle methods without a Tk
display: fake lease, fake worker thread, and a fake askyesno whose nested call
simulates the modal's nested event loop reentering the start path.
"""

import threading
from typing import ClassVar

import pytest

import _SMART_VAC_CLEANER as vac


class _StubWidget:
    def __init__(self):
        self.state = "normal"
        self.deleted = 0

    def configure(self, **kwargs):
        if "state" in kwargs:
            self.state = kwargs["state"]

    def delete(self, *args):
        self.deleted += 1


class FakeLease:
    acquired = 0
    released = 0
    fail_acquire = False

    def acquire(self):
        if type(self).fail_acquire:
            return False
        type(self).acquired += 1
        return True

    def release(self):
        type(self).released += 1


class FakeThread:
    instances: ClassVar[list] = []
    explode = False

    def __init__(self, target=None, args=(), daemon=None):
        self.target = target
        self.args = args
        self.started = False
        self._alive = False
        type(self).instances.append(self)

    def start(self):
        if type(self).explode:
            raise RuntimeError("injected worker start failure")
        self.started = True
        self._alive = True

    def is_alive(self):
        return self._alive

    def join(self, *args):
        self._alive = False


@pytest.fixture
def app(monkeypatch):
    FakeThread.instances = []
    FakeThread.explode = False
    FakeLease.acquired = 0
    FakeLease.released = 0
    FakeLease.fail_acquire = False
    a = vac.App.__new__(vac.App)
    a.T = {"confirm_title": "Confirm", "confirm_body": "Delete?",
           "error_title": "Error", "cancelling": "Cancelling"}
    a.config = {}
    a.sys_targets = {}
    a.cancel_event = threading.Event()
    a._clean_in_progress = False
    a._job_starting = False
    a._close_pending = False
    a._lease = None
    a._worker_thread = None
    a._job_done_event = threading.Event()
    a.progress = vac.ProgressTracker()
    a.btn_clean = _StubWidget()
    a.btn_preview = _StubWidget()
    a.btn_stop = _StubWidget()
    a.text_log = _StubWidget()
    a._tray_icon = None
    a._clean_timer = None
    a.messages = []
    a._log = lambda m, kind=None: a.messages.append(str(m))
    a._schedule_auto_clean = lambda: None
    a._rebuild_cat_bars = lambda: None
    a._reset_dashboard = lambda: None
    a._persist_window_geometry = lambda: None
    a._full_exit_impl = lambda: None
    monkeypatch.setattr(vac, "_JobLease", FakeLease)
    monkeypatch.setattr(vac.threading, "Thread", FakeThread)
    monkeypatch.setattr(vac, "load_config_strict",
                        lambda *a, **k: (vac.ConfigState.VALID, {}, []))
    monkeypatch.setattr(vac, "merged_system_targets", lambda c: {})
    monkeypatch.setattr(vac, "resolve_job_spec", lambda **k: object())
    monkeypatch.setattr(vac.messagebox, "askyesno", lambda *a, **k: True)
    return a


def test_modal_reentry_cannot_start_second_job(app, monkeypatch):
    events = []

    def fake_askyesno(*args, **kwargs):
        events.append("dialog")
        if len(events) == 1:
            # The modal's nested event loop: poller/tray callbacks reenter the
            # start path while the confirmation is still open.
            events.append(("reenter_start", app._start_job()))
            events.append(("reenter_preview", app._start_preview()))
            events.append(("during_in_progress", app._clean_in_progress))
            events.append(("during_worker", app._worker_thread))
            events.append(("during_gate", app._job_starting))
            events.append(("during_lease", app._lease))
        return True

    monkeypatch.setattr(vac.messagebox, "askyesno", fake_askyesno)

    app._start_job()

    # The nested reentry produced nothing: one worker, one lease, no swap.
    assert ("reenter_start", None) in events
    assert ("reenter_preview", None) in events
    assert ("during_in_progress", False) in events
    assert ("during_worker", None) in events
    assert ("during_gate", True) in events
    assert ("during_lease", None) in events
    assert len(FakeThread.instances) == 1
    worker = FakeThread.instances[0]
    assert worker.started
    assert app._worker_thread is worker
    assert app._clean_in_progress is True
    assert FakeLease.acquired == 1
    assert app._lease is not None
    assert app._job_starting is False
    assert app.btn_clean.state == "disabled"


def test_close_during_confirmation_stops_launch(app, monkeypatch):
    def fake_askyesno(*args, **kwargs):
        app._on_close()
        return True

    monkeypatch.setattr(vac.messagebox, "askyesno", fake_askyesno)

    app._start_job()

    assert FakeThread.instances == []
    assert app._clean_in_progress is False
    assert app._close_pending is True
    assert app._job_starting is False


def test_failed_start_rollback_is_idempotent(app, monkeypatch):
    FakeThread.explode = True

    app._start_job()

    assert FakeLease.acquired == 1
    assert FakeLease.released == 1
    assert app._clean_in_progress is False
    assert app._worker_thread is None
    assert app._lease is None
    assert app._job_starting is False
    assert app.cancel_event.is_set()
    assert any("Could not start cleaning" in m for m in app.messages)
    before = FakeLease.released
    assert app._reset_to_idle() is True
    assert FakeLease.released == before


def test_reset_refuses_to_release_alive_worker_lease(app):
    app._clean_in_progress = True
    worker = FakeThread()
    worker.start()
    app._worker_thread = worker
    lease = FakeLease()
    lease.acquire()
    app._lease = lease

    assert app._reset_to_idle() is False
    assert FakeLease.released == 0
    assert app._clean_in_progress is True
    assert app._lease is lease


def test_start_during_active_job_is_refused(app):
    app._clean_in_progress = True
    worker = FakeThread()
    worker.start()
    app._worker_thread = worker
    lease = FakeLease()
    lease.acquire()
    app._lease = lease

    app._start_job()

    assert len(FakeThread.instances) == 1
    assert FakeLease.acquired == 1
    assert app._worker_thread is worker
    assert app._lease is lease
