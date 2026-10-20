"""T-210: log retention must not delete outside the verified logs directory.

The swap oracle injects a directory swap BETWEEN the final identity check and
the mutation itself -- a check-time-only swap proves nothing. On Windows the
mutation is the native pinned delete (CreateFileW + SetFileInformationByHandle);
on POSIX it is the anchored unlinkat; the oracle patches whichever mutation
primitive the subject uses. Disposable fixtures only; no user log is ever
touched.
"""

import errno
import os
import subprocess
from pathlib import Path

import pytest

import _SMART_VAC_CLEANER as vac

KEEP = 3


def _can_symlink():
    try:
        os.symlink(".t210_probe_target", ".t210_probe_link")
        os.unlink(".t210_probe_link")
        return True
    except OSError as exc:
        denied = exc.errno in (errno.EPERM, errno.EACCES, getattr(errno, "WSAEACCES", 13), 1314)
        return not (denied or getattr(exc, "winerror", None) in (1314, 5, 1311))


def _dir_link(link: Path, target: Path) -> None:
    """Link a directory; a symlink needs a privilege this host may lack, so
    fall back to a native junction (mklink /J), which needs none and is just
    as much of a reparse point."""
    try:
        os.symlink(target, link)
    except OSError:
        result = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)],
                                capture_output=True, text=True, check=False)
        if result.returncode != 0 or not link.is_dir():
            raise OSError(f"cannot create directory link {link} -> {target}: {result.stdout}")


can_symlink = pytest.mark.skipif(not _can_symlink(), reason="symlink creation not permitted on this host")


def _names(n=8):
    return sorted(f"clean_2026010{i}_00000{i}.log" for i in range(n))


def _make_logs(root, names, content=b"log line\n"):
    logs = root / "logs"
    logs.mkdir()
    for name in names:
        (logs / name).write_bytes(content)
    return logs


def test_trusted_directory_still_rotates(tmp_path):
    names = _names(n=8)
    logs = _make_logs(tmp_path, names)

    vac._prune_old_logs(logs, keep=KEEP)

    assert sorted(p.name for p in logs.iterdir()) == names[-KEEP:]


def test_swap_after_identity_check_cannot_escape(tmp_path, monkeypatch):
    """The exact post-identity-check/pre-mutation race: the swap happens inside
    the mutation call, after every check the code performs."""
    names = _names(n=8)
    logs = _make_logs(tmp_path, names)
    outside = tmp_path / "outside"
    outside.mkdir()
    for name in names[:5]:
        (outside / name).write_bytes(b"OUTSIDE OWNER DATA\n")
    sentinel_before = {p.name: p.read_bytes() for p in outside.iterdir()}

    real_unlink = os.unlink
    real_pinned = getattr(vac, "_win_delete_pinned", None)
    fired = []

    def swap_once(*args, **kwargs):
        if not fired:
            fired.append(True)
            # swap logs/ to a link onto the outside directory right now,
            # between the final identity check and this mutation
            origin = str(logs)
            os.rename(origin, origin + "_real")
            _dir_link(logs, outside)
        return real_unlink(*args, **kwargs)

    def pinned_swap_once(*args, **kwargs):
        if not fired:
            fired.append(True)
            origin = str(logs)
            os.rename(origin, origin + "_real")
            _dir_link(logs, outside)
        return real_pinned(*args, **kwargs)

    monkeypatch.setattr(os, "unlink", swap_once)
    monkeypatch.setattr(vac, "_win_delete_pinned", pinned_swap_once, raising=False)

    vac._prune_old_logs(logs, keep=KEEP)

    # the race was really injected (an oracle that silently no-ops proves nothing)
    assert fired
    assert os.path.realpath(logs) == os.path.realpath(outside)
    after = {p.name: p.read_bytes() for p in outside.iterdir()}
    assert after == sentinel_before  # nothing outside was touched
    # the real victims still sat in the moved-away logs directory
    assert sorted(p.name for p in (logs.parent / (logs.name + "_real")).iterdir()) == names


def test_entry_replaced_after_enumeration_is_skipped(tmp_path, monkeypatch):
    names = _names(n=8)
    logs = _make_logs(tmp_path, names)
    victim = names[0]  # oldest legitimate prune victim

    real_anchor = vac._anchor_stat
    calls = {}

    def racing_anchor(entry, dir_fd):
        calls[entry.name] = calls.get(entry.name, 0) + 1
        if entry.name == victim and calls[entry.name] == 2:
            # an outside actor replaces the entry at the recheck point
            (logs / victim).unlink()
            (logs / victim).write_bytes(b"REPLACEMENT CONTENT\n")
        return real_anchor(entry, dir_fd)

    monkeypatch.setattr(vac, "_anchor_stat", racing_anchor, raising=False)

    vac._prune_old_logs(logs, keep=KEEP)

    assert calls[victim] >= 2  # the recheck really ran
    assert (logs / victim).read_bytes() == b"REPLACEMENT CONTENT\n"


def test_locked_entry_does_not_stop_rotation(tmp_path, monkeypatch):
    names = _names(n=8)
    logs = _make_logs(tmp_path, names)
    locked = names[2]

    real_unlink = os.unlink
    real_pinned = getattr(vac, "_win_delete_pinned", None)

    def locking_unlink(path, *args, **kwargs):
        name = Path(path).name if isinstance(path, (str, os.PathLike)) else path
        if name == locked:
            raise OSError(13, "locked")
        return real_unlink(path, *args, **kwargs)

    def locking_pinned(path, identity):
        if Path(path).name == locked:
            raise OSError(13, "locked")
        return real_pinned(path, identity)

    monkeypatch.setattr(os, "unlink", locking_unlink)
    monkeypatch.setattr(vac, "_win_delete_pinned", locking_pinned, raising=False)

    vac._prune_old_logs(logs, keep=KEEP)

    remaining = sorted(p.name for p in logs.iterdir())
    assert locked in remaining
    assert names[0] not in remaining  # other victims still pruned


def test_hardlinked_entry_keeps_outside_data(tmp_path):
    """A retained log that is itself a hardlink to outside data: deleting the
    name removes one link, it must never destroy the outside bytes."""
    names = _names(n=8)
    logs = _make_logs(tmp_path, names)
    outside = tmp_path / "outside_owner.log"
    outside.write_bytes(b"owner payload\n")
    (logs / names[0]).unlink()
    os.link(outside, logs / names[0])

    vac._prune_old_logs(logs, keep=KEEP)

    assert outside.read_bytes() == b"owner payload\n"
    assert not (logs / names[0]).exists()  # the stale name is gone, link count permits it


@can_symlink
def test_linked_entry_is_skipped(tmp_path):
    names = _names(n=8)
    logs = _make_logs(tmp_path, names)
    outside = tmp_path / "outside_owner.log"
    outside.write_bytes(b"owner\n")
    (logs / names[0]).unlink()
    os.symlink(outside, logs / names[0])

    vac._prune_old_logs(logs, keep=KEEP)

    assert (logs / names[0]).is_symlink()
    assert outside.read_bytes() == b"owner\n"
    assert sorted(p.name for p in logs.iterdir()) == [names[0]] + names[-KEEP:]


def test_untrusted_logs_directory_is_refused(tmp_path):
    names = _names(n=4)
    real_logs = _make_logs(tmp_path, names)
    link_logs = tmp_path / "link_logs"
    _dir_link(link_logs, real_logs)

    vac._prune_old_logs(link_logs, keep=KEEP)

    assert sorted(p.name for p in real_logs.iterdir()) == names  # nothing pruned


def test_dry_run_never_prunes(tmp_path):
    names = _names(n=8)
    logs = _make_logs(tmp_path, names)

    # Logger in dry-run mode never wires the file handler and never prunes
    vac.Logger(logs / "clean_20260101_000000.log", True, quiet=True)

    # nothing pruned, and no run file is created either: dry-run stays console-only
    assert sorted(p.name for p in logs.iterdir()) == names
