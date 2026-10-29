#!/usr/bin/env python3
# ruff: noqa: BLE001, PLW1510

# -*- coding: utf-8 -*-

"""

_SMART_VAC_CLEANER.py

Portable, dependency-free-ish (customtkinter, pystray, Pillow) smart cleaner
for system junk, app caches, portable-app roots, and user-defined rules.

Portable roots are configured per machine in cleaner_config.json
(portable_roots). Only roots that actually EXIST on the current machine get
swept and only known junk patterns inside them are removed. Missing
drives/disks are silently skipped, never errors.

Defense in depth: blacklist, path-part minimums, running-process checks,
symlink refusal, never-delete names, exclude lists, dry-run default.

GUI for interactive use + CLI for automated Task Scheduler execution.

"""


import argparse
import concurrent.futures
import copy
import csv
import enum
import errno
import fnmatch
import itertools
import json
import logging
import os
import queue
import re
import stat
import subprocess
import sys
import time
import weakref
from collections import deque
from contextlib import contextmanager


class ConfigState(enum.Enum):
    MISSING = 1
    VALID = 2
    INVALID = 3

import threading

try:

    import pystray
    from PIL import Image, ImageDraw

except ImportError:

    pystray = None


from datetime import datetime
from pathlib import Path
from typing import NamedTuple

try:
    from tkinter import Listbox, filedialog, messagebox, simpledialog

    import customtkinter as ctk
except ImportError:
    Listbox = None
    filedialog = None
    messagebox = None
    simpledialog = None
    ctk = None


def safe_exists(path: Path | str | None) -> bool:
    """Check existence safely, returning False on PermissionError/OSError."""
    if path is None:
        return False
    try:
        return os.path.exists(path)
    except (OSError, ValueError):
        return False


def safe_is_dir(path: Path | str | None) -> bool:
    """Check if path is a directory safely, returning False on PermissionError/OSError."""
    if path is None:
        return False
    try:
        return os.path.isdir(path)
    except (OSError, ValueError):
        return False

#  CORE CONFIGURATION



VERSION = "2.6.10"
PROCESS_AGNOSTIC = "__PROCESS_AGNOSTIC__"

DEFAULT_THREADS = 12


SCRIPT_PATH = Path(__file__).resolve()

if getattr(sys, "frozen", False):
    BASE_DIR = Path(sys.executable).resolve().parent
else:
    BASE_DIR = SCRIPT_PATH.parent

# T-139: writable persistence root differs by deployment. A frozen portable exe
# keeps config/logs next to the exe; a source checkout keeps them next to the
# source; an INSTALLED wheel (module in site-packages) must NOT write user data
# into site-packages -- it uses the per-user %LOCALAPPDATA%\SmartVACCleaner
# (may be read-only / shared). SMARTVAC_DATA_DIR overrides the root explicitly
# (tests, CI, unusual deployments).
if os.environ.get("SMARTVAC_DATA_DIR"):
    DATA_DIR = Path(os.environ["SMARTVAC_DATA_DIR"]).resolve()
elif getattr(sys, "frozen", False):
    DATA_DIR = BASE_DIR
elif "site-packages" in str(BASE_DIR).lower():
    DATA_DIR = Path(os.environ.get("LOCALAPPDATA") or Path.home()) / "SmartVACCleaner"
else:
    DATA_DIR = BASE_DIR

CONFIG_FILE = DATA_DIR / "cleaner_config.json"

LOGS_DIR = DATA_DIR / "logs"

# Locale resources stay readable wherever the MODULE lives (site-packages
# included), independent of the writable data root (T-139).
STRINGS_DIR = BASE_DIR / "strings"

DEFAULT_STRINGS: dict[str, str] = {
    "clean": "Clean",
    "preview": "Preview",
    "stop": "Stop",
    "install_task": "Install Auto-Clean Task",
    "run_bg": "Run in bg",
    "run_bg_started": "Background clean started (hidden).",
    "run_bg_running": "Background clean already running.",
    "window_title": "Smart VAC Cleaner",
    "confirm_title": "Confirm DELETE",
    "confirm_body": "Files will be permanently removed (no recycle bin).\n\nContinue?",
    "cancelled": "Cancelled.",
    "cancelling": "Cancelling...",
    "task_dialog_title": "Auto-Clean Task",
    "task_dialog_prompt": "Daily start time (HH:MM):",
    "exclusions": "Exclusions",
    "exc_title": "Exclusions",
    "exc_patterns": "Patterns",
    "exc_paths": "Paths",
    "exc_add_path": "Add Path",
    "exc_remove": "Remove",
    "exc_saved": "Exclusions saved.",
    "exc_help": "One pattern or path per line.\nPatterns use * wildcards (e.g. *.tmp).",
    "save": "Save",
    "sys_targets": "System Targets",
    "syst_title": "System Targets",
    "syst_help": "Risky targets (Recycle Bin, DNS, Windows Update) delete real data.\nThey stay OFF by default. Safe targets stay ON.",
    "syst_saved": "System targets saved.",
}


def load_strings(lang: str) -> dict[str, str]:
    strings = dict(DEFAULT_STRINGS)
    candidates = [STRINGS_DIR]
    if getattr(sys, "frozen", False):
        candidates.append(Path(getattr(sys, "_MEIPASS", STRINGS_DIR)) / "strings")
    for base in candidates:
        path = base / f"{lang}.json"
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                strings.update({k: v for k, v in data.items() if isinstance(v, str)})
                break
        except (OSError, ValueError):
            continue
    return strings


MIN_PATH_PARTS = 5

# F2: bounded STOP_PENDING wait when stopping wuauserv. STOP_PENDING is WAIT,
# never authorization; only the exact STOPPED state authorizes deletion.
_WU_STOP_POLL_TIMEOUT = 30.0
_WU_STOP_POLL_INTERVAL = 0.25

# T-131: re-check the owning process state every N file mutations inside a long
# directory plan, not once per file (tasklist is expensive).
_OWNER_REFRESH_BATCH = 64

# T-134: explicit mutation inventory by subsystem. Every filesystem mutation the
# cleaner performs must live in one of these allowed sites; the chokepoint test
# fails on ANY unknown cleaner mutation primitive.
_CLEANER_MUTATION_SITES = ("_apply_file_plan", "_apply_tree_plan")
_CLEANER_MUTATION_TOKENS = (".chmod(", ".unlink(", ".rmdir(")
_CONFIG_PERSISTENCE_SITES = ("save_config",)
_CONFIG_PERSISTENCE_TOKENS = (".replace(",)  # atomic config save (Path.replace)
_SERVICE_ACTION_SITES = ("_clean_windows_update_cache", "run_all", "_service_state")
_SERVICE_ACTION_TOKENS = ("net stop", "net start", "ipconfig", "SHEmptyRecycleBin", "sc query")
_BANNED_CLEANER_PRIMITIVES = ("os.remove(", "os.unlink(", "os.rmdir(",
                              "shutil.rmtree(", "shutil.move(", "Path.rename(", ".rename(")

# T-110: log-hygiene retention is its own mutation subsystem (NOT a cleaner
# deletion): it only ever removes clean_*.log files from the cleaner's own
# logs/ directory.
_LOG_RETENTION_KEEP = 14
_LOG_RETENTION_SITES = ("_prune_old_logs",)
# T-210: entry-style path unlink, plus the POSIX anchored unlinkat(dir_fd) form
_LOG_RETENTION_TOKENS = (".unlink(", "os.unlink(")


def _is_reparse_point(path: Path) -> bool:
    """T-202: True when path ITSELF is a link, junction, mount point or any
    other reparse point. lstat only -- it never follows the link.
    Path.resolve() proves nothing here: it happily returns the target hiding
    behind the junction."""
    try:
        st = os.lstat(path)
    except (OSError, ValueError):
        return False
    attrs = getattr(st, "st_file_attributes", 0)
    if attrs & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0):
        return True  # Windows: any reparse tag (symlink, junction, mount point)
    return stat.S_ISLNK(st.st_mode)  # POSIX symlink


def _log_dir_boundary_ok(logs_dir: Path, *, require_dir: bool) -> bool:
    """T-202: no-follow trust boundary for the logs directory.

    Every EXISTING component of the absolute path -- the logs directory itself
    and each ancestor -- must be a real directory. One link/junction/reparse
    point anywhere on the chain makes the whole path untrusted: retention
    would traverse out of the application data root and delete files there,
    and Logger would write run logs into the redirected target as well.
    """
    try:
        absolute = Path(os.path.abspath(logs_dir))
    except (OSError, ValueError):
        return False
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current = current / part
        if not current.exists():
            break  # nothing below an absent component can be traversed yet
        if _is_reparse_point(current) or not current.is_dir():
            return False
    if require_dir:
        return absolute.is_dir() and not _is_reparse_point(absolute)
    return not absolute.exists() or (absolute.is_dir() and not _is_reparse_point(absolute))


def _dir_identity(path: Path) -> tuple[int, int]:
    """T-202: filesystem identity (device, inode) for replacement detection."""
    st = os.stat(path)
    return (st.st_dev, st.st_ino)


def _log_retention_refused(logs_dir: Path, reason: str) -> None:
    logging.getLogger("vac_cleaner").warning(f"Log retention skipped for {logs_dir}: {reason}")


class _AnchoredRunLogHandler(logging.FileHandler):
    """T-211/T-212: run-log handler wrapping an already-anchored stream.

    Never reopens or re-resolves the destination path after the initial create;
    if closed or unseated, emits are dropped rather than re-creating the file.
    """

    def _open(self):
        # Never reopen on emit; the stream was anchored at creation
        return None

    def emit(self, record: logging.LogRecord) -> None:
        if self.stream is None or getattr(self.stream, "closed", False):
            return
        try:
            super().emit(record)
        except (OSError, ValueError):
            pass

    def close(self) -> None:
        try:
            logging.getLogger("vac_cleaner").removeHandler(self)
        except Exception:  # noqa: S110 - best effort removal on close
            pass
        super().close()


def _open_run_log_stream(log_file: Path, parent_identity, instance_logger=None):
    """T-211/T-212: create a run log exclusively, anchored to the verified
    directory (T-211). Refusal diagnostics go through instance_logger when the
    caller supplies one, so a refused create never lands in a *different*
    Logger's file (T-212).

    A pre-existing destination of any kind is refused, never appended to: plain
    file, symlink, or file hardlink. Run-log names are freshly timestamped, so
    an existing name means something foreign already sits there. On POSIX the
    create runs O_CREAT|O_EXCL|O_NOFOLLOW relative to an O_DIRECTORY|O_NOFOLLOW
    directory handle opened after the boundary check, so a parent swapped
    between check and create cannot redirect it. On Windows the stdlib has no
    dir-handle-relative create, so the parent identity is re-checked and the
    destination lstat'ed for reparse points immediately before the O_EXCL create
    (ponytail: narrows the race to the open syscall itself; a native
    NtCreateFile dir-relative open is the upgrade path if the window matters).
    """
    log = instance_logger or logging.getLogger("vac_cleaner")
    name = log_file.name
    parent = str(log_file.parent)
    dir_fd = None
    try:
        if os.name == "posix":
            dir_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | os.O_NOFOLLOW)
            fd = os.open(name, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600, dir_fd=dir_fd)
        else:
            try:
                if _dir_identity(log_file.parent) != parent_identity or _is_reparse_point(log_file):
                    log.warning(
                        f"Refusing log destination {log_file}: parent identity changed or linked destination"
                    )
                    return None
            except OSError as exc:
                log.warning(f"Cannot verify log destination {log_file}: {exc}")
                return None
            fd = os.open(str(log_file), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        log.warning(
            f"Refusing pre-existing log destination {log_file}: exclusive create expected a fresh name"
        )
        return None
    except OSError as exc:
        log.warning(f"Cannot create log file {log_file}: {exc}")
        return None
    finally:
        if dir_fd is not None:
            os.close(dir_fd)
    try:
        stream = os.fdopen(fd, "a", encoding="utf-8")
    except OSError as exc:
        os.close(fd)
        log.warning(f"Cannot wrap log stream {log_file}: {exc}")
        return None
    # The handler never re-resolves log_file: delay=True never opens, our
    # anchored stream is assigned directly, and close() closes that stream.
    fh = _AnchoredRunLogHandler(str(log_file), encoding="utf-8", delay=True)
    fh.stream = stream
    return fh


def _anchor_stat(entry, dir_fd):
    """T-110: identity of an enumerated entry, relative to the anchor when the
    platform supports it, else through its pathname."""
    if dir_fd is not None:
        return os.stat(entry.name, dir_fd=dir_fd, follow_symlinks=False)
    return os.stat(entry.path, follow_symlinks=False)


# T-110: Windows native pinned delete. The stdlib has no dir-handle-relative
# unlink on Windows, so the verified entry is deleted through an open handle:
# CreateFileW pins the current object, its identity is re-verified against the
# entry stat, and SetFileInformationByHandle deletes that object with no name
# re-resolution, so a later swap cannot redirect the deletion.
_WIN_DELETE_ACCESS = 0x00010000
_WIN_OPEN_EXISTING = 3
_WIN_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_WIN_INVALID_HANDLE = 0xFFFFFFFFFFFFFFFF  # c_void_p restype yields unsigned pointers
_WIN_FILE_DISPOSITION_INFO = 4
_WIN_SHARE_ALL = 0x00000007


def _win_file_information_cls():
    """ctypes.wintypes ships no BY_HANDLE_FILE_INFORMATION; build it here (the
    volume serial + file index are the identity the pinned delete re-verifies).
    Cached on the function so repeated deletes stay cheap."""
    import ctypes
    from ctypes import wintypes

    cls = getattr(_win_file_information_cls, "_cls", None)
    if cls is None:

        class BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
            # _pack_ = 1 is required: the real struct has no alignment padding,
            # so dwVolumeSerialNumber sits at offset 28. Default 8-byte
            # alignment shifts every identity field and breaks the comparison
            # against os.stat()'s (st_dev, st_ino).
            _pack_ = 1
            _fields_ = [
                ("dwFileAttributes", wintypes.DWORD),
                ("_creation", ctypes.c_uint64),
                ("_access", ctypes.c_uint64),
                ("_write", ctypes.c_uint64),
                ("dwVolumeSerialNumber", wintypes.DWORD),
                ("_sizeHigh", wintypes.DWORD),
                ("_sizeLow", wintypes.DWORD),
                ("_links", wintypes.DWORD),
                ("nFileIndexHigh", wintypes.DWORD),
                ("nFileIndexLow", wintypes.DWORD),
            ]

        cls = _win_file_information_cls._cls = BY_HANDLE_FILE_INFORMATION
    return cls


def _win_delete_pinned(path: Path, identity) -> bool:
    """Delete one verified entry through a pinned Windows handle.

    Returns False without mutating when the open handle does not carry the
    expected (volume, file-index) identity -- the entry was replaced between
    the check and the open. Raises OSError only for OS-level refusals the
    caller treats as skip-and-continue.
    """
    import ctypes
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                   wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel.SetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.c_int,
                                                  ctypes.c_void_p, wintypes.DWORD]
    info_cls = _win_file_information_cls()
    kernel.GetFileInformationByHandle.argtypes = [wintypes.HANDLE,
                                                  ctypes.POINTER(info_cls)]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel.CreateFileW(str(path), _WIN_DELETE_ACCESS, _WIN_SHARE_ALL, None,
                                _WIN_OPEN_EXISTING, _WIN_FILE_FLAG_BACKUP_SEMANTICS, None)
    if not handle or handle == _WIN_INVALID_HANDLE:
        raise OSError(ctypes.get_last_error(), "cannot open entry for pinned delete")
    try:
        info = info_cls()
        if not kernel.GetFileInformationByHandle(handle, ctypes.byref(info)):
            raise OSError(ctypes.get_last_error(), "cannot verify pinned entry handle")
        if (info.dwVolumeSerialNumber,
                (info.nFileIndexHigh << 32) | info.nFileIndexLow) != identity:
            return False
        disposition = ctypes.c_byte(1)
        if not kernel.SetFileInformationByHandle(handle, _WIN_FILE_DISPOSITION_INFO,
                                                 ctypes.byref(disposition), ctypes.sizeof(disposition)):
            raise OSError(ctypes.get_last_error(), "pinned delete refused")
        return True
    finally:
        kernel.CloseHandle(handle)


def _prune_old_logs(logs_dir: Path, keep: int = _LOG_RETENTION_KEEP) -> None:
    """T-110/T-202: keep the `keep` most recent clean_*.log files, prune older.

    LOG-hygiene, not a cleaner deletion: the only files it ever removes are the
    cleaner's own timestamped run logs, and it is allowlisted in the mutation
    inventory as its own subsystem (never routed through the deletion
    SafetyGuard). Runs once per job at Logger construction.

    T-202 no-follow boundary: when the logs directory or an existing ancestor
    is a link/junction/reparse point, retention is REFUSED with a diagnostic
    instead of following the redirect and deleting outside the application
    data root. Symlinked entries, directories and any non-regular file are
    skipped, never followed. Optional hygiene never fails the cleaner:
    unreadable/vanished directories simply prune nothing.

    T-110: the identity check and the mutation are never separate pathname
    operations. On POSIX the whole loop runs relative to ONE O_DIRECTORY|
    O_NOFOLLOW directory handle, opened after the boundary check and proven
    against the boundary-checked pathname identity, so a directory swapped
    after the final identity check cannot redirect an unlink. Every entry's
    identity is re-verified immediately before its unlink as well, so an entry
    replaced after enumeration is skipped, never deleted. Windows lacks
    stdlib dir-fd operations: there the directory identity and every entry's
    (device, inode) identity are re-verified immediately before each unlink,
    which narrows but cannot close the window (ponytail: a native
    NtCreateFile dir-relative delete is the upgrade path if it matters).
    """
    try:
        if not _log_dir_boundary_ok(logs_dir, require_dir=True):
            _log_retention_refused(logs_dir, "untrusted directory boundary (link/junction/reparse point on the path)")
            return
        identity = _dir_identity(logs_dir)
        dir_fd = None
        try:
            if os.name == "posix":
                dir_fd = os.open(logs_dir, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | os.O_NOFOLLOW)
                # prove the handle and the boundary-checked pathname are the
                # same inode before trusting the handle for deletions
                handle_st = os.fstat(dir_fd)
                if (handle_st.st_dev, handle_st.st_ino) != identity:
                    _log_retention_refused(logs_dir, "directory handle identity mismatch")
                    return
                scan_path = dir_fd
            else:
                scan_path = logs_dir
            with os.scandir(scan_path) as scan:
                entries = [e for e in scan
                           if e.name.startswith("clean_") and e.name.endswith(".log")]
            entries.sort(key=lambda e: e.name, reverse=True)
            for entry in entries[keep:]:
                # replacement race: the directory was swapped under us
                if _dir_identity(logs_dir) != identity:
                    _log_retention_refused(logs_dir, "directory identity changed during retention")
                    return
                # unsafe file types are skipped, never followed: symlink entry,
                # junction entry, directory named clean_*.log, anything non-plain
                if entry.is_symlink() or not entry.is_file(follow_symlinks=False):
                    continue
                try:
                    seen = _anchor_stat(entry, dir_fd)
                except OSError:
                    continue  # vanished between enumeration and stat
                # pre-mutation identity recheck: directory and entry as known
                if _dir_identity(logs_dir) != identity:
                    _log_retention_refused(logs_dir, "directory identity changed during retention")
                    return
                try:
                    now = _anchor_stat(entry, dir_fd)
                except OSError:
                    continue
                if (now.st_dev, now.st_ino) != (seen.st_dev, seen.st_ino):
                    continue  # entry replaced after enumeration: never mutated
                try:
                    if dir_fd is not None:
                        os.unlink(entry.name, dir_fd=dir_fd)
                    else:
                        _win_delete_pinned(logs_dir / entry.name,
                                           (now.st_dev, now.st_ino))
                except OSError:
                    continue  # locked or vanished: the remaining logs still prune
        finally:
            if dir_fd is not None:
                os.close(dir_fd)
    except OSError:
        pass  # logs dir missing/unreadable: nothing to prune


APP_PROCESSES: dict[str, set[str]] = {

    "cent":     {"chrome.exe"},

    "brave":    {"brave.exe"},

    "firefox":  {"firefox.exe"},

    "opera":    {"opera.exe"},

    "telegram": {"telegram.exe"},

    "chrome":   {"chrome.exe"},

    "edge":     {"msedge.exe"},

    "discord":  {"discord.exe"},

    "ollama":   {"ollama.exe", "ollama app.exe"},

    "maxonapp": {"maxonapp.exe"},

    "photoshop": {"photoshop.exe"},

    "razer":    {"razerappengine.exe"},

    "epic":     {"epicgameslauncher.exe"},

    "code":     {"code.exe"},

    "claude":   {"claude.exe", "claude desktop.exe"},

    "bridge":   {"bridge.exe"},

    "qbittorrent": {"qbittorrent.exe"},

    "megasync": {"megasync.exe"},

    "drivefs":  {"googledrivesync.exe", "drivefs.exe"},

    "obs":      {"obs64.exe", "obs32.exe"},

    "listary":  {"listary.exe"},

    "eagle":    {"eagle.exe"},

    "freefilesync": {"freefilesync.exe", "ffs.exe", "realtimesync.exe"},

    "steam":    {"steam.exe"},

    "docker":   {"docker desktop.exe", "docker.exe"},

    "antigravity": {"antigravity-x64.exe", "antigravity.exe"},

    "obsidian": {"obsidian.exe"},

    "maxon":    {"maxon.exe"},

    "aichatter": {"aichatter.exe", "ai chatter.exe"},

    "codenomad": {"codenomad.exe"},

    "devin":    {"devin.exe"},

    "calibre":  {"calibre.exe", "calibre-portable.exe"},

    "quiterss": {"quiterss.exe"},

    "freebuff": {"freebuff.exe"},

    "lmstudio": {"lm studio.exe"},

    "losslesscut": {"losslesscut.exe"},

    "topaz":    {"topaz video ai.exe", "topaz video.exe", "topaz photo ai.exe"},

    "bluestacks": {"bluestacksai.exe", "bluestacksairun.exe", "bluestacksappplayerweb.exe"},

    "hdplayer": {"hd-player.exe"},

    "omniroute": {"omniroute.exe", "omniroute-desktop.exe"},

    "stemstudio": {"stem-studio.exe", "stemstudio.exe"},

    "deskchat": {"deskchat.exe"},

    "dropdead": {"dropdead.exe"},

    "verifiedskill": {"verifiedskill.exe"},

    "borisfx":  {"borisfx.exe", "continuum.exe", "sapphire.exe"},

    "betterdiscord": {"betterdiscord installer.exe", "betterdiscord.exe"},

    "jangafx":  {"liquigen.exe"},

    "krisp":    {"krisp.exe"},

    "fontbase": {"fontbase.exe"},

    "influx":   {"influx.exe"},

    "itop":     {"itop.exe", "itop easy desktop.exe"},

    "clipstudio": {"clipstudiopaint.exe"},

    "charactercreator": {"charactercreator.exe"},

    "accu rig": {"accu rig.exe", "actorcore.exe"},

    "unreal":   {"unrealenginelauncher.exe"},

    "siyuan":   {"siyuan.exe", "siyuan-kernel.exe"},

    "viber":    {"viber.exe"},

    "yandexdisk": {"yandexdisk2.exe"},

    "githubcli": {"gh.exe"},

    "mailbird": {"mailbird.exe", "mailbirdportable.exe"},

    "substance": {"adobe substance 3d sampler.exe", "adobe substance 3d painter.exe", "adobe substance 3d designer.exe"},

    PROCESS_AGNOSTIC:  set(),

}

# F10: semantic provenance for every APP_PROCESSES group. A mapping is only
# trusted when it carries evidence here. "verified:disk" = the exe was located
# on this machine under the owning app's install/data dir (2026-08 audit);
# "verified:runtimelog" = the process gate fired in real clean logs;
# "product:exe" = canonical product executable name (app not installed here,
# name matches the vendor's shipping binary); "unverified-exe" = mapping kept
# but NOT independently confirmed -- treat with extra suspicion in future
# audits. Adding a process group without a provenance entry fails the tests.
APP_PROCESSES_PROVENANCE: dict[str, str] = {
    "cent": "verified:runtimelog (clean log 2026-07-26: 'cent' running; Chromium engine ships chrome.exe)",
    "brave": "verified:runtimelog (clean log 2026-07-26: 'brave' running) + verified:disk %LOCALAPPDATA%\\BraveSoftware",
    "firefox": "product:exe (firefox.exe)",
    "opera": "product:exe (opera.exe)",
    "telegram": "product:exe (telegram.exe)",
    "chrome": "product:exe (chrome.exe)",
    "edge": "product:exe (msedge.exe)",
    "discord": "product:exe (discord.exe)",
    "ollama": "verified:disk %LOCALAPPDATA%\\Programs\\Ollama\\ollama app.exe (2026-08)",
    "maxonapp": "unverified-exe",
    "photoshop": "product:exe (photoshop.exe)",
    "razer": "product:exe (razerappengine.exe)",
    "epic": "product:exe (epicgameslauncher.exe)",
    "code": "verified:disk %LOCALAPPDATA%\\Programs\\Microsoft VS Code\\Code.exe (2026-08)",
    "claude": "verified:disk %LOCALAPPDATA%\\AnthropicClaude\\claude.exe (2026-08)",
    "bridge": "verified:disk %APPDATA%\\Bridge\\bridge.exe (2026-08)",
    "qbittorrent": "product:exe (qbittorrent.exe)",
    "megasync": "product:exe (megasync.exe)",
    "drivefs": "product:exe (googledrivesync.exe / drivefs.exe)",
    "obs": "product:exe (obs64.exe / obs32.exe)",
    "listary": "verified:disk %ProgramFiles%\\Listary\\Listary.exe (2026-08)",
    "eagle": "verified:disk %ProgramFiles%\\Eagle\\Eagle.exe (2026-08)",
    "freefilesync": "product:exe (freefilesync.exe / ffs.exe / realtimesync.exe)",
    "steam": "product:exe (steam.exe)",
    "docker": "product:exe (docker desktop.exe / docker.exe)",
    "antigravity": "product:exe (antigravity-x64.exe)",
    "obsidian": "product:exe (obsidian.exe)",
    "maxon": "verified:disk %APPDATA%\\Maxon\\maxon.exe (2026-08)",
    "aichatter": "unverified-exe",
    "codenomad": "unverified-exe",
    "devin": "verified:disk %LOCALAPPDATA%\\Programs\\Devin\\Devin.exe (2026-08; corrected from invented devinst.exe)",
    "calibre": "product:exe (calibre.exe / calibre-portable.exe)",
    "quiterss": "unverified-exe",
    "freebuff": "verified:disk %LOCALAPPDATA%\\Programs\\@codebufffreebuff-desktop\\Freebuff.exe (2026-08)",
    "lmstudio": "verified:disk %LOCALAPPDATA%\\Programs\\LM Studio\\LM Studio.exe (2026-08)",
    "losslesscut": "unverified-exe",
    "topaz": "verified:disk %APPDATA%\\Topaz Labs LLC\\topaz photo ai.exe (2026-08)",
    "bluestacks": "verified:disk %ProgramFiles%\\BlueStacks_nxt\\BlueStacksAI.exe / BlueStacksAIRun.exe / BlueStacksAppplayerWeb.exe (2026-08)",
    "hdplayer": "verified:disk %ProgramFiles%\\BlueStacks_nxt\\HD-Player.exe (2026-08)",
    "omniroute": "unverified-exe",
    "stemstudio": "unverified-exe",
    "deskchat": "unverified-exe",
    "dropdead": "unverified-exe",
    "verifiedskill": "unverified-exe",
    "borisfx": "product:exe (borisfx.exe / continuum.exe / sapphire.exe)",
    "betterdiscord": "product:exe (betterdiscord installer.exe / betterdiscord.exe)",
    "jangafx": "verified:disk %ProgramFiles%\\JangaFX\\LiquiGen\\LiquiGen.exe (2026-08)",
    "krisp": "verified:disk %APPDATA%\\Krisp\\krisp.exe (2026-08)",
    "fontbase": "verified:disk %LOCALAPPDATA%\\Programs\\FontBase\\FontBase.exe (2026-08)",
    "influx": "unverified-exe",
    "itop": "unverified-exe",
    "clipstudio": "verified:disk %ProgramFiles%\\CELSYS\\CLIP STUDIO 1.5\\CLIP STUDIO PAINT\\CLIPStudioPaint.exe (2026-08)",
    "charactercreator": "verified:disk %ProgramFiles%\\Reallusion\\Character Creator 5\\Bin64\\CharacterCreator.exe (2026-08)",
    "accu rig": "unverified-exe (actorcore.exe / accu rig.exe NOT found on disk 2026-08)",
    "unreal": "product:exe (unrealenginelauncher.exe)",
    "siyuan": "verified:disk %APPDATA%\\SiYuan\\siyuan.exe (2026-08)",
    "viber": "verified:disk %LOCALAPPDATA%\\Viber\\Viber.exe (2026-08)",
    "yandexdisk": "verified:disk %APPDATA%\\Yandex\\YandexDisk2\\YandexDisk2.exe (2026-08)",
    "githubcli": "verified:disk %ProgramFiles%\\GitHub CLI\\gh.exe (2026-08)",
    "mailbird": "product:exe (mailbird.exe / mailbirdportable.exe)",
    "substance": "product:exe (adobe substance 3d sampler/painter/designer.exe)",
    PROCESS_AGNOSTIC: "verified: intentional empty group (never blocks)",
}


NEVER_DELETE_NAMES: frozenset = frozenset({

    "login data", "login data for account", "bookmarks", "bookmarks.bak",

    "preferences", "secure preferences", "web data", "local state",

    "history", "shortcuts", "top sites", "favicons", "reporting and nel",

    "session storage", "local storage", "databases", "indexeddb",

    "extensions", "local extension settings", "managed extension settings",

    "sync extension settings", "sync app settings", "sync data",

    "extension rules", "extension scripts", "extension state", "dnr extension rules",

    "client certificates", "accounts", "network persistent state", "transportsecurity",

    "cookies", "extension cookies", "widevinecdm",

    "key4.db", "logins.json", "logins-backup.json", "cert9.db", "pkcs11.txt", "prefs.js",

    "places.sqlite", "cookies.sqlite",

    "key_datas", "settingss", "a7fdf864fbc10b77", "d877f783d5d3ef8c",

    # profile / account / security / session state lost in runtime deletions (P0-5)
    "passkey_enclave_state", "trusted_vault.pb", "affiliation database",
    "browsingtopicsstate", "sharedstorage", "interestgroups", "privateaggregation",
    "downloadmetadata", "dips", "network action predictor",
    "heavy_ad_intervention_opt_out.db", "parcel_tracking_db", "coupon_db",
    "discounts_db", "commerce_subscription_db", "autofillstrikedatabase",
    "budgetdatabase", "site characteristics database", "segmentation platform",
    "shared_proto_db", "optimization_guide_hint_cache_store",
    "optimization_guide_model_metadata_store", "feature engagement tracker",
    "download service", "persistentorigintrials", "safe browsing network",
    "gcm store", "platform notifications", "safe browsing", "p3aconfig",
    "variations", "safetytips", "tpcdmetadata", "zxcvbndata", "hyphen-data",
    "crowd deny", "meipreload", "origintrials", "pkimetadata",
    "sslerrorassistant", "certificaterevocation", "filetypepolicies",
    "firstpartysetspreloaded", "autofillstates", "trusttokenkeycommitments",
    "subresource filter", "webstore downloads", "ondeviceheadsuggestmodel",
    "optimizationhints", "optimization_guide_model_store",
    "sessionstore-backups", "security_state", "datareporting", "safebrowsing",
    "alternateservices.bin", "sitesecurityservicestate.bin",
    "bounce-tracking-protection.sqlite", "domain_to_categories.sqlite",
    "activity-stream.inferred_personalization_feed.json",
    "activity-stream.weather_feed.json", "shield-preference-experiments.json",
    "targeting.snapshot.json",
    # FreeFileSync config / state (P0-1)
    "global settings.xml", "global settings.xml.ffs_bak",
    "lastrun.ffs_real", "lastrun.ffs_gui",

})

# Numbered-copy cleanup is explicit junk-only (P0-2). A numbered copy is only
# deletable when its base name is an unequivocal cache/temp/log/crash artifact.
# Profile data backups (e.g. "History (2)", "Login Data (3)") are NEVER junk.
NUMBERED_COPY_JUNK_BASES = frozenset({
    "cache", "code cache", "gpucache", "shadercache", "dawncache",
    "dawn graphiteprogramcache", "dawn webgpu cache", "crashpad",
    "crash reports", "browsermetrics", "local traces", "component_crx_cache",
    "extensions_crx_cache", "logs", "log", "temp", "tmp",
})

# SQLite/journal/backup tails that still refer to the protected base name.
_NAME_TAIL_RE = re.compile(r"-(?:journal|wal|shm|old|bak)$")

# Numbered-copy names 'X (N)'. group(1) = base name, group(2) = copy number.
# Shared by the never-delete reducer and the portable numbered-copy sweeper
# (one canonical copy, H).
_NAME_NUMBERED_RE = re.compile(r"^(.+?) \((\d+)\)$")


def _name_variants(name_lower: str) -> list[str]:
    """Yield every mechanical variant of a name for never-delete matching.

    Reduces to a fixed point using ONLY the known mechanical suffix rules:
    numbered copies 'X (N)' and the -journal/-wal/-shm/-old/-bak tails. This
    composes correctly: 'cookies (2)-journal' -> 'cookies (2)' -> 'cookies'.
    No fuzzy/substring matching is ever applied (T-097).
    """
    out: set[str] = set()
    frontier = [name_lower.strip()]
    while frontier:
        current = frontier.pop()
        if not current or current in out:
            continue
        out.add(current)
        m = _NAME_NUMBERED_RE.match(current)
        if m:
            frontier.append(m.group(1).strip())
        tailed = _NAME_TAIL_RE.sub("", current)
        if tailed != current and tailed.strip():
            frontier.append(tailed.strip())
    return [v for v in sorted(out) if v]


CHROMIUM_PROFILE_DIRS = ["Cache", "Code Cache", "GPUCache", "DawnCache", "DawnGraphiteCache", "DawnWebGPUCache", "blob_storage", "VideoDecodeStats", "WebrtcVideoStats", "JumpListIconsMostVisited", "JumpListIconsRecentClosed", "CRXTelemetry"]

CHROMIUM_SW_SUBDIRS = ["CacheStorage", "ScriptCache"]

CHROMIUM_PROFILE_FILES = ["LOCK", "LOG", "LOG.old"]

CHROMIUM_USERDATA_DIRS = ["BrowserMetrics", "Local Traces", "Crashpad", "ShaderCache", "GrShaderCache", "GraphiteDawnCache", "component_crx_cache", "extensions_crx_cache"]

CHROMIUM_USERDATA_FILES = ["BrowserMetrics-spare.pma"]



#  HELPERS & SYSTEM DATA





# CORE-005/W2-001: cross-process destructive-job lease via Windows named mutex.
# Only one real-DELETE job can hold mutation rights at a time across GUI,
# background, CLI, and Task Scheduler processes. Dry-run/status are always
# allowed concurrently. The mutex name is stable per-installation (derived from
# CONFIG_FILE parent) so different machines don't collide. Release is automatic
# on process death; a zombie mutex from a crashed process is transparently
# acquired by the next process (Windows kernel releases it).
def _lease_mutex_name():
    return r"Global\SmartVACCleaner_DestructiveJob_e614c8c8-d876-4bac-9c7c-462f3516f7c0"


EXIT_LEASE_BUSY = 4


class JobBusyError(RuntimeError):
    pass


class _JobLease:
    """One product-wide Windows mutex, independent of deployment/config paths."""

    def __init__(self):
        self._mutex = None
        self._wait_ms = 0
        self.last_failure = None

    def acquire(self):
        if self._mutex is not None:
            return True
        self.last_failure = "api"
        if os.name != "nt":
            return False
        import ctypes
        from ctypes import wintypes

        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        create = kernel.CreateMutexW
        create.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
        create.restype = wintypes.HANDLE
        wait = kernel.WaitForSingleObject
        wait.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        wait.restype = wintypes.DWORD
        close = kernel.CloseHandle
        close.argtypes = [wintypes.HANDLE]
        close.restype = wintypes.BOOL
        handle = create(None, False, _lease_mutex_name())
        if not handle:
            return False
        result = wait(handle, self._wait_ms)
        if result in (0, 0x80):
            self._mutex = handle
            self.last_failure = None
            return True
        close(handle)
        if result == 258:
            self.last_failure = "busy"
        return False

    def release(self):
        handle, self._mutex = self._mutex, None
        if handle is None:
            return
        import ctypes
        from ctypes import wintypes

        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        release = kernel.ReleaseMutex
        release.argtypes = [wintypes.HANDLE]
        release.restype = wintypes.BOOL
        close = kernel.CloseHandle
        close.argtypes = [wintypes.HANDLE]
        close.restype = wintypes.BOOL
        try:
            if not release(handle):
                logging.getLogger("vac_cleaner").warning("Could not release destructive-job mutex")
        finally:
            if not close(handle):
                logging.getLogger("vac_cleaner").warning("Could not close destructive-job mutex handle")

    def __enter__(self):
        if not self.acquire():
            if self.last_failure == "busy":
                raise JobBusyError("Another destructive job holds the lease")
            raise RuntimeError("Destructive-job lease API unavailable")
        return self

    def __exit__(self, *exc):
        self.release()
        return False


def get_env_path(var_name: str, fallback: str) -> Path:

    """Resolve an env var to a canonical path, or the fallback.

    An EMPTY or missing env value uses the fallback -- never the cwd
    (markhunt F: Path('') is the current working directory). This is safe only
    for NON-destructive display purposes; destructive system roots MUST go
    through _resolve_env_root() (T-147).
    """

    val = os.environ.get(var_name) or fallback

    return Path(val).resolve()


# T-147: a dynamic environment value is NEVER a trusted system target. Every
# env-derived destructive root must pass provenance validation before it can
# receive the shallow system-target capability. Invalid/uncertain => None
# (target disabled), never a fallback to the cwd or to an arbitrary location.
def _is_under(ancestor: Path, child: Path) -> bool:
    try:
        child.relative_to(ancestor)
        return True
    except ValueError:
        return False


def _real_user_profile():
    if os.name == "nt":
        return _get_known_folder_win("{5E6C858F-0E22-4760-9AFE-EA3317B67173}")
    return Path.home().resolve()


def _resolve_env_root(var: str, expected: Path | None = None, exact: bool = False) -> Path | None:
    """Validate + resolve a destructive system-root env var (T-147).

    Returns a canonical absolute Path, or None when the value is unsafe:
      missing / empty / relative / drive-or-filesystem root / the cwd / inside
      the cleaner's own tree / outside the expected location class.
    None => the derived target is DISABLED, never redirected. `expected` is the
    location class the value must belong to (exact= must equal it); a missing
    expected class means the whole class is uncertain -> fail closed.
    """
    raw = os.environ.get(var)
    if not raw or not raw.strip():
        return None
    try:
        p = Path(raw.strip()).expanduser().resolve()
    except OSError:
        return None
    if not p.is_absolute():
        return None
    if len(p.parts) <= 1:
        return None  # drive root (C:\)
    try:
        if p == Path.cwd().resolve():
            return None  # arbitrary cwd is not a trusted root
    except OSError:
        return None
    if _is_under(BASE_DIR, p):
        return None  # cleaner's own directory tree
    if expected is None:
        return None  # expected location class unknown -> uncertain
    if exact:
        if p != expected:
            return None
    elif not _is_under(expected, p):
        return None  # wrong location class (poisoned to an arbitrary dir)
    return p


def _rooted(base: Path | None, *parts: str) -> Path | None:
    """Join a validated root with suffix parts; a None root stays None (disabled)."""
    if base is None:
        return None
    return base.joinpath(*parts)


def _resolve_temp_root() -> Path | None:
    """Validate the USER TEMP root (T-147).

    TEMP may legitimately live on another drive (e.g. V:\\_TEMP_), so unlike
    APPDATA/LOCALAPPDATA it is not required to sit under the user profile --
    but an arbitrary directory must never be accepted: the value must be an
    absolute, non-root, non-cwd, non-cleaner path that is EITHER under the
    user profile OR has a temp-like name. Anything else -> None (disabled).
    """
    raw = os.environ.get("TEMP")
    if not raw or not raw.strip():
        return None
    try:
        p = Path(raw.strip()).expanduser().resolve()
    except OSError:
        return None
    if not p.is_absolute() or len(p.parts) <= 1:
        return None
    try:
        if p == Path.cwd().resolve():
            return None
    except OSError:
        return None
    if _is_under(BASE_DIR, p):
        return None
    if sys.platform == "win32":
        trusted = _trusted_user_temp_win()
        if trusted is None:
            return None
        if p != trusted:
            return None
        return p
    profile = _real_user_profile()
    if profile is not None and _is_under(profile, p):
        return p
    base = p.name.lower()
    if base == "temp" or base == "tmp" or base.startswith("temp") or "_temp" in base or "temp_" in base:
        return p
    return None


def _resolve_active_drive_temp() -> Path | None:
    """Validate and resolve an active drive-level temp directory (e.g. V:\\_TEMP_).

    T-213: Discovers secondary or drive-level temp directories such as V:\\_TEMP_
    when configured in the environment or present at the repository/drive root.
    Must be an absolute, non-root, non-cwd, non-cleaner directory with a
    temp-like name.
    """
    for var in ("DRIVE_TEMP", "TEMP", "TMP"):
        raw = os.environ.get(var)
        if not raw or not raw.strip():
            continue
        try:
            p = Path(raw.strip()).expanduser().resolve()
        except OSError:
            continue
        if not p.is_absolute() or len(p.parts) <= 1:
            continue
        try:
            if p == Path.cwd().resolve():
                continue
        except OSError:
            continue
        if _is_under(BASE_DIR, p):
            continue
        base = p.name.lower()
        if (base in ("_temp_", "_temp", "temp_", "temp", "tmp") or "_temp" in base or "temp_" in base) and p.is_dir():
            return p
    try:
        drive = BASE_DIR.drive
        if drive:
            candidate = Path(f"{drive}\\_TEMP_").resolve()
            if candidate.is_dir() and not _is_under(BASE_DIR, candidate):
                return candidate
    except Exception:  # noqa: S110 - best effort candidate probe
        pass
    return None


_FOLDERID_LOCAL_APPDATA = "{F1B32785-6FBA-4FCF-9D55-7B8E7F157091}"
_FOLDERID_ROAMING_APPDATA = "{3EB685DB-65F9-4CF6-A03A-E3EF65729F3D}"


def _get_known_folder_win(folder_id_str: str) -> Path | None:
    if sys.platform != "win32":
        return None
    try:
        import ctypes
        import uuid
        from ctypes import wintypes
        class GUID(ctypes.Structure):
            _fields_ = [
                ("Data1", wintypes.DWORD),
                ("Data2", wintypes.WORD),
                ("Data3", wintypes.WORD),
                ("Data4", wintypes.BYTE * 8)
            ]
        u = uuid.UUID(folder_id_str)
        guid = GUID(u.time_low, u.time_mid, u.time_hi_version, (wintypes.BYTE * 8)(*u.bytes[8:]))
        p_path = wintypes.LPWSTR()
        res = ctypes.windll.shell32.SHGetKnownFolderPath(ctypes.byref(guid), 0, None, ctypes.byref(p_path))
        if res == 0 and p_path.value:
            path_val = p_path.value
            ctypes.windll.ole32.CoTaskMemFree(p_path)
            return Path(path_val).resolve()
    except Exception as exc:
        logging.getLogger("vac_cleaner").debug(f"SHGetKnownFolderPath error: {exc}")
    return None


def _get_windows_directory_win():
    if os.name != "nt":
        return None
    try:
        import ctypes
        from ctypes import wintypes
        function = ctypes.WinDLL("kernel32", use_last_error=True).GetWindowsDirectoryW
        function.argtypes = [wintypes.LPWSTR, wintypes.UINT]
        function.restype = wintypes.UINT
        buffer = ctypes.create_unicode_buffer(32768)
        length = function(buffer, len(buffer))
        if 0 < length < len(buffer):
            return Path(buffer.value).resolve()
    except (OSError, ValueError) as exc:
        logging.getLogger("vac_cleaner").warning(f"Windows-directory authority unavailable: {exc}")
    return None


def _trusted_user_temp_win() -> Path | None:
    local_app = _get_known_folder_win(_FOLDERID_LOCAL_APPDATA)
    if local_app is not None:
        return (local_app / "Temp").resolve()
    return None


_OS_LOCAL_APPDATA = _get_known_folder_win(_FOLDERID_LOCAL_APPDATA)
_OS_ROAMING_APPDATA = _get_known_folder_win(_FOLDERID_ROAMING_APPDATA)

_os_windir = _get_windows_directory_win()
SYSTEM_TEMP = _rooted(_os_windir, "Temp") if _os_windir else None

USER_TEMP = _resolve_temp_root()

_LOCALAPPDATA = _resolve_env_root("LOCALAPPDATA",
                                  _OS_LOCAL_APPDATA,
                                  exact=True)

_APPDATA = _resolve_env_root("APPDATA",
                             _OS_ROAMING_APPDATA,
                             exact=True)

USER_CRASH = _rooted(_LOCALAPPDATA, "CrashDumps")

USER_EXPLORER = _rooted(_LOCALAPPDATA, "Microsoft", "Windows", "Explorer")


# CORE-004: invalid env roots stay None end-to-end. A rejected root must NEVER
# become a relative cwd cleanup scope through a sentinel fallback.
# _LOCALAPPDATA and _APPDATA are either a validated absolute Path or None.


# Deep System & App Caches
# CORE-004: raw target definitions use path-tuple + description. Actual Path
# objects are built from validated roots; None bases produce no targets.
_RAW_APPDATA_TARGETS: list[tuple[tuple[str, ...], str, str]] = [
    (("NVIDIA", "GLCache"), "NVIDIA GL Cache", 'LOCAL'),
    (("NVIDIA", "DXCache"), "NVIDIA DX Cache", 'LOCAL'),
    (("D3DSCache",), "DirectX Shader Cache", 'LOCAL'),
    (("Steam", "htmlcache"), "Steam Web Cache", 'LOCAL'),
    (("Microsoft", "Windows", "INetCache"), "Windows INetCache", 'LOCAL'),
    (("discord", "Cache"), "Discord Cache", 'ROAMING'),
    (("discord", "Code Cache"), "Discord Code Cache", 'ROAMING'),
    # dev tool caches (LocalAppData)
    (("npm-cache",), "npm Cache", 'LOCAL'),
    (("uv", "cache"), "uv Cache", 'LOCAL'),
    (("pip", "cache"), "pip Cache", 'LOCAL'),
    (("Nuitka",), "Nuitka Cache", 'LOCAL'),
    (("node-gyp", "Cache"), "node-gyp Cache", 'LOCAL'),
    (("python", "Cache"), "python Cache", 'LOCAL'),
    (("Cypress", "Cache"), "Cypress Cache", 'LOCAL'),
    # app logs (Roaming)
    (("Maxon", "Logs"), "Maxon Logs", 'ROAMING'),
    (("Maxon", "Temp"), "Maxon Temp", 'ROAMING'),
    (("FreeFileSync", "Logs"), "FreeFileSync Logs", 'ROAMING'),
    (("obs-studio", "logs"), "obs-studio Logs", 'ROAMING'),
    (("Google", "DriveFS", "Logs"), "DriveFS Logs", 'LOCAL'),
    (("Mega Limited", "MEGAsync", "Logs"), "MEGAsync Logs", 'ROAMING'),
    (("discord", "Logs"), "discord Logs", 'ROAMING'),
    (("discord", "module_data", "crashlogs"), "discord Crash Logs", 'ROAMING'),
    (("Claude", "Logs"), "Claude Logs", 'ROAMING'),
    (("Listary", "UserProfile", "Cache"), "Listary Cache", 'ROAMING'),
    # Eagle
    (("Eagle", "eagle-temp"), "Eagle Temp", 'BOTH'),
    (("Eagle", "Cache"), "Eagle Cache", 'BOTH'),
    (("Eagle", "library-caches"), "Eagle Library Caches", 'BOTH'),
    (("Eagle", "Crashpad"), "Eagle Crashpad", 'BOTH'),
    # VS Code family
    (("Code", "CachedExtensionVSIXs"), "VS Code VSIX Cache", 'ROAMING'),
    (("Code", "Crashpad"), "VS Code Crashpad", 'ROAMING'),
    (("Code", "CachedData"), "VS Code CachedData", 'ROAMING'),
    (("Code", "Cache"), "VS Code Cache", 'ROAMING'),
    (("Antigravity", "CachedExtensionVSIXs"), "Antigravity VSIX Cache", 'ROAMING'),
    (("Antigravity", "Cache"), "Antigravity Cache", 'ROAMING'),
    (("Antigravity", "CachedData"), "Antigravity CachedData", 'ROAMING'),
    (("Claude", "Cache"), "Claude Cache", 'ROAMING'),
    (("Claude", "Code Cache"), "Claude Code Cache", 'ROAMING'),
    (("obsidian", "Cache"), "Obsidian Cache", 'ROAMING'),
    (("obsidian", "Code Cache"), "Obsidian Code Cache", 'ROAMING'),
    (("CELSYS", "promenade", "dbcache"), "CELSYS dbcache", 'BOTH'),
    (("EpicGamesLauncher", "Saved", "webcache_4430"), "Epic webcache", 'LOCAL'),
    (("AI Chatter", "Cache"), "AIChatter Cache", 'BOTH'),
    (("Programs", "DockerDesktop", "tmp-delete"), "Docker tmp-delete", 'BOTH'),
    # browsers (LocalAppData)
    (("Opera Software", "Opera Stable", "Default", "Cache"), "Opera Cache (C:)", 'LOCAL'),
    (("Opera Software", "Opera Stable", "Default", "Code Cache"), "Opera Code Cache (C:)", 'LOCAL'),
    (("Opera Software", "Opera Stable", "Default", "GrShaderCache"), "Opera Shader Cache (C:)", 'LOCAL'),
    (("Opera Software", "Opera Stable", "Default", "System Cache"), "Opera System Cache (C:)", 'LOCAL'),
    (("Opera Software", "Opera Stable", "Default", "Crash Reports"), "Opera Crash Reports (C:)", 'LOCAL'),
    (("Google", "Chrome", "User Data", "Default", "Cache"), "Chrome Cache (C:)", 'LOCAL'),
    (("Google", "Chrome", "User Data", "Default", "GrShaderCache"), "Chrome Shader Cache (C:)", 'LOCAL'),
    (("Microsoft", "Edge", "User Data", "Default", "Cache"), "Edge Cache (C:)", 'LOCAL'),
    (("Razer", "RazerAppEngine", "Cache"), "Razer Cache", 'LOCAL'),
    (("Razer", "RazerAppEngine", "Code Cache"), "Razer Code Cache", 'LOCAL'),
    (("Razer", "RazerAppEngine", "Service Worker", "CacheStorage"), "Razer SW CacheStorage", 'LOCAL'),
    (("electron", "Cache"), "Electron Cache", 'BOTH'),
    (("Telegram Desktop", "tdata", "user_data", "cache"), "Telegram Cache (C:)", 'ROAMING'),
    (("ollama app.exe", "EBWebView", "Default", "Cache"), "Ollama WebView Cache", 'BOTH'),
    (("MaxonApp", "UserData", "EBWebView", "Default", "Cache"), "Maxon WebView Cache", 'BOTH'),
    (("Photoshop1-25-WIN", "EBWebView", "Default", "Cache"), "Photoshop WebView Cache", 'BOTH'),
    # Brave browser (LocalAppData)
    (("BraveSoftware", "Brave-Browser", "User Data", "Default", "Cache"), "Brave Cache", 'LOCAL'),
    (("BraveSoftware", "Brave-Browser", "User Data", "Default", "Code Cache"), "Brave Code Cache", 'LOCAL'),
    (("BraveSoftware", "Brave-Browser", "User Data", "Default", "GPUCache"), "Brave GPU Cache", 'LOCAL'),
    # Code Cache for Chrome/Edge (Cache already covered)
    (("Google", "Chrome", "User Data", "Default", "Code Cache"), "Chrome Code Cache", 'LOCAL'),
    (("Microsoft", "Edge", "User Data", "Default", "Code Cache"), "Edge Code Cache", 'LOCAL'),
    # misc safe caches / logs
    (("calibre-cache",), "Calibre Cache", 'LOCAL'),
    (("fontconfig",), "fontconfig Cache", 'LOCAL'),
    (("qBittorrent", "logs"), "qBittorrent Logs", 'BOTH'),
    (("claude-cli-nodejs", "Cache"), "Claude CLI Cache", 'BOTH'),
    # New findings (v2.4.8)
    (("Mega Limited", "MEGAsync", "logs"), "MEGAsync Logs (Local)", 'LOCAL'),
    (("Devin", "Cache"), "Devin Cache", 'BOTH'),
    (("Devin", "CachedData"), "Devin CachedData", 'BOTH'),
    (("FontBase", "Cache"), "FontBase Cache", 'BOTH'),
    (("Bridge", "Cache"), "Adobe Bridge Cache", 'BOTH'),
    (("AIChatter", "AI Chatter", "cache"), "AIChatter Cache", 'BOTH'),
    (("Autokroma", "Influx", "Cache"), "Autokroma Influx Cache", 'BOTH'),
    (("Adobe", "Adobe Substance 3D Sampler", "thumbnailCache"), "Substance 3D Thumbnail Cache", 'BOTH'),
    (("BlueStacks X", "cache"), "BlueStacks X Cache", 'BOTH'),
    (("@neuralnomads", "codenomad-electron-app", "session-data-v2", "Cache"), "CodeNomad Cache", 'BOTH'),
    (("MAXON", "_assetcache"), "Maxon Asset Cache", 'BOTH'),
    (("Mailbird", "Misc", "component_crx_cache"), "Mailbird CRX Cache", 'BOTH'),
    (("Opera Software", "Opera Stable", "component_crx_cache"), "Opera CRX Cache", 'ROAMING'),
    (("BraveSoftware", "Brave-Browser", "User Data", "component_crx_cache"), "Brave CRX Cache", 'LOCAL'),
    (("discord", "component_crx_cache"), "Discord CRX Cache", 'ROAMING'),
    # New findings (v2.4.9)
    (("Devin", "GPUCache"), "Devin GPUCache", 'BOTH'),
    (("Devin", "logs"), "Devin Logs", 'BOTH'),
    (("Devin", "cli", "logs"), "Devin CLI Logs", 'BOTH'),
    (("Claude", "GPUCache"), "Claude GPUCache", 'ROAMING'),
    (("Antigravity", "GPUCache"), "Antigravity GPUCache", 'ROAMING'),
    (("Antigravity", "logs"), "Antigravity Logs", 'ROAMING'),
    (("@neuralnomads", "codenomad-electron-app", "session-data-v2", "Code Cache"), "CodeNomad Code Cache", 'BOTH'),
    (("@neuralnomads", "codenomad-electron-app", "session-data-v2", "GPUCache"), "CodeNomad GPUCache", 'BOTH'),
    (("ollama app.exe", "EBWebView", "Default", "GPUCache"), "Ollama GPUCache", 'BOTH'),
    (("LM Studio", "GPUCache"), "LM Studio GPUCache", 'BOTH'),
    (("Adobe", "Adobe Substance 3D Painter", "cache"), "Substance 3D Painter Cache", 'BOTH'),
    (("Adobe", "Adobe Substance 3D Sampler", "cache"), "Substance 3D Sampler Cache", 'BOTH'),
    (("CELSYS", "CLIPStudioPaint", "1.5.0", "CacheData"), "CLIP Studio Paint Cache", 'BOTH'),
    (("Reallusion", "ActorCore AccuRIG", "Cache"), "AccuRIG Cache", 'BOTH'),
    (("Reallusion", "ActorCore AccuRIG", "Code Cache"), "AccuRIG Code Cache", 'BOTH'),
    (("Reallusion", "Character Creator", "5.0", "cache"), "Character Creator Cache", 'BOTH'),
    (("LosslessCut", "Cache"), "LosslessCut Cache", 'BOTH'),
    (("LosslessCut", "GPUCache"), "LosslessCut GPUCache", 'BOTH'),
    (("Topaz Labs LLC", "Topaz Video", "cache"), "Topaz Video Cache", 'BOTH'),
    (("Topaz Labs LLC", "Topaz Video AI", "cache"), "Topaz Video AI Cache", 'BOTH'),
    (("UnrealEngine", "5.6", "DerivedDataCache"), "Unreal Engine 5.6 DDCache", 'BOTH'),
    (("omniroute-desktop", "Cache"), "Omniroute Cache", 'BOTH'),
    (("omniroute-desktop", "Code Cache"), "Omniroute Code Cache", 'BOTH'),
    (("omniroute-desktop", "GPUCache"), "Omniroute GPUCache", 'BOTH'),
    (("omniroute-desktop", "Service Worker", "CacheStorage"), "Omniroute SW CacheStorage", 'BOTH'),
    (("stem-studio", "Cache"), "Stem Studio Cache", 'BOTH'),
    (("stem-studio", "GPUCache"), "Stem Studio GPUCache", 'BOTH'),
    (("QuiteRss", "QuiteRss", "cache"), "QuiteRss Cache", 'BOTH'),
    (("com.dropdead.app", "EBWebView", "Default", "Cache"), "Dropdead WebView Cache", 'BOTH'),
    (("DeskChat", "DeskChat", "cache"), "DeskChat Cache", 'BOTH'),
    (("DeskChat Dump", "cache"), "DeskChat Dump Cache", 'BOTH'),
    (("HD-Player", "cache"), "HD-Player Cache", 'BOTH'),
    (("JangaFX", "liquigen", "gl-cache"), "Liquigen GL Cache", 'BOTH'),
    (("Krisp", "Logs"), "Krisp Logs", 'BOTH'),
    (("Mailbird", "Misc", "Default", "Cache"), "Mailbird Cache", 'BOTH'),
    (("SiYuan-Electron", "GPUCache"), "SiYuan GPUCache", 'BOTH'),
    (("BetterDiscord Installer", "Cache"), "BetterDiscord Cache", 'BOTH'),
    (("BorisFX", "BorisFX Direct", "Cache"), "BorisFX Direct Cache", 'BOTH'),
    # New findings (v2.4.10)
    (("Google", "DriveFS", "Logs"), "DriveFS Logs (Local)", 'LOCAL'),
    (("Razer", "RazerAppEngine", "User Data", "Default", "Cache"), "Razer Engine Cache", 'LOCAL'),
    (("Razer", "RazerAppEngine", "User Data", "Default", "Code Cache"), "Razer Engine Code Cache", 'LOCAL'),
    (("Razer", "RazerAppEngine", "User Data", "Default", "GPUCache"), "Razer Engine GPUCache", 'LOCAL'),
    (("EpicGamesLauncher", "Saved", "webcache_4430"), "Epic webcache (Local)", 'LOCAL'),
    (("Code", "WebStorage", "2", "CacheStorage"), "VS Code WebStorage Cache", 'ROAMING'),
    (("Code", "WebStorage", "3", "CacheStorage"), "VS Code WebStorage Cache (2)", 'ROAMING'),
    (("com.verifiedskill.desktop", "EBWebView", "component_crx_cache"), "VerifiedSkill CRX Cache", 'BOTH'),
    (("MaxonApp", "UserData", "EBWebView", "Default", "Cache"), "MaxonApp WebView Cache", 'BOTH'),
    (("MaxonApp", "UserData", "EBWebView", "Default", "Code Cache"), "MaxonApp WebView Code Cache", 'BOTH'),
    (("MaxonApp", "UserData", "EBWebView", "Default", "GrShaderCache"), "MaxonApp WebView Shader Cache", 'BOTH'),
    (("Adobe", "Adobe Photoshop 2024", "Logs"), "Photoshop 2024 Logs", 'BOTH'),
    (("obsidian", "GPUCache"), "Obsidian GPUCache", 'ROAMING'),
    # New findings (v2.4.14)
    (("Packages", "Microsoft.Windows.Search_cw5n1h2txyewy", "LocalState", "DeviceSearchCache"), "Windows Search DeviceSearchCache", 'LOCAL'),
    (("Packages", "Microsoft.Windows.Search_cw5n1h2txyewy", "LocalState", "AppIconCache"), "Windows Search AppIconCache", 'LOCAL'),
    (("iTop Easy Desktop", "Thumb"), "iTop Easy Desktop Thumbs", 'BOTH'),
    (("Freebuff", "Cache"), "Freebuff Cache", 'BOTH'),
    (("Photoshop1-25-WIN", "EBWebView", "Default", "Cache"), "Photoshop WebView Cache (Local)", 'LOCAL'),
    (("Bridge", "Code Cache"), "Adobe Bridge Code Cache", 'BOTH'),
    (("Bridge", "GPUCache"), "Adobe Bridge GPUCache", 'BOTH'),
    (("ollama app.exe", "EBWebView", "GrShaderCache"), "Ollama Shader Cache", 'BOTH'),
    (("AIChatter", "profiles", "edge", "chatgpt", "Default", "Cache"), "AIChatter Edge Profile Cache", 'BOTH'),
    (("Telegram Desktop", "tdata", "user_data", "media_cache"), "Telegram Media Cache (C:)", 'ROAMING'),
    (("Opera Software", "Opera Stable", "Service Worker", "CacheStorage"), "Opera SW CacheStorage", 'ROAMING'),
    (("Opera Software", "Opera Stable", "Service Worker", "ScriptCache"), "Opera SW ScriptCache", 'ROAMING'),
]

# CORE-004: build live target list from validated roots. None bases -> no targets.
_user_targets_raw: list = []
# Single-root entries stay in their reviewed namespace. Legacy definitions
# supporting both namespaces retain explicit BOTH compatibility.
for _base, _provenance in ((_LOCALAPPDATA, "LOCAL"), (_APPDATA, "ROAMING")):
    if _base is not None:
        for parts, desc, provenance in _RAW_APPDATA_TARGETS:
            if provenance in (_provenance, "BOTH"):
                _user_targets_raw.append((_base.joinpath(*parts), desc))

# Deduplicate by resolved path
_seen: set[str] = set()
_user_targets_deduped: list = []
for p, d in _user_targets_raw:
    key = str(p.resolve()) if p is not None else ""
    if key and key not in _seen:
        _seen.add(key)
        _user_targets_deduped.append((p, d))
del _seen, _user_targets_raw
USER_APPDATA_TARGETS = _user_targets_deduped
del _user_targets_deduped


# Process owners for app-sensitive targets (P1-9): if the owning app is running
# (or the process table is UNKNOWN), the target is skipped.
# T-092: every USER_APPDATA_TARGETS entry must either have an owner in
# APP_PROCESSES or be explicitly listed as PROCESS_AGNOSTIC. There is no
# implicit owner=None escape hatch.
PROCESS_AGNOSTIC_TARGETS: frozenset = frozenset({
    # shared system / driver caches (regenerated by the OS, no single owner)
    "NVIDIA GL Cache", "NVIDIA DX Cache", "DirectX Shader Cache",
    "Windows INetCache",
    "Windows Search DeviceSearchCache", "Windows Search AppIconCache",
    # shared package/compiler caches (regenerated by tooling, no running app)
    "npm Cache", "uv Cache", "pip Cache", "Nuitka Cache", "node-gyp Cache",
    "python Cache", "Cypress Cache", "fontconfig Cache",
    # shared Electron framework cache (owned by whichever app uses the runtime)
    "Electron Cache",
})

_TARGET_APP_GROUPS: dict[str, str | None] = {
    "Discord Cache": "discord", "Discord Code Cache": "discord", "discord Logs": "discord",
    "discord Crash Logs": "discord", "Discord CRX Cache": "discord",
    "Chrome Cache (C:)": "chrome", "Chrome Shader Cache (C:)": "chrome", "Chrome Code Cache": "chrome",
    "Edge Cache (C:)": "edge", "Edge Code Cache": "edge",
    "Opera Cache (C:)": "opera", "Opera Code Cache (C:)": "opera", "Opera Shader Cache (C:)": "opera",
    "Opera System Cache (C:)": "opera", "Opera Crash Reports (C:)": "opera", "Opera CRX Cache": "opera",
    "Opera SW CacheStorage": "opera", "Opera SW ScriptCache": "opera",
    "Brave Cache": "brave", "Brave Code Cache": "brave", "Brave GPU Cache": "brave", "Brave CRX Cache": "brave",
    "Telegram Cache (C:)": "telegram", "Telegram Media Cache (C:)": "telegram",
    "Razer Cache": "razer", "Razer Code Cache": "razer", "Razer SW CacheStorage": "razer",
    "Razer Engine Cache": "razer", "Razer Engine Code Cache": "razer", "Razer Engine GPUCache": "razer",
    "Ollama WebView Cache": "ollama", "Ollama GPUCache": "ollama", "Ollama Shader Cache": "ollama",
    "Maxon WebView Cache": "maxonapp", "MaxonApp WebView Cache": "maxonapp",
    "MaxonApp WebView Code Cache": "maxonapp", "MaxonApp WebView Shader Cache": "maxonapp",
    "Photoshop WebView Cache": "photoshop", "Photoshop WebView Cache (Local)": "photoshop",
    "Epic webcache": "epic", "Epic webcache (Local)": "epic",
    "VS Code VSIX Cache": "code", "VS Code Crashpad": "code", "VS Code CachedData": "code",
    "VS Code Cache": "code", "VS Code WebStorage Cache": "code", "VS Code WebStorage Cache (2)": "code",
    "Claude Logs": "claude", "Claude Cache": "claude", "Claude Code Cache": "claude", "Claude GPUCache": "claude",
    "Claude CLI Cache": "claude",
    "qBittorrent Logs": "qbittorrent",
    "MEGAsync Logs": "megasync", "MEGAsync Logs (Local)": "megasync",
    "DriveFS Logs": "drivefs", "DriveFS Logs (Local)": "drivefs",
    "obs-studio Logs": "obs",
    "Listary Cache": "listary",
    "Eagle Temp": "eagle", "Eagle Cache": "eagle", "Eagle Library Caches": "eagle", "Eagle Crashpad": "eagle",
    "Adobe Bridge Cache": "bridge", "Adobe Bridge Code Cache": "bridge", "Adobe Bridge GPUCache": "bridge",
    "FreeFileSync Logs": "freefilesync",
    # T-092 verified owners (exe names confirmed from installed applications)
    "Steam Web Cache": "steam",
    "Docker tmp-delete": "docker",
    "Antigravity VSIX Cache": "antigravity", "Antigravity Cache": "antigravity",
    "Antigravity CachedData": "antigravity", "Antigravity GPUCache": "antigravity",
    "Antigravity Logs": "antigravity",
    "Obsidian Cache": "obsidian", "Obsidian Code Cache": "obsidian", "Obsidian GPUCache": "obsidian",
    "Maxon Logs": "maxon", "Maxon Temp": "maxon", "Maxon Asset Cache": "maxon",
    "AIChatter Cache": "aichatter", "AIChatter Edge Profile Cache": "aichatter",
    "CodeNomad Cache": "codenomad", "CodeNomad Code Cache": "codenomad", "CodeNomad GPUCache": "codenomad",
    "Devin Cache": "devin", "Devin CachedData": "devin", "Devin GPUCache": "devin",
    "Devin Logs": "devin", "Devin CLI Logs": "devin",
    "Calibre Cache": "calibre",
    "QuiteRss Cache": "quiterss",
    "Freebuff Cache": "freebuff",
    "LM Studio GPUCache": "lmstudio",
    "LosslessCut Cache": "losslesscut", "LosslessCut GPUCache": "losslesscut",
    "Topaz Video Cache": "topaz", "Topaz Video AI Cache": "topaz",
    "BlueStacks X Cache": "bluestacks",
    "HD-Player Cache": "hdplayer",
    "Omniroute Cache": "omniroute", "Omniroute Code Cache": "omniroute",
    "Omniroute GPUCache": "omniroute", "Omniroute SW CacheStorage": "omniroute",
    "Stem Studio Cache": "stemstudio", "Stem Studio GPUCache": "stemstudio",
    "DeskChat Cache": "deskchat", "DeskChat Dump Cache": "deskchat",
    "Dropdead WebView Cache": "dropdead",
    "VerifiedSkill CRX Cache": "verifiedskill",
    "BorisFX Direct Cache": "borisfx",
    "BetterDiscord Cache": "betterdiscord",
    "Liquigen GL Cache": "jangafx",
    "Krisp Logs": "krisp",
    "FontBase Cache": "fontbase",
    "Autokroma Influx Cache": "influx",
    "iTop Easy Desktop Thumbs": "itop",
    "CLIP Studio Paint Cache": "clipstudio",
    "Character Creator Cache": "charactercreator",
    "AccuRIG Cache": "accu rig", "AccuRIG Code Cache": "accu rig",
    "Unreal Engine 5.6 DDCache": "unreal",
    "SiYuan GPUCache": "siyuan",
    "Photoshop 2024 Logs": "photoshop",
    "Mailbird Cache": "mailbird", "Mailbird CRX Cache": "mailbird",
    "CELSYS dbcache": "clipstudio",
    "Substance 3D Thumbnail Cache": "substance",
    "Substance 3D Painter Cache": "substance",
    "Substance 3D Sampler Cache": "substance",
}

# CORE-004/T-147: entries whose base env root failed provenance validation are
# dropped -- a poisoned APPDATA/LOCALAPPDATA can never turn a reviewed cache
# suffix into a live destructive target. A None base means the entire target
# subtree is excluded; no sentinel-path workaround exists.
USER_APPDATA_TARGETS = [
    (p, d, _TARGET_APP_GROUPS.get(d) or (PROCESS_AGNOSTIC if d in PROCESS_AGNOSTIC_TARGETS else None)) for p, d, *_ in USER_APPDATA_TARGETS
    if p is not None and (
        (_LOCALAPPDATA is not None and not _is_under(_LOCALAPPDATA, p)) or
        (_APPDATA is not None and not _is_under(_APPDATA, p)) or
        True  # p is not under either validated base but is still a valid path
    )
]

def _enumerate_processes_win():
    if os.name != "nt":
        return None
    import ctypes
    from ctypes import wintypes

    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
                    ("th32ProcessID", wintypes.DWORD), ("th32DefaultHeapID", ctypes.c_size_t),
                    ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
                    ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", wintypes.LONG),
                    ("dwFlags", wintypes.DWORD), ("szExeFile", wintypes.WCHAR * 260)]
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    create = kernel.CreateToolhelp32Snapshot
    create.argtypes, create.restype = [wintypes.DWORD, wintypes.DWORD], wintypes.HANDLE
    first, following = kernel.Process32FirstW, kernel.Process32NextW
    for function in (first, following):
        function.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
        function.restype = wintypes.BOOL
    close = kernel.CloseHandle
    close.argtypes, close.restype = [wintypes.HANDLE], wintypes.BOOL
    handle = create(2, 0)
    if handle == ctypes.c_void_p(-1).value:
        return None
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(entry)
        if not first(handle, ctypes.byref(entry)):
            return set() if ctypes.get_last_error() == 18 else None
        names = set()
        while True:
            if entry.szExeFile:
                names.add(entry.szExeFile.lower())
            if not following(handle, ctypes.byref(entry)):
                return names if ctypes.get_last_error() == 18 else None
    finally:
        close(handle)


def get_running_processes() -> set[str] | None:
    """Query running process image names.

    Returns a set of lowercased image names, or None when the query FAILED
    (tasklist nonzero exit, timeout, parse error). Callers must treat None as
    UNKNOWN and skip app-sensitive work (fail closed), never as 'nothing runs'.

    PERF-002: on Windows uses Toolhelp32Snapshot (no subprocess); falls back
    to subprocess.tasklist on other platforms or when the native call fails.
    """
    if os.name == "nt":
        procs = _enumerate_processes_win()
        if procs is not None:
            return procs
        # Native call failed; fall through to subprocess as last resort.
        logging.getLogger("vac_cleaner").warning("Toolhelp32Snapshot failed; falling back to tasklist")

    try:
        result = subprocess.run(["tasklist", "/fo", "csv", "/nh"], capture_output=True, text=True, timeout=15, check=False)
        if result.returncode != 0:
            logging.getLogger("vac_cleaner").error(f"tasklist exited with code {result.returncode}")
            return None
        procs: set[str] = set()
        for row in csv.reader(result.stdout.splitlines()):
            if not row:
                continue
            pname = row[0].strip().replace('"', "").lower()
            if pname:
                procs.add(pname)
        return procs
    except Exception as e:
        logging.getLogger("vac_cleaner").error(f"Failed to query running processes: {e}")
        return None


def is_app_running(app_group: str, running: set[str] | None) -> bool:
    """True when any process of `app_group` is running.

    `running` is None (UNKNOWN) when process detection failed. A real process
    group with an UNKNOWN snapshot is treated as running (fail closed); the
    empty 'general' group carries no process mapping and never blocks.
    """
    procs = APP_PROCESSES.get(app_group, set())
    if not procs:
        return False
    if running is None:
        return True
    return bool(procs & running)


def _owner_trust(app_group: str) -> str:
    """T-130: 'verified' or 'unverified' trust for a process group.

    Trust is decided by EVIDENCE, not by the presence of a provenance entry:
      VERIFIED  - verified:disk, verified:runtimelog, or an independently
                  justified product:exe mapping.
      UNVERIFIED - unverified-exe (mapping kept but not confirmed) or any
                  group with NO provenance.
    A group with no process mapping (e.g. PROCESS_AGNOSTIC) is trivially verified:
    there is nothing running to guard against. An UNVERIFIED owner can never
    authorize a real deletion of an app-sensitive target (fail closed); it may
    only appear in DISCOVERED / NOT AUTHORIZED reporting.
    """
    if app_group == PROCESS_AGNOSTIC:
        return "verified"
    if app_group not in APP_PROCESSES:
        return "unverified"
    prov = APP_PROCESSES_PROVENANCE.get(app_group, "")
    if prov.startswith(("verified:", "product:")):
        return "verified"
    return "unverified"


def is_link(path: Path) -> bool:
    """True for symlinks and (on Windows) junctions/reparse points."""
    try:
        st = path.lstat()
    except OSError:
        return False
    if stat.S_ISLNK(st.st_mode):
        return True
    if os.name == "nt":
        return bool(getattr(st, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT)
    return False


# CORE-002: a configured cleanup root that is itself a symlink/junction or
# contains a reparse component must be refused BEFORE any resolve happens.
# Resolving first destroys the evidence and transfers cleanup authority to the
# destination while downstream code sees only an ordinary canonical path.
def _has_link_or_reparse_component(raw: str) -> bool:
    """True when any EXISTING path component is a symlink/junction/reparse.

    Walks the absolute path component-by-component using lstat (no follow).
    Non-existent components are skipped. Returns False when the path does not
    exist at all (caller handles that).
    """
    try:
        absolute = Path(raw).expanduser().absolute()
    except OSError:
        return False
    parts = list(absolute.parts)
    # Windows: parts[0] is the drive letter (e.g. 'V:'); skip it.
    start = 1 if parts and len(parts[0]) == 1 and parts[0].endswith(":") else 0
    cursor = Path(parts[0]) if start else Path()
    for part in parts[start:]:
        candidate = cursor / part
        try:
            st = candidate.lstat()
        except OSError:
            return False  # component missing: stop checking
        mode = st.st_mode
        if stat.S_ISLNK(mode):
            return True
        if os.name == "nt":
            attrs = int(getattr(st, "st_file_attributes", 0))
            if attrs & stat.FILE_ATTRIBUTE_REPARSE_POINT:
                return True
        cursor = candidate
    return False


# F1: object identity for TOCTOU defence. A path being present at plan time is
# NOT permission forever -- between planning and mutation the object at that
# path may be replaced (file swap, dir swap, symlink/junction introduction).
# Every mutation candidate carries the identity captured during planning, and
# the mutation chokepoint re-proves the object is still the SAME object.
def _identity_from_stat(observed):
    attrs = int(getattr(observed, "st_file_attributes", 0))
    if stat.S_ISLNK(observed.st_mode) or (os.name == "nt" and attrs & stat.FILE_ATTRIBUTE_REPARSE_POINT):
        return {"type": "link_or_reparse"}
    if not (stat.S_ISREG(observed.st_mode) or stat.S_ISDIR(observed.st_mode)):
        return None
    kind = "dir" if stat.S_ISDIR(observed.st_mode) else "file"
    identity = {"type": kind, "attrs": attrs, "ctime_ns": int(observed.st_ctime_ns)}
    if observed.st_ino and observed.st_dev:
        identity.update(dev=int(observed.st_dev), ino=int(observed.st_ino))
    if kind == "file":
        identity.update(size=int(observed.st_size), mtime_ns=int(observed.st_mtime_ns))
    return identity


def _capture_identity(path):
    try:
        return _identity_from_stat(path.lstat())
    except OSError:
        return None


def _identity_matches(planned: dict | None, current: dict | None, ignore_attrs: bool = False) -> bool:
    """True ONLY when `current` provably describes the same object as `planned`.

    Inode identity wins when both sides carry one. If exactly one side has an
    inode the state is UNCERTAIN -> False (fail closed; never assume path
    equality means object equality). Without inodes a conservative fingerprint
    (size + mtime + ctime + attrs) is compared; ANY mismatch refuses. A
    missing side always refuses.

    `ignore_attrs` (T-137) is reserved for the cleaner's OWN attribute
    mutation: after we chmod away read-only, only the attrs differ from the
    plan, so the re-baseline check must ignore that one field while every
    mutation-stable field (dev/ino/ctime/size/mtime) still must match.
    """
    if not planned or not current:
        return False
    if planned.get("type") != current.get("type"):
        return False
    if planned.get("type") == "link_or_reparse":
        return False
    p_ino, c_ino = planned.get("ino"), current.get("ino")
    if p_ino and c_ino:
        # CORE-001: inode reuse defeats TOCTOU when only dev+ino is checked.
        # A deleted+recreated object can inherit the same dev+ino but carry
        # completely different content. Require fingerprint match too.
        if planned.get("dev") != current.get("dev") or p_ino != c_ino:
            return False
        for key in ("size", "mtime_ns", "ctime_ns"):
            if planned.get(key) != current.get(key):
                return False
        return planned.get("attrs") == current.get("attrs") or ignore_attrs
    if p_ino or c_ino:
        return False
    for key in ("size", "mtime_ns", "ctime_ns", "attrs"):
        if ignore_attrs and key == "attrs":
            continue
        if planned.get(key) != current.get(key):
            return False
    return True


class MutationResult:
    """Structured outcome of one filesystem mutation (F7).

    `success` is deliberately separate from `bytes_freed`: a successfully
    deleted empty file is success=True with bytes=0, and a zero result must
    never be mistaken for a failure (nor a failure for a zero-byte success).
    `reason` carries the skip/failure cause when success is False.
    """

    __slots__ = ("bytes_freed", "reason", "success")

    def __init__(self, success: bool, bytes_freed: int = 0, reason: str = ""):
        self.success = bool(success)
        self.bytes_freed = int(bytes_freed)
        self.reason = reason


BYTES_PER_MB = 1_048_576

BYTES_PER_GB = 1_073_741_824


def fmt(n: int) -> str:

    if n >= BYTES_PER_GB: return f"{n/BYTES_PER_GB:.2f} GB"

    if n >= BYTES_PER_MB: return f"{n/BYTES_PER_MB:.1f} MB"

    if n >= 1_024: return f"{n/1_024:.0f} KB"

    return f"{n} B"



#  LOGGER



class _GuiLogMessage(str):
    """Keep display text compatible with callbacks while carrying severity."""

    def __new__(cls, text, kind="ordinary"):
        message = super().__new__(cls, text)
        message.kind = kind
        return message


class _GuiLogBuffer:
    """Nonblocking, bounded channels; ordinary traffic cannot evict failures."""

    def __init__(self, maxsize=8192, protected_size=1024):
        self.maxsize = maxsize or 8192
        self._ordinary = deque(maxlen=self.maxsize)
        self._protected = deque(maxlen=protected_size)
        self._controls = deque()
        self._overflow = 0
        self._lock = threading.Lock()

    def put_nowait(self, message):
        kind = getattr(message, "kind", "ordinary")
        with self._lock:
            if kind == "control" and message in ("__AUTO_CLEAN__", "__CLOSE__"):
                if message not in self._controls:
                    self._controls.append(message)
            elif kind in {"error", "warning", "summary", "control"}:
                if len(self._protected) == self._protected.maxlen:
                    self._overflow += 1
                self._protected.append(message)
            else:
                self._ordinary.append(message)

    def put(self, message, block=True, timeout=None):
        self.put_nowait(message)

    def get_nowait(self):
        with self._lock:
            if self._controls:
                return self._controls.popleft()
            if self._overflow:
                count, self._overflow = self._overflow, 0
                return _GuiLogMessage(
                    f"[WARNING] {count} earlier critical log messages were coalesced.",
                    "warning",
                )
            if self._protected:
                return self._protected.popleft()
            if self._ordinary:
                return self._ordinary.popleft()
            raise queue.Empty

    def qsize(self):
        with self._lock:
            return len(self._ordinary) + len(self._protected) + len(self._controls) + bool(self._overflow)

    def empty(self):
        return self.qsize() == 0


_LOGGER_INSTANCES: "weakref.WeakValueDictionary[int, Logger]" = weakref.WeakValueDictionary()
_LOGGER_REGISTRY_LOCK = threading.Lock()
_LOGGER_OWNER_COUNTER = itertools.count(1)
_OWNER_ATTR = "vac_logger_owner"
_DIAGNOSTIC_OWNER = None


def _vac_safe_call_handlers(logger: logging.Logger, record: logging.LogRecord) -> None:
    c = logger
    while c:
        for hdlr in list(c.handlers):
            if record.levelno >= hdlr.level and hdlr.filter(record):
                hdlr.emit(record)
        if not c.propagate:
            break
        c = c.parent


def _ensure_concurrent_safe_logger(logger: logging.Logger) -> None:
    if not getattr(logger, "_vac_concurrent_safe", False):
        def callHandlers(record: logging.LogRecord) -> None:
            _vac_safe_call_handlers(logger, record)

        logger.callHandlers = callHandlers  # type: ignore[assignment]
        logger._vac_concurrent_safe = True  # type: ignore[attr-defined]


class _InstanceScopedFilter:
    """T-212: route shared-logger records to their instance's own handlers.

    A record carries the instance marker only when emitted through that
    Logger's adapter. Module diagnostics (logged directly on the shared logger
    by retention/pruning helpers) carry no marker and are allowed through every
    active instance's file handler, so run logs keep those warnings; console
    handlers reject markerless records and stay one-line-per-message.
    """

    __slots__ = ("_console", "_owner")

    def __init__(self, owner, console: bool):
        self._owner = owner
        self._console = console

    def filter(self, record) -> bool:
        owner = getattr(record, _OWNER_ATTR, _DIAGNOSTIC_OWNER)
        if self._console:
            return owner is self._owner
        return owner is self._owner or owner is _DIAGNOSTIC_OWNER


class _InstanceLoggerAdapter(logging.LoggerAdapter):
    """Stamps every emitted record with the constructing instance's marker."""

    def process(self, msg, kwargs):
        extra = kwargs.get("extra")
        if extra is None:
            extra = {}
            kwargs["extra"] = extra
        extra.setdefault(_OWNER_ATTR, self.extra[_OWNER_ATTR])
        return msg, kwargs

    @property
    def handlers(self):
        return self.logger.handlers


def _register_logger(logger: "Logger") -> None:
    with _LOGGER_REGISTRY_LOCK:
        _LOGGER_INSTANCES[logger._owner] = logger


def _unregister_logger(logger: "Logger") -> None:
    with _LOGGER_REGISTRY_LOCK:
        if _LOGGER_INSTANCES.get(logger._owner) is logger:
            del _LOGGER_INSTANCES[logger._owner]


class Logger:

    @staticmethod
    def enable_recorder() -> None:
        """PERF-006: enable path recording for tests that need candidate truth."""
        Logger._recorder_enabled = True

    _recorder_enabled = False

    def __init__(self, log_file: Path | None, dry_run: bool, gui_callback=None, quiet: bool = False):

        self.dry_run = dry_run

        self.log_file = log_file

        self.bytes_freed = 0

        self.n_deleted = 0

        self.n_skipped = 0

        self.n_errors = 0

        self.gui_callback = gui_callback

        self.quiet = quiet

        # F4: candidate truth recorder. Opt-in only — disabled by default for
        # production Logger (avoids retaining O(N) path strings). Tests that need
        # candidate truth call Logger.enable_recorder() before constructing the
        # Logger, or set self.deleted_paths = [] directly.
        if Logger._recorder_enabled:
            self.deleted_paths: list[str] = []
            Logger._recorder_enabled = False
        else:
            self.deleted_paths = None

        self.lock = threading.Lock()

        # T-212: each Logger owns its handlers. All instances share the
        # "vac_cleaner" logger (module diagnostics still route there), but a
        # record only reaches its own instance's file handler, so constructing
        # one Logger can never close, silence, or cross-feed a live one.
        self._handlers: list[logging.Handler] = []
        self._closed = False
        self._owner = next(_LOGGER_OWNER_COUNTER)

        self._shared = logging.getLogger("vac_cleaner")
        _ensure_concurrent_safe_logger(self._shared)
        self._shared.setLevel(logging.DEBUG)

        self._log = _InstanceLoggerAdapter(self._shared, {_OWNER_ATTR: self._owner})
        _register_logger(self)

        if not self.quiet:
            # Owned console handler; a quiet collector never installs one and
            # never removes another instance's.
            ch = logging.StreamHandler(stream=sys.stdout)
            ch.setLevel(logging.INFO)
            ch.setFormatter(logging.Formatter("%(message)s"))
            ch.addFilter(_InstanceScopedFilter(self._owner, console=True))
            self._attach(ch)


        if not self.quiet and log_file and not self.dry_run:
            # T-202: refuse to write run logs through a redirected logs
            # directory -- a link/junction/reparse ancestor would land user
            # logs outside the application data root.
            parent = log_file.parent
            parent_ok = _log_dir_boundary_ok(parent, require_dir=False)
            if not parent_ok:
                self._log.warning(
                    f"Refusing to write log file {log_file}: {parent} fails the no-follow boundary"
                )
                log_file = None
            else:
                try:
                    parent.mkdir(parents=True, exist_ok=True)
                    parent_identity = _dir_identity(parent)
                except OSError:
                    log_file = None  # exe in read-only dir: logs stay console-only
                    parent_ok = False

            if parent_ok:
                # T-211: exclusive, handle-anchored creation. A pre-existing
                # destination (plain file, symlink, file hardlink) is refused.
                fh = _open_run_log_stream(log_file, parent_identity, instance_logger=self._log)
                if fh is None:
                    log_file = None
                else:
                    fh.setLevel(logging.DEBUG)
                    fh.setFormatter(logging.Formatter("%(asctime)s  %(levelname)-7s  %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
                    # Markerless module diagnostics (retention/pruning warnings)
                    # reach every active run log; own-instance records reach
                    # only this one.
                    fh.addFilter(_InstanceScopedFilter(self._owner, console=False))
                    self._attach(fh)
                # T-110: bound the logs/ directory (retention) on every real
                # run start. Retention is authorized by the boundary check,
                # never by the file-write outcome (T-211): a failed optional
                # logging subsystem cannot authorize or block mutations.
                try:
                    _prune_old_logs(parent)
                except OSError as exc:
                    logging.getLogger("vac_cleaner").warning(f"Log retention prune failed: {exc}")

    def _attach(self, handler: logging.Handler) -> None:
        """T-212: attach an owned handler; only this instance's handlers are
        ever removed, and the lock keeps concurrent construction serialized."""
        with _LOGGER_REGISTRY_LOCK:
            if self._closed:
                handler.close()
                return
            self._handlers.append(handler)
            self._shared.addHandler(handler)

    def close(self) -> None:
        """T-212: shut down only this instance's handlers. A live Logger's
        console and file handlers are untouched."""
        with _LOGGER_REGISTRY_LOCK:
            if self._closed:
                return
            self._closed = True
            handlers, self._handlers = self._handlers, []
        for handler in handlers:
            try:
                self._shared.removeHandler(handler)
            except Exception:  # noqa: S110 - already removed elsewhere
                pass
            try:
                handler.close()
            except Exception:  # noqa: S110 - best effort teardown
                pass
        _unregister_logger(self)

    def __enter__(self):
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:  # noqa: S110 - best effort cleanup in finalizer
            pass


    def _emit_gui(self, msg: str, kind=None):

        if self.gui_callback:

            self.gui_callback(_GuiLogMessage(msg, kind or getattr(msg, "kind", "ordinary")))


    def header(self, text: str) -> None:

        bar = "=" * 70

        msg = f"\n{bar}\n  {text}\n{bar}"

        self._log.info(msg)

        self._emit_gui(msg)


    def section(self, text: str) -> None:

        dashes = "-" * max(0, 60 - len(text))

        msg = f"\n-- {text} {dashes}"

        self._log.info(msg)

        self._emit_gui(msg)


    def info(self, msg: str) -> None:

        self._log.info(msg)

        self._emit_gui(msg)


    def warning(self, msg: str) -> None:

        self._log.warning(msg)

        self._emit_gui(msg, "warning")


    def error(self, msg: str) -> None:

        with self.lock:

            self.n_errors += 1

        text = f"  [ERROR]  {msg}"

        self._log.error(text)

        self._emit_gui(text, "error")


    def deleted(self, path: Path, size: int, desc: str) -> None:

        with self.lock:

            self.bytes_freed += size

            self.n_deleted += 1

            if self.deleted_paths is not None:
                self.deleted_paths.append(str(path))

        tag = "DRY-RUN" if self.dry_run else "DELETED"

        mb = size / BYTES_PER_MB

        text = f"  [{tag}] {mb:>9.2f} MB  {desc}"

        self._log.info(text)

        self._log.debug(f"            ->  {path}")

        self._emit_gui(text)


    def skipped(self, path: Path, reason: str) -> None:

        with self.lock:

            self.n_skipped += 1

        self._log.debug(f"  [SKIP ]            {reason}  ({path})")


    def summary(self) -> None:

        mode = "DRY-RUN  (nothing was deleted)" if self.dry_run else "DELETE  (files permanently removed)"

        mb = self.bytes_freed / BYTES_PER_MB

        gb = self.bytes_freed / BYTES_PER_GB

        bar = "=" * 68

        freed_label = "Would free" if self.dry_run else "Space freed"

        msg = (

            f"\n+{bar}+\n"

            f"| SUMMARY -- {mode:<55}|\n"

            f"+{bar}+\n"

            f"| {freed_label:<11}:  {mb:>10.1f} MB  /  {gb:>7.3f} GB{' '*22}|\n"

            f"| Items acted :  {self.n_deleted:<50} |\n"

            f"| Items skipped: {self.n_skipped:<50} |\n"

            f"| Errors       : {self.n_errors:<50} |\n"

            f"+{bar}+"

        )

        self._log.info(msg)

        self._emit_gui(msg, "summary")



#  SAFETY GUARD



def _path_part_key(part):
    return part.lower() if os.name == "nt" else part


class _PathTrie:
    def __init__(self, paths=()):
        self.root = {}
        for path in paths:
            self.insert(path.parts if isinstance(path, Path) else tuple(path))

    def insert(self, parts):
        original = tuple(parts)
        node = self.root
        for part in original:
            if None in node:
                return False
            node = node.setdefault(_path_part_key(part), {})
        if None in node:
            return False
        node.clear()
        node[None] = original
        return True

    def matches(self, parts):
        node = self.root
        for part in parts:
            if None in node:
                return node[None]
            node = node.get(_path_part_key(part))
            if node is None:
                return None
        return node.get(None)


def _root_boundary(path):
    path = Path(path).absolute()
    if _has_link_or_reparse_component(str(path)):
        return None
    identity = _capture_identity(path)
    if not identity or identity.get("type") != "dir":
        return None
    return path, identity


def _root_boundary_matches(token):
    if token is None:
        return False
    path, identity = token
    return not _has_link_or_reparse_component(str(path)) and _identity_matches(identity, _capture_identity(path))


class SafetyGuard:
    def __init__(self, base_root, allow_shallow_system_target=False,
                 exclude_patterns=None, exclude_paths=None, exclude_trie=None,
                 protect_against_blacklist=False, blacklist_trie=None):
        raw = Path(base_root).absolute()
        self._root_blocked = _has_link_or_reparse_component(str(raw))
        before = _root_boundary(raw) if not self._root_blocked else None
        self.base_root = self._canon(raw) if not self._root_blocked else raw
        self._root_token = before
        if before is not None and not _root_boundary_matches(before):
            self._root_blocked = True
        self.allow_shallow_system_target = allow_shallow_system_target
        self.exclude_patterns = list(exclude_patterns or ())
        self.exclude_paths = [Path(p) for p in (exclude_paths or ())]
        self._exclude_trie = exclude_trie if exclude_trie is not None else _PathTrie(p.resolve() for p in self.exclude_paths)
        self.protect_against_blacklist = protect_against_blacklist
        self._blacklist_trie = blacklist_trie if blacklist_trie is not None else _PathTrie(
            root.resolve() for root in BLACKLIST_PATHS
        )

    @staticmethod
    def _canon(path):
        try:
            return path.resolve()
        except OSError:
            return path.absolute()

    def is_safe(self, path, observed=None):
        if self._root_blocked:
            return False, "Configured root is linked or changed during establishment"
        if observed is None:
            linked = is_link(path)
        else:
            linked = stat.S_ISLNK(observed.st_mode) or bool(getattr(observed, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))
        if linked:
            return False, "Symlink/reparse point refused"
        path = self._canon(path)
        try:
            path.relative_to(self.base_root)
        except ValueError:
            return False, f"Outside TARGET ROOT ({self.base_root})"
        if path == self.base_root:
            return False, "Path IS the target root"
        if not self.allow_shallow_system_target and len(path.parts) < MIN_PATH_PARTS:
            return False, f"Path too shallow ({len(path.parts)} components)"
        if self.protect_against_blacklist and self._blacklist_trie.matches(path.parts) is not None:
            return False, "Protected blacklist path"
        name = path.name.lower()
        if any(variant in NEVER_DELETE_NAMES for variant in _name_variants(name)):
            return False, f"'{path.name}' is in the never-delete list"
        for pattern in self.exclude_patterns:
            if fnmatch.fnmatch(name, pattern.lower()):
                return False, f"'{path.name}' matches exclude pattern '{pattern}'"
        excluded = self._exclude_trie.matches(path.parts)
        if excluded is not None:
            return False, f"'{path}' is under excluded path '{Path(*excluded)}'"
        return True, "OK"


class _PlanBudget:
    def __init__(self, limit):
        self.limit = limit
        self.used = 0
        self.lock = threading.Lock()

    def try_acquire(self, count=1):
        with self.lock:
            if self.used + count > self.limit:
                return False
            self.used += count
            return True

    def release(self, count):
        with self.lock:
            self.used -= count



#  CORE CLEANER ENGINE



class CandidateLedger:
    """Thread-safe prefix claims: candidate lookup scales with path depth."""

    def __init__(self):
        self._trie = _PathTrie()
        self._count = 0
        self._lock = threading.Lock()

    @staticmethod
    def _canon(path):
        try:
            return path.resolve()
        except OSError:
            return path.absolute()

    def covered(self, path):
        canonical = self._canon(path)
        with self._lock:
            return self._trie.matches(canonical.parts) is not None

    def _within(self, parts):
        node = self._trie.root
        for part in parts:
            node = node.get(_path_part_key(part))
            if node is None:
                return []
        result, stack = [], [node]
        while stack:
            current = stack.pop()
            if None in current:
                result.append(current[None])
            stack.extend(value for key, value in current.items() if key is not None)
        return result

    def claims_within(self, path):
        canonical = self._canon(path)
        with self._lock:
            return [Path(*parts) for parts in self._within(canonical.parts) if Path(*parts) != canonical]

    def claim(self, path):
        canonical = self._canon(path)
        with self._lock:
            if self._trie.matches(canonical.parts) is not None:
                return
            absorbed = len(self._within(canonical.parts))
            self._trie.insert(canonical.parts)
            self._count += 1 - absorbed

    def __len__(self):
        with self._lock:
            return self._count


class CancelJobException(Exception):

    """Raised when the user cancels the running job."""



class CleanerEngine:

    """Base class providing safe file/dir deletion and logging utilities."""

    def __init__(self, dry_run: bool, log: Logger, guard: SafetyGuard, root: Path, max_threads: int = DEFAULT_THREADS, cancel_event: threading.Event | None = None,

                 exclude_patterns: list[str] | None = None, exclude_paths: list[str] | None = None, progress=None, ledger: CandidateLedger | None = None):

        self.exclude_patterns = exclude_patterns or []

        self.exclude_paths = exclude_paths or []

        self.dry_run = dry_run

        self.log = log

        self.root = root

        self.max_threads = max_threads

        self.cancel_event = cancel_event

        self.progress = progress

        self._owner_lock = threading.RLock()
        self._owner_ops_since_refresh = _OWNER_REFRESH_BATCH
        self.running = get_running_processes()

        self._exclude_trie = _PathTrie(Path(p).resolve() for p in self.exclude_paths)
        self._blacklist_trie = _PathTrie(root.resolve() for root in BLACKLIST_PATHS)
        self._boundary_store = threading.local()
        self._shared_plan_budget = None
        self._plan_budget_lock = threading.Lock()
        self._planning_abort_count = 0
        self._sweep_gate = None
        self._root_mismatch_abort = False
        self.guard = self.make_guard(guard.base_root, guard.allow_shallow_system_target)
        if guard._root_blocked or (guard._root_token is not None and not _root_boundary_matches(guard._root_token)):
            self.guard._root_blocked = True

        self.ledger = ledger

         # T-131: app-sensitive targets carry their owner group so the apply
        # phase can re-check the process state just-in-time (process TOCTOU).
        self._owner_group: str | None = None

        # PERF-001: when True, child ledger gates/claims are bypassed and the
        # parent is claimed once after a successful sweep.
        self._skip_ledger = False

    def make_guard(self, root, allow_shallow_system_target=False, protect_against_blacklist=False):
        return SafetyGuard(root, allow_shallow_system_target=allow_shallow_system_target,
                           exclude_patterns=self.exclude_patterns, exclude_paths=self.exclude_paths,
                           exclude_trie=self._exclude_trie, protect_against_blacklist=protect_against_blacklist,
                           blacklist_trie=self._blacklist_trie)


    def _boundary_stack(self):
        return getattr(self._boundary_store, "stack", ())


    def _boundary_set(self, stack):
        self._boundary_store.stack = tuple(stack)


    @property
    def _root_boundary_token(self):
        stack = self._boundary_stack()
        return stack[-1] if stack else None


    @_root_boundary_token.setter
    def _root_boundary_token(self, token):
        self._boundary_set((token,) if token is not None else ())


    @contextmanager
    def _boundary_push(self, token):
        previous = self._boundary_stack()
        self._boundary_set(previous + (token,))
        try:
            yield
        finally:
            self._boundary_set(previous)


    def _release_plan_budget(self, plan):
        count = plan.pop("budget_held", 0)
        if count:
            for key in ("files", "dirs", "protected"):
                plan[key].clear()
            self._plan_budget().release(count)

    def _plan_budget(self):
        try:
            file_limit = max(1, int(os.environ.get("SMARTVAC_PLAN_MAX_FILES", "20000")))
            limit = max(1, int(os.environ.get("SMARTVAC_PLAN_MAX_RECORDS", str(file_limit * 2))))
        except ValueError:
            limit = 40000
        with self._plan_budget_lock:
            if self._shared_plan_budget is None:
                self._shared_plan_budget = _PlanBudget(limit)
            elif self._shared_plan_budget.used == 0:
                self._shared_plan_budget.limit = limit
            return self._shared_plan_budget


    def check_cancel(self):

        if self.cancel_event and self.cancel_event.is_set():

            raise CancelJobException("Job cancelled by user.")


    def refresh_running(self):
        with self._owner_lock:
            self.running = get_running_processes()
            self._owner_ops_since_refresh = 0


    def _ledger_gate(self, path: Path, desc: str) -> bool:
        """Job-level dedup gate for a top-level target (T-124).

        False when another cleaner already claims this subtree -- the target
        must not be planned a second time. This is checked at plan time; the
        claim is registered only after a successful plan.

        PERF-001: when `_skip_ledger` is set (batch scope), bypass per-child
        ledger checks; the parent claims the whole subtree atomically.
        """
        if self._skip_ledger:
            return True
        if self.ledger is None:
            return True
        if self.ledger.covered(path):
            self.log.skipped(path, "Already covered by an earlier candidate claim")
            return False
        return True


    def _ledger_claims_within(self, path: Path) -> list[Path]:
        if self.ledger is None:
            return []
        return self.ledger.claims_within(path)


    def _ledger_claim(self, path: Path) -> None:
        if self._skip_ledger:
            return
        if self.ledger is not None:
            self.ledger.claim(path)


    def _owner_gate_ok(self, app):
        if self._sweep_gate is not None and not self._sweep_gate():
            return False
        if app == PROCESS_AGNOSTIC:
            return True
        if app is None or app not in APP_PROCESSES:
            return False
        with self._owner_lock:
            if self._owner_ops_since_refresh >= _OWNER_REFRESH_BATCH:
                self.refresh_running()
            self._owner_ops_since_refresh += 1
            return not is_app_running(app, self.running)


    def _owner_boundary_ok(self, app):
        if app in APP_PROCESSES and app != PROCESS_AGNOSTIC:
            self.refresh_running()
        return self._owner_gate_ok(app)


    def _log_deleted(self, path: Path, size: int, desc: str) -> None:

        self.log.deleted(path, size, desc)


    def _io_failure(self, path, error, operation="Directory operation"):
        if isinstance(error, (FileNotFoundError, NotADirectoryError, PermissionError)) or error.errno in (
            errno.ENOENT, errno.ENOTDIR, errno.EACCES, errno.EPERM, errno.EBUSY, errno.ENOTEMPTY,
        ):
            self.log.skipped(path, f"{operation} unavailable: {error}")
        else:
            self.log.error(f"{operation} failed for {path}: {error}")

    def _plan_file(self, path):
        if self.guard._root_blocked or not _root_boundary_matches(self.guard._root_token):
            self.log.skipped(path, "Configured root changed before planning")
            return None
        try:
            observed = path.lstat()
        except OSError as exc:
            self._io_failure(path, exc, "File metadata")
            return None
        identity = _identity_from_stat(observed)
        if identity is None or identity.get("type") != "file":
            self.log.skipped(path, "Non-file or linked candidate refused")
            return None
        ok, reason = self.guard.is_safe(path, observed=observed)
        if not ok:
            self.log.skipped(path, reason)
            return None
        return identity["size"], identity


    def _authorize_mutation(self, path, planned_identity, boundary_token=None):
        self.check_cancel()
        tokens = self._boundary_stack()
        if boundary_token is not None:
            tokens += (boundary_token,)
        if self.guard._root_token is None or self.guard._root_blocked or not _root_boundary_matches(self.guard._root_token):
            self._root_mismatch_abort = True
            return False, "Configured root changed before mutation"
        for token in tokens:
            if not _root_boundary_matches(token):
                self._root_mismatch_abort = True
                return False, "Root directory changed before mutation"
        if self._sweep_gate is not None and not self._sweep_gate():
            return False, "Service authorization expired"
        try:
            observed = path.lstat()
        except OSError as exc:
            self._io_failure(path, exc, "File metadata")
            if isinstance(exc, (FileNotFoundError, NotADirectoryError)):
                return False, "Path missing before mutation"
            return False, f"Path unavailable before mutation: {exc}"
        current = _identity_from_stat(observed)
        if current is None or current.get("type") == "link_or_reparse":
            return False, "Symlink/reparse point introduced before mutation"
        ok, reason = self.guard.is_safe(path)
        if not ok:
            return False, reason
        if not _identity_matches(planned_identity, current):
            return False, "Object identity changed since planning"
        return True, "OK"


    def _apply_file_plan(self, path, size, identity):
        chmod_identity = None
        try:
            original_mode = path.lstat().st_mode
        except OSError as exc:
            self._io_failure(path, exc, "File metadata")
            if isinstance(exc, (FileNotFoundError, NotADirectoryError)):
                return MutationResult(False, 0, "File missing")
            return MutationResult(False, 0, f"File metadata unavailable: {exc}")

        def restore_mode():
            if chmod_identity is None:
                return
            ok, _reason = self._authorize_mutation(path, chmod_identity)
            if ok:
                try:
                    path.chmod(original_mode & 0o7777)
                except OSError as exc:
                    logging.getLogger("vac_cleaner").warning(f"Could not restore mode on {path}: {exc}")

        for attempt in range(2):
            ok, reason = self._authorize_mutation(path, identity)
            if not ok:
                restore_mode()
                self.log.skipped(path, reason)
                return MutationResult(False, 0, reason)
            try:
                path.unlink()
                if path.exists():
                    self.log.skipped(path, "File still present after unlink")
                    restore_mode()
                    return MutationResult(False, 0, "File still present after unlink")
                return MutationResult(True, size, "OK")
            except PermissionError:
                if attempt:
                    restore_mode()
                    self.log.skipped(path, "File in use or access denied")
                    return MutationResult(False, 0, "File in use or access denied")
                ok, reason = self._authorize_mutation(path, identity)
                if not ok:
                    self.log.skipped(path, reason)
                    return MutationResult(False, 0, reason)
                try:
                    path.chmod(0o666)
                except OSError:
                    self.log.skipped(path, "File in use or access denied")
                    return MutationResult(False, 0, "File in use or access denied")
                observed = _capture_identity(path)
                if not _identity_matches(identity, observed, ignore_attrs=True):
                    self.log.skipped(path, "Object changed during chmod")
                    return MutationResult(False, 0, "Object changed during chmod")
                chmod_identity = identity = observed
            except OSError as exc:
                restore_mode()
                self.log.error(f"Delete failed for {path}: {exc}")
                return MutationResult(False, 0, str(exc))
            except Exception as exc:
                restore_mode()
                self.log.error(f"Unexpected delete failure for {path}: {exc}")
                return MutationResult(False, 0, str(exc))
        return MutationResult(False, 0, "Delete refused")


    def _del_file(self, path: Path, desc: str, owner_group: str | None = None) -> int:

        """Delete one file. Counters/log/progress advance only after verified success (P1-12/F7).

        owner_group (T-131): when set, the owning process state is re-checked
        just-in-time before the mutation batch; a running/UNKNOWN owner aborts.
        """

        self.check_cancel()

        if not self._ledger_gate(path, desc):
            return 0

        plan = self._plan_file(path)
        if plan is None:
            return 0

        size, identity = plan

        # T-124: the claim registers the candidate truth and is mode-independent
        # (dry-run and real-delete must see the SAME candidate set).
        self._ledger_claim(path)

        if self.dry_run:
            self._log_deleted(path, size, desc)
            return size

        if owner_group is not None and not self._owner_gate_ok(owner_group):
            self.log.skipped(path, f"'{owner_group}' became running or unknown before delete; aborting target")
            return 0

        result = self._apply_file_plan(path, size, identity)
        if result.success:
            self._log_deleted(path, result.bytes_freed, desc)
            if self.progress:
                self.progress.advance(result.bytes_freed)
        return result.bytes_freed


    def _plan_tree(self, path, desc, excluded_regions=()):
        """Stage each complete directory read-only under one shared record budget."""
        self.check_cancel()
        if not _root_boundary_matches(self.guard._root_token) or is_link(path) or not self.guard.is_safe(path)[0]:
            self.log.skipped(path, "Tree root refused")
            return None
        token = _root_boundary(path)
        if token is None:
            return None
        try:
            file_limit = max(1, int(os.environ.get("SMARTVAC_PLAN_MAX_FILES", "20000")))
        except ValueError:
            file_limit = 20000
        budget = self._plan_budget()
        regions = _PathTrie(Path(p).resolve() for p in excluded_regions)
        files, dirs, protected = [], [], set()
        reserved = 0

        def reserve():
            nonlocal reserved
            if not budget.try_acquire():
                raise OverflowError("Total planning record budget exceeded")
            reserved += 1

        stack = [path]
        staged_files, staged_dirs, staged_protected = [], [], set()
        identity = None

        def discard():
            nonlocal identity
            for records in (files, dirs, protected, stack, staged_files, staged_dirs, staged_protected):
                records.clear()
            identity = None

        try:
            while stack:
                current = stack.pop()
                self.check_cancel()
                staged_files, staged_dirs, staged_protected = [], [], set()
                before_directory = reserved
                try:
                    with os.scandir(current) as entries:
                        for entry in entries:
                            self.check_cancel()
                            candidate = Path(entry.path)
                            observed = candidate.lstat() if os.name == "nt" else entry.stat(follow_symlinks=False)
                            reserve()
                            safe = self.guard.is_safe(candidate, observed=observed)[0]
                            if not safe or regions.matches(candidate.parts) is not None:
                                staged_protected.add(candidate)
                                continue
                            identity = _identity_from_stat(observed)
                            if identity is not None and identity.get("type") != "link_or_reparse" and not identity.get("ino"):
                                # Windows DirEntry.stat may omit file IDs. A fresh
                                # no-follow lstat is then required to prove identity.
                                identity = _capture_identity(candidate)
                            if identity is None or identity.get("type") == "link_or_reparse":
                                staged_protected.add(candidate)
                            elif identity["type"] == "dir":
                                staged_dirs.append((candidate, identity))
                            else:
                                if len(files) + len(staged_files) >= file_limit:
                                    raise OverflowError("Accepted-file planning budget exceeded")
                                staged_files.append((candidate, identity["size"], identity))
                except OSError as exc:
                    discarded = reserved - before_directory
                    staged_files.clear()
                    staged_dirs.clear()
                    staged_protected.clear()
                    identity = None
                    budget.release(discarded)
                    reserved -= discarded
                    self._io_failure(current, exc)
                    reserve()
                    protected.add(current)
                    continue
                files.extend(staged_files)
                dirs.extend(staged_dirs)
                protected.update(staged_protected)
                stack.extend(candidate for candidate, _identity in staged_dirs)
            if not _root_boundary_matches(token):
                discard()
                budget.release(reserved)
                return None
            return {"bytes": sum(size for _p, size, _i in files), "files": files,
                    "dirs": dirs, "protected": protected, "root": path,
                    "root_identity": token[1], "budget_held": reserved}
        except OverflowError as exc:
            with self._plan_budget_lock:
                self._planning_abort_count += 1
            discard()
            budget.release(reserved)
            self.log.error(str(exc))
            return None
        except BaseException:
            discard()
            budget.release(reserved)
            raise


    def _apply_tree_plan(self, plan, desc, owner_group=None):
        freed, fully = 0, not bool(plan["protected"])
        root = plan["root"]
        with self._boundary_push((root, plan["root_identity"])):
            for index, (candidate, size, identity) in enumerate(plan["files"]):
                self.check_cancel()
                if owner_group is not None and index % _OWNER_REFRESH_BATCH == 0 and not self._owner_boundary_ok(owner_group):
                    return freed, False
                freed += self._apply_file_plan(candidate, size, identity).bytes_freed
            for candidate, identity in reversed(plan["dirs"] + [(root, plan["root_identity"])]):
                # Root is handled last below; discovery order reverses child-before-parent.
                if candidate == root or candidate in plan["protected"]:
                    continue
                self.check_cancel()
                if owner_group is not None and not self._owner_boundary_ok(owner_group):
                    return freed, False
                if self._sweep_gate is not None and not self._sweep_gate(force=True):
                    return freed, False
                try:
                    if any(candidate.iterdir()):
                        fully = False
                        continue
                    ok, reason = self._authorize_mutation(candidate, identity)
                    if not ok:
                        self.log.skipped(candidate, reason)
                        fully = False
                        continue
                    candidate.rmdir()
                except OSError as exc:
                    self._io_failure(candidate, exc)
                    fully = False
            if fully:
                self.check_cancel()
                if owner_group is not None and not self._owner_boundary_ok(owner_group):
                    return freed, False
                if self._sweep_gate is not None and not self._sweep_gate(force=True):
                    return freed, False
                try:
                    if any(root.iterdir()):
                        fully = False
                    else:
                        ok, reason = self._authorize_mutation(root, plan["root_identity"])
                        if ok:
                            root.rmdir()
                        else:
                            self.log.skipped(root, reason)
                            fully = False
                except OSError as exc:
                    self._io_failure(root, exc)
                    fully = False
        return freed, fully


    def _del_dir(self, path: Path, desc: str, owner_group: str | None = None) -> int:

        """Delete a directory tree, preserving protected/excluded descendants (P0-4).

        Planning is read-only and runs for BOTH modes; the apply phase runs
        only when dry_run is False (T-090). owner_group (T-131) is re-checked
        just-in-time before the apply batch.
        """

        self.check_cancel()

        if not path.exists() or not path.is_dir():
            return 0

        if not self._ledger_gate(path, desc):
            return 0

        excluded = self._ledger_claims_within(path)
        plan = self._plan_tree(path, desc, excluded_regions=excluded)
        if plan is None:
            return 0

        try:
            # T-124: the claim registers the candidate truth and is mode-independent
            # (dry-run and real-delete must see the SAME candidate set).
            self._ledger_claim(path)

            if self.dry_run:
                if plan["bytes"] > 0:
                    self._log_deleted(path, plan["bytes"], desc)
                return plan["bytes"]

            if owner_group is not None and not self._owner_gate_ok(owner_group):
                self.log.skipped(path, f"'{owner_group}' became running or unknown before delete; aborting target")
                return 0

            freed, fully = self._apply_tree_plan(plan, desc, owner_group=owner_group)
            if fully:
                self._log_deleted(path, freed, desc)
            elif freed > 0:
                self.log.skipped(path, f"Partially removed; kept {len(plan['protected'])} protected/excluded item(s)")
                self._log_deleted(path, freed, f"{desc} (partial)")
            else:
                self.log.skipped(path, "Content protected or excluded; nothing deleted")
            if self.progress and freed > 0:
                self.progress.advance(freed)
            return freed
        finally:
            self._release_plan_budget(plan)


    def _del_dir_contents(self, path, desc, owner_group=None):
        self.check_cancel()
        if not safe_is_dir(path) or not self._ledger_gate(path, desc):
            return 0
        token = _root_boundary(path)
        if token is None or self.guard._root_blocked or not _root_boundary_matches(self.guard._root_token):
            self.log.skipped(path, "Root identity could not be established")
            return 0
        try:
            limit = max(1, int(os.environ.get("SMARTVAC_CONTENT_MAX_ENTRIES", "20000")))
        except ValueError:
            limit = 20000
        abort_epoch = self._planning_abort_count
        items = []
        try:
            for index, item in enumerate(path.iterdir()):
                self.check_cancel()
                if index >= limit:
                    self.log.error("Content enumeration budget exceeded")
                    return 0
                if self.guard.is_safe(item)[0]:
                    items.append(item)
        except OSError as exc:
            self._io_failure(path, exc)
            return 0
        if not _root_boundary_matches(token):
            return 0
        with self._boundary_push(token):
            inherited = self._boundary_stack()

            def handle(item):
                previous = self._boundary_stack()
                self._boundary_set(inherited)
                try:
                    self.check_cancel()
                    if not _root_boundary_matches(token):
                        return 0
                    if owner_group is not None and not self._owner_gate_ok(owner_group):
                        return 0
                    if item.is_dir():
                        return self._del_dir(item, f"{desc} / {item.name}", owner_group=owner_group)
                    return self._del_file(item, f"{desc} / {item.name}", owner_group=owner_group)
                finally:
                    self._boundary_set(previous)

            freed = 0
            if self.max_threads > 1 and len(items) > 1:
                iterator = iter(items)
                pending = {}
                stopped, cancelled, exhausted = False, False, False
                with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                    while pending or not exhausted:
                        try:
                            self.check_cancel()
                        except CancelJobException:
                            stopped = cancelled = True
                        while not stopped and not exhausted and len(pending) < self.max_threads * 4:
                            item = next(iterator, None)
                            if item is None:
                                exhausted = True
                                break
                            pending[executor.submit(handle, item)] = item
                        if stopped:
                            for future in pending:
                                future.cancel()
                        if not pending:
                            break
                        done, _remaining = concurrent.futures.wait(pending, return_when=concurrent.futures.FIRST_COMPLETED)
                        for future in done:
                            item = pending.pop(future)
                            try:
                                freed += future.result()
                            except concurrent.futures.CancelledError:
                                continue
                            except CancelJobException:
                                stopped = cancelled = True
                            except Exception as exc:
                                self.log.error(f"Child target failed for {item}: {exc}")
                                stopped = True
                if cancelled:
                    raise CancelJobException("Job cancelled by user")
            else:
                stopped = False
                for item in items:
                    try:
                        freed += handle(item)
                    except CancelJobException:
                        raise
                    except Exception as exc:
                        self.log.error(f"Child target failed for {item}: {exc}")
                        stopped = True
                        break
            if not stopped and self._planning_abort_count == abort_epoch and _root_boundary_matches(token):
                self._ledger_claim(path)
            return freed


    def safe_del_dir(self, path: Path, desc: str, app: str) -> int:

        if is_app_running(app, self.running):

            self.log.skipped(path, f"'{app}' is running (or process state unknown)")

            return 0

        ok, reason = self.guard.is_safe(path)

        if not ok:
            self.log.skipped(path, reason)
            return 0

        return self._del_dir(path, desc, owner_group=app)


    def safe_del_file(self, path: Path, desc: str, app: str) -> int:

        if is_app_running(app, self.running):

            self.log.skipped(path, f"'{app}' is running (or process state unknown)")

            return 0

        ok, reason = self.guard.is_safe(path)

        if not ok:
            self.log.skipped(path, reason)
            return 0

        return self._del_file(path, desc, owner_group=app)


    def safe_del_dir_contents(self, path: Path, desc: str, app: str) -> int:

        if is_app_running(app, self.running):

            self.log.skipped(path, f"'{app}' is running (or process state unknown)")

            return 0

        ok, reason = self.guard.is_safe(path)

        if not ok:
            self.log.skipped(path, reason)
            return 0

        return self._del_dir_contents(path, desc, owner_group=app)


class PortableCleaner(CleanerEngine):

    r"""Cleans configurable portable-app roots (portable_roots in cleaner_config.json)."""


    def sweep_numbered_copies(self, parent: Path, app: str) -> int:

        if not parent.exists() or not parent.is_dir(): return 0

        if is_app_running(app, self.running): return 0

        freed = 0

        try:

            for item in parent.iterdir():

                self.check_cancel()

                m = _NAME_NUMBERED_RE.match(item.name)

                if not m or int(m.group(2)) < 2: continue

                base = m.group(1).strip().lower()

                if base not in NUMBERED_COPY_JUNK_BASES:

                    self.log.skipped(item, f"Numbered copy '{item.name}' is not proven junk; kept")

                    continue

                ok, reason = self.guard.is_safe(item)

                if not ok:

                    self.log.skipped(item, reason)

                    continue

                desc = f"Numbered crash-backup: {item.name}"

                if item.is_file(): freed += self._del_file(item, desc, owner_group=app)

                elif item.is_dir(): freed += self._del_dir(item, desc, owner_group=app)

        except OSError:

            pass  # expected: dir may be deleted by another process

        return freed


    def _clean_chromium_profile(self, profile_dir: Path, app: str) -> int:

        if not profile_dir.exists(): return 0

        freed = 0

        for name in CHROMIUM_PROFILE_DIRS:

            freed += self.safe_del_dir(profile_dir / name, f"[{app}] {name}", app)

        sw = profile_dir / "Service Worker"

        if sw.exists():

            for name in CHROMIUM_SW_SUBDIRS: freed += self.safe_del_dir(sw / name, f"[{app}] SW/{name}", app)

        for name in CHROMIUM_PROFILE_FILES:

            freed += self.safe_del_file(profile_dir / name, f"[{app}] {name}", app)

        net = profile_dir / "Network"

        if net.exists():

            try:

                for item in net.iterdir():

                    self.check_cancel()

                    if item.suffix.lower() == ".tmp" and item.is_file() and self.guard.is_safe(item)[0]:

                        freed += self._del_file(item, f"[{app}] Net tmp: {item.name}", owner_group=app)

            except OSError:

                pass  # expected: temp files may vanish mid-scan

            freed += self.sweep_numbered_copies(net, app)

        freed += self.sweep_numbered_copies(profile_dir, app)

        return freed


    def _clean_chromium_profiles(self, user_data: Path, app: str) -> int:

        if not user_data.exists() or not user_data.is_dir(): return 0

        freed = 0

        profile_re = re.compile(r'^(Default|System Profile|Guest Profile|Profile \d+)$')

        try:

            for item in user_data.iterdir():

                self.check_cancel()

                if item.is_dir() and profile_re.match(item.name):

                    freed += self._clean_chromium_profile(item, app)

        except OSError:

            pass  # expected: user_data dir may be locked

        return freed


    def _clean_chromium_userdata(self, user_data: Path, app: str) -> int:

        freed = 0

        for name in CHROMIUM_USERDATA_DIRS: freed += self.safe_del_dir(user_data / name, f"[{app}/UD] {name}", app)

        for name in CHROMIUM_USERDATA_FILES: freed += self.safe_del_file(user_data / name, f"[{app}/UD] {name}", app)

        freed += self.sweep_numbered_copies(user_data, app)

        return freed


    def _clean_old_opera_versions(self, opera_dir: Path) -> int:

        if is_app_running("opera", self.running) or not opera_dir.exists(): return 0

        ver_re = re.compile(r'^\d+\.\d+\.\d+\.\d+$')

        ver_dirs = []

        try:

            for item in opera_dir.iterdir():

                self.check_cancel()

                if item.is_dir() and ver_re.match(item.name): ver_dirs.append(item)

        except OSError: return 0

        if len(ver_dirs) <= 1: return 0

        ver_dirs.sort(key=lambda p: tuple(int(x) for x in p.name.split('.')))

        old_dirs = ver_dirs[:-1]

        freed = 0

        for d in old_dirs: freed += self.safe_del_dir(d, f"[Opera] old version {d.name}", "opera")

        return freed


    def clean_cent(self) -> int:

        self.refresh_running()

        cdir = self.root / "_CENT"

        ud = cdir / "User Data"

        if not safe_exists(cdir): return 0

        self.log.section("Cent Browser")

        freed = self._clean_chromium_userdata(ud, "cent") + self._clean_chromium_profiles(ud, "cent")

        for p, d in [(cdir/"debug.log", "debug.log"), (cdir/"old_chrome.exe", "old_chrome.exe"), (cdir/"old_chrome_proxy.exe", "old_chrome_proxy.exe")]:

            freed += self.safe_del_file(p, f"[Cent] {d}", "cent")

        return freed


    def clean_brave(self) -> int:

        self.refresh_running()

        bdir = self.root / "__SOFT" / "_BRAVE"

        data = bdir / "data"

        if not safe_exists(bdir): return 0

        self.log.section("Brave Browser")

        freed = 0

        for name in CHROMIUM_USERDATA_DIRS: freed += self.safe_del_dir(data / name, f"[Brave/UD] {name}", "brave")

        for name in CHROMIUM_USERDATA_FILES: freed += self.safe_del_file(data / name, f"[Brave/UD] {name}", "brave")

        freed += self.sweep_numbered_copies(data, "brave")

        freed += self._clean_chromium_profiles(data, "brave")

        return freed


    def clean_firefox(self) -> int:

        self.refresh_running()

        fdir = self.root / "__SOFT" / "_FIREFOX"

        prof = fdir / "Data" / "profile"

        if not safe_exists(fdir): return 0

        self.log.section("Firefox Portable")

        freed = 0

        for name in ["cache2", "startupCache", "shader-cache", "thumbnails", "crashes", "minidumps"]:

            freed += self.safe_del_dir(prof / name, f"[Firefox] {name}", "firefox")

        for name in ["parent.lock"]:

            freed += self.safe_del_file(prof / name, f"[Firefox] {name}", "firefox")

        return freed


    def clean_opera(self) -> int:

        self.refresh_running()

        odir = self.root / "__SOFT" / "_OPERA"

        if not safe_exists(odir): return 0

        self.log.section("Opera")

        return self._clean_old_opera_versions(odir) + self.safe_del_dir(odir / "old_status", "[Opera] old_status", "opera")


    def clean_telegram(self) -> int:

        self.refresh_running()

        tdir = self.root / "_TG"

        tdata = tdir / "tdata"

        ud = tdata / "user_data"

        if not safe_exists(tdir): return 0

        self.log.section("Telegram")

        freed = 0

        for p, d in [(tdata/"temp_data", "temp_data"), (tdata/"dumps", "crash dumps"), (ud/"cache", "media cache"), (ud/"media_cache", "media_cache"), (ud/"wvbots", "wvbots"), (ud/"wvother", "wvother")]:

            freed += self.safe_del_dir(p, f"[Telegram] {d}", "telegram")

        freed += self.safe_del_dir_contents(tdata / "temp", "[Telegram] temp dir contents", "telegram")

        for name in ["log.txt", "log_start0.txt", "log_start1.txt", "log_start2.txt", "log_start3.txt"]:

            freed += self.safe_del_file(tdir / name, f"[Telegram] {name}", "telegram")

        return freed


    def _universal_owner_for(self, path):
        try:
            parts = path.relative_to(self.root).parts
        except ValueError:
            return None
        if not parts:
            return None
        keys = tuple(part.lower() for part in parts)
        if keys[0] in ("_cent", "_tg"):
            return {"_cent": "cent", "_tg": "telegram"}[keys[0]]
        if len(keys) > 1 and keys[0] == "__soft":
            return {"_brave": "brave", "_opera": "opera", "_firefox": "firefox"}.get(keys[1])
        return None


    def clean_universal_caches(self):
        """Bounded discovery only; dedicated owners never gain fallback authority."""
        if not safe_is_dir(self.root) or not _root_boundary_matches(self.guard._root_token):
            return 0
        self.log.section(f"Universal Sweeper: {self.root}")
        names = {"cache", "code cache", "gpucache", "shadercache", "dawncache",
                 "media cache", "crashpad", "crash reports", "logs"}
        try:
            limit = max(1, int(os.environ.get("SMARTVAC_DISCOVERY_MAX_NODES", "10000")))
        except ValueError:
            limit = 10000
        visited, stack = 0, [(self.root, 0)]
        while stack:
            current, depth = stack.pop()
            self.check_cancel()
            try:
                with os.scandir(current) as entries:
                    for entry in entries:
                        self.check_cancel()
                        visited += 1
                        if visited > limit:
                            self.log.warning(f"Universal discovery truncated at {limit} entries; no discovery target is authorized for deletion")
                            return 0
                        candidate = Path(entry.path)
                        if is_link(candidate) or not entry.is_dir(follow_symlinks=False):
                            continue
                        owner = self._universal_owner_for(candidate)
                        if owner is not None and _owner_trust(owner) == "verified":
                            self.log.skipped(candidate, f"Owned by dedicated sweeper ('{owner}'); universal discovery defers")
                            continue
                        if candidate.name.lower() in names:
                            self.log.info(f"  [DISCOVERED] {candidate} -- no verified owner; NOT AUTHORIZED to delete")
                        elif depth < 5:
                            stack.append((candidate, depth + 1))
            except OSError:
                continue
        return 0


    def run_all(self) -> int:

        freed = self.clean_cent() + self.clean_brave() + self.clean_firefox() + self.clean_opera() + self.clean_telegram()

        freed += self.clean_universal_caches()

        return freed

    def make_guard(self, root, allow_shallow_system_target=False, protect_against_blacklist=True):
        return super().make_guard(root, False, protect_against_blacklist=True)


class SystemCleaner(CleanerEngine):

    """Cleans OS level junk (Temp, Thumbnails, CrashDumps)."""

    def __init__(self, dry_run: bool, log: Logger, max_threads: int = DEFAULT_THREADS, targets: dict[str, bool] | None = None, cancel_event: threading.Event | None = None,

                 exclude_patterns: list[str] | None = None, exclude_paths: list[str] | None = None, progress=None, ledger: CandidateLedger | None = None,
                 system_roots: dict | None = None):

        # The root here isn't a single drive, so we pass dummy C:\.

        # But we create a specialized SafetyGuard for each system path.

        super().__init__(dry_run, log, SafetyGuard(Path("C:\\")), Path("C:\\"), max_threads, cancel_event,

                         exclude_patterns=exclude_patterns, exclude_paths=exclude_paths, progress=progress, ledger=ledger)

        self.targets = targets if targets is not None else {}

        # CORE-013: consume the frozen per-job system-root snapshot instead of
        # reading module globals directly.
        self._system_roots = system_roots if system_roots is not None else resolve_system_roots()

        # F4: per-target planned/freed bytes populated by run_all. This is the
        # single source of truth shared by dry-run, --status and the GUI
        # preview/progress estimation (T-114).
        self.results: dict[str, int] = {}



    import contextlib

    @contextlib.contextmanager
    def target_scope(self, root: Path):
        r"""Scoped guard for a narrow target (P0-3). Never use C:\."""
        old_guard = getattr(self, "guard", None)
        self._set_guard(root)
        try:
            yield self.guard
        finally:
            if old_guard:
                self.guard = old_guard

    def _set_guard(self, root: Path) -> SafetyGuard:

        """Switch the active guard to `root`, keeping engine exclusions (P0-3).

        System-internal targets are hardcoded, reviewed cleanup roots; they are
        allowed to be shallow (F3: the shallow-target capability is reserved
        for these internal targets, never for user-supplied custom rules).
        """

        self.guard = self.make_guard(root, allow_shallow_system_target=True)

        return self.guard


    def run_all(self) -> int:

        system_temp = self._system_roots.get("SYSTEM_TEMP")
        user_temp = self._system_roots.get("USER_TEMP")
        user_crash = self._system_roots.get("USER_CRASH")
        user_explorer = self._system_roots.get("USER_EXPLORER")
        appdata_targets = self._system_roots.get("USER_APPDATA_TARGETS", ())
        self.log.section("System Junk (C:\\)")

        freed = 0


        # System Temp

        if self.targets.get("System Temp", True) and system_temp is not None and system_temp.exists():

            self._set_guard(system_temp)

            before = freed

            freed += self._del_dir_contents(system_temp, "Windows System Temp", owner_group=PROCESS_AGNOSTIC)

            self.results["System Temp"] = freed - before


        # User Temp

        if self.targets.get("User Temp", True) and user_temp is not None and user_temp.exists():

            self._set_guard(user_temp)

            before = freed

            freed += self._del_dir_contents(user_temp, "Windows User Temp", owner_group=PROCESS_AGNOSTIC)

            self.results["User Temp"] = freed - before


        # User CrashDumps

        if self.targets.get("App CrashDumps", True) and user_crash is not None and user_crash.exists():

            self._set_guard(user_crash)

            before = freed

            freed += self._del_dir_contents(user_crash, "Windows App CrashDumps", owner_group=PROCESS_AGNOSTIC)

            self.results["App CrashDumps"] = freed - before


        # Explorer Thumbnails

        if self.targets.get("Explorer Thumbnails", True) and user_explorer is not None and user_explorer.exists():

            guard = self._set_guard(user_explorer)

            before = freed

            try:

                for item in user_explorer.iterdir():

                    if item.is_file() and item.name.lower().startswith("thumbcache_") and guard.is_safe(item)[0]:

                        freed += self._del_file(item, f"Thumbnail Cache: {item.name}")

                tcd = user_explorer / "ThumbCacheToDelete"

                if tcd.is_dir() and guard.is_safe(tcd)[0]:

                    freed += self._del_dir(tcd, "Thumbnail Cache: ThumbCacheToDelete")

            except OSError:

                pass  # expected: thumbnail cache may be in use

            self.results["Explorer Thumbnails"] = freed - before


        # Deep AppData Caches

        for target_path, desc, *rest in appdata_targets:

            app_group = rest[0] if rest else None

            if not (self.targets.get(desc, True) and target_path.exists()):
                continue

            # T-092: no implicit owner=None escape hatch. An app-specific target
            # without a verified owner is SKIPPED (fail closed), never swept.
            if app_group is None and desc not in PROCESS_AGNOSTIC_TARGETS:
                self.log.skipped(target_path, f"No verified owner for '{desc}'; skipping (T-092)")
                continue

            # T-130: an UNVERIFIED owner cannot authorize destructive cleaning in
            # EITHER mode. Presence of a provenance entry is not trust; only a
            # verified:disk/runtimelog or independently justified product:exe
            # mapping is. The target is reported separately, contributing ZERO
            # planned bytes/candidates/progress (discovery stays in --analyze-caches).
            if app_group is not None and _owner_trust(app_group) == "unverified":
                self.log.info(f"  [DISCOVERED] {target_path} -- owner '{app_group}' is UNVERIFIED; NOT AUTHORIZED to delete")
                continue

            if app_group:
                self.refresh_running()
                if is_app_running(app_group, self.running):
                    self.log.skipped(target_path, f"'{app_group}' is running (or process state unknown)")
                    continue

            self._set_guard(target_path)

            before = freed

            freed += self._del_dir_contents(target_path, desc, owner_group=app_group)

            self.results[desc] = freed - before


        # Windows Update Cache

        if self.targets.get("Windows Update Cache", False):

            win_dir = self._system_roots.get("WINDIR")
            wu_path = win_dir / "SoftwareDistribution" / "Download" if win_dir is not None else None

            if wu_path is not None and wu_path.exists():

                import ctypes

                try: is_admin = ctypes.windll.shell32.IsUserAnAdmin()

                except Exception:

                    self.log.warning("Failed to check admin privileges, assuming non-admin")

                    is_admin = False

                if is_admin:

                    self._set_guard(wu_path)

                    before = freed

                    if self.dry_run:
                        # T-095: dry-run performs ZERO service mutation.
                        freed += self._del_dir_contents(wu_path, "Windows Update Cache", owner_group=PROCESS_AGNOSTIC)
                    else:
                        freed += self._clean_windows_update_cache(wu_path) # owner_group is handled inside

                    self.results["Windows Update Cache"] = freed - before

                else:

                    self.log.info("  [SKIP] Windows Update Cache requires Administrator privileges.")


        # DNS Cache

        if self.targets.get("DNS Cache", False):

            if self.dry_run:

                self.log.info("  [DNS] Would flush DNS Resolver Cache.")

            else:

                import subprocess

                try:

                    self.check_cancel()
                    result = subprocess.run(["ipconfig", "/flushdns"], capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW, timeout=30, check=False)

                    if result.returncode == 0:

                        self.log.info("  [DNS] Successfully flushed DNS Resolver Cache.")

                    else:

                        self.log.error(f"Failed to flush DNS Resolver Cache (exit {result.returncode})")

                except Exception:

                    self.log.error("Failed to flush DNS Resolver Cache")


        # Recycle Bin

        if self.targets.get("Recycle Bin", False):

            if self.dry_run:

                self.log.info("  [Recycle Bin] Would empty Recycle Bin.")

            else:

                import ctypes

                # SHERB_NOCONFIRMATION = 1, SHERB_NOPROGRESSUI = 2, SHERB_NOSOUND = 4

                self.check_cancel()
                result = ctypes.windll.shell32.SHEmptyRecycleBinW(None, None, 7)

                if result == 0:

                    self.log.info("  [Recycle Bin] Successfully emptied the Recycle Bin.")

                else:

                    self.log.error(f"Recycle Bin empty failed (result {result})")


        # Deep C: Junk

        if self.targets.get("Deep C: Junk", True):

            self.log.section("Deep C: Junk")

            before = freed

            freed += self._deep_junk_sweep()

            self.results["Deep C: Junk"] = freed - before

        return freed


    def _service_state(self, name):
        try:
            result = subprocess.run(["sc", "query", name], capture_output=True, text=True,
                                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                                    timeout=10, check=False)
        except (OSError, subprocess.TimeoutExpired):
            return None
        if result.returncode:
            return None
        match = re.search(r"\bSTATE\s*:\s*\d+\s+([A-Z_]+)", result.stdout, re.IGNORECASE)
        return match[1].upper() if match else None


    def _make_service_gate(self, name="wuauserv"):
        lock = threading.Lock()
        batch = _OWNER_REFRESH_BATCH
        remaining, valid = 0, True

        def gate(force=False):
            nonlocal remaining, valid
            with lock:
                if not valid:
                    return False
                if force or remaining <= 0:
                    valid = self._service_state(name) == "STOPPED"
                    remaining = batch
                    if not valid:
                        self.log.warning(f"{name} is no longer exactly STOPPED; remaining cache mutations refused")
                if not force:
                    remaining -= 1
                return valid
        return gate


    def _stop_wuauserv_bounded(self):
        self.check_cancel()
        try:
            result = subprocess.run(["net", "stop", "wuauserv"], capture_output=True,
                                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                                    timeout=30, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            self.log.error(f"Could not stop wuauserv: {exc}")
            return False
        if result.returncode not in (0, 2):
            self.log.error(f"Failed to stop wuauserv (exit {result.returncode})")
            return False
        deadline = time.monotonic() + _WU_STOP_POLL_TIMEOUT
        while True:
            self.check_cancel()
            state = self._service_state("wuauserv")
            if state == "STOPPED":
                return True
            if state != "STOP_PENDING" or time.monotonic() >= deadline:
                self.log.error(f"wuauserv did not reach STOPPED (state {state!r})")
                return False
            time.sleep(_WU_STOP_POLL_INTERVAL)


    def _clean_windows_update_cache(self, wu_path):
        original = self._service_state("wuauserv")
        if original not in ("RUNNING", "START_PENDING", "STOPPED"):
            self.log.warning("wuauserv state does not authorize cleanup")
            return 0
        self.check_cancel()
        restore = original != "STOPPED"
        previous_gate = self._sweep_gate
        try:
            if restore and not self._stop_wuauserv_bounded():
                return 0
            self._sweep_gate = self._make_service_gate()
            with self.target_scope(wu_path):
                return self._del_dir_contents(wu_path, "Windows Update Cache", owner_group=PROCESS_AGNOSTIC)
        finally:
            self._sweep_gate = previous_gate
            if restore:
                try:
                    result = subprocess.run(["net", "start", "wuauserv"], capture_output=True,
                                            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                                            timeout=30, check=False)
                    if result.returncode:
                        self.log.error(f"Failed to restart wuauserv (exit {result.returncode})")
                except (OSError, subprocess.TimeoutExpired) as exc:
                    self.log.error(f"Could not restore wuauserv: {exc}")


    def _subtree_latest_mtime(self, path: Path) -> float | None:
        latest = None
        try:
            latest = path.lstat().st_mtime
        except OSError:
            return None
        if path.is_file():
            return latest
        for root, dirs, files in os.walk(path, followlinks=False):
            # Never follow link/reparse directories.
            dirs[:] = [d for d in dirs if not is_link(Path(root) / d)]
            for name in list(dirs) + list(files):
                try:
                    st = (Path(root) / name).lstat()
                except OSError:
                    continue
                if latest is None or st.st_mtime > latest:
                    latest = st.st_mtime
        return latest

    def _has_active_markers(self, path: Path) -> bool:
        lock_tokens = ("lock", ".lock", "pid", "inuse", "in-use", "active")
        for root, dirs, files in os.walk(path, followlinks=False):
            dirs[:] = [d for d in dirs if not is_link(Path(root) / d)]
            for name in files:
                low = name.lower()
                if any(tok in low for tok in lock_tokens):
                    return True
                # A very recently touched file indicates an active producer.
                try:
                    if time.time() - (Path(root) / name).lstat().st_mtime < 300:
                        return True
                except OSError:
                    continue
        return False

    def _deep_junk_sweep(self):
        roots = self._system_roots
        local, roaming = roots.get("LOCALAPPDATA"), roots.get("APPDATA")
        user_temp = roots.get("USER_TEMP")
        system_temp = roots.get("SYSTEM_TEMP")
        user_profile = roots.get("USERPROFILE")
        drive_temp = roots.get("DRIVE_TEMP")
        targets = [
            (user_temp, "*-updater", "Updater leftover", PROCESS_AGNOSTIC),
            (user_temp, "*@", "Updater leftover", PROCESS_AGNOSTIC),
            (_rooted(roaming, "ViberPC"), "*/QmlWebCache", "Viber QmlWebCache", "viber"),
            (_rooted(roaming, "ViberPC"), "*/Thumbnails", "Viber Thumbnails", "viber"),
            (local, "*.exe.tmp", "Installer temp", PROCESS_AGNOSTIC),
            (_rooted(local, "Eagle"), "ai-search*.log", "Eagle log", "eagle"),
            (_rooted(local, "Eagle"), "log.old.log", "Eagle old log", "eagle"),
            (_rooted(local, "Yandex"), "Yandex.Disk.2/*.log", "Yandex.Disk log", "yandexdisk"),
            (_rooted(roaming, "Autodesk"), "ODIS/DDA.log", "Autodesk ODIS log", PROCESS_AGNOSTIC),
            (_rooted(local, "GitHub CLI"), "run-log-*.zip", "GitHub CLI run log", "githubcli"),
        ]
        for name in ("startupCache", "cache2", "shader-cache", "crashes", "minidumps"):
            targets.append((_rooted(local, "Mozilla"), f"Firefox/Profiles/*/{name}", f"Firefox {name}", "firefox"))

        min_age_24h = 86400

        # NOTE: .tmp.driveupload (Google Drive upload staging) is intentionally
        # NOT registered here. Upload completion cannot be reliably established
        # from name, age, or process membership alone: an UNKNOWN process
        # snapshot (None) must not be treated as "no Google Drive running", and
        # old staging data may still be unsynchronized user content. Automatic
        # deletion authority is removed for all roots (temp, drive temp, Local
        # Google\DriveFS, profile). See ticket T-215 / T-216.

        # T-213 (T-214 repair): 9router build cache. Narrowed to the exact
        # build root; active work is refused by freshness + lock checks below.
        for r in (user_profile, user_temp, drive_temp, local):
            targets.append((r, ".9router-build", "9router build cache", PROCESS_AGNOSTIC, min_age_24h))

        # T-213 (T-214 repair): user-root node_modules is treated as
        # potentially intentional user data and is NOT auto-deleted.

        # T-213 (T-214 repair): test sandboxes. Narrowed to owned prefixes.
        for r in (user_temp, drive_temp, system_temp):
            targets.append((r, "ctx-fixtures*", "Test sandbox ctx-fixtures", PROCESS_AGNOSTIC, min_age_24h))
            targets.append((r, "testfb*", "Test sandbox testfb", PROCESS_AGNOSTIC, min_age_24h))
            targets.append((r, "CamoSetup*", "Test sandbox CamoSetup", PROCESS_AGNOSTIC, min_age_24h))

        # T-213 (T-214 repair): stale fixture directories. Narrowed to
        # documented producer-owned prefixes only; broad test_* names are not
        # authorized for recursive deletion.
        for r in (system_temp, user_temp, drive_temp):
            for pat in (
                "pytest-*", "audit_checks_*", "audapack_*",
            ):
                targets.append((r, pat, "Stale test fixture", PROCESS_AGNOSTIC, min_age_24h))

        freed = 0
        self.refresh_running()
        for item in targets:
            if len(item) == 5:
                root, pattern, description, owner, min_age = item
            else:
                root, pattern, description, owner = item
                min_age = None
            if root is None or not safe_is_dir(root):
                continue
            with self.target_scope(root):
                if self.guard._root_blocked:
                    continue
                try:
                    for candidate in root.glob(pattern):
                        self.check_cancel()
                        if is_link(candidate):
                            continue
                        if min_age is not None:
                            try:
                                latest = self._subtree_latest_mtime(candidate)
                            except OSError:
                                continue
                            if latest is None or (time.time() - latest < min_age):
                                continue
                        # Active-work / lock / retained-evidence refusal.
                        if candidate.is_dir() and self._has_active_markers(candidate):
                            self.log.skipped(candidate, "Active work, lock or retained evidence present; not authorized")
                            continue
                        # pytest fixtures are never deleted while a pytest/python
                        # worker is actually running.
                        if pattern.startswith("pytest-") and any("pytest" in str(p) for p in (self.running or ())):
                            self.log.skipped(candidate, "pytest worker running; not authorized")
                            continue
                        # Owner gate shared by dry-run and delete (candidate truth).
                        if owner not in (None, PROCESS_AGNOSTIC) and not self._owner_gate_ok(owner):
                            self.log.skipped(candidate, f"'{owner}' running or unknown; not authorized")
                            continue
                        if not self.guard.is_safe(candidate)[0]:
                            continue
                        if candidate.is_dir():
                            freed += self._del_dir(candidate, f"{description}: {candidate.name}", owner_group=owner)
                        elif candidate.is_file():
                            freed += self._del_file(candidate, f"{description}: {candidate.name}", owner_group=owner)
                except OSError as exc:
                    self.log.warning(f"Could not enumerate {description}: {exc}")
        return freed


class CustomCleaner(CleanerEngine):

    """Executes user-defined cleaning rules."""

    def __init__(self, dry_run: bool, log: Logger, rules: list[dict], max_threads: int = DEFAULT_THREADS, cancel_event: threading.Event | None = None,

                 exclude_patterns: list[str] | None = None, exclude_paths: list[str] | None = None, progress=None, ledger: CandidateLedger | None = None):

        super().__init__(dry_run, log, SafetyGuard(Path("C:\\")), Path("C:\\"), max_threads, cancel_event,

                         exclude_patterns=exclude_patterns, exclude_paths=exclude_paths, progress=progress, ledger=ledger)

        self.rules = rules


    def run_all(self) -> int:

        if not self.rules: return 0

        self.log.section("Custom Rules")

        freed = 0


        for rule in self.rules:
            if not rule.get("enabled", True):
                continue

            path_str = rule.get("path", "")

            pattern = rule.get("pattern", "*")

            if not path_str: continue


            target = Path(path_str)

            if is_path_blacklisted(target):

                self.log.warning(f"Custom rule path is protected (blacklisted): {target}")

                continue

            if not safe_is_dir(target):

                self.log.warning(f"Custom rule path not found or not dir: {target}")

                continue


            self.guard = self.make_guard(target)

            guard = self.guard


            try:

                if pattern == "*":

                    freed += self._del_dir_contents(target, f"Custom: {target}", owner_group=PROCESS_AGNOSTIC)

                else:

                    for item in target.glob(pattern):

                        if guard.is_safe(item)[0]:

                            if item.is_file(): freed += self._del_file(item, f"Custom: {item.name}")

                            elif item.is_dir(): freed += self._del_dir(item, f"Custom: {item.name}")

            except (OSError, ValueError, NotImplementedError) as e:

                self.log.error(f"Custom rule failed on {target}: {e}")


        return freed

    def make_guard(self, root, allow_shallow_system_target=False, protect_against_blacklist=True):
        return super().make_guard(root, False, protect_against_blacklist=True)



#  CUSTOM RULES CONFIG



def _blacklisted_windows_root() -> Path:
    """OS-authoritative Windows root for the never-delete blacklist (T-199).

    The env WINDIR fallback serves non-Windows/test hosts only: on Windows the
    blacklist must name the real directory even when WINDIR is poisoned, so a
    hostile env can never unprotect the actual C:\\Windows.
    """
    if _os_windir is not None:
        return _os_windir
    return Path(os.environ.get("windir", r"C:\Windows")).resolve()


BLACKLIST_PATHS = {

    Path("C:\\").resolve(),

    _blacklisted_windows_root(),

    Path(os.environ.get("USERPROFILE", r"C:\Users")).resolve(),

    Path(os.environ.get("ProgramFiles", r"C:\Program Files")).resolve(),

    Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")).resolve(),

    SCRIPT_PATH.parent,

    BASE_DIR,

}


def is_path_blacklisted(p: Path) -> bool:
    r"""Reject a protected root AND every descendant of it (P1-10).

    Protected roots: C:\, Windows, USERPROFILE, Program Files (both), and the
    cleaner's own source/base dirs. This is the single rule used for portable
    roots, custom rules and direct deletion.
    """
    try:
        p = p.resolve()
    except OSError:
        return True

    if not p.is_absolute():
        return True

    # An ancestor of a protected root is equally dangerous (e.g. C:\ covers
    # everything); treat any path that equals a protected root or sits under
    # one as blacklisted.
    for root in BLACKLIST_PATHS:
        try:
            p.relative_to(root)
            return True
        except ValueError:
            try:
                root.relative_to(p)
                return True
            except ValueError:
                continue
    return False


_CONTROL_CHARS = frozenset(chr(i) for i in range(32) if chr(i) not in "\t\n\r")


def normalize_path(raw, require_absolute: bool = True) -> Path | None:
    """Canonicalize a user-supplied path. Fixes slash style, trailing separators,
    dot segments, quotes, duplicates, expands %ENV% vars. Returns None for garbage.

    The canonical (resolved) form is what everything downstream compares against,
    so 'D:\\Portable\\..\\Portable\\' and 'D:/Portable' become one identical path.

    CORE-002: when require_absolute is True, any EXISTING path component that is
    a symlink/junction/reparse point causes immediate rejection (None). This
    prevents a portable/custom root that is itself a link from transferring
    cleanup authority to its destination.
    """
    if not raw or not isinstance(raw, str):
        return None
    raw = raw.strip().strip('"').strip()
    if not raw:
        return None
    if any(c in _CONTROL_CHARS for c in raw):
        return None
    expanded = os.path.expandvars(raw)
    if require_absolute and not os.path.isabs(expanded):
        return None
    # CORE-002: reject link/reparse chains BEFORE resolve.
    if require_absolute and _has_link_or_reparse_component(expanded):
        return None
    try:
        return Path(expanded).resolve()
    except OSError:
        return Path(expanded).absolute()


def _is_ancestor(a: Path, b: Path) -> bool:
    try:
        b.relative_to(a)
        return True
    except ValueError:
        return False


def sanitize_roots(raw_roots) -> tuple[list[str], list[str]]:
    """Canonicalize, dedupe, and reject unsafe portable roots.

    Returns (valid_canonical_paths, rejected_reasons). Layers: canonical form,
    blacklist, duplicates, nested-inside-another-root.
    """
    valid: list[Path] = []
    rejected: list[str] = []
    for raw in raw_roots or []:
        p = normalize_path(raw)
        if p is None:
            rejected.append(f"{raw!r}: invalid or relative path")
            continue
        if is_path_blacklisted(p):
            rejected.append(f"{p}: protected (blacklisted) path")
            continue
        if p in valid:
            continue  # already canonicalized -> duplicates collapse here
        nested_in = next((v for v in valid if _is_ancestor(p, v) or _is_ancestor(v, p)), None)
        if nested_in is not None:
            rejected.append(f"{p}: nested inside another configured root {nested_in}")
            continue
        valid.append(p)
    return [str(p) for p in valid], rejected


def load_config() -> dict:

    """Tolerant loader for display/GUI (never used to authorize a DELETE).

    A missing config creates the default safely. An EXISTING but malformed
    config yields the default snapshot with the errors logged loudly -- the
    destructive boundary must use load_config_strict() so it can fail closed
    instead of silently running with empty exclusions/policy (T-138).

    CORE-005: INVALID provenance is preserved via get_config_state(); callers
    that need to know the state must use that helper rather than relying on
    load_config() alone.
    """

    state, cfg, errors = _load_and_validate()

    if state == ConfigState.INVALID:

        for e in errors:

            logging.getLogger("vac_cleaner").warning(f"Config invalid: {e}")

        return _default_config()

    return cfg


def get_config_state() -> ConfigState:
    """Return current ConfigState for CONFIG_FILE without side effects.

    CORE-005: callers that need to know whether the on-disk config is INVALID
    must use this helper rather than trying to re-parse the file themselves.
    """
    state, _, _ = _load_and_validate()
    return state


def _default_config() -> dict:

    return {

        "custom_rules": [],

        "exclude_patterns": [],

        "exclude_paths": [],

        "auto_clean_interval_hours": 0,

        "lang": "en",

        "window_geometry": "",

        "portable_roots": [],

        "system_targets": {}

    }


def load_config_strict() -> tuple[ConfigState, dict, list[str]]:
    """(valid, config, errors) for the destructive job boundary (T-138).

    Fresh MISSING config -> (True, defaults, []) -- creating a default is safe.
    An EXISTING malformed config -> (False, {}, errors): the DELETE path MUST
    NOT run a destructive job with silently-empty exclusions/policy. Each
    safety-critical field is validated independently, so one malformed field
    can never silently erase the others.
    """
    return _load_and_validate()


def _custom_glob_is_absolute(pattern):
    from pathlib import PureWindowsPath

    candidate = PureWindowsPath(pattern)
    return bool(candidate.drive or candidate.root)


def validate_and_normalize_config_dict(candidate):
    """Validate a detached candidate without reading or writing policy files."""
    default_cfg = _default_config()
    data = copy.deepcopy(candidate)
    # explicit per-field type validation (T-138): a wrong type in any
    # safety-critical field invalidates the WHOLE existing config for DELETE.
    errors: list[str] = []

    if not isinstance(data, dict):

        return ConfigState.INVALID, {}, ["config root must be a JSON object"]

    unknown = set(data) - set(default_cfg) - {"profiles"}
    if unknown:
        errors.append("unknown top-level config keys: " + ", ".join(sorted(map(str, unknown))))

    if not isinstance(data.get("portable_roots", []), list) or any(not isinstance(r, str) for r in data.get("portable_roots", [])):
        errors.append("portable_roots must be a list of path strings")

    rules = data.get("custom_rules", [])
    if not isinstance(rules, list):
        errors.append("custom_rules must be a list of rule objects")
    else:
        for i, r in enumerate(rules):
            if not isinstance(r, dict):
                errors.append(f"custom_rules[{i}] must be an object")
                continue
            path_val = r.get("path")
            if not isinstance(path_val, str) or not path_val.strip():
                errors.append(f"custom_rules[{i}] must have a non-empty string 'path'")
            
            pattern_val = r.get("pattern", "*")
            if not isinstance(pattern_val, str) or not pattern_val.strip():
                errors.append(f"custom_rules[{i}] must have a non-empty string 'pattern'")
            else:
                if _custom_glob_is_absolute(pattern_val) or any(
                    part == ".." for part in re.split(r"[\\/]", pattern_val)
                ) or not any(part not in ("", ".") for part in re.split(r"[\\/]", pattern_val)):
                    errors.append(f"custom_rules[{i}] 'pattern' is not an executable glob (must be relative)")

            if "enabled" in r and not isinstance(r["enabled"], bool):
                errors.append(f"custom_rules[{i}] 'enabled' must be a boolean if present")
                
            allowed_keys = {"path", "pattern", "enabled"}
            for k in r:
                if k not in allowed_keys:
                    errors.append(f"custom_rules[{i}] contains unknown key: {k}")

    ep = data.get("exclude_patterns", [])
    if not isinstance(ep, list) or any(not isinstance(p, str) for p in ep):
        errors.append("exclude_patterns must be a list of strings")

    xp = data.get("exclude_paths", [])
    if not isinstance(xp, list) or any(not isinstance(p, str) for p in xp):
        errors.append("exclude_paths must be a list of strings")

    st = data.get("system_targets", {})
    if not isinstance(st, dict) or any(not isinstance(k, str) or not isinstance(v, bool) for k, v in st.items()):
        errors.append("system_targets must be an object mapping target names to booleans")

    interval = data.get("auto_clean_interval_hours", 0)
    if isinstance(interval, bool) or not isinstance(interval, (int, float)):
        errors.append("auto_clean_interval_hours must be a number")
    elif 0 < interval < 1 / 60:
        errors.append("auto_clean_interval_hours is below the one-minute minimum")
    elif interval < 0 or interval > 8760:
        errors.append("auto_clean_interval_hours must be between 0 and 8760")
    else:
        import math
        if math.isnan(interval) or math.isinf(interval):
            errors.append("auto_clean_interval_hours must be a finite number")

    if not isinstance(data.get("lang", "en"), str):
        errors.append("lang must be a string")

    if not isinstance(data.get("window_geometry", ""), str):
        errors.append("window_geometry must be a string")

    if errors:
        return ConfigState.INVALID, {}, errors

    # T-147/T-138: migration is done IN MEMORY first; nothing is persisted until
    # the whole config has passed type validation AND normalization. A corrupt
    # config stays byte-identical on disk for forensics/recovery (item 3).
    migrated_profiles = "profiles" in data

    if migrated_profiles:

        del data["profiles"]

    if "portable_roots" not in data:

        data["portable_roots"] = default_cfg["portable_roots"]

    roots, root_rejects = sanitize_roots(data.get("portable_roots", []))

    data["portable_roots"] = roots

    for r in root_rejects:

        logging.getLogger("vac_cleaner").warning(f"Portable root rejected: {r}")

    rules = []

    for rule in data.get("custom_rules", []):

        p = normalize_path(rule.get("path", ""))

        if p is None:

            logging.getLogger("vac_cleaner").warning(f"Custom rule dropped (invalid path): {rule.get('path')!r}")

            continue

        if is_path_blacklisted(p):

            logging.getLogger("vac_cleaner").warning(f"Custom rule dropped (protected path): {p}")

            continue

        rules.append({**rule, "path": str(p)})

    data["custom_rules"] = rules

    norm_paths = []
    for ep in data.get("exclude_paths", []):
        p = normalize_path(ep)
        if p is None:
            errors.append(f"exclude_paths contains invalid/unresolvable path: {ep}")
        else:
            norm_paths.append(str(p))
    if errors:
        return ConfigState.INVALID, {}, errors
    data["exclude_paths"] = norm_paths

    raw_st = data.get("system_targets")

    if not isinstance(raw_st, dict):

        raw_st = {}

        data["system_targets"] = {}

    for name in raw_st:
        if name not in SYSTEM_TARGET_DEFAULTS:
            errors.append(f"Unknown system target in config: {name}")

    if errors:
        return ConfigState.INVALID, {}, errors
        
    data["system_targets"] = {k: bool(v) for k, v in raw_st.items() if k in SYSTEM_TARGET_DEFAULTS}

    return ConfigState.VALID, data, []


def _load_and_validate_impl(persist=False):
    try:
        with CONFIG_FILE.open("r", encoding="utf-8") as stream:
            original = json.load(stream)
    except FileNotFoundError:
        data = _default_config()
        if persist and not save_config(data):
            return ConfigState.INVALID, {}, ["Could not persist first-run configuration"]
        return ConfigState.MISSING, data, []
    except (OSError, ValueError) as exc:
        return ConfigState.INVALID, {}, [f"config file unreadable or not valid JSON: {exc}"]
    state, data, errors = validate_and_normalize_config_dict(original)
    if state == ConfigState.INVALID:
        return state, data, errors
    if persist and "profiles" in original and not save_config(data):
        return ConfigState.INVALID, {}, ["Could not persist validated config migration"]
    return state, data, errors


def _load_and_validate(persist=False):
    if not persist:
        return _load_and_validate_impl()
    try:
        with _config_transaction():
            return _load_and_validate_impl(persist=True)
    except (OSError, TimeoutError) as exc:
        return ConfigState.INVALID, {}, [f"Config transaction unavailable: {exc}"]


def bootstrap_config():
    """The explicit writable owner of first-run creation and legacy migration."""
    return _load_and_validate(persist=True)


def read_config_snapshot(create_if_missing=True):
    return _load_and_validate(persist=create_if_missing)


def parse_geometry(geom, default="960x640", min_w=800, min_h=500):
    if not isinstance(geom, str):
        return default
    match = re.fullmatch(r"(\d{1,6})x(\d{1,6})(?:([+-]\d{1,6})([+-]\d{1,6}))?", geom.strip())
    if match is None:
        return default
    width, height = int(match[1]), int(match[2])
    if width > 16384 or height > 16384:
        return default
    return f"{max(width, min_w)}x{max(height, min_h)}{match[3] or ''}{match[4] or ''}"


_CONFIG_RMW_LOCK = threading.RLock()
_CONFIG_LOCK_DEPTH = 0
_CONFIG_LOCK_FD = None
_CONFIG_LOCK_TIMEOUT = 5.0


def _config_lock_path():
    return CONFIG_FILE.with_name("." + CONFIG_FILE.name + ".lock")


def _config_lock_try(fd):
    os.lseek(fd, 0, os.SEEK_SET)
    if os.name == "nt":
        import msvcrt
        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
    else:
        import fcntl
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)


def _config_lock_drop(fd):
    try:
        os.lseek(fd, 0, os.SEEK_SET)
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


@contextmanager
def _config_transaction():
    global _CONFIG_LOCK_DEPTH, _CONFIG_LOCK_FD
    with _CONFIG_RMW_LOCK:
        if _CONFIG_LOCK_DEPTH:
            _CONFIG_LOCK_DEPTH += 1
            try:
                yield
            finally:
                _CONFIG_LOCK_DEPTH -= 1
            return
        CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(_config_lock_path(), os.O_RDWR | os.O_CREAT, 0o600)
        deadline = time.monotonic() + _CONFIG_LOCK_TIMEOUT
        try:
            while True:
                try:
                    _config_lock_try(fd)
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise TimeoutError("Configuration is locked by another writer") from None
                    time.sleep(0.01)
        except BaseException:
            os.close(fd)
            raise
        _CONFIG_LOCK_FD, _CONFIG_LOCK_DEPTH = fd, 1
        try:
            yield
        finally:
            _CONFIG_LOCK_FD, _CONFIG_LOCK_DEPTH = None, 0
            _config_lock_drop(fd)


def _config_fingerprint(config):
    import hashlib
    return hashlib.sha256(json.dumps(config, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


class _ConfigUpdateResult(NamedTuple):
    ok: bool
    reason: str = ""
    message: str = ""

    def __bool__(self):
        return self.ok


def _config_rmw_transaction(merge_fn, expected_fingerprint=None, *, detailed=False):
    def result(ok, reason="", message=""):
        if not ok and message:
            logging.getLogger("vac_cleaner").warning(f"Config update refused: {message}")
        outcome = _ConfigUpdateResult(ok, reason, message)
        return outcome if detailed else outcome.ok

    try:
        with _config_transaction():
            state, latest, errors = read_config_snapshot(create_if_missing=False)
            if state == ConfigState.INVALID:
                return result(False, "invalid_current", "Existing configuration is invalid: " + "; ".join(errors))
            if expected_fingerprint is not None and _config_fingerprint(latest) != expected_fingerprint:
                return result(False, "conflict", "Configuration changed; reopen the editor and retry.")
            merged = merge_fn(copy.deepcopy(latest))
            if merged is None:
                return result(False, "cancelled", "Configuration update was cancelled.")
            state, normalized, errors = validate_and_normalize_config_dict(merged)
            if state == ConfigState.INVALID:
                return result(False, "invalid_candidate", "Invalid changes: " + "; ".join(errors))
            if not save_config(normalized):
                return result(False, "write_error", "Cannot write configuration; check permissions and free disk space.")
            return result(True)
    except TimeoutError as exc:
        return result(False, "lock_timeout", f"Another configuration writer is busy; wait and retry. {exc}")
    except (OSError, ValueError, TypeError) as exc:
        return result(False, "write_error", f"Configuration update failed: {exc}")


def update_config_field(field, value, expected_fingerprint=None):
    return _config_rmw_transaction(
        lambda latest: {**latest, field: value}, expected_fingerprint=expected_fingerprint,
    )


def save_config(config):
    """Replace only a fully flushed private temporary file under the writer lock."""
    import uuid
    tmp_file = None
    try:
        with _config_transaction():
            tmp_file = CONFIG_FILE.parent / f".config.tmp.{uuid.uuid4().hex}"
            try:
                with tmp_file.open("x", encoding="utf-8") as stream:
                    json.dump(config, stream, indent=4)
                    stream.flush()
                    os.fsync(stream.fileno())
                tmp_file.replace(CONFIG_FILE)
            finally:
                tmp_file.unlink(missing_ok=True)
        return True
    except (OSError, TimeoutError, ValueError, TypeError) as exc:
        logging.getLogger("vac_cleaner").warning(f"Failed to save config: {exc}")
        return False


# PROGRESS TRACKER
class ProgressTracker:
    def __init__(self):
        self.lock = threading.Lock()
        self.categories = {}
        self.category_order = []
        self.current_category = ''
        self.start_time = time.time()
        self._revision = 0
    def _bump(self):
        """Increment revision counter. Call under lock."""
        self._revision += 1
    def start_category(self, name, total_estimate=0):
        with self.lock:
            self.current_category = name
            if name not in self.categories:
                self.categories[name] = {'current': 0, 'total': total_estimate, 'bytes': 0, 'status': 'running'}
                self.category_order.append(name)
            else:
                self.categories[name]['status'] = 'running'
            self._bump()
    def advance(self, bytes_freed=0):
        with self.lock:
            if self.current_category and self.current_category in self.categories:
                c = self.categories[self.current_category]
                c['current'] += 1
                c['bytes'] += bytes_freed
                self._bump()
    def finish_category(self, status='done', total_bytes=None):
        with self.lock:
            if self.current_category and self.current_category in self.categories:
                c = self.categories[self.current_category]
                c['status'] = status
                if total_bytes is not None:
                    c['total'] = total_bytes
                self._bump()
    def get_snapshot(self):
        with self.lock:
            items_done = 0; total_bytes = 0; planned_bytes = 0; cats = []
            for name in self.category_order:
                c = self.categories.get(name, {})
                cur = c.get('current', 0); t = c.get('total', 0)
                items_done += cur; total_bytes += c.get('bytes', 0)
                if t > 0: planned_bytes += t
                cats.append({'name': name, 'current': cur, 'total': t, 'bytes': c.get('bytes', 0), 'status': c.get('status', 'pending')})
            elapsed = time.time() - self.start_time
            running_unknown = any(c.get('status') == 'running' and c.get('total', 0) <= 0 for c in self.categories.values())
            return {'categories': cats, 'total_current': items_done, 'total_bytes': total_bytes,
                    'total_items_done': items_done, 'total_bytes_planned': planned_bytes,
                    'running_unknown_total': running_unknown, 'elapsed': elapsed,
                    'current_category': self.current_category, 'revision': self._revision}


# Only targets with a real, safe implementation live here (P2-14). Risky
# opt-in actions default to False and are reachable ONLY via explicit
# --sys-targets, never via --all (P1-7).
SYSTEM_TARGET_DEFAULTS = {
    'System Temp': True, 'User Temp': True, 'App CrashDumps': True, 'Explorer Thumbnails': True,
    'Windows Update Cache': False, 'DNS Cache': False, 'Recycle Bin': False,
    'Deep C: Junk': True,
}

def merged_system_targets(overrides) -> dict[str, bool]:
    """Persisted per-target preferences (T-108) over the safe defaults.

    Only declared SYSTEM_TARGET_DEFAULTS names are honored; unknown names are
    rejected (dropped). Used by the GUI session state, which is also what the
    scheduled-task / background argv is built from (T-106). The plain CLI clean
    path intentionally keeps the safe defaults -- risky opt-ins reach it only
    through an explicit --sys-targets (P1-7).
    """
    out = dict(SYSTEM_TARGET_DEFAULTS)
    for name, val in (overrides or {}).items():
        if name in SYSTEM_TARGET_DEFAULTS:
            out[name] = bool(val)
    return out

def calculate_target_sizes(targets, exclude_patterns=None, exclude_paths=None):
    """Per-target planned bytes from the SAME read-only planner as dry-run (F4).

    Runs a quiet dry-run SystemCleaner, so every gate the real dry-run applies
    -- process ownership, exclusions, NEVER_DELETE names, depth, symlink
    refusal -- applies here too. This replaces the old raw get_size() pseudo
    cleaner whose numbers never matched a real dry-run. Returns a dict of
    target-name -> planned bytes (only targets whose block actually ran).
    """
    log = Logger(log_file=None, dry_run=True, quiet=True)
    c = SystemCleaner(True, log, DEFAULT_THREADS, targets, None,
                      exclude_patterns=exclude_patterns, exclude_paths=exclude_paths)
    c.run_all()
    return dict(c.results)

def _canonical_exclusions(patterns, paths):
    """Dedupe + canonicalize exclusions so every cleaner sees one identical set (P0-3)."""
    pats = list(dict.fromkeys(p for p in (patterns or []) if p and str(p).strip()))
    pths = []
    for p in (paths or []):
        norm = normalize_path(str(p)) if isinstance(p, str) else normalize_path(str(Path(p)))
        if norm is not None and str(norm) not in pths:
            pths.append(str(norm))
    return pats, pths


class JobSpec:
    """ONE resolved policy contract per job (T-126).

    Everything a job needs is resolved HERE, once, at the surface boundary:
    the frozen config snapshot, portable roots, custom rules, exclusions,
    the resolved system-target mask and the execution surface. Cleaners
    consume ONLY this immutable snapshot -- there is no downstream policy
    reconstruction (CLI/status/GUI/background/scheduled all resolve through
    the same function). The CandidateLedger is job-shared so one physical
    candidate is planned once across every layer.
    """

    __slots__ = ("config", "dry_run", "exclude_paths", "exclude_patterns",
                 "ledger", "run_custom", "run_portable", "run_system", "surface", "sys_targets",
                 "system_roots")

    def __init__(self, *, dry_run, run_portable, run_system, run_custom, config,
                 sys_targets, exclude_patterns, exclude_paths, ledger, surface="cli",
                 system_roots=None):
        import copy
        import types
        self.dry_run = bool(dry_run)
        self.run_portable = bool(run_portable)
        self.run_system = bool(run_system)
        self.run_custom = bool(run_custom)
        self.config = types.MappingProxyType(copy.deepcopy(config))
        self.sys_targets = types.MappingProxyType(dict(sys_targets))
        self.exclude_patterns = tuple(exclude_patterns)
        self.exclude_paths = tuple(exclude_paths)
        self.ledger = ledger
        self.surface = surface
        self.system_roots = types.MappingProxyType(system_roots if system_roots is not None else resolve_system_roots())


def resolve_system_roots() -> dict:
    """Validated destructive system-root snapshot (T-147).

    Every env-derived root has already passed provenance validation at module
    init; invalid/uncertain roots are None (target disabled), never a fallback.
    The JobSpec carries this snapshot so all surfaces share the same validated
    root provenance for the whole run.
    """
    return {
        "SYSTEM_TEMP": SYSTEM_TEMP,
        "USER_TEMP": USER_TEMP,
        "USER_CRASH": USER_CRASH,
        "USER_EXPLORER": USER_EXPLORER,
        "LOCALAPPDATA": _LOCALAPPDATA,
        "APPDATA": _APPDATA,
        "WINDIR": _get_windows_directory_win(),
        "appdata_target_count": len(USER_APPDATA_TARGETS),
        "USER_APPDATA_TARGETS": tuple(USER_APPDATA_TARGETS),
        "USERPROFILE": _real_user_profile(),
        "DRIVE_TEMP": _resolve_active_drive_temp(),
    }


def resolve_job_spec(*, dry_run, run_portable, run_system, run_custom, config,
                     sys_targets=None, cli_excludes=(), cli_enable=(), cli_disable=(),
                     surface="cli") -> JobSpec:
    """Resolve every policy input ONCE into one immutable JobSpec (T-126).

    Surface semantics (the ONLY place policy is reconstructed):
      "gui"/"background"/"scheduled" - the FULL GUI target state (enable risky
          AND disable safe deviations; foreground/preview/bg/schedule all
          resolve to the identical mask).
      "cli"      - SAFE defaults + explicit --sys-targets enables and
                   --disable-targets disables. Plain --all never silently
                   enables risky targets (P1-7).
      "status"   - the same SAFE CLI policy (documented --status contract).
    Saved exclude_patterns/exclude_paths ALWAYS apply on every surface.
    """
    cfg = copy.deepcopy(config)
    if surface in ("gui", "background", "scheduled"):
        mask = merged_system_targets(sys_targets if sys_targets is not None else cfg.get("system_targets"))
    else:
        mask = dict(SYSTEM_TARGET_DEFAULTS)
        for name in cli_enable:
            if name in SYSTEM_TARGET_DEFAULTS:
                mask[name] = True
        for name in cli_disable:
            if name in SYSTEM_TARGET_DEFAULTS:
                mask[name] = False
    exclude_patterns, exclude_paths = _canonical_exclusions(
        list(cfg.get("exclude_patterns", [])) + list(cli_excludes),
        cfg.get("exclude_paths", []))
    return JobSpec(dry_run=dry_run, run_portable=run_portable, run_system=run_system,
                   run_custom=run_custom, config=cfg, sys_targets=mask,
                   exclude_patterns=exclude_patterns, exclude_paths=exclude_paths,
                   ledger=CandidateLedger(), surface=surface)


def run_cleaning_job(spec, log, cancel_event=None, progress=None):
    """Execute (or, when spec.dry_run, plan) one job from a resolved JobSpec.

    Consumes ONLY the immutable spec (T-126): frozen config snapshot, resolved
    exclusions, resolved system-target mask and the job-shared CandidateLedger.
    Never reloads config, never re-resolves policy.

    Returns a results dict with the per-layer planned/freed bytes and the
    per-target system results -- the single source of truth shared by dry-run,
    --status and the GUI preview/progress estimation (F4/T-114).
    """
    cfg = spec.config
    exclude_patterns = list(spec.exclude_patterns)
    exclude_paths = list(spec.exclude_paths)
    dry_run = spec.dry_run
    max_threads = DEFAULT_THREADS
    results: dict = {}
    log.header(f"Smart VAC Cleaner v{VERSION} | {'DRY-RUN' if dry_run else 'DELETE MODE'} | {datetime.now().astimezone()}")
    if dry_run: log.info('[DRY-RUN] Nothing will be deleted.')
    else: log.info('[WARNING] DELETE MODE active!')
    if spec.run_portable:
        roots = [Path(r) for r in cfg.get('portable_roots', []) if safe_exists(r)]
        if not roots:
            log.info('No portable roots configured (see cleaner_config.json) - skipped.')
        if progress: progress.start_category('Portable')
        portable_freed = 0
        for r in roots:
            if cancel_event and cancel_event.is_set(): raise CancelJobException('Cancelled')
            portable_freed += PortableCleaner(dry_run, log, SafetyGuard(r), r, max_threads, cancel_event, exclude_patterns=exclude_patterns, exclude_paths=exclude_paths, progress=progress, ledger=spec.ledger).run_all()
        if progress: progress.finish_category(total_bytes=portable_freed)
        results['portable'] = portable_freed
    if spec.run_system:
        if cancel_event and cancel_event.is_set(): raise CancelJobException('Cancelled')
        if progress: progress.start_category('System')
        sc = SystemCleaner(dry_run, log, max_threads, spec.sys_targets, cancel_event, exclude_patterns=exclude_patterns, exclude_paths=exclude_paths, progress=progress, ledger=spec.ledger, system_roots=spec.system_roots)
        system_freed = sc.run_all()
        results['system'] = dict(sc.results)
        results['system_bytes'] = system_freed
        if progress: progress.finish_category(total_bytes=system_freed)
    if spec.run_custom:
        if cancel_event and cancel_event.is_set(): raise CancelJobException('Cancelled')
        rules = cfg.get('custom_rules', [])
        if rules:
            if progress: progress.start_category('Custom')
            custom_freed = CustomCleaner(dry_run, log, rules, max_threads, cancel_event, exclude_patterns=exclude_patterns, exclude_paths=exclude_paths, progress=progress, ledger=spec.ledger).run_all()
            if progress: progress.finish_category(total_bytes=custom_freed)
        else:
            custom_freed = 0
        results['custom'] = custom_freed
    log.summary()
    return results

def cli_status():
    """--status: planned bytes from the SAME read-only planner as dry-run (F4/T-127).

    Resolves ONE JobSpec with the documented status policy:
      - SAFE CLI system-target mask (no config prefs, no explicit targets)
      - saved exclude_patterns/exclude_paths DO apply
    and runs the shared dry-run planner. The candidate truth is identical to a
    dry-run for the same snapshot/config.
    """
    state, config, config_errors = load_config_strict()
    if state == ConfigState.INVALID:
        for e in config_errors:
            print(f"Warning: config invalid - {e}")
        config = _default_config()
    spec = resolve_job_spec(dry_run=True, run_portable=True, run_system=True, run_custom=True,
                            config=config, surface="status")
    print(f"Smart VAC Cleaner v{VERSION}")
    print(f"Config: {CONFIG_FILE}")
    print(f"Custom rules: {len(config.get('custom_rules', []))}")
    quiet = Logger(log_file=None, dry_run=True, quiet=True)
    results = run_cleaning_job(spec, quiet)
    sizes = results.get("system", {})
    print('System targets:')

    for name, sz in sorted(sizes.items()):
        if sz > 0: print(f'  {fmt(sz):>10}  {name}')
    total = sum(sizes.values())
    total += results.get('portable', 0)
    total += results.get('custom', 0)
    if results.get('portable'):
        print(f'  {fmt(results["portable"]):>10}  PORTABLE')
    if results.get('custom'):
        print(f'  {fmt(results["custom"]):>10}  CUSTOM')
    print(f'  {"-"*30}')
    print(f'  {fmt(total):>10}  TOTAL')


# ── Canonical Golden Default Tokens (UI.md / Wintage spec) ──────────
WIN95_BG             = '#1A1810'  # --background
WIN95_BG_SOFT        = '#232018'  # --backgroundSoft
WIN95_SURFACE        = '#332E22'  # --surface
WIN95_SURFACE_RAISED = '#3D372A'  # --surfaceRaised
WIN95_SURFACE_ALT    = '#453D30'  # --surfaceAlt

WIN95_BORDER_DARK    = '#100E08'  # --borderDark
WIN95_BORDER_HI      = '#F0D060'  # --borderHighlight
WIN95_BEVEL_HI       = '#75663D'  # --bevelLight
WIN95_BORDER_MUTED   = '#5A5040'  # --borderMuted

WIN95_TEXT           = '#D4C89A'  # --textPrimary
WIN95_TEXT_DIM       = '#9C9371'  # --textSecondary
WIN95_TEXT_MUTED     = '#6E674E'  # --textMuted

WIN95_ACCENT_TEAL    = '#008080'  # --accentTeal
WIN95_ACCENT_DEEP    = '#004C4C'  # --accentTealDeep

WIN95_SUCCESS        = '#4A7A20'  # --success
WIN95_WARNING        = '#7A7A20'  # --warning
WIN95_DANGER         = '#7A2020'  # --danger
WIN95_DANGER_TEXT    = '#D66464'  # --dangerText (UI.md line 132: high-contrast danger text)

WIN95_SELECTION      = '#3D372A'  # --selection
WIN95_COMPARE_BACK   = '#14120C'  # --compareBack
WIN95_LINK           = '#F0D060'  # --link

# Semantic aliases conforming to UI.md component rules
WIN95_BUTTON         = WIN95_SURFACE_RAISED  # '#3D372A' (UI.md line 180: background is surfaceRaised)
WIN95_BUTTON_HOVER   = WIN95_SURFACE_ALT     # '#453D30' (UI.md line 205: hover is surfaceAlt)
WIN95_BUTTON_TEXT    = WIN95_TEXT            # '#D4C89A' (UI.md line 193: button color is textPrimary)
WIN95_ACCENT         = WIN95_TEXT            # UI.md line 193: button text is textPrimary, NOT dark teal!
WIN95_GOLD           = WIN95_BORDER_HI       # '#F0D060' (UI.md line 118: borderHighlight)
WIN95_GOLD_DIM       = WIN95_TEXT_DIM        # '#9C9371'
WIN95_DANGER_BTN_TXT = WIN95_DANGER_TEXT     # '#D66464'
WIN95_ENTRY          = WIN95_COMPARE_BACK    # '#14120C' (UI.md line 222: inputs use compareBack)

Z = 0  # UI.md Iron law 2: zero rounded corners everywhere (sharp 90° rectangles)

BEVEL_RAISED = WIN95_BEVEL_HI     # '#75663D' (UI.md line 179: border on raised controls)
BEVEL_SUNKEN = WIN95_BORDER_DARK   # '#100E08' (UI.md line 185: border on sunken/entry controls)

# UI.md Iron law 1: Verdana, non-antialiased everywhere, sizes only 10/11/12/14/16px
native_font      = ('Verdana', 11)        # buttons and standard controls
native_font_bold = ('Verdana', 11, 'bold')
body_font        = ('Verdana', 12)        # default body size (UI.md line 244)
title_font       = ('Verdana', 14, 'bold')# section headers (UI.md line 246)
stats_font       = ('Verdana', 10)        # secondary metadata (UI.md line 245)
data_font        = ('Consolas', 10)       # technical logs (UI.md line 335)

if ctk is not None:
    ctk.set_appearance_mode('dark')
    ctk.set_default_color_theme('dark-blue')



class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        bootstrap_config()
        self.config = load_config()
        self.T = load_strings(self.config.get("lang", "en"))
        self.title(f"{self.T['window_title']} v{VERSION}")
        self.geometry(parse_geometry(self.config.get("window_geometry", "")))
        self.minsize(800, 500)
        self.configure(fg_color=WIN95_BG)
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.progress = ProgressTracker()
        self._pulse = 0  # F8: indeterminate-pulse phase counter
        self.log_queue = _GuiLogBuffer()
        self._auto_clean_pending = False
        self._auto_clean_generation = 0
        self.cancel_event = threading.Event()
        self.sys_targets = merged_system_targets(self.config.get("system_targets"))
        self._clean_in_progress = False
        # T-209: explicit single-owner startup gate. Tk modal dialogs run a
        # nested event loop on this same thread, so another callback can reenter
        # the launch path while a confirmation is still open.
        self._job_starting = False
        self._clean_timer = None
        self._bg_proc = None
        self._lease = None
        self._worker_thread = None
        self._job_done_event = threading.Event()
        self._close_pending = False
        self.dash_cat_widgets = {}
        self._build_ui()
        self._schedule_auto_clean()
        self.after(500, self._create_tray_icon)
        # T-093: ONE main-thread poller owns all Tk/after calls; worker threads
        # only put() to log_queue and set() the job-done event.
        self.after(150, self._poll_main)

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=0, minsize=220)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        side = ctk.CTkFrame(self, fg_color=WIN95_BG_SOFT, corner_radius=Z, width=220)
        side.grid(row=0, column=0, sticky="nsew")
        side.grid_rowconfigure(20, weight=1)
        side.grid_columnconfigure(0, weight=1)
        row = 0
        ctk.CTkLabel(side, text=f"VAC CLEANER v{VERSION}", font=title_font, text_color=WIN95_GOLD).grid(row=row, column=0, pady=(14, 4), padx=8)
        row += 1
        self.btn_clean = ctk.CTkButton(side, text=self.T["clean"], font=("Verdana", 12, "bold"), fg_color=WIN95_BUTTON, hover_color=WIN95_BUTTON_HOVER, text_color=WIN95_DANGER_BTN_TXT, corner_radius=Z, height=34, border_width=2, border_color=BEVEL_RAISED, command=lambda: self._start_job())
        self.btn_clean.grid(row=row, column=0, pady=(16, 6), padx=10, sticky="ew")
        row += 1
        self.btn_stop = ctk.CTkButton(side, text=self.T["stop"], font=native_font, fg_color=WIN95_BUTTON, hover_color=WIN95_BUTTON_HOVER, text_color=WIN95_TEXT, text_color_disabled=WIN95_TEXT_MUTED, corner_radius=Z, height=30, border_width=2, border_color=BEVEL_RAISED, command=self._cancel_job, state="disabled")
        self.btn_stop.grid(row=row, column=0, pady=4, padx=10, sticky="ew")

        row += 1
        self.btn_preview = ctk.CTkButton(side, text=self.T["preview"], font=native_font, fg_color=WIN95_BUTTON, hover_color=WIN95_BUTTON_HOVER, text_color=WIN95_TEXT, corner_radius=Z, border_width=2, border_color=BEVEL_RAISED, command=self._start_preview)
        self.btn_preview.grid(row=row, column=0, pady=4, padx=10, sticky="ew")

        row += 1
        self.btn_task = ctk.CTkButton(side, text=self.T["install_task"], font=native_font, fg_color=WIN95_BUTTON, hover_color=WIN95_BUTTON_HOVER, text_color=WIN95_TEXT, corner_radius=Z, border_width=2, border_color=BEVEL_RAISED, command=self._install_scheduled_task)
        self.btn_task.grid(row=row, column=0, pady=4, padx=10, sticky="ew")
        row += 1
        self.btn_bg = ctk.CTkButton(side, text=self.T["run_bg"], font=native_font, fg_color=WIN95_BUTTON, hover_color=WIN95_BUTTON_HOVER, text_color=WIN95_TEXT, corner_radius=Z, border_width=2, border_color=BEVEL_RAISED, command=self._run_bg)
        self.btn_bg.grid(row=row, column=0, pady=4, padx=10, sticky="ew")
        row += 1
        self.btn_exc = ctk.CTkButton(side, text=self.T["exclusions"], font=native_font, fg_color=WIN95_BUTTON, hover_color=WIN95_BUTTON_HOVER, text_color=WIN95_TEXT, corner_radius=Z, border_width=2, border_color=BEVEL_RAISED, command=self._open_exclusions)
        self.btn_exc.grid(row=row, column=0, pady=4, padx=10, sticky="ew")
        row += 1
        self.btn_syst = ctk.CTkButton(side, text=self.T["sys_targets"], font=native_font, fg_color=WIN95_BUTTON, hover_color=WIN95_BUTTON_HOVER, text_color=WIN95_TEXT, corner_radius=Z, border_width=2, border_color=BEVEL_RAISED, command=self._open_system_targets)
        self.btn_syst.grid(row=row, column=0, pady=4, padx=10, sticky="ew")
        self.main_frame = ctk.CTkFrame(self, fg_color=WIN95_BG, corner_radius=Z)
        self.main_frame.grid(row=0, column=1, sticky="nsew", padx=(4,4), pady=4)
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(3, weight=1)
        dash = ctk.CTkFrame(self.main_frame, fg_color=WIN95_BG_SOFT, corner_radius=Z)
        dash.grid(row=0, column=0, sticky="ew")
        dash.grid_columnconfigure(0, weight=1)
        self.dash_stats = ctk.CTkLabel(dash, text="", font=stats_font, text_color=WIN95_TEXT, anchor="w")
        self.dash_stats.grid(row=0, column=0, sticky="ew", padx=8, pady=(6,0))
        self.dash_cat_container = ctk.CTkFrame(dash, fg_color="transparent", corner_radius=Z, height=0)
        self.dash_cat_container.grid(row=1, column=0, sticky="ew", padx=8, pady=(2,0))
        self.dash_cat_container.grid_columnconfigure(0, weight=1)
        self.dash_cat_container.grid_propagate(False)
        self.dash_bar = ctk.CTkProgressBar(dash, fg_color=WIN95_ENTRY, progress_color=WIN95_GOLD, corner_radius=Z, height=12)
        self.dash_bar.grid(row=2, column=0, sticky="ew", padx=8, pady=(4,2))
        self.dash_bar.set(0)
        self.text_log = ctk.CTkTextbox(self.main_frame, fg_color=WIN95_ENTRY, text_color=WIN95_TEXT, font=data_font, corner_radius=Z, border_width=2, border_color=BEVEL_SUNKEN, state="disabled")
        self.text_log.grid(row=3, column=0, sticky="nsew", pady=(4,0))

    def _on_close(self):
        # T-094: request cancellation; actual destroy happens only after the
        # worker thread terminates (polled from the main thread).
        self.cancel_event.set()
        if hasattr(self,"_tray_icon") and self._tray_icon:
            try:
                self._tray_icon.stop()
            except Exception as exc:
                logging.getLogger("vac_cleaner").debug(f"Tray icon stop error: {exc}")
        if self._clean_timer: self._clean_timer.cancel()
        self._persist_window_geometry()
        self._close_pending = True
        self.btn_clean.configure(state="disabled")
        self.btn_preview.configure(state="disabled")
        self.btn_stop.configure(state="disabled")
        if self._worker_thread is None or not self._worker_thread.is_alive():
            self._full_exit_impl()

    def _persist_window_geometry(self):
        try:
            update_config_field("window_geometry", parse_geometry(self.geometry()))
        except Exception as exc:
            logging.getLogger("vac_cleaner").debug(f"Persist geometry error: {exc}")

    def _full_exit_impl(self):
        if self.__dict__.get("_exit_done", False):
            return
        worker = self.__dict__.get("_worker_thread")
        if worker is not None and worker.is_alive():
            return
        self._exit_done = True
        self._close_pending = True
        timer = self.__dict__.get("_clean_timer")
        if timer is not None:
            timer.cancel()
        lease = self.__dict__.get("_lease")
        if lease is not None:
            lease.release()
            self._lease = None
        self.quit()
        self.destroy()

    def _start_job(self):
        self._launch_foreground(False)


    def _launch_foreground(self, dry_run):
        # T-209: the single-owner startup gate. It is set before the modal
        # confirmation and only cleared in the finally, so a reentrant callback
        # from the dialog's nested event loop is refused instead of starting a
        # second job and replacing the first worker and lease.
        if self._clean_in_progress or self._close_pending or self.__dict__.get("_job_starting", False):
            return
        self._job_starting = True
        try:
            state, config, errors = load_config_strict()
            if state == ConfigState.INVALID:
                messagebox.showerror(self.T.get("error_title", "Error"), "Configuration is invalid.\n" + "\n".join(errors), parent=self)
                return
            targets = merged_system_targets(config.get("system_targets"))
            try:
                spec = resolve_job_spec(dry_run=dry_run, run_portable=True, run_system=True,
                                        run_custom=True, config=config, sys_targets=targets, surface="gui")
            except (OSError, ValueError, TypeError) as exc:
                self._log(_GuiLogMessage(f"Could not resolve cleaning policy: {exc}", "error"))
                return
            if not dry_run and not messagebox.askyesno(
                self.T["confirm_title"],
                self.T["confirm_body"],
                parent=self, icon="warning", default="no",
            ):
                return
            # Ownership revalidation after the modal: the nested event loop may
            # have started a job or opened shutdown while we waited for it.
            # (_job_starting is this call's own gate and is intentionally not
            # re-checked here.)
            if self._clean_in_progress or self._close_pending:
                return
            stale = self.__dict__.get("_lease")
            if stale is not None:
                stale_worker = self.__dict__.get("_worker_thread")
                if stale_worker is None or not stale_worker.is_alive():
                    stale.release()  # never release while its worker is alive
                self._lease = None
            if not dry_run:
                lease = _JobLease()
                if not lease.acquire():
                    self._log(_GuiLogMessage("Another clean job is running or the lease is unavailable. Please wait.", "warning"))
                    return
                self._lease = lease
            try:
                self.config, self.sys_targets = config, targets
                self._rebuild_cat_bars()
                self._reset_dashboard()
                self._clean_in_progress = True
                self.cancel_event.clear()
                self.btn_clean.configure(state="disabled")
                self.btn_preview.configure(state="disabled")
                self.btn_stop.configure(state="normal")
                self.text_log.configure(state="normal")
                self.text_log.delete("1.0", "end")
                self.text_log.configure(state="disabled")
                self.progress = ProgressTracker()
                self._job_done_event.clear()
                self._worker_thread = threading.Thread(target=self._run_job, args=(spec,), daemon=True)
                self._worker_thread.start()
            except Exception as exc:
                self._abort_failed_start(exc)
        finally:
            self._job_starting = False

    def _abort_failed_start(self, exc):
        """Failed-start rollback (T-209). Idempotent: if the worker somehow
        already runs, ownership stays with it and the poller resets later;
        otherwise cancel, release the lease and return to idle."""
        worker = self.__dict__.get("_worker_thread")
        if worker is not None and worker.is_alive():
            self._log(_GuiLogMessage(f"Could not start cleaning: {exc}", "error"))
            return
        self.cancel_event.set()
        self._reset_to_idle()
        self._log(_GuiLogMessage(f"Could not start cleaning: {exc}", "error"))


    def _reset_to_idle(self):
        worker = self.__dict__.get("_worker_thread")
        if worker is not None and worker.is_alive():
            return False
        lease = self.__dict__.get("_lease")
        if lease is not None:
            lease.release()
        self._lease = None
        self._clean_in_progress = False
        self._worker_thread = None
        self._job_done_event.clear()
        state = "disabled" if self._close_pending else "normal"
        self.btn_clean.configure(state=state)
        self.btn_preview.configure(state=state)
        self.btn_stop.configure(state="disabled")
        self._schedule_auto_clean()
        return True


    def _policy_edit_allowed(self):
        worker = self.__dict__.get("_worker_thread")
        process = self.__dict__.get("_bg_proc")
        active = self._clean_in_progress or (worker is not None and worker.is_alive())
        if process is not None:
            try:
                active = active or process.poll() is None
            except OSError:
                active = True
        if active:
            self._log(_GuiLogMessage("Stop or wait for the active job before changing its safety policy.", "warning"))
            return False
        return True

    def _start_preview(self):
        self._launch_foreground(True)

    def _run_job(self, spec):
        try:
            log = Logger(LOGS_DIR/f"clean_{datetime.now().astimezone():%Y%m%d_%H%M%S}.log", spec.dry_run, gui_callback=self._log)
            # T-126/T-128: the worker consumes ONLY the frozen JobSpec. It never
            # reads self.config / self.sys_targets after start.
            run_cleaning_job(spec, log, cancel_event=self.cancel_event, progress=self.progress)
        except CancelJobException:
            self._log(_GuiLogMessage(self.T["cancelled"], "summary"))
        except Exception as e:
            self._log(_GuiLogMessage(f"Error: {e}", "error"))
        finally:
            # T-093: the worker never touches Tk; it only signals the main-thread poller.
            self._job_done_event.set()

    def _finish_job(self):
        state, refreshed, _ = read_config_snapshot(create_if_missing=False)
        if state == ConfigState.VALID:
            self.config = refreshed
            self.sys_targets = merged_system_targets(refreshed.get("system_targets"))
        self._reset_to_idle()

    def _cancel_job(self):
        self.cancel_event.set()
        self._log(self.T["cancelling"])

    _AUTO_CLEAN_MARKER = "__AUTO_CLEAN__"
    _CLOSE_MARKER = "__CLOSE__"

    def _log(self, m):
        # T-093: worker-safe -- never calls Tk/after from this path.
        if not isinstance(self.log_queue, _GuiLogBuffer):
            # Production creates the bounded buffer directly. This one-time
            # conversion supports callers supplying a standard Queue.
            init_lock = self.__dict__.setdefault("_log_init_lock", threading.Lock())
            with init_lock:
                if not isinstance(self.log_queue, _GuiLogBuffer):
                    previous = self.log_queue
                    replacement = _GuiLogBuffer(previous.maxsize or 8192)
                    while True:
                        try:
                            item = previous.get_nowait()
                        except queue.Empty:
                            break
                        kind = "control" if item in (self._AUTO_CLEAN_MARKER, self._CLOSE_MARKER) else getattr(item, "kind", "ordinary")
                        replacement.put_nowait(_GuiLogMessage(item, kind))
                    self.log_queue = replacement
        kind = "control" if m in (self._AUTO_CLEAN_MARKER, self._CLOSE_MARKER) else getattr(m, "kind", "ordinary")
        self.log_queue.put_nowait(_GuiLogMessage(m, kind))

    def _poll_main(self):
        """The single main-thread poller (T-093/094). Drains the log queue,
        watches job completion and the shutdown lifecycle, updates the dashboard.

        CORE-010: bounded batch drain with no per-message sleep; yields back to
        Tk between batches so UI events are processed promptly.
        """
        # Drain up to 256 messages per poll cycle to prevent a burst from
        # monopolizing the Tk event loop for seconds.
        drained = 0
        messages = []
        while drained < 256:
            try:
                m = self.log_queue.get_nowait()
            except queue.Empty:
                break
            drained += 1
            if m == self._AUTO_CLEAN_MARKER:
                self._start_job()
                continue
            if m == self._CLOSE_MARKER:
                self._on_close()
                return
            messages.append(str(m))
        self._poll_batch_log(messages)
        if self.__dict__.get("_auto_clean_pending", False):
            generation = self.__dict__.get("_auto_clean_pending_generation")
            self._auto_clean_pending = False
            if not self._close_pending and (generation is None or generation == self.__dict__.get("_auto_clean_generation", 0)):
                try:
                    self._start_job()
                finally:
                    self._schedule_auto_clean()
        self._poll_background_child()
        # CORE-010: only finish/clear worker when BOTH the done event is set
        # AND the retained Thread object reports not alive.
        if self._clean_in_progress and self._job_done_event.is_set():
            w = self._worker_thread
            if w is None or not w.is_alive():
                self._job_done_event.clear()
                self._finish_job()
        if self._clean_in_progress:
            self._update_dashboard()
        if self._close_pending:
            w = self._worker_thread
            if w is None or not w.is_alive():
                self._full_exit_impl()
                return
        self.after(150, self._poll_main)

    def _poll_batch_log(self, messages):
        if not messages:
            return
        self.text_log.configure(state="normal")
        self.text_log.insert("end", "\n".join(messages) + "\n")
        try:
            line_count = int(self.text_log.index("end-1c").split(".")[0])
            if line_count > 1000:
                self.text_log.delete("1.0", f"{line_count - 1000 + 1}.0")
        except (AttributeError, TypeError, ValueError) as exc:
            logging.getLogger("vac_cleaner").debug(f"Log view trim error: {exc}")
        self.text_log.see("end")
        self.text_log.configure(state="disabled")

    def _schedule_auto_clean(self):
        if self._clean_timer:
            self._clean_timer.cancel()
        self._clean_timer = None
        self._auto_clean_generation = self.__dict__.get("_auto_clean_generation", 0) + 1
        self._auto_clean_pending = False
        generation = self._auto_clean_generation
        interval = self.config.get("auto_clean_interval_hours", 0)
        if interval > 0 and not self._close_pending:
            self._clean_timer = threading.Timer(interval * 3600, lambda: self._auto_clean_trigger(generation))
            self._clean_timer.daemon = True
            self._clean_timer.start()

    def _auto_clean_trigger(self, generation=None):
        # Only the main-thread scheduler creates timers. Cancelled callbacks
        # cannot arm a successor or block behind telemetry.
        if self._close_pending:
            return
        if generation is not None and generation != self.__dict__.get("_auto_clean_generation", 0):
            return
        self._auto_clean_pending_generation = generation
        self._auto_clean_pending = True

    def _update_dashboard(self):
        if not self._clean_in_progress:
            return
        s = self.progress.get_snapshot()
        # PERF-008: skip render when progress state hasn't changed and elapsed
        # hasn't crossed a second boundary. This avoids continuous widget work
        # during long scans with no new mutations.
        prev_rev = self.__dict__.get('_dash_last_revision', -1)
        prev_sec = self.__dict__.get('_dash_last_elapsed_sec', -1)
        cur_sec = int(s['elapsed'])
        if s['revision'] == prev_rev and cur_sec == prev_sec:
            return
        self.__dict__['_dash_last_revision'] = s['revision']
        self.__dict__['_dash_last_elapsed_sec'] = cur_sec
        e = f"{int(s['elapsed']//60):02d}:{int(s['elapsed']%60):02d}"
        self.dash_stats.configure(text=f"Items: {s['total_current']}  Freed: {fmt(s['total_bytes'])}  Elapsed: {e}")
        # F8: no fake determinate bars. A determinate fill is shown only when a
        # real planned byte total exists; otherwise the bar is indeterminate
        # (working pulse) -- never a static 0% that implies 'nothing done'.
        self._pulse = getattr(self, "_pulse", 0) + 1
        triangle = abs(((self._pulse % 40) / 20.0) - 1.0)
        if s['total_bytes_planned'] > 0 and not s['running_unknown_total']:
            self.dash_bar.set(min(s['total_bytes'] / s['total_bytes_planned'], 1.0))
        elif s['current_category']:
            self.dash_bar.set(triangle)
        else:
            self.dash_bar.set(0)
        # Auto-create + update per-category bars
        n_cats = len(s['categories'])
        # PERF-008: only resize container when category count changes.
        cur_height = self.__dict__.get('_dash_last_cat_height', -1)
        if n_cats != cur_height:
            self.dash_cat_container.configure(height=n_cats * 22 if n_cats > 0 else 0)
            self.__dict__['_dash_last_cat_height'] = n_cats
        for cat_data in s['categories']:
            nm = cat_data['name']
            if nm not in self.dash_cat_widgets:
                self._add_cat_bar(nm)
            w = self.dash_cat_widgets.get(nm)
            if w:
                tot, byt = cat_data['total'], cat_data['bytes']
                if tot > 0:
                    w['label'].configure(text=f"{nm}: {fmt(byt)}/{fmt(tot)}")
                    w['bar'].set(min(byt / tot, 1.0))
                else:
                    w['label'].configure(text=f"{nm}: {fmt(byt)}" if cat_data['status'] == 'done' else f"{nm}: {fmt(byt)} (scanning)")
                    w['bar'].set(triangle if cat_data['status'] == 'running' and tot <= 0 else 0)

    def _rebuild_cat_bars(self):
        for w in list(self.dash_cat_widgets.values()):
            w['frame'].destroy()
        self.dash_cat_widgets = {}
        self.dash_cat_container.configure(height=0)

    def _reset_dashboard(self):
        self.dash_stats.configure(text='')
        self.dash_bar.set(0)
        for w in self.dash_cat_widgets.values():
            w['label'].configure(text='')
            w['bar'].set(0)

    def _add_cat_bar(self, name, current=0, total=0, bytes_freed=0):
        frame = ctk.CTkFrame(self.dash_cat_container, fg_color='transparent', corner_radius=Z)
        frame.grid_columnconfigure(1, weight=1)
        label = ctk.CTkLabel(frame, text=f'{name}: {current}/{total}  {fmt(bytes_freed)}' if total > 0 else f'{name}: {current}  {fmt(bytes_freed)}', font=stats_font, text_color=WIN95_TEXT_MUTED, anchor='w')
        label.grid(row=0, column=0, sticky='w')
        bar = ctk.CTkProgressBar(frame, fg_color=WIN95_ENTRY, progress_color=WIN95_GOLD, corner_radius=Z, height=6)
        bar.grid(row=0, column=1, sticky='ew', padx=(6,0))
        bar.set(0)
        frame.pack(fill='x', pady=1)
        self.dash_cat_widgets[name] = {'frame': frame, 'label': label, 'bar': bar}

    def _create_tray_icon(self):
        if pystray is None:
            return
        try:
            img = Image.new("RGB", (16, 16), (26, 14, 5))
            d = ImageDraw.Draw(img)
            d.rectangle([2, 2, 13, 13], outline=(200, 168, 78))
            d.line([4, 8, 12, 8], fill=(200, 168, 78))
            d.line([8, 4, 8, 12], fill=(200, 168, 78))
            # T-093: tray callbacks run in the tray thread -- they only enqueue;
            # the main-thread poller starts the job / closes the app.
            def on_cl(ic, it):
                if not self._clean_in_progress:
                    self.log_queue.put(self._AUTO_CLEAN_MARKER)
            def on_ex(ic, it):
                ic.stop()
                self.log_queue.put(self._CLOSE_MARKER)
            self._tray_icon = pystray.Icon("vac_cleaner", img, "VAC", pystray.Menu(pystray.MenuItem(self.T["clean"], on_cl), pystray.MenuItem("Exit", on_ex)))
            self._tray_icon.run_detached()
        except Exception as e:
            logging.getLogger("vac_cleaner").warning(f"Tray icon failed to start: {e}")

    def _install_scheduled_task(self):
        start = simpledialog.askstring(self.T["task_dialog_title"], self.T["task_dialog_prompt"], initialvalue="09:00", parent=self)
        if not start:
            return
        # CORE-006/W2-006: canonical HH:MM parser shared by GUI and CLI.
        parsed = _parse_time_str(start)
        if parsed is None:
            messagebox.showerror(
                self.T.get("error_title", "Error"),
                f"Invalid time format: {start!r}. Expected HH:MM (00-23:00-59).",
                parent=self)
            return
        ok = install_task(parsed, self.sys_targets)
        if ok:
            messagebox.showinfo(
                self.T.get("task_dialog_title", "Task"),
                f"Task installed -> runs daily at {parsed}, silent full clean.",
                parent=self)
        else:
            messagebox.showerror(
                self.T.get("error_title", "Error"),
                "Failed to install scheduled task. Check logs for details.",
                parent=self)

    def _poll_background_child(self):
        process = self.__dict__.get("_bg_proc")
        if process is None:
            return False
        code = process.poll()
        if code is None:
            return True
        self._bg_proc = None
        self._bg_proc_observed = True
        self._bg_proc_retcode = code
        if code == 0:
            message, kind = "Background clean completed successfully.", "summary"
        elif code == EXIT_LEASE_BUSY:
            message, kind = "Another job acquired the lease before background start. Please retry after it finishes.", "warning"
        else:
            message, kind = f"Background clean failed (exit code {code}).", "error"
        self._log(_GuiLogMessage(message, kind))
        return False


    def _run_bg(self):
        if self._clean_in_progress or self._poll_background_child():
            self._log(self.T["run_bg_running"])
            return
        state, config, _ = read_config_snapshot(create_if_missing=False)
        if state == ConfigState.INVALID:
            self._log(_GuiLogMessage("Config invalid; background clean aborted.", "error"))
            return
        lease = _JobLease()
        if not lease.acquire():
            self._log(_GuiLogMessage("Another clean job is running. Background clean deferred.", "warning"))
            return
        # This is a probe only. The child acquires its own lease before mutation.
        lease.release()
        self.config = config
        self.sys_targets = merged_system_targets(config.get("system_targets"))
        flags = 0
        for name in ("DETACHED_PROCESS", "CREATE_NEW_PROCESS_GROUP", "CREATE_NO_WINDOW"):
            flags |= getattr(subprocess, name, 0)
        self._bg_proc_observed = False
        self._bg_proc_retcode = None
        try:
            self._bg_proc = subprocess.Popen(
                background_clean_argv(self.sys_targets), cwd=str(BASE_DIR),
                close_fds=True, creationflags=flags,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        except OSError as exc:
            self._bg_proc = None
            self._log(_GuiLogMessage(f"Error: {exc}", "error"))
            return
        self._log(_GuiLogMessage(self.T["run_bg_started"], "summary"))

    def _open_exclusions(self):
        if not self._policy_edit_allowed():
            return
        win = ctk.CTkToplevel(self)
        win.title(self.T["exc_title"])
        win.geometry("640x540")
        win.minsize(560, 440)
        win.configure(fg_color=WIN95_BG)
        win.transient(self)
        win.grab_set()
        win.grid_columnconfigure(0, weight=1)
        win.grid_rowconfigure(4, weight=1)

        ctk.CTkLabel(win, text=self.T["exc_help"], font=native_font, text_color=WIN95_TEXT_MUTED, anchor='w').grid(row=0, column=0, sticky='ew', padx=10, pady=(10, 4))
        ctk.CTkLabel(win, text=self.T["exc_patterns"], font=native_font_bold, text_color=WIN95_TEXT, anchor='w').grid(row=1, column=0, sticky='ew', padx=10)
        txt = ctk.CTkTextbox(win, fg_color=WIN95_ENTRY, text_color=WIN95_TEXT, font=data_font, corner_radius=Z, border_width=1, border_color=WIN95_BORDER_MUTED)
        txt.grid(row=2, column=0, sticky='nsew', padx=10, pady=(2, 8))
        txt.insert('1.0', "\n".join(self.config.get('exclude_patterns', [])))

        ctk.CTkLabel(win, text=self.T["exc_paths"], font=native_font_bold, text_color=WIN95_TEXT, anchor='w').grid(row=3, column=0, sticky='ew', padx=10)
        path_frame = ctk.CTkFrame(win, fg_color=WIN95_SURFACE, corner_radius=Z)
        path_frame.grid(row=4, column=0, sticky='nsew', padx=10, pady=(2, 8))
        path_frame.grid_columnconfigure(0, weight=1)
        path_frame.grid_rowconfigure(0, weight=1)
        lb = Listbox(path_frame, bg=WIN95_ENTRY, fg=WIN95_TEXT, selectbackground=WIN95_SURFACE_ALT, selectforeground=WIN95_TEXT, relief='flat', bd=1, font=("Consolas", 10), highlightthickness=0, exportselection=False)
        lb.grid(row=0, column=0, sticky='nsew', padx=6, pady=6)
        for p in self.config.get('exclude_paths', []):
            lb.insert('end', str(p))
        btn_col = ctk.CTkFrame(path_frame, fg_color='transparent', corner_radius=Z)
        btn_col.grid(row=0, column=1, sticky='n', padx=(0, 6), pady=6)
        ctk.CTkButton(btn_col, text=self.T["exc_add_path"], width=110, font=native_font, fg_color=WIN95_BUTTON, hover_color=WIN95_BUTTON_HOVER, text_color=WIN95_BUTTON_TEXT, corner_radius=Z, border_width=1, border_color=WIN95_BORDER_DARK, command=lambda: self._exc_add_path(lb)).pack(pady=2)
        ctk.CTkButton(btn_col, text=self.T["exc_remove"], width=110, font=native_font, fg_color=WIN95_BUTTON, hover_color=WIN95_BUTTON_HOVER, text_color=WIN95_BUTTON_TEXT, corner_radius=Z, border_width=1, border_color=WIN95_BORDER_DARK, command=lambda: self._exc_remove_path(lb)).pack(pady=2)

        bar = ctk.CTkFrame(win, fg_color='transparent', corner_radius=Z)
        bar.grid(row=5, column=0, sticky='ew', padx=10, pady=(0, 10))
        bar.grid_columnconfigure(0, weight=1)
        ctk.CTkButton(bar, text=self.T["save"], width=110, font=native_font_bold, fg_color="#0D9488", hover_color="#14B8A6", text_color=WIN95_TEXT, corner_radius=Z, command=lambda: self._save_exclusions(win, txt, lb)).grid(row=0, column=0, sticky='w')

    def _exc_add_path(self, lb):
        d = filedialog.askdirectory(parent=lb.winfo_toplevel(), title=self.T["exc_add_path"])
        if d:
            lb.insert('end', str(Path(d)))

    def _exc_remove_path(self, lb):
        sel = lb.curselection()
        if sel:
            lb.delete(sel[0])

    def _save_exclusions(self, win, txt, lb):
        if not self._policy_edit_allowed():
            return
        patterns = [line.strip() for line in txt.get("1.0", "end").splitlines() if line.strip()]
        paths = []
        for raw in lb.get(0, "end"):
            normalized = normalize_path(str(raw))
            if normalized is None:
                self._log(_GuiLogMessage(f"Invalid exclusion path: {raw}. Select an ordinary absolute path.", "error"))
                return
            paths.append(str(normalized))
        result = _config_rmw_transaction(lambda latest: {**latest, "exclude_patterns": patterns, "exclude_paths": paths}, detailed=True)
        if not result:
            self._log(_GuiLogMessage(f"Could not save exclusions: {result.message}", "error"))
            return
        _state, self.config, _errors = read_config_snapshot(create_if_missing=False)
        self.exclude_patterns = patterns
        self.exclude_paths = paths
        win.destroy()
        self._log(self.T["exc_saved"])

    def _open_system_targets(self):
        if not self._policy_edit_allowed():
            return
        win = ctk.CTkToplevel(self)
        win.title(self.T["syst_title"])
        win.geometry("480x420")
        win.minsize(400, 320)
        win.configure(fg_color=WIN95_BG)
        win.transient(self)
        win.grab_set()
        win.grid_columnconfigure(0, weight=1)
        win.grid_rowconfigure(3, weight=1)

        ctk.CTkLabel(win, text=self.T["syst_help"], font=native_font, text_color=WIN95_TEXT_MUTED, anchor='w', justify='left').grid(row=0, column=0, sticky='ew', padx=10, pady=(10, 6))

        self.syst_vars = {}
        for i, name in enumerate(SYSTEM_TARGET_DEFAULTS):
            var = ctk.BooleanVar(value=bool(self.sys_targets.get(name, False)))
            self.syst_vars[name] = var
            cb = ctk.CTkCheckBox(win, text=name, variable=var, font=native_font,
                                 text_color=WIN95_TEXT, hover_color=WIN95_BUTTON_HOVER,
                                 fg_color=WIN95_ACCENT_TEAL, border_color=WIN95_BORDER_DARK,
                                 corner_radius=Z, border_width=1, checkbox_width=18, checkbox_height=18,
                                 checkmark_color="#FFFFFF")
            cb.grid(row=i + 1, column=0, sticky='w', padx=16, pady=4)

        bar = ctk.CTkFrame(win, fg_color='transparent', corner_radius=Z)
        bar.grid(row=len(SYSTEM_TARGET_DEFAULTS) + 1, column=0, sticky='ew', padx=10, pady=(4, 10))
        bar.grid_columnconfigure(0, weight=1)
        ctk.CTkButton(bar, text=self.T["save"], width=110, font=native_font_bold, fg_color="#0D9488", hover_color="#14B8A6", text_color=WIN95_TEXT, corner_radius=Z, command=lambda: self._save_system_targets(win)).grid(row=0, column=0, sticky='w')

    def _save_system_targets(self, win):
        if not self._policy_edit_allowed():
            return
        targets = {name: bool(var.get()) for name, var in self.syst_vars.items()}
        result = _config_rmw_transaction(lambda latest: {**latest, "system_targets": targets}, detailed=True)
        if not result:
            self._log(_GuiLogMessage(f"Could not save system targets: {result.message}", "error"))
            return
        _state, self.config, _errors = read_config_snapshot(create_if_missing=False)
        self.sys_targets = targets
        win.destroy()
        self._log(self.T["syst_saved"])


def _get_pythonw() -> str:
    """Return pythonw.exe path (no console window) next to current python.exe."""
    py = Path(sys.executable)
    pw = py.parent / "pythonw.exe"
    return str(pw) if pw.exists() else str(py)


def _hide_console():
    """Hide the console window if running via python.exe (not pythonw.exe)."""
    try:
        import ctypes
        hwnd = ctypes.windll.kernel32.GetConsoleWindow()
        if hwnd:
            ctypes.windll.user32.ShowWindow(hwnd, 0)  # SW_HIDE
    except Exception as exc:
        logging.getLogger("vac_cleaner").debug(f"Hide console error: {exc}")


def _parse_time_str(raw: str) -> str | None:
    """Canonical HH:MM parser. Returns formatted time string or None on failure."""
    try:
        parts = raw.strip().split(":")
        if len(parts) != 2:
            return None
        hh, mm = int(parts[0]), int(parts[1])
        if not (0 <= hh < 24 and 0 <= mm < 60):
            return None
        return f"{hh:02d}:{mm:02d}"
    except (ValueError, AttributeError):
        return None


TASK_NAME = "SmartVACCleaner"


def enabled_risky_targets(sys_targets) -> list[str]:
    """Risky opt-in targets currently enabled beyond the safe defaults.

    Safe targets (on by default) are already carried by --all; only the risky
    opt-ins (Recycle Bin / DNS / Windows Update) need an explicit --sys-targets
    in scheduled/background argv (T-106). Kept for the plain-CLI P1-7 surface;
    one implementation of the deviation logic (T-129, G).
    """
    return _target_deviations(sys_targets)[0]


def _target_deviations(sys_targets) -> tuple[list[str], list[str]]:
    """T-129: FULL deviation from the safe defaults, both directions.

    Returns (enables, disables): risky targets switched ON and safe targets
    switched OFF. Scheduling/background argv must carry BOTH, otherwise a
    disabled safe default (e.g. System Temp off) is silently re-enabled by
    --all. Unknown names are dropped (fail closed, same as config load).
    """
    enables: list[str] = []
    disables: list[str] = []
    for name, val in (sys_targets or {}).items():
        if name not in SYSTEM_TARGET_DEFAULTS:
            continue
        if val and not SYSTEM_TARGET_DEFAULTS[name]:
            enables.append(name)
        elif not val and SYSTEM_TARGET_DEFAULTS[name]:
            disables.append(name)
    return enables, disables


def clean_argv(sys_targets=None) -> list[str]:
    """Canonical argv for a silent full-clean (scheduled + background share this, T-067).

    --all here means portable+system+custom with SAFE system-target defaults.
    `sys_targets` is the FULL target mask (dict or mapping): every deviation
    from the safe defaults is serialized -- risky targets enabled via
    --sys-targets AND safe targets disabled via --disable-targets (T-129), so a
    GUI state that turns System Temp off survives a scheduled/background run.
    Public plain --all semantics stay unchanged: with no mask, the safe
    defaults apply untouched.

    CORE-009: scheduled execution loads CURRENT config at runtime for roots
    and rules, and resolves surface="scheduled" from current system_targets.
    The canonical argv carries NO system-target snapshot -- it is a clean
    invocation that always reads current policy. Manual public CLI --all keeps
    the safe-default semantics.
    """
    if getattr(sys, "frozen", False):
        argv = [sys.executable, "--cli", "--all", "--delete", "--hidden"]
    else:
        argv = [_get_pythonw(), str(SCRIPT_PATH), "--cli", "--all", "--delete", "--hidden"]
    argv.append("--surface=scheduled")
    # CORE-009: never serialize sys_targets into the command. Scheduled runs
    # always read current config for the full target mask.
    return argv


def scheduled_task_command(sys_targets=None) -> str:
    """Command line for the scheduled silent full-clean task."""
    return subprocess.list2cmdline(clean_argv(sys_targets))


def background_clean_argv(sys_targets=None) -> list[str]:
    """Argv for a detached silent background full-clean (no console, no GUI)."""
    return clean_argv(sys_targets)


def install_task(time_str: str, sys_targets=None) -> bool:
    """Register daily silent full-clean task in Windows Task Scheduler.

    Returns True on success so callers can propagate a nonzero CLI outcome.

    CORE-011: use bounded subprocess with timeout for schtasks creation.
    """
    tr = scheduled_task_command()
    try:
        result = subprocess.run(
            ['schtasks', '/create',
             '/tn', TASK_NAME,
             '/tr', tr,
             '/sc', 'daily',
             '/st', time_str,
             '/rl', 'HIGHEST',
             '/f'],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            fallback = subprocess.run(
                ['schtasks', '/create',
                 '/tn', TASK_NAME,
                 '/tr', tr,
                 '/sc', 'daily',
                 '/st', time_str,
                 '/f'],
                capture_output=True, text=True, timeout=30
            )
            if fallback.returncode == 0:
                result = fallback
            else:
                user_task = f"{TASK_NAME}_{os.environ.get('USERNAME', 'User')}"
                fallback_user = subprocess.run(
                    ['schtasks', '/create',
                     '/tn', user_task,
                     '/tr', tr,
                     '/sc', 'daily',
                     '/st', time_str,
                     '/f'],
                    capture_output=True, text=True, timeout=30
                )
                if fallback_user.returncode == 0:
                    print(f"Task '{user_task}' installed -> runs daily at {time_str}, silent full clean.")
                    return True
    except subprocess.TimeoutExpired:
        print("schtasks create timed out after 30s")
        return False
    except Exception as e:
        print(f"schtasks error: {e}")
        return False
    if result.returncode == 0:
        print(f"Task '{TASK_NAME}' installed -> runs daily at {time_str}, silent full clean.")
        return True
    print(f"schtasks error: {result.stderr.strip()}")
    return False


def uninstall_task() -> bool:
    """Remove both task names, refusing success when either removal fails."""
    if sys.platform != "win32":
        print("Task Scheduler is Windows-only.")
        return False
    user_task = f"{TASK_NAME}_{os.environ.get('USERNAME', 'User')}"
    removed = False
    failed = False
    for name in (TASK_NAME, user_task):
        try:
            res = subprocess.run(['schtasks', '/delete', '/tn', name, '/f', '/HRESULT'],
                                 capture_output=True, text=True, timeout=30)
            code = res.returncode & 0xFFFFFFFF
            if code == 0:
                print(f"Task '{name}' uninstalled successfully.")
                removed = True
            elif code != 0x80070002:  # HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)
                detail = (res.stderr or res.stdout or f"HRESULT 0x{code:08X}").strip()
                print(f"Failed to delete task '{name}': {detail}")
                failed = True
        except Exception as e:
            print(f"Failed to delete task '{name}': {e}")
            failed = True
    if not removed and not failed:
        print(f"No task '{TASK_NAME}' found to remove.")
    return removed and not failed


def main():
    parser = argparse.ArgumentParser(description=f"Smart VAC Cleaner v{VERSION}")
    parser.add_argument("--dry-run",  action="store_true", default=False)
    parser.add_argument("--delete",   action="store_true", default=False)
    parser.add_argument("--portable", action="store_true")
    parser.add_argument("--system",   action="store_true")
    parser.add_argument("--custom",   action="store_true")
    parser.add_argument("--all",      action="store_true")
    parser.add_argument("--cli",      action="store_true", default=False)
    parser.add_argument("--status",   action="store_true")
    parser.add_argument("--analyze-caches", action="store_true",
                        help="Scan AppData for cache folders > 5 MB")
    parser.add_argument("--hidden",   action="store_true", default=False,
                        help="Hide console window (used when launched by Task Scheduler)")
    parser.add_argument("--sys-targets", type=str, default="")
    parser.add_argument("--disable-targets", type=str, default="",
                        help="Comma-separated safe-default targets to switch OFF (internal scheduled/background surface, T-129)")
    parser.add_argument("--exclude",     type=str, default="")
    parser.add_argument("--install-task", action="store_true",
                        help="Register daily Task Scheduler job")
    parser.add_argument("--uninstall-task", action="store_true",
                        help="Deregister daily Task Scheduler job")
    parser.add_argument("--time", type=str, default="09:00",
                        help="Start time for scheduled task (HH:MM, default 09:00)")
    parser.add_argument("--surface", choices=("cli", "scheduled", "background"),
                        default="cli", help=argparse.SUPPRESS)
    args = parser.parse_args()
    args.uninstall_task = getattr(args, "uninstall_task", False) is True
    surface = getattr(args, "surface", "cli")
    if not isinstance(surface, str):
        surface = "cli"
    clean = bool(args.cli or args.portable or args.system or args.custom or args.all)
    actions = {
        "install-task": bool(args.install_task),
        "uninstall-task": args.uninstall_task,
        "status": bool(args.status),
        "analyze-caches": bool(args.analyze_caches),
        "clean": clean,
    }
    selected = [name for name, enabled in actions.items() if enabled]
    if len(selected) > 1:
        print("Error: conflicting actions specified: " + " + ".join(selected))
        sys.exit(2)
    action = selected[0] if selected else "gui"
    modifiers = {
        "--dry-run": bool(args.dry_run), "--delete": bool(args.delete),
        "--hidden": bool(args.hidden), "--sys-targets": bool(args.sys_targets),
        "--disable-targets": bool(args.disable_targets), "--exclude": bool(args.exclude),
        "--time": args.time != "09:00", "--surface": surface != "cli",
    }
    permitted = {
        "clean": {"--dry-run", "--delete", "--hidden", "--sys-targets", "--disable-targets", "--exclude", "--surface"},
        "install-task": {"--time"},
        "uninstall-task": set(), "status": set(), "analyze-caches": set(), "gui": set(),
    }
    rejected = [name for name, supplied in modifiers.items() if supplied and name not in permitted[action]]
    if rejected:
        print(f"Error: {', '.join(rejected)} does not belong to {action}")
        sys.exit(2)
    enables = [name.strip() for name in args.sys_targets.split(",") if name.strip()]
    disables = [name.strip() for name in args.disable_targets.split(",") if name.strip()]
    for target in enables + disables:
        if target not in SYSTEM_TARGET_DEFAULTS:
            print(f"Error: unknown system target '{target}'. Known: {', '.join(SYSTEM_TARGET_DEFAULTS)}")
            sys.exit(2)
    if action == "install-task":
        try:
            canonical_time = _parse_time_str(args.time)
            if canonical_time is None:
                raise ValueError("invalid time")
        except (ValueError, TypeError):
            print("Error: --time must be a valid HH:MM time")
            sys.exit(2)
        sys.exit(0 if install_task(canonical_time, dict(SYSTEM_TARGET_DEFAULTS)) else 1)
    if action == "uninstall-task":
        sys.exit(0 if uninstall_task() else 1)
    if action == "status":
        cli_status()
        return
    if action == "analyze-caches":
        from analyze_caches import main as analyze_caches_main
        analyze_caches_main()
        return
    if action == "gui":
        _hide_console()
        App().mainloop()
        return
    dry_run = args.dry_run or not args.delete
    state, config, errors = load_config_strict()
    if state == ConfigState.INVALID:
        if not dry_run:
            print("Config error - refusing to run a destructive job:", "; ".join(errors))
            sys.exit(3)
        for error in errors:
            print(f"Warning: config invalid - {error}")
        config = _default_config()

    def execute():
        nonlocal config
        if not dry_run:
            boot = bootstrap_config()
            if isinstance(boot, tuple) and len(boot) == 3:
                if boot[0] == ConfigState.INVALID:
                    print("Config error - refusing to run a destructive job:", "; ".join(boot[2]))
                    sys.exit(3)
                config = boot[1]
        if args.hidden:
            _hide_console()
        target_mask = merged_system_targets(config.get("system_targets")) if surface != "cli" else None
        spec = resolve_job_spec(
            dry_run=dry_run, run_portable=args.portable or args.all,
            run_system=args.system or args.all, run_custom=args.custom or args.all,
            config=config, sys_targets=target_mask,
            cli_excludes=[value.strip() for value in args.exclude.split(",") if value.strip()],
            cli_enable=enables, cli_disable=disables, surface=surface,
        )
        log = Logger(LOGS_DIR / f"clean_{datetime.now().astimezone():%Y%m%d_%H%M%S}.log", dry_run)
        log.info(f"Config: {CONFIG_FILE}")
        run_cleaning_job(spec, log)
        if isinstance(log.n_errors, int) and log.n_errors > 0:
            sys.exit(1)

    if dry_run:
        execute()
    else:
        try:
            with _JobLease():
                execute()
        except JobBusyError as exc:
            print(f"Busy: {exc}")
            sys.exit(EXIT_LEASE_BUSY)
        except RuntimeError as exc:
            print(f"Error: {exc}")
            sys.exit(1)


if __name__ == "__main__":
    main()


