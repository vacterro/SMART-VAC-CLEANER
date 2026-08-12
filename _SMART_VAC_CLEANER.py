#!/usr/bin/env python3
# ruff: noqa: BLE001, S110, PLW1510

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
import fnmatch
import json
import logging
import os
import queue
import re
import stat
import subprocess
import sys
import threading
import time

try:

    import pystray
    from PIL import Image, ImageDraw

except ImportError:

    pystray = None


from datetime import datetime
from pathlib import Path
from tkinter import Listbox, filedialog, messagebox, simpledialog

import customtkinter as ctk

#  CORE CONFIGURATION



VERSION = "2.6.8"

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
_LOG_RETENTION_TOKENS = (".unlink(",)


def _prune_old_logs(logs_dir: Path, keep: int = _LOG_RETENTION_KEEP) -> None:
    """T-110: keep the `keep` most recent clean_*.log files, prune older ones.

    LOG-hygiene, not a cleaner deletion: the only files it ever removes are the
    cleaner's own timestamped run logs, and it is allowlisted in the mutation
    inventory as its own subsystem (never routed through the deletion
    SafetyGuard). Runs once per job at Logger construction.
    """
    try:
        logs = sorted(logs_dir.glob("clean_*.log"), key=lambda p: p.name, reverse=True)
        for old in logs[keep:]:
            try:
                old.unlink()
            except OSError:
                continue
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

    "general":  set(),

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
    "general": "intentional empty group (never blocks)",
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


def _real_user_profile() -> Path | None:
    """Canonical existing user profile dir, or None (fail closed)."""
    raw = os.environ.get("USERPROFILE") or os.environ.get("HOME")
    if not raw or not raw.strip():
        return None
    try:
        p = Path(raw.strip()).expanduser().resolve()
    except OSError:
        return None
    if not p.is_dir():
        return None
    return p


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
    profile = _real_user_profile()
    if profile is not None and _is_under(profile, p):
        return p
    base = p.name.lower()
    if base == "temp" or base == "tmp" or base.startswith("temp") or "_temp" in base or "temp_" in base:
        return p
    return None


SYSTEM_TEMP = _rooted(_resolve_env_root("windir",
                                       Path(os.environ.get("SystemRoot") or r"C:\Windows").resolve(),
                                       exact=True), "Temp")

USER_TEMP = _resolve_temp_root()

_LOCALAPPDATA = _resolve_env_root("LOCALAPPDATA",
                                  _rooted(_real_user_profile(), "AppData", "Local"),
                                  exact=True)

_APPDATA = _resolve_env_root("APPDATA",
                             _rooted(_real_user_profile(), "AppData", "Roaming"),
                             exact=True)

USER_CRASH = _rooted(_LOCALAPPDATA, "CrashDumps")

USER_EXPLORER = _rooted(_LOCALAPPDATA, "Microsoft", "Windows", "Explorer")


# T-147: poisoned/absent env roots become impossible relative SENTINEL paths so
# the AppData target list still builds (Path/ never sees None); entries rooted
# in a sentinel are filtered out of the live target list below.
_INVALID_LOCAL = Path("__INVALID_LOCALAPPDATA__")
_INVALID_ROAM = Path("__INVALID_APPDATA__")

_LOCALAPPDATA = _LOCALAPPDATA if _LOCALAPPDATA is not None else _INVALID_LOCAL
_APPDATA = _APPDATA if _APPDATA is not None else _INVALID_ROAM

USER_CRASH = (_LOCALAPPDATA / "CrashDumps") if _LOCALAPPDATA is not _INVALID_LOCAL else None
USER_EXPLORER = (_LOCALAPPDATA / "Microsoft" / "Windows" / "Explorer") if _LOCALAPPDATA is not _INVALID_LOCAL else None


# Deep System & App Caches

USER_APPDATA_TARGETS = [

    (_LOCALAPPDATA / "NVIDIA" / "GLCache", "NVIDIA GL Cache"),

    (_LOCALAPPDATA / "NVIDIA" / "DXCache", "NVIDIA DX Cache"),

    (_LOCALAPPDATA / "D3DSCache", "DirectX Shader Cache"),

    (_LOCALAPPDATA / "Steam" / "htmlcache", "Steam Web Cache"),

    (_LOCALAPPDATA / "Microsoft" / "Windows" / "INetCache", "Windows INetCache"),

    (_APPDATA / "discord" / "Cache", "Discord Cache"),

    (_APPDATA / "discord" / "Code Cache", "Discord Code Cache"),

]

USER_APPDATA_TARGETS.extend([
    # dev tool caches (LocalAppData)
    (_LOCALAPPDATA / "npm-cache", "npm Cache"),
    (_LOCALAPPDATA / "uv" / "cache", "uv Cache"),
    (_LOCALAPPDATA / "pip" / "cache", "pip Cache"),
    (_LOCALAPPDATA / "Nuitka", "Nuitka Cache"),
    (_LOCALAPPDATA / "node-gyp" / "Cache", "node-gyp Cache"),
    (_LOCALAPPDATA / "python" / "Cache", "python Cache"),
    (_LOCALAPPDATA / "Cypress" / "Cache", "Cypress Cache"),
    # app logs (Roaming)
    (_APPDATA / "Maxon" / "Logs", "Maxon Logs"),
    (_APPDATA / "Maxon" / "Temp", "Maxon Temp"),
    (_APPDATA / "FreeFileSync" / "Logs", "FreeFileSync Logs"),
    (_APPDATA / "obs-studio" / "logs", "obs-studio Logs"),
    (_APPDATA / "Google" / "DriveFS" / "Logs", "DriveFS Logs"),
    (_APPDATA / "Mega Limited" / "MEGAsync" / "Logs", "MEGAsync Logs"),
    (_APPDATA / "discord" / "Logs", "discord Logs"),
    (_APPDATA / "discord" / "module_data" / "crashlogs", "discord Crash Logs"),
    (_APPDATA / "Claude" / "Logs", "Claude Logs"),
    (_APPDATA / "Listary" / "UserProfile" / "Cache", "Listary Cache"),
    # Eagle
    (_APPDATA / "Eagle" / "eagle-temp", "Eagle Temp"),
    (_APPDATA / "Eagle" / "Cache", "Eagle Cache"),
    (_APPDATA / "Eagle" / "library-caches", "Eagle Library Caches"),
    (_APPDATA / "Eagle" / "Crashpad", "Eagle Crashpad"),
    # VS Code family
    (_APPDATA / "Code" / "CachedExtensionVSIXs", "VS Code VSIX Cache"),
    (_APPDATA / "Code" / "Crashpad", "VS Code Crashpad"),
    (_APPDATA / "Code" / "CachedData", "VS Code CachedData"),
    (_APPDATA / "Code" / "Cache", "VS Code Cache"),
    (_APPDATA / "Antigravity" / "CachedExtensionVSIXs", "Antigravity VSIX Cache"),
    (_APPDATA / "Antigravity" / "Cache", "Antigravity Cache"),
    (_APPDATA / "Antigravity" / "CachedData", "Antigravity CachedData"),
    (_APPDATA / "Claude" / "Cache", "Claude Cache"),
    (_APPDATA / "Claude" / "Code Cache", "Claude Code Cache"),
    (_APPDATA / "obsidian" / "Cache", "Obsidian Cache"),
    (_APPDATA / "obsidian" / "Code Cache", "Obsidian Code Cache"),
    (_APPDATA / "CELSYS" / "promenade" / "dbcache", "CELSYS dbcache"),
    (_APPDATA / "EpicGamesLauncher" / "Saved" / "webcache_4430", "Epic webcache"),
    (_APPDATA / "AI Chatter" / "Cache", "AIChatter Cache"),
    (_APPDATA / "Programs" / "DockerDesktop" / "tmp-delete", "Docker tmp-delete"),
    # browsers (LocalAppData)
    (_LOCALAPPDATA / "Opera Software" / "Opera Stable" / "Default" / "Cache", "Opera Cache (C:)"),
    (_LOCALAPPDATA / "Opera Software" / "Opera Stable" / "Default" / "Code Cache", "Opera Code Cache (C:)"),
    (_LOCALAPPDATA / "Opera Software" / "Opera Stable" / "Default" / "GrShaderCache", "Opera Shader Cache (C:)"),
    (_LOCALAPPDATA / "Opera Software" / "Opera Stable" / "Default" / "System Cache", "Opera System Cache (C:)"),
    (_LOCALAPPDATA / "Opera Software" / "Opera Stable" / "Default" / "Crash Reports", "Opera Crash Reports (C:)"),
    (_LOCALAPPDATA / "Google" / "Chrome" / "User Data" / "Default" / "Cache", "Chrome Cache (C:)"),
    (_LOCALAPPDATA / "Google" / "Chrome" / "User Data" / "Default" / "GrShaderCache", "Chrome Shader Cache (C:)"),
    (_LOCALAPPDATA / "Microsoft" / "Edge" / "User Data" / "Default" / "Cache", "Edge Cache (C:)"),
    (_LOCALAPPDATA / "Razer" / "RazerAppEngine" / "Cache", "Razer Cache"),
    (_LOCALAPPDATA / "Razer" / "RazerAppEngine" / "Code Cache", "Razer Code Cache"),
    (_LOCALAPPDATA / "Razer" / "RazerAppEngine" / "Service Worker" / "CacheStorage", "Razer SW CacheStorage"),
    (_LOCALAPPDATA / "electron" / "Cache", "Electron Cache"),
    (_APPDATA / "Telegram Desktop" / "tdata" / "user_data" / "cache", "Telegram Cache (C:)"),
    (_LOCALAPPDATA / "ollama app.exe" / "EBWebView" / "Default" / "Cache", "Ollama WebView Cache"),
    (_APPDATA / "MaxonApp" / "UserData" / "EBWebView" / "Default" / "Cache", "Maxon WebView Cache"),
    (_APPDATA / "Photoshop1-25-WIN" / "EBWebView" / "Default" / "Cache", "Photoshop WebView Cache"),
    # Brave browser (LocalAppData)
    (_LOCALAPPDATA / "BraveSoftware" / "Brave-Browser" / "User Data" / "Default" / "Cache", "Brave Cache"),
    (_LOCALAPPDATA / "BraveSoftware" / "Brave-Browser" / "User Data" / "Default" / "Code Cache", "Brave Code Cache"),
    (_LOCALAPPDATA / "BraveSoftware" / "Brave-Browser" / "User Data" / "Default" / "GPUCache", "Brave GPU Cache"),
    # Code Cache for Chrome/Edge (Cache already covered)
    (_LOCALAPPDATA / "Google" / "Chrome" / "User Data" / "Default" / "Code Cache", "Chrome Code Cache"),
    (_LOCALAPPDATA / "Microsoft" / "Edge" / "User Data" / "Default" / "Code Cache", "Edge Code Cache"),
    # misc safe caches / logs
    (_LOCALAPPDATA / "calibre-cache", "Calibre Cache"),
    (_LOCALAPPDATA / "fontconfig", "fontconfig Cache"),
    (_LOCALAPPDATA / "qBittorrent" / "logs", "qBittorrent Logs"),
    (_LOCALAPPDATA / "claude-cli-nodejs" / "Cache", "Claude CLI Cache"),
    # New findings (v2.4.8)
    (_LOCALAPPDATA / "Mega Limited" / "MEGAsync" / "logs", "MEGAsync Logs (Local)"),
    (_APPDATA / "Devin" / "Cache", "Devin Cache"),
    (_APPDATA / "Devin" / "CachedData", "Devin CachedData"),
    (_APPDATA / "FontBase" / "Cache", "FontBase Cache"),
    (_APPDATA / "Bridge" / "Cache", "Adobe Bridge Cache"),
    (_LOCALAPPDATA / "AIChatter" / "AI Chatter" / "cache", "AIChatter Cache"),
    (_APPDATA / "Autokroma" / "Influx" / "Cache", "Autokroma Influx Cache"),
    (_APPDATA / "Adobe" / "Adobe Substance 3D Sampler" / "thumbnailCache", "Substance 3D Thumbnail Cache"),
    (_LOCALAPPDATA / "BlueStacks X" / "cache", "BlueStacks X Cache"),
    (_APPDATA / "@neuralnomads" / "codenomad-electron-app" / "session-data-v2" / "Cache", "CodeNomad Cache"),
    (_APPDATA / "MAXON" / "_assetcache", "Maxon Asset Cache"),
    (_LOCALAPPDATA / "Mailbird" / "Misc" / "component_crx_cache", "Mailbird CRX Cache"),
    (_APPDATA / "Opera Software" / "Opera Stable" / "component_crx_cache", "Opera CRX Cache"),
    (_LOCALAPPDATA / "BraveSoftware" / "Brave-Browser" / "User Data" / "component_crx_cache", "Brave CRX Cache"),
    (_APPDATA / "discord" / "component_crx_cache", "Discord CRX Cache"),
    # New findings (v2.4.9)
    (_APPDATA / "Devin" / "GPUCache", "Devin GPUCache"),
    (_APPDATA / "Devin" / "logs", "Devin Logs"),
    (_APPDATA / "Devin" / "cli" / "logs", "Devin CLI Logs"),
    (_APPDATA / "Claude" / "GPUCache", "Claude GPUCache"),
    (_APPDATA / "Antigravity" / "GPUCache", "Antigravity GPUCache"),
    (_APPDATA / "Antigravity" / "logs", "Antigravity Logs"),
    (_APPDATA / "@neuralnomads" / "codenomad-electron-app" / "session-data-v2" / "Code Cache", "CodeNomad Code Cache"),
    (_APPDATA / "@neuralnomads" / "codenomad-electron-app" / "session-data-v2" / "GPUCache", "CodeNomad GPUCache"),
    (_APPDATA / "ollama app.exe" / "EBWebView" / "Default" / "GPUCache", "Ollama GPUCache"),
    (_APPDATA / "LM Studio" / "GPUCache", "LM Studio GPUCache"),
    (_LOCALAPPDATA / "Adobe" / "Adobe Substance 3D Painter" / "cache", "Substance 3D Painter Cache"),
    (_LOCALAPPDATA / "Adobe" / "Adobe Substance 3D Sampler" / "cache", "Substance 3D Sampler Cache"),
    (_APPDATA / "CELSYS" / "CLIPStudioPaint" / "1.5.0" / "CacheData", "CLIP Studio Paint Cache"),
    (_LOCALAPPDATA / "Reallusion" / "ActorCore AccuRIG" / "Cache", "AccuRIG Cache"),
    (_LOCALAPPDATA / "Reallusion" / "ActorCore AccuRIG" / "Code Cache", "AccuRIG Code Cache"),
    (_LOCALAPPDATA / "Reallusion" / "Character Creator" / "5.0" / "cache", "Character Creator Cache"),
    (_APPDATA / "LosslessCut" / "Cache", "LosslessCut Cache"),
    (_APPDATA / "LosslessCut" / "GPUCache", "LosslessCut GPUCache"),
    (_LOCALAPPDATA / "Topaz Labs LLC" / "Topaz Video" / "cache", "Topaz Video Cache"),
    (_LOCALAPPDATA / "Topaz Labs LLC" / "Topaz Video AI" / "cache", "Topaz Video AI Cache"),
    (_LOCALAPPDATA / "UnrealEngine" / "5.6" / "DerivedDataCache", "Unreal Engine 5.6 DDCache"),
    (_APPDATA / "omniroute-desktop" / "Cache", "Omniroute Cache"),
    (_APPDATA / "omniroute-desktop" / "Code Cache", "Omniroute Code Cache"),
    (_APPDATA / "omniroute-desktop" / "GPUCache", "Omniroute GPUCache"),
    (_APPDATA / "omniroute-desktop" / "Service Worker" / "CacheStorage", "Omniroute SW CacheStorage"),
    (_APPDATA / "stem-studio" / "Cache", "Stem Studio Cache"),
    (_APPDATA / "stem-studio" / "GPUCache", "Stem Studio GPUCache"),
    (_LOCALAPPDATA / "QuiteRss" / "QuiteRss" / "cache", "QuiteRss Cache"),
    (_LOCALAPPDATA / "com.dropdead.app" / "EBWebView" / "Default" / "Cache", "Dropdead WebView Cache"),
    (_LOCALAPPDATA / "DeskChat" / "DeskChat" / "cache", "DeskChat Cache"),
    (_LOCALAPPDATA / "DeskChat Dump" / "cache", "DeskChat Dump Cache"),
    (_LOCALAPPDATA / "HD-Player" / "cache", "HD-Player Cache"),
    (_LOCALAPPDATA / "JangaFX" / "liquigen" / "gl-cache", "Liquigen GL Cache"),
    (_LOCALAPPDATA / "Krisp" / "Logs", "Krisp Logs"),
    (_LOCALAPPDATA / "Mailbird" / "Misc" / "Default" / "Cache", "Mailbird Cache"),
    (_APPDATA / "SiYuan-Electron" / "GPUCache", "SiYuan GPUCache"),
    (_APPDATA / "BetterDiscord Installer" / "Cache", "BetterDiscord Cache"),
    (_APPDATA / "BorisFX" / "BorisFX Direct" / "Cache", "BorisFX Direct Cache"),
    # New findings (v2.4.10)
    (_LOCALAPPDATA / "Google" / "DriveFS" / "Logs", "DriveFS Logs (Local)"),
    (_LOCALAPPDATA / "Razer" / "RazerAppEngine" / "User Data" / "Default" / "Cache", "Razer Engine Cache"),
    (_LOCALAPPDATA / "Razer" / "RazerAppEngine" / "User Data" / "Default" / "Code Cache", "Razer Engine Code Cache"),
    (_LOCALAPPDATA / "Razer" / "RazerAppEngine" / "User Data" / "Default" / "GPUCache", "Razer Engine GPUCache"),
    (_LOCALAPPDATA / "EpicGamesLauncher" / "Saved" / "webcache_4430", "Epic webcache (Local)"),
    (_APPDATA / "Code" / "WebStorage" / "2" / "CacheStorage", "VS Code WebStorage Cache"),
    (_APPDATA / "Code" / "WebStorage" / "3" / "CacheStorage", "VS Code WebStorage Cache (2)"),
    (_LOCALAPPDATA / "com.verifiedskill.desktop" / "EBWebView" / "component_crx_cache", "VerifiedSkill CRX Cache"),
    (_LOCALAPPDATA / "MaxonApp" / "UserData" / "EBWebView" / "Default" / "Cache", "MaxonApp WebView Cache"),
    (_LOCALAPPDATA / "MaxonApp" / "UserData" / "EBWebView" / "Default" / "Code Cache", "MaxonApp WebView Code Cache"),
    (_LOCALAPPDATA / "MaxonApp" / "UserData" / "EBWebView" / "Default" / "GrShaderCache", "MaxonApp WebView Shader Cache"),
    (_APPDATA / "Adobe" / "Adobe Photoshop 2024" / "Logs", "Photoshop 2024 Logs"),
    (_APPDATA / "obsidian" / "GPUCache", "Obsidian GPUCache"),
    # New findings (v2.4.14)
    (_LOCALAPPDATA / "Packages" / "Microsoft.Windows.Search_cw5n1h2txyewy" / "LocalState" / "DeviceSearchCache", "Windows Search DeviceSearchCache"),
    (_LOCALAPPDATA / "Packages" / "Microsoft.Windows.Search_cw5n1h2txyewy" / "LocalState" / "AppIconCache", "Windows Search AppIconCache"),
    (_LOCALAPPDATA / "iTop Easy Desktop" / "Thumb", "iTop Easy Desktop Thumbs"),
    (_APPDATA / "Freebuff" / "Cache", "Freebuff Cache"),
    (_LOCALAPPDATA / "Photoshop1-25-WIN" / "EBWebView" / "Default" / "Cache", "Photoshop WebView Cache (Local)"),
    (_APPDATA / "Bridge" / "Code Cache", "Adobe Bridge Code Cache"),
    (_APPDATA / "Bridge" / "GPUCache", "Adobe Bridge GPUCache"),
    (_APPDATA / "ollama app.exe" / "EBWebView" / "GrShaderCache", "Ollama Shader Cache"),
    (_APPDATA / "AIChatter" / "profiles" / "edge" / "chatgpt" / "Default" / "Cache", "AIChatter Edge Profile Cache"),
    (_APPDATA / "Telegram Desktop" / "tdata" / "user_data" / "media_cache", "Telegram Media Cache (C:)"),
    (_APPDATA / "Opera Software" / "Opera Stable" / "Service Worker" / "CacheStorage", "Opera SW CacheStorage"),
    (_APPDATA / "Opera Software" / "Opera Stable" / "Service Worker" / "ScriptCache", "Opera SW ScriptCache"),
])

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

# T-147: entries whose base env root failed provenance validation are dropped --
# a poisoned APPDATA/LOCALAPPDATA can never turn a reviewed cache suffix into a
# live destructive target.
USER_APPDATA_TARGETS = [
    (p, d, _TARGET_APP_GROUPS.get(d)) for p, d, *_ in USER_APPDATA_TARGETS
    if p is not None and not _is_under(_INVALID_LOCAL, p) and not _is_under(_INVALID_ROAM, p)
]

def get_running_processes() -> set[str] | None:
    """Query running process image names.

    Returns a set of lowercased image names, or None when the query FAILED
    (tasklist nonzero exit, timeout, parse error). Callers must treat None as
    UNKNOWN and skip app-sensitive work (fail closed), never as 'nothing runs'.
    """
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
    A group with no process mapping (e.g. 'general') is trivially verified:
    there is nothing running to guard against. An UNVERIFIED owner can never
    authorize a real deletion of an app-sensitive target (fail closed); it may
    only appear in DISCOVERED / NOT AUTHORIZED reporting.
    """
    if not APP_PROCESSES.get(app_group):
        return "verified"
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


# F1: object identity for TOCTOU defence. A path being present at plan time is
# NOT permission forever -- between planning and mutation the object at that
# path may be replaced (file swap, dir swap, symlink/junction introduction).
# Every mutation candidate carries the identity captured during planning, and
# the mutation chokepoint re-proves the object is still the SAME object.
def _capture_identity(path: Path) -> dict | None:
    """Capture a conservative identity for the object at `path` via lstat.

    Returns a dict, or None when the object cannot be identified (missing /
    unreadable). Symlinks and reparse points get a fixed 'link_or_reparse'
    identity that never authorizes a mutation. Inode (dev, ino) identity is
    used when the filesystem provides it; on Windows the file creation time
    (st_ctime_ns) is a strong replacement detector that our own mutations do
    not move (chmod/rmdir of empty dirs leave ctime untouched).
    """
    try:
        st = path.lstat()
    except OSError:
        return None
    attrs = int(getattr(st, "st_file_attributes", 0))
    if stat.S_ISLNK(st.st_mode) or (os.name == "nt" and (attrs & stat.FILE_ATTRIBUTE_REPARSE_POINT)):
        return {"type": "link_or_reparse"}
    kind = "dir" if stat.S_ISDIR(st.st_mode) else "file"
    ident: dict = {"type": kind, "attrs": attrs, "ctime_ns": int(st.st_ctime_ns)}
    if st.st_ino and st.st_dev:
        ident["dev"] = int(st.st_dev)
        ident["ino"] = int(st.st_ino)
    if kind == "file":
        ident["size"] = int(st.st_size)
        ident["mtime_ns"] = int(st.st_mtime_ns)
    return ident


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
        return planned.get("dev") == current.get("dev") and p_ino == c_ino
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



class Logger:

    def __init__(self, log_file: Path | None, dry_run: bool, gui_callback=None, quiet: bool = False):

        self.dry_run = dry_run

        self.log_file = log_file

        self.bytes_freed = 0

        self.n_deleted = 0

        self.n_skipped = 0

        self.n_errors = 0

        self.gui_callback = gui_callback

        self.quiet = quiet

        self.deleted_paths: list[str] = []  # F4: candidate truth recorder

        self.lock = threading.Lock()


        self._log = logging.getLogger("vac_cleaner")

        self._log.setLevel(logging.DEBUG)

        for h in self._log.handlers[:]:

            h.close()

            self._log.removeHandler(h)


        if self.quiet:

            # F4: silent collector used by --status / calculate_target_sizes.
            # Counters still update; nothing is emitted to console or GUI.
            self._log.addHandler(logging.NullHandler())

        else:

            ch = logging.StreamHandler(stream=sys.stdout)

            ch.setLevel(logging.INFO)

            ch.setFormatter(logging.Formatter("%(message)s"))

            self._log.addHandler(ch)


        if not self.quiet and log_file:

            try:
                log_file.parent.mkdir(parents=True, exist_ok=True)
            except OSError:
                log_file = None  # exe in read-only dir: logs stay console-only

            try:

                fh = logging.FileHandler(log_file, encoding="utf-8")

                fh.setLevel(logging.DEBUG)

                fh.setFormatter(logging.Formatter("%(asctime)s  %(levelname)-7s  %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))

                self._log.addHandler(fh)

            except OSError as exc:

                self._log.warning(f"Cannot open log file {log_file}: {exc}")

            # T-110: bound the logs/ directory (retention) on every job start --
            # clean/scheduled/background runs all construct a Logger.
            _prune_old_logs(log_file.parent)


    def _emit_gui(self, msg: str):

        if self.gui_callback:

            self.gui_callback(msg)


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

        self._emit_gui(msg)


    def error(self, msg: str) -> None:

        with self.lock:

            self.n_errors += 1

        text = f"  [ERROR]  {msg}"

        self._log.error(text)

        self._emit_gui(text)


    def deleted(self, path: Path, size: int, desc: str) -> None:

        with self.lock:

            self.bytes_freed += size

            self.n_deleted += 1

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

        self._emit_gui(msg)



#  SAFETY GUARD



class SafetyGuard:

    def __init__(self, base_root: Path, allow_shallow_system_target: bool = False,

                 exclude_patterns: list[str] | None = None,

                 exclude_paths: list[str] | None = None):

        self.base_root = self._canon(base_root)

        self.allow_shallow_system_target = allow_shallow_system_target

        self.exclude_patterns = exclude_patterns or []

        self.exclude_paths = [Path(p).resolve() for p in (exclude_paths or [])]


    @staticmethod

    def _canon(p: Path) -> Path:

        try: return p.resolve()

        except OSError: return p.absolute()


    def is_safe(self, path: Path) -> tuple[bool, str]:

        if is_link(path):
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


        name_lower = path.name.lower()

        for variant in _name_variants(name_lower):

            if variant in NEVER_DELETE_NAMES:

                return False, f"'{path.name}' is in the never-delete list"


        # User-defined exclusion patterns (fnmatch)

        for pat in self.exclude_patterns:

            if fnmatch.fnmatch(name_lower, pat.lower()):

                return False, f"'{path.name}' matches exclude pattern '{pat}'"


        # User-defined exclusion paths (exact)

        if path in self.exclude_paths:

            return False, f"'{path}' is in the exclude-paths list"


        # Check if path is under any excluded path

        for ep in self.exclude_paths:

            try:

                path.relative_to(ep)

                return False, f"'{path}' is under excluded path '{ep}'"

            except ValueError:

                pass


        # T-144: '..' segments were already canonicalized by _canon() at the top
        # of is_safe, so no raw '..' part can reach here. The resolved path is
        # confined by the relative_to(base_root) check above -- a '..' that
        # would escape the target root is refused there. There is deliberately
        # no separate '..' part check: it would be a dead check claiming a
        # safety layer (docs say canonicalized + confined, not '.. refused').

        return True, "OK"



#  CORE CLEANER ENGINE



class CandidateLedger:
    """Job-level claim registry (T-124): ONE physical candidate is planned ONCE.

    Each cleaner claims the subtree it plans; a later target fully inside an
    existing claim is skipped, and a target that is an ancestor of existing
    claims absorbs them (its plan must EXCLUDE the absorbed subtrees so their
    bytes are not double-counted). Paths are canonicalized before comparison so
    aliases collapse; ancestor/descendant overlap is handled, not only exact
    duplicates. Shared by every layer of one job (portable/system/custom).
    """

    def __init__(self):
        self._claims: list[Path] = []
        self._lock = threading.Lock()

    @staticmethod
    def _canon(p: Path) -> Path:
        try:
            return p.resolve()
        except OSError:
            return p.absolute()

    def covered(self, path: Path) -> bool:
        """True when `path` is inside an existing claim (equal or descendant)."""
        c = self._canon(path)
        with self._lock:
            return any(_is_ancestor(x, c) for x in self._claims)

    def claims_within(self, path: Path) -> list[Path]:
        """Existing claims strictly inside `path` (to exclude from its plan)."""
        c = self._canon(path)
        with self._lock:
            return [x for x in self._claims if _is_ancestor(c, x) and x != c]

    def claim(self, path: Path) -> None:
        """Register `path`'s subtree as claimed, absorbing claims inside it."""
        c = self._canon(path)
        with self._lock:
            self._claims = [x for x in self._claims if not _is_ancestor(c, x)]
            self._claims.append(c)

    def __len__(self) -> int:
        with self._lock:
            return len(self._claims)


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

        self.running = get_running_processes()

        self.guard = self.make_guard(guard.base_root, guard.allow_shallow_system_target)

        self.ledger = ledger

        # T-131: app-sensitive targets carry their owner group so the apply
        # phase can re-check the process state just-in-time (process TOCTOU).
        self._owner_group: str | None = None


    def make_guard(self, root: Path, allow_shallow_system_target: bool = False) -> SafetyGuard:

        """Build a guard that inherits the engine's exclusions (global invariant, P0-3)."""

        pats = list(dict.fromkeys(self.exclude_patterns or []))

        paths = list(dict.fromkeys(self.exclude_paths or []))

        return SafetyGuard(root, allow_shallow_system_target=allow_shallow_system_target, exclude_patterns=pats, exclude_paths=paths)


    def check_cancel(self):

        if self.cancel_event and self.cancel_event.is_set():

            raise CancelJobException("Job cancelled by user.")


    def refresh_running(self) -> None:

        """Re-query the process table before a destructive app group (P1-8)."""

        self.running = get_running_processes()


    def _ledger_gate(self, path: Path, desc: str) -> bool:
        """Job-level dedup gate for a top-level target (T-124).

        False when another cleaner already claims this subtree -- the target
        must not be planned a second time. This is checked at plan time; the
        claim is registered only after a successful plan.
        """
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
        if self.ledger is not None:
            self.ledger.claim(path)


    def _owner_gate_ok(self, app: str | None) -> bool:
        """T-131: just-in-time process check for an app-sensitive target.

        Refreshes the process table and refuses when the owning app is running
        or the snapshot is UNKNOWN. Returns True when no process gate applies.
        """
        if not app or app == "general" or not APP_PROCESSES.get(app):
            return True
        self.refresh_running()
        return not is_app_running(app, self.running)


    def _log_deleted(self, path: Path, size: int, desc: str) -> None:

        self.log.deleted(path, size, desc)


    def _plan_file(self, path: Path):
        """READ-ONLY file validation + size + identity (T-090/F1).

        Returns (size_bytes, identity) or None when the path must not be
        touched. Performs no chmod/unlink/rmdir. The identity is what the
        apply phase re-verifies immediately before mutation (F1 TOCTOU gate).
        """
        if not path.exists():
            return None
        if is_link(path):
            self.log.skipped(path, "Symlink/reparse point refused")
            return None
        ok, reason = self.guard.is_safe(path)
        if not ok:
            self.log.skipped(path, reason)
            return None
        identity = _capture_identity(path)
        if not identity or identity.get("type") == "link_or_reparse":
            self.log.skipped(path, "Object identity could not be established")
            return None
        try:
            return int(path.stat().st_size), identity
        except OSError:
            return 0, identity


    def _authorize_mutation(self, path: Path, planned_identity):
        """THE single just-in-time mutation authorization gate (F1).

        Runs immediately before every chmod/unlink/rmdir on every candidate:
        0. cancellation is a mutation invariant (T-132).
        1. lstat the path again.
        2. refuse symlink/reparse/junction.
        3. re-run the active SafetyGuard.
        4. verify the object identity still matches the planned identity.
        Anything missing / changed / uncertain => (False, reason); the caller
        must SKIP and never mutate. Never chmod before this gate.
        """
        self.check_cancel()
        try:
            st = path.lstat()
        except OSError:
            return False, "Path missing before mutation"
        if stat.S_ISLNK(st.st_mode):
            return False, "Symlink introduced before mutation"
        attrs = int(getattr(st, "st_file_attributes", 0))
        if os.name == "nt" and (attrs & stat.FILE_ATTRIBUTE_REPARSE_POINT):
            return False, "Reparse point introduced before mutation"
        ok, reason = self.guard.is_safe(path)
        if not ok:
            return False, reason
        current = _capture_identity(path)
        if not _identity_matches(planned_identity, current):
            return False, "Object identity changed since planning"
        return True, "OK"


    def _apply_file_plan(self, path: Path, size: int, identity) -> MutationResult:
        """REAL delete of a single file (F1/F7/T-137).

        MUTATES the filesystem. MUST be unreachable when dry_run is True.

        T-137: EVERY filesystem mutation gets its OWN immediately-adjacent
        authorization. Never `authorize -> chmod -> unlink` under one auth:
          attempt 1: authorize -> unlink directly (no chmod).
          PermissionError (read-only) -> authorize -> chmod ->
                     re-baseline the expected identity after OUR chmod
                     (mutation-stable fields must still match the plan) ->
                     attempt 2: authorize -> unlink.
        Cancellation is part of the gate (check_cancel runs inside
        _authorize_mutation), so a cancel set at any boundary fails the auth
        before the next mutation.
        """
        for attempt in range(2):
            ok, reason = self._authorize_mutation(path, identity)
            if not ok:
                self.log.skipped(path, reason)
                return MutationResult(False, 0, reason)
            try:
                path.unlink()
                return MutationResult(True, size)
            except PermissionError:
                if attempt == 1:
                    self.log.skipped(path, "File locked by another process")
                    return MutationResult(False, 0, "File locked by another process")
                # read-only attribute blocks unlink: clear it under its OWN auth
                ok, reason = self._authorize_mutation(path, identity)
                if not ok:
                    self.log.skipped(path, reason)
                    return MutationResult(False, 0, reason)
                try:
                    path.chmod(0o666)
                except OSError:
                    self.log.skipped(path, "File in use or access denied")
                    return MutationResult(False, 0, "File in use or access denied")
                # Our chmod changed the attributes; re-baseline the expected
                # identity so the next authorize can only fail on a REAL change
                # since our own mutation. The object must still match the ORIGINAL
                # plan on every mutation-stable field (dev/ino/ctime/size/mtime) --
                # if an attacker swapped the file in the auth->chmod window, the
                # recapture differs from the plan and we refuse (T-137).
                recaptured = _capture_identity(path)
                if not recaptured or not _identity_matches(identity, recaptured, ignore_attrs=True):
                    self.log.skipped(path, "Object identity changed since planning")
                    return MutationResult(False, 0, "Object identity changed since planning")
                identity = recaptured
                continue
            except Exception:
                self.log.skipped(path, "File in use or access denied")
                return MutationResult(False, 0, "File in use or access denied")
        return MutationResult(False, 0, "File in use or access denied")


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


    def _plan_tree(self, path: Path, desc: str, excluded_regions: list[Path] | tuple = ()):
        """READ-ONLY discovery of a deletable tree (T-090/F1).

        Validates every node via guard.is_safe, collects deletable files + dirs,
        their byte totals and their captured identities, records protected
        nodes. Performs ZERO chmod/unlink/rmdir/write. Returns a plan dict, or
        None when the root is refused. Cancellation is checked during BOTH
        discovery phases (T-094). The apply phase re-verifies every identity
        immediately before each mutation (F1).
        """
        if is_link(path):
            self.log.skipped(path, "Symlink/reparse point refused")
            return None
        ok, reason = self.guard.is_safe(path)
        if not ok:
            self.log.skipped(path, reason)
            return None

        root_identity = _capture_identity(path)
        if not root_identity or root_identity.get("type") == "link_or_reparse":
            self.log.skipped(path, "Root identity could not be established")
            return None

        # T-124: prior claims absorbed by this target are excluded from the plan
        # so their bytes are never counted a second time.
        def _in_excluded(p: Path) -> bool:
            if not excluded_regions:
                return False
            return any(_is_ancestor(r, p) for r in excluded_regions)

        protected: set[Path] = set()

        # Phase 1: find protected nodes top-down (do not descend into them).
        stack = [path]
        while stack:
            cur = stack.pop()
            self.check_cancel()
            if _in_excluded(cur):
                protected.add(cur)
                continue
            ok, _reason = self.guard.is_safe(cur)
            if not ok or is_link(cur):
                protected.add(cur)
                continue
            try:
                for entry in os.scandir(cur):
                    e = Path(entry.path)
                    if entry.is_dir(follow_symlinks=False):
                        stack.append(e)
                    elif not self.guard.is_safe(e)[0] or is_link(e):
                        protected.add(e)
            except OSError:
                protected.add(cur)

        # Phase 2: collect files + dirs bottom-up for later deletion.
        files: list[tuple[Path, int, dict]] = []
        dirs: list[tuple[Path, dict]] = []
        stack = [path]
        while stack:
            cur = stack.pop()
            self.check_cancel()
            if cur in protected or is_link(cur):
                continue
            try:
                for entry in os.scandir(cur):
                    e = Path(entry.path)
                    if entry.is_file(follow_symlinks=False):
                        if e in protected or is_link(e) or _in_excluded(e):
                            continue
                        ident = _capture_identity(e)
                        if not ident or ident.get("type") == "link_or_reparse":
                            protected.add(e)
                            continue
                        try:
                            files.append((e, int(e.stat().st_size), ident))
                        except OSError:
                            files.append((e, 0, ident))
                    elif entry.is_dir(follow_symlinks=False):
                        ident = _capture_identity(e)
                        if not ident or ident.get("type") == "link_or_reparse":
                            protected.add(e)
                            continue
                        if _in_excluded(e):
                            protected.add(e)
                            continue
                        dirs.append((e, ident))
                        stack.append(e)
            except OSError:
                protected.add(cur)

        total = sum(sz for _, sz, _ in files)
        return {"bytes": total, "files": files, "dirs": dirs,
                "protected": sorted(protected), "root": path,
                "root_identity": root_identity}


    def _apply_tree_plan(self, plan: dict, desc: str, owner_group: str | None = None) -> tuple[int, bool]:
        """REAL delete of a planned tree. Returns (freed, fully_removed).

        MUTATES the filesystem. MUST be unreachable when dry_run is True.
        Every file, every directory and the root itself passes the mutation
        authorization gate immediately before its mutation (F1): a replaced /
        swapped / linked object is SKIPPED, never touched. No ad-hoc checks
        elsewhere -- this is the single chokepoint.

        owner_group (T-131): the owning process state is re-checked just-in-time
        before the mutation batch and periodically (every _OWNER_REFRESH_BATCH
        files); a running/UNKNOWN owner aborts the remaining mutations.
        """
        freed = 0
        root = plan["root"]
        root_identity = plan["root_identity"]
        files = sorted(plan["files"], key=lambda x: len(x[0].parts), reverse=True)
        for idx, (f, sz, ident) in enumerate(files):
            self.check_cancel()
            if owner_group is not None and idx % _OWNER_REFRESH_BATCH == 0 and not self._owner_gate_ok(owner_group):
                self.log.skipped(root, f"'{owner_group}' became running or unknown; aborting remaining target mutations")
                return freed, False
            freed += self._apply_file_plan(f, sz, ident).bytes_freed

        if owner_group is not None and not self._owner_gate_ok(owner_group):
            self.log.skipped(root, f"'{owner_group}' became running or unknown; aborting remaining target mutations")
            return freed, False

        fully = root not in plan["protected"]
        for d, ident in sorted(plan["dirs"], key=lambda x: len(x[0].parts), reverse=True):
            if d in plan["protected"]:
                continue
            self.check_cancel()
            # T-137: the emptiness check runs FIRST, then a FRESH authorization is
            # immediately adjacent to the rmdir -- nothing but the mutation itself
            # may sit between the final auth and the destructive call.
            try:
                if not any(d.iterdir()):
                    ok, reason = self._authorize_mutation(d, ident)
                    if not ok:
                        self.log.skipped(d, reason)
                        fully = False
                        continue
                    d.rmdir()
            except OSError:
                fully = False
        if fully:
            try:
                if not any(root.iterdir()):
                    ok, reason = self._authorize_mutation(root, root_identity)
                    if not ok:
                        self.log.skipped(root, reason)
                        fully = False
                    else:
                        root.rmdir()
                else:
                    fully = False
            except OSError:
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


    def _del_dir_contents(self, path: Path, desc: str, owner_group: str | None = None) -> int:

        if not path.exists() or not path.is_dir(): return 0

        if is_link(path):
            self.log.skipped(path, "Symlink/reparse point refused")
            return 0

        if not self._ledger_gate(path, desc):
            return 0

        freed = 0

        items = []
        try:
            for item in path.iterdir():
                self.check_cancel()
                ok, reason = self.guard.is_safe(item)
                if not ok:
                    self.log.skipped(item, reason)
                    continue
                items.append(item)
        except (PermissionError, OSError):
            self.log.warning("Directory iteration failed during content deletion")

        def _handle(item: Path) -> int:
            self.check_cancel()
            if is_link(item):
                self.log.skipped(item, "Symlink/reparse point refused")
                return 0
            if item.is_dir():
                return self._del_dir(item, f"{desc} / {item.name}")
            if item.is_file():
                return self._del_file(item, f"{desc} / {item.name}")
            return 0

        if not items:
            self._ledger_claim(path)
            return 0

        if owner_group is not None and not self._owner_gate_ok(owner_group):
            self.log.skipped(path, f"'{owner_group}' became running or unknown before delete; aborting target")
            return 0

        if self.max_threads > 1 and len(items) > 1:
            # Bounded in-flight futures (T-094/T-132): cancel is checked before
            # every submit, submissions stop immediately on cancel, pending
            # futures are cancelled, and the executor shuts down with
            # cancel_futures=True so running work stops at the next
            # cancel-aware mutation gate. Owner state (T-131) is re-checked
            # once per batch window, never per child.
            _MAX_IN_FLIGHT = max(1, self.max_threads * 4)
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                pending = set()
                idx = 0
                try:
                    while idx < len(items):
                        self.check_cancel()
                        if owner_group is not None and not self._owner_gate_ok(owner_group):
                            self.log.skipped(path, f"'{owner_group}' became running or unknown mid-sweep; aborting remaining mutations")
                            break
                        while idx < len(items) and len(pending) < _MAX_IN_FLIGHT:
                            pending.add(executor.submit(_handle, items[idx]))
                            idx += 1
                        if idx >= len(items):
                            break
                        done, pending = concurrent.futures.wait(pending, return_when=concurrent.futures.FIRST_COMPLETED)
                        for f in done:
                            freed += f.result()
                    for f in concurrent.futures.as_completed(pending):
                        freed += f.result()
                except CancelJobException:
                    for fut in pending:
                        fut.cancel()
                    executor.shutdown(cancel_futures=True)
                    raise
                except Exception as e:
                    self.log.warning(f"Future result failed: {e}")
        else:
            for item in items:
                self.check_cancel()
                if owner_group is not None and not self._owner_gate_ok(owner_group):
                    self.log.skipped(path, f"'{owner_group}' became running or unknown mid-sweep; aborting remaining mutations")
                    break
                freed += _handle(item)
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

        if not cdir.exists(): return 0

        self.log.section("Cent Browser")

        freed = self._clean_chromium_userdata(ud, "cent") + self._clean_chromium_profiles(ud, "cent")

        for p, d in [(cdir/"debug.log", "debug.log"), (cdir/"old_chrome.exe", "old_chrome.exe"), (cdir/"old_chrome_proxy.exe", "old_chrome_proxy.exe")]:

            freed += self.safe_del_file(p, f"[Cent] {d}", "cent")

        return freed


    def clean_brave(self) -> int:

        self.refresh_running()

        bdir = self.root / "__SOFT" / "_BRAVE"

        data = bdir / "data"

        if not bdir.exists(): return 0

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

        if not fdir.exists(): return 0

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

        if not odir.exists(): return 0

        self.log.section("Opera")

        return self._clean_old_opera_versions(odir) + self.safe_del_dir(odir / "old_status", "[Opera] old_status", "opera")


    def clean_telegram(self) -> int:

        self.refresh_running()

        tdir = self.root / "_TG"

        tdata = tdir / "tdata"

        ud = tdata / "user_data"

        if not tdir.exists(): return 0

        self.log.section("Telegram")

        freed = 0

        for p, d in [(tdata/"temp_data", "temp_data"), (tdata/"dumps", "crash dumps"), (ud/"cache", "media cache"), (ud/"media_cache", "media_cache"), (ud/"wvbots", "wvbots"), (ud/"wvother", "wvother")]:

            freed += self.safe_del_dir(p, f"[Telegram] {d}", "telegram")

        freed += self.safe_del_dir_contents(tdata / "temp", "[Telegram] temp dir contents", "telegram")

        for name in ["log.txt", "log_start0.txt", "log_start1.txt", "log_start2.txt", "log_start3.txt"]:

            freed += self.safe_del_file(tdir / name, f"[Telegram] {name}", "telegram")

        return freed


    def _universal_owner_for(self, path: Path) -> str | None:
        """Resolve the owning app group for a discovered cache dir (T-098).

        Walks ancestors up to the portable root and maps the known portable app
        directories to their process groups. Returns None when no verified
        owner exists -- such a target must never be deleted under unknown
        ownership.
        """
        cur = path.parent
        while cur != self.root:
            try:
                cur.relative_to(self.root)
            except ValueError:
                break
            name = cur.name.lower()
            if name == "_cent":
                return "cent"
            if name == "_tg":
                return "telegram"
            if name == "_brave":
                return "brave"
            if name == "_opera":
                return "opera"
            if name == "_firefox":
                return "firefox"
            cur = cur.parent
        return None


    def clean_universal_caches(self) -> int:

        freed = 0

        if not self.root.exists() or not self.root.is_dir(): return 0

        self.refresh_running()  # T-092: fresh snapshot before this app group

        self.log.section(f"Universal Sweeper: {self.root}")


        target_names = {"cache", "code cache", "gpucache", "shadercache", "dawncache", "media cache", "crashpad", "crash reports", "logs"}


        # Max recursion depth to prevent locking UI for too long

        bfs_queue = [(self.root, 0)]

        MAX_DEPTH = 5


        while bfs_queue:

            self.check_cancel()

            current_dir, depth = bfs_queue.pop(0)

            if depth > MAX_DEPTH: continue


            try:

                for item in current_dir.iterdir():

                    self.check_cancel()

                    if item.is_dir() and not item.is_symlink():

                        if item.name.lower() in target_names:

                            # T-124/T-125: Universal Sweeper is fallback
                            # DISCOVERY only, never a second planner for the
                            # same physical cache.
                            #  - caches under a known portable app dir are owned
                            #    by that app's DEDICATED sweeper -> defer, never
                            #    plan a second time (one object -> one candidate).
                            #  - caches with NO verified owner are NOT actionable
                            #    in any mode: reported separately as DISCOVERED /
                            #    NOT AUTHORIZED with zero planned bytes, zero
                            #    candidates, zero progress.
                            if self.ledger is not None and self.ledger.covered(item):
                                self.log.skipped(item, "Already covered by an earlier candidate claim")
                                continue
                            owner = self._universal_owner_for(item)
                            if owner is not None:
                                self.log.skipped(item, f"Owned by dedicated sweeper ('{owner}'); universal discovery defers")
                                continue
                            self.log.info(f"  [DISCOVERED] {item} -- no verified owner; NOT AUTHORIZED to delete")

                        else:

                            bfs_queue.append((item, depth + 1))

            except (PermissionError, OSError):

                pass  # expected: some system dirs are inaccessible


        return freed


    def run_all(self) -> int:

        freed = self.clean_cent() + self.clean_brave() + self.clean_firefox() + self.clean_opera() + self.clean_telegram()

        freed += self.clean_universal_caches()

        return freed


class SystemCleaner(CleanerEngine):

    """Cleans OS level junk (Temp, Thumbnails, CrashDumps)."""

    def __init__(self, dry_run: bool, log: Logger, max_threads: int = DEFAULT_THREADS, targets: dict[str, bool] | None = None, cancel_event: threading.Event | None = None,

                 exclude_patterns: list[str] | None = None, exclude_paths: list[str] | None = None, progress=None, ledger: CandidateLedger | None = None):

        # The root here isn't a single drive, so we pass dummy C:\.

        # But we create a specialized SafetyGuard for each system path.

        super().__init__(dry_run, log, SafetyGuard(Path("C:\\")), Path("C:\\"), max_threads, cancel_event,

                         exclude_patterns=exclude_patterns, exclude_paths=exclude_paths, progress=progress, ledger=ledger)

        self.targets = targets if targets is not None else {}

        # F4: per-target planned/freed bytes populated by run_all. This is the
        # single source of truth shared by dry-run, --status and the GUI
        # preview/progress estimation (calculate_target_sizes feeds off it).
        self.results: dict[str, int] = {}


    def _set_guard(self, root: Path) -> SafetyGuard:

        """Switch the active guard to `root`, keeping engine exclusions (P0-3).

        System-internal targets are hardcoded, reviewed cleanup roots; they are
        allowed to be shallow (F3: the shallow-target capability is reserved
        for these internal targets, never for user-supplied custom rules).
        """

        self.guard = self.make_guard(root, allow_shallow_system_target=True)

        return self.guard


    def run_all(self) -> int:

        self.log.section("System Junk (C:\\)")

        freed = 0


        # System Temp

        if self.targets.get("System Temp", True) and SYSTEM_TEMP is not None and SYSTEM_TEMP.exists():

            self._set_guard(SYSTEM_TEMP)

            before = freed

            freed += self._del_dir_contents(SYSTEM_TEMP, "Windows System Temp")

            self.results["System Temp"] = freed - before


        # User Temp

        if self.targets.get("User Temp", True) and USER_TEMP is not None and USER_TEMP.exists():

            self._set_guard(USER_TEMP)

            before = freed

            freed += self._del_dir_contents(USER_TEMP, "Windows User Temp")

            self.results["User Temp"] = freed - before


        # User CrashDumps

        if self.targets.get("App CrashDumps", True) and USER_CRASH is not None and USER_CRASH.exists():

            self._set_guard(USER_CRASH)

            before = freed

            freed += self._del_dir_contents(USER_CRASH, "Windows App CrashDumps")

            self.results["App CrashDumps"] = freed - before


        # Explorer Thumbnails

        if self.targets.get("Explorer Thumbnails", True) and USER_EXPLORER is not None and USER_EXPLORER.exists():

            guard = self._set_guard(USER_EXPLORER)

            before = freed

            try:

                for item in USER_EXPLORER.iterdir():

                    if item.is_file() and item.name.lower().startswith("thumbcache_") and guard.is_safe(item)[0]:

                        freed += self._del_file(item, f"Thumbnail Cache: {item.name}")

                tcd = USER_EXPLORER / "ThumbCacheToDelete"

                if tcd.is_dir() and guard.is_safe(tcd)[0]:

                    freed += self._del_dir(tcd, "Thumbnail Cache: ThumbCacheToDelete")

            except OSError:

                pass  # expected: thumbnail cache may be in use

            self.results["Explorer Thumbnails"] = freed - before


        # Deep AppData Caches

        for target_path, desc, *rest in USER_APPDATA_TARGETS:

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

            wu_path = Path("C:\\Windows\\SoftwareDistribution\\Download")

            if wu_path.exists():

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
                        freed += self._del_dir_contents(wu_path, "Windows Update Cache")
                    else:
                        freed += self._clean_windows_update_cache(wu_path)

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

                    result = subprocess.run(["ipconfig", "/flushdns"], capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)

                    if result.returncode == 0:

                        self.log.info("  [DNS] Successfully flushed DNS Resolver Cache.")

                    else:

                        self.log.warning(f"Failed to flush DNS Resolver Cache (exit {result.returncode})")

                except Exception:

                    self.log.warning("Failed to flush DNS Resolver Cache")


        # Recycle Bin

        if self.targets.get("Recycle Bin", False):

            if self.dry_run:

                self.log.info("  [Recycle Bin] Would empty Recycle Bin.")

            else:

                import ctypes

                # SHERB_NOCONFIRMATION = 1, SHERB_NOPROGRESSUI = 2, SHERB_NOSOUND = 4

                result = ctypes.windll.shell32.SHEmptyRecycleBinW(None, None, 7)

                if result == 0:

                    self.log.info("  [Recycle Bin] Successfully emptied the Recycle Bin.")

                else:

                    self.log.warning(f"Recycle Bin empty failed (result {result})")


        # Deep C: Junk

        if self.targets.get("Deep C: Junk", True):

            self.log.section("Deep C: Junk")

            before = freed

            freed += self._deep_junk_sweep()

            self.results["Deep C: Junk"] = freed - before

        return freed


    def _service_state(self, name: str) -> str | None:
        """Query a Windows service state via 'sc query'. None = unknown/error."""
        try:
            r = subprocess.run(["sc", "query", name], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
        except Exception:
            return None
        if r.returncode != 0:
            return None
        m = re.search(r"\bSTATE\s*:\s*\d+\s+([A-Z_]+)", r.stdout, re.IGNORECASE)
        return m.group(1).upper() if m else None


    def _clean_windows_update_cache(self, wu_path: Path) -> int:
        """F2/T-095: transaction-safe wuauserv stop / clean / restore.

        Deletion is authorized ONLY by an EXACT 'STOPPED' state:
        - Queries the ORIGINAL service state.
        - RUNNING / START_PENDING -> requests a stop.
        - STOP_PENDING is WAIT, not authorization: the state is polled until
          the EXACT 'STOPPED' value appears, bounded by _WU_STOP_POLL_TIMEOUT.
        - timeout, nonzero stop exit, UNKNOWN, PAUSED or any unhandled state
          => SKIP the cache deletion (never delete under an unverified state).
        - Restores the ORIGINAL state in a finally, so a cancellation or
          deletion error cannot leave wuauserv stopped.
        - Originally STOPPED => stays stopped (never started).
        - Dry-run performs ZERO service mutation (the caller only reaches this
          path when dry_run is False).
        """
        import subprocess

        freed = 0
        orig = self._service_state("wuauserv")
        if orig is None:
            self.log.warning("wuauserv state unknown; skipping Windows Update Cache")
            return 0
        if orig not in ("RUNNING", "STOPPED", "START_PENDING"):
            self.log.warning(f"wuauserv in unhandled state {orig!r}; skipping Windows Update Cache")
            return 0

        should_stop = orig in ("RUNNING", "START_PENDING")
        if not should_stop:
            # already EXACTLY STOPPED: deletion may proceed, nothing to restore.
            return self._del_dir_contents(wu_path, "Windows Update Cache")

        # We are about to stop a service that was running. Whatever happens
        # afterwards -- stop failure, STOP_PENDING timeout, cancellation,
        # deletion error -- the ORIGINAL state is restored in a finally, so the
        # service can never be left stopped by this method.
        try:
            stop = subprocess.run(["net", "stop", "wuauserv"], capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
            if stop.returncode not in (0, 2):
                self.log.warning(f"Failed to stop wuauserv (exit {stop.returncode}); skipping Windows Update Cache")
                return 0
            deadline = time.monotonic() + _WU_STOP_POLL_TIMEOUT
            while True:
                now = self._service_state("wuauserv")
                if now == "STOPPED":
                    break
                if now == "STOP_PENDING":
                    if time.monotonic() >= deadline:
                        self.log.warning("wuauserv stuck in STOP_PENDING; skipping Windows Update Cache")
                        return 0
                    time.sleep(_WU_STOP_POLL_INTERVAL)
                    continue
                self.log.warning(f"wuauserv did not reach STOPPED (now {now!r}); skipping Windows Update Cache")
                return 0
            freed += self._del_dir_contents(wu_path, "Windows Update Cache")
            return freed
        finally:
            start = subprocess.run(["net", "start", "wuauserv"], capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
            if start.returncode != 0:
                self.log.warning(f"Failed to restart wuauserv (exit {start.returncode})")


    def _deep_junk_sweep(self) -> int:

        freed = 0

        self.refresh_running()  # T-092: fresh snapshot, never reuse stale startup state

        # T-091: install the C:\ guard as the ACTIVE guard so deletion
        # primitives validate against it, not a stale AppData target root.
        guard = self._set_guard(Path("C:\\"))

        # T-147: poisoned/absent env roots are disabled -- the sweep uses an
        # impossible relative placeholder so every glob below is empty and the
        # guard refuses anything, instead of sweeping an arbitrary directory.
        loc = _LOCALAPPDATA if _LOCALAPPDATA is not None else Path("__INVALID_LOCALAPPDATA__")

        prog = _APPDATA if _APPDATA is not None else Path("__INVALID_APPDATA__")

        # updater leftovers in %TEMP% (-updater / @ tails)

        if USER_TEMP is not None:
            try:

                for item in USER_TEMP.iterdir():

                    self.check_cancel()

                    if item.is_dir() and (item.name.endswith("-updater") or item.name.endswith("@")) and guard.is_safe(item)[0]:

                        freed += self._del_dir(item, f"Updater leftover: {item.name}")

            except OSError:

                pass

        # Viber QmlWebCache / Thumbnails (per-account subdir, under Roaming)
        # T-092: app-specific vector obeys the running-app gate.

        if not is_app_running("viber", self.running):

            try:

                for vdir in (prog / "ViberPC").glob("*/QmlWebCache"):

                    self.check_cancel()

                    if guard.is_safe(vdir)[0]:

                        freed += self._del_dir(vdir, f"[Viber] QmlWebCache: {vdir.parent.name}")

                for vdir in (prog / "ViberPC").glob("*/Thumbnails"):

                    self.check_cancel()

                    if guard.is_safe(vdir)[0]:

                        freed += self._del_dir(vdir, f"[Viber] Thumbnails: {vdir.parent.name}")

            except OSError:

                pass

        # leftover installer temps in %LOCALAPPDATA%

        try:

            for f in loc.glob("*.exe.tmp"):

                self.check_cancel()

                if guard.is_safe(f)[0]:

                    freed += self._del_file(f, f"Installer temp: {f.name}")

        except OSError:

            pass

        # Eagle logs (T-092: running-app gate)
        if not is_app_running("eagle", self.running):

            for pat, desc in [("ai-search*.log", "Eagle log: {name}"), ("log.old.log", "Eagle old log: {name}")]:

                try:

                    for f in (loc / "Eagle").glob(pat):

                        self.check_cancel()

                        if guard.is_safe(f)[0]:

                            freed += self._del_file(f, desc.format(name=f.name))

                except OSError:

                    pass

        # Yandex.Disk leftover logs (T-099: *.bak rollback files are never auto-deleted;
        # T-092: running-app gate)

        if not is_app_running("yandexdisk", self.running):

            yd = loc / "Yandex" / "Yandex.Disk.2"

            try:

                for f in yd.glob("*.log"):

                    self.check_cancel()

                    if guard.is_safe(f)[0]:

                        freed += self._del_file(f, f"Yandex.Disk log: {f.name}")

            except OSError:

                pass

        # Claude desktop app.asar rollback is NOT auto-deleted (T-099)

        # Autodesk ODIS log

        odis_log = prog / "Autodesk" / "ODIS" / "DDA.log"

        if odis_log.is_file() and guard.is_safe(odis_log)[0]:

            freed += self._del_file(odis_log, f"Autodesk ODIS log: {odis_log.name}")

        # GitHub CLI run-log zips (cache dir only; device-id/config stay; T-092 gate)

        if not is_app_running("githubcli", self.running):

            try:

                for f in (loc / "GitHub CLI").glob("run-log-*.zip"):

                    self.check_cancel()

                    if guard.is_safe(f)[0]:

                        freed += self._del_file(f, f"GitHub CLI run-log: {f.name}")

            except OSError:

                pass

        # Firefox system profile caches (profile dirs vary per machine)

        if not is_app_running("firefox", self.running):

            try:

                for prof in (loc / "Mozilla" / "Firefox" / "Profiles").glob("*"):

                    self.check_cancel()

                    for sub in ["startupCache", "cache2", "shader-cache", "crashes", "minidumps"]:

                        p = prof / sub

                        if p.is_dir() and guard.is_safe(p)[0]:

                            freed += self._del_dir(p, f"Firefox {sub}: {prof.name}")

            except OSError:

                pass

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

            path_str = rule.get("path", "")

            pattern = rule.get("pattern", "*")

            if not path_str: continue


            target = Path(path_str)

            if is_path_blacklisted(target):

                self.log.warning(f"Custom rule path is protected (blacklisted): {target}")

                continue

            if not target.exists() or not target.is_dir():

                self.log.warning(f"Custom rule path not found or not dir: {target}")

                continue


            self.guard = self.make_guard(target)

            guard = self.guard


            try:

                if pattern == "*":

                    freed += self._del_dir_contents(target, f"Custom: {target}")

                else:

                    for item in target.glob(pattern):

                        if guard.is_safe(item)[0]:

                            if item.is_file(): freed += self._del_file(item, f"Custom: {item.name}")

                            elif item.is_dir(): freed += self._del_dir(item, f"Custom: {item.name}")

            except OSError as e:

                self.log.error(f"Custom rule failed on {target}: {e}")


        return freed



#  CUSTOM RULES CONFIG



BLACKLIST_PATHS = {

    Path("C:\\").resolve(),

    Path(os.environ.get("windir", r"C:\Windows")).resolve(),

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
            continue
    return False


_CONTROL_CHARS = frozenset(chr(i) for i in range(32) if chr(i) not in "\t\n\r")


def normalize_path(raw, require_absolute: bool = True) -> Path | None:
    """Canonicalize a user-supplied path. Fixes slash style, trailing separators,
    dot segments, quotes, duplicates, expands %ENV% vars. Returns None for garbage.

    The canonical (resolved) form is what everything downstream compares against,
    so 'D:\\Portable\\..\\Portable\\' and 'D:/Portable' become one identical path.
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
    """

    valid, cfg, errors = _load_and_validate()

    if not valid:

        for e in errors:

            logging.getLogger("vac_cleaner").warning(f"Config invalid: {e}")

        return _default_config()

    return cfg


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


def load_config_strict() -> tuple[bool, dict, list[str]]:
    """(valid, config, errors) for the destructive job boundary (T-138).

    Fresh MISSING config -> (True, defaults, []) -- creating a default is safe.
    An EXISTING malformed config -> (False, {}, errors): the DELETE path MUST
    NOT run a destructive job with silently-empty exclusions/policy. Each
    safety-critical field is validated independently, so one malformed field
    can never silently erase the others.
    """
    return _load_and_validate()


def _load_and_validate() -> tuple[bool, dict, list[str]]:

    default_cfg = _default_config()

    if not CONFIG_FILE.exists():

        try:

            with open(CONFIG_FILE, "w", encoding="utf-8") as f:

                json.dump(default_cfg, f, indent=4)

        except OSError:

            pass  # read-only FS: config stays in-memory only

        return True, default_cfg, []

    try:

        with open(CONFIG_FILE, "r", encoding="utf-8") as f:

            data = json.load(f)

    except (OSError, ValueError) as exc:

        return False, {}, [f"config file unreadable or not valid JSON: {exc}"]

    # explicit per-field type validation (T-138): a wrong type in any
    # safety-critical field invalidates the WHOLE existing config for DELETE.
    errors: list[str] = []

    if not isinstance(data, dict):

        return False, {}, ["config root must be a JSON object"]

    if not isinstance(data.get("portable_roots", []), list) or any(not isinstance(r, str) for r in data.get("portable_roots", [])):
        errors.append("portable_roots must be a list of path strings")

    rules = data.get("custom_rules", [])
    if not isinstance(rules, list):
        errors.append("custom_rules must be a list of rule objects")
    else:
        for i, r in enumerate(rules):
            if not isinstance(r, dict) or not isinstance(r.get("path"), str):
                errors.append(f"custom_rules[{i}] must be an object with a string 'path'")

    ep = data.get("exclude_patterns", [])
    if not isinstance(ep, list) or any(not isinstance(p, str) for p in ep):
        errors.append("exclude_patterns must be a list of strings")

    xp = data.get("exclude_paths", [])
    if not isinstance(xp, list) or any(not isinstance(p, str) for p in xp):
        errors.append("exclude_paths must be a list of strings")

    st = data.get("system_targets", {})
    if not isinstance(st, dict) or any(not isinstance(k, str) or not isinstance(v, bool) for k, v in st.items()):
        errors.append("system_targets must be an object mapping target names to booleans")

    if not isinstance(data.get("auto_clean_interval_hours", 0), (int, float)):
        errors.append("auto_clean_interval_hours must be a number")

    if not isinstance(data.get("lang", "en"), str):
        errors.append("lang must be a string")

    if not isinstance(data.get("window_geometry", ""), str):
        errors.append("window_geometry must be a string")

    if errors:
        return False, {}, errors

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

    data["exclude_paths"] = [str(p) for p in (normalize_path(ep) for ep in data.get("exclude_paths", [])) if p is not None]

    raw_st = data.get("system_targets")

    if not isinstance(raw_st, dict):

        raw_st = {}

        data["system_targets"] = {}

    for name in raw_st:

        if name not in SYSTEM_TARGET_DEFAULTS:

            logging.getLogger("vac_cleaner").warning(f"Unknown system target in config dropped: {name}")

    data["system_targets"] = {k: bool(v) for k, v in raw_st.items() if k in SYSTEM_TARGET_DEFAULTS}

    # Only now -- after type validation AND normalization both passed -- is the
    # in-memory migration persisted (best-effort; a read-only FS keeps it
    # in-memory only). The on-disk config is never written before this point.
    if migrated_profiles:
        try:
            with open(CONFIG_FILE, "w", encoding="utf-8") as f2:
                json.dump(data, f2, indent=4)
        except OSError:
            pass  # migration persist is best-effort

    return True, data, []


def parse_geometry(geom: str, default: str = "960x640", min_w: int = 800, min_h: int = 500) -> str:
    """Validate a Tk geometry string "WxH+X+Y" and clamp it to the minimums."""
    geom = (geom or "").strip()
    if not geom:
        return default
    m = re.fullmatch(r"(\d+)x(\d+)(?:([+-]\d+)([+-]\d+))?", geom)
    if not m:
        return default
    w, h = max(int(m.group(1)), min_w), max(int(m.group(2)), min_h)
    return f"{w}x{h}{m.group(3) or ''}{m.group(4) or ''}"


def save_config(config: dict) -> bool:
    """Persist config atomically. Returns True on success (T-141).

    Callers must treat a False result as a persistence failure and must NOT
    report "saved" / close editors over it -- a silent drop would make the user
    believe their exclusions/targets are active when they are not.
    """

    try:

        tmp_file = CONFIG_FILE.with_suffix(".json.tmp")

        with open(tmp_file, "w", encoding="utf-8") as f:

            json.dump(config, f, indent=4)

        tmp_file.replace(CONFIG_FILE)

        return True

    except Exception as e:
        logging.getLogger("vac_cleaner").warning(f"Failed to save config: {e}")
        return False


# PROGRESS TRACKER
class ProgressTracker:
    def __init__(self):
        self.lock = threading.Lock()
        self.categories = {}
        self.category_order = []
        self.current_category = ''
        self.start_time = time.time()
    def start_category(self, name, total_estimate=0):
        with self.lock:
            self.current_category = name
            if name not in self.categories:
                self.categories[name] = {'current': 0, 'total': total_estimate, 'bytes': 0, 'status': 'running'}
                self.category_order.append(name)
            else:
                self.categories[name]['status'] = 'running'
    def advance(self, bytes_freed=0):
        with self.lock:
            if self.current_category and self.current_category in self.categories:
                c = self.categories[self.current_category]
                c['current'] += 1
                c['bytes'] += bytes_freed
    def finish_category(self, status='done', total_bytes=None):
        with self.lock:
            if self.current_category and self.current_category in self.categories:
                c = self.categories[self.current_category]
                c['status'] = status
                if total_bytes is not None:
                    # F8: feed the layer's real planned total from the shared
                    # planner so a completed layer shows a truthful determinate bar.
                    c['total'] = total_bytes
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
            # F8: a determinate bar is only truthful when a real total exists.
            # While any running category has no known total, the UI must use an
            # indeterminate/status mode instead of a fake 0% determinate bar.
            running_unknown = any(c.get('status') == 'running' and c.get('total', 0) <= 0 for c in self.categories.values())
            return {'categories': cats, 'total_current': items_done, 'total_bytes': total_bytes,
                    'total_items_done': items_done, 'total_bytes_planned': planned_bytes,
                    'running_unknown_total': running_unknown, 'elapsed': elapsed,
                    'current_category': self.current_category}


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
        self.dry_run = bool(dry_run)
        self.run_portable = bool(run_portable)
        self.run_system = bool(run_system)
        self.run_custom = bool(run_custom)
        self.config = config
        self.sys_targets = sys_targets
        self.exclude_patterns = tuple(exclude_patterns)
        self.exclude_paths = tuple(exclude_paths)
        self.ledger = ledger
        self.surface = surface
        self.system_roots = system_roots if system_roots is not None else resolve_system_roots()


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
        "appdata_target_count": len(USER_APPDATA_TARGETS),
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
        roots = [Path(r) for r in cfg.get('portable_roots', []) if Path(r).exists()]
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
        sc = SystemCleaner(dry_run, log, max_threads, spec.sys_targets, cancel_event, exclude_patterns=exclude_patterns, exclude_paths=exclude_paths, progress=progress, ledger=spec.ledger)
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
    valid, config, config_errors = load_config_strict()
    if not valid:
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


# ── Vintage Dark-Golden token map (UI.md spec) ──────────────────────
WIN95_BG           = '#1A1810'
WIN95_BG_SOFT      = '#232018'
WIN95_SURFACE_RAISED = '#3D372A'
WIN95_SURFACE_ALT  = '#453D30'
WIN95_BEVEL_HI     = '#75663D'
WIN95_BEVEL_SH     = '#100E08'
WIN95_TEXT         = '#D4C89A'
WIN95_TEXT_DIM     = '#9C9371'
WIN95_TEXT_MUTED   = '#6E674E'
WIN95_GOLD         = '#D4C89A'
WIN95_GOLD_DIM     = '#9C9371'
WIN95_ACCENT       = '#008080'
WIN95_DANGER       = '#7A2020'  # using dangerText for better contrast
WIN95_SUCCESS      = '#4A7A20'
WIN95_BUTTON       = '#3D372A'
WIN95_BUTTON_HOVER = '#453D30'
WIN95_ENTRY        = '#1A1810'
Z = 0  # corner_radius: 0 everywhere (sharp 90° rectangles)

ctk.set_appearance_mode('dark')
ctk.set_default_color_theme('dark-blue')  # neutral base, overridden per widget
native_font = ('Verdana', 11)         # vintage UI font
data_font   = ('Courier New', 10)           # data / log values

# Bevel helpers вЂ” simulated via border_color on CTk widgets
# raised: top-left highlight, bottom-right shadow в†’ border_color=BEVEL_HI (CTk uses single colour)
# CTk border_color accepts [light, dark] tuple; we use single value, bevel via fg contrast
BEVEL_RAISED = WIN95_BEVEL_HI   # border on raised controls
BEVEL_SUNKEN = WIN95_BEVEL_SH   # border on sunken/entry controls



class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.config = load_config()
        self.T = load_strings(self.config.get("lang", "en"))
        self.title(f"{self.T['window_title']} v{VERSION}")
        self.geometry(parse_geometry(self.config.get("window_geometry", "")))
        self.minsize(800, 500)
        self.configure(fg_color=WIN95_BG)
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.progress = ProgressTracker()
        self._pulse = 0  # F8: indeterminate-pulse phase counter
        self.log_queue = queue.Queue()
        self.cancel_event = threading.Event()
        self.sys_targets = merged_system_targets(self.config.get("system_targets"))
        self._clean_in_progress = False
        self._clean_timer = None
        self._bg_proc = None
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
        ctk.CTkLabel(side, text=f"VAC CLEANER v{VERSION}", font=("Verdana", 14, "bold"), text_color=WIN95_TEXT).grid(row=row, column=0, pady=(14, 4), padx=8)
        row += 1
        self.btn_clean = ctk.CTkButton(side, text=self.T["clean"], font=("Verdana", 12, "bold"), fg_color=WIN95_BUTTON, hover_color=WIN95_BUTTON_HOVER, text_color=WIN95_DANGER, corner_radius=Z, height=34, border_width=2, border_color=BEVEL_RAISED, command=lambda: self._start_job())
        self.btn_clean.grid(row=row, column=0, pady=(16, 6), padx=10, sticky="ew")
        row += 1
        self.btn_stop = ctk.CTkButton(side, text=self.T["stop"], font=native_font, fg_color=WIN95_BUTTON, hover_color=WIN95_BUTTON_HOVER, text_color=WIN95_TEXT, text_color_disabled=WIN95_TEXT_MUTED, corner_radius=Z, height=30, border_width=2, border_color=BEVEL_RAISED, command=self._cancel_job, state="disabled")
        self.btn_stop.grid(row=row, column=0, pady=4, padx=10, sticky="ew")

        row += 1
        self.btn_preview = ctk.CTkButton(side, text=self.T["preview"], font=native_font, fg_color=WIN95_BUTTON, hover_color=WIN95_BUTTON_HOVER, text_color=WIN95_ACCENT, corner_radius=Z, border_width=2, border_color=BEVEL_RAISED, command=self._start_preview)
        self.btn_preview.grid(row=row, column=0, pady=4, padx=10, sticky="ew")

        row += 1
        self.btn_task = ctk.CTkButton(side, text=self.T["install_task"], font=native_font, fg_color=WIN95_BUTTON, hover_color=WIN95_BUTTON_HOVER, text_color=WIN95_ACCENT, corner_radius=Z, border_width=2, border_color=BEVEL_RAISED, command=self._install_scheduled_task)
        self.btn_task.grid(row=row, column=0, pady=4, padx=10, sticky="ew")
        row += 1
        self.btn_bg = ctk.CTkButton(side, text=self.T["run_bg"], font=native_font, fg_color=WIN95_BUTTON, hover_color=WIN95_BUTTON_HOVER, text_color=WIN95_ACCENT, corner_radius=Z, border_width=2, border_color=BEVEL_RAISED, command=self._run_bg)
        self.btn_bg.grid(row=row, column=0, pady=4, padx=10, sticky="ew")
        row += 1
        self.btn_exc = ctk.CTkButton(side, text=self.T["exclusions"], font=native_font, fg_color=WIN95_BUTTON, hover_color=WIN95_BUTTON_HOVER, text_color=WIN95_ACCENT, corner_radius=Z, border_width=2, border_color=BEVEL_RAISED, command=self._open_exclusions)
        self.btn_exc.grid(row=row, column=0, pady=4, padx=10, sticky="ew")
        row += 1
        self.btn_syst = ctk.CTkButton(side, text=self.T["sys_targets"], font=native_font, fg_color=WIN95_BUTTON, hover_color=WIN95_BUTTON_HOVER, text_color=WIN95_ACCENT, corner_radius=Z, border_width=2, border_color=BEVEL_RAISED, command=self._open_system_targets)
        self.btn_syst.grid(row=row, column=0, pady=4, padx=10, sticky="ew")
        self.main_frame = ctk.CTkFrame(self, fg_color=WIN95_BG, corner_radius=Z)
        self.main_frame.grid(row=0, column=1, sticky="nsew", padx=(4,4), pady=4)
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(3, weight=1)
        dash = ctk.CTkFrame(self.main_frame, fg_color=WIN95_BG_SOFT, corner_radius=Z)
        dash.grid(row=0, column=0, sticky="ew")
        dash.grid_columnconfigure(0, weight=1)
        self.dash_stats = ctk.CTkLabel(dash, text="", font=("Verdana",10), text_color=WIN95_TEXT, anchor="w")
        self.dash_stats.grid(row=0, column=0, sticky="ew", padx=8, pady=(6,0))
        self.dash_cat_container = ctk.CTkFrame(dash, fg_color="transparent", corner_radius=Z, height=0)
        self.dash_cat_container.grid(row=1, column=0, sticky="ew", padx=8, pady=(2,0))
        self.dash_cat_container.grid_columnconfigure(0, weight=1)
        self.dash_cat_container.grid_propagate(False)
        self.dash_bar = ctk.CTkProgressBar(dash, fg_color=WIN95_ENTRY, progress_color=WIN95_GOLD, corner_radius=Z, height=12)
        self.dash_bar.grid(row=2, column=0, sticky="ew", padx=8, pady=(4,2))
        self.dash_bar.set(0)
        self.text_log = ctk.CTkTextbox(self.main_frame, fg_color=WIN95_BG, text_color=WIN95_TEXT, font=data_font, corner_radius=Z, border_width=2, border_color=BEVEL_SUNKEN, state="disabled")
        self.text_log.grid(row=3, column=0, sticky="nsew", pady=(4,0))

    def _on_close(self):
        # T-094: request cancellation; actual destroy happens only after the
        # worker thread terminates (polled from the main thread).
        self.cancel_event.set()
        if hasattr(self,"_tray_icon") and self._tray_icon:
            try: self._tray_icon.stop()
            except Exception: pass  # tray may already be gone during close
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
            self.config["window_geometry"] = parse_geometry(self.geometry())
            save_config(self.config)
        except Exception:
            pass  # read-only FS or closing race: best-effort only

    def _full_exit_impl(self):
        # T-094: called from the main-thread poller only, and only once the
        # cleaning worker is confirmed dead (no destroy over a live worker).
        try:
            if self._worker_thread and self._worker_thread.is_alive():
                return
        except Exception:
            return
        self.quit()
        self.destroy()

    def _start_job(self):
        if self._clean_in_progress: return
        if self._close_pending: return
        if not messagebox.askyesno(
                self.T["confirm_title"],
                self.T["confirm_body"],
                parent=self, icon="warning", default="no"):
            return
        self._rebuild_cat_bars()
        self._reset_dashboard()
        self._clean_in_progress = True
        self.cancel_event.clear()
        self.btn_clean.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self.text_log.configure(state="normal")
        self.text_log.delete("1.0", "end")
        self.text_log.configure(state="disabled")
        self.progress = ProgressTracker()
        self._job_done_event.clear()
        # T-128: freeze the job spec on the Tk thread BEFORE the worker starts.
        # The worker reads ONLY this spec, never the mutable GUI state.
        spec = resolve_job_spec(dry_run=False, run_portable=True, run_system=True, run_custom=True,
                                config=self.config, sys_targets=self.sys_targets, surface="gui")
        self._worker_thread = threading.Thread(target=self._run_job, args=(spec,), daemon=True)
        self._worker_thread.start()

    def _start_preview(self):
        # T-107: read-only dry-run -- shows the candidate list, deletes nothing.
        # dry_run=True is physically read-only (T-090 plan/apply separation), so
        # no confirm dialog is needed or shown here.
        if self._clean_in_progress: return
        if self._close_pending: return
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
        # T-128: freeze the job spec before the worker starts (same gui surface).
        spec = resolve_job_spec(dry_run=True, run_portable=True, run_system=True, run_custom=True,
                                config=self.config, sys_targets=self.sys_targets, surface="gui")
        self._worker_thread = threading.Thread(target=self._run_job, args=(spec,), daemon=True)
        self._worker_thread.start()

    def _run_job(self, spec):
        try:
            log = Logger(LOGS_DIR/f"clean_{datetime.now().astimezone():%Y%m%d_%H%M%S}.log", spec.dry_run, gui_callback=self._log)
            # T-126/T-128: the worker consumes ONLY the frozen JobSpec. It never
            # reads self.config / self.sys_targets after start.
            run_cleaning_job(spec, log, cancel_event=self.cancel_event, progress=self.progress)
        except CancelJobException:
            self._log(self.T["cancelled"])
        except Exception as e:
            self._log(f"Error: {e}")
        finally:
            # T-093: the worker never touches Tk; it only signals the main-thread poller.
            self._job_done_event.set()

    def _finish_job(self):
        self._clean_in_progress = False
        self._worker_thread = None
        # Keep the final dashboard snapshot visible instead of wiping it (P2-16).
        self.btn_clean.configure(state="normal")
        self.btn_preview.configure(state="normal")
        self.btn_stop.configure(state="disabled")
        self._schedule_auto_clean()

    def _cancel_job(self):
        self.cancel_event.set()
        self._log(self.T["cancelling"])

    _AUTO_CLEAN_MARKER = "__AUTO_CLEAN__"
    _CLOSE_MARKER = "__CLOSE__"

    def _log(self, m):
        # T-093: worker-safe -- never calls Tk/after from this path.
        self.log_queue.put(m)

    def _poll_main(self):
        """The single main-thread poller (T-093/094). Drains the log queue,
        watches job completion and the shutdown lifecycle, updates the dashboard."""
        try:
            while True:
                m = self.log_queue.get_nowait()
                if m == self._AUTO_CLEAN_MARKER:
                    self._start_job()
                    continue
                if m == self._CLOSE_MARKER:
                    self._on_close()
                    continue
                self.text_log.configure(state="normal")
                self.text_log.insert("end", m + "\n")
                self.text_log.see("end")
                self.text_log.configure(state="disabled")
        except queue.Empty:
            pass
        if self._clean_in_progress and self._job_done_event.is_set():
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

    def _schedule_auto_clean(self):
        if self._clean_timer:
            self._clean_timer.cancel()
        interval = self.config.get("auto_clean_interval_hours", 0)
        if interval > 0:
            self._clean_timer = threading.Timer(interval * 3600, self._auto_clean_trigger)
            self._clean_timer.daemon = True
            self._clean_timer.start()

    def _auto_clean_trigger(self):
        # T-093: timer thread only enqueues; the main-thread poller starts the job.
        if not self._clean_in_progress and not self._close_pending:
            self.log_queue.put(self._AUTO_CLEAN_MARKER)

    def _update_dashboard(self):
        if not self._clean_in_progress:
            return
        s = self.progress.get_snapshot()
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
        if n_cats > 0:
            self.dash_cat_container.configure(height=n_cats * 22)
        else:
            self.dash_cat_container.configure(height=0)
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
                    w['label'].configure(text=f"{nm}: {fmt(byt)} (scanning)" if cat_data['status'] == 'running' else f"{nm}: {fmt(byt)}")
                    w['bar'].set(triangle)

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
        label = ctk.CTkLabel(frame, text=f'{name}: {current}/{total}  {fmt(bytes_freed)}' if total > 0 else f'{name}: {current}  {fmt(bytes_freed)}', font=('Consolas', 9), text_color=WIN95_TEXT_DIM, anchor='w')
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
        try:
            hh, mm = start.split(":")
            if not (0 <= int(hh) < 24 and 0 <= int(mm) < 60):
                return
            install_task(f"{int(hh):02d}:{int(mm):02d}", self.sys_targets)
        except Exception as e:
            logging.getLogger("vac_cleaner").warning(f"Failed to install scheduled task: {e}")

    def _run_bg(self):
        if self._bg_proc is not None and self._bg_proc.poll() is None:
            self._log(self.T["run_bg_running"])
            return
        flags = 0
        for f in ("DETACHED_PROCESS", "CREATE_NEW_PROCESS_GROUP", "CREATE_NO_WINDOW"):
            flags |= getattr(subprocess, f, 0)
        try:
            self._bg_proc = subprocess.Popen(
                background_clean_argv(self.sys_targets),
                cwd=str(BASE_DIR),
                close_fds=True,
                creationflags=flags,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except OSError as e:
            self._log(f"Error: {e}")
            return
        self._log(self.T["run_bg_started"])

    def _open_exclusions(self):
        win = ctk.CTkToplevel(self)
        win.title(self.T["exc_title"])
        win.geometry("640x540")
        win.minsize(560, 440)
        win.configure(fg_color=WIN95_BG)
        win.transient(self)
        win.grab_set()
        win.grid_columnconfigure(0, weight=1)
        win.grid_rowconfigure(4, weight=1)

        ctk.CTkLabel(win, text=self.T["exc_help"], font=native_font, text_color=WIN95_TEXT_DIM, anchor='w').grid(row=0, column=0, sticky='ew', padx=10, pady=(10, 4))
        ctk.CTkLabel(win, text=self.T["exc_patterns"], font=native_font, text_color=WIN95_TEXT, anchor='w').grid(row=1, column=0, sticky='ew', padx=10)
        txt = ctk.CTkTextbox(win, fg_color=WIN95_BG, text_color=WIN95_TEXT, font=data_font, corner_radius=Z, border_width=2, border_color=BEVEL_SUNKEN)
        txt.grid(row=2, column=0, sticky='nsew', padx=10, pady=(2, 8))
        txt.insert('1.0', "\n".join(self.config.get('exclude_patterns', [])))

        ctk.CTkLabel(win, text=self.T["exc_paths"], font=native_font, text_color=WIN95_TEXT, anchor='w').grid(row=3, column=0, sticky='ew', padx=10)
        path_frame = ctk.CTkFrame(win, fg_color=WIN95_BG_SOFT, corner_radius=Z)
        path_frame.grid(row=4, column=0, sticky='nsew', padx=10, pady=(2, 8))
        path_frame.grid_columnconfigure(0, weight=1)
        path_frame.grid_rowconfigure(0, weight=1)
        lb = Listbox(path_frame, bg=WIN95_BG, fg=WIN95_TEXT, selectbackground=WIN95_SURFACE_RAISED, selectforeground=WIN95_TEXT, relief='sunken', bd=2, font=("Courier New", 10), highlightthickness=0, exportselection=False)
        lb.grid(row=0, column=0, sticky='nsew', padx=6, pady=6)
        for p in self.config.get('exclude_paths', []):
            lb.insert('end', str(p))
        btn_col = ctk.CTkFrame(path_frame, fg_color='transparent', corner_radius=Z)
        btn_col.grid(row=0, column=1, sticky='n', padx=(0, 6), pady=6)
        ctk.CTkButton(btn_col, text=self.T["exc_add_path"], width=110, font=native_font, fg_color=WIN95_BUTTON, hover_color=WIN95_BUTTON_HOVER, text_color=WIN95_TEXT, corner_radius=Z, border_width=2, border_color=BEVEL_RAISED, command=lambda: self._exc_add_path(lb)).pack(pady=2)
        ctk.CTkButton(btn_col, text=self.T["exc_remove"], width=110, font=native_font, fg_color=WIN95_BUTTON, hover_color=WIN95_BUTTON_HOVER, text_color=WIN95_TEXT, corner_radius=Z, border_width=2, border_color=BEVEL_RAISED, command=lambda: self._exc_remove_path(lb)).pack(pady=2)

        bar = ctk.CTkFrame(win, fg_color='transparent', corner_radius=Z)
        bar.grid(row=5, column=0, sticky='ew', padx=10, pady=(0, 10))
        bar.grid_columnconfigure(0, weight=1)
        ctk.CTkButton(bar, text=self.T["save"], width=110, font=native_font, fg_color=WIN95_BUTTON, hover_color=WIN95_BUTTON_HOVER, text_color=WIN95_GOLD, corner_radius=Z, border_width=2, border_color=BEVEL_RAISED, command=lambda: self._save_exclusions(win, txt, lb)).grid(row=0, column=0, sticky='w')

    def _exc_add_path(self, lb):
        d = filedialog.askdirectory(parent=lb.winfo_toplevel(), title=self.T["exc_add_path"])
        if d:
            lb.insert('end', str(Path(d)))

    def _exc_remove_path(self, lb):
        sel = lb.curselection()
        if sel:
            lb.delete(sel[0])

    def _save_exclusions(self, win, txt, lb):
        pats = [ln.strip() for ln in txt.get('1.0', 'end').splitlines() if ln.strip()]
        paths = [str(Path(p)) for p in lb.get(0, 'end') if str(p).strip()]
        self.config['exclude_patterns'] = pats
        self.config['exclude_paths'] = paths
        # T-141: on a persistence failure the dialog stays open and the user is
        # told -- never a false "saved" over a silently-dropped config.
        if not save_config(self.config):
            self._log("Error: could not save exclusions (config not writable)")
            return
        win.destroy()
        self._log(self.T["exc_saved"])

    def _open_system_targets(self):
        win = ctk.CTkToplevel(self)
        win.title(self.T["syst_title"])
        win.geometry("480x420")
        win.minsize(400, 320)
        win.configure(fg_color=WIN95_BG)
        win.transient(self)
        win.grab_set()
        win.grid_columnconfigure(0, weight=1)
        win.grid_rowconfigure(3, weight=1)

        ctk.CTkLabel(win, text=self.T["syst_help"], font=native_font, text_color=WIN95_TEXT_DIM, anchor='w', justify='left').grid(row=0, column=0, sticky='ew', padx=10, pady=(10, 6))

        self.syst_vars = {}
        for i, name in enumerate(SYSTEM_TARGET_DEFAULTS):
            var = ctk.BooleanVar(value=bool(self.sys_targets.get(name, False)))
            self.syst_vars[name] = var
            cb = ctk.CTkCheckBox(win, text=name, variable=var, font=native_font,
                                 text_color=WIN95_TEXT, hover_color=WIN95_BUTTON_HOVER,
                                 fg_color=WIN95_BUTTON, border_color=BEVEL_SUNKEN,
                                 corner_radius=Z, border_width=2, checkbox_width=20, checkbox_height=20,
                                 checkmark_color=WIN95_GOLD)
            cb.grid(row=i + 1, column=0, sticky='w', padx=16, pady=4)

        bar = ctk.CTkFrame(win, fg_color='transparent', corner_radius=Z)
        bar.grid(row=len(SYSTEM_TARGET_DEFAULTS) + 1, column=0, sticky='ew', padx=10, pady=(4, 10))
        bar.grid_columnconfigure(0, weight=1)
        ctk.CTkButton(bar, text=self.T["save"], width=110, font=native_font, fg_color=WIN95_BUTTON, hover_color=WIN95_BUTTON_HOVER, text_color=WIN95_GOLD, corner_radius=Z, border_width=2, border_color=BEVEL_RAISED, command=lambda: self._save_system_targets(win)).grid(row=0, column=0, sticky='w')

    def _save_system_targets(self, win):
        for name, var in self.syst_vars.items():
            self.sys_targets[name] = bool(var.get())
        self.config["system_targets"] = dict(self.sys_targets)
        if not save_config(self.config):
            self._log("Error: could not save system targets (config not writable)")
            return
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
    except Exception:
        pass


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


def disabled_safe_targets(sys_targets) -> list[str]:
    """Safe-default targets the user switched OFF (serialized as --disable-targets)."""
    return _target_deviations(sys_targets)[1]


def clean_argv(sys_targets=None) -> list[str]:
    """Canonical argv for a silent full-clean (scheduled + background share this, T-067).

    --all here means portable+system+custom with SAFE system-target defaults.
    `sys_targets` is the FULL target mask (dict or mapping): every deviation
    from the safe defaults is serialized -- risky targets enabled via
    --sys-targets AND safe targets disabled via --disable-targets (T-129), so a
    GUI state that turns System Temp off survives a scheduled/background run.
    Public plain --all semantics stay unchanged: with no mask, the safe
    defaults apply untouched.
    """
    if getattr(sys, "frozen", False):
        argv = [sys.executable, "--cli", "--all", "--delete", "--hidden"]
    else:
        argv = [_get_pythonw(), str(SCRIPT_PATH), "--cli", "--all", "--delete", "--hidden"]
    enables, disables = _target_deviations(sys_targets)
    if enables:
        argv += ["--sys-targets", ",".join(enables)]
    if disables:
        argv += ["--disable-targets", ",".join(disables)]
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
    """
    tr = scheduled_task_command(sys_targets)
    result = subprocess.run(
        ['schtasks', '/create',
         '/tn', TASK_NAME,
         '/tr', tr,
         '/sc', 'daily',
         '/st', time_str,
         '/rl', 'HIGHEST',
         '/f'],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        print(f"Task '{TASK_NAME}' installed -> runs daily at {time_str}, silent full clean.")
        return True
    print(f"schtasks error: {result.stderr.strip()}")
    return False


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
    parser.add_argument("--time", type=str, default="09:00",
                        help="Start time for scheduled task (HH:MM, default 09:00)")
    args = parser.parse_args()

    # ── install-task ──────────────────────────────────────────────────────────
    if args.install_task:
        targets = [t.strip() for t in args.sys_targets.split(",") if t.strip()]
        disables = [t.strip() for t in args.disable_targets.split(",") if t.strip()]
        for t in targets + disables:
            if t not in SYSTEM_TARGET_DEFAULTS:
                print(f"Error: unknown system target '{t}'. Known: {', '.join(SYSTEM_TARGET_DEFAULTS)}")
                sys.exit(2)
        mask = dict(SYSTEM_TARGET_DEFAULTS)
        for t in targets:
            mask[t] = True
        for t in disables:
            mask[t] = False
        sys.exit(0 if install_task(args.time, mask) else 1)

    # ── status ────────────────────────────────────────────────────────────────
    if args.status:
        cli_status()
        return

    # ── analyze-caches ─────────────────────────────────────────────────────────
    if args.analyze_caches:
        from analyze_caches import main as analyze_caches_main
        analyze_caches_main()
        return

    # в”Ђв”Ђ CLI / scheduled mode в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
    dry_run = args.dry_run or not args.delete

    if args.cli or args.portable or args.system or args.custom or args.all:
        if args.hidden:
            _hide_console()
        # T-138: an existing but malformed config must NEVER authorize a
        # destructive run with silently-empty exclusions/policy.
        valid, config, config_errors = load_config_strict()
        if not valid:
            if not dry_run:
                print("Config error - refusing to run a destructive job:", "; ".join(config_errors))
                sys.exit(3)
            for e in config_errors:
                print(f"Warning: config invalid - {e}")
            config = _default_config()
        rp = args.portable or args.all
        rs = args.system or args.all
        rc = args.custom or args.all
        enables = []
        disables = []
        for t in [x.strip() for x in args.sys_targets.split(",") if x.strip()]:
            if t not in SYSTEM_TARGET_DEFAULTS:
                print(f"Error: unknown system target '{t}'. Known: {', '.join(SYSTEM_TARGET_DEFAULTS)}")
                sys.exit(2)
            enables.append(t)
        for t in [x.strip() for x in args.disable_targets.split(",") if x.strip()]:
            if t not in SYSTEM_TARGET_DEFAULTS:
                print(f"Error: unknown system target '{t}'. Known: {', '.join(SYSTEM_TARGET_DEFAULTS)}")
                sys.exit(2)
            disables.append(t)
        ep = [p.strip() for p in args.exclude.split(",") if p.strip()]
        # T-126: resolve the ENTIRE job policy ONCE; the planner consumes only
        # this spec. Plain --all keeps the safe P1-7 defaults; explicit
        # --sys-targets / --disable-targets are the only deviations.
        spec = resolve_job_spec(dry_run=dry_run, run_portable=rp, run_system=rs, run_custom=rc,
                                config=config, cli_excludes=ep,
                                cli_enable=enables, cli_disable=disables, surface="cli")
        log = Logger(
            LOGS_DIR / f"clean_{datetime.now().astimezone():%Y%m%d_%H%M%S}.log",
            dry_run
        )
        run_cleaning_job(spec, log)
        return

    # ── GUI mode ────────────────────────────────────────────────────────────────
    _hide_console()
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()


