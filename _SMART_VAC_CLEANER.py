#!/usr/bin/env python3
# ruff: noqa: BLE001, S110, PLW1510

# -*- coding: utf-8 -*-

"""

_SMART_VAC_CLEANER.py  --  v2.1.0

Portable, dependency-free-ish (customtkinter, pystray, Pillow) smart cleaner
for system junk, app caches, portable-app roots, and user-defined rules.

No hard dependency on any single machine: all candidate portable roots are
always seeded into the config, but only paths that actually EXIST on the
current machine get swept and only known junk patterns inside them are
removed. Missing drives/disks are silently skipped, never errors.

Defense in depth: blacklist, path-part minimums, running-process checks,
symlink refusal, never-delete names, exclude lists, dry-run default.

GUI for interactive use + CLI for automated Task Scheduler execution.

"""


import argparse
import concurrent.futures
import fnmatch
import json
import logging
import os
import queue
import re
import shutil
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
from tkinter import messagebox, simpledialog

import customtkinter as ctk

#  CORE CONFIGURATION



VERSION = "2.4.11"

DEFAULT_THREADS = 12


PRIMARY_ROOT = Path(r"V:\___VAC\__P")

BACKUP_ROOTS = [

    Path(r"G:\__SAVE_G\__P"),

    Path(r"P:\__SAVE_P\___VAC\__P"),

    Path(r"R:\__SAVE_R\__P"),

    Path(r"U:\___VAC\__P"),

]


SCRIPT_PATH = Path(__file__).resolve()

if getattr(sys, "frozen", False):
    BASE_DIR = Path(sys.executable).resolve().parent
else:
    BASE_DIR = SCRIPT_PATH.parent

CONFIG_FILE = BASE_DIR / "cleaner_config.json"

STRINGS_DIR = BASE_DIR / "strings"

DEFAULT_STRINGS: dict[str, str] = {
    "clean": "Clean",
    "stop": "Stop",
    "find_new_junk": "Find New Junk",
    "install_task": "Install Auto-Clean Task",
    "window_title": "Smart VAC Cleaner",
    "confirm_title": "Confirm DELETE",
    "confirm_body": "Files will be permanently removed (no recycle bin).\n\nContinue?",
    "junk_window_title": "Find New Junk",
    "scanning": "Scanning...",
    "nothing_found": "Nothing new found.",
    "cancelled": "Cancelled.",
    "cancelling": "Cancelling...",
    "task_dialog_title": "Auto-Clean Task",
    "task_dialog_prompt": "Daily start time (HH:MM):",
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


APP_PROCESSES: dict[str, set[str]] = {

    "cent":     {"chrome.exe"},

    "brave":    {"brave.exe"},

    "firefox":  {"firefox.exe"},

    "opera":    {"opera.exe"},

    "telegram": {"telegram.exe"},

    "general":  set(),

}


NEVER_DELETE_NAMES: frozenset = frozenset({

    "login data", "login data for account", "bookmarks", "bookmarks.bak",

    "preferences", "secure preferences", "web data", "local state",

    "extensions", "local extension settings", "managed extension settings",

    "sync extension settings", "sync app settings", "sync data",

    "extension rules", "extension scripts", "extension state", "dnr extension rules",

    "client certificates", "accounts", "network persistent state", "transportsecurity",

    "cookies", "extension cookies", "widevinecdm",

    "key4.db", "logins.json", "logins-backup.json", "cert9.db", "pkcs11.txt", "prefs.js",

    "places.sqlite", "cookies.sqlite",

    "key_datas", "settingss", "a7fdf864fbc10b77", "d877f783d5d3ef8c",

})


CHROMIUM_PROFILE_DIRS = ["Cache", "Code Cache", "GPUCache", "DawnCache", "DawnGraphiteCache", "DawnWebGPUCache", "blob_storage", "VideoDecodeStats", "WebrtcVideoStats", "JumpListIconsMostVisited", "JumpListIconsRecentClosed", "Segmentation Platform", "shared_proto_db", "optimization_guide_hint_cache_store", "optimization_guide_model_metadata_store", "parcel_tracking_db", "coupon_db", "discounts_db", "commerce_subscription_db", "AutofillStrikeDatabase", "BudgetDatabase", "CRXTelemetry", "Feature Engagement Tracker", "Site Characteristics Database", "Download Service", "PersistentOriginTrials", "Safe Browsing Network", "GCM Store", "Platform Notifications"]

CHROMIUM_SW_SUBDIRS = ["CacheStorage", "ScriptCache", "Database"]

CHROMIUM_PROFILE_FILES = ["Affiliation Database", "Affiliation Database-journal", "BrowsingTopicsSiteData", "BrowsingTopicsSiteData-journal", "BrowsingTopicsState", "InterestGroups", "InterestGroups-wal", "SharedStorage", "SharedStorage-wal", "heavy_ad_intervention_opt_out.db", "heavy_ad_intervention_opt_out.db-journal", "DIPS", "DIPS-journal", "Network Action Predictor", "Network Action Predictor-journal", "LOCK", "LOG", "LOG.old", "DownloadMetadata", "PrivateAggregation", "PrivateAggregation-journal", "passkey_enclave_state", "trusted_vault.pb"]

CHROMIUM_NETWORK_FILES = ["Reporting and NEL", "Reporting and NEL-journal", "SCT Auditing Pending Reports", "NetworkDataMigrated"]

CHROMIUM_USERDATA_DIRS = ["BrowserMetrics", "Local Traces", "Crashpad", "ShaderCache", "GrShaderCache", "GraphiteDawnCache", "component_crx_cache", "extensions_crx_cache", "optimization_guide_model_store", "segmentation_platform", "OnDeviceHeadSuggestModel", "OptimizationHints", "Safe Browsing", "SafetyTips", "TpcdMetadata", "ZxcvbnData", "hyphen-data", "Crowd Deny", "MEIPreload", "OriginTrials", "PKIMetadata", "SSLErrorAssistant", "CertificateRevocation", "FileTypePolicies", "FirstPartySetsPreloaded", "AutofillStates", "TrustTokenKeyCommitments", "Subresource Filter", "Webstore Downloads"]

CHROMIUM_USERDATA_FILES = ["BrowserMetrics-spare.pma", "Variations"]



#  HELPERS & SYSTEM DATA



def get_env_path(var_name: str, fallback: str) -> Path:

    val = os.environ.get(var_name, fallback)

    return Path(val).resolve()


def format_env_path(path_obj: Path) -> str:

    p = str(path_obj.resolve())

    localappdata = os.environ.get("LOCALAPPDATA", "")

    appdata = os.environ.get("APPDATA", "")

    userprofile = os.environ.get("USERPROFILE", "")

    windir = os.environ.get("windir", "")


    if localappdata and p.startswith(localappdata):

        return p.replace(localappdata, "%LOCALAPPDATA%", 1)

    if appdata and p.startswith(appdata):

        return p.replace(appdata, "%APPDATA%", 1)

    if userprofile and p.startswith(userprofile):

        return p.replace(userprofile, "%USERPROFILE%", 1)

    if windir and p.startswith(windir):

        return p.replace(windir, "%WINDIR%", 1)

    return p


SYSTEM_TEMP = Path(os.environ.get("windir", r"C:\Windows")) / "Temp"

USER_TEMP = get_env_path("TEMP", r"C:\Temp")

USER_CRASH = get_env_path("LOCALAPPDATA", r"C:\Temp") / "CrashDumps"

USER_EXPLORER = get_env_path("LOCALAPPDATA", r"C:\Temp") / "Microsoft" / "Windows" / "Explorer"


# Deep System & App Caches

USER_APPDATA_TARGETS = [

    (get_env_path("LOCALAPPDATA", r"C:\Temp") / "NVIDIA" / "GLCache", "NVIDIA GL Cache"),

    (get_env_path("LOCALAPPDATA", r"C:\Temp") / "NVIDIA" / "DXCache", "NVIDIA DX Cache"),

    (get_env_path("LOCALAPPDATA", r"C:\Temp") / "D3DSCache", "DirectX Shader Cache"),

    (get_env_path("LOCALAPPDATA", r"C:\Temp") / "Steam" / "htmlcache", "Steam Web Cache"),

    (get_env_path("LOCALAPPDATA", r"C:\Temp") / "Microsoft" / "Windows" / "INetCache", "Windows INetCache"),

    (get_env_path("APPDATA", r"C:\Temp") / "discord" / "Cache", "Discord Cache"),

    (get_env_path("APPDATA", r"C:\Temp") / "discord" / "Code Cache", "Discord Code Cache"),

]

USER_APPDATA_TARGETS.extend([
    # dev tool caches (LocalAppData)
    (get_env_path("LOCALAPPDATA", r"C:\Temp") / "npm-cache", "npm Cache"),
    (get_env_path("LOCALAPPDATA", r"C:\Temp") / "uv" / "cache", "uv Cache"),
    (get_env_path("LOCALAPPDATA", r"C:\Temp") / "pip" / "cache", "pip Cache"),
    (get_env_path("LOCALAPPDATA", r"C:\Temp") / "Nuitka", "Nuitka Cache"),
    (get_env_path("LOCALAPPDATA", r"C:\Temp") / "node-gyp" / "Cache", "node-gyp Cache"),
    (get_env_path("LOCALAPPDATA", r"C:\Temp") / "python" / "Cache", "python Cache"),
    (get_env_path("LOCALAPPDATA", r"C:\Temp") / "Cypress" / "Cache", "Cypress Cache"),
    # app logs (Roaming)
    (get_env_path("APPDATA", r"C:\ProgramData") / "Maxon" / "Logs", "Maxon Logs"),
    (get_env_path("APPDATA", r"C:\ProgramData") / "Maxon" / "Temp", "Maxon Temp"),
    (get_env_path("APPDATA", r"C:\ProgramData") / "FreeFileSync", "FreeFileSync Logs"),
    (get_env_path("APPDATA", r"C:\ProgramData") / "obs-studio" / "logs", "obs-studio Logs"),
    (get_env_path("APPDATA", r"C:\ProgramData") / "Google" / "DriveFS" / "Logs", "DriveFS Logs"),
    (get_env_path("APPDATA", r"C:\ProgramData") / "Mega Limited" / "MEGAsync" / "Logs", "MEGAsync Logs"),
    (get_env_path("APPDATA", r"C:\ProgramData") / "discord" / "Logs", "discord Logs"),
    (get_env_path("APPDATA", r"C:\ProgramData") / "discord" / "module_data" / "crashlogs", "discord Crash Logs"),
    (get_env_path("APPDATA", r"C:\ProgramData") / "Claude" / "Logs", "Claude Logs"),
    (get_env_path("APPDATA", r"C:\ProgramData") / "Listary" / "UserProfile" / "Cache", "Listary Cache"),
    (get_env_path("USERPROFILE", r"C:\Users") / "AppData" / "LocalLow" / "NVIDIA" / "PerDriverVersion", "NVIDIA PerDriver DXCache"),
    # Eagle
    (get_env_path("APPDATA", r"C:\ProgramData") / "Eagle" / "eagle-temp", "Eagle Temp"),
    (get_env_path("APPDATA", r"C:\ProgramData") / "Eagle" / "Cache", "Eagle Cache"),
    (get_env_path("APPDATA", r"C:\ProgramData") / "Eagle" / "library-caches", "Eagle Library Caches"),
    (get_env_path("APPDATA", r"C:\ProgramData") / "Eagle" / "Crashpad", "Eagle Crashpad"),
    # VS Code family
    (get_env_path("APPDATA", r"C:\ProgramData") / "Code" / "CachedExtensionVSIXs", "VS Code VSIX Cache"),
    (get_env_path("APPDATA", r"C:\ProgramData") / "Code" / "Crashpad", "VS Code Crashpad"),
    (get_env_path("APPDATA", r"C:\ProgramData") / "Code" / "CachedData", "VS Code CachedData"),
    (get_env_path("APPDATA", r"C:\ProgramData") / "Code" / "Cache", "VS Code Cache"),
    (get_env_path("APPDATA", r"C:\ProgramData") / "Antigravity" / "CachedExtensionVSIXs", "Antigravity VSIX Cache"),
    (get_env_path("APPDATA", r"C:\ProgramData") / "Antigravity" / "Cache", "Antigravity Cache"),
    (get_env_path("APPDATA", r"C:\ProgramData") / "Antigravity" / "CachedData", "Antigravity CachedData"),
    (get_env_path("APPDATA", r"C:\ProgramData") / "Claude" / "Cache", "Claude Cache"),
    (get_env_path("APPDATA", r"C:\ProgramData") / "Claude" / "Code Cache", "Claude Code Cache"),
    (get_env_path("APPDATA", r"C:\ProgramData") / "obsidian" / "Cache", "Obsidian Cache"),
    (get_env_path("APPDATA", r"C:\ProgramData") / "obsidian" / "Code Cache", "Obsidian Code Cache"),
    (get_env_path("APPDATA", r"C:\ProgramData") / "CELSYS" / "promenade" / "dbcache", "CELSYS dbcache"),
    (get_env_path("APPDATA", r"C:\ProgramData") / "EpicGamesLauncher" / "Saved" / "webcache_4430", "Epic webcache"),
    (get_env_path("APPDATA", r"C:\ProgramData") / "AI Chatter" / "Cache", "AIChatter Cache"),
    (get_env_path("APPDATA", r"C:\ProgramData") / "Programs" / "DockerDesktop" / "tmp-delete", "Docker tmp-delete"),
    # browsers (LocalAppData)
    (get_env_path("LOCALAPPDATA", r"C:\Temp") / "Opera Software" / "Opera Stable" / "Default" / "Cache", "Opera Cache (C:)"),
    (get_env_path("LOCALAPPDATA", r"C:\Temp") / "Opera Software" / "Opera Stable" / "Default" / "Code Cache", "Opera Code Cache (C:)"),
    (get_env_path("LOCALAPPDATA", r"C:\Temp") / "Opera Software" / "Opera Stable" / "Default" / "GrShaderCache", "Opera Shader Cache (C:)"),
    (get_env_path("LOCALAPPDATA", r"C:\Temp") / "Opera Software" / "Opera Stable" / "Default" / "System Cache", "Opera System Cache (C:)"),
    (get_env_path("LOCALAPPDATA", r"C:\Temp") / "Opera Software" / "Opera Stable" / "Default" / "Crash Reports", "Opera Crash Reports (C:)"),
    (get_env_path("LOCALAPPDATA", r"C:\Temp") / "Google" / "Chrome" / "User Data" / "Default" / "Cache", "Chrome Cache (C:)"),
    (get_env_path("LOCALAPPDATA", r"C:\Temp") / "Google" / "Chrome" / "User Data" / "Default" / "GrShaderCache", "Chrome Shader Cache (C:)"),
    (get_env_path("LOCALAPPDATA", r"C:\Temp") / "Microsoft" / "Edge" / "User Data" / "Default" / "Cache", "Edge Cache (C:)"),
    (get_env_path("LOCALAPPDATA", r"C:\Temp") / "Razer" / "RazerAppEngine" / "Cache", "Razer Cache"),
    (get_env_path("LOCALAPPDATA", r"C:\Temp") / "Razer" / "RazerAppEngine" / "Code Cache", "Razer Code Cache"),
    (get_env_path("LOCALAPPDATA", r"C:\Temp") / "Razer" / "RazerAppEngine" / "Service Worker" / "CacheStorage", "Razer SW CacheStorage"),
    (get_env_path("LOCALAPPDATA", r"C:\Temp") / "electron" / "Cache", "Electron Cache"),
    (get_env_path("APPDATA", r"C:\ProgramData") / "Telegram Desktop" / "tdata" / "user_data" / "cache", "Telegram Cache (C:)"),
    (get_env_path("LOCALAPPDATA", r"C:\Temp") / "ollama app.exe" / "EBWebView" / "Default" / "Cache", "Ollama WebView Cache"),
    (get_env_path("APPDATA", r"C:\ProgramData") / "MaxonApp" / "UserData" / "EBWebView" / "Default" / "Cache", "Maxon WebView Cache"),
    (get_env_path("APPDATA", r"C:\ProgramData") / "Photoshop1-25-WIN" / "EBWebView" / "Default" / "Cache", "Photoshop WebView Cache"),
    # Brave browser (LocalAppData)
    (get_env_path("LOCALAPPDATA", r"C:\Temp") / "BraveSoftware" / "Brave-Browser" / "User Data" / "Default" / "Cache", "Brave Cache"),
    (get_env_path("LOCALAPPDATA", r"C:\Temp") / "BraveSoftware" / "Brave-Browser" / "User Data" / "Default" / "Code Cache", "Brave Code Cache"),
    (get_env_path("LOCALAPPDATA", r"C:\Temp") / "BraveSoftware" / "Brave-Browser" / "User Data" / "Default" / "GPUCache", "Brave GPU Cache"),
    # Code Cache for Chrome/Edge (Cache already covered)
    (get_env_path("LOCALAPPDATA", r"C:\Temp") / "Google" / "Chrome" / "User Data" / "Default" / "Code Cache", "Chrome Code Cache"),
    (get_env_path("LOCALAPPDATA", r"C:\Temp") / "Microsoft" / "Edge" / "User Data" / "Default" / "Code Cache", "Edge Code Cache"),
    # misc safe caches / logs
    (get_env_path("LOCALAPPDATA", r"C:\Temp") / "CEF", "CEF Cache"),
    (get_env_path("LOCALAPPDATA", r"C:\Temp") / "calibre-cache", "Calibre Cache"),
    (get_env_path("LOCALAPPDATA", r"C:\Temp") / "fontconfig", "fontconfig Cache"),
    (get_env_path("LOCALAPPDATA", r"C:\Temp") / "qBittorrent" / "logs", "qBittorrent Logs"),
    (get_env_path("LOCALAPPDATA", r"C:\Temp") / "claude-cli-nodejs" / "Cache", "Claude CLI Cache"),
    (get_env_path("LOCALAPPDATA", r"C:\Temp") / "DaVinci Resolve Welcome", "Resolve Welcome Cache"),
    # New findings (v2.4.8)
    (get_env_path("LOCALAPPDATA", r"C:\Temp") / "Mega Limited" / "MEGAsync" / "logs", "MEGAsync Logs (Local)"),
    (get_env_path("APPDATA", r"C:\ProgramData") / "Devin" / "Cache", "Devin Cache"),
    (get_env_path("APPDATA", r"C:\ProgramData") / "Devin" / "CachedData", "Devin CachedData"),
    (get_env_path("APPDATA", r"C:\ProgramData") / "FontBase" / "Cache", "FontBase Cache"),
    (get_env_path("APPDATA", r"C:\ProgramData") / "Bridge" / "Cache", "Adobe Bridge Cache"),
    (get_env_path("LOCALAPPDATA", r"C:\Temp") / "AIChatter" / "AI Chatter" / "cache", "AIChatter Cache"),
    (get_env_path("APPDATA", r"C:\ProgramData") / "Autokroma" / "Influx" / "Cache", "Autokroma Influx Cache"),
    (get_env_path("APPDATA", r"C:\ProgramData") / "Adobe" / "Adobe Substance 3D Sampler" / "thumbnailCache", "Substance 3D Thumbnail Cache"),
    (get_env_path("LOCALAPPDATA", r"C:\Temp") / "BlueStacks X" / "cache", "BlueStacks X Cache"),
    (get_env_path("APPDATA", r"C:\ProgramData") / "@neuralnomads" / "codenomad-electron-app" / "session-data-v2" / "Cache", "CodeNomad Cache"),
    (get_env_path("APPDATA", r"C:\ProgramData") / "MAXON" / "_assetcache", "Maxon Asset Cache"),
    (get_env_path("LOCALAPPDATA", r"C:\Temp") / "Mailbird" / "Misc" / "component_crx_cache", "Mailbird CRX Cache"),
    (get_env_path("APPDATA", r"C:\ProgramData") / "Opera Software" / "Opera Stable" / "component_crx_cache", "Opera CRX Cache"),
    (get_env_path("LOCALAPPDATA", r"C:\Temp") / "BraveSoftware" / "Brave-Browser" / "User Data" / "component_crx_cache", "Brave CRX Cache"),
    (get_env_path("APPDATA", r"C:\ProgramData") / "discord" / "component_crx_cache", "Discord CRX Cache"),
    # New findings (v2.4.9)
    (get_env_path("APPDATA", r"C:\ProgramData") / "Devin" / "GPUCache", "Devin GPUCache"),
    (get_env_path("APPDATA", r"C:\ProgramData") / "Devin" / "logs", "Devin Logs"),
    (get_env_path("APPDATA", r"C:\ProgramData") / "Devin" / "cli" / "logs", "Devin CLI Logs"),
    (get_env_path("APPDATA", r"C:\ProgramData") / "Claude" / "GPUCache", "Claude GPUCache"),
    (get_env_path("APPDATA", r"C:\ProgramData") / "Antigravity" / "GPUCache", "Antigravity GPUCache"),
    (get_env_path("APPDATA", r"C:\ProgramData") / "Antigravity" / "logs", "Antigravity Logs"),
    (get_env_path("APPDATA", r"C:\ProgramData") / "@neuralnomads" / "codenomad-electron-app" / "session-data-v2" / "Code Cache", "CodeNomad Code Cache"),
    (get_env_path("APPDATA", r"C:\ProgramData") / "@neuralnomads" / "codenomad-electron-app" / "session-data-v2" / "GPUCache", "CodeNomad GPUCache"),
    (get_env_path("APPDATA", r"C:\ProgramData") / "ollama app.exe" / "EBWebView" / "Default" / "GPUCache", "Ollama GPUCache"),
    (get_env_path("APPDATA", r"C:\ProgramData") / "LM Studio" / "GPUCache", "LM Studio GPUCache"),
    (get_env_path("LOCALAPPDATA", r"C:\Temp") / "Adobe" / "Adobe Substance 3D Painter" / "cache", "Substance 3D Painter Cache"),
    (get_env_path("LOCALAPPDATA", r"C:\Temp") / "Adobe" / "Adobe Substance 3D Sampler" / "cache", "Substance 3D Sampler Cache"),
    (get_env_path("APPDATA", r"C:\ProgramData") / "CELSYS" / "CLIPStudioPaint" / "1.5.0" / "CacheData", "CLIP Studio Paint Cache"),
    (get_env_path("LOCALAPPDATA", r"C:\Temp") / "Reallusion" / "ActorCore AccuRIG" / "Cache", "AccuRIG Cache"),
    (get_env_path("LOCALAPPDATA", r"C:\Temp") / "Reallusion" / "ActorCore AccuRIG" / "Code Cache", "AccuRIG Code Cache"),
    (get_env_path("LOCALAPPDATA", r"C:\Temp") / "Reallusion" / "Character Creator" / "5.0" / "cache", "Character Creator Cache"),
    (get_env_path("APPDATA", r"C:\ProgramData") / "LosslessCut" / "Cache", "LosslessCut Cache"),
    (get_env_path("APPDATA", r"C:\ProgramData") / "LosslessCut" / "GPUCache", "LosslessCut GPUCache"),
    (get_env_path("LOCALAPPDATA", r"C:\Temp") / "Topaz Labs LLC" / "Topaz Video" / "cache", "Topaz Video Cache"),
    (get_env_path("LOCALAPPDATA", r"C:\Temp") / "Topaz Labs LLC" / "Topaz Video AI" / "cache", "Topaz Video AI Cache"),
    (get_env_path("LOCALAPPDATA", r"C:\Temp") / "UnrealEngine" / "5.6" / "DerivedDataCache", "Unreal Engine 5.6 DDCache"),
    (get_env_path("APPDATA", r"C:\ProgramData") / "omniroute-desktop" / "Cache", "Omniroute Cache"),
    (get_env_path("APPDATA", r"C:\ProgramData") / "omniroute-desktop" / "Code Cache", "Omniroute Code Cache"),
    (get_env_path("APPDATA", r"C:\ProgramData") / "omniroute-desktop" / "GPUCache", "Omniroute GPUCache"),
    (get_env_path("APPDATA", r"C:\ProgramData") / "omniroute-desktop" / "Service Worker" / "CacheStorage", "Omniroute SW CacheStorage"),
    (get_env_path("APPDATA", r"C:\ProgramData") / "stem-studio" / "Cache", "Stem Studio Cache"),
    (get_env_path("APPDATA", r"C:\ProgramData") / "stem-studio" / "GPUCache", "Stem Studio GPUCache"),
    (get_env_path("LOCALAPPDATA", r"C:\Temp") / "QuiteRss" / "QuiteRss" / "cache", "QuiteRss Cache"),
    (get_env_path("LOCALAPPDATA", r"C:\Temp") / "com.dropdead.app" / "EBWebView" / "Default" / "Cache", "Dropdead WebView Cache"),
    (get_env_path("LOCALAPPDATA", r"C:\Temp") / "DeskChat" / "DeskChat" / "cache", "DeskChat Cache"),
    (get_env_path("LOCALAPPDATA", r"C:\Temp") / "DeskChat Dump" / "cache", "DeskChat Dump Cache"),
    (get_env_path("LOCALAPPDATA", r"C:\Temp") / "HD-Player" / "cache", "HD-Player Cache"),
    (get_env_path("LOCALAPPDATA", r"C:\Temp") / "JangaFX" / "liquigen" / "gl-cache", "Liquigen GL Cache"),
    (get_env_path("LOCALAPPDATA", r"C:\Temp") / "Krisp" / "Logs", "Krisp Logs"),
    (get_env_path("LOCALAPPDATA", r"C:\Temp") / "Mailbird" / "Misc" / "Default" / "Cache", "Mailbird Cache"),
    (get_env_path("APPDATA", r"C:\ProgramData") / "SiYuan-Electron" / "GPUCache", "SiYuan GPUCache"),
    (get_env_path("APPDATA", r"C:\ProgramData") / "BetterDiscord Installer" / "Cache", "BetterDiscord Cache"),
    (get_env_path("APPDATA", r"C:\ProgramData") / "BorisFX" / "BorisFX Direct" / "Cache", "BorisFX Direct Cache"),
    # New findings (v2.4.10)
    (get_env_path("LOCALAPPDATA", r"C:\Temp") / "Google" / "DriveFS" / "Logs", "DriveFS Logs (Local)"),
    (get_env_path("LOCALAPPDATA", r"C:\Temp") / "Razer" / "RazerAppEngine" / "User Data" / "Default" / "Cache", "Razer Engine Cache"),
    (get_env_path("LOCALAPPDATA", r"C:\Temp") / "Razer" / "RazerAppEngine" / "User Data" / "Default" / "Code Cache", "Razer Engine Code Cache"),
    (get_env_path("LOCALAPPDATA", r"C:\Temp") / "Razer" / "RazerAppEngine" / "User Data" / "Default" / "GPUCache", "Razer Engine GPUCache"),
    (get_env_path("LOCALAPPDATA", r"C:\Temp") / "Razer" / "RazerAppEngine" / "User Data" / "Default" / "Service Worker", "Razer Engine Service Worker"),
    (get_env_path("LOCALAPPDATA", r"C:\Temp") / "EpicGamesLauncher" / "Saved" / "webcache_4430", "Epic webcache (Local)"),
    (get_env_path("APPDATA", r"C:\ProgramData") / "Code" / "WebStorage" / "2" / "CacheStorage", "VS Code WebStorage Cache"),
    (get_env_path("APPDATA", r"C:\ProgramData") / "Code" / "WebStorage" / "3" / "CacheStorage", "VS Code WebStorage Cache (2)"),
    (get_env_path("LOCALAPPDATA", r"C:\Temp") / "com.verifiedskill.desktop" / "EBWebView" / "component_crx_cache", "VerifiedSkill CRX Cache"),
    (get_env_path("LOCALAPPDATA", r"C:\Temp") / "MaxonApp" / "UserData" / "EBWebView" / "Default" / "Cache", "MaxonApp WebView Cache"),
    (get_env_path("LOCALAPPDATA", r"C:\Temp") / "MaxonApp" / "UserData" / "EBWebView" / "Default" / "Code Cache", "MaxonApp WebView Code Cache"),
    (get_env_path("LOCALAPPDATA", r"C:\Temp") / "MaxonApp" / "UserData" / "EBWebView" / "Default" / "GrShaderCache", "MaxonApp WebView Shader Cache"),
    (get_env_path("APPDATA", r"C:\ProgramData") / "Adobe" / "Adobe Photoshop 2024" / "Logs", "Photoshop 2024 Logs"),
    (get_env_path("APPDATA", r"C:\ProgramData") / "obsidian" / "GPUCache", "Obsidian GPUCache"),
])


SYSTEM_SAFE_ROOTS = {

    SYSTEM_TEMP.resolve(),

    USER_TEMP.resolve(),

    USER_CRASH.resolve(),

    USER_EXPLORER.resolve()

}

for path, _ in USER_APPDATA_TARGETS:

    try: SYSTEM_SAFE_ROOTS.add(path.resolve())

    except Exception:

        logging.getLogger("vac_cleaner").warning("Failed to resolve path for SYSTEM_SAFE_ROOTS")


def get_running_processes() -> set[str]:

    try:

        result = subprocess.run(["tasklist", "/fo", "csv", "/nh"], capture_output=True, text=True, timeout=15, check=False)

        procs: set[str] = set()

        for line in result.stdout.splitlines():

            parts = line.split(",")

            pname = parts[0].strip().replace('"', '').lower()

            if pname: procs.add(pname)

        return procs

    except Exception as e:

        logging.getLogger("vac_cleaner").error(f"Failed to query running processes: {e}")

        return set()


def is_app_running(app_group: str, running: set[str]) -> bool:

    return bool(APP_PROCESSES.get(app_group, set()) & running)


def get_size(path: Path) -> int:

    if not path.exists():

        return 0

    if path.is_file():

        try: return path.stat().st_size

        except OSError: return 0

    total = 0

    stack = [path]

    while stack:

        current = stack.pop()

        try:

            for entry in os.scandir(current):

                if entry.is_file(follow_symlinks=False):

                    try: total += entry.stat().st_size

                    except OSError:

                        pass  # expected: file may be locked during scan

                elif entry.is_dir(follow_symlinks=False) and not entry.is_symlink():

                    stack.append(Path(entry.path))

        except (PermissionError, OSError):

            pass  # expected: dir may be inaccessible

    return total


BYTES_PER_MB = 1_048_576

BYTES_PER_GB = 1_073_741_824


def fmt(n: int) -> str:

    if n >= BYTES_PER_GB: return f"{n/BYTES_PER_GB:.2f} GB"

    if n >= BYTES_PER_MB: return f"{n/BYTES_PER_MB:.1f} MB"

    if n >= 1_024: return f"{n/1_024:.0f} KB"

    return f"{n} B"



#  LOGGER



class Logger:

    def __init__(self, log_file: Path | None, dry_run: bool, gui_callback=None):

        self.dry_run = dry_run

        self.log_file = log_file

        self.bytes_freed = 0

        self.n_deleted = 0

        self.n_skipped = 0

        self.n_errors = 0

        self.gui_callback = gui_callback

        self.lock = threading.Lock()


        self._log = logging.getLogger("vac_cleaner")

        self._log.setLevel(logging.DEBUG)

        for h in self._log.handlers[:]:

            h.close()

            self._log.removeHandler(h)


        ch = logging.StreamHandler(stream=sys.stdout)

        ch.setLevel(logging.INFO)

        ch.setFormatter(logging.Formatter("%(message)s"))

        self._log.addHandler(ch)


        if log_file:

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


    def warn(self, msg: str) -> None:

        text = f"  [WARN]  {msg}"

        self._log.warning(text)

        self._emit_gui(text)


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

        msg = (

            f"\n+{bar}+\n"

            f"| SUMMARY -- {mode:<55}|\n"

            f"+{bar}+\n"

            f"| Space freed :  {mb:>10.1f} MB  /  {gb:>7.3f} GB{' '*22}|\n"

            f"| Items acted :  {self.n_deleted:<50} |\n"

            f"| Items skipped: {self.n_skipped:<50} |\n"

            f"| Errors       : {self.n_errors:<50} |\n"

            f"+{bar}+"

        )

        self._log.info(msg)

        self._emit_gui(msg)



#  SAFETY GUARD



class SafetyGuard:

    def __init__(self, base_root: Path, is_system_root: bool = False,

                 exclude_patterns: list[str] | None = None,

                 exclude_paths: list[str] | None = None):

        self.base_root = self._canon(base_root)

        self.is_system_root = is_system_root

        self.exclude_patterns = exclude_patterns or []

        self.exclude_paths = [Path(p).resolve() for p in (exclude_paths or [])]


    @staticmethod

    def _canon(p: Path) -> Path:

        try: return p.resolve()

        except OSError: return p.absolute()


    def is_safe(self, path: Path) -> tuple[bool, str]:

        path = self._canon(path)

        try:

            path.relative_to(self.base_root)

        except ValueError:

            return False, f"Outside TARGET ROOT ({self.base_root})"


        if path == self.base_root:

            return False, "Path IS the target root"


        if not self.is_system_root and len(path.parts) < MIN_PATH_PARTS:

            return False, f"Path too shallow ({len(path.parts)} components)"


        name_lower = path.name.lower()

        if name_lower in NEVER_DELETE_NAMES:

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


        if ".." in path.parts:

            return False, "Path contains '..' component"


        return True, "OK"



#  CORE CLEANER ENGINE



class CancelJobException(Exception):

    """Raised when the user cancels the running job."""



class CleanerEngine:

    """Base class providing safe file/dir deletion and logging utilities."""

    def __init__(self, dry_run: bool, log: Logger, guard: SafetyGuard, root: Path, max_threads: int = DEFAULT_THREADS, cancel_event: threading.Event | None = None,

                 exclude_patterns: list[str] | None = None, exclude_paths: list[str] | None = None, progress=None):

        self.exclude_patterns = exclude_patterns or []

        self.exclude_paths = exclude_paths or []

        self.dry_run = dry_run

        self.log = log

        self.guard = guard

        self.root = root

        self.max_threads = max_threads

        self.cancel_event = cancel_event

        self.progress = progress

        self.running = get_running_processes()

        self.deleted_rel_paths: set[Path] = set()


    def check_cancel(self):

        if self.cancel_event and self.cancel_event.is_set():

            raise CancelJobException("Job cancelled by user.")


    def _rmtree_onerror(self, func, path, exc_info):

        try:

            os.chmod(path, 0o666)

            func(path)

        except Exception:

            self.log.skipped(Path(path), "File in use or access denied")


    def _del_dir(self, path: Path, desc: str) -> int:

        if not path.exists() or not path.is_dir(): return 0

        size = get_size(path)

        try:

            self.deleted_rel_paths.add(path.relative_to(self.root))

        except ValueError:

            self.log.warning(f"Could not record deleted dir relative path: {path}")


        self.log.deleted(path, size, desc)

        if not self.dry_run:

            try: shutil.rmtree(path, onerror=self._rmtree_onerror)

            except Exception as exc:

                self.log.error(f"rmtree failed for {path}: {exc}")

                return 0

        return size


    def _del_file(self, path: Path, desc: str) -> int:

        if not path.exists() or not path.is_file(): return 0

        try: size = path.stat().st_size

        except OSError: size = 0

        try:

            self.deleted_rel_paths.add(path.relative_to(self.root))

        except ValueError:

            self.log.warning(f"Could not record deleted file relative path: {path}")


        self.log.deleted(path, size, desc)

        if not self.dry_run:

            for attempt in range(2):

                try:

                    path.chmod(0o666)

                    path.unlink()

                    break

                except PermissionError:

                    if attempt == 0:

                        time.sleep(0.01) # Windows Defender micro-lock backoff

                    else:

                        self.log.skipped(path, "File locked by another process")

                        return 0

                except Exception:

                    self.log.skipped(path, "File in use or access denied")

                    return 0

        return size


    def _del_dir_contents(self, path: Path, desc: str) -> int:

        if not path.exists() or not path.is_dir(): return 0

        freed = 0

        try:

            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:

                active_futures = set()

                for item in path.iterdir():

                    ok, reason = self.guard.is_safe(item)

                    if not ok:
                        self.log.skipped(item, reason)
                        continue


                    if len(active_futures) >= 2000:

                        done, active_futures = concurrent.futures.wait(active_futures, return_when=concurrent.futures.FIRST_COMPLETED)

                        for f in done:

                            try: freed += f.result()

                            except Exception as e:

                                self.log.warning(f"Thread batch result failed: {e}")


                    if item.is_dir():

                        active_futures.add(executor.submit(self._del_dir, item, f"{desc} / {item.name}"))

                    elif item.is_file():

                        active_futures.add(executor.submit(self._del_file, item, f"{desc} / {item.name}"))


                for f in concurrent.futures.as_completed(active_futures):

                    try: freed += f.result()

                    except Exception as e:

                        self.log.warning(f"Future result failed: {e}")

        except (PermissionError, OSError):

            self.log.warning("Directory iteration failed during content deletion")

        return freed


    def safe_del_dir(self, path: Path, desc: str, app: str) -> int:

        if is_app_running(app, self.running):

            self.log.skipped(path, f"'{app}' is running")

            return 0

        ok, reason = self.guard.is_safe(path)

        if not ok:
            self.log.skipped(path, reason)
            return 0

        return self._del_dir(path, desc)


    def safe_del_file(self, path: Path, desc: str, app: str) -> int:

        if is_app_running(app, self.running):

            self.log.skipped(path, f"'{app}' is running")

            return 0

        ok, reason = self.guard.is_safe(path)

        if not ok:
            self.log.skipped(path, reason)
            return 0

        return self._del_file(path, desc)


    def safe_del_dir_contents(self, path: Path, desc: str, app: str) -> int:

        if is_app_running(app, self.running):

            self.log.skipped(path, f"'{app}' is running")

            return 0

        ok, reason = self.guard.is_safe(path)

        if not ok:
            self.log.skipped(path, reason)
            return 0

        return self._del_dir_contents(path, desc)


class PortableCleaner(CleanerEngine):

    r"""Cleans the V:\ and backup drives portable apps."""

    _NUMBERED_RE = re.compile(r'^(.+) \((\d+)\)$')


    def sweep_numbered_copies(self, parent: Path, app: str) -> int:

        if not parent.exists() or not parent.is_dir(): return 0

        if is_app_running(app, self.running): return 0

        freed = 0

        try:

            for item in parent.iterdir():

                self.check_cancel()

                m = self._NUMBERED_RE.match(item.name)

                if not m or int(m.group(2)) < 2: continue

                ok, _reason = self.guard.is_safe(item)

                if not ok: continue

                desc = f"Numbered crash-backup: {item.name}"

                if item.is_file(): freed += self._del_file(item, desc)

                elif item.is_dir(): freed += self._del_dir(item, desc)

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

            for name in CHROMIUM_NETWORK_FILES: freed += self.safe_del_file(net / name, f"[{app}] Net/{name}", app)

            try:

                for item in net.iterdir():

                    self.check_cancel()

                    if item.suffix.lower() == ".tmp" and item.is_file() and self.guard.is_safe(item)[0]:

                        freed += self._del_file(item, f"[{app}] Net tmp: {item.name}")

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

        cdir = self.root / "_CENT"

        ud = cdir / "User Data"

        if not cdir.exists(): return 0

        self.log.section("Cent Browser")

        freed = self._clean_chromium_userdata(ud, "cent") + self._clean_chromium_profiles(ud, "cent")

        for p, d in [(cdir/"debug.log", "debug.log"), (cdir/"old_chrome.exe", "old_chrome.exe"), (cdir/"old_chrome_proxy.exe", "old_chrome_proxy.exe")]:

            freed += self.safe_del_file(p, f"[Cent] {d}", "cent")

        return freed


    def clean_brave(self) -> int:

        bdir = self.root / "__SOFT" / "_BRAVE"

        data = bdir / "data"

        if not bdir.exists(): return 0

        self.log.section("Brave Browser")

        freed = 0

        for name in list(CHROMIUM_USERDATA_DIRS) + ["P3AConfig"]: freed += self.safe_del_dir(data / name, f"[Brave/UD] {name}", "brave")

        for name in CHROMIUM_USERDATA_FILES: freed += self.safe_del_file(data / name, f"[Brave/UD] {name}", "brave")

        freed += self.sweep_numbered_copies(data, "brave")

        freed += self._clean_chromium_profiles(data, "brave")

        return freed


    def clean_firefox(self) -> int:

        fdir = self.root / "__SOFT" / "_FIREFOX"

        prof = fdir / "Data" / "profile"

        if not fdir.exists(): return 0

        self.log.section("Firefox Portable")

        freed = 0

        for name in ["cache2", "startupCache", "shader-cache", "thumbnails", "crashes", "minidumps", "datareporting", "safebrowsing", "sessionstore-backups", "security_state"]:

            freed += self.safe_del_dir(prof / name, f"[Firefox] {name}", "firefox")

        for name in ["AlternateServices.bin", "SiteSecurityServiceState.bin", "bounce-tracking-protection.sqlite", "bounce-tracking-protection.sqlite-shm", "bounce-tracking-protection.sqlite-wal", "domain_to_categories.sqlite", "domain_to_categories.sqlite-journal", "activity-stream.inferred_personalization_feed.json", "activity-stream.weather_feed.json", "shield-preference-experiments.json", "targeting.snapshot.json", "parent.lock"]:

            freed += self.safe_del_file(prof / name, f"[Firefox] {name}", "firefox")

        return freed


    def clean_opera(self) -> int:

        odir = self.root / "__SOFT" / "_OPERA"

        if not odir.exists(): return 0

        self.log.section("Opera")

        return self._clean_old_opera_versions(odir) + self.safe_del_dir(odir / "old_status", "[Opera] old_status", "opera")


    def clean_telegram(self) -> int:

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


    def clean_universal_caches(self) -> int:

        freed = 0

        if not self.root.exists() or not self.root.is_dir(): return 0

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

                            freed += self.safe_del_dir_contents(item, f"[Universal Cache] {item.name}", "general")

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

                 exclude_patterns: list[str] | None = None, exclude_paths: list[str] | None = None, progress=None):

        # The root here isn't a single drive, so we pass dummy C:\.

        # But we create a specialized SafetyGuard for each system path.

        super().__init__(dry_run, log, SafetyGuard(Path("C:\\")), Path("C:\\"), max_threads, cancel_event,

                         exclude_patterns=exclude_patterns, exclude_paths=exclude_paths, progress=progress)

        self.targets = targets if targets is not None else {}


    def run_all(self) -> int:

        self.log.section("System Junk (C:\\)")

        freed = 0


        # System Temp

        if self.targets.get("System Temp", True) and SYSTEM_TEMP.exists():

            guard = SafetyGuard(SYSTEM_TEMP, is_system_root=True)

            self.guard = guard

            freed += self._del_dir_contents(SYSTEM_TEMP, "Windows System Temp")


        # User Temp

        if self.targets.get("User Temp", True) and USER_TEMP.exists():

            guard = SafetyGuard(USER_TEMP, is_system_root=True)

            self.guard = guard

            freed += self._del_dir_contents(USER_TEMP, "Windows User Temp")


        # User CrashDumps

        if self.targets.get("App CrashDumps", True) and USER_CRASH.exists():

            guard = SafetyGuard(USER_CRASH, is_system_root=True)

            self.guard = guard

            freed += self._del_dir_contents(USER_CRASH, "Windows App CrashDumps")


        # Explorer Thumbnails

        if self.targets.get("Explorer Thumbnails", True) and USER_EXPLORER.exists():

            guard = SafetyGuard(USER_EXPLORER, is_system_root=True)

            self.guard = guard

            try:

                for item in USER_EXPLORER.iterdir():

                    if item.is_file() and item.name.lower().startswith("thumbcache_") and guard.is_safe(item)[0]:

                        freed += self._del_file(item, f"Thumbnail Cache: {item.name}")

            except OSError:

                pass  # expected: thumbnail cache may be in use


        # Deep AppData Caches

        for target_path, desc in USER_APPDATA_TARGETS:

            if self.targets.get(desc, True) and target_path.exists():

                guard = SafetyGuard(target_path, is_system_root=True)

                self.guard = guard

                freed += self._del_dir_contents(target_path, desc)


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

                    import subprocess

                    if not self.dry_run:

                        subprocess.run(["net", "stop", "wuauserv"], capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)

                    guard = SafetyGuard(wu_path, is_system_root=True)

                    self.guard = guard

                    freed += self._del_dir_contents(wu_path, "Windows Update Cache")

                    if not self.dry_run:

                        subprocess.run(["net", "start", "wuauserv"], capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)

                else:

                    self.log.info("  [SKIP] Windows Update Cache requires Administrator privileges.")


        # DNS Cache

        if self.targets.get("DNS Cache", False):

            if self.dry_run:

                self.log.info("  [DNS] Would flush DNS Resolver Cache.")

            else:

                import subprocess

                try:

                    subprocess.run(["ipconfig", "/flushdns"], capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)

                    self.log.info("  [DNS] Successfully flushed DNS Resolver Cache.")

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


        # Deep C: Junk

        if self.targets.get("Deep C: Junk", True):

            self.log.section("Deep C: Junk")

            freed += self._deep_junk_sweep()

        return freed


    def _deep_junk_sweep(self) -> int:

        freed = 0

        loc = get_env_path("LOCALAPPDATA", r"C:\Temp")

        prog = get_env_path("APPDATA", r"C:\ProgramData")

        # updater leftovers in %TEMP% (-updater / @ tails)

        try:

            for item in USER_TEMP.iterdir():

                self.check_cancel()

                if item.is_dir() and (item.name.endswith("-updater") or item.name.endswith("@")) and self.guard.is_safe(item)[0]:

                    freed += self._del_dir(item, f"Updater leftover: {item.name}")

        except OSError:

            pass

        # Viber QmlWebCache

        freed += self.safe_del_dir(loc / "ViberPC" / "QmlWebCache", "[Viber] QmlWebCache", "general")

        # leftover installer temps in %LOCALAPPDATA%

        try:

            for f in loc.glob("*.exe.tmp"):

                self.check_cancel()

                if self.guard.is_safe(f)[0]:

                    freed += self._del_file(f, f"Installer temp: {f.name}")

        except OSError:

            pass

        # Eagle logs

        for pat, desc in [("ai-search*.log", "Eagle log: {name}"), ("log.old.log", "Eagle old log: {name}")]:

            try:

                for f in (loc / "Eagle").glob(pat):

                    self.check_cancel()

                    if self.guard.is_safe(f)[0]:

                        freed += self._del_file(f, desc.format(name=f.name))

            except OSError:

                pass

        # Yandex.Disk leftovers

        yd = loc / "Yandex" / "Yandex.Disk.2"

        for pat, desc in [("*.bak", "Yandex.Disk bak: {name}"), ("*.log", "Yandex.Disk log: {name}")]:

            try:

                for f in yd.glob(pat):

                    self.check_cancel()

                    if self.guard.is_safe(f)[0]:

                        freed += self._del_file(f, desc.format(name=f.name))

            except OSError:

                pass

        # FastPrompter baks

        try:

            for f in (prog / "FastPrompter").glob("*.bak"):

                self.check_cancel()

                if self.guard.is_safe(f)[0]:

                    freed += self._del_file(f, f"FastPrompter bak: {f.name}")

        except OSError:

            pass

        # Claude desktop app.asar.bak

        app_asar = loc / "AnthropicClaude" / "app.asar.bak"

        if app_asar.is_file() and self.guard.is_safe(app_asar)[0]:

            freed += self._del_file(app_asar, f"Claude app.asar.bak: {app_asar.name}")

        # Autodesk ODIS log

        odis_log = prog / "Autodesk" / "ODIS" / "DDA.log"

        if odis_log.is_file() and self.guard.is_safe(odis_log)[0]:

            freed += self._del_file(odis_log, f"Autodesk ODIS log: {odis_log.name}")

        # GitHub CLI run-log zips (cache dir only; device-id/config stay)

        try:

            for f in (loc / "GitHub CLI").glob("run-log-*.zip"):

                self.check_cancel()

                if self.guard.is_safe(f)[0]:

                    freed += self._del_file(f, f"GitHub CLI run-log: {f.name}")

        except OSError:

            pass

        return freed


class CustomCleaner(CleanerEngine):

    """Executes user-defined cleaning rules."""

    def __init__(self, dry_run: bool, log: Logger, rules: list[dict], max_threads: int = DEFAULT_THREADS, cancel_event: threading.Event | None = None,

                 exclude_patterns: list[str] | None = None, exclude_paths: list[str] | None = None, progress=None):

        super().__init__(dry_run, log, SafetyGuard(Path("C:\\")), Path("C:\\"), max_threads, cancel_event,

                         exclude_patterns=exclude_patterns, exclude_paths=exclude_paths, progress=progress)

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


            guard = SafetyGuard(target, is_system_root=True)

            self.guard = guard


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

    try: p = p.resolve()

    except OSError: return True


    # Block exact matches

    if p in BLACKLIST_PATHS: return True


    # Block anything inside Windows or Program Files

    windir = Path(os.environ.get("windir", r"C:\Windows")).resolve()

    try:

        p.relative_to(windir)

        return True

    except ValueError:

        pass  # path not under windir, which is the expected case


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

    default_cfg = {

        "custom_rules": [],

        "exclude_patterns": [],

        "exclude_paths": [],

        "auto_clean_interval_hours": 0,

        "lang": "en",

        "window_geometry": "",

        "portable_roots": [str(PRIMARY_ROOT.resolve())] + [str(b.resolve()) for b in BACKUP_ROOTS]

    }

    if not CONFIG_FILE.exists():

        try:

            with open(CONFIG_FILE, "w", encoding="utf-8") as f:

                json.dump(default_cfg, f, indent=4)

        except OSError:

            pass  # read-only FS: config stays in-memory only

        return default_cfg

    try:

        with open(CONFIG_FILE, "r", encoding="utf-8") as f:

            data = json.load(f)

            if "profiles" in data:

                del data["profiles"]

                try:

                    with open(CONFIG_FILE, "w", encoding="utf-8") as f2:

                        json.dump(data, f2, indent=4)

                except OSError:

                    pass  # migration persist is best-effort

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

            return data

    except Exception:

        logging.getLogger("vac_cleaner").warning(f"Config file corrupted or unreadable: {CONFIG_FILE} - falling back to defaults")

        return default_cfg


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


def save_config(config: dict) -> None:

    try:

        tmp_file = CONFIG_FILE.with_suffix(".json.tmp")

        with open(tmp_file, "w", encoding="utf-8") as f:

            json.dump(config, f, indent=4)

        tmp_file.replace(CONFIG_FILE)

    except Exception as e:
        logging.getLogger("vac_cleaner").warning(f"Failed to save config: {e}")


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
    def set_total(self, total):
        with self.lock:
            if self.current_category and self.current_category in self.categories:
                self.categories[self.current_category]['total'] = total
    def finish_category(self, status='done'):
        with self.lock:
            if self.current_category and self.current_category in self.categories:
                self.categories[self.current_category]['status'] = status
    def get_snapshot(self):
        with self.lock:
            items_done = 0; total_bytes = 0; planned = 0; cats = []
            for name in self.category_order:
                c = self.categories.get(name, {})
                cur = c.get('current', 0); t = c.get('total', 0)
                items_done += cur; total_bytes += c.get('bytes', 0)
                if t > 0: planned += t
                cats.append({'name': name, 'current': cur, 'total': t, 'bytes': c.get('bytes', 0), 'status': c.get('status', 'pending')})
            elapsed = time.time() - self.start_time
            return {'categories': cats, 'total_current': items_done, 'total_bytes': total_bytes, 'total_items_done': items_done, 'total_items_planned': planned, 'elapsed': elapsed, 'current_category': self.current_category}


TARGET_MAPPING = {
    'System Temp': 'System Temp', 'User Temp': 'User Temp',
    'App CrashDumps': 'App CrashDumps', 'Explorer Thumbnails': 'Explorer Thumbnails',
    'Windows Update Cache': 'Windows Update Cache', 'DNS Cache': 'DNS Cache',
    'Recycle Bin': 'Recycle Bin', 'Windows Prefetch': 'Windows Prefetch',
    'Windows Logs': 'Windows Logs',
    'Yarn Cache': 'Yarn Cache',
    'Battle.net Cache': 'Battle.net Cache', 'Epic Games Cache': 'Epic Games Cache',
    'Steam AppCache': 'Steam AppCache', 'Steam DepotCache': 'Steam DepotCache',
    'Steam Logs': 'Steam Logs', 'Deep C: Junk': 'Deep C: Junk',
}
SYSTEM_TARGET_DEFAULTS = {
    'System Temp': True, 'User Temp': True, 'App CrashDumps': True, 'Explorer Thumbnails': True,
    'Windows Update Cache': False, 'DNS Cache': False, 'Recycle Bin': False,
    'Windows Prefetch': False, 'Windows Logs': False,
    'Yarn Cache': False, 'Battle.net Cache': False, 'Epic Games Cache': False,
    'Steam AppCache': False, 'Steam DepotCache': False, 'Steam Logs': False,
    'Deep C: Junk': True,
}

def calculate_target_sizes(targets):
    result = {}
    if targets.get('System Temp', True) and SYSTEM_TEMP.exists(): result['System Temp'] = get_size(SYSTEM_TEMP)
    if targets.get('User Temp', True) and USER_TEMP.exists(): result['User Temp'] = get_size(USER_TEMP)
    if targets.get('App CrashDumps', True) and USER_CRASH.exists(): result['App CrashDumps'] = get_size(USER_CRASH)
    if targets.get('Explorer Thumbnails', True) and USER_EXPLORER.exists(): result['Explorer Thumbnails'] = get_size(USER_EXPLORER)
    for t, d in USER_APPDATA_TARGETS:
        if targets.get(d, True) and t.exists(): result[d] = get_size(t)
    return result

def run_cleaning_job(dry_run, run_portable, run_system, run_custom, log, max_threads=DEFAULT_THREADS, sys_targets=None, cancel_event=None, exclude_patterns=None, exclude_paths=None, progress=None):
    log.header(f"Smart VAC Cleaner v{VERSION} | {'DRY-RUN' if dry_run else 'DELETE MODE'} | {datetime.now().astimezone()}")
    if dry_run: log.info('[DRY-RUN] Nothing will be deleted.')
    else: log.info('[WARNING] DELETE MODE active!')
    if run_portable:
        config = load_config()
        roots = [Path(r) for r in config.get('portable_roots', []) if Path(r).exists()]
        if not roots:
            log.info('No portable roots configured (see cleaner_config.json) - skipped.')
        for r in roots:
            if cancel_event and cancel_event.is_set(): raise CancelJobException('Cancelled')
            guard = SafetyGuard(r, exclude_patterns=exclude_patterns, exclude_paths=exclude_paths)
            PortableCleaner(dry_run, log, guard, r, max_threads, cancel_event, exclude_patterns=exclude_patterns, exclude_paths=exclude_paths, progress=progress).run_all()
    if run_system:
        if cancel_event and cancel_event.is_set(): raise CancelJobException('Cancelled')
        SystemCleaner(dry_run, log, max_threads, sys_targets, cancel_event, exclude_patterns=exclude_patterns, exclude_paths=exclude_paths, progress=progress).run_all()
    if run_custom:
        if cancel_event and cancel_event.is_set(): raise CancelJobException('Cancelled')
        config = load_config()
        if config.get('custom_rules'):
            CustomCleaner(dry_run, log, config['custom_rules'], max_threads, cancel_event, exclude_patterns=exclude_patterns, exclude_paths=exclude_paths, progress=progress).run_all()
    log.summary()

def cli_status():
    config = load_config()
    print(f"Smart VAC Cleaner v{VERSION}")
    print(f"Config: {CONFIG_FILE}")
    print(f"Custom rules: {len(config.get('custom_rules', []))}")
    sizes = calculate_target_sizes(dict(SYSTEM_TARGET_DEFAULTS))
    print('System targets:')

    for name, sz in sorted(sizes.items()):
        if sz > 0: print(f'  {fmt(sz):>10}  {name}')
    total = sum(sizes.values())
    print(f'  {"-"*30}')
    print(f'  {fmt(total):>10}  TOTAL')


JUNK_KEYWORDS = {
    'cache', 'caches', 'code cache', 'gpucache', 'shadercache', 'dawncache',
    'temp', 'tmp', 'temporary', 'tempor',
    'crash', 'crashdumps', 'crashpad', 'dumps',
    'logs', 'log', 'old', 'backup', 'backups',
    'blob_storage', 'storage', 'videodecodestats',
}


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
        self.config = load_config()
        self.progress = ProgressTracker()
        self.log_queue = queue.Queue()
        self.cancel_event = threading.Event()
        self._clean_in_progress = False
        self._clean_timer = None
        self._dashboard_after_id = None
        self.dash_cat_widgets = {}
        self._build_ui()
        self._schedule_auto_clean()
        self.after(500, self._create_tray_icon)
        self.after(200, self._update_dashboard)

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
        self.btn_task = ctk.CTkButton(side, text=self.T["install_task"], font=native_font, fg_color=WIN95_BUTTON, hover_color=WIN95_BUTTON_HOVER, text_color=WIN95_ACCENT, corner_radius=Z, border_width=2, border_color=BEVEL_RAISED, command=self._install_scheduled_task)
        self.btn_task.grid(row=row, column=0, pady=4, padx=10, sticky="ew")
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
        if hasattr(self,"_tray_icon") and self._tray_icon:
            try: self._tray_icon.stop()
            except Exception: pass  # tray may already be gone during close
        if self._clean_timer: self._clean_timer.cancel()
        self._persist_window_geometry()
        self._full_exit()

    def _persist_window_geometry(self):
        try:
            self.config["window_geometry"] = parse_geometry(self.geometry())
            save_config(self.config)
        except Exception:
            pass  # read-only FS or closing race: best-effort only

    def _full_exit(self):
        self.cancel_event.set()
        if self._dashboard_after_id:
            try:
                self.after_cancel(self._dashboard_after_id)
            except Exception:
                pass
        self.quit()
        self.destroy()

    def _start_job(self):
        if self._clean_in_progress: return
        if not messagebox.askyesno(
                self.T["confirm_title"],
                self.T["confirm_body"],
                parent=self, icon="warning", default="no"):
            return
        self._rebuild_cat_bars()
        self._clean_in_progress = True
        self.cancel_event.clear()
        self.btn_clean.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self.text_log.configure(state="normal")
        self.text_log.delete("1.0", "end")
        self.text_log.configure(state="disabled")
        self.progress = ProgressTracker()
        t = threading.Thread(target=self._run_job, daemon=True)
        t.start()

    def _run_job(self):
        try:
            log = Logger(BASE_DIR/"logs"/f"clean_{datetime.now().astimezone():%Y%m%d_%H%M%S}.log", False, gui_callback=self._log)
            all_targets = {k: True for k in SYSTEM_TARGET_DEFAULTS}
            run_cleaning_job(False, True, True, True, log, DEFAULT_THREADS, all_targets, self.cancel_event, progress=self.progress)
        except CancelJobException:
            self._log(self.T["cancelled"])
        except Exception as e:
            self._log(f"Error: {e}")
        finally:
            self.after(0, self._finish_job)

    def _finish_job(self):
        self._clean_in_progress = False
        self._reset_dashboard()
        self.btn_clean.configure(state="normal")
        self.btn_stop.configure(state="disabled")
        self._schedule_auto_clean()

    def _cancel_job(self):
        self.cancel_event.set()
        self._log(self.T["cancelling"])

    def _log(self, m):
        self.log_queue.put(m)
        self.after(0, self._check_queue)

    def _check_queue(self):
        try:
            while True:
                m = self.log_queue.get_nowait()
                self.text_log.configure(state="normal")
                self.text_log.insert("end", m + "\n")
                self.text_log.see("end")
                self.text_log.configure(state="disabled")
        except queue.Empty:
            pass

    def _schedule_auto_clean(self):
        if self._clean_timer:
            self._clean_timer.cancel()
        interval = self.config.get("auto_clean_interval_hours", 0)
        if interval > 0:
            self._clean_timer = threading.Timer(interval * 3600, self._auto_clean_trigger)
            self._clean_timer.daemon = True
            self._clean_timer.start()

    def _auto_clean_trigger(self):
        if not self._clean_in_progress:
            self.after(0, self._start_job)

    def _update_dashboard(self):
        if self._clean_in_progress:
            s = self.progress.get_snapshot()
            e = f"{int(s['elapsed']//60):02d}:{int(s['elapsed']%60):02d}"
            self.dash_stats.configure(text=f"Items: {s['total_current']}  Freed: {fmt(s['total_bytes'])}  Elapsed: {e}")
            if s['total_items_planned'] > 0:
                self.dash_bar.set(min(s['total_current'] / s['total_items_planned'], 1.0))
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
                    cur, tot, byt = cat_data['current'], cat_data['total'], cat_data['bytes']
                    w['label'].configure(text=f"{nm}: {cur}/{tot}  {fmt(byt)}" if tot > 0 else f"{nm}: {cur}  {fmt(byt)}")
                    if tot > 0:
                        w['bar'].set(min(cur / tot, 1.0))
        self._dashboard_after_id = self.after(500, self._update_dashboard)

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
            def on_cl(ic, it): ic.stop(); self.after(0, self._start_job)
            def on_ex(ic, it): ic.stop(); self.after(0, self._full_exit)
            self._tray_icon = pystray.Icon("vac_cleaner", img, "VAC", pystray.Menu(pystray.MenuItem(self.T["clean"], on_cl), pystray.MenuItem("Exit", on_ex)))
            self._tray_icon.run_detached()
        except Exception:
            pass

    def _install_scheduled_task(self):
        start = simpledialog.askstring(self.T["task_dialog_title"], self.T["task_dialog_prompt"], initialvalue="09:00", parent=self)
        if not start:
            return
        hh, mm = start.split(":")
        if not (0 <= int(hh) < 24 and 0 <= int(mm) < 60):
            return
        install_task(f"{int(hh):02d}:{int(mm):02d}")


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


def scheduled_task_command() -> str:
    """Command line for the scheduled silent full-clean task."""
    if getattr(sys, "frozen", False):
        return f'"{sys.executable}" --cli --all --delete --hidden'
    pythonw = _get_pythonw()
    return f'"{pythonw}" "{SCRIPT_PATH}" --cli --all --delete --hidden'


def install_task(time_str: str) -> None:
    """Register daily silent full-clean task in Windows Task Scheduler."""
    tr = scheduled_task_command()
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
    else:
        print(f"schtasks error: {result.stderr.strip()}")


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
    parser.add_argument("--exclude",     type=str, default="")
    parser.add_argument("--install-task", action="store_true",
                        help="Register daily Task Scheduler job")
    parser.add_argument("--time", type=str, default="09:00",
                        help="Start time for scheduled task (HH:MM, default 09:00)")
    args = parser.parse_args()

    # ── install-task ──────────────────────────────────────────────────────────
    if args.install_task:
        install_task(args.time)
        return

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
        config = load_config()
        rp = args.portable or args.all
        rs = args.system or args.all
        rc = args.custom or args.all
        st = dict(SYSTEM_TARGET_DEFAULTS)
        if args.sys_targets:
            for t in args.sys_targets.split(","): st[t.strip()] = True
        elif args.all:
            st = {k: True for k in SYSTEM_TARGET_DEFAULTS}
        ep = [p.strip() for p in args.exclude.split(",") if p.strip()]
        log = Logger(
            BASE_DIR / "logs" / f"clean_{datetime.now().astimezone():%Y%m%d_%H%M%S}.log",
            dry_run
        )
        run_cleaning_job(
            dry_run, rp, rs, rc, log,
            max_threads=DEFAULT_THREADS,
            sys_targets=st,
            exclude_patterns=ep,
            exclude_paths=config.get("exclude_paths", [])
        )
        return

    # ── GUI mode ────────────────────────────────────────────────────────────────
    _hide_console()
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()


