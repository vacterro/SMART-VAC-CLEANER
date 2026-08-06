# Smart VAC Cleaner

[English](README.md) · [Русский](README.ru.md) · [Eesti](README.et.md)

![Smart VAC Cleaner GUI](assets/screenshot.png)

Portable, safe, modern junk cleaner for Windows. GUI + CLI + Task Scheduler.

Safe by default: dry-run unless you say `--delete`. All candidate portable
roots are always listed in the config; only roots that actually exist on the
current machine are swept, and only known junk patterns inside them.
Missing drives are silently skipped, never errors.

## What it cleans

| Layer | What | Where |
|---|---|---|
| System | Temp, crash dumps, Explorer thumbnails, Windows Update Cache, DNS cache, Recycle Bin, per-user app caches (100+ AppData targets: browsers, Node/uv/pip caches, VS Code family, Eagle, OBS, Discord...) | `%TEMP%`, `%LOCALAPPDATA%`, `%APPDATA%` |
| Deep C: Junk | Updater leftovers, `*.exe.tmp`, Viber QmlWebCache, Yandex.Disk backups, ODIS logs, app.asar.bak and similar | `%LOCALAPPDATA%`, `%TEMP%` |
| Portable roots | Known junk patterns inside portable-app roots you configure | `portable_roots` in config |
| Custom rules | Your own path + glob pattern rules | `custom_rules` in config |

## Safety (defense in depth)

- **Dry-run by default** — GUI "Clean" is real delete (with a confirm dialog), the CLI needs `--delete` explicitly
- **Blacklist**: `C:\`, `C:\Windows`, `USERPROFILE`, Program Files, the script's own folder — never touched, even by custom rules
- **Min path depth**: shallow paths (fewer than 5 parts) are refused
- **Running-process check**: apps using a target are skipped (per-app process lists)
- **Symlinks refused**, `..` traversal refused
- **Never-delete names**: `login data`, `bookmarks`, `cookies`, `database`, etc.
- **Exclusions**: `exclude_patterns` / `exclude_paths` in config
- All deletes go through a `SafetyGuard` per root; errors are counted, never fatal

## Requirements

- Windows 10/11
- Python 3.10+

## Install

```bat
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

Or install as a package (adds the `vac-cleaner` command):

```bat
pip install .
vac-cleaner --status
```

No Python? Grab `SmartVACCleaner.exe` from the GitHub
[Releases](https://github.com/vacterro/SMART-VAC-CLEANER/releases) tab —
fully portable, config and logs live next to the exe.

## Build the exe yourself

```bat
powershell -ExecutionPolicy Bypass -File build_exe.ps1
```

Produces `dist\SmartVACCleaner.exe` (PyInstaller onefile). On every
`v*` tag, CI builds and uploads the exe as an artifact automatically.

## GUI

```bat
python _SMART_VAC_CLEANER.py
```

Four buttons: **Clean** (real delete — asks for confirmation first), **Stop**,
**Find New Junk** (scans AppData for new junk candidates), **Install Auto-Clean
Task**. Progress bars per category, full log window; every run also lands in
`logs\clean_*.log`.

## CLI

The CLI is **dry-run by default** — it only reports what would be deleted.
Add `--delete` to actually remove files. `--dry-run` forces preview even when
`--delete` is present.

| Flag | Effect |
|---|---|
| `--cli` | Force console mode |
| `--portable` / `--system` / `--custom` | Select cleaning layers (default: dry-run preview) |
| `--all` | All layers at once |
| `--delete` | **Real delete** (without it the run is a dry-run preview) |
| `--dry-run` | Force preview even with `--delete` |
| `--status` | Show how much junk exists per target; nothing is deleted |
| `--analyze-caches` | Discover AppData cache folders > 5 MB |
| `--sys-targets` | Comma list of system targets to force-enable (`System Temp`, `User Temp`, ...) |
| `--exclude` | Comma list of extra exclude patterns (`--exclude "*.db,*.tmp"`) |
| `--hidden` | Hide console window (used by Task Scheduler) |
| `--install-task` | Register the daily silent full-clean task |
| `--time HH:MM` | Start time for the scheduled task (default `09:00`) |

Examples:

```bat
REM preview everything
python _SMART_VAC_CLEANER.py --cli --all

REM actually delete everything
python _SMART_VAC_CLEANER.py --cli --all --delete

REM preview, then real delete, dry-run flag always wins
python _SMART_VAC_CLEANER.py --cli --all --delete --dry-run
```

Inspect what would be cleaned:

```bat
python _SMART_VAC_CLEANER.py --status
```

### Automated cleanup (Task Scheduler)

```bat
python _SMART_VAC_CLEANER.py --install-task --time 09:00
```

Installs `SmartVACCleaner` task (highest privileges, hidden window). Uninstall:

```bat
schtasks /Delete /TN SmartVACCleaner /F
```

## Configuration

`cleaner_config.json` is auto-created next to the script (or next to the exe)
on first run, with defaults. All paths in it are canonicalized on load:
slash style, trailing separators and `..` segments are normalized, duplicate
roots collapse, protected paths (`C:\`, Windows, Program Files, user profile,
the cleaner's own folder) and nested roots are rejected with a warning.
Example:

```json
{
  "portable_roots": ["D:\\Portable"],
  "custom_rules": [{"path": "D:\\Apps\\TestApp", "pattern": "*.log"}],
  "exclude_patterns": ["*.db"],
  "exclude_paths": ["C:\\Users\\me\\AppData\\Local\\Important"],
  "auto_clean_interval_hours": 0,
  "lang": "en"
}
```

- `portable_roots`: folders whose known-junk subfolders are swept (pattern-based, e.g. `Cache`, `Temp`, `Logs`, numbered backups). Anything not matching junk patterns is untouched.
- `custom_rules`: `path` (folder) + `pattern` (glob, `*` = whole contents).
- `exclude_patterns` / `exclude_paths`: extra no-go lists.
- `lang`: GUI language — `en` (default), `ru`, `et`. Built-in `strings/*.json` live next to the script (or bundled into the exe); drop your own `<lang>.json` there to add a language.

## Tests

```bat
python -m pytest -q
```

Runs offline, touches only temp directories.

## Documentation

Full docs live in [docs/](docs/Home.md): [Safety](docs/Safety.md), [CLI Reference](docs/CLI-Reference.md), [Configuration](docs/Configuration.md), [Build & Install](docs/Build-and-Install.md), [FAQ](docs/FAQ.md).

## Notes

- Task Scheduler mode needs admin to install the task (`/rl HIGHEST`).
- Portable roots on non-system drives are cleaned even without admin (VAC pattern).
- This project is not affiliated with any vendor; all paths are well-known app cache/log locations that apps regenerate.
