# Smart VAC Cleaner

Portable, safe, modern junk cleaner for Windows. GUI + CLI + Task Scheduler.

Safe by default: dry-run unless you say `--delete`. All candidate portable
roots are always listed in the config; only roots that actually exist on the
current machine are swept, and only known junk patterns inside them.
Missing drives are silently skipped, never errors.

## What it cleans

| Layer | What | Where |
|---|---|---|
| System | Temp, crash dumps, Explorer thumbnails, Windows Update Cache, DNS cache, Recycle Bin, per-user app caches (60+ AppData targets: browsers, Node/uv/pip caches, VS Code family, Eagle, OBS, Discord...) | `%TEMP%`, `%LOCALAPPDATA%`, `%APPDATA%` |
| Deep C: Junk | Updater leftovers, `*.exe.tmp`, Viber QmlWebCache, Yandex.Disk backups, ODIS logs, app.asar.bak and similar | `%LOCALAPPDATA%`, `%TEMP%` |
| Portable roots | Known junk patterns inside portable-app roots you configure | `portable_roots` in config |
| Custom rules | Your own path + glob pattern rules | `custom_rules` in config |

## Safety (defense in depth)

- **Dry-run by default** — GUI "Clean" is real delete, but the CLI needs `--delete` explicitly
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

GUI:

```bat
python _SMART_VAC_CLEANER.py
```

CLI (preview only):

```bat
python _SMART_VAC_CLEANER.py --cli --portable --system --custom
```

CLI (real delete, all layers):

```bat
python _SMART_VAC_CLEANER.py --cli --all --delete
```

Inspect what would be cleaned:

```bat
python _SMART_VAC_CLEANER.py --status
```

Find new junk candidates in AppData:

```bat
python _SMART_VAC_CLEANER.py --find-junk
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

`cleaner_config.json` is auto-created on first save / not required to run.
Example:

```json
{
  "portable_roots": ["D:\\Portable"],
  "custom_rules": [{"path": "D:\\Apps\\TestApp", "pattern": "*.log"}],
  "exclude_patterns": ["*.db"],
  "exclude_paths": ["C:\\Users\\me\\AppData\\Local\\Important"],
  "auto_clean_interval_hours": 0
}
```

- `portable_roots`: folders whose known-junk subfolders are swept (pattern-based, e.g. `Cache`, `Temp`, `Logs`, numbered backups). Anything not matching junk patterns is untouched.
- `custom_rules`: `path` (folder) + `pattern` (glob, `*` = whole contents).
- `exclude_patterns` / `exclude_paths`: extra no-go lists.

## Tests

```bat
python -m pytest -q
```

Runs offline, touches only temp directories.

## Notes

- Task Scheduler mode needs admin to install the task (`/rl HIGHEST`).
- Portable roots on non-system drives are cleaned even without admin (VAC pattern).
- This project is not affiliated with any vendor; all paths are well-known app cache/log locations that apps regenerate.
