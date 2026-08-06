# CLI Reference

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
| `--analyze-caches` | Scan `%LOCALAPPDATA%`/`%APPDATA%` for cache/temp/log/crash folders over 5 MB and print the biggest -- cache discovery for auditing, nothing is deleted |
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

REM how much junk exists
python _SMART_VAC_CLEANER.py --status

REM daily silent task at 09:00
python _SMART_VAC_CLEANER.py --install-task --time 09:00
```

Task removal:

```bat
schtasks /Delete /TN SmartVACCleaner /F
```

After a `pip install .`, the same commands work as `vac-cleaner ...`.
The standalone exe supports the identical flags: `SmartVACCleaner.exe --all --delete`.
