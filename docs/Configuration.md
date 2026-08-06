# Configuration

`cleaner_config.json` is auto-created next to the script (or next to the exe)
on first run, with defaults.

```json
{
  "portable_roots": ["D:\\Portable"],
  "custom_rules": [{"path": "D:\\Apps\\TestApp", "pattern": "*.log"}],
  "exclude_patterns": ["*.db"],
  "exclude_paths": ["C:\\Users\\me\\AppData\\Local\\Important"],
  "auto_clean_interval_hours": 0,
  "lang": "en",
  "window_geometry": ""
}
```

## Keys

- `portable_roots` — folders whose known-junk subfolders are swept (names like
  `Cache`, `Code Cache`, `GPUCache`, `Temp`, `Logs`, `Crashpad`, numbered
  backups). Anything not matching junk patterns is untouched.
- `custom_rules` — `path` (folder) + `pattern` (glob, `*` = whole contents).
- `exclude_patterns` — fnmatch patterns, applied to every deletion.
- `exclude_paths` — exact paths never touched.
- `auto_clean_interval_hours` — GUI auto-reclean interval; `0` = off.
- `lang` — GUI language: `en`, `ru`, or `et`; any missing string falls back
  to English. Read at GUI start.
- `window_geometry` — last GUI window size/position, saved on close and
  restored on start; `""` means the default geometry (clamped to a minimum
  of 800x500).

## Canonicalization (on load)

Every path is normalized the moment the config is read:

- slash style unified (`/` and `\`), trailing separators and duplicate
  separators collapsed, `..` segments resolved
- `%ENV%` variables expanded (e.g. `%LOCALAPPDATA%\Cache`)
- surrounding quotes stripped
- relative paths rejected (must be absolute)
- duplicate roots collapse to one canonical entry
- roots nested inside another configured root are rejected with a warning
- protected paths (blacklist: `C:\`, Windows, Program Files, user profile,
  the cleaner's own folder) are rejected for roots and custom rules

User config values survive upgrades; a legacy `profiles` key is dropped
automatically. The GUI **Exclusions** button edits `exclude_patterns` and
`exclude_paths`; other keys are edited in the JSON by hand.
