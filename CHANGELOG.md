# Changelog

## v2.4.7
- Removed developer-only "Find New Junk" scanner button to reduce UI noise.

## v2.4.6
- Fixed "Golden Default" theme tokens using exact `goldendefault.json` from the Wintage repo (`#1A1810` background, restored semantic button colors).

## v2.4.5
- Fixed UI tokens to match the UI.md Vintage Golden default (lighter background `#342012`, uniform golden button text).

## v2.4.4
- Applied precise vintage Dark-Golden theme tokens to UI (UI.md / vintage SKILL compliance).

## v2.4.3
- 11 new safe junk targets: Brave Cache/Code Cache/GPU Cache, Chrome + Edge Code Cache, CEF, Calibre, fontconfig, qBittorrent Logs, Claude CLI Cache, DaVinci Resolve Welcome Cache
- Deep junk sweep: GitHub CLI `run-log-*.zip` cleanup (device-id/config untouched)
- 3 new tests (80 total)

## v2.4.2
- Window geometry persistence restored: size/position saved to `cleaner_config.json` on close, restored on start (`parse_geometry` clamps to 800x500 minimum)
- `save_config()` now used by the GUI close path (was test-only)
- 6 new tests (77 total)

## v2.4.1
- Docs refresh: wiki pages updated for v2.4.0 (lang config key, 71 tests, strings bundle) — `docs/` synced from saiwiki payload
- Translations: `lang` config key documented in README.ru.md / README.et.md

## v2.4.0
- GUI i18n: config `lang` key (`en`/`ru`/`et`), `load_strings()` with English fallback, all GUI strings (buttons, dialogs, junk scanner, tray menu) localizable via `strings/<lang>.json`
- Exe bundles `strings/` (PyInstaller datas); frozen builds also check `BASE_DIR/strings` next to the exe
- 3 new i18n tests (71 total)

## v2.3.1
- i18n: full README translations — Russian (`README.ru.md`), Estonian (`README.et.md`) — with language switcher in README
- docs: release table of contents (this file)

## v2.3.0
- Path hardening: `normalize_path` (env vars, slash style, trailing separators, dot-segments, quotes, control chars), config roots/rules/excludes canonicalized on load, portable-root dedupe + nesting/blacklist rejection, custom-rule protection check before existence check
- 11 new tests (68 total)

## v2.2.0
- Standalone exe build: PyInstaller onefile console, portable `BASE_DIR` next to the exe (config + logs travel with it), `scheduled_task_command` uses the exe when frozen
- `build_exe.ps1` + `SmartVACCleaner.spec` committed; CI builds exe on `v*` tags (artifact upload)
- Logger falls back to console-only if `logs/` cannot be created

## v2.1.1
- `pyproject.toml` + console entry point `vac-cleaner`
- GUI: confirm dialog (default No) before real delete
- First run auto-creates `cleaner_config.json` with defaults

## v2.1.0
- GitHub publishing: LICENSE (MIT), README, requirements.txt, .gitignore, CI workflow (pytest + ruff)
- Config migration: dead `profiles` key dropped on load and persisted
- PortableCleaner sweep tests (numbered copies, running-app skip, chromium profile, universal cache)

## v2.0.0
- Rebuilt from recovered sources: GUI (Win95 dark-golden theme) + CLI + Task Scheduler, `SafetyGuard` per root
