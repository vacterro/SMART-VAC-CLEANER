# Changelog

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
