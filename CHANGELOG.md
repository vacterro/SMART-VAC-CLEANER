# Changelog

## v2.6.1
- **Scheduled/background target customization (T-106)**: the scheduled task and "Run in background" now carry the GUI's risky opt-in system targets — if you enabled Recycle Bin / DNS / Windows Update in the System Targets dialog, the scheduled run and background clean apply them too. New `--sys-targets` support on `--install-task` (unknown targets exit 2). `--all` and the default no-target forms are byte-identical to before (safe defaults only). 169 tests green, ruff clean.

## v2.6.0
- **GUI opt-in for risky system targets (T-105)**: new *System Targets* dialog — per-target checkboxes let a GUI user explicitly enable Recycle Bin / DNS cache / Windows Update cache purge, the same opt-in CLI `--sys-targets` provides. Risky targets stay OFF by default and `--all` / scheduled / background behavior is unchanged; the opt-in is session-scoped (persistence is a separate planned change). i18n keys for all four locales (en/ru/et/ded). 162 tests green, ruff clean.

## v2.5.2
- docs: fixed broken screenshot link in `README.ru.md` / `README.et.md` (`../assets/` → `assets/`); wiki payload refreshed and collected (6 pages, invariants green).

## v2.5.1
- test: `test_old_opera_versions_keep_latest` made environment-independent — it no longer depends on whether Opera happens to be running on the host (the safety gate correctly skips when it is); regression is now deterministic. 159 tests green, ruff clean.

## v2.5.0
- **Safety hardening (data-loss fixes)**
  - **Dry-run is physically read-only**: deletion split into a pure read-only planning phase and an apply phase that runs only in real-delete mode. A dry-run performs no unlink/chmod/rmdir, no DNS flush, no service stop/start, no recycle-bin call (mutation-tripwire + byte-identical snapshot tests).
  - FreeFileSync cache target retargeted to the explicit `Logs` child; `GlobalSettings.xml` / `LastRun.ffs_*` protected. Numbered copies are explicit junk-only; `Cookies (2)` / `Login Data (3)` / `History (3)` survive.
  - Exclusions are a global invariant (every guard inherits engine exclusions; CLI merges config + `--exclude`). Guarded recursive deletion validates every node; protected/excluded subtrees survive.
  - Browser allowlists shrunk (SW/Database, `passkey_enclave_state`, `trusted_vault.pb`, `P3AConfig`, Firefox session/state removed); explicit-name never-delete, no fuzzy matching; compound names (`Cookies (2)-journal`) reduce mechanically.
  - Broad AppData roots quarantined (CEF, DaVinci Resolve Welcome, Razer Service Worker, NVIDIA PerDriverVersion); Epic webcache session/database data protected.
- **Invariants**: `--all`/GUI/scheduled use safe system-target defaults (Recycle Bin/DNS/Windows Update only via explicit `--sys-targets`); process detection fails closed (UNKNOWN → skip); every AppData target is owned or explicitly process-agnostic (no `owner=None` escape hatch); blacklist rejects roots + descendants; symlinks/junctions/reparse refused; delete counters advance only after verified success; cancellation checked during discovery/submit/mutation.
- **Windows Update cache purge is transaction-safe**: original service state queried, stopped only if running, verified before deletion (failure → skip), restored in `finally` on success/error/cancel; originally-stopped service never started; dry-run does zero service mutation.
- **Portable roots**: hardcoded `PRIMARY_ROOT`/`BACKUP_ROOTS` removed; fresh config defaults to `portable_roots: []` (existing user roots untouched).
- **Cleanup policy**: generic `.bak` rollback files are never auto-deleted; universal (BFS) sweeper refuses discovered caches under unknown app ownership in real-delete mode.
- **GUI lifecycle**: worker threads never touch Tk (queue + completion event only; one main-thread poller); closing during a clean cancels and destroys only after the worker terminates.
- Shared dependency-free `_fs_helpers` (get_size dedup), canonical `clean_argv()` builder, dead symbols removed, `ded` locale in i18n symmetry, docs synced. 159 tests green, ruff clean.

## v2.4.16
- i18n: Added angry-grandpa (`Дед`) voice UI localization (`strings/ded.json`) and translated `README.ded.md`.
- Updated language switcher across all READMEs (`en`, `ru`, `et`, `ded`) and appended source-digest to locales.
- Version bump to 2.4.16 (VERSION, pyproject, CHANGELOG).

## v2.4.15
- New **Run in bg** button (sidebar, under Install Auto-Clean Task): spawns a detached silent background full-clean (`pythonw`/exe, hidden console, no GUI) and returns — double-click guarded via `Popen.poll()`. Reuses the same argv as the scheduled task.
- i18n: 3 new string keys (en/ru/et): `run_bg`, `run_bg_started`, `run_bg_running`.
- Dead i18n sweep: removed 4 unused keys (`find_new_junk`, `junk_window_title`, `scanning`, `nothing_found`, T-043 leftovers) from en/ru/et; added `TestI18nSymmetry` (no dead keys, ru/et key-sets == en).
- README GUI section updated to the current five buttons (en/ru/et); wiki test count synced to 86.
- New `background_clean_argv()` helper (frozen-aware) + 3 unit tests; 86 tests green, ruff clean.
- Version bump to 2.4.15 (VERSION, pyproject, CHANGELOG).

## v2.4.14
- Added 12 new safe cache targets to `USER_APPDATA_TARGETS`: Windows Search DeviceSearchCache/AppIconCache, iTop Easy Desktop Thumbs, Freebuff Cache, AIChatter Edge Profile Cache, Telegram media_cache, Photoshop WebView Cache (Local), Adobe Bridge Code/GPU Cache, Ollama Shader Cache, Opera SW CacheStorage/ScriptCache (~400 MB found live).
- Fixed `_deep_junk_sweep` guard bug: it used the rebound `self.guard` (last AppData target root), so every `is_safe` check failed and all deep-sweep items were silently skipped. Now uses its own C:\-rooted `SafetyGuard`.
- Fixed Viber sweep path (was `LOCALAPPDATA/ViberPC/QmlWebCache`, real path is per-account under Roaming) — now globs `*/QmlWebCache` and `*/Thumbnails`.
- Added Firefox system-profile cache sweep (startupCache/cache2/shader-cache/crashes/minidumps, skipped while firefox runs) and Explorer `ThumbCacheToDelete` cleanup.
- Version bump to 2.4.14.

## v2.4.13
- Removed dead `ProgressLogger.warn()` and `ProgressTracker.set_total()` (zero call sites).
- Fixed duplicate `--time HH:MM` row in docs/CLI-Reference.md + wiki payload source.
- 81 tests green, ruff clean.

## v2.4.12
- GUI Exclusions editor: new **Exclusions** button opens a dialog editing `exclude_patterns` / `exclude_paths` (patterns textbox, paths list with browse + remove, Save persists to config); excludes are now actually passed into the cleaning job from the GUI.
- Live progress dashboard: `ProgressTracker` wired into the cleaners — items freed and bytes now count per category instead of staying at 0.
- Removed dead `format_env_path()`; tray-icon and scheduled-task install failures now log a warning instead of failing silently.
- i18n: 9 new GUI string keys (en/ru/et); README.ru/et GUI sections synced to the current button set (Find New Junk removed, Exclusions added).
- Wiki/docs sync: Configuration (GUI editor note), Home (Exclusions + live progress bullets), CLI Reference (+`--time HH:MM` flag row).
- 81 tests green, ruff clean.

## v2.4.11
- Added 14 new safe cache paths to `USER_APPDATA_TARGETS` discovered via `--analyze-caches` / deep scan: DriveFS Logs (Local), Razer Engine Cache/Code/GPU/Service Worker, Epic webcache (Local), VS Code WebStorage CacheStorage, VerifiedSkill CRX Cache, MaxonApp WebView Cache/Code/Shader, Photoshop 2024 Logs, Obsidian GPUCache (~2.2 GB on this machine).
- Fixed dead `--analyze-caches` flag: `main()` now dispatches to `analyze_caches.main()` (flag was parsed but never executed).
- Test mocks updated for the new flag; 81 tests green, ruff clean.
- saiwiki docs refresh applied: CLI Reference (+`--analyze-caches`), Configuration (+`window_geometry`), Home/Build (100+ targets, 81 tests).
- Version bump to 2.4.11 (VERSION, pyproject, CHANGELOG).

## v2.4.10
- Fixed doc drift: updated "60+ AppData targets" to "100+ AppData targets" across `README.md`, `README.ru.md`, `README.et.md`, `docs/Home.md`.
- Added native CLI `--analyze-caches` flag to discover AppData cache folders > 5 MB directly via console.
- Documented `--analyze-caches` and exclude options across CLI docs and README tables.

- Added 38 new safe system junk and cache paths to `USER_APPDATA_TARGETS` (Devin, Claude, Antigravity, CodeNomad, Ollama, LM Studio, Substance 3D, AccuRIG, Topaz, Unreal, Omniroute, etc.).

## v2.4.8
- Added 15 new safe system cache paths to `USER_APPDATA_TARGETS` (including Devin, FontBase, Maxon, Opera, Brave, Discord CRX caches, BlueStacks, AIChatter).

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
