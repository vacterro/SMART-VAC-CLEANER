# Changelog

## v2.6.9
- **Triple-wave audit (CORE-001..014, W2-001..008, PERF-001..008)**: P0 security fixes — root-identity TOCTOU (identity fingerprint + ino reuse blocked), symlink/junction rejection before resolve, invalid env roots stay None end-to-end, INVALID config preserved (no overwrite on close), read-only config snapshot for dry-run/status, concurrent future errors escalate to ERROR, operational failures (DNS/RecycleBin/wuauserv) escalated from warning to error, canonical scheduled argv without stale target mask, _poll_main checks thread death not just event, schtasks/net start bounded timeouts, CLI validates exactly one action family. P1 stability — cross-process destructive-job lease via Windows named mutex, GUI strict-loads latest config per action with field-level merge on persistence, save_config uses unique temp+fsync per writer, Logger mkdir failure degrades to console-only, Windows Update derives from trusted WINDIR snapshot, canonical HH:MM parser, test_package_install asserts fixture bytes via subprocess. P2 performance — CandidateLedger batched scope when no prior claims exist, Toolhelp32Snapshot native process enum (zero tasklist subprocesses), deque.popleft for Universal Sweeper BFS, opt-in deleted_paths for production Logger, ProgressTracker revision cache avoids redundant repaint. 288 tests green, ruff clean, package smoke PASS.

## v2.6.8
- **Second-pass safety audit (T-137..T-146)**: every filesystem mutation now has its own immediately-adjacent authorization — `authorize -> unlink` directly, and on a read-only `PermissionError` `authorize -> chmod -> re-baseline -> authorize -> unlink`; directories and tree roots run the emptiness check before a fresh authorization immediately before `rmdir` (T-137). A malformed EXISTING config can no longer authorize a destructive run: per-field type validation (`load_config_strict`) and DELETE aborts with exit code 3 instead of silently continuing with empty exclusions/policy (T-138). Installed wheels now keep config/logs in `%LOCALAPPDATA%\SmartVACCleaner` instead of site-packages (`SMARTVAC_DATA_DIR` overrides it for tests), and the clean-install smoke test actually plans its 64-byte fixture once (T-139/140). `save_config` returns a boolean and the GUI editors no longer close over a failed save (T-141). `analyze_caches.py` is env-safe (empty env never falls back to the cwd), deque-based, link/reparse-safe, token-boundary matched and strictly read-only (T-142). The v* tag workflow now creates a GitHub Release with the exe (T-143). The dead `..` part-check was removed and the docs say paths are canonicalized and confined to their root (T-144). Hand-built oracle fixtures give exact expected candidate sets instead of planner-vs-planner parity (T-145). Markhunt A-H closed, including a real `get_env_path` empty-env-to-cwd fix (T-146). 280 tests green, ruff clean.

## v2.6.7
- **Logs/ retention (T-110)**: the daily scheduled clean appends `clean_*.log` forever with no pruning (28 files in 15 days). Every job start (clean / scheduled / background) now prunes the cleaner's own `logs/` directory to the newest 14 run logs; older ones are removed, non-log files are never touched. The retention is its own allowlisted mutation subsystem (log hygiene, not a cleaner deletion). 260 tests green, ruff clean.

## v2.6.6
- **Post-v2.6.5 candidate-truth & policy audit (T-124..T-136)**: one physical candidate is now planned exactly once -- a job-shared CandidateLedger deduplicates across portable/system/custom (including parent/child and canonical aliases), the Universal Sweeper defers known-app caches to their dedicated sweepers and reports unknown-owner caches as `DISCOVERED / NOT AUTHORIZED` with zero bytes, so a 10-byte cache reports 10, never 20, and dry-run contains only actionable candidates (T-124/125). One resolved `JobSpec` now carries every policy input per job, resolved once at the surface boundary -- CLI/status/GUI/preview/background/scheduled stop reconstructing config/mask/exclusions downstream, `--status` uses the documented safe CLI mask plus saved exclusions, and the GUI freezes the job before its worker thread starts (T-126/127/128). Background and scheduled runs serialize the full target-mask deviation both ways (new `--disable-targets`), so a disabled safe default survives `--all` (T-129). Owner provenance is now enforceable: `unverified-exe` owners cannot authorize real deletion in either mode (T-130). Owning-process state is re-checked just-in-time before each apply batch, so an app starting between plan and apply aborts the target (T-131). Cancellation is a mutation invariant inside the authorization gate, covering every chmod/unlink/rmdir including the retry and root-removal paths (T-132). The Safety-doc contract now proves behavior rather than class existence (T-133); a mutation-inventory allowlist by subsystem closes unreviewed cleaner side doors (T-134); and the blacklist wording documents the exact user-root vs internal-system-target boundary (T-135). 258 tests green, ruff clean.

## v2.6.5
- **Safety hardening audit (T-111..T-122)**: plan is no longer permission forever -- every file/dir/root mutation is re-authorized just-in-time against the identity captured during planning, so a swapped, replaced, symlinked or recreated object is skipped, never deleted (TOCTOU close, T-111). Windows Update purge deletes only under an exact `STOPPED` service state and restores the original state on every path (T-112). Custom rules now enforce the same shallow-root depth protection as user roots (T-113). `--status`, GUI preview and dry-run share one read-only planner, so their bytes and candidate sets are identical (T-114); config is loaded once per job and frozen (T-115). Wheel packaging ships `_fs_helpers`/`analyze_caches` and the locale files, with a clean-install smoke test (T-116). Zero-byte deletions are counted as successes (T-117); progress bars are determinate only when a real total exists (T-118); stale version claims and an installed 2.1.0 dist were removed (T-119); the process-owner map got semantic provenance and a corrected `devin` executable (T-120); dead/duplicate helpers collapsed (T-121); a mutation-chokepoint and Safety-doc contract regression suite was added (T-122). 224 tests green, ruff clean.

## v2.6.4
- **README/screenshot doc-drift fix (T-109)**: GUI docs updated from "five buttons" to seven -- the sidebar's *Preview* (read-only dry-run, T-107) and *System Targets* (risky-target opt-in, T-105) buttons were missing from the README and its translations. README.md/ru/et/ded rewritten, screenshot regenerated from the live build, translation package refreshed (ee). 179 tests green, ruff clean.

## v2.6.3
- **Persistent per-target preferences (T-108)**: the System Targets dialog now saves your choices to the config file (`system_targets` key), so your opt-in for Recycle Bin / DNS / Windows Update survives restarts. Unknown target names in a hand-edited config are rejected on load; safe defaults are unchanged. The plain CLI path keeps the P1-7 guarantee -- `--all` never enables risky targets silently; persisted opt-ins reach scheduled/background runs through the explicit `--sys-targets` embedded in the task (v2.6.1). 179 tests green, ruff clean.

## v2.6.2
- **GUI Preview mode (T-107)**: new *Preview* button in the sidebar runs a physically read-only dry-run and shows exactly what would be deleted — sizes, categories, total "Would free" — before you commit to a real clean. No confirm dialog, zero filesystem mutation; the dry-run engine is the same read-only plan/apply machinery (T-090). i18n key added for all four locales (en/ru/et/ded). 172 tests green, ruff clean.

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
