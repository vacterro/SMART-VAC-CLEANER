# Safety (defense in depth)

Layers, in order:

1. **Dry-run by default** — the CLI never deletes without `--delete`. The GUI "Clean" button shows a confirm dialog with default = No. `--dry-run` forces a preview even when `--delete` is present.
2. **Path canonicalization** — every user-supplied path is normalized on load: slash style (`\`/`/`), trailing separators, `..` segments, quotes, `%ENV%` vars. Only canonical paths reach the engine, so comparisons never drift.
3. **Blacklist** — `C:\`, `C:\Windows`, `USERPROFILE`, Program Files (both), and the cleaner's own folder are rejected for portable roots, custom rules, and direct deletion — even if user config asks for them. The rule is exact root **plus every descendant**: any path equal to or under a protected root is refused.
4. **Root validation** — duplicate roots collapse; a root nested inside another configured root is rejected with a warning.
5. **Min path depth** — paths shallower than 5 components are refused (catches typos like `C:\` or `D:\`).
6. **Running-process check** — per-app process lists; a target whose app is running is skipped entirely. When the process table cannot be queried (`tasklist` failure or nonzero exit) the state is **UNKNOWN**, and every app-sensitive target is skipped (fail closed) — the cleaner never assumes "nothing is running".
7. **Symlink / reparse refusal** — symlinks, junctions and reparse points are refused before any resolve or delete; the cleaner never follows or descends through them.
8. **Never-delete names** — an explicit list of protected names (`login data`, `bookmarks`, `cookies`, `history`, `preferences`, `passkey_enclave_state`, `trusted_vault.pb`, FreeFileSync `GlobalSettings.xml` / `LastRun.ffs_*`, …) is always kept, even if a pattern matches. Numbered copies (`Cookies (2)`, `Login Data (3)`) and journal/`-wal`/`-shm`/`-bak` variants of a protected name resolve back to the protected base and are kept too. Matching is explicit-name based; there is no fuzzy word matching.
9. **Exclusions** — `exclude_patterns` (fnmatch) and `exclude_paths` (exact) from the config. They are a global invariant: every SafetyGuard the engine builds — portable, system, custom, deep sweep — inherits the same exclusions, and the CLI merges config exclusions with `--exclude` additions (deduped).
10. **Guarded recursive deletion** — `_del_dir` does not `rmtree` blindly: every node under a target is validated by the guard before deletion. Protected / excluded / link nodes and their whole subtrees survive; only deletable siblings and the now-empty parents are removed. Counters, progress and log entries advance only *after* a verified successful delete — a failed `unlink` frees nothing and inflates nothing.

Operational notes:

- `--all` / the scheduled task / the background clean use the **safe** system-target defaults. Risky opt-in actions — Recycle Bin, DNS cache flush, Windows Update cache purge — are **never** enabled by `--all`; they require an explicit `--sys-targets "Recycle Bin,DNS Cache,Windows Update Cache"`.
- The Recycle Bin is emptied only when the target is explicitly enabled via `--sys-targets`, never silently and never by selecting all layers.
- AppData targets are structured as `(path, description, owning-process group)`: when the owning app runs — or the process table is UNKNOWN — that target is skipped.
- A crashed run is safe to re-run: deletes are idempotent (missing paths are skipped).
