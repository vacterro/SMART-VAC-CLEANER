# Safety (defense in depth)

Layers, in order:

1. **Dry-run by default** — the CLI never deletes without `--delete`. The GUI "Clean" button shows a confirm dialog with default = No.
2. **Path canonicalization** — every user-supplied path is normalized on load: slash style (`\`/`/`), trailing separators, `..` segments, quotes, `%ENV%` vars. Only canonical paths reach the engine, so comparisons never drift.
3. **Blacklist** — `C:\`, `C:\Windows`, `USERPROFILE`, Program Files (both), and the cleaner's own folder are rejected for portable roots, custom rules, and direct deletion — even if user config asks for them.
4. **Root validation** — duplicate roots collapse; a root nested inside another configured root is rejected with a warning.
5. **Min path depth** — paths shallower than 5 components are refused (catches typos like `C:\` or `D:\`).
6. **Running-process check** — per-app process lists; a target whose app is running is skipped entirely.
7. **Symlink refusal** — symlinks are never followed or deleted.
8. **Never-delete names** — `login data`, `bookmarks`, `cookies`, `database`, etc. are always kept, even if a pattern matches.
9. **Exclusions** — `exclude_patterns` (fnmatch) and `exclude_paths` (exact) in config.
10. **Per-root SafetyGuard** — every deletion goes through a guard scoped to its root; errors are counted, never fatal; lock/access issues are logged as skipped.

Operational notes:

- Task Scheduler mode installs with `/rl HIGHEST`; run it from a user-level context, not the built-in admin account.
- The Recycle Bin is emptied only by the `--all` / full-clean path, never silently.
- A crashed run is safe to re-run: deletes are idempotent (missing paths are skipped).
