# ruff: noqa: BLE001, S110
import os
from pathlib import Path


def get_size(p):
    total = 0
    try:
        if p.is_file():
            return p.stat().st_size
        for root, _, files in os.walk(p):
            for f in files:
                try:
                    total += os.path.getsize(os.path.join(root, f))
                except OSError:
                    pass
    except Exception:
        pass
    return total


def main():
    keywords = ["cache", "temp", "logs", "crash", "dumps"]
    local = Path(os.environ.get("LOCALAPPDATA", ""))
    roaming = Path(os.environ.get("APPDATA", ""))

    found = []

    for base in [local, roaming]:
        if not base.exists():
            continue
        queue = [(base, 0)]
        while queue:
            cur, depth = queue.pop(0)
            if depth > 3:
                continue
            try:
                for item in cur.iterdir():
                    if not item.is_dir():
                        continue
                    nm = item.name.lower()
                    if any(k in nm for k in keywords):
                        sz = get_size(item)
                        if sz > 1024 * 1024 * 5:  # > 5 MB
                            found.append((str(item), sz))
                    else:
                        queue.append((item, depth + 1))
            except Exception:
                pass

    found.sort(key=lambda x: x[1], reverse=True)
    for p, sz in found[:40]:
        print(f"{sz / (1024 * 1024):8.1f} MB  {p}")


if __name__ == "__main__":
    main()

