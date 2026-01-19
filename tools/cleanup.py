#!/usr/bin/env python3
import json
from pathlib import Path
from datetime import datetime, timedelta, timezone

BASE = Path("/opt/apk-signer")
SECRETS = BASE / "secrets.json"

def load_sec():
    if SECRETS.exists():
        return json.loads(SECRETS.read_text(encoding="utf-8"))
    return {}

def rm_tree(p: Path):
    for c in sorted(p.rglob("*"), reverse=True):
        try:
            if c.is_file() or c.is_symlink():
                c.unlink(missing_ok=True)
            elif c.is_dir():
                c.rmdir()
        except Exception:
            pass
    try:
        p.rmdir()
    except Exception:
        pass

def main():
    sec = load_sec()
    work = Path(sec.get("WORK_DIR", str(BASE / "work")))
    log_dir = Path(sec.get("LOG_DIR", str(BASE / "logs")))
    ttl_h = int(sec.get("SESSION_TTL_HOURS", 24))
    cutoff = datetime.now(timezone.utc) - timedelta(hours=ttl_h)

    sessions = work / "sessions"
    removed = 0
    if sessions.exists():
        for d in sessions.iterdir():
            try:
                if not d.is_dir():
                    continue
                mtime = datetime.fromtimestamp(d.stat().st_mtime, tz=timezone.utc)
                if mtime < cutoff:
                    rm_tree(d)
                    removed += 1
            except Exception:
                continue

    # rotate app.jsonl if > 10 MiB
    app_log = log_dir / "app.jsonl"
    if app_log.exists():
        try:
            if app_log.stat().st_size > 10 * 1024 * 1024:
                ts = datetime.now(timezone.utc).strftime("%Y-%m-%d-%H%M%S")
                app_log.rename(log_dir / f"app.jsonl.{ts}")
                app_log.write_text("", encoding="utf-8")
        except Exception:
            pass

    print(f"cleanup: removed_sessions={removed}")

if __name__ == "__main__":
    main()
