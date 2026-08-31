#!/usr/bin/env python3
"""
Mantenimiento periódico: purga sesiones caducadas y rota la traza.

La rotación enlaza la cadena de hash entre ficheros. Sin ese enlace, rotar
dejaría el fichero nuevo empezando desde cero y borrar la traza entera sería
indistinguible de un arranque limpio.
"""
import hashlib
import hmac
import json
import os
import re
import base64
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Optional

BASE = Path(__file__).resolve().parents[1]
ROTATE_AT_BYTES = 10 * 1024 * 1024


def secrets_path() -> Path:
    """Mismo criterio que la aplicación: LoadCredential= tiene prioridad."""
    cred_dir = os.environ.get("CREDENTIALS_DIRECTORY", "").strip()
    if cred_dir:
        candidate = Path(cred_dir) / "secrets.json"
        if candidate.exists():
            return candidate
    return BASE / "secrets.json"


def load_sec():
    p = secrets_path()
    if p.exists():
        return json.loads(p.read_text(encoding="utf-8"))
    return {}


def hmac_key(sec) -> Optional[bytes]:
    raw = str(sec.get("LOG_HMAC_KEY", "")).strip()
    if not raw:
        return None
    try:
        if re.fullmatch(r"[0-9a-fA-F]{64}", raw):
            return bytes.fromhex(raw)
        return base64.b64decode(raw)
    except Exception:
        return None


def canon(obj) -> bytes:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"),
                      sort_keys=True).encode("utf-8")


def event_hash(evt) -> str:
    clean = {k: v for k, v in evt.items() if not k.startswith("_")}
    return hashlib.sha256(canon(clean)).hexdigest()


def last_event(path: Path):
    if not path.exists():
        return None
    for line in reversed(path.read_text(encoding="utf-8", errors="replace").splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            continue
    return None


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


def rotate_log(app_log: Path, key) -> bool:
    """Rota y deja en el fichero nuevo un evento ancla que enlaza la cadena."""
    if not app_log.exists() or app_log.stat().st_size <= ROTATE_AT_BYTES:
        return False

    previo = last_event(app_log)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d-%H%M%S")
    rotado = app_log.parent / f"app.jsonl.{ts}"
    app_log.rename(rotado)

    ancla = {
        "seq": int(previo.get("seq", 0)) + 1 if previo else 1,
        "prev": event_hash(previo) if previo else "",
        "ts": datetime.now(timezone.utc).isoformat(),
        "action": "log-rotated",
        "ok": True,
        "ip": "",
        "ua": "apk-signer-cleanup",
        "rotatedTo": rotado.name,
    }
    if key:
        ancla["mac"] = hmac.new(key, canon(ancla), hashlib.sha256).hexdigest()

    app_log.write_text(json.dumps(ancla, ensure_ascii=False) + "\n", encoding="utf-8")
    try:
        os.chmod(app_log, 0o640)
    except Exception:
        pass
    return True


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

    rotated = False
    try:
        rotated = rotate_log(log_dir / "app.jsonl", hmac_key(sec))
    except Exception as e:
        print(f"cleanup: fallo rotando la traza: {e}")

    print(f"cleanup: removed_sessions={removed} rotated={rotated}")


if __name__ == "__main__":
    main()
