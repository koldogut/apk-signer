"""
Manipulacion de APK: inspeccion con aapt2, alineado y firma.
"""
import json
import os
import re
import secrets
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from werkzeug.utils import secure_filename

from config import AAPT_BIN, WORK_DIR, ZIPALIGN_BIN, ZIPALIGN_PAGE_KB, check_bin

_ZIPALIGN_SUPPORTS_PAGE_SIZE: Optional[bool] = None

def zipalign_supports_page_size() -> bool:
    """
    `-P <kb>` solo existe desde build-tools 35. En 34 hay que conformarse con
    `-p`, que alinea a 4 KB. Se comprueba una vez leyendo el propio uso del
    binario, en vez de deducirlo de la version del SDK.
    """
    global _ZIPALIGN_SUPPORTS_PAGE_SIZE
    if _ZIPALIGN_SUPPORTS_PAGE_SIZE is None:
        if not check_bin(ZIPALIGN_BIN):
            _ZIPALIGN_SUPPORTS_PAGE_SIZE = False
        else:
            try:
                _, out, err = run_cmd([ZIPALIGN_BIN], timeout=10)
                _ZIPALIGN_SUPPORTS_PAGE_SIZE = "-P <pagesize_kb>" in (out + err)
            except Exception:
                _ZIPALIGN_SUPPORTS_PAGE_SIZE = False
    return _ZIPALIGN_SUPPORTS_PAGE_SIZE

def zipalign_args(src: Path, dst: Path) -> Tuple[List[str], int]:
    """
    Devuelve (argumentos, tamano_de_pagina_kb_efectivo).

    `-P` y `-p` son excluyentes: zipalign rechaza que se pasen juntos.
    """
    args = [ZIPALIGN_BIN]
    if ZIPALIGN_PAGE_KB and zipalign_supports_page_size():
        args += ["-P", str(ZIPALIGN_PAGE_KB)]
        page = ZIPALIGN_PAGE_KB
    else:
        args += ["-p"]   # equivale a 4 KB
        page = 4
    args += ["-f", "4", str(src), str(dst)]
    return args, page

def run_cmd(args: List[str], timeout: int = 60, env: Optional[Dict[str, str]] = None) -> Tuple[int, str, str]:
    # env se fusiona con el entorno del proceso; se usa para pasar secretos
    # (contraseñas de keystore) sin exponerlos en la línea de comandos.
    run_env = {**os.environ, **env} if env else None
    p = subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=run_env,
    )
    return p.returncode, p.stdout, p.stderr

def new_session_id() -> str:
    # URL-safe, corto, suficiente para sesiones temporales
    return secrets.token_urlsafe(12)

# Los sessionId generados son [A-Za-z0-9_-]{16}. Validar el formato evita que un
# sessionId recibido por parámetro escape del árbol de WORK_DIR.
_SID_RE = re.compile(r"[A-Za-z0-9_-]{8,64}")

def valid_sid(sid: str) -> bool:
    return bool(_SID_RE.fullmatch(sid or ""))

def safe_apk_name(original_name: str, fallback: str = "app.apk") -> str:
    """
    Normaliza un nombre de fichero recibido del cliente a un nombre plano y sin
    componentes de ruta. Werkzeug NO sanea FileStorage.filename, así que usarlo
    sin filtrar para construir rutas permitiría escribir fuera de la sesión.
    """
    base = secure_filename(Path(str(original_name or "")).name)
    if not base:
        return fallback
    if not base.lower().endswith(".apk"):
        base = f"{base}.apk"
    return base

def session_dir(sid: str) -> Path:
    return WORK_DIR / "sessions" / sid

def session_meta_path(sid: str) -> Path:
    return session_dir(sid) / "meta.json"

def load_session_meta(sid: str) -> Dict[str, Any]:
    mp = session_meta_path(sid)
    if not mp.exists():
        raise FileNotFoundError("Sesión no encontrada o expirada")
    return json.loads(mp.read_text(encoding="utf-8"))

def save_session_meta(sid: str, meta: Dict[str, Any]) -> None:
    session_meta_path(sid).write_text(json.dumps(meta, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

def aapt_exists() -> bool:
    return check_bin(AAPT_BIN)

def java_ok() -> bool:
    try:
        rc, _, _ = run_cmd(["java", "-version"], timeout=10)
        return rc == 0
    except Exception:
        return False

# ----------------------------
# APK inspect (aapt2)
# ----------------------------
_re_package = re.compile(r"package:\s+name='([^']+)'(?:\s+versionCode='([^']+)')?(?:\s+versionName='([^']+)')?")
_re_sdk = re.compile(r"sdkVersion:'([^']+)'")
_re_target = re.compile(r"targetSdkVersion:'([^']+)'")
_re_label = re.compile(r"application-label:'([^']*)'")
_re_perm = re.compile(r"uses-permission:\s+name='([^']+)'")

def inspect_apk_with_aapt(apk_path: Path) -> Dict[str, Any]:
    if not aapt_exists():
        raise RuntimeError("aapt/aapt2 no encontrado")

    # aapt2 suele aceptar: aapt2 dump badging <apk>
    rc, out, err = run_cmd([AAPT_BIN, "dump", "badging", str(apk_path)], timeout=60)
    if rc != 0:
        # algunos aapt (no aapt2) usan: aapt dump badging <apk>
        raise RuntimeError((err or out or f"aapt fallo rc={rc}").strip())

    info: Dict[str, Any] = {}
    m = _re_package.search(out)
    if m:
        info["packageName"] = m.group(1) or ""
        info["versionCode"] = m.group(2) or ""
        info["versionName"] = m.group(3) or ""

    m = _re_label.search(out)
    if m:
        info["appLabel"] = m.group(1) or ""

    m = _re_sdk.search(out)
    if m:
        info["minSdk"] = m.group(1) or ""

    m = _re_target.search(out)
    if m:
        info["targetSdk"] = m.group(1) or ""

    perms = _re_perm.findall(out) or []
    perms = sorted(set(perms))
    info["permissions"] = perms

    # tags para UI (ordenados)
    tags: List[Dict[str, str]] = []
    if info.get("packageName"):
        tags.append({"k": "Package", "v": info["packageName"]})
    if info.get("versionName"):
        tags.append({"k": "Versión", "v": info["versionName"]})
    if info.get("versionCode"):
        tags.append({"k": "VersionCode", "v": str(info["versionCode"])})
    if info.get("minSdk"):
        tags.append({"k": "minSdk", "v": str(info["minSdk"])})
    if info.get("targetSdk"):
        tags.append({"k": "targetSdk", "v": str(info["targetSdk"])})
    info["tags"] = tags

    return info

def _signed_filename(original_name: str) -> str:
    base = safe_apk_name(original_name)
    if base.lower().endswith(".apk"):
        base = base[:-4]
    return f"{base}_signed.apk"
