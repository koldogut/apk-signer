#!/usr/bin/env python3
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from flask import Flask, jsonify, request, send_from_directory, send_file, abort, make_response

BASE_DIR = Path(__file__).resolve().parent
SECRETS_PATH = BASE_DIR / "secrets.json"

app = Flask(__name__, static_folder="static", static_url_path="/static")

# ----------------------------
# Config / secrets
# ----------------------------
def _load_secrets() -> Dict[str, Any]:
    if not SECRETS_PATH.exists():
        raise RuntimeError(f"No existe {SECRETS_PATH}. Crea secrets.json a partir de secrets.example.json")
    try:
        return json.loads(SECRETS_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise RuntimeError(f"secrets.json inválido: {e}")

SEC = _load_secrets()

PIN_REQUIRED = str(SEC.get("PIN", "")).strip()
AAPT_BIN = str(SEC.get("AAPT", "")).strip()  # ruta absoluta a aapt2 o aapt
APKSIGNER_JAR = str(SEC.get("APKSIGNER_JAR", "")).strip()
KEYSTORE_PATH = str(SEC.get("KEYSTORE_PATH", "")).strip()
KS_PASS = str(SEC.get("KS_PASS", "")).strip()
KEY_ALIAS = str(SEC.get("KEY_ALIAS", "")).strip()
KEY_PASS = str(SEC.get("KEY_PASS", "")).strip()

WORK_DIR = Path(str(SEC.get("WORK_DIR", str(BASE_DIR / "work"))))
LOG_DIR = Path(str(SEC.get("LOG_DIR", str(BASE_DIR / "logs"))))
MAX_CONTENT_LENGTH = int(SEC.get("MAX_CONTENT_LENGTH", 100 * 1024 * 1024))  # 100MB default
SESSION_TTL_HOURS = int(SEC.get("SESSION_TTL_HOURS", 24))
LOG_MAX_LINES = int(SEC.get("LOG_MAX_LINES", 2000))

app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH

LOG_FILE = LOG_DIR / "app.jsonl"

def _hmac_key_bytes() -> Optional[bytes]:
    raw = str(SEC.get("LOG_HMAC_KEY", "")).strip()
    if not raw:
        return None
    try:
        # admite hex de 32 bytes (64 chars) o base64
        if re.fullmatch(r"[0-9a-fA-F]{64}", raw):
            return bytes.fromhex(raw)
        return base64.b64decode(raw)
    except Exception:
        return None

HMAC_KEY = _hmac_key_bytes()

# ----------------------------
# Helpers
# ----------------------------
def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def safe_mkdir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def check_bin(path: str) -> bool:
    return bool(path) and Path(path).exists()

def run_cmd(args: List[str], timeout: int = 60) -> Tuple[int, str, str]:
    p = subprocess.run(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
    )
    return p.returncode, p.stdout, p.stderr

def new_session_id() -> str:
    # URL-safe, corto, suficiente para sesiones temporales
    return secrets.token_urlsafe(12)

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

def client_ip() -> str:
    # si detrás de proxy, ajustar a tu realidad. Por defecto, REMOTE_ADDR.
    return request.headers.get("X-Forwarded-For", "").split(",")[0].strip() or request.remote_addr or ""

def _canon_json(obj: Dict[str, Any]) -> bytes:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")

def log_event(action: str, ok: bool, **fields: Any) -> None:
    """
    Logging best-effort. NUNCA debe tumbar la app si hay permisos/FS raros.
    """
    try:
        safe_mkdir(LOG_DIR)
        if not LOG_FILE.exists():
            # evita el “primer arranque 500” si falta el fichero
            LOG_FILE.touch()
        evt: Dict[str, Any] = {
            "ts": utc_now_iso(),
            "action": action,
            "ok": bool(ok),
            "ip": client_ip(),
            "ua": request.headers.get("User-Agent", ""),
        }
        for k, v in fields.items():
            evt[k] = v
        if HMAC_KEY:
            to_mac = dict(evt)
            to_mac.pop("mac", None)
            mac = hmac.new(HMAC_KEY, _canon_json(to_mac), hashlib.sha256).hexdigest()
            evt["mac"] = mac

        with LOG_FILE.open("a", encoding="utf-8") as fp:
            fp.write(json.dumps(evt, ensure_ascii=False) + "\n")
    except Exception:
        # silencio deliberado: logs no pueden romper funcionalidad.
        pass

def verify_event_mac(evt: Dict[str, Any]) -> Tuple[str, bool]:
    """
    Devuelve (estado, ok_verificacion)
    estado: "OK", "Fallo", "Sin MAC", "Sin clave"
    """
    mac = evt.get("mac")
    if not mac:
        return ("Sin MAC", False)
    if not HMAC_KEY:
        return ("Sin clave", False)
    try:
        to_mac = dict(evt)
        to_mac.pop("mac", None)
        expected = hmac.new(HMAC_KEY, _canon_json(to_mac), hashlib.sha256).hexdigest()
        return ("OK" if hmac.compare_digest(str(mac), expected) else "Fallo", hmac.compare_digest(str(mac), expected))
    except Exception:
        return ("Fallo", False)

def require_pin(pin: str) -> bool:
    # Comparación constante
    return bool(PIN_REQUIRED) and hmac.compare_digest(pin or "", PIN_REQUIRED)

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

# ----------------------------
# Routes
# ----------------------------
@app.after_request
def add_headers(resp):
    # Cabeceras “razonables” sin romper fetch/clipboard.
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    resp.headers["Permissions-Policy"] = "clipboard-read=(self), clipboard-write=(self)"
    resp.headers["Cache-Control"] = "public, max-age=600"
    resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    # CSP: sin inline JS. CSS self.
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "font-src 'self' data:; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "base-uri 'none'; "
        "frame-ancestors 'none'; "
        "form-action 'self'"
    )
    return resp

@app.get("/")
def index():
    return send_from_directory(app.static_folder, "index.html")

@app.get("/favicon.ico")
def favicon():
    # evita 500 si no hay favicon real
    return ("", 204)

@app.get("/healthz")
def healthz():
    checks = {
        "work_writable": False,
        "aapt_configured": bool(AAPT_BIN),
        "aapt_exists": aapt_exists(),
        "apksigner_jar_exists": check_bin(APKSIGNER_JAR),
        "keystore_exists": check_bin(KEYSTORE_PATH),
        "java": java_ok(),
        "disk_free_bytes": None,
    }
    try:
        safe_mkdir(WORK_DIR)
        safe_mkdir(WORK_DIR / "sessions")
        test = WORK_DIR / ".writetest"
        test.write_text("ok", encoding="utf-8")
        test.unlink(missing_ok=True)
        checks["work_writable"] = True
    except Exception:
        checks["work_writable"] = False

    try:
        st = shutil.disk_usage(str(WORK_DIR))
        checks["disk_free_bytes"] = int(st.free)
    except Exception:
        pass

    return jsonify({"ok": True, "checks": checks, "now": utc_now_iso(), "version": "1.6.0"})

@app.post("/inspect")
def inspect_ep():
    t0 = time.time()
    if "apk" not in request.files:
        return jsonify({"ok": False, "error": "Falta fichero (campo 'apk')"}), 400

    f = request.files["apk"]
    original_name = (f.filename or "input.apk").strip()
    if not original_name.lower().endswith(".apk"):
        return jsonify({"ok": False, "error": "El fichero debe ser .apk"}), 400

    safe_mkdir(WORK_DIR / "sessions")
    sid = new_session_id()
    sdir = session_dir(sid)
    safe_mkdir(sdir)

    in_path = sdir / "input.apk"
    f.save(in_path)

    size_b = in_path.stat().st_size
    sha = sha256_file(in_path)

    ok = True
    data: Dict[str, Any] = {}
    err = ""

    try:
        info = inspect_apk_with_aapt(in_path)
        data = {
            "sessionId": sid,
            "originalName": original_name,
            "sizeBytes": size_b,
            "sha256": sha,
            "apkInfo": info,
        }
        meta = {
            "sessionId": sid,
            "createdAt": utc_now_iso(),
            "originalName": original_name,
            "inputPath": str(in_path),
            "sha256": sha,
            "sizeBytes": size_b,
            "signedPath": "",
            "signedName": "",
            "signedOk": False,
            "verifiedOk": False,
        }
        save_session_meta(sid, meta)
    except Exception as e:
        ok = False
        err = str(e)
        # aun así guardamos meta mínima para diagnóstico
        meta = {
            "sessionId": sid,
            "createdAt": utc_now_iso(),
            "originalName": original_name,
            "inputPath": str(in_path),
            "sha256": sha,
            "sizeBytes": size_b,
            "signedPath": "",
            "signedName": "",
            "signedOk": False,
            "verifiedOk": False,
        }
        try:
            save_session_meta(sid, meta)
        except Exception:
            pass

    dt_ms = int((time.time() - t0) * 1000)
    log_event("inspect", ok=ok, filename=original_name, size=size_b, sha256=sha, ms=dt_ms, error=(err if not ok else ""))

    if not ok:
        return jsonify({"ok": False, "error": err, "rc": 127, "sha256": sha, "sizeBytes": size_b}), 200

    return jsonify({"ok": True, **data}), 200

def _signed_filename(original_name: str) -> str:
    base = original_name
    if base.lower().endswith(".apk"):
        base = base[:-4]
    return f"{base}_signed.apk"

@app.post("/sign")
def sign_ep():
    payload = request.get_json(force=True, silent=True) or {}
    sid = str(payload.get("sessionId", "")).strip()
    pin = str(payload.get("pin", "")).strip()

    if not sid:
        return jsonify({"ok": False, "error": "Falta sessionId"}), 400
    if not require_pin(pin):
        log_event("sign", ok=False, sessionId=sid, error="PIN incorrecto")
        return jsonify({"ok": False, "error": "PIN incorrecto"}), 403

    try:
        meta = load_session_meta(sid)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 404

    in_path = Path(meta["inputPath"])
    if not in_path.exists():
        return jsonify({"ok": False, "error": "Input APK no existe"}), 404

    signed_name = _signed_filename(meta.get("originalName", "app.apk"))
    out_path = session_dir(sid) / signed_name

    if not (check_bin(APKSIGNER_JAR) and check_bin(KEYSTORE_PATH)):
        err = "apksigner.jar o keystore no configurados"
        log_event("sign", ok=False, sessionId=sid, filename=meta.get("originalName", ""), error=err)
        return jsonify({"ok": False, "error": err}), 500

    args = [
        "java", "-jar", APKSIGNER_JAR,
        "sign",
        "--v1-signing-enabled", "true",
        "--v2-signing-enabled", "true",
        "--ks", KEYSTORE_PATH,
        "--ks-pass", f"pass:{KS_PASS}",
        "--ks-key-alias", KEY_ALIAS,
        "--key-pass", f"pass:{KEY_PASS}",
        "--in", str(in_path),
        "--out", str(out_path),
    ]

    t0 = time.time()
    rc, out, err = run_cmd(args, timeout=120)
    dt_ms = int((time.time() - t0) * 1000)

    if rc != 0:
        msg = (err or out or f"Fallo firmando (rc={rc})").strip()
        log_event("sign", ok=False, sessionId=sid, filename=meta.get("originalName", ""), ms=dt_ms, error=msg)
        return jsonify({"ok": False, "error": msg, "stdout": out, "stderr": err}), 200

    # apksigner suele no imprimir nada en OK
    meta["signedPath"] = str(out_path)
    meta["signedName"] = signed_name
    meta["signedOk"] = True
    meta["verifiedOk"] = False
    save_session_meta(sid, meta)

    log_event("sign", ok=True, sessionId=sid, filename=meta.get("originalName", ""), ms=dt_ms, signedName=signed_name)

    return jsonify({
        "ok": True,
        "message": "Firma correcta",
        "sessionId": sid,
        "signedName": signed_name,
        "stdout": out,
        "stderr": err
    }), 200

@app.post("/verify")
def verify_ep():
    payload = request.get_json(force=True, silent=True) or {}
    sid = str(payload.get("sessionId", "")).strip()
    if not sid:
        return jsonify({"ok": False, "error": "Falta sessionId"}), 400

    try:
        meta = load_session_meta(sid)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 404

    if not meta.get("signedOk"):
        return jsonify({"ok": False, "error": "No hay APK firmado aún"}), 400

    signed_path = Path(meta.get("signedPath", ""))
    if not signed_path.exists():
        return jsonify({"ok": False, "error": "APK firmado no existe"}), 404

    if not check_bin(APKSIGNER_JAR):
        return jsonify({"ok": False, "error": "apksigner.jar no configurado"}), 500

    args = [
        "java", "-jar", APKSIGNER_JAR,
        "verify", "--verbose", "--print-certs",
        str(signed_path),
    ]

    t0 = time.time()
    rc, out, err = run_cmd(args, timeout=120)
    dt_ms = int((time.time() - t0) * 1000)

    if rc != 0:
        msg = (err or out or f"Verificación fallida (rc={rc})").strip()
        meta["verifiedOk"] = False
        save_session_meta(sid, meta)
        log_event("verify", ok=False, sessionId=sid, filename=meta.get("signedName", ""), ms=dt_ms, error=msg)
        return jsonify({"ok": False, "error": msg, "stdout": out, "stderr": err}), 200

    meta["verifiedOk"] = True
    save_session_meta(sid, meta)
    log_event("verify", ok=True, sessionId=sid, filename=meta.get("signedName", ""), ms=dt_ms)

    return jsonify({"ok": True, "message": "Verificación correcta", "stdout": out, "stderr": err}), 200

@app.get("/download/<sid>")
def download_ep(sid: str):
    sid = (sid or "").strip()
    try:
        meta = load_session_meta(sid)
    except Exception:
        abort(404)

    # según lo acordado: habilitar tras firma correcta (no hace falta verify)
    if not meta.get("signedOk"):
        abort(403)

    signed_path = Path(meta.get("signedPath", ""))
    if not signed_path.exists():
        abort(404)

    log_event("download", ok=True, sessionId=sid, filename=meta.get("signedName", ""))
    return send_file(
        signed_path,
        as_attachment=True,
        download_name=meta.get("signedName", "signed.apk"),
        mimetype="application/vnd.android.package-archive",
        max_age=0,
        conditional=True,
    )

@app.get("/logs/data")
def logs_data():
    # Devuelve las últimas N líneas parseadas, con integridad “user-friendly”
    limit = request.args.get("limit", "").strip()
    try:
        n = int(limit) if limit else 200
    except Exception:
        n = 200
    n = max(1, min(n, LOG_MAX_LINES))

    events: List[Dict[str, Any]] = []
    if LOG_FILE.exists():
        try:
            lines = LOG_FILE.read_text(encoding="utf-8", errors="replace").splitlines()
            for line in lines[-n:]:
                line = line.strip()
                if not line:
                    continue
                try:
                    evt = json.loads(line)
                    integrity, okv = verify_event_mac(evt)
                    evt["_integrity"] = integrity
                    evt["_integrity_ok"] = okv
                    events.append(evt)
                except Exception:
                    continue
        except Exception:
            pass

    return jsonify({"ok": True, "events": events, "count": len(events)}), 200

# ----------------------------
# Main
# ----------------------------
if __name__ == "__main__":
    # Dev mode
    safe_mkdir(WORK_DIR / "sessions")
    safe_mkdir(LOG_DIR)
    if not LOG_FILE.exists():
        LOG_FILE.touch()
    app.run(host="0.0.0.0", port=8001, debug=False)
