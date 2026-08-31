#!/usr/bin/env python3
import base64
import fcntl
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import shutil
import subprocess
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple
from urllib.parse import quote

import qrcode
from flask import Flask, jsonify, request, send_from_directory, send_file
from werkzeug.exceptions import HTTPException, RequestEntityTooLarge
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent

def _resolve_secrets_path() -> Path:
    """
    Si systemd inyecta el secreto con LoadCredential=, viene en
    $CREDENTIALS_DIRECTORY y el fichero nunca toca el árbol de la aplicación.
    Si no, se usa el secrets.json de siempre junto a app.py.
    """
    cred_dir = os.environ.get("CREDENTIALS_DIRECTORY", "").strip()
    if cred_dir:
        candidate = Path(cred_dir) / "secrets.json"
        if candidate.exists():
            return candidate
    return BASE_DIR / "secrets.json"

SECRETS_PATH = _resolve_secrets_path()
SECRETS_MISSING = False
SECRETS_ERROR: Optional[str] = None

app = Flask(__name__, static_folder="static", static_url_path="/static")

# ----------------------------
# Config / secrets
# ----------------------------
def _load_secrets() -> Dict[str, Any]:
    global SECRETS_MISSING, SECRETS_ERROR
    if not SECRETS_PATH.exists():
        SECRETS_MISSING = True
        SECRETS_ERROR = f"No existe {SECRETS_PATH}. Crea secrets.json a partir de secrets.example.json"
        return {}
    try:
        return json.loads(SECRETS_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        SECRETS_ERROR = f"secrets.json inválido: {e}"
        return {}

SEC = _load_secrets()

AAPT_BIN = str(SEC.get("AAPT", "")).strip()  # ruta absoluta a aapt2 o aapt
APKSIGNER_JAR = str(SEC.get("APKSIGNER_JAR", "")).strip()
ZIPALIGN_BIN = str(SEC.get("ZIPALIGN", "")).strip()
KEYSTORE_PATH = str(SEC.get("KEYSTORE_PATH", "")).strip()
KS_PASS = str(SEC.get("KS_PASS", "")).strip()
KEY_ALIAS = str(SEC.get("KEY_ALIAS", "")).strip()
KEY_PASS = str(SEC.get("KEY_PASS", "")).strip()

WORK_DIR = Path(str(SEC.get("WORK_DIR", str(BASE_DIR / "work"))))
LOG_DIR = Path(str(SEC.get("LOG_DIR", str(BASE_DIR / "logs"))))
USERS_PATH = Path(str(SEC.get("USERS_PATH", str(BASE_DIR / "users.json"))))
AUTH_STATE_PATH = Path(str(SEC.get("AUTH_STATE_PATH", str(WORK_DIR / "auth_state.json"))))
MAX_CONTENT_LENGTH = int(SEC.get("MAX_CONTENT_LENGTH", 100 * 1024 * 1024))  # 100MB default
SESSION_TTL_HOURS = int(SEC.get("SESSION_TTL_HOURS", 24))
LOG_MAX_LINES = int(SEC.get("LOG_MAX_LINES", 2000))

# Sesión de autenticación: un TOTP se canjea una vez por una sesión corta que
# autoriza firmar, verificar, descargar y consultar la traza.
AUTH_TTL_MINUTES = int(SEC.get("AUTH_TTL_MINUTES", 15))
MAX_AUTH_FAILURES = int(SEC.get("MAX_AUTH_FAILURES", 5))
AUTH_LOCKOUT_MINUTES = int(SEC.get("AUTH_LOCKOUT_MINUTES", 15))

# Nº de proxies de confianza delante de la app (nginx = 1). Con 0 se ignora
# por completo X-Forwarded-For.
TRUSTED_PROXIES = int(SEC.get("TRUSTED_PROXIES", 1))

app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH

if TRUSTED_PROXIES > 0:
    # Sin esto, cualquiera falsifica la IP de la traza con una cabecera
    # X-Forwarded-For. ProxyFix solo confía en los N saltos declarados.
    app.wsgi_app = ProxyFix(
        app.wsgi_app,
        x_for=TRUSTED_PROXIES,
        x_proto=TRUSTED_PROXIES,
        x_host=0,
        x_prefix=0,
    )

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

def run_cmd(args: List[str], timeout: int = 60, env: Optional[Dict[str, str]] = None) -> Tuple[int, str, str]:
    # env se fusiona con el entorno del proceso; se usa para pasar secretos
    # (contraseñas de keystore) sin exponerlos en la línea de comandos.
    run_env = {**os.environ, **env} if env else None
    p = subprocess.run(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
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

def client_ip() -> str:
    # remote_addr ya viene corregido por ProxyFix cuando TRUSTED_PROXIES > 0.
    # Nunca se lee X-Forwarded-For a mano: era falsificable por cualquiera.
    return request.remote_addr or ""

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

def _base32_decode(secret: str) -> bytes:
    cleaned = re.sub(r"\s+", "", secret or "").upper()
    padding = "=" * ((8 - len(cleaned) % 8) % 8)
    return base64.b32decode(cleaned + padding)

def _totp_code(secret: str, for_time: Optional[int] = None, step: int = 30, digits: int = 6) -> str:
    key = _base32_decode(secret)
    counter = int((for_time or int(time.time())) / step)
    counter_bytes = counter.to_bytes(8, "big")
    digest = hmac.new(key, counter_bytes, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = (
        ((digest[offset] & 0x7F) << 24)
        | ((digest[offset + 1] & 0xFF) << 16)
        | ((digest[offset + 2] & 0xFF) << 8)
        | (digest[offset + 3] & 0xFF)
    )
    return str(binary % (10 ** digits)).zfill(digits)

def verify_totp_counter(secret: str, code: str, step: int = 30, digits: int = 6, skew: int = 2) -> Optional[int]:
    """
    Devuelve el contador TOTP con el que casa el código, o None si no es válido.
    El contador es lo que permite detectar la reutilización de un código.
    """
    code = str(code or "").strip()
    if not re.fullmatch(rf"\d{{{digits}}}", code):
        return None
    now = int(time.time())
    try:
        for offset in range(-skew, skew + 1):
            at = now + offset * step
            if hmac.compare_digest(code, _totp_code(secret, at, step=step, digits=digits)):
                return int(at / step)
    except Exception:
        return None
    return None

# ----------------------------
# Estado de autenticación (sesiones, anti-replay y bloqueo por intentos)
#
# Vive en un fichero con bloqueo exclusivo (flock) porque gunicorn arranca
# varios workers: un contador en memoria daría un límite por worker y el
# anti-replay no vería los códigos consumidos por el proceso vecino.
# ----------------------------
@contextmanager
def _auth_state() -> Iterator[Dict[str, Any]]:
    """
    Abre el estado de autenticación con bloqueo exclusivo y lo persiste al salir.

    IMPORTANTE: la escritura va en un `finally`, así que el estado se guarda
    TAMBIÉN cuando el bloque lanza una excepción. Es deliberado: los intentos
    fallidos se registran y acto seguido se lanza PermissionError, y si la
    escritura dependiera de una salida limpia el contador de fallos no se
    guardaría nunca y el bloqueo por intentos no llegaría a activarse.
    """
    safe_mkdir(AUTH_STATE_PATH.parent)
    fd = os.open(str(AUTH_STATE_PATH), os.O_RDWR | os.O_CREAT, 0o600)
    with os.fdopen(fd, "r+", encoding="utf-8") as fp:
        fcntl.flock(fp.fileno(), fcntl.LOCK_EX)
        try:
            raw = fp.read()
            try:
                state = json.loads(raw) if raw.strip() else {}
            except json.JSONDecodeError:
                state = {}
            if not isinstance(state, dict):
                state = {}
            state.setdefault("sessions", {})
            state.setdefault("totp", {})
            state.setdefault("failures", {})

            try:
                yield state
            finally:
                _prune_auth_state(state)
                fp.seek(0)
                fp.truncate()
                fp.write(json.dumps(state, ensure_ascii=False))
                fp.flush()
                os.fsync(fp.fileno())
        finally:
            fcntl.flock(fp.fileno(), fcntl.LOCK_UN)

def _prune_auth_state(state: Dict[str, Any]) -> None:
    now = datetime.now(timezone.utc)
    sessions = state.get("sessions", {})
    for key in [k for k, v in sessions.items() if _parse_iso(v.get("expiresAt")) <= now]:
        sessions.pop(key, None)
    failures = state.get("failures", {})
    for key in [k for k, v in failures.items() if _parse_iso(v.get("resetAt")) <= now]:
        failures.pop(key, None)

def _parse_iso(value: Any) -> datetime:
    try:
        return datetime.fromisoformat(str(value))
    except Exception:
        return datetime.min.replace(tzinfo=timezone.utc)

def _lock_remaining(entry: Dict[str, Any]) -> int:
    """Segundos que quedan de bloqueo, 0 si no está bloqueado."""
    if int(entry.get("count", 0)) < MAX_AUTH_FAILURES:
        return 0
    delta = _parse_iso(entry.get("resetAt")) - datetime.now(timezone.utc)
    return max(0, int(delta.total_seconds()))

def _register_failure(state: Dict[str, Any], key: str) -> None:
    failures = state.setdefault("failures", {})
    entry = failures.get(key) or {}
    now = datetime.now(timezone.utc)
    if _parse_iso(entry.get("resetAt")) <= now:
        entry = {"count": 0}
    entry["count"] = int(entry.get("count", 0)) + 1
    entry["resetAt"] = (now + timedelta(minutes=AUTH_LOCKOUT_MINUTES)).isoformat()
    failures[key] = entry

def _new_auth_session(state: Dict[str, Any], user: Dict[str, Any]) -> Tuple[str, str]:
    token = secrets.token_urlsafe(32)
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=AUTH_TTL_MINUTES)).isoformat()
    state.setdefault("sessions", {})[_hash_token(token)] = {
        "userId": user.get("id", ""),
        "name": user.get("name", ""),
        "role": user.get("role", ""),
        "createdAt": utc_now_iso(),
        "expiresAt": expires_at,
    }
    return token, expires_at

def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()

def load_users() -> Dict[str, Any]:
    if not USERS_PATH.exists():
        raise RuntimeError("No existe users.json. Ejecuta el bootstrap de usuarios.")
    try:
        data = json.loads(USERS_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise RuntimeError(f"users.json inválido: {e}")
    if "users" not in data or not isinstance(data["users"], list):
        raise RuntimeError("users.json inválido: falta lista de usuarios")
    return data

def save_users(data: Dict[str, Any]) -> None:
    tmp = USERS_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    tmp.replace(USERS_PATH)

def find_user_by_token(token: str) -> Optional[Dict[str, Any]]:
    token = token.strip()
    if not token:
        return None
    token_hash = _hash_token(token)
    data = load_users()
    for user in data.get("users", []):
        if hmac.compare_digest(str(user.get("token_hash", "")), token_hash):
            return user
    return None

class AuthLocked(PermissionError):
    """Demasiados intentos fallidos: bloqueo temporal."""
    def __init__(self, seconds: int):
        self.seconds = seconds
        minutes = max(1, (seconds + 59) // 60)
        super().__init__(f"Demasiados intentos fallidos. Reintenta en {minutes} min.")

def login(user_token: str, mfa_code: str) -> Tuple[str, str, Dict[str, Any]]:
    """
    Canjea token + MFA por una sesión corta. Devuelve (authToken, expiresAt, user).

    Aplica, bajo un único bloqueo de fichero:
      - bloqueo temporal tras MAX_AUTH_FAILURES intentos,
      - anti-replay: un contador TOTP no se acepta dos veces.
    """
    try:
        user = find_user_by_token(user_token)
    except Exception as e:
        raise PermissionError(str(e))

    # Un token desconocido no identifica a nadie: se contabiliza por IP para
    # que adivinar tokens también acabe bloqueado.
    fail_key = f"user:{user['id']}" if user else f"ip:{client_ip()}"

    with _auth_state() as state:
        entry = state.get("failures", {}).get(fail_key) or {}
        remaining = _lock_remaining(entry)
        if remaining > 0:
            raise AuthLocked(remaining)

        if not user:
            _register_failure(state, fail_key)
            raise PermissionError("Credenciales inválidas")

        counter = verify_totp_counter(str(user.get("totp_secret", "")), mfa_code)
        if counter is None:
            _register_failure(state, fail_key)
            raise PermissionError("Credenciales inválidas")

        user_id = str(user.get("id", ""))
        last_counter = int(state.get("totp", {}).get(user_id, -1))
        if counter <= last_counter:
            # Código ya canjeado: no se cuenta como fallo (no es un intento de
            # adivinar), pero tampoco se acepta.
            raise PermissionError("Ese código MFA ya se ha usado. Espera al siguiente.")

        state.setdefault("totp", {})[user_id] = counter
        state.get("failures", {}).pop(fail_key, None)
        auth_token, expires_at = _new_auth_session(state, user)

    return auth_token, expires_at, user

def require_session(auth_token: str) -> Dict[str, Any]:
    """
    Valida una sesión emitida por login(). Devuelve {id, name, role}.
    """
    auth_token = (auth_token or "").strip()
    if not auth_token:
        raise PermissionError("Sesión requerida")

    with _auth_state() as state:
        sess = state.get("sessions", {}).get(_hash_token(auth_token))
        if not sess:
            raise PermissionError("Sesión inválida o caducada")
        if _parse_iso(sess.get("expiresAt")) <= datetime.now(timezone.utc):
            state["sessions"].pop(_hash_token(auth_token), None)
            raise PermissionError("Sesión inválida o caducada")
        return {
            "id": sess.get("userId", ""),
            "name": sess.get("name", ""),
            "role": sess.get("role", ""),
        }

def logout(auth_token: str) -> None:
    auth_token = (auth_token or "").strip()
    if not auth_token:
        return
    with _auth_state() as state:
        state.get("sessions", {}).pop(_hash_token(auth_token), None)

def build_otpauth_uri(label: str, secret: str, issuer: str = "APK Signer") -> str:
    label_enc = quote(label.strip().replace(" ", ""))
    issuer_enc = quote(issuer.strip())
    return f"otpauth://totp/{label_enc}?secret={secret}&issuer={issuer_enc}"

def make_qr_data_url(otpauth: str) -> str:
    img = qrcode.make(otpauth)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    encoded = base64.b64encode(buf.getvalue()).decode("ascii")
    return f"data:image/png;base64,{encoded}"

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
    # Solo los assets estáticos son cacheables. El resto (APK firmado, logs,
    # listados de usuarios) no debe quedar en caché de navegador ni de proxy.
    if request.path.startswith("/static/"):
        resp.headers["Cache-Control"] = "public, max-age=600"
    else:
        resp.headers["Cache-Control"] = "no-store"
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

@app.get("/admin")
def admin_page():
    return send_from_directory(app.static_folder, "admin.html")

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
        "zipalign_configured": bool(ZIPALIGN_BIN),
        "zipalign_exists": check_bin(ZIPALIGN_BIN),
        "keystore_exists": check_bin(KEYSTORE_PATH),
        "secrets_exists": SECRETS_PATH.exists(),
        "secrets_error": SECRETS_ERROR or "",
        "users_exists": USERS_PATH.exists(),
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

    return jsonify({
        "ok": True,
        "checks": checks,
        "auth": {
            "sessionTtlMinutes": AUTH_TTL_MINUTES,
            "maxFailures": MAX_AUTH_FAILURES,
            "lockoutMinutes": AUTH_LOCKOUT_MINUTES,
            "trustedProxies": TRUSTED_PROXIES,
        },
        "now": utc_now_iso(),
        "version": "1.7.0",
    })

# ----------------------------
# Errores: siempre JSON, nunca la página HTML de Werkzeug
# ----------------------------
@app.errorhandler(RequestEntityTooLarge)
def _err_too_large(e):
    mb = MAX_CONTENT_LENGTH / (1024 * 1024)
    return jsonify({"ok": False, "error": f"El fichero supera el límite de {mb:.0f} MB"}), 413

@app.errorhandler(HTTPException)
def _err_http(e):
    return jsonify({"ok": False, "error": e.description, "status": e.code}), e.code

@app.errorhandler(subprocess.TimeoutExpired)
def _err_timeout(e):
    log_event("error", ok=False, path=request.path, error=f"timeout: {e}")
    return jsonify({"ok": False, "error": "La operación superó el tiempo máximo"}), 504

@app.errorhandler(Exception)
def _err_unhandled(e):
    log_event("error", ok=False, path=request.path, error=repr(e))
    return jsonify({"ok": False, "error": "Error interno del servicio"}), 500

# ----------------------------
# Autenticación
# ----------------------------
@app.post("/api/auth/login")
def auth_login():
    payload = request.get_json(force=True, silent=True) or {}
    user_token = str(payload.get("userToken", "")).strip()
    mfa_code = str(payload.get("mfaCode", "")).strip()

    if not user_token or not mfa_code:
        return jsonify({"ok": False, "error": "Faltan token y código MFA"}), 400

    try:
        auth_token, expires_at, user = login(user_token, mfa_code)
    except AuthLocked as e:
        log_event("login", ok=False, error=str(e))
        return jsonify({"ok": False, "error": str(e), "lockedSeconds": e.seconds}), 429
    except PermissionError as e:
        log_event("login", ok=False, error=str(e))
        return jsonify({"ok": False, "error": str(e)}), 403

    log_event("login", ok=True, userId=user.get("id", ""), userName=user.get("name", ""))
    return jsonify({
        "ok": True,
        "authToken": auth_token,
        "expiresAt": expires_at,
        "user": {"id": user.get("id", ""), "name": user.get("name", ""), "role": user.get("role", "")},
    }), 200

@app.post("/api/auth/logout")
def auth_logout():
    payload = request.get_json(force=True, silent=True) or {}
    logout(str(payload.get("authToken", "")).strip())
    return jsonify({"ok": True}), 200

def _session_from_request(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Acepta la sesión en la cabecera Authorization: Bearer <token> o en el
    cuerpo JSON. Lanza PermissionError si no es válida.
    """
    header = request.headers.get("Authorization", "")
    token = header[7:].strip() if header.lower().startswith("bearer ") else ""
    return require_session(token or str(payload.get("authToken", "")).strip())

def _admin_from_request(payload: Dict[str, Any]) -> Dict[str, Any]:
    user = _session_from_request(payload)
    if user.get("role") != "admin":
        raise PermissionError("Se requiere rol de administrador")
    return user

@app.post("/inspect")
def inspect_ep():
    t0 = time.time()
    if "apk" not in request.files:
        return jsonify({"ok": False, "error": "Falta fichero (campo 'apk')"}), 400

    f = request.files["apk"]
    raw_name = (f.filename or "input.apk").strip()
    if not raw_name.lower().endswith(".apk"):
        return jsonify({"ok": False, "error": "El fichero debe ser .apk"}), 400

    # A partir de aquí solo se usa el nombre saneado: es el que acabará
    # formando la ruta del APK firmado.
    original_name = safe_apk_name(raw_name, fallback="input.apk")

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
    base = safe_apk_name(original_name)
    if base.lower().endswith(".apk"):
        base = base[:-4]
    return f"{base}_signed.apk"

@app.post("/sign")
def sign_ep():
    payload = request.get_json(force=True, silent=True) or {}
    sid = str(payload.get("sessionId", "")).strip()

    if not sid:
        return jsonify({"ok": False, "error": "Falta sessionId"}), 400
    if not valid_sid(sid):
        return jsonify({"ok": False, "error": "sessionId inválido"}), 400
    if SECRETS_ERROR or SECRETS_MISSING:
        return jsonify({"ok": False, "error": "Falta configurar secrets.json"}), 503

    try:
        user = _session_from_request(payload)
    except PermissionError as e:
        log_event("sign", ok=False, sessionId=sid, error=str(e))
        return jsonify({"ok": False, "error": str(e)}), 403

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
        log_event(
            "sign",
            ok=False,
            sessionId=sid,
            filename=meta.get("originalName", ""),
            error=err,
            userId=user.get("id", ""),
            userName=user.get("name", ""),
        )
        return jsonify({"ok": False, "error": err}), 500

    # zipalign ANTES de firmar: apksigner preserva el alineado, pero alinear
    # después invalidaría la firma. Sin alinear, los recursos sin comprimir no
    # se pueden mapear en memoria en el dispositivo.
    sign_input = in_path
    align_warning = ""
    if check_bin(ZIPALIGN_BIN):
        aligned_path = session_dir(sid) / "aligned.apk"
        rc_a, out_a, err_a = run_cmd(
            [ZIPALIGN_BIN, "-p", "-f", "4", str(in_path), str(aligned_path)],
            timeout=120,
        )
        if rc_a == 0 and aligned_path.exists():
            sign_input = aligned_path
        else:
            align_warning = (err_a or out_a or f"zipalign falló (rc={rc_a})").strip()
            log_event("zipalign", ok=False, sessionId=sid, error=align_warning,
                      userId=user.get("id", ""), userName=user.get("name", ""))
    else:
        align_warning = "zipalign no configurado: el APK se firma sin alinear"

    # Las contraseñas se pasan por entorno (env:VAR), no por argv: cualquier
    # usuario local vería `pass:<contraseña>` en `ps` durante la firma.
    args = [
        "java", "-jar", APKSIGNER_JAR,
        "sign",
        "--v1-signing-enabled", "true",
        "--v2-signing-enabled", "true",
        "--ks", KEYSTORE_PATH,
        "--ks-pass", "env:APK_SIGNER_KS_PASS",
        "--ks-key-alias", KEY_ALIAS,
        "--key-pass", "env:APK_SIGNER_KEY_PASS",
        "--in", str(sign_input),
        "--out", str(out_path),
    ]
    sign_env = {
        "APK_SIGNER_KS_PASS": KS_PASS,
        "APK_SIGNER_KEY_PASS": KEY_PASS,
    }

    t0 = time.time()
    rc, out, err = run_cmd(args, timeout=120, env=sign_env)
    dt_ms = int((time.time() - t0) * 1000)

    if rc != 0:
        msg = (err or out or f"Fallo firmando (rc={rc})").strip()
        log_event(
            "sign",
            ok=False,
            sessionId=sid,
            filename=meta.get("originalName", ""),
            ms=dt_ms,
            error=msg,
            userId=user.get("id", ""),
            userName=user.get("name", ""),
        )
        return jsonify({"ok": False, "error": msg, "stdout": out, "stderr": err}), 200

    # apksigner suele no imprimir nada en OK
    meta["signedPath"] = str(out_path)
    meta["signedName"] = signed_name
    meta["signedOk"] = True
    meta["verifiedOk"] = False
    meta["signedBy"] = {
        "id": user.get("id", ""),
        "name": user.get("name", ""),
    }
    meta["aligned"] = sign_input != in_path
    save_session_meta(sid, meta)

    log_event(
        "sign",
        ok=True,
        sessionId=sid,
        filename=meta.get("originalName", ""),
        ms=dt_ms,
        signedName=signed_name,
        userId=user.get("id", ""),
        userName=user.get("name", ""),
    )

    return jsonify({
        "ok": True,
        "message": "Firma correcta",
        "sessionId": sid,
        "signedName": signed_name,
        "aligned": meta["aligned"],
        "warning": align_warning,
        "stdout": out,
        "stderr": err
    }), 200

@app.post("/verify")
def verify_ep():
    payload = request.get_json(force=True, silent=True) or {}
    sid = str(payload.get("sessionId", "")).strip()
    if not sid:
        return jsonify({"ok": False, "error": "Falta sessionId"}), 400
    if not valid_sid(sid):
        return jsonify({"ok": False, "error": "sessionId inválido"}), 400

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
    signed_by = meta.get("signedBy") or {}

    t0 = time.time()
    rc, out, err = run_cmd(args, timeout=120)
    dt_ms = int((time.time() - t0) * 1000)

    if rc != 0:
        msg = (err or out or f"Verificación fallida (rc={rc})").strip()
        meta["verifiedOk"] = False
        save_session_meta(sid, meta)
        log_event(
            "verify",
            ok=False,
            sessionId=sid,
            filename=meta.get("signedName", ""),
            ms=dt_ms,
            error=msg,
            userId=signed_by.get("id", ""),
            userName=signed_by.get("name", ""),
        )
        return jsonify({"ok": False, "error": msg, "stdout": out, "stderr": err}), 200

    meta["verifiedOk"] = True
    save_session_meta(sid, meta)
    log_event(
        "verify",
        ok=True,
        sessionId=sid,
        filename=meta.get("signedName", ""),
        ms=dt_ms,
        userId=signed_by.get("id", ""),
        userName=signed_by.get("name", ""),
    )

    return jsonify({"ok": True, "message": "Verificación correcta", "stdout": out, "stderr": err}), 200

@app.post("/download")
def download_ep():
    """
    Descarga del APK firmado. Exige token + MFA y que quien descarga sea quien
    firmó (o un admin): conocer el sessionId ya no basta.
    """
    payload = request.get_json(force=True, silent=True) or {}
    sid = str(payload.get("sessionId", "")).strip()

    if not sid:
        return jsonify({"ok": False, "error": "Falta sessionId"}), 400
    if not valid_sid(sid):
        return jsonify({"ok": False, "error": "sessionId inválido"}), 400

    try:
        user = _session_from_request(payload)
    except PermissionError as e:
        log_event("download", ok=False, sessionId=sid, error=str(e))
        return jsonify({"ok": False, "error": str(e)}), 403

    try:
        meta = load_session_meta(sid)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 404

    # según lo acordado: habilitar tras firma correcta (no hace falta verify)
    if not meta.get("signedOk"):
        return jsonify({"ok": False, "error": "No hay APK firmado aún"}), 403

    signed_by = meta.get("signedBy") or {}
    is_admin = user.get("role") == "admin"
    if not is_admin and str(signed_by.get("id", "")) != str(user.get("id", "")):
        log_event(
            "download",
            ok=False,
            sessionId=sid,
            filename=meta.get("signedName", ""),
            error="Descarga de sesión ajena",
            userId=user.get("id", ""),
            userName=user.get("name", ""),
        )
        return jsonify({"ok": False, "error": "La sesión pertenece a otro usuario"}), 403

    signed_path = Path(meta.get("signedPath", ""))
    if not signed_path.exists():
        return jsonify({"ok": False, "error": "APK firmado no existe"}), 404

    log_event(
        "download",
        ok=True,
        sessionId=sid,
        filename=meta.get("signedName", ""),
        userId=user.get("id", ""),
        userName=user.get("name", ""),
    )
    return send_file(
        signed_path,
        as_attachment=True,
        download_name=meta.get("signedName", "signed.apk"),
        mimetype="application/vnd.android.package-archive",
        max_age=0,
        conditional=True,
    )

@app.post("/api/admin/verify")
def admin_verify():
    payload = request.get_json(force=True, silent=True) or {}

    try:
        admin = _admin_from_request(payload)
    except PermissionError as e:
        return jsonify({"ok": False, "error": str(e)}), 403
    return jsonify({"ok": True, "admin": {"id": admin.get("id", ""), "name": admin.get("name", "")}}), 200

@app.post("/api/admin/users/list")
def admin_users_list():
    payload = request.get_json(force=True, silent=True) or {}

    try:
        _admin_from_request(payload)
    except PermissionError as e:
        return jsonify({"ok": False, "error": str(e)}), 403

    try:
        data = load_users()
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
    users = []
    for user in data.get("users", []):
        users.append({
            "id": user.get("id", ""),
            "name": user.get("name", ""),
            "role": user.get("role", ""),
            "createdAt": user.get("createdAt", ""),
        })
    return jsonify({"ok": True, "users": users}), 200

@app.post("/api/admin/users/create")
def admin_users_create():
    payload = request.get_json(force=True, silent=True) or {}

    name = str(payload.get("name", "")).strip()
    if not name:
        return jsonify({"ok": False, "error": "Nombre requerido"}), 400

    try:
        _admin_from_request(payload)
    except PermissionError as e:
        return jsonify({"ok": False, "error": str(e)}), 403

    try:
        data = load_users()
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
    new_id = secrets.token_hex(4)
    while any(u.get("id") == new_id for u in data.get("users", [])):
        new_id = secrets.token_hex(4)

    token = secrets.token_urlsafe(24)
    secret = base64.b32encode(os.urandom(20)).decode("ascii").strip("=").upper()
    user = {
        "id": new_id,
        "name": name,
        "role": "user",
        "token_hash": _hash_token(token),
        "totp_secret": secret,
        "createdAt": utc_now_iso(),
    }
    data.setdefault("users", []).append(user)
    save_users(data)

    otpauth = build_otpauth_uri(f"{name}", secret)
    qr_data_url = make_qr_data_url(otpauth)

    return jsonify({
        "ok": True,
        "user": {
            "id": new_id,
            "name": name,
            "role": "user",
            "createdAt": user["createdAt"],
        },
        "token": token,
        "secret": secret,
        "otpauth": otpauth,
        "qrDataUrl": qr_data_url,
    }), 200

@app.post("/api/admin/users/delete")
def admin_users_delete():
    payload = request.get_json(force=True, silent=True) or {}

    user_id = str(payload.get("userId", "")).strip()
    if not user_id:
        return jsonify({"ok": False, "error": "userId requerido"}), 400

    try:
        _admin_from_request(payload)
    except PermissionError as e:
        return jsonify({"ok": False, "error": str(e)}), 403

    try:
        data = load_users()
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
    users = data.get("users", [])
    target = next((u for u in users if u.get("id") == user_id), None)
    if not target:
        return jsonify({"ok": False, "error": "Usuario no encontrado"}), 404

    if target.get("role") == "admin":
        admins = [u for u in users if u.get("role") == "admin"]
        if len(admins) <= 1:
            return jsonify({"ok": False, "error": "No se puede borrar el último admin"}), 400

    data["users"] = [u for u in users if u.get("id") != user_id]
    save_users(data)
    return jsonify({"ok": True}), 200

@app.post("/logs/data")
def logs_data():
    """
    Últimos N eventos con su estado de integridad. Requiere token + MFA:
    la traza contiene nombres de artefacto, usuarios, IPs y sessionId.
    Un admin ve todo; un usuario normal solo sus propios eventos.
    """
    payload = request.get_json(force=True, silent=True) or {}

    try:
        user = _session_from_request(payload)
    except PermissionError as e:
        return jsonify({"ok": False, "error": str(e)}), 403

    try:
        n = int(payload.get("limit") or 200)
    except Exception:
        n = 200
    n = max(1, min(n, LOG_MAX_LINES))

    is_admin = user.get("role") == "admin"
    own_id = str(user.get("id", ""))

    events: List[Dict[str, Any]] = []
    if LOG_FILE.exists():
        try:
            lines = LOG_FILE.read_text(encoding="utf-8", errors="replace").splitlines()
            # Se recorre desde el final para quedarse con los N últimos eventos
            # visibles, no con los N últimos del fichero antes de filtrar.
            for line in reversed(lines):
                if len(events) >= n:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    evt = json.loads(line)
                except Exception:
                    continue
                if not is_admin and str(evt.get("userId", "")) != own_id:
                    continue
                integrity, okv = verify_event_mac(evt)
                evt["_integrity"] = integrity
                evt["_integrity_ok"] = okv
                events.append(evt)
            events.reverse()
        except Exception:
            pass

    return jsonify({"ok": True, "events": events, "count": len(events), "scope": "all" if is_admin else "own"}), 200

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
