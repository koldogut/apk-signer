"""
Autenticacion: TOTP con anti-replay, sesiones cortas y bloqueo por intentos.
"""
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterator, Optional, Tuple
from urllib.parse import quote

import fcntl
import io
import qrcode

from audit import client_ip
from config import (
    AUTH_LOCKOUT_MINUTES,
    AUTH_STATE_PATH,
    AUTH_TTL_MINUTES,
    MAX_AUTH_FAILURES,
    USERS_PATH,
    safe_mkdir,
    utc_now_iso,
)

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
        raise RuntimeError(f"users.json inválido: {e}") from e
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
        raise PermissionError(str(e)) from e

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
