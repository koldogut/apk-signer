"""
Configuracion del servicio: carga de secretos, rutas y constantes.

Es el modulo base: no importa a ninguno de los otros, para que la cadena de
dependencias sea config -> audit -> auth -> signing -> app y no haya ciclos.
"""
import base64
import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

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

# Envío opcional de la traza a syslog remoto: "host:514" o "/dev/log".
SYSLOG_ADDRESS = str(SEC.get("SYSLOG_ADDRESS", "")).strip()

# Sesión de autenticación: un TOTP se canjea una vez por una sesión corta que
# autoriza firmar, verificar, descargar y consultar la traza.
AUTH_TTL_MINUTES = int(SEC.get("AUTH_TTL_MINUTES", 15))
MAX_AUTH_FAILURES = int(SEC.get("MAX_AUTH_FAILURES", 5))
AUTH_LOCKOUT_MINUTES = int(SEC.get("AUTH_LOCKOUT_MINUTES", 15))

# Nº de proxies de confianza delante de la app (nginx = 1). Con 0 se ignora
# por completo X-Forwarded-For.
TRUSTED_PROXIES = int(SEC.get("TRUSTED_PROXIES", 1))

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
