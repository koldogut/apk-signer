#!/usr/bin/env python3
import base64
import hashlib
import json
import os
import secrets
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

import qrcode

BASE_DIR = Path(__file__).resolve().parents[1]
SECRETS_PATH = BASE_DIR / "secrets.json"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_secrets():
    if not SECRETS_PATH.exists():
        raise SystemExit(f"No existe {SECRETS_PATH}. Ejecuta setup.sh primero.")
    return json.loads(SECRETS_PATH.read_text(encoding="utf-8"))


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def build_otpauth_uri(label: str, secret: str, issuer: str = "APK Signer") -> str:
    label_enc = quote(label.strip().replace(" ", ""))
    issuer_enc = quote(issuer.strip())
    return f"otpauth://totp/{label_enc}?secret={secret}&issuer={issuer_enc}"


def print_qr_terminal(otpauth: str) -> None:
    qrencode = shutil.which("qrencode")
    if qrencode:
        try:
            subprocess.run([qrencode, "-t", "ANSIUTF8", otpauth], check=True)
            return
        except Exception:
            pass

    qr = qrcode.QRCode(border=1)
    qr.add_data(otpauth)
    qr.make(fit=True)
    matrix = qr.get_matrix()
    black = "██"
    white = "  "
    print("")
    for row in matrix:
        print("".join(black if cell else white for cell in row))
    print("")


def main() -> None:
    sec = load_secrets()
    users_path = Path(sec.get("USERS_PATH", str(BASE_DIR / "users.json")))

    if users_path.exists():
        print(f"[apk-signer] users.json ya existe en {users_path}. No se modifica.")
        return

    users_path.parent.mkdir(parents=True, exist_ok=True)

    admin_token = secrets.token_urlsafe(24)
    admin_secret = base64.b32encode(os.urandom(20)).decode("ascii").strip("=").upper()

    data = {
        "users": [
            {
                "id": "admin",
                "name": "Administrador",
                "role": "admin",
                "token_hash": hash_token(admin_token),
                "totp_secret": admin_secret,
                "createdAt": utc_now_iso(),
            }
        ]
    }

    users_path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.chmod(users_path, 0o600)

    otpauth = build_otpauth_uri("Administrador", admin_secret)
    img = qrcode.make(otpauth)
    qr_path = users_path.parent / "admin-qr.png"
    img.save(qr_path)
    os.chmod(qr_path, 0o600)

    print("[apk-signer] Usuario administrador creado.")
    print(f"[apk-signer] Token admin: {admin_token}")
    print(f"[apk-signer] MFA secret: {admin_secret}")
    print(f"[apk-signer] QR admin: {qr_path}")
    print(f"[apk-signer] OTPAUTH: {otpauth}")
    print("[apk-signer] Escanea este QR con Google Authenticator:")
    print_qr_terminal(otpauth)


if __name__ == "__main__":
    main()
