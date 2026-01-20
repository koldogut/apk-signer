#!/usr/bin/env python3
import base64
import hashlib
import json
import os
import re
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


def normalize_secret(secret: str) -> str:
    return re.sub(r"\s+", "", secret or "").upper()


def write_qr_assets(otpauth: str, qr_path: Path, otpauth_path: Path) -> None:
    qrencode = shutil.which("qrencode")
    otpauth_path.write_text(f"{otpauth}\n", encoding="utf-8")
    os.chmod(otpauth_path, 0o600)

    if qrencode:
        try:
            subprocess.run([qrencode, "-o", str(qr_path), "-t", "PNG", otpauth], check=True)
            os.chmod(qr_path, 0o600)
            return
        except Exception:
            pass

    img = qrcode.make(otpauth)
    img.save(qr_path)
    os.chmod(qr_path, 0o600)


def main() -> None:
    sec = load_secrets()
    users_path = Path(sec.get("USERS_PATH", str(BASE_DIR / "users.json")))

    if users_path.exists():
        data = json.loads(users_path.read_text(encoding="utf-8"))
        admin = next((u for u in data.get("users", []) if u.get("role") == "admin"), None)
        if not admin:
            raise SystemExit("[apk-signer] users.json existe pero no hay usuario admin.")

        admin_secret = normalize_secret(admin.get("totp_secret", ""))
        if not admin_secret:
            raise SystemExit("[apk-signer] Usuario admin sin totp_secret.")

        otpauth = build_otpauth_uri(admin.get("name", "Administrador"), admin_secret)
        qr_path = users_path.parent / "admin-qr.png"
        otpauth_path = users_path.parent / "admin-otpauth.txt"
        write_qr_assets(otpauth, qr_path, otpauth_path)

        print(f"[apk-signer] users.json ya existe en {users_path}.")
        print("[apk-signer] No se puede recuperar el token admin original.")
        print(f"[apk-signer] QR admin regenerado: {qr_path}")
        print(f"[apk-signer] OTPAUTH guardado en: {otpauth_path}")
        print(f"[apk-signer] OTPAUTH: {otpauth}")
        print("[apk-signer] Escanea este QR con Google Authenticator:")
        print_qr_terminal(otpauth)
        return

    users_path.parent.mkdir(parents=True, exist_ok=True)

    admin_token = secrets.token_urlsafe(24)
    admin_secret = normalize_secret(base64.b32encode(os.urandom(20)).decode("ascii").strip("="))

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
    qr_path = users_path.parent / "admin-qr.png"
    otpauth_path = users_path.parent / "admin-otpauth.txt"
    write_qr_assets(otpauth, qr_path, otpauth_path)

    print("[apk-signer] Usuario administrador creado.")
    print(f"[apk-signer] Token admin: {admin_token}")
    print(f"[apk-signer] MFA secret: {admin_secret}")
    print(f"[apk-signer] QR admin: {qr_path}")
    print(f"[apk-signer] OTPAUTH guardado en: {otpauth_path}")
    print(f"[apk-signer] OTPAUTH: {otpauth}")
    print("[apk-signer] Escanea este QR con Google Authenticator:")
    print_qr_terminal(otpauth)


if __name__ == "__main__":
    main()
