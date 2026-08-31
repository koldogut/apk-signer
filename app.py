#!/usr/bin/env python3
"""
Punto de entrada: la aplicacion Flask y sus rutas.

La logica vive en config/audit/auth/signing; aqui solo queda el transporte
HTTP. Se reexporta lo que consumen los tests y las herramientas externas para
que `import app` siga siendo suficiente.
"""
import base64
import json
import os
import secrets
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List

from flask import Flask, jsonify, request, send_file, send_from_directory
from werkzeug.exceptions import HTTPException, RequestEntityTooLarge
from werkzeug.middleware.proxy_fix import ProxyFix

from audit import (  # noqa: F401  (reexportado para tests y herramientas)
    client_ip,
    event_hash,
    log_event,
    verify_event_mac,
    verify_log_chain,
)
from auth import (  # noqa: F401
    AuthLocked,
    _auth_state,
    _hash_token,
    _totp_code,
    build_otpauth_uri,
    find_user_by_token,
    load_users,
    login,
    logout,
    make_qr_data_url,
    require_session,
    save_users,
    verify_totp_counter,
)
# Se reexporta la configuracion entera: los tests y las herramientas del repo
# acceden a ella como `app.<CONSTANTE>`.
from config import (  # noqa: F401
    AAPT_BIN,
    APKSIGNER_JAR,
    AUTH_LOCKOUT_MINUTES,
    AUTH_STATE_PATH,
    AUTH_TTL_MINUTES,
    HMAC_KEY,
    KEY_ALIAS,
    KEY_PASS,
    KEYSTORE_PATH,
    KS_PASS,
    LOG_DIR,
    LOG_FILE,
    LOG_MAX_LINES,
    MAX_AUTH_FAILURES,
    MAX_CONTENT_LENGTH,
    SECRETS_ERROR,
    SECRETS_MISSING,
    SECRETS_PATH,
    SESSION_TTL_HOURS,
    SYSLOG_ADDRESS,
    TRUSTED_PROXIES,
    USERS_PATH,
    WORK_DIR,
    ZIPALIGN_BIN,
    check_bin,
    safe_mkdir,
    sha256_file,
    utc_now_iso,
)
from signing import (  # noqa: F401
    _signed_filename,
    aapt_exists,
    inspect_apk_with_aapt,
    java_ok,
    load_session_meta,
    new_session_id,
    run_cmd,
    safe_apk_name,
    save_session_meta,
    session_dir,
    valid_sid,
)

app = Flask(__name__, static_folder="static", static_url_path="/static")


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
        "version": "1.8.0",
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

@app.post("/logs/verify")
def logs_verify():
    """
    Verificación completa de la traza: recorre el fichero entero comprobando
    MAC y encadenado. Solo admin: revela el volumen total de actividad.
    """
    payload = request.get_json(force=True, silent=True) or {}
    try:
        _admin_from_request(payload)
    except PermissionError as e:
        return jsonify({"ok": False, "error": str(e)}), 403

    try:
        summary = verify_log_chain()
    except Exception as e:
        return jsonify({"ok": False, "error": f"No se pudo verificar la traza: {e}"}), 500
    return jsonify({"ok": True, "summary": summary}), 200

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
    # Modo desarrollo. En produccion arranca gunicorn desde la unit de systemd.
    # Se escucha solo en loopback por defecto; para probar desde otra maquina,
    # APK_SIGNER_DEV_HOST=0.0.0.0 python app.py
    host = os.environ.get("APK_SIGNER_DEV_HOST", "127.0.0.1")
    app.run(host=host, port=8001, debug=False)
