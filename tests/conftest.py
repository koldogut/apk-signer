"""
Fixtures comunes.

La aplicación lee su configuración al importarse, así que el entorno se monta
ANTES del import y se reutiliza durante toda la sesión. Se aprovecha el mismo
mecanismo que usa systemd con LoadCredential=: apuntando CREDENTIALS_DIRECTORY
a un directorio temporal, `app` toma de ahí su secrets.json y no toca el árbol
del repositorio.

Las herramientas externas (java/apksigner, aapt2, zipalign) se sustituyen por
scripts en tests/fakebin, que se anteponen al PATH. Así los tests recorren el
mismo código de subprocess que producción -- incluido el paso de contraseñas
por entorno -- en lugar de parchear run_cmd.
"""
import base64
import importlib
import json
import os
import shutil
import sys
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
FAKEBIN = Path(__file__).resolve().parent / "fakebin"


@pytest.fixture(scope="session")
def env(tmp_path_factory):
    root = tmp_path_factory.mktemp("apk-signer")
    cred_dir = root / "credentials"
    for d in (cred_dir, root / "work" / "sessions", root / "logs", root / "tools"):
        d.mkdir(parents=True, exist_ok=True)

    secrets = {
        "AAPT": str(FAKEBIN / "aapt2"),
        "APKSIGNER_JAR": str(root / "tools" / "apksigner.jar"),
        "ZIPALIGN": str(FAKEBIN / "zipalign"),
        "KEYSTORE_PATH": str(root / "tools" / "KeyStore.jks"),
        "KS_PASS": "clave-del-keystore",
        "KEY_ALIAS": "test_signkey",
        "KEY_PASS": "clave-de-la-key",
        "WORK_DIR": str(root / "work"),
        "LOG_DIR": str(root / "logs"),
        "USERS_PATH": str(root / "users.json"),
        "AUTH_STATE_PATH": str(root / "work" / "auth_state.json"),
        "MAX_CONTENT_LENGTH": 1024 * 1024,
        "SESSION_TTL_HOURS": 24,
        "AUTH_TTL_MINUTES": 15,
        "MAX_AUTH_FAILURES": 5,
        "AUTH_LOCKOUT_MINUTES": 15,
        "TRUSTED_PROXIES": 1,
        "LOG_MAX_LINES": 2000,
        "LOG_HMAC_KEY": "a" * 64,
    }
    (cred_dir / "secrets.json").write_text(json.dumps(secrets), encoding="utf-8")

    # apksigner.jar y el keystore solo tienen que existir: quien los "usa" es
    # el java de mentira.
    (root / "tools" / "apksigner.jar").write_text("fake jar", encoding="utf-8")
    (root / "tools" / "KeyStore.jks").write_text("fake keystore", encoding="utf-8")

    os.environ["CREDENTIALS_DIRECTORY"] = str(cred_dir)
    os.environ["PATH"] = f"{FAKEBIN}{os.pathsep}{os.environ['PATH']}"
    os.environ["FAKE_TOOLS_LOG"] = str(root / "tool-calls.log")

    sys.path.insert(0, str(REPO_ROOT))
    import app as app_module
    importlib.reload(app_module)
    return app_module, root


@pytest.fixture
def A(env):
    """El módulo de la aplicación, con el estado reiniciado en cada test."""
    app_module, root = env
    app_module.AUTH_STATE_PATH.unlink(missing_ok=True)
    app_module.LOG_FILE.unlink(missing_ok=True)
    shutil.rmtree(root / "work" / "sessions", ignore_errors=True)
    (root / "work" / "sessions").mkdir(parents=True, exist_ok=True)
    Path(os.environ["FAKE_TOOLS_LOG"]).unlink(missing_ok=True)
    for var in ("FAKE_ZIPALIGN_FAIL", "FAKE_AAPT_FAIL", "FAKE_VERIFY_FAIL"):
        os.environ.pop(var, None)
    return app_module


@pytest.fixture
def tool_calls():
    """Lo que se ha invocado realmente, para afirmar sobre orden y argumentos."""
    def _read():
        p = Path(os.environ["FAKE_TOOLS_LOG"])
        return p.read_text(encoding="utf-8").splitlines() if p.exists() else []
    return _read


@pytest.fixture
def users(A):
    """Un admin, un firmante y un tercero sin relación con las sesiones."""
    def secret(seed: bytes) -> str:
        return base64.b32encode(seed.ljust(20, b"0")[:20]).decode("ascii").strip("=")

    data = {"users": []}
    creds = {}
    for uid, name, role, seed in (
        ("admin", "Administrador", "admin", b"admin-seed"),
        ("u001", "Firmante", "user", b"firmante-seed"),
        ("u002", "Tercero", "user", b"tercero-seed"),
    ):
        token = f"token-de-{uid}-para-pruebas"
        data["users"].append({
            "id": uid, "name": name, "role": role,
            "token_hash": A._hash_token(token),
            "totp_secret": secret(seed),
            "createdAt": A.utc_now_iso(),
        })
        creds[uid] = {"token": token, "secret": secret(seed)}
    A.save_users(data)
    return creds


@pytest.fixture
def client(A):
    return A.app.test_client()


@pytest.fixture
def login(client, A, users):
    """Canjea token+MFA y devuelve la cabecera Authorization lista para usar."""
    def _login(uid="u001", offset=0):
        code = A._totp_code(users[uid]["secret"], int(time.time()) + offset * 30)
        r = client.post("/api/auth/login",
                        json={"userToken": users[uid]["token"], "mfaCode": code})
        assert r.status_code == 200, r.get_json()
        return {"Authorization": f"Bearer {r.get_json()['authToken']}"}
    return _login


@pytest.fixture
def apk(A, client):
    """Sube un APK y devuelve el sessionId de la sesión de trabajo."""
    def _apk(name="punto-de-venta.apk", content=b"PK\x03\x04contenido-apk"):
        r = client.post("/inspect", data={"apk": (io_bytes(content), name)},
                        content_type="multipart/form-data")
        assert r.status_code == 200, r.get_json()
        return r.get_json()
    return _apk


def io_bytes(data: bytes):
    import io
    return io.BytesIO(data)

