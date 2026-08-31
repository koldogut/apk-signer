"""Mantenimiento: purga de sesiones y rotación de la traza sin partir la cadena."""
import importlib
import json
import os
import sys
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def cleanup(A):
    sys.path.insert(0, str(REPO_ROOT / "tools"))
    import cleanup as mod
    importlib.reload(mod)
    return mod


class TestPurgaDeSesiones:
    def test_borra_las_sesiones_caducadas(self, cleanup, A):
        vieja = A.session_dir("viejasesion12345")
        vieja.mkdir(parents=True, exist_ok=True)
        (vieja / "input.apk").write_bytes(b"x")
        antiguo = time.time() - (A.SESSION_TTL_HOURS + 1) * 3600
        os.utime(vieja, (antiguo, antiguo))

        cleanup.main()
        assert not vieja.exists()

    def test_respeta_las_sesiones_recientes(self, cleanup, A):
        nueva = A.session_dir("nuevasesion12345")
        nueva.mkdir(parents=True, exist_ok=True)
        (nueva / "input.apk").write_bytes(b"x")

        cleanup.main()
        assert nueva.exists()


class TestRotacion:
    def test_no_rota_por_debajo_del_umbral(self, cleanup, A):
        A.LOG_FILE.write_text('{"seq":1,"prev":"","action":"x"}\n', encoding="utf-8")
        assert cleanup.rotate_log(A.LOG_FILE, None) is False

    def test_rota_y_enlaza_la_cadena(self, cleanup, A, client, login):
        # Traza real y luego se fuerza el tamaño por encima del umbral.
        client.post("/logs/data", json={}, headers=login())
        eventos = [json.loads(linea) for linea in
                   A.LOG_FILE.read_text(encoding="utf-8").splitlines() if linea.strip()]
        ultimo = eventos[-1]

        relleno = " " * cleanup.ROTATE_AT_BYTES
        with A.LOG_FILE.open("a", encoding="utf-8") as fp:
            fp.write(f"{relleno}\n")   # línea en blanco: no altera el último evento

        assert cleanup.rotate_log(A.LOG_FILE, A.HMAC_KEY) is True

        rotados = list(A.LOG_FILE.parent.glob("app.jsonl.*"))
        assert len(rotados) == 1

        ancla = json.loads(A.LOG_FILE.read_text(encoding="utf-8").splitlines()[0])
        assert ancla["action"] == "log-rotated"
        assert ancla["seq"] == ultimo["seq"] + 1
        assert ancla["prev"] == A.event_hash(ultimo)
        assert ancla["rotatedTo"] == rotados[0].name

    def test_el_ancla_lleva_mac_valido(self, cleanup, A, client, login):
        client.post("/logs/data", json={}, headers=login())
        with A.LOG_FILE.open("a", encoding="utf-8") as fp:
            fp.write(" " * cleanup.ROTATE_AT_BYTES + "\n")
        cleanup.rotate_log(A.LOG_FILE, A.HMAC_KEY)

        ancla = json.loads(A.LOG_FILE.read_text(encoding="utf-8").splitlines()[0])
        estado, ok = A.verify_event_mac(ancla)
        assert estado == "OK" and ok is True

    def test_la_traza_sigue_creciendo_encadenada_tras_rotar(self, cleanup, A, client, login):
        client.post("/logs/data", json={}, headers=login())
        with A.LOG_FILE.open("a", encoding="utf-8") as fp:
            fp.write(" " * cleanup.ROTATE_AT_BYTES + "\n")
        cleanup.rotate_log(A.LOG_FILE, A.HMAC_KEY)

        client.post("/logs/data", json={}, headers=login("u002"))
        resumen = A.verify_log_chain()
        assert resumen["ok"] is True, resumen


class TestConfiguracion:
    def test_usa_credentials_directory_como_la_app(self, cleanup):
        """Mismo criterio que la app: si systemd inyecta el secreto, se usa ese."""
        assert cleanup.secrets_path() == Path(os.environ["CREDENTIALS_DIRECTORY"]) / "secrets.json"

    def test_lee_las_rutas_del_secrets(self, cleanup, A):
        sec = cleanup.load_sec()
        assert Path(sec["WORK_DIR"]) == A.WORK_DIR
        assert Path(sec["LOG_DIR"]) == A.LOG_DIR
