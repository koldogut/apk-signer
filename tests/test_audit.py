"""Traza de auditoría: MAC por evento, encadenado por hash y detección de manipulación."""
import io
import json


def actividad(client, login, veces=3):
    """Genera eventos reales en la traza."""
    headers = login()
    for _ in range(veces):
        sid = client.post("/inspect",
                          data={"apk": (io.BytesIO(b"PK\x03\x04x"), "a.apk")},
                          content_type="multipart/form-data").get_json()["sessionId"]
        client.post("/sign", json={"sessionId": sid}, headers=headers)
    return headers


def leer(A):
    return [json.loads(linea) for linea in
            A.LOG_FILE.read_text(encoding="utf-8").splitlines() if linea.strip()]


def escribir(A, eventos):
    A.LOG_FILE.write_text(
        "".join(json.dumps(e, ensure_ascii=False) + "\n" for e in eventos),
        encoding="utf-8")


class TestEncadenado:
    def test_cada_evento_apunta_al_anterior(self, client, login, A):
        actividad(client, login)
        eventos = leer(A)
        assert len(eventos) > 2
        assert eventos[0]["prev"] == ""
        assert eventos[0]["seq"] == 1
        for anterior, siguiente in zip(eventos, eventos[1:]):
            assert siguiente["prev"] == A.event_hash(anterior)
            assert siguiente["seq"] == anterior["seq"] + 1

    def test_la_cadena_se_valida_entera(self, client, login, A):
        actividad(client, login)
        resumen = A.verify_log_chain()
        assert resumen["ok"] is True
        assert resumen["chainBad"] == []
        assert resumen["macBad"] == []
        assert resumen["macOk"] == resumen["events"]

    def test_el_mac_detecta_un_evento_modificado(self, client, login, A):
        actividad(client, login)
        eventos = leer(A)
        eventos[1]["userName"] = "Otro"        # se falsea quién firmó
        escribir(A, eventos)
        resumen = A.verify_log_chain()
        assert resumen["ok"] is False
        assert eventos[1]["seq"] in resumen["macBad"]

    def test_la_cadena_detecta_un_evento_borrado(self, client, login, A):
        """Un MAC por línea no ve esto: cada línea que queda sigue siendo válida."""
        actividad(client, login)
        eventos = leer(A)
        del eventos[1]
        escribir(A, eventos)
        resumen = A.verify_log_chain()
        assert resumen["ok"] is False
        assert resumen["chainBad"]
        # Las líneas supervivientes conservan su MAC intacto: lo que delata el
        # borrado es exclusivamente el encadenado.
        assert resumen["macBad"] == []

    def test_la_cadena_detecta_reordenado(self, client, login, A):
        actividad(client, login)
        eventos = leer(A)
        eventos[1], eventos[2] = eventos[2], eventos[1]
        escribir(A, eventos)
        resumen = A.verify_log_chain()
        assert resumen["ok"] is False
        assert resumen["chainBad"]

    def test_senala_la_primera_rotura(self, client, login, A):
        actividad(client, login, veces=4)
        eventos = leer(A)
        del eventos[3]
        escribir(A, eventos)
        resumen = A.verify_log_chain()
        assert resumen["firstProblemSeq"] is not None

    def test_los_eventos_antiguos_sin_cadena_se_marcan(self, A):
        """Compatibilidad con trazas anteriores a esta versión."""
        A.LOG_FILE.write_text(
            json.dumps({"ts": "2026-01-01T00:00:00+00:00", "action": "sign", "ok": True}) + "\n",
            encoding="utf-8")
        resumen = A.verify_log_chain()
        assert resumen["chainBad"][0]["motivo"] == "sin cadena"

    def test_una_linea_ilegible_se_contabiliza(self, client, login, A):
        actividad(client, login)
        with A.LOG_FILE.open("a", encoding="utf-8") as fp:
            fp.write("esto no es json\n")
        resumen = A.verify_log_chain()
        assert resumen["unreadable"] == 1
        assert resumen["ok"] is False


class TestEndpointVerificacion:
    def test_requiere_admin(self, client, login):
        assert client.post("/logs/verify", json={}, headers=login("u001")).status_code == 403

    def test_sin_sesion(self, client):
        assert client.post("/logs/verify", json={}).status_code == 403

    def test_el_admin_obtiene_el_resumen(self, client, login, A):
        headers = login("admin")
        r = client.post("/logs/verify", json={}, headers=headers)
        assert r.status_code == 200
        resumen = r.get_json()["summary"]
        assert resumen["ok"] is True
        assert resumen["hasKey"] is True
        assert resumen["events"] > 0

    def test_el_admin_ve_la_manipulacion(self, client, login, A):
        actividad(client, login)
        headers = login("admin")
        eventos = leer(A)
        eventos[1]["ok"] = False
        escribir(A, eventos)
        resumen = client.post("/logs/verify", json={}, headers=headers).get_json()["summary"]
        assert resumen["ok"] is False


class TestVisualizacion:
    def test_el_usuario_solo_ve_sus_eventos(self, client, login, A):
        actividad(client, login)
        eventos = client.post("/logs/data", json={"limit": 500},
                              headers=login("u002")).get_json()["events"]
        assert all(e.get("userId") == "u002" for e in eventos)

    def test_el_admin_ve_mas_que_un_usuario(self, client, login, A):
        actividad(client, login)
        propios = client.post("/logs/data", json={"limit": 500},
                              headers=login("u002")).get_json()["events"]
        todos = client.post("/logs/data", json={"limit": 500},
                            headers=login("admin")).get_json()["events"]
        assert len(todos) > len(propios)

    def test_cada_evento_llega_con_su_estado_de_integridad(self, client, login):
        eventos = client.post("/logs/data", json={"limit": 50},
                              headers=login("admin")).get_json()["events"]
        assert eventos and all(e["_integrity"] == "OK" for e in eventos)

    def test_se_respeta_el_limite(self, client, login, A):
        actividad(client, login, veces=5)
        eventos = client.post("/logs/data", json={"limit": 3},
                              headers=login("admin")).get_json()["events"]
        assert len(eventos) == 3

    def test_el_limite_esta_acotado(self, client, login, A):
        eventos = client.post("/logs/data", json={"limit": 10 ** 9},
                              headers=login("admin")).get_json()["events"]
        assert len(eventos) <= A.LOG_MAX_LINES


class TestContenido:
    def test_se_registra_quien_firma(self, client, login, A):
        actividad(client, login)
        firmas = [e for e in leer(A) if e["action"] == "sign" and e["ok"]]
        assert firmas and all(e["userId"] == "u001" for e in firmas)

    def test_se_registran_los_login_fallidos(self, client, A, users):
        client.post("/api/auth/login",
                    json={"userToken": users["u001"]["token"], "mfaCode": "000000"})
        fallos = [e for e in leer(A) if e["action"] == "login" and not e["ok"]]
        assert len(fallos) == 1

    def test_la_traza_no_guarda_secretos(self, client, login, A):
        actividad(client, login)
        crudo = A.LOG_FILE.read_text(encoding="utf-8")
        assert A.KS_PASS not in crudo
        assert A.KEY_PASS not in crudo
        for u in A.load_users()["users"]:
            assert u["totp_secret"] not in crudo
