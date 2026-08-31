"""Login, anti-replay, bloqueo por intentos, sesiones y roles."""
import time
from datetime import datetime, timedelta, timezone


def code(A, users, uid, offset=0):
    return A._totp_code(users[uid]["secret"], int(time.time()) + offset * 30)


class TestLogin:
    def test_canjea_token_y_mfa_por_sesion(self, client, A, users):
        r = client.post("/api/auth/login", json={
            "userToken": users["u001"]["token"], "mfaCode": code(A, users, "u001")})
        j = r.get_json()
        assert r.status_code == 200 and j["ok"]
        assert j["authToken"]
        assert j["user"] == {"id": "u001", "name": "Firmante", "role": "user"}

    def test_la_sesion_caduca_segun_configuracion(self, client, A, users):
        r = client.post("/api/auth/login", json={
            "userToken": users["u001"]["token"], "mfaCode": code(A, users, "u001")})
        expires = datetime.fromisoformat(r.get_json()["expiresAt"])
        minutos = (expires - datetime.now(timezone.utc)).total_seconds() / 60
        assert A.AUTH_TTL_MINUTES - 1 < minutos <= A.AUTH_TTL_MINUTES + 0.1

    def test_faltan_credenciales(self, client):
        assert client.post("/api/auth/login", json={}).status_code == 400

    def test_token_desconocido(self, client, A, users):
        r = client.post("/api/auth/login",
                        json={"userToken": "no-existe", "mfaCode": "123456"})
        assert r.status_code == 403

    def test_codigo_incorrecto(self, client, A, users):
        r = client.post("/api/auth/login",
                        json={"userToken": users["u001"]["token"], "mfaCode": "000000"})
        assert r.status_code == 403

    def test_el_error_no_distingue_token_de_codigo(self, client, A, users):
        """No debe revelar si el token existe: mismo mensaje en ambos casos."""
        a = client.post("/api/auth/login",
                        json={"userToken": "no-existe", "mfaCode": "000000"}).get_json()
        b = client.post("/api/auth/login",
                        json={"userToken": users["u001"]["token"],
                              "mfaCode": "000000"}).get_json()
        assert a["error"] == b["error"]


class TestAntiReplay:
    def test_un_codigo_solo_se_canjea_una_vez(self, client, A, users):
        mismo = code(A, users, "u001")
        payload = {"userToken": users["u001"]["token"], "mfaCode": mismo}
        assert client.post("/api/auth/login", json=payload).status_code == 200
        r = client.post("/api/auth/login", json=payload)
        assert r.status_code == 403
        assert "ya se ha usado" in r.get_json()["error"]

    def test_un_codigo_anterior_tampoco_vale(self, client, A, users):
        client.post("/api/auth/login", json={
            "userToken": users["u001"]["token"], "mfaCode": code(A, users, "u001")})
        r = client.post("/api/auth/login", json={
            "userToken": users["u001"]["token"],
            "mfaCode": code(A, users, "u001", offset=-1)})
        assert r.status_code == 403

    def test_el_replay_no_cuenta_como_intento_fallido(self, client, A, users):
        """Reutilizar el propio código es un error de uso, no fuerza bruta."""
        mismo = code(A, users, "u001")
        payload = {"userToken": users["u001"]["token"], "mfaCode": mismo}
        client.post("/api/auth/login", json=payload)
        for _ in range(A.MAX_AUTH_FAILURES + 2):
            assert client.post("/api/auth/login", json=payload).status_code == 403
        with A._auth_state() as st:
            assert "user:u001" not in st["failures"]

    def test_cada_usuario_lleva_su_propio_contador(self, client, A, users):
        client.post("/api/auth/login", json={
            "userToken": users["u001"]["token"], "mfaCode": code(A, users, "u001")})
        r = client.post("/api/auth/login", json={
            "userToken": users["u002"]["token"], "mfaCode": code(A, users, "u002")})
        assert r.status_code == 200


class TestBloqueo:
    def _fallar(self, client, users, veces):
        for _ in range(veces):
            client.post("/api/auth/login", json={
                "userToken": users["u001"]["token"], "mfaCode": "000000"})

    def test_bloquea_tras_el_maximo_de_fallos(self, client, A, users):
        self._fallar(client, users, A.MAX_AUTH_FAILURES)
        r = client.post("/api/auth/login", json={
            "userToken": users["u001"]["token"], "mfaCode": "000000"})
        assert r.status_code == 429
        assert isinstance(r.get_json()["lockedSeconds"], int)

    def test_el_bloqueo_aplica_aunque_el_codigo_sea_correcto(self, client, A, users):
        self._fallar(client, users, A.MAX_AUTH_FAILURES)
        r = client.post("/api/auth/login", json={
            "userToken": users["u001"]["token"], "mfaCode": code(A, users, "u001")})
        assert r.status_code == 429

    def test_un_login_correcto_limpia_el_contador(self, client, A, users):
        self._fallar(client, users, A.MAX_AUTH_FAILURES - 1)
        assert client.post("/api/auth/login", json={
            "userToken": users["u001"]["token"],
            "mfaCode": code(A, users, "u001")}).status_code == 200
        with A._auth_state() as st:
            assert "user:u001" not in st["failures"]

    def test_el_bloqueo_expira(self, client, A, users):
        self._fallar(client, users, A.MAX_AUTH_FAILURES)
        with A._auth_state() as st:
            st["failures"]["user:u001"]["resetAt"] = (
                datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
        r = client.post("/api/auth/login", json={
            "userToken": users["u001"]["token"], "mfaCode": code(A, users, "u001")})
        assert r.status_code == 200

    def test_los_tokens_desconocidos_se_cuentan_por_ip(self, client, A, users):
        for _ in range(A.MAX_AUTH_FAILURES):
            client.post("/api/auth/login",
                        json={"userToken": "inventado", "mfaCode": "000000"})
        with A._auth_state() as st:
            assert any(k.startswith("ip:") for k in st["failures"])


class TestSesion:
    def test_la_sesion_autoriza_los_endpoints(self, client, login):
        assert client.post("/logs/data", json={}, headers=login()).status_code == 200

    def test_sin_sesion(self, client):
        assert client.post("/logs/data", json={}).status_code == 403

    def test_sesion_inventada(self, client):
        r = client.post("/logs/data", json={},
                        headers={"Authorization": "Bearer inventada"})
        assert r.status_code == 403

    def test_la_sesion_vale_tambien_en_el_cuerpo(self, client, login):
        token = login()["Authorization"].split(" ", 1)[1]
        assert client.post("/logs/data", json={"authToken": token}).status_code == 200

    def test_sesion_caducada(self, client, A, login):
        headers = login()
        token = headers["Authorization"].split(" ", 1)[1]
        with A._auth_state() as st:
            st["sessions"][A._hash_token(token)]["expiresAt"] = (
                datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
        assert client.post("/logs/data", json={}, headers=headers).status_code == 403

    def test_logout(self, client, login):
        headers = login()
        token = headers["Authorization"].split(" ", 1)[1]
        client.post("/api/auth/logout", json={"authToken": token})
        assert client.post("/logs/data", json={}, headers=headers).status_code == 403

    def test_logout_de_una_sesion_no_afecta_a_otra(self, client, login):
        primera = login("u001")
        segunda = login("u002")
        token = primera["Authorization"].split(" ", 1)[1]
        client.post("/api/auth/logout", json={"authToken": token})
        assert client.post("/logs/data", json={}, headers=segunda).status_code == 200


class TestRolAdmin:
    ENDPOINTS = ["/api/admin/verify", "/api/admin/users/list"]

    def test_un_usuario_normal_no_pasa(self, client, login):
        # Una sola sesion para todos los endpoints: pedir dos seguidas chocaria
        # con el anti-replay, que solo canjea un codigo TOTP por periodo.
        headers = login("u001")
        for ep in self.ENDPOINTS:
            assert client.post(ep, json={}, headers=headers).status_code == 403

    def test_un_admin_si(self, client, login):
        headers = login("admin")
        for ep in self.ENDPOINTS:
            assert client.post(ep, json={}, headers=headers).status_code == 200

    def test_crear_usuario_requiere_admin(self, client, login):
        r = client.post("/api/admin/users/create", json={"name": "Nuevo"},
                        headers=login("u001"))
        assert r.status_code == 403

    def test_el_admin_crea_usuario_con_token_y_qr(self, client, login):
        r = client.post("/api/admin/users/create", json={"name": "Nuevo"},
                        headers=login("admin"))
        j = r.get_json()
        assert r.status_code == 200 and j["token"] and j["secret"]
        assert j["qrDataUrl"].startswith("data:image/png;base64,")

    def test_no_se_puede_borrar_el_ultimo_admin(self, client, login):
        r = client.post("/api/admin/users/delete", json={"userId": "admin"},
                        headers=login("admin"))
        assert r.status_code in (400, 404)
