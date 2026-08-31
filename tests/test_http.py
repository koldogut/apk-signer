"""Cabeceras, manejo de errores y confianza en el proxy."""
import io


class TestCabeceras:
    def test_los_estaticos_son_cacheables(self, client):
        r = client.get("/static/css/app.css")
        assert r.headers["Cache-Control"] == "public, max-age=600"

    def test_el_resto_no_se_cachea(self, client):
        assert client.get("/").headers["Cache-Control"] == "no-store"
        assert client.get("/healthz").headers["Cache-Control"] == "no-store"

    def test_el_apk_firmado_no_se_cachea(self, client, login):
        headers = login()
        sid = client.post("/inspect",
                          data={"apk": (io.BytesIO(b"PK\x03\x04x"), "a.apk")},
                          content_type="multipart/form-data").get_json()["sessionId"]
        client.post("/sign", json={"sessionId": sid}, headers=headers)
        r = client.post("/download", json={"sessionId": sid}, headers=headers)
        assert r.headers["Cache-Control"] == "no-store"

    def test_la_traza_no_se_cachea(self, client, login):
        r = client.post("/logs/data", json={}, headers=login())
        assert r.headers["Cache-Control"] == "no-store"

    def test_cabeceras_de_seguridad(self, client):
        h = client.get("/").headers
        assert h["X-Content-Type-Options"] == "nosniff"
        assert h["X-Frame-Options"] == "DENY"
        assert h["Referrer-Policy"] == "no-referrer"
        assert "max-age=31536000" in h["Strict-Transport-Security"]

    def test_la_csp_no_permite_inline(self, client):
        csp = client.get("/").headers["Content-Security-Policy"]
        assert "script-src 'self'" in csp
        assert "unsafe-inline" not in csp
        assert "frame-ancestors 'none'" in csp
        assert "object-src 'none'" in csp


class TestErrores:
    def test_404_en_json(self, client):
        r = client.get("/ruta/inexistente")
        assert r.status_code == 404
        assert r.is_json and r.get_json()["ok"] is False

    def test_405_en_json(self, client):
        r = client.get("/logs/data")
        assert r.status_code == 405 and r.is_json

    def test_413_en_json_con_el_limite(self, client, A):
        r = client.post("/inspect", data=b"x" * (A.MAX_CONTENT_LENGTH + 1024),
                        content_type="application/octet-stream")
        assert r.status_code == 413 and r.is_json
        assert "MB" in r.get_json()["error"]

    def test_un_json_malformado_no_rompe(self, client, login):
        r = client.post("/sign", data="{{no es json", content_type="application/json",
                        headers=login())
        assert r.status_code == 400 and r.is_json

    def test_el_timeout_de_una_herramienta_devuelve_504(self, client, login, A, monkeypatch):
        import subprocess

        def timeout(*args, **kwargs):
            raise subprocess.TimeoutExpired(cmd="java", timeout=120)

        sid = client.post("/inspect",
                          data={"apk": (io.BytesIO(b"PK\x03\x04x"), "a.apk")},
                          content_type="multipart/form-data").get_json()["sessionId"]
        headers = login()
        monkeypatch.setattr(A, "run_cmd", timeout)
        r = client.post("/sign", json={"sessionId": sid}, headers=headers)
        assert r.status_code == 504 and r.is_json
        assert "tiempo máximo" in r.get_json()["error"]


class TestProxy:
    def test_no_se_lee_x_forwarded_for_a_mano(self, A):
        """Antes cualquiera falsificaba la IP de la traza con una cabecera."""
        with A.app.test_request_context(
                "/", headers={"X-Forwarded-For": "1.2.3.4"},
                environ_base={"REMOTE_ADDR": "127.0.0.1"}):
            assert A.client_ip() == "127.0.0.1"

    def test_proxyfix_esta_montado_con_los_saltos_declarados(self, A):
        from werkzeug.middleware.proxy_fix import ProxyFix
        assert isinstance(A.app.wsgi_app, ProxyFix)
        assert A.app.wsgi_app.x_for == A.TRUSTED_PROXIES

    def test_una_cadena_falsa_de_xff_no_rompe_el_login(self, client):
        r = client.post("/api/auth/login",
                        json={"userToken": "x", "mfaCode": "000000"},
                        headers={"X-Forwarded-For": "9.9.9.9, 8.8.8.8"})
        assert r.status_code in (403, 429)
