"""Flujo completo inspect -> sign -> verify -> download, y sus caminos de error."""
import io
import os



def subir(client, name="punto-de-venta.apk", content=b"PK\x03\x04apk"):
    return client.post("/inspect",
                       data={"apk": (io.BytesIO(content), name)},
                       content_type="multipart/form-data")


class TestInspect:
    def test_extrae_los_metadatos_del_apk(self, client):
        j = subir(client).get_json()
        info = j["apkInfo"]
        assert j["ok"]
        assert info["packageName"] == "com.example.pos"
        assert info["versionName"] == "3.1.4"
        assert info["versionCode"] == "42"
        assert info["minSdk"] == "24"
        assert info["targetSdk"] == "34"
        assert info["appLabel"] == "Punto de Venta"

    def test_los_permisos_salen_ordenados_y_sin_repetir(self, client):
        perms = subir(client).get_json()["apkInfo"]["permissions"]
        assert perms == sorted(set(perms))
        assert "android.permission.NFC" in perms

    def test_calcula_sha256_y_tamano(self, client):
        import hashlib
        contenido = b"PK\x03\x04contenido-concreto"
        j = subir(client, content=contenido).get_json()
        assert j["sha256"] == hashlib.sha256(contenido).hexdigest()
        assert j["sizeBytes"] == len(contenido)

    def test_rechaza_lo_que_no_sea_apk(self, client):
        r = subir(client, name="documento.pdf")
        assert r.status_code == 400

    def test_sanea_el_nombre_recibido(self, client):
        j = subir(client, name="../../../../tmp/fuera.apk").get_json()
        assert j["originalName"] == "fuera.apk"

    def test_si_aapt_falla_informa_sin_romper(self, client):
        os.environ["FAKE_AAPT_FAIL"] = "1"
        try:
            j = subir(client).get_json()
            assert j["ok"] is False and "ERROR" in j["error"]
        finally:
            os.environ.pop("FAKE_AAPT_FAIL", None)


class TestFirma:
    def test_flujo_completo(self, client, login, A):
        headers = login()
        sid = subir(client).get_json()["sessionId"]

        r = client.post("/sign", json={"sessionId": sid}, headers=headers)
        assert r.status_code == 200 and r.get_json()["ok"]
        assert r.get_json()["signedName"] == "punto-de-venta_signed.apk"

        r = client.post("/verify", json={"sessionId": sid})
        assert r.status_code == 200 and r.get_json()["ok"]
        assert "Verifies" in r.get_json()["stdout"]

        r = client.post("/download", json={"sessionId": sid}, headers=headers)
        assert r.status_code == 200
        assert r.data == b"PK\x03\x04apk"

    def test_zipalign_corre_antes_que_apksigner(self, client, login, tool_calls):
        sid = subir(client).get_json()["sessionId"]
        client.post("/sign", json={"sessionId": sid}, headers=login())
        llamadas = [linea for linea in tool_calls() if linea.startswith(("zipalign", "java -jar"))]
        assert llamadas[0].startswith("zipalign")
        assert llamadas[1].startswith("java -jar")

    def test_zipalign_pide_pagina_de_16kb(self, client, login, tool_calls, A):
        """Android 15+ exige 16 KB; el viejo `-p` solo alinea a 4 KB."""
        sid = subir(client).get_json()["sessionId"]
        r = client.post("/sign", json={"sessionId": sid}, headers=login())
        za = next(linea for linea in tool_calls() if linea.startswith("zipalign "))
        assert "-P 16" in za
        assert " -p " not in za, "-P y -p son excluyentes en zipalign"
        assert za.split()[-3] == "4"
        assert r.get_json()["alignPageKb"] == 16

    def test_con_zipalign_antiguo_cae_a_4kb_y_avisa(self, client, login, tool_calls, A):
        """build-tools 34 no admite -P: hay que degradar, no fallar."""
        os.environ["FAKE_ZIPALIGN_OLD"] = "1"
        import signing
        signing._ZIPALIGN_SUPPORTS_PAGE_SIZE = None
        try:
            sid = subir(client).get_json()["sessionId"]
            j = client.post("/sign", json={"sessionId": sid}, headers=login()).get_json()
            za = next(linea for linea in tool_calls() if linea.startswith("zipalign "))
            assert " -p " in za and "-P" not in za
            assert j["ok"] is True and j["aligned"] is True
            assert j["alignPageKb"] == 4
            assert "build-tools 35" in j["warning"]
        finally:
            os.environ.pop("FAKE_ZIPALIGN_OLD", None)
            signing._ZIPALIGN_SUPPORTS_PAGE_SIZE = None

    def test_se_firma_el_apk_alineado(self, client, login, tool_calls):
        sid = subir(client).get_json()["sessionId"]
        r = client.post("/sign", json={"sessionId": sid}, headers=login())
        firma = next(linea for linea in tool_calls() if linea.startswith("java -jar"))
        assert "aligned.apk" in firma
        assert r.get_json()["aligned"] is True

    def test_si_zipalign_falla_se_firma_igual_pero_avisando(self, client, login, tool_calls):
        os.environ["FAKE_ZIPALIGN_FAIL"] = "1"
        try:
            sid = subir(client).get_json()["sessionId"]
            j = client.post("/sign", json={"sessionId": sid}, headers=login()).get_json()
            assert j["ok"] is True
            assert j["aligned"] is False
            assert "unable to open" in j["warning"]
            firma = next(linea for linea in tool_calls() if linea.startswith("java -jar"))
            assert "input.apk" in firma
        finally:
            os.environ.pop("FAKE_ZIPALIGN_FAIL", None)

    def test_las_contrasenas_van_por_entorno_no_en_argv(self, client, login, tool_calls, A):
        """El java de mentira aborta si no las recibe por entorno."""
        sid = subir(client).get_json()["sessionId"]
        r = client.post("/sign", json={"sessionId": sid}, headers=login())
        assert r.get_json()["ok"] is True

        firma = next(linea for linea in tool_calls() if linea.startswith("java -jar"))
        assert A.KS_PASS not in firma
        assert A.KEY_PASS not in firma
        assert "env:APK_SIGNER_KS_PASS" in firma
        assert f"env APK_SIGNER_KS_PASS={A.KS_PASS}" in tool_calls()

    def test_firmar_exige_sesion(self, client):
        sid = subir(client).get_json()["sessionId"]
        assert client.post("/sign", json={"sessionId": sid}).status_code == 403

    def test_sessionid_invalido(self, client, login):
        r = client.post("/sign", json={"sessionId": "../../etc"}, headers=login())
        assert r.status_code == 400

    def test_sesion_inexistente(self, client, login):
        r = client.post("/sign", json={"sessionId": "noexistesid12345"},
                        headers=login())
        assert r.status_code == 404

    def test_queda_registrado_quien_firma(self, client, login, A):
        sid = subir(client).get_json()["sessionId"]
        client.post("/sign", json={"sessionId": sid}, headers=login())
        meta = A.load_session_meta(sid)
        assert meta["signedBy"] == {"id": "u001", "name": "Firmante"}


class TestVerificacion:
    def test_no_se_puede_verificar_sin_firmar(self, client):
        sid = subir(client).get_json()["sessionId"]
        r = client.post("/verify", json={"sessionId": sid})
        assert r.status_code == 400

    def test_una_verificacion_fallida_se_refleja_en_la_sesion(self, client, login, A):
        sid = subir(client).get_json()["sessionId"]
        client.post("/sign", json={"sessionId": sid}, headers=login())
        os.environ["FAKE_VERIFY_FAIL"] = "1"
        try:
            j = client.post("/verify", json={"sessionId": sid}).get_json()
            assert j["ok"] is False
            assert A.load_session_meta(sid)["verifiedOk"] is False
        finally:
            os.environ.pop("FAKE_VERIFY_FAIL", None)


class TestDescarga:
    def _firmada(self, client, headers):
        sid = subir(client).get_json()["sessionId"]
        client.post("/sign", json={"sessionId": sid}, headers=headers)
        return sid

    def test_el_firmante_descarga(self, client, login):
        headers = login("u001")
        sid = self._firmada(client, headers)
        assert client.post("/download", json={"sessionId": sid},
                           headers=headers).status_code == 200

    def test_un_tercero_no_descarga(self, client, login):
        sid = self._firmada(client, login("u001"))
        r = client.post("/download", json={"sessionId": sid}, headers=login("u002"))
        assert r.status_code == 403
        assert "otro usuario" in r.get_json()["error"]

    def test_el_admin_descarga_cualquier_sesion(self, client, login):
        sid = self._firmada(client, login("u001"))
        assert client.post("/download", json={"sessionId": sid},
                           headers=login("admin")).status_code == 200

    def test_no_se_descarga_lo_que_no_se_ha_firmado(self, client, login):
        headers = login()
        sid = subir(client).get_json()["sessionId"]
        assert client.post("/download", json={"sessionId": sid},
                           headers=headers).status_code == 403

    def test_el_get_antiguo_ya_no_existe(self, client):
        assert client.get("/download/cualquiercosa123").status_code in (404, 405)

    def test_nombre_de_descarga_y_tipo(self, client, login):
        headers = login()
        sid = self._firmada(client, headers)
        r = client.post("/download", json={"sessionId": sid}, headers=headers)
        assert "punto-de-venta_signed.apk" in r.headers["Content-Disposition"]
        assert r.headers["Content-Type"] == "application/vnd.android.package-archive"


class TestHealthz:
    def test_reporta_el_utillaje(self, client):
        checks = client.get("/healthz").get_json()["checks"]
        assert checks["aapt_exists"] is True
        assert checks["zipalign_exists"] is True
        assert checks["apksigner_jar_exists"] is True
        assert checks["keystore_exists"] is True
        assert checks["java"] is True
        assert checks["work_writable"] is True

    def test_reporta_la_configuracion_de_sesion(self, client, A):
        auth = client.get("/healthz").get_json()["auth"]
        assert auth["sessionTtlMinutes"] == A.AUTH_TTL_MINUTES
        assert auth["trustedProxies"] == A.TRUSTED_PROXIES
