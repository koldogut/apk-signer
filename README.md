# APK Signer Web

Servicio web para inspeccionar APKs y firmarlos con un keystore local. Expone una UI estática y una API REST en el puerto 8001, y publica el portal vía nginx en `https://localhost/`. El puerto 80 redirige a HTTPS.

## Contenido del repositorio

| Componente | Descripción |
|---|---|
| `setup.sh` | Instalación desde cero: dependencias, Android Build Tools, TLS, usuario administrador y servicios |
| `update.sh` | Actualización de una instalación existente, con copia de seguridad y reversión automática |
| `app.py`, `config.py`, `audit.py`, `auth.py`, `signing.py` | Aplicación Flask |
| `static/` | Portal web y panel de administración |
| `systemd/`, `nginx/` | Unidades de servicio y configuración del proxy |
| `tools/` | Alta del administrador inicial y mantenimiento periódico |
| `tests/` | Suite de pruebas (100 casos) |

El keystore no se incluye: hay que aportarlo.

## Requisitos

* Debian 12+ / Ubuntu 24.04+.
* Python 3.11 o superior, con `venv` y `pip`.
* Java (JRE) para ejecutar `apksigner.jar`.
* Android Build Tools 35 o superior. Los instala `setup.sh`.
* Un keystore JKS con su alias y contraseñas.
* Un certificado TLS. `setup.sh` genera uno autofirmado si no hay ninguno.

Sobre Debian 11 o Ubuntu 22.04, instala un Python 3.11 aparte y ejecuta el instalador con él en el `PATH`:

```bash
sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt-get update && sudo apt-get install -y python3.11 python3.11-venv
```

## Instalación

```bash
git clone https://github.com/koldogut/apk-signer.git
cd apk-signer
sudo bash setup.sh
```

Durante la instalación se abre el aceptador de licencias del SDK: confirma con `y`.

Al terminar:

1. **Guarda el token y el QR del administrador** que imprime el instalador. No se pueden recuperar después.
2. Edita `/opt/apk-signer/secrets.json` con el alias y las contraseñas del keystore.
3. Copia tu keystore a `/opt/apk-signer/keystore/KeyStore.jks`.
4. Reinicia y comprueba:

```bash
sudo systemctl restart apk-signer
curl -s http://localhost:8001/healthz | jq .checks
```

El portal queda en `https://localhost/` y la gestión de usuarios en `https://localhost/admin`.

Para instalación paso a paso, consulta [docs/INSTALACION.md](docs/INSTALACION.md). Para despliegue con contenedores, [docs/DOCKER.md](docs/DOCKER.md).

### Certificado TLS

`setup.sh` genera un certificado autofirmado en `/etc/ssl/apk-signer/`, que provoca un aviso del navegador. Para poner el corporativo:

```bash
sudo cp tu-certificado.crt /etc/ssl/apk-signer/apk-signer.crt
sudo cp tu-clave.key /etc/ssl/apk-signer/apk-signer.key
sudo chown root:www-data /etc/ssl/apk-signer/apk-signer.key
sudo chmod 0640 /etc/ssl/apk-signer/apk-signer.key
sudo nginx -t && sudo systemctl reload nginx
```

Las rutas se pueden cambiar con `TLS_CERT` y `TLS_KEY` al ejecutar `setup.sh`.

## Actualización

```bash
cd apk-signer
git pull
sudo bash update.sh
```

`update.sh` actualiza el código, las dependencias Python, las unidades de systemd y la configuración de nginx. Conserva `secrets.json`, `users.json`, el keystore, la traza y las sesiones de trabajo, y añade a `secrets.json` las claves nuevas que aparezcan en `secrets.example.json` sin tocar los valores existentes.

Antes de modificar nada hace una copia en `/var/backups/apk-signer/`. Si el servicio no responde en `/healthz` tras reiniciar, restaura esa copia y vuelve a arrancar la versión anterior.

No instala paquetes del sistema ni el SDK de Android.

| Variable | Efecto |
|---|---|
| `KEEP_BACKUPS=10` | Número de copias que se conservan (5 por defecto) |
| `SKIP_DEPS=1` | No toca las dependencias Python |
| `INSTALL_BUILD_TOOLS=1` | Instala la versión de Build Tools configurada si falta |

La versión instalada queda en `/opt/apk-signer/.version`.

### Restaurar una copia

```bash
sudo systemctl stop apk-signer
sudo tar -xzf /var/backups/apk-signer/apk-signer-AAAAMMDD-HHMMSS.tar.gz -C /opt/apk-signer
sudo chown -R apk-signer:apk-signer /opt/apk-signer
sudo systemctl start apk-signer
```

## Comprobación del servicio

```bash
sudo systemctl status apk-signer.service nginx --no-pager
sudo journalctl -u apk-signer.service -n 200 --no-pager
curl -s http://localhost:8001/healthz | jq .checks
curl -I http://localhost/          # 301 hacia https://
curl -kI https://localhost/        # 200
```

Todas las comprobaciones de `/healthz` deben dar `true`, y `zipalign_page_kb` debe valer 16.

Si faltan `secrets.json` o el keystore, el portal muestra una advertencia y la firma queda deshabilitada.

Ante un error 413 al subir un APK, revisa `client_max_body_size` en nginx (100m) y `MAX_CONTENT_LENGTH` en `secrets.json`.

## Control de acceso

El token de usuario y el código MFA se canjean una vez por una sesión de 15 minutos. Esa sesión autoriza el resto de operaciones y viaja en la cabecera `Authorization: Bearer <authToken>` o en el campo `authToken` del cuerpo.

| Endpoint | Método | Requiere |
|---|---|---|
| `/api/auth/login` | POST | token + MFA |
| `/api/auth/logout` | POST | `authToken` |
| `/inspect` | POST | — |
| `/sign` | POST | sesión |
| `/verify` | POST | — |
| `/download` | POST | sesión del firmante, o de un admin |
| `/logs/data` | POST | sesión |
| `/logs/verify` | POST | sesión de admin |
| `/api/admin/*` | POST | sesión de admin |

Ejemplo:

```bash
AUTH=$(curl -sk https://localhost/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"userToken":"TU_TOKEN","mfaCode":"123456"}' | jq -r .authToken)

curl -sk https://localhost/logs/data \
  -H "Authorization: Bearer $AUTH" \
  -H 'Content-Type: application/json' -d '{"limit":50}' | jq
```

En el modal de Logs, un administrador ve la traza completa y un usuario normal solo sus propios eventos.

### Límites de intentos

| Control | Valor por defecto | Ajuste |
|---|---|---|
| Reutilización de un código TOTP | Rechazada | — |
| Intentos fallidos antes de bloquear | 5 | `MAX_AUTH_FAILURES` |
| Duración del bloqueo | 15 min | `AUTH_LOCKOUT_MINUTES` |
| Duración de la sesión | 15 min | `AUTH_TTL_MINUTES` |
| Peticiones a `/api/auth/login` | 12/min por IP | `nginx/apk-signer.conf` |
| Peticiones a `/inspect` | 20/min y 3 conexiones por IP | `nginx/apk-signer.conf` |

El estado se guarda en `AUTH_STATE_PATH`, compartido entre los workers de gunicorn.

## Alineado de los APK

Antes de firmar se ejecuta `zipalign` sobre el APK. Si no está configurado o falla, la firma continúa y la respuesta incluye `"aligned": false` con un `warning`, que también queda en la traza.

Las librerías nativas sin comprimir se alinean al tamaño de página de `ZIPALIGN_PAGE_KB` (16 KB por defecto), lo que requiere Build Tools 35 o superior. Con una versión anterior el servicio alinea a 4 KB y lo indica en el `warning` de cada firma.

| `.so` en el APK | Tratamiento |
|---|---|
| Sin comprimir (`Stored`) | Se alinea a `ZIPALIGN_PAGE_KB` |
| Comprimida (`Deflated`) | Se deja como está |

Una `.so` comprimida en un offset no alineado es el comportamiento esperado.

`/healthz` informa del valor efectivo en `zipalign_page_kb`, y cada firma en `alignPageKb`.

## Traza de auditoría

Cada evento se registra en `logs/app.jsonl` con un MAC (HMAC-SHA256 con `LOG_HMAC_KEY`), un número de orden `seq` y el hash del evento anterior en `prev`.

Un administrador puede verificar la traza completa desde el botón "Verificar cadena" del modal de Logs, o por API:

```bash
curl -sk https://localhost/logs/verify \
  -H "Authorization: Bearer $AUTH" \
  -H 'Content-Type: application/json' -d '{}' | jq .summary
```

La verificación devuelve `ok: false` si detecta eventos modificados, huecos en la numeración, líneas ilegibles o ausencia de `LOG_HMAC_KEY`.

`cleanup.py` rota el fichero cada hora si supera los 10 MB y deja en el nuevo un evento `log-rotated` enlazado con el anterior.

Para conservar la traza fuera de la máquina, configura `SYSLOG_ADDRESS` (`"host:514"` o `"/dev/log"`).

## Aislamiento del servicio

La unidad de systemd corre con `ProtectSystem=strict`, `PrivateTmp`, `NoNewPrivileges` y `SystemCallFilter=@system-service`, con `/opt/apk-signer` como único árbol escribible.

**No añadas `MemoryDenyWriteExecute=true`**: impide el JIT de la JVM y el servicio deja de arrancar.

Si `apksigner` falla tras actualizar Java, comenta `SystemCallFilter` como primera prueba.

Para sacar las contraseñas del árbol de la aplicación, deja el fichero en `/etc/apk-signer/secrets.json` (`root:root`, `0600`) y descomenta la línea `LoadCredential=` de la unidad.

## Configuración

Todas las opciones viven en `secrets.json`. `secrets.example.json` tiene la plantilla completa.

| Clave | Descripción |
|---|---|
| `AAPT`, `APKSIGNER_JAR`, `ZIPALIGN` | Rutas de las herramientas del SDK |
| `ZIPALIGN_PAGE_KB` | Tamaño de página del alineado (16) |
| `KEYSTORE_PATH`, `KEY_ALIAS`, `KS_PASS`, `KEY_PASS` | Keystore y credenciales |
| `WORK_DIR`, `LOG_DIR`, `USERS_PATH`, `AUTH_STATE_PATH` | Rutas de datos |
| `MAX_CONTENT_LENGTH` | Tamaño máximo del APK subido |
| `SESSION_TTL_HOURS` | Caducidad de las sesiones de trabajo |
| `AUTH_TTL_MINUTES`, `MAX_AUTH_FAILURES`, `AUTH_LOCKOUT_MINUTES` | Sesión y bloqueo |
| `TRUSTED_PROXIES` | Número de proxies delante de la aplicación (1 con nginx) |
| `LOG_MAX_LINES`, `LOG_HMAC_KEY`, `SYSLOG_ADDRESS` | Traza de auditoría |

## Desarrollo

```bash
pip install -r requirements-dev.txt
pytest
```

Los tests sustituyen `java`, `aapt2` y `zipalign` por los scripts de `tests/fakebin/`, así que no necesitan el SDK de Android. La configuración de prueba se inyecta con `CREDENTIALS_DIRECTORY` y no toca el `secrets.json` de la máquina.

Servidor de desarrollo, sin nginx ni TLS delante:

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python app.py                                  # 127.0.0.1:8001
APK_SIGNER_DEV_HOST=0.0.0.0 python app.py      # accesible desde la red
```

### Integración continua

`.github/workflows/ci.yml` ejecuta en cada push y pull request:

* `pytest` en Python 3.11, 3.12 y 3.14
* `ruff` y `bash -n setup.sh`
* `bandit` y `pip-audit` sobre las dependencias de producción
* Construcción de la imagen de Docker y comprobación del utillaje dentro del contenedor
* `nginx -t` sobre `nginx/apk-signer.conf`

## Solución de problemas

[docs/RESUMEN_ERRORES.md](docs/RESUMEN_ERRORES.md) recoge 30 problemas conocidos con su causa y su remedio.

## Capturas

1. **Setup inicial con MFA**: token de administrador y QR generado durante `setup.sh`.

   ![Token y QR inicial del administrador](png/admin-token.png)

2. **Flujo de firma principal**: pantalla de firma con resultado y verificación posterior.

   ![Pantalla principal de firma y verificación](png/firma.png)

3. **Gestión de usuarios**: creación de un usuario nuevo desde el panel administrativo.

   ![Creación de usuario nuevo](png/user-man.png)
