# Changelog

Todos los cambios notables de este proyecto se documentarán en este archivo.

El formato está basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/),
y el proyecto sigue [Semantic Versioning](https://semver.org/lang/es/).

## [Unreleased]
### Security
- Flask sube de 3.0.3 a 3.1.3 por PYSEC-2026-2151, detectado por `pip-audit` en la primera ejecución del CI. Los 95 tests pasan sin cambios en 3.1.3.

## [1.8.0] - 2026-08-31
### Added
- Suite de tests con pytest (95 casos): autenticación, flujo completo de firma, cabeceras y errores HTTP, traza de auditoría y mantenimiento. Las herramientas externas se sustituyen por scripts en `tests/fakebin/` antepuestos al `PATH`, de modo que los tests recorren el mismo código de `subprocess` que producción sin necesitar el Android SDK.
- Integración continua en GitHub Actions: `pytest` en Python 3.9 y 3.11, `ruff`, `bandit`, `pip-audit`, `bash -n setup.sh` y `nginx -t` sobre la configuración real. Dependabot para pip, actions y la imagen base.
- Traza de auditoría encadenada por hash: cada evento lleva `seq` correlativo y `prev` con el hash del anterior. Un MAC por línea no detecta el borrado de eventos, porque las líneas supervivientes siguen siendo válidas; el encadenado sí.
- `POST /logs/verify` (solo admin) recorre la traza completa comprobando MAC y encadenado, y señala la primera rotura. Botón "Verificar cadena" en el modal de Logs.
- `SYSLOG_ADDRESS` opcional para enviar la traza a un syslog o SIEM remoto, única defensa real frente a quien controle la máquina y pueda borrar el fichero.
- La rotación de `cleanup.py` deja un evento `log-rotated` que enlaza con el hash del fichero rotado, de forma que la cadena no se parte al rotar.

### Changed
- `app.py` (1.427 líneas) se separa en `config.py`, `audit.py`, `auth.py`, `signing.py` y `app.py`, con dependencias en una sola dirección. `app:app` sigue siendo el punto de entrada, así que ni la unit de systemd ni el `Dockerfile` cambian. Los 95 tests pasan sin modificación, que es lo que acredita que el corte preserva el comportamiento.
- `cleanup.py` deja de tener `/opt/apk-signer` fijo: deriva la ruta de su propia ubicación y respeta `CREDENTIALS_DIRECTORY` igual que la aplicación.
- El servidor de desarrollo escucha en `127.0.0.1` en lugar de `0.0.0.0`; se abre con `APK_SIGNER_DEV_HOST` si hace falta. En producción arranca gunicorn desde systemd.

### Fixed
- La verificación de la cadena trataba el evento ancla de rotación como una rotura, porque su `prev` y su `seq` no empiezan de cero. Ahora se reconoce como continuación y se informa del fichero de origen en `continuesFrom`.

## [1.7.0] - 2026-08-31
### Security
- Autenticación por sesión corta: token + MFA se canjean una sola vez en `POST /api/auth/login` por un `authToken` con caducidad (15 min por defecto) que autoriza firmar, verificar, descargar y consultar la traza. Nuevo `POST /api/auth/logout`.
- Anti-replay de TOTP: el contador consumido se guarda por usuario, de modo que un código capturado no abre una segunda sesión.
- Bloqueo temporal tras 5 intentos fallidos (15 min), aplicado también cuando el intento siguiente es correcto. Los tokens desconocidos se contabilizan por IP.
- El estado de autenticación (sesiones, contadores, bloqueos) se guarda con bloqueo exclusivo de fichero (`flock`), de forma que es coherente entre los varios workers de gunicorn. Verificado con 8 procesos concurrentes: un único canje por código.
- Rate limiting en nginx: 12 r/min en `/api/auth/login`, 20 r/min y 3 conexiones en `/inspect`, 10 r/s en el resto, respondiendo 429.
- `ProxyFix` con número de proxies de confianza configurable (`TRUSTED_PROXIES`). La IP de la traza deja de leerse de `X-Forwarded-For` a mano, que era falsificable por cualquiera.
- `/sign`, `/download`, `/logs/data` y `/api/admin/*` dejan de aceptar `userToken`/`mfaCode`/`adminToken`/`adminCode`: usan la sesión.
- Unit de systemd endurecida: `ProtectSystem=strict`, `PrivateTmp`, `PrivateDevices`, `NoNewPrivileges`, `SystemCallFilter=@system-service` y `ReadWritePaths` acotado a `/opt/apk-signer`. `MemoryDenyWriteExecute` se deja fuera a propósito porque rompería el JIT de la JVM.
- Soporte opcional de `LoadCredential=` de systemd: si se define, `secrets.json` se lee de `$CREDENTIALS_DIRECTORY` y no necesita vivir en el árbol de la aplicación.

### Added
- `zipalign -p -f 4` antes de firmar, instalado por `setup.sh` y por el `Dockerfile`. Si falta o falla, la firma continúa pero se informa con `"aligned": false` y un `warning`, y queda en la traza.
- `/healthz` informa de `zipalign_configured`, `zipalign_exists` y de la configuración de sesión.
- Indicador de sesión activa y botón "Cerrar sesión" en el portal.

### Changed
- Los errores 4xx/5xx devuelven siempre JSON en lugar de la página HTML de Werkzeug, incluidos 413 (con el límite en MB) y los timeouts de `apksigner`, que antes producían un 500 sin explicación.

### Fixed
- El contador de intentos fallidos no llegaba a persistirse: al registrarse dentro de un gestor de contexto que lanzaba a continuación `PermissionError`, la escritura posterior al `yield` se saltaba y el bloqueo nunca se activaba.

### Removed
- `verify_totp` y `require_admin_session`, sin uso tras la migración a sesiones.

## [1.6.1] - 2026-08-31
### Security
- El portal se sirve solo por HTTPS: nginx redirige el puerto 80 a 443 y `setup.sh` genera un certificado autofirmado si no hay uno corporativo. El token de usuario y el código MFA dejan de viajar en claro.
- `/logs/data` deja de ser anónimo: pasa a `POST` con token + MFA. Un admin ve toda la traza; un usuario normal, solo sus propios eventos.
- `/download/<sessionId>` (GET, sin autenticar) se sustituye por `POST /download` con token + MFA, restringido al usuario que firmó la sesión o a un admin. Conocer un `sessionId` ya no da acceso al APK firmado.
- Las contraseñas del keystore se pasan a `apksigner` por entorno (`env:`) en lugar de `argv`, donde eran visibles en `ps` durante la firma.
- El nombre de fichero recibido del cliente se sanea con `secure_filename` antes de construir la ruta del APK firmado, y el `sessionId` se valida contra `[A-Za-z0-9_-]{8,64}`.
- `Cache-Control` deja de ser `public, max-age=600` en todas las respuestas: solo `/static/*` es cacheable y el resto (APK firmado, trazas, listado de usuarios) pasa a `no-store`.
- `secrets.json` se crea con permisos `0600` de forma explícita.

### Added
- `LICENSE` (MIT) y `.gitignore` que excluye `secrets.json`, `users.json`, keystores y material TLS.
- Sección "Control de acceso" en el README y entradas 11-15 en `docs/RESUMEN_ERRORES.md`.

### Changed
- `client_max_body_size` de nginx baja de 150m a 100m para alinearse con `MAX_CONTENT_LENGTH`.

## [1.6.0] - 2026-01-21
### Added
- Registro del usuario que firma/verifica/descarga en los logs y visualización en el modal de Logs.
