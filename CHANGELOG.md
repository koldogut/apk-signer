# Changelog

Todos los cambios notables de este proyecto se documentarán en este archivo.

El formato está basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/),
y el proyecto sigue [Semantic Versioning](https://semver.org/lang/es/).

## [Unreleased]

## [2.0.0] - 2026-08-31

Endurecimiento completo del servicio: autenticación por sesión, traza de
auditoría verificable, alineado de APK a 16 KB y despliegue reproducible en
systemd y contenedores.

### Cambios incompatibles
- El token de usuario y el código MFA se canjean una sola vez en `POST /api/auth/login` por una sesión de 15 minutos. `/sign`, `/download`, `/logs/data` y `/api/admin/*` ya no aceptan `userToken`/`mfaCode`/`adminToken`/`adminCode`: usan esa sesión en `Authorization: Bearer` o en el campo `authToken`.
- Se eliminan `GET /download/<sessionId>` y `GET /logs/data`. Sus equivalentes son `POST /download` y `POST /logs/data`, ambos autenticados.
- El mínimo de Python sube de 3.9 a 3.11. Implica Debian 12+ / Ubuntu 24.04+ con el Python del sistema.
- El portal se sirve solo por HTTPS. nginx redirige el puerto 80 a 443.

### Seguridad
- TLS obligatorio. `setup.sh` genera un certificado autofirmado si no hay uno corporativo.
- `/logs/data` deja de ser anónimo. Un administrador ve la traza completa; un usuario, solo sus propios eventos.
- `POST /download` exige ser el firmante de la sesión, o administrador.
- Anti-replay de TOTP: cada código se canjea una sola vez.
- Bloqueo temporal tras 5 intentos fallidos, efectivo aunque el siguiente intento sea correcto. Los tokens desconocidos se contabilizan por IP.
- Rate limiting en nginx: 12 r/min en `/api/auth/login`, 20 r/min y 3 conexiones en `/inspect`, 10 r/s en el resto.
- Las contraseñas del keystore se pasan a `apksigner` por entorno, no en `argv`.
- El nombre de fichero recibido del cliente se sanea con `secure_filename`, y el `sessionId` se valida contra `[A-Za-z0-9_-]{8,64}`.
- `ProxyFix` con número de proxies de confianza configurable (`TRUSTED_PROXIES`).
- `Cache-Control: no-store` en todo salvo `/static/*`.
- Unidad de systemd endurecida: `ProtectSystem=strict`, `PrivateTmp`, `PrivateDevices`, `NoNewPrivileges`, `SystemCallFilter=@system-service` y `ReadWritePaths` acotado.
- Soporte opcional de `LoadCredential=` para sacar `secrets.json` del árbol de la aplicación.
- `secrets.json` se crea con permisos `0600`.
- Flask 3.1.3 (PYSEC-2026-2151), gunicorn 26.2.0 y qrcode 8.2.

### Añadido
- `update.sh`: actualiza una instalación existente conservando configuración, usuarios, keystore, traza y sesiones. Copia de seguridad previa en `/var/backups/apk-signer/` y reversión automática si el servicio no responde tras reiniciar. Incorpora a `secrets.json` las claves nuevas del ejemplo sin tocar los valores existentes.
- Traza de auditoría encadenada: cada evento lleva `seq` correlativo, el hash del anterior en `prev` y un MAC por línea. `POST /logs/verify` recorre el fichero completo y señala la primera rotura. Botón "Verificar cadena" en el modal de Logs.
- `SYSLOG_ADDRESS` opcional para enviar la traza a un syslog o SIEM remoto.
- `zipalign` antes de firmar, con alineado a página de 16 KB (`ZIPALIGN_PAGE_KB`). Si el binario instalado no admite `-P`, degrada a 4 KB avisando en la firma.
- Suite de 100 tests con pytest e integración continua: tests en Python 3.11, 3.12 y 3.14, `ruff`, `bandit`, `pip-audit`, construcción de la imagen de Docker con comprobación del utillaje dentro del contenedor, y `nginx -t`.
- `docs/DOCKER.md` con el despliegue en contenedores y la obtención del QR del TOTP inicial.
- Indicador de sesión activa y botón de cierre de sesión en el portal.

### Corregido
- `zipalign` se ejecuta correctamente en una instalación real y los APK se firman alineados.
- La imagen de Docker construye sobre Debian 13 con `default-jre-headless`.
- `setup.sh` y `update.sh` generan la clave que sella la traza, y la verificación devuelve `ok: false` si falta.
- Los errores 4xx/5xx devuelven siempre JSON, incluidos 413 y los timeouts de `apksigner`.
- El bloqueo por intentos fallidos se activa al superar el máximo configurado.

### Cambiado
- `app.py` se separa en `config`, `audit`, `auth`, `signing` y `app`. `app:app` sigue siendo el punto de entrada.
- `docker-compose.yml` monta `./data` como directorio: `users.json` y el QR del administrador quedan accesibles en el host. Incluye `healthcheck`.
- Documentación reorganizada en README (uso), `docs/INSTALACION.md` (systemd), `docs/DOCKER.md` (contenedores) y `docs/RESUMEN_ERRORES.md` (31 problemas conocidos).
- Build Tools 35.0.0 por defecto, con resolución a la versión más nueva instalada si falta.
- El servidor de desarrollo escucha en `127.0.0.1`; se abre con `APK_SIGNER_DEV_HOST`.

## [1.6.0] - 2026-01-21
### Added
- Registro del usuario que firma/verifica/descarga en los logs y visualización en el modal de Logs.
