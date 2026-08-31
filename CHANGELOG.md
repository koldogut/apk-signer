# Changelog

Todos los cambios notables de este proyecto se documentarán en este archivo.

El formato está basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/),
y el proyecto sigue [Semantic Versioning](https://semver.org/lang/es/).

## [Unreleased]
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
