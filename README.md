# APK Signer Web

Servicio web para inspeccionar APKs y firmarlos con un keystore local. Expone una UI estática y una API REST en `/:8001`, y publica el portal vía nginx en `http://localhost/`.

## Estado del repositorio

El repositorio incluye el backend, UI, scripts y servicios systemd. Para ejecutar en Debian/Ubuntu se requiere instalar dependencias del sistema, Android Build Tools (`aapt2`/`apksigner.jar`) y un keystore real. El script `setup.sh` ahora descarga e instala automáticamente los Build Tools públicos y configura rutas por defecto.

## Requisitos

* Debian 11+/Ubuntu 20.04+.
* Python 3.9+ (con `venv`) y `pip`.
* Java 17 (JRE) para ejecutar `apksigner.jar`.
* Android Build Tools para `aapt2` y `apksigner.jar` (instalados por `setup.sh`).
* Un keystore real (JKS) con alias y contraseñas válidas.
* MFA (TOTP) para firmar: se genera un usuario administrador durante la instalación.

> Nota: el keystore no se incluye en el repo. Debe copiarse localmente y configurarse en `secrets.json`.

## Instalación rápida (modo sistema con systemd)

1. Clona el repo y ejecuta el instalador (como root). El script usa el código del clon local, no requiere URL adicional:

   ```bash
   git clone https://github.com/koldogut/apk-signer.git
   cd apk-signer
   sudo bash setup.sh
   ```

2. Durante la instalación se abrirá el aceptador de licencias de `sdkmanager` (confirma con `y` cuando se solicite).
3. El instalador generará un usuario administrador MFA y mostrará el token + QR para Google Authenticator.
4. Edita `/opt/apk-signer/secrets.json` con alias y contraseñas reales.
5. Copia tu `KeyStore.jks` a `/opt/apk-signer/keystore/KeyStore.jks`.
6. Verifica estado:

   ```bash
   curl -s http://localhost:8001/healthz | jq
   ```

Accede a `http://localhost/admin` para gestionar usuarios y generar nuevos QR MFA (requiere token + MFA del admin).

## Comprobaciones básicas de funcionamiento

Ejecuta estos comandos para confirmar que el servicio web está levantado y sirviendo la UI:

```bash
sudo systemctl status apk-signer.service --no-pager
sudo systemctl status nginx --no-pager
sudo journalctl -u apk-signer.service -n 200 --no-pager
ss -tulpn | grep 8001
curl -s http://localhost:8001/healthz | jq
curl -I http://localhost/
```

Si `/healthz` no responde, revisa permisos de `/opt/apk-signer`, la existencia de `secrets.json` y de `users.json`, y que el servicio `apk-signer` esté activo.

Si necesitas diagnosticar por tu cuenta, revisa estado, logs y el listener del puerto antes de reintentar la instalación.

Si faltan `secrets.json` o el `KeyStore.jks`, el portal mostrará una advertencia y la firma quedará deshabilitada hasta completar esos pasos.

Para más detalles y solución de errores, revisa `docs/INSTALACION.md` y `docs/RESUMEN_ERRORES.md`.
