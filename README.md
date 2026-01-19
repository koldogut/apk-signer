# APK Signer Web

Servicio web para inspeccionar APKs y firmarlos con un keystore local. Expone una UI estática y una API REST en `/:8001`.

## Estado del repositorio

El repositorio incluye el backend, UI, scripts y servicios systemd. Para ejecutar en Debian/Ubuntu se requiere instalar dependencias del sistema, Android Build Tools (`aapt2`/`apksigner.jar`) y un keystore real. El script `setup.sh` ahora descarga e instala automáticamente los Build Tools públicos y configura rutas por defecto.

## Requisitos

* Debian 11+/Ubuntu 20.04+.
* Python 3.9+ (con `venv`) y `pip`.
* Java 17 (JRE) para ejecutar `apksigner.jar`.
* Android Build Tools para `aapt2` y `apksigner.jar` (instalados por `setup.sh`).
* Un keystore real (JKS) con alias y contraseñas válidas.

> Nota: el keystore no se incluye en el repo. Debe copiarse localmente y configurarse en `secrets.json`.

## Instalación rápida (modo sistema con systemd)

1. Clona el repo y ejecuta el instalador (como root):

   ```bash
   sudo bash setup.sh <repo_url>
   ```

2. Edita `/opt/apk-signer/secrets.json` con PIN, alias y contraseñas reales.
3. Copia tu `KeyStore.jks` a `/opt/apk-signer/keystore/KeyStore.jks`.
4. Verifica estado:

   ```bash
   curl -s http://localhost:8001/healthz | jq
   ```

Para más detalles y solución de errores, revisa `docs/INSTALACION.md` y `docs/RESUMEN_ERRORES.md`.
