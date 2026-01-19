# Resumen de errores comunes

## 1) `/healthz` muestra `aapt_exists: false`

**Causa:** `AAPT` no apunta a un binario válido.

**Solución:** reinstala Android Build Tools o copia `aapt2` y actualiza `secrets.json`.

## 2) `/healthz` muestra `apksigner_jar_exists: false`

**Causa:** `APKSIGNER_JAR` no apunta al `apksigner.jar` real.

**Solución:** reinstala Android Build Tools o copia el jar y actualiza `secrets.json`.

## 3) Error "apksigner.jar o keystore no configurados"

**Causa:** rutas vacías o inexistentes en `APKSIGNER_JAR`/`KEYSTORE_PATH`.

**Solución:** revisa `secrets.json` y permisos de lectura.

## 4) Error "MFA incorrecto"

**Causa:** el token de usuario o el código MFA no son válidos.

**Solución:** verifica que el usuario existe en `/opt/apk-signer/users.json`, que el token sea el correcto y que el MFA sea el actual.

## 5) Error "No existe users.json"

**Causa:** no se ejecutó el bootstrap de usuarios durante la instalación.

**Solución:** ejecuta `sudo -u apk-signer /opt/apk-signer/.venv/bin/python /opt/apk-signer/tools/bootstrap_users.py`.

## 6) Error "Input APK no existe" o "Sesión no encontrada"

**Causa:** la sesión expiró o se borró por el cleanup.

**Solución:** vuelve a subir el APK y firma de nuevo.

## 7) `java -version` falla

**Causa:** Java no instalado.

**Solución:** `sudo apt-get install -y openjdk-17-jre-headless`.

## 8) Problemas de permisos en `/opt/apk-signer`

**Causa:** archivos creados con otro usuario.

**Solución:** asegura que el usuario `apk-signer` sea dueño:

```bash
sudo chown -R apk-signer:apk-signer /opt/apk-signer
```

## 9) `sdkmanager` no acepta licencias

**Causa:** el entorno no permite aceptar licencias de Android SDK automáticamente.

**Solución:** ejecuta manualmente:

```bash
sudo -E /opt/android-sdk/cmdline-tools/latest/bin/sdkmanager --licenses
```
