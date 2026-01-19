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

## 4) Error "PIN incorrecto"

**Causa:** el PIN enviado no coincide con `PIN` en `secrets.json`.

**Solución:** actualiza el PIN del cliente o cambia `PIN`.

## 5) Error "Input APK no existe" o "Sesión no encontrada"

**Causa:** la sesión expiró o se borró por el cleanup.

**Solución:** vuelve a subir el APK y firma de nuevo.

## 6) `java -version` falla

**Causa:** Java no instalado.

**Solución:** `sudo apt-get install -y openjdk-17-jre-headless`.

## 7) Problemas de permisos en `/opt/apk-signer`

**Causa:** archivos creados con otro usuario.

**Solución:** asegura que el usuario `apk-signer` sea dueño:

```bash
sudo chown -R apk-signer:apk-signer /opt/apk-signer
```

## 8) `sdkmanager` no acepta licencias

**Causa:** el entorno no permite aceptar licencias de Android SDK automáticamente.

**Solución:** ejecuta manualmente:

```bash
sudo -E /opt/android-sdk/cmdline-tools/latest/bin/sdkmanager --licenses
```
