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

## 4) Error "Failed to obtain key with alias ..." / "UnrecoverableKeyException: Cannot recover key"

**Causa:** el alias es correcto pero la contraseña de la clave privada (`KEY_PASS`) no coincide con la del keystore o con la definida en el alias.

**Solución:** valida que `KEY_ALIAS` exista en el keystore y revisa en `secrets.json` que `KS_PASS` (contraseña del keystore) y `KEY_PASS` (contraseña de la clave) sean las correctas. Si el alias existe y puedes listar el keystore, normalmente el problema es `KEY_PASS` o un alias distinto.

## 5) Error "MFA incorrecto"

**Causa:** el token de usuario o el código MFA no son válidos.

**Solución:** verifica que el usuario existe en `/opt/apk-signer/users.json`, que el token sea el correcto y que el MFA sea el actual.

## 6) Error "No existe users.json"

**Causa:** no se ejecutó el bootstrap de usuarios durante la instalación.

**Solución:** ejecuta `sudo -u apk-signer /opt/apk-signer/.venv/bin/python /opt/apk-signer/tools/bootstrap_users.py`.

## 7) Error "Input APK no existe" o "Sesión no encontrada"

**Causa:** la sesión expiró o se borró por el cleanup.

**Solución:** vuelve a subir el APK y firma de nuevo.

## 8) `java -version` falla

**Causa:** Java no instalado.

**Solución:** `sudo apt-get install -y openjdk-17-jre-headless`.

## 9) Problemas de permisos en `/opt/apk-signer`

**Causa:** archivos creados con otro usuario.

**Solución:** asegura que el usuario `apk-signer` sea dueño:

```bash
sudo chown -R apk-signer:apk-signer /opt/apk-signer
```

## 10) `sdkmanager` no acepta licencias

**Causa:** el entorno no permite aceptar licencias de Android SDK automáticamente.

**Solución:** ejecuta manualmente:

```bash
sudo -E /opt/android-sdk/cmdline-tools/latest/bin/sdkmanager --licenses
```

## 11) El navegador avisa de "conexión no privada" / certificado no válido

**Causa:** `setup.sh` generó un certificado autofirmado porque no había uno en `/etc/ssl/apk-signer/`.

**Solución:** sustituye `apk-signer.crt` y `apk-signer.key` por el certificado corporativo y recarga nginx (`sudo nginx -t && sudo systemctl reload nginx`). Ver la sección "Certificado TLS" del README.

## 12) `nginx -t` falla con "cannot load certificate"

**Causa:** faltan `/etc/ssl/apk-signer/apk-signer.crt` o `.key`, o nginx (usuario `www-data`) no puede leer la clave.

**Solución:** vuelve a ejecutar `setup.sh`, o genera el certificado a mano. Comprueba permisos:

```bash
sudo ls -l /etc/ssl/apk-signer/
sudo chown root:www-data /etc/ssl/apk-signer/apk-signer.key
sudo chmod 0640 /etc/ssl/apk-signer/apk-signer.key
```

## 13) Error "La sesión pertenece a otro usuario" al descargar

**Causa:** la descarga está atada al usuario que firmó. Estás usando un token distinto al que se usó para firmar esa sesión.

**Solución:** descarga con el token del firmante, o con un token de administrador.

## 14) El modal de Logs pide token y MFA / aparece vacío

**Causa:** `/logs/data` ya no es anónimo. Además, un usuario sin rol `admin` solo ve sus propios eventos.

**Solución:** introduce token y código MFA en la pantalla principal antes de abrir Logs. Para ver la traza completa, usa un token de administrador.

## 15) Error 405 al llamar a `GET /logs/data` o `GET /download/<sessionId>`

**Causa:** ambos endpoints pasaron a ser `POST` con credenciales en el cuerpo. Los `GET` anónimos se eliminaron.

**Solución:** actualiza el cliente o script a `POST /logs/data` y `POST /download` enviando `userToken` y `mfaCode`. Ver la tabla "Control de acceso" del README.

## 16) Error "Ese código MFA ya se ha usado. Espera al siguiente."

**Causa:** el anti-replay solo permite canjear cada código TOTP una vez. Estás reutilizando uno que ya abrió sesión, o uno de un periodo anterior.

**Solución:** espera al siguiente código del autenticador. Recuerda que ya no hace falta un código por operación: la sesión que abres cubre firmar, verificar, descargar y consultar la traza durante `AUTH_TTL_MINUTES` (15 min por defecto).

## 17) Error 429 "Demasiados intentos fallidos"

**Causa:** se superaron `MAX_AUTH_FAILURES` (5) intentos de login fallidos. El bloqueo dura `AUTH_LOCKOUT_MINUTES` (15) y aplica aunque después se acierte el código.

**Solución:** espera a que expire. Si es un bloqueo legítimo que hay que levantar ya, borra la entrada del usuario en el fichero de estado y reinicia el servicio:

```bash
sudo -u apk-signer cat /opt/apk-signer/work/auth_state.json | jq .failures
sudo systemctl stop apk-signer
sudo -u apk-signer rm /opt/apk-signer/work/auth_state.json
sudo systemctl start apk-signer
```

> Borrar ese fichero también cierra todas las sesiones activas y reinicia el anti-replay.

Si el 429 llega sin haber fallado nada, es el rate limiting de nginx: revisa `limit_req` en `nginx/apk-signer.conf`.

## 18) Error "Sesión inválida o caducada"

**Causa:** la sesión duró más de `AUTH_TTL_MINUTES`, se cerró con "Cerrar sesión", o el servicio se reinició y se limpió el estado.

**Solución:** introduce token y un código MFA nuevo. Para sesiones más largas, sube `AUTH_TTL_MINUTES` en `secrets.json`.

## 19) La firma avisa de "APK sin alinear"

**Causa:** `ZIPALIGN` no está en `secrets.json`, el binario no existe, o `zipalign` devolvió error.

**Solución:** comprueba `zipalign_exists` en `/healthz`. Reinstala build-tools o copia el binario y actualiza `secrets.json`:

```bash
sudo -u apk-signer install -m 0755 \
  /opt/android-sdk/build-tools/34.0.0/zipalign /opt/apk-signer/tools/zipalign
```

## 20) El servicio no arranca tras endurecer systemd

**Causa:** alguna directiva de aislamiento choca con el entorno. Las sospechosas, por orden: `SystemCallFilter`, `RestrictAddressFamilies`, `ProtectSystem=strict`.

**Solución:** mira el motivo exacto y prueba a comentar la directiva señalada:

```bash
sudo journalctl -u apk-signer.service -n 100 --no-pager
sudo systemd-analyze security apk-signer.service
```

Si el fallo aparece al firmar y no al arrancar, casi siempre es la JVM: comprueba que **no** se ha añadido `MemoryDenyWriteExecute=true`, que es incompatible con el JIT de Java.

## 21) La IP de la traza sale como 127.0.0.1

**Causa:** `TRUSTED_PROXIES` está a 0, o nginx no envía `X-Forwarded-For`.

**Solución:** con nginx delante, `TRUSTED_PROXIES` debe ser 1. Si añades otro proxy o balanceador por delante, súbelo al número real de saltos: un valor mayor del real permitiría falsificar la IP con una cabecera.

## 22) "Verificar cadena" informa de roturas

**Causa:** la traza no cuadra. Distingue entre:

* **eventos modificados** (`macBad`): alguien cambió el contenido de una línea;
* **roturas de cadena** (`chainBad`): se borraron o reordenaron eventos;
* **líneas ilegibles** (`unreadable`): JSON corrupto, normalmente por un disco lleno o un corte durante la escritura;
* **"sin cadena"**: eventos anteriores a la versión 1.8.0, que no llevaban `prev`. Es esperado en trazas antiguas y no indica manipulación.

**Solución:** `firstProblemSeq` señala el primer evento afectado; a partir de ahí la traza ya no prueba nada. Conserva el fichero como evidencia antes de tocarlo:

```bash
sudo cp /opt/apk-signer/logs/app.jsonl /var/tmp/app.jsonl.evidencia
sudo ls -l /opt/apk-signer/logs/
```

Si la cadena se rompe justo en el primer evento y este es `log-rotated`, no es una rotura: es el enlace normal con el fichero rotado, y el resumen lo indica en `continuesFrom`.

## 23) El resumen dice `hasKey: false`

**Causa:** no hay `LOG_HMAC_KEY` en `secrets.json`, así que los eventos no llevan MAC.

**Solución:** genera una clave y reinicia el servicio. Los eventos ya escritos no se pueden sellar retroactivamente:

```bash
python3 -c "import os;print(os.urandom(32).hex())"
```

## 24) Los tests fallan con "No existe secrets.json"

**Causa:** se está ejecutando `pytest` sin las dependencias de desarrollo, o desde un directorio distinto de la raíz del repo.

**Solución:**

```bash
pip install -r requirements-dev.txt
pytest
```

Los tests montan su propia configuración en un directorio temporal vía `CREDENTIALS_DIRECTORY`: no usan ni modifican el `secrets.json` de la máquina.
