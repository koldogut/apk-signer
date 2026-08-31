# Despliegue con Docker

Alternativa al despliegue con systemd. La imagen incluye Java, el SDK de Android y las Build Tools, así que no hay que preparar nada en el host más allá de Docker.

> **Este despliegue no incluye TLS.** `docker-compose.yml` publica el puerto 8001 en claro. El token de usuario y el código MFA viajarían sin cifrar. Pon un proxy inverso con TLS delante, o usa el despliegue con systemd, que configura nginx y el certificado.

## Requisitos

* Docker con el plugin `compose`.
* Un keystore JKS con su alias y contraseñas.
* Unos 3 GB de espacio para la imagen.

## 1. Preparar el árbol de trabajo

```bash
git clone https://github.com/koldogut/apk-signer.git
cd apk-signer
mkdir -p keystore data work logs
```

| Directorio | Contenido | Persistente |
|---|---|---|
| `keystore/` | Tu `KeyStore.jks` | Sí |
| `data/` | `users.json` y el QR del administrador | Sí |
| `work/` | Sesiones de firma y estado de autenticación | Sí |
| `logs/` | Traza de auditoría | Sí |

## 2. Construir la imagen

```bash
docker compose build
```

## 3. Configurar `secrets.json`

```bash
cp secrets.example.json secrets.json
```

Edita estos valores:

```json
{
  "USERS_PATH": "/opt/apk-signer/data/users.json",
  "KEYSTORE_PATH": "/opt/apk-signer/keystore/KeyStore.jks",
  "KEY_ALIAS": "tu_alias",
  "KS_PASS": "contraseña del keystore",
  "KEY_PASS": "contraseña de la clave",
  "LOG_HMAC_KEY": "..."
}
```

`USERS_PATH` debe apuntar a `data/`, que es el directorio montado desde el host.

Genera la clave que sella la traza de auditoría. Sin ella los eventos se registran sin MAC y `/logs/verify` responde `ok: false`:

```bash
docker compose run --rm --entrypoint python3 apk-signer \
  -c "import os; print(os.urandom(32).hex())"
```

Copia el valor a `LOG_HMAC_KEY`.

> El despliegue con Docker no ejecuta `setup.sh`, que es quien genera esta clave en el despliegue con systemd. Aquí hay que hacerlo a mano.

Deja tu keystore en su sitio:

```bash
cp /ruta/a/tu/KeyStore.jks keystore/KeyStore.jks
```

## 4. Obtener el QR del TOTP inicial

El alta del administrador crea `users.json` y genera su secreto TOTP. **Se ejecuta una sola vez**, antes de levantar el servicio:

```bash
docker compose run --rm apk-signer python3 tools/bootstrap_users.py
```

La salida trae cuatro cosas:

```
[apk-signer] Usuario administrador creado.
[apk-signer] Token admin: e3Z3MNvADmlX3Vl-XSDuacjYTGF6aVXz
[apk-signer] MFA secret: 7TEKH2TYDKKCX76BMT6ECUDVEN2RHNBX
[apk-signer] QR admin: /opt/apk-signer/data/admin-qr.png
[apk-signer] OTPAUTH: otpauth://totp/Administrador?secret=7TEK...&issuer=APK%20Signer
[apk-signer] Escanea este QR con Google Authenticator:

  ██████████████    ██    ██    ████    ████    ████      ██  ██████████████
  ██          ██      █████        ████████████        ██    ██          ██
  ...
```

### Guarda el token

**El token de administrador no se puede recuperar después.** Solo se guarda su hash en `users.json`. Si lo pierdes, hay que borrar `data/users.json` y repetir el alta, lo que invalida el MFA anterior.

### Registrar el MFA en el autenticador

Tienes tres formas, todas equivalentes:

**a) Escanear el QR del terminal.** Se dibuja directamente en la salida del comando. Apunta la cámara a la pantalla.

**b) Escanear el PNG.** El alta deja el fichero en `data/`, accesible desde el host:

```bash
ls -l data/admin-qr.png
```

Ábrelo con cualquier visor y escanéalo. Para llevártelo a otra máquina:

```bash
scp data/admin-qr.png tu-equipo:~/
```

**c) Introducir el secreto a mano.** En Google Authenticator o Authy, "Introducir clave de configuración" y pega el valor de `MFA secret`. El tipo es *basado en tiempo*.

### Después de registrarlo

Borra el PNG: contiene el secreto TOTP en claro.

```bash
shred -u data/admin-qr.png    # o: rm data/admin-qr.png
```

> El QR y el secreto son equivalentes a la segunda mitad de las credenciales. Trátalos como una contraseña: no los dejes en el disco ni los mandes por correo o chat.

## 5. Levantar el servicio

```bash
docker compose up -d
```

Comprueba el estado:

```bash
curl -s http://localhost:8001/healthz | jq .checks
```

Todas las comprobaciones deben dar `true`, y `zipalign_page_kb` debe valer 16:

```json
{
  "aapt_exists": true,
  "apksigner_jar_exists": true,
  "java": true,
  "keystore_exists": true,
  "work_writable": true,
  "zipalign_exists": true,
  "zipalign_page_kb": 16
}
```

El portal queda en `http://localhost:8001/` y la gestión de usuarios en `http://localhost:8001/admin`.

`docker compose ps` muestra el estado de salud del contenedor, que se comprueba cada 30 segundos contra `/healthz`.

## 6. Dar de alta más usuarios

Desde el panel de administración, con el token y el MFA del administrador. Cada usuario nuevo recibe su token y su QR en pantalla, sin tocar la línea de comandos.

## Actualizar

```bash
git pull
docker compose build
docker compose up -d
```

Los datos de `keystore/`, `data/`, `work/` y `logs/` sobreviven porque están montados desde el host. `secrets.json` tampoco se toca; si la nueva versión añade opciones, compáralo con `secrets.example.json`:

```bash
docker compose run --rm --entrypoint python3 apk-signer -c "
import json
ej = json.load(open('/opt/apk-signer/secrets.example.json'))
" && diff <(jq -S 'keys' secrets.example.json) <(jq -S 'keys' secrets.json)
```

## Diferencias con el despliegue de systemd

| | systemd | Docker |
|---|---|---|
| TLS | nginx con certificado, 80 → 443 | No incluido |
| Límites de peticiones | `limit_req` en nginx | No incluidos |
| Clave de sellado de la traza | Generada por `setup.sh` | Manual |
| Alta del administrador | Automática en la instalación | `docker compose run` |
| Aislamiento | Directivas de systemd | Aislamiento del contenedor |
| Actualización | `update.sh`, con copia y reversión | `build` + `up -d` |
| Rotación de la traza | `apk-signer-cleanup.timer` | No programada |

Los dos últimos puntos merecen atención en un despliegue prolongado: no hay reversión automática si la imagen nueva falla, y la traza no se rota sola. Para lo segundo, programa el `cleanup` desde el host:

```bash
docker compose exec apk-signer python3 tools/cleanup.py
```

## Problemas comunes

**`users.json` aparece como directorio.** Ocurre si se levanta el servicio antes de ejecutar el alta del administrador y una versión anterior del `compose` montaba el fichero directamente. Borra el directorio y repite el paso 4:

```bash
docker compose down
sudo rm -rf users.json
docker compose run --rm apk-signer python3 tools/bootstrap_users.py
```

**`keystore_exists: false`.** El keystore no está en `keystore/KeyStore.jks` o `KEYSTORE_PATH` no apunta a `/opt/apk-signer/keystore/KeyStore.jks`.

**`No existe users.json`.** Falta el paso 4, o `USERS_PATH` no apunta a `/opt/apk-signer/data/users.json`.

**La firma avisa de `"aligned": false`.** Comprueba que `ZIPALIGN` apunta a `/opt/android-sdk/build-tools/35.0.0/zipalign`, que es donde está dentro de la imagen. No copies ese binario a otro sitio: necesita las librerías de su directorio del SDK.

**Los ficheros de `data/` y `logs/` pertenecen a root.** El contenedor corre como root. Ajusta los permisos en el host si necesitas leerlos con tu usuario:

```bash
sudo chown -R "$USER" data logs work
```

El resto de problemas conocidos están en [RESUMEN_ERRORES.md](RESUMEN_ERRORES.md).
