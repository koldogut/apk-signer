# Instalación en Debian/Ubuntu

Guía detallada de instalación con systemd. Para la versión rápida y la operativa diaria, mira el [README](../README.md). Para contenedores, [DOCKER.md](DOCKER.md).

## Requisitos previos

* **Debian 12+ / Ubuntu 24.04+** si vas a usar el Python del sistema.
* **Python 3.11 o superior**. `setup.sh` aborta si encuentra una versión anterior.
* Salida a internet para descargar Android Command Line Tools y Build Tools.
* Un keystore JKS real con su alias y contraseñas.

Sobre Debian 11 o Ubuntu 22.04 necesitas instalar un Python 3.11 aparte:

```bash
sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt-get update && sudo apt-get install -y python3.11 python3.11-venv
```

## 1) Instalación automática con `setup.sh`

El script instala dependencias del sistema, descarga Android Build Tools, genera un certificado TLS autofirmado si no hay uno, crea el usuario administrador MFA, sella la traza de auditoría y habilita los servicios de systemd. Debe ejecutarse desde un clon local del repo.

```bash
git clone https://github.com/koldogut/apk-signer.git
cd apk-signer
sudo bash setup.sh
```

Variables opcionales:

```bash
SDK_ROOT=/opt/android-sdk \
BUILD_TOOLS_VERSION=35.0.0 \
TLS_CERT=/etc/ssl/apk-signer/apk-signer.crt \
TLS_KEY=/etc/ssl/apk-signer/apk-signer.key \
sudo bash setup.sh
```

> **Usa Build Tools 35 o superior.** Con versiones anteriores el alineado de las librerías nativas se queda en 4 KB, insuficiente para Android 15+, y el servicio lo avisa en cada firma.

### El instalador no es desatendido

`setup.sh` abre el aceptador de licencias de `sdkmanager` y espera respuesta. Para automatizarlo, acepta las licencias antes:

```bash
sudo ANDROID_SDK_ROOT=/opt/android-sdk \
  /opt/android-sdk/cmdline-tools/latest/bin/sdkmanager --licenses
```

Con las licencias aceptadas, esa fase del instalador termina sola.

### Después de instalar

1. **Guarda el token y el QR del administrador** que imprime `setup.sh`. No se pueden recuperar después; si los pierdes, hay que borrar `users.json` y volver a ejecutar el bootstrap.
2. Edita `/opt/apk-signer/secrets.json` con el alias y las contraseñas reales del keystore.
3. Copia tu keystore a `/opt/apk-signer/keystore/KeyStore.jks`.
4. Sustituye el certificado autofirmado por el corporativo en `/etc/ssl/apk-signer/`.
5. Reinicia y verifica:

```bash
sudo systemctl restart apk-signer
curl -s http://localhost:8001/healthz | jq .checks
```

Todas las comprobaciones deben salir en `true`. El portal queda en `https://localhost/` y la gestión de usuarios en `https://localhost/admin`.

### Qué deja configurado el instalador

| Ruta | Contenido |
|---|---|
| `/opt/apk-signer/` | Aplicación, `secrets.json`, `users.json`, `work/`, `logs/` |
| `/opt/android-sdk/` | Command Line Tools y Build Tools |
| `/etc/ssl/apk-signer/` | Certificado y clave TLS |
| `/etc/systemd/system/` | `apk-signer.service`, `apk-signer-cleanup.{service,timer}` |
| `/etc/nginx/sites-enabled/apk-signer` | Portal HTTPS con redirección desde el 80 |

`secrets.json` y `users.json` quedan en `0600` propiedad de `apk-signer`.

## 2) Actualización

`setup.sh` es para instalar desde cero. Para actualizar una instalación en marcha usa `update.sh`, que conserva configuración, usuarios, keystore y traza, hace copia de seguridad previa y revierte si el servicio no levanta:

```bash
cd apk-signer && git pull && sudo bash update.sh
```

Los detalles están en el apartado "Actualización de una instalación existente" del README.

## 3) Instalación manual (paso a paso)

Solo si no puedes usar `setup.sh`. El resultado equivalente exige bastante más cuidado.

### Dependencias del sistema

```bash
sudo apt-get update
sudo apt-get install -y git python3 python3-venv python3-pip openjdk-17-jre \
  curl unzip zip jq ca-certificates rsync nginx qrencode iproute2 chrony openssl
```

### Android Build Tools

```bash
sudo mkdir -p /opt/android-sdk/cmdline-tools
cd /opt/android-sdk/cmdline-tools
sudo curl -fL -o tools.zip \
  https://dl.google.com/android/repository/commandlinetools-linux-11479570_latest.zip
sudo unzip -q tools.zip && sudo mv cmdline-tools latest

export ANDROID_SDK_ROOT=/opt/android-sdk
yes | sudo -E /opt/android-sdk/cmdline-tools/latest/bin/sdkmanager --licenses
sudo -E /opt/android-sdk/cmdline-tools/latest/bin/sdkmanager \
  "platform-tools" "build-tools;35.0.0"
```

### Rutas de las herramientas

`aapt2` y `apksigner.jar` se pueden copiar a `/opt/apk-signer/tools/`. **`zipalign` no.**

```json
"AAPT": "/opt/apk-signer/tools/aapt2",
"APKSIGNER_JAR": "/opt/apk-signer/tools/apksigner.jar",
"ZIPALIGN": "/opt/android-sdk/build-tools/35.0.0/zipalign",
"ZIPALIGN_PAGE_KB": 16
```

> **No copies `zipalign` fuera del SDK.** Necesita las librerías de su propio directorio y fuera de ahí no arranca; la firma continúa pero sin alinear el APK. `aapt2` sí se puede copiar. Comprueba que el binario resuelve sus dependencias:
>
> ```bash
> ldd /opt/android-sdk/build-tools/35.0.0/zipalign | grep "not found"
> ```

### Keystore y secretos

```bash
sudo -u apk-signer cp secrets.example.json /opt/apk-signer/secrets.json
sudo chmod 600 /opt/apk-signer/secrets.json
```

Rellena el keystore:

```json
"KEYSTORE_PATH": "/opt/apk-signer/keystore/KeyStore.jks",
"KEY_ALIAS": "mi_alias",
"KS_PASS": "contraseña del keystore",
"KEY_PASS": "contraseña de la clave"
```

Y **genera la clave que sella la traza de auditoría**. Sin ella los eventos se registran sin MAC:

```bash
python3 -c "import os; print(os.urandom(32).hex())"
# copiar el valor a LOG_HMAC_KEY
```

### Entorno virtual

```bash
sudo -u apk-signer python3 -m venv /opt/apk-signer/.venv
sudo -u apk-signer /opt/apk-signer/.venv/bin/pip install -U pip
sudo -u apk-signer /opt/apk-signer/.venv/bin/pip install -r /opt/apk-signer/requirements.txt
```

### Usuario administrador MFA

```bash
sudo -u apk-signer /opt/apk-signer/.venv/bin/python /opt/apk-signer/tools/bootstrap_users.py
```

Guarda el token y el secreto que imprime.

### TLS y nginx

```bash
sudo mkdir -p /etc/ssl/apk-signer && sudo chmod 750 /etc/ssl/apk-signer
sudo openssl req -x509 -nodes -newkey rsa:2048 -days 825 \
  -keyout /etc/ssl/apk-signer/apk-signer.key \
  -out /etc/ssl/apk-signer/apk-signer.crt \
  -subj "/CN=$(hostname -f)" \
  -addext "subjectAltName=DNS:$(hostname -f),DNS:localhost,IP:127.0.0.1"
sudo chown root:www-data /etc/ssl/apk-signer/apk-signer.key
sudo chmod 640 /etc/ssl/apk-signer/apk-signer.key

sudo cp /opt/apk-signer/nginx/apk-signer.conf /etc/nginx/sites-available/apk-signer
sudo ln -sf /etc/nginx/sites-available/apk-signer /etc/nginx/sites-enabled/apk-signer
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl reload nginx
```

### Servicios

```bash
sudo cp /opt/apk-signer/systemd/*.service /opt/apk-signer/systemd/*.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now apk-signer.service apk-signer-cleanup.timer
```

### Arranque en modo desarrollo

Solo para desarrollo, sin nginx ni TLS por delante:

```bash
cd apk-signer
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python app.py          # escucha en 127.0.0.1:8001
```

Para llegar desde otra máquina: `APK_SIGNER_DEV_HOST=0.0.0.0 python app.py`. En producción arranca gunicorn desde systemd, nunca este servidor.

## 4) Verificación final

```bash
sudo systemctl status apk-signer.service nginx --no-pager
curl -s http://localhost:8001/healthz | jq .checks
curl -I http://localhost/          # 301 hacia https://
curl -kI https://localhost/        # 200
sudo systemd-analyze security apk-signer.service | tail -1
```

`/healthz` debe dar `true` en todo, y `zipalign_page_kb` debe valer 16. Si algo falla, [RESUMEN_ERRORES.md](RESUMEN_ERRORES.md) recoge los problemas conocidos con su causa y su remedio.
