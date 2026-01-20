# Instalación en Debian/Ubuntu

Esta guía permite clonar y ejecutar el proyecto en cualquier Debian/Ubuntu reciente.

## 1) Instalación automática con `setup.sh`

El script instala dependencias del sistema, descarga Android Build Tools públicos (`aapt2` y `apksigner.jar`), configura rutas por defecto y habilita systemd. Debe ejecutarse desde el clon local del repo.

```bash
git clone https://github.com/tu-org/apk-signer.git
cd apk-signer
sudo bash setup.sh
```

Variables opcionales:

```bash
SDK_ROOT=/opt/android-sdk BUILD_TOOLS_VERSION=34.0.0 sudo bash setup.sh
```

Después de ejecutar el script:

1. Guarda el token y el QR del administrador MFA que imprime `setup.sh` (necesarios para `/admin`).
2. Edita `/opt/apk-signer/secrets.json` con alias y contraseñas reales.
3. Copia tu `KeyStore.jks` a `/opt/apk-signer/keystore/KeyStore.jks`.
4. Verifica estado:

```bash
curl -s http://localhost:8001/healthz | jq
```

El archivo de usuarios MFA se crea en `/opt/apk-signer/users.json` y se administra desde `/admin`.

Comprobaciones adicionales recomendadas:

```bash
sudo systemctl status apk-signer.service --no-pager
sudo journalctl -u apk-signer.service -n 200 --no-pager
ss -tulpn | grep 8001
curl -I http://localhost:8001/
```

## 2) Instalación manual (paso a paso)

### Dependencias del sistema

```bash
sudo apt-get update
sudo apt-get install -y git python3 python3-venv python3-pip openjdk-17-jre-headless curl unzip jq ca-certificates rsync
```

### Android Build Tools (aapt2 + apksigner.jar)

Hay dos rutas posibles. Elige una:

#### Opción A: Android SDK Command Line Tools (recomendada)

1. Descarga e instala las tools oficiales:

```bash
mkdir -p $HOME/android-sdk/cmdline-tools
cd $HOME/android-sdk/cmdline-tools
curl -L -o tools.zip https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip
unzip tools.zip
mv cmdline-tools latest
```

2. Instala build-tools y platform-tools:

```bash
export ANDROID_SDK_ROOT=$HOME/android-sdk
export PATH=$ANDROID_SDK_ROOT/cmdline-tools/latest/bin:$PATH
yes | sdkmanager --licenses
sdkmanager "platform-tools" "build-tools;34.0.0"
```

3. Usa estas rutas en `secrets.json`:

```json
"AAPT": "$HOME/android-sdk/build-tools/34.0.0/aapt2",
"APKSIGNER_JAR": "$HOME/android-sdk/build-tools/34.0.0/lib/apksigner.jar"
```

#### Opción B: Copiar artefactos existentes

Si ya tienes `aapt2` y `apksigner.jar`, cópialos a una ruta fija (ej. `/opt/apk-signer/tools/`) y apunta `AAPT` y `APKSIGNER_JAR` a esas rutas.

### Keystore

Coloca un keystore real (JKS) y actualiza:

```json
"KEYSTORE_PATH": "/opt/apk-signer/keystore/KeyStore.jks",
"KEY_ALIAS": "mi_alias",
"KS_PASS": "mi_password",
"KEY_PASS": "mi_keypass"
```

### Configuración del proyecto

1. Clona el repo:

```bash
git clone https://github.com/tu-org/apk-signer.git
cd apk-signer
```

2. Crea y edita `secrets.json`:

```bash
cp secrets.example.json secrets.json
nano secrets.json
```

3. Crea un entorno virtual e instala dependencias:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -U pip
pip install -r requirements.txt
```

### Arranque (modo desarrollo)

```bash
. .venv/bin/activate
python app.py
```

La app quedará en `http://localhost:8001`.

### Arranque (modo servicio con systemd)

```bash
sudo bash setup.sh
```

El script crea el usuario `apk-signer`, instala dependencias, prepara rutas y habilita los servicios systemd.
