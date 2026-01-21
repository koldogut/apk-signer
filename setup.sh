#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="/opt/apk-signer"
USER_NAME="apk-signer"
SDK_ROOT="${SDK_ROOT:-/opt/android-sdk}"
BUILD_TOOLS_VERSION="${BUILD_TOOLS_VERSION:-34.0.0}"
CMDLINE_ZIP_URL="https://dl.google.com/android/repository/commandlinetools-linux-11479570_latest.zip"
CMDLINE_ZIP_FALLBACK_URL="https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip"
CMDLINE_SHA256_URL="${CMDLINE_SHA256_URL:-}"
SDKMANAGER_BIN="${SDK_ROOT}/cmdline-tools/latest/bin/sdkmanager"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log() {
  echo "[apk-signer] $*"
}

warn() {
  echo "[apk-signer][WARN] $*" >&2
}

die() {
  echo "[apk-signer][ERROR] $*" >&2
  exit 1
}

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    die "Ejecuta este script como root (usa sudo)."
  fi
}

install_packages() {
  export DEBIAN_FRONTEND=noninteractive
  log "Instalando dependencias del sistema..."
  apt-get update
  apt-get install -y git python3 python3-venv python3-pip openjdk-17-jre curl unzip zip jq ca-certificates rsync nginx qrencode iproute2 chrony
}

cleanup_legacy_install() {
  if [[ -d "/etc/systemd/system/apk-signer.service.d" ]]; then
    log "Eliminando overrides antiguos de systemd..."
    rm -rf "/etc/systemd/system/apk-signer.service.d"
  fi

  if [[ -d "${INSTALL_DIR}/venv" ]]; then
    log "Eliminando entorno virtual antiguo ${INSTALL_DIR}/venv..."
    rm -rf "${INSTALL_DIR}/venv"
  fi

  if [[ -S "/run/apk-signer/uvicorn.sock" ]]; then
    log "Eliminando socket legado /run/apk-signer/uvicorn.sock..."
    rm -f "/run/apk-signer/uvicorn.sock"
  fi
}

ensure_user() {
  if ! id -u "${USER_NAME}" >/dev/null 2>&1; then
    log "Creando usuario del sistema ${USER_NAME}..."
    adduser --system --group --home "${INSTALL_DIR}" "${USER_NAME}"
  fi
}

sync_repo() {
  if [[ ! -d "${SCRIPT_DIR}/.git" ]]; then
    die "Ejecuta este script desde un clon del repo (no se encontró .git)."
  fi

  log "Sincronizando repo desde ${SCRIPT_DIR} a ${INSTALL_DIR}..."
  mkdir -p "${INSTALL_DIR}"
  rsync -a --delete \
    --exclude ".git" \
    --exclude ".venv" \
    --exclude "work" \
    --exclude "logs" \
    --exclude "keystore/KeyStore.jks" \
    --exclude "secrets.json" \
    "${SCRIPT_DIR}/" "${INSTALL_DIR}/"
  chown -R "${USER_NAME}:${USER_NAME}" "${INSTALL_DIR}"
}

verify_web_assets() {
  if [[ ! -f "${INSTALL_DIR}/static/index.html" ]]; then
    die "No se encontró ${INSTALL_DIR}/static/index.html. Revisa la sincronización del repo."
  fi

  if [[ ! -f "${INSTALL_DIR}/static/admin.html" ]]; then
    warn "No se encontró ${INSTALL_DIR}/static/admin.html. El portal de gestión puede no estar disponible."
  fi

  if [[ ! -f "${INSTALL_DIR}/nginx/apk-signer.conf" ]]; then
    warn "No se encontró ${INSTALL_DIR}/nginx/apk-signer.conf. nginx no se configurará."
  fi
}

install_python_deps() {
  log "Creando entorno virtual e instalando dependencias Python..."
  sudo -u "${USER_NAME}" -H python3 -m venv "${INSTALL_DIR}/.venv"
  sudo -u "${USER_NAME}" -H "${INSTALL_DIR}/.venv/bin/pip" install -U pip
  sudo -u "${USER_NAME}" -H "${INSTALL_DIR}/.venv/bin/pip" install -r "${INSTALL_DIR}/requirements.txt"
}

verify_cmdline_tools() {
  if [[ -x "${SDKMANAGER_BIN}" ]]; then
    return
  fi

  log "Descargando Android command line tools..."
  local tmp_dir
  local download_url=""
  local sha_url=""
  tmp_dir="$(mktemp -d)"

  for url in "${CMDLINE_ZIP_URL}" "${CMDLINE_ZIP_FALLBACK_URL}"; do
    if curl -fL -o "${tmp_dir}/cmdline-tools.zip" "${url}"; then
      download_url="${url}"
      break
    fi
    warn "No se pudo descargar command line tools desde ${url}"
  done

  if [[ -z "${download_url}" ]]; then
    die "No se pudo descargar command line tools. Configura CMDLINE_ZIP_URL y vuelve a ejecutar."
  fi

  if [[ -n "${CMDLINE_SHA256_URL}" ]]; then
    sha_url="${CMDLINE_SHA256_URL}"
  else
    sha_url="${download_url}.sha256"
  fi

  if curl -fsSL -o "${tmp_dir}/cmdline-tools.sha256" "${sha_url}"; then
    (cd "${tmp_dir}" && sha256sum -c cmdline-tools.sha256) || die "Checksum inválido para command line tools"
  else
    warn "No se pudo descargar checksum para command line tools (continuando)"
  fi

  mkdir -p "${SDK_ROOT}/cmdline-tools"
  unzip -q "${tmp_dir}/cmdline-tools.zip" -d "${SDK_ROOT}/cmdline-tools"
  if [[ -d "${SDK_ROOT}/cmdline-tools/cmdline-tools" ]]; then
    mv "${SDK_ROOT}/cmdline-tools/cmdline-tools" "${SDK_ROOT}/cmdline-tools/latest"
  fi
  rm -rf "${tmp_dir}"

  if [[ ! -x "${SDKMANAGER_BIN}" ]]; then
    die "No se encontró sdkmanager en ${SDKMANAGER_BIN}. Revisa la descarga de command line tools."
  fi
}

accept_android_licenses() {
  log "Se requiere aceptar licencias del Android SDK manualmente."
  log "Cuando se solicite, escribe 'y' para aceptar todas las licencias."
  verify_cmdline_tools
  export ANDROID_SDK_ROOT="${SDK_ROOT}"
  export PATH="${SDK_ROOT}/cmdline-tools/latest/bin:${PATH}"
  "${SDKMANAGER_BIN}" --licenses
}

install_android_build_tools() {
  log "Instalando Android build-tools ${BUILD_TOOLS_VERSION}..."
  verify_cmdline_tools

  export ANDROID_SDK_ROOT="${SDK_ROOT}"
  export PATH="${SDK_ROOT}/cmdline-tools/latest/bin:${PATH}"

  "${SDKMANAGER_BIN}" "platform-tools" "build-tools;${BUILD_TOOLS_VERSION}"

  chown -R "${USER_NAME}:${USER_NAME}" "${SDK_ROOT}"
}

prepare_dirs() {
  log "Creando carpetas de trabajo..."
  sudo -u "${USER_NAME}" -H mkdir -p \
    "${INSTALL_DIR}/work/sessions" \
    "${INSTALL_DIR}/logs" \
    "${INSTALL_DIR}/keystore" \
    "${INSTALL_DIR}/tools"

  sudo -u "${USER_NAME}" -H touch "${INSTALL_DIR}/logs/app.jsonl"
}

ensure_secrets() {
  if [[ ! -f "${INSTALL_DIR}/secrets.json" ]]; then
    sudo -u "${USER_NAME}" -H cp "${INSTALL_DIR}/secrets.example.json" "${INSTALL_DIR}/secrets.json"
    log "Creado ${INSTALL_DIR}/secrets.json (editar rutas/credenciales antes de arrancar)"
  fi
}

ensure_time_sync() {
  log "Verificando sincronización horaria..."
  if systemctl list-unit-files chrony.service >/dev/null 2>&1; then
    systemctl enable --now chrony || warn "No se pudo iniciar chrony"
  elif systemctl list-unit-files systemd-timesyncd.service >/dev/null 2>&1; then
    systemctl enable --now systemd-timesyncd || warn "No se pudo iniciar systemd-timesyncd"
  else
    warn "No se encontró un servicio de sincronización horaria disponible"
    return
  fi

  if command -v chronyc >/dev/null 2>&1; then
    if chronyc tracking >/dev/null 2>&1; then
      log "Sincronización horaria verificada con chrony."
    else
      warn "Chrony no reporta sincronización. Revisa chronyc tracking."
    fi
    return
  fi

  if timedatectl show -p NTPSynchronized --value 2>/dev/null | grep -q "yes"; then
    log "Sincronización horaria verificada con timedatectl."
  else
    warn "Timedatectl no reporta NTP sincronizado. Revisa timedatectl status."
  fi
}

bootstrap_admin_user() {
  log "Generando usuario administrador MFA..."
  sudo -u "${USER_NAME}" -H "${INSTALL_DIR}/.venv/bin/python" "${INSTALL_DIR}/tools/bootstrap_users.py"
}

update_secrets_paths() {
  local aapt_src="${SDK_ROOT}/build-tools/${BUILD_TOOLS_VERSION}/aapt2"
  local apksigner_src="${SDK_ROOT}/build-tools/${BUILD_TOOLS_VERSION}/lib/apksigner.jar"

  if [[ -f "${apksigner_src}" ]]; then
    sudo -u "${USER_NAME}" -H cp "${apksigner_src}" "${INSTALL_DIR}/tools/apksigner.jar"
  else
    warn "No se encontró apksigner.jar en ${apksigner_src}"
  fi

  if [[ -x "${aapt_src}" ]]; then
    sudo -u "${USER_NAME}" -H install -m 0755 "${aapt_src}" "${INSTALL_DIR}/tools/aapt2"
  else
    warn "No se encontró aapt2 en ${aapt_src}"
  fi

  if [[ -f "${INSTALL_DIR}/secrets.json" ]]; then
    local tmp_file
    tmp_file="$(mktemp)"
    jq \
      --arg aapt "${INSTALL_DIR}/tools/aapt2" \
      --arg apksigner "${INSTALL_DIR}/tools/apksigner.jar" \
      '.AAPT=$aapt | .APKSIGNER_JAR=$apksigner' \
      "${INSTALL_DIR}/secrets.json" > "${tmp_file}"
    mv "${tmp_file}" "${INSTALL_DIR}/secrets.json"
    chown "${USER_NAME}:${USER_NAME}" "${INSTALL_DIR}/secrets.json"
  fi
}

install_systemd_units() {
  log "Instalando servicios systemd..."
  systemctl stop apk-signer.service >/dev/null 2>&1 || true
  systemctl reset-failed apk-signer.service >/dev/null 2>&1 || true
  cp "${INSTALL_DIR}/systemd/"*.service /etc/systemd/system/
  cp "${INSTALL_DIR}/systemd/"*.timer /etc/systemd/system/
  systemctl daemon-reload
  systemctl enable --now apk-signer.service
  systemctl enable --now apk-signer-cleanup.timer
}

configure_nginx() {
  log "Configurando nginx para el portal web..."
  if [[ -f "${INSTALL_DIR}/nginx/apk-signer.conf" ]]; then
    cp "${INSTALL_DIR}/nginx/apk-signer.conf" /etc/nginx/sites-available/apk-signer
    ln -sf /etc/nginx/sites-available/apk-signer /etc/nginx/sites-enabled/apk-signer
    if [[ -f /etc/nginx/sites-enabled/default ]]; then
      rm -f /etc/nginx/sites-enabled/default
    fi
    nginx -t
    systemctl enable --now nginx
    systemctl reload nginx
  else
    warn "No se encontró la configuración de nginx en ${INSTALL_DIR}/nginx/apk-signer.conf"
  fi
}

check_service() {
  log "Verificando servicio apk-signer..."
  if systemctl is-active --quiet apk-signer.service; then
    log "Servicio apk-signer activo."
  else
    warn "Servicio apk-signer no está activo. Revisa logs con: journalctl -u apk-signer.service -n 200 --no-pager"
  fi

  if [[ -d "/etc/systemd/system/apk-signer.service.d" ]]; then
    warn "Se detectaron overrides en /etc/systemd/system/apk-signer.service.d. Revisa posibles configuraciones antiguas."
  fi

  if systemctl cat apk-signer.service | grep -q "gunicorn"; then
    log "Servicio usa gunicorn."
  else
    warn "El servicio no usa gunicorn. Revisa /etc/systemd/system/apk-signer.service."
  fi

  if ss -tulpn | grep -q ":8001"; then
    log "Puerto 8001 en escucha."
  else
    warn "No se detecta listener en el puerto 8001. Revisa systemd o firewall."
  fi

  if curl -fsS --max-time 5 http://localhost:8001/healthz >/dev/null; then
    log "Healthz OK: http://localhost:8001/healthz"
  else
    warn "Healthz no responde. Revisa el estado del servicio y permisos."
    warn "Últimos logs del servicio:"
    journalctl -u apk-signer.service -n 50 --no-pager || true
  fi
}

post_checks() {
  if [[ ! -f "${INSTALL_DIR}/keystore/KeyStore.jks" ]]; then
    warn "No hay keystore en ${INSTALL_DIR}/keystore/KeyStore.jks. Copia un JKS real y ajusta secrets.json."
  fi

  if [[ ! -x "${INSTALL_DIR}/tools/aapt2" ]]; then
    warn "aapt2 no está instalado o no es ejecutable. Revisa la instalación del SDK."
  fi

  if [[ ! -f "${INSTALL_DIR}/tools/apksigner.jar" ]]; then
    warn "apksigner.jar no está instalado. Revisa la instalación del SDK."
  fi
}

require_root
install_packages
cleanup_legacy_install
ensure_user
sync_repo
verify_web_assets
install_python_deps
accept_android_licenses
install_android_build_tools
prepare_dirs
ensure_secrets
update_secrets_paths
bootstrap_admin_user
ensure_time_sync
install_systemd_units
configure_nginx
check_service
post_checks

log "OK. Edita ${INSTALL_DIR}/secrets.json y copia un KeyStore.jks real antes de usar el servicio."
