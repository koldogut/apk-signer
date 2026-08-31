#!/usr/bin/env bash
# Funciones compartidas por setup.sh (instalacion) y update.sh (actualizacion).
# Se carga con `source`, no se ejecuta directamente.

INSTALL_DIR="${INSTALL_DIR:-/opt/apk-signer}"
USER_NAME="${USER_NAME:-apk-signer}"
SDK_ROOT="${SDK_ROOT:-/opt/android-sdk}"
BUILD_TOOLS_VERSION="${BUILD_TOOLS_VERSION:-35.0.0}"
MIN_PYTHON_MAJOR=3
MIN_PYTHON_MINOR=11

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

require_python() {
  # 3.11 es el minimo: por debajo, pillow y click no tienen version parcheada
  # (los arreglos exigen 3.10+). Ver la nota del README.
  local version
  if ! command -v python3 >/dev/null 2>&1; then
    die "No se encontro python3."
  fi
  version="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
  if ! python3 -c "import sys; sys.exit(0 if sys.version_info >= (${MIN_PYTHON_MAJOR}, ${MIN_PYTHON_MINOR}) else 1)"; then
    die "Se requiere Python ${MIN_PYTHON_MAJOR}.${MIN_PYTHON_MINOR} o superior (detectado ${version}).
       En Debian 11 / Ubuntu 22.04 el Python del sistema es anterior: instala un
       ${MIN_PYTHON_MAJOR}.${MIN_PYTHON_MINOR} aparte (por ejemplo con deadsnakes) y vuelve a ejecutar con
       PATH apuntando a el."
  fi
  log "Python ${version} OK."
}

# Rutas de las herramientas del SDK.
#
# zipalign NO se copia fuera del SDK: enlaza dinamicamente contra
# lib64/libc++.so y, sacado de su directorio, falla con "error while loading
# shared libraries". aapt2 si se puede copiar porque va enlazado estaticamente.
# Version de build-tools realmente utilizable: la configurada si esta
# instalada, y si no la mas nueva que haya. Asi una instalacion antigua sigue
# funcionando aunque suba el valor por defecto.
resolve_build_tools() {
  if [[ -d "${SDK_ROOT}/build-tools/${BUILD_TOOLS_VERSION}" ]]; then
    echo "${BUILD_TOOLS_VERSION}"
    return
  fi
  local disponible
  disponible="$(ls -1 "${SDK_ROOT}/build-tools" 2>/dev/null | sort -V | tail -1)"
  if [[ -n "${disponible}" ]]; then
    warn "build-tools ${BUILD_TOOLS_VERSION} no esta instalada; se usa ${disponible}."
    echo "${disponible}"
  fi
}

sdk_zipalign() {
  local ver
  ver="$(resolve_build_tools)"
  [[ -n "${ver}" ]] && echo "${SDK_ROOT}/build-tools/${ver}/zipalign"
}

update_tool_paths() {
  local ver
  ver="$(resolve_build_tools)"
  [[ -n "${ver}" ]] || { warn "No hay build-tools instaladas en ${SDK_ROOT}."; return 0; }
  local aapt_src="${SDK_ROOT}/build-tools/${ver}/aapt2"
  local apksigner_src="${SDK_ROOT}/build-tools/${ver}/lib/apksigner.jar"
  local zipalign_src
  zipalign_src="$(sdk_zipalign)"

  if [[ -f "${apksigner_src}" ]]; then
    sudo -u "${USER_NAME}" -H cp "${apksigner_src}" "${INSTALL_DIR}/tools/apksigner.jar"
  else
    warn "No se encontro apksigner.jar en ${apksigner_src}"
  fi

  if [[ -x "${aapt_src}" ]]; then
    sudo -u "${USER_NAME}" -H install -m 0755 "${aapt_src}" "${INSTALL_DIR}/tools/aapt2"
  else
    warn "No se encontro aapt2 en ${aapt_src}"
  fi

  if [[ ! -x "${zipalign_src}" ]]; then
    warn "No se encontro zipalign en ${zipalign_src}. Los APK se firmaran sin alinear."
  fi

  # Se limpia una copia de zipalign de instalaciones anteriores: estaba rota.
  rm -f "${INSTALL_DIR}/tools/zipalign"

  if [[ -f "${INSTALL_DIR}/secrets.json" ]]; then
    local tmp_file
    tmp_file="$(mktemp)"
    jq \
      --arg aapt "${INSTALL_DIR}/tools/aapt2" \
      --arg apksigner "${INSTALL_DIR}/tools/apksigner.jar" \
      --arg zipalign "${zipalign_src}" \
      '.AAPT=$aapt | .APKSIGNER_JAR=$apksigner | .ZIPALIGN=$zipalign' \
      "${INSTALL_DIR}/secrets.json" > "${tmp_file}"
    mv "${tmp_file}" "${INSTALL_DIR}/secrets.json"
    chown "${USER_NAME}:${USER_NAME}" "${INSTALL_DIR}/secrets.json"
    chmod 0600 "${INSTALL_DIR}/secrets.json"
  fi
}

# Sella la traza de auditoria. Sin clave, los eventos se escriben sin MAC y
# cualquiera con acceso al fichero puede reescribirlos sin dejar rastro.
ensure_hmac_key() {
  local secrets="${INSTALL_DIR}/secrets.json"
  [[ -f "${secrets}" ]] || return 0

  local actual
  actual="$(jq -r '.LOG_HMAC_KEY // ""' "${secrets}")"

  # Se considera valida solo una clave hex de 64 caracteres. El valor de
  # ejemplo ("opcional_hex_64_chars") no lo es, y dejarlo hacia que la traza
  # quedara sin sellar sin que nadie se enterara.
  if [[ "${actual}" =~ ^[0-9a-fA-F]{64}$ ]]; then
    log "LOG_HMAC_KEY ya configurada."
    return 0
  fi

  local nueva tmp_file
  nueva="$(python3 -c 'import os; print(os.urandom(32).hex())')"
  tmp_file="$(mktemp)"
  jq --arg k "${nueva}" '.LOG_HMAC_KEY=$k' "${secrets}" > "${tmp_file}"
  mv "${tmp_file}" "${secrets}"
  chown "${USER_NAME}:${USER_NAME}" "${secrets}"
  chmod 0600 "${secrets}"
  log "Generada LOG_HMAC_KEY para sellar la traza de auditoria."
  warn "Los eventos anteriores a este momento no llevan MAC y apareceran como 'Sin MAC' al verificar."
}

# Anade a secrets.json las claves nuevas del ejemplo que aun no existan, sin
# tocar los valores ya configurados. Es lo que permite que una instalacion
# antigua reciba opciones nuevas al actualizar.
merge_new_secret_keys() {
  local secrets="${INSTALL_DIR}/secrets.json"
  local ejemplo="${INSTALL_DIR}/secrets.example.json"
  [[ -f "${secrets}" && -f "${ejemplo}" ]] || return 0

  local nuevas
  nuevas="$(jq -r --slurpfile cur "${secrets}" \
    'to_entries | map(select(.key as $k | ($cur[0] | has($k)) | not)) | map(.key) | join(", ")' \
    "${ejemplo}")"

  if [[ -z "${nuevas}" ]]; then
    log "secrets.json ya tiene todas las claves conocidas."
    return 0
  fi

  local tmp_file
  tmp_file="$(mktemp)"
  # El actual manda: solo se rellenan las claves ausentes.
  jq -s '.[0] * .[1]' "${ejemplo}" "${secrets}" > "${tmp_file}"
  mv "${tmp_file}" "${secrets}"
  chown "${USER_NAME}:${USER_NAME}" "${secrets}"
  chmod 0600 "${secrets}"
  log "Anadidas a secrets.json las claves nuevas: ${nuevas}"
}

# Espera a que el servicio responda. Devuelve 1 si no llega a levantar.
wait_for_health() {
  local intentos="${1:-30}"
  local i
  for ((i = 0; i < intentos; i++)); do
    if curl -fsS --max-time 3 http://127.0.0.1:8001/healthz >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

installed_version() {
  if [[ -f "${INSTALL_DIR}/.version" ]]; then
    cat "${INSTALL_DIR}/.version"
  else
    echo "desconocida"
  fi
}

record_version() {
  local commit="$1"
  echo "${commit}" > "${INSTALL_DIR}/.version"
  chown "${USER_NAME}:${USER_NAME}" "${INSTALL_DIR}/.version"
}
