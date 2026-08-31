#!/usr/bin/env bash
#
# Actualiza una instalacion existente de APK Signer.
#
#   cd apk-signer && git pull && sudo bash update.sh
#
# A diferencia de setup.sh, este script NO instala paquetes del sistema ni el
# SDK de Android: asume que ya estan. Actualiza el codigo, las dependencias
# Python y las unidades de systemd, conservando secrets.json, users.json, el
# keystore, la traza y las sesiones de trabajo.
#
# Si el servicio no vuelve a levantar, restaura el estado anterior.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

BACKUP_DIR="/var/backups/apk-signer"
KEEP_BACKUPS="${KEEP_BACKUPS:-5}"
SKIP_DEPS="${SKIP_DEPS:-0}"
BACKUP_PATH=""

require_install() {
  [[ -d "${INSTALL_DIR}" ]] || die "No hay ninguna instalacion en ${INSTALL_DIR}. Usa setup.sh para instalar."
  [[ -x "${INSTALL_DIR}/.venv/bin/python" ]] || die "No se encontro el entorno virtual en ${INSTALL_DIR}/.venv. Usa setup.sh."
  id -u "${USER_NAME}" >/dev/null 2>&1 || die "No existe el usuario ${USER_NAME}. Usa setup.sh."
  [[ -d "${SCRIPT_DIR}/.git" ]] || die "Ejecuta este script desde un clon del repo (no se encontro .git)."
  command -v jq >/dev/null 2>&1 || die "Falta jq. Instalalo con: apt-get install -y jq"
}

target_commit() {
  git -C "${SCRIPT_DIR}" rev-parse --short HEAD 2>/dev/null || echo "desconocido"
}

show_plan() {
  local actual objetivo
  actual="$(installed_version)"
  objetivo="$(target_commit)"
  log "Instalado: ${actual}"
  log "Objetivo:  ${objetivo}"
  if [[ "${actual}" == "${objetivo}" ]]; then
    log "Ya esta en esa version. Se reaplican codigo y dependencias de todos modos."
  fi
}

# Copia de seguridad de lo que no se puede reconstruir: configuracion,
# usuarios, keystore y traza. Las sesiones de trabajo se dejan fuera porque son
# temporales y pueden pesar cientos de MB.
make_backup() {
  mkdir -p "${BACKUP_DIR}"
  chmod 0700 "${BACKUP_DIR}"
  local stamp
  stamp="$(date -u +%Y%m%d-%H%M%S)"
  BACKUP_PATH="${BACKUP_DIR}/apk-signer-${stamp}.tar.gz"

  log "Copia de seguridad en ${BACKUP_PATH}..."
  tar -czf "${BACKUP_PATH}" \
    --exclude="./work/sessions" \
    --exclude="./.venv" \
    -C "${INSTALL_DIR}" . 2>/dev/null || die "No se pudo crear la copia de seguridad."
  chmod 0600 "${BACKUP_PATH}"

  # Se conservan las N ultimas.
  local sobrantes
  sobrantes="$(find "${BACKUP_DIR}" -maxdepth 1 -name 'apk-signer-*.tar.gz' -printf '%T@ %p\n' 2>/dev/null \
    | sort -rn | tail -n +$((KEEP_BACKUPS + 1)) | cut -d' ' -f2- || true)"
  if [[ -n "${sobrantes}" ]]; then
    echo "${sobrantes}" | xargs -r rm -f
    log "Copias antiguas eliminadas (se conservan ${KEEP_BACKUPS})."
  fi
}

restore_backup() {
  [[ -n "${BACKUP_PATH}" && -f "${BACKUP_PATH}" ]] || return 1
  warn "Restaurando ${BACKUP_PATH}..."
  systemctl stop apk-signer.service >/dev/null 2>&1 || true
  tar -xzf "${BACKUP_PATH}" -C "${INSTALL_DIR}"
  chown -R "${USER_NAME}:${USER_NAME}" "${INSTALL_DIR}"
  systemctl start apk-signer.service >/dev/null 2>&1 || true
}

sync_code() {
  log "Sincronizando codigo desde ${SCRIPT_DIR}..."
  # Los mismos excludes que setup.sh: nada de lo que sea estado se toca.
  rsync -a --delete \
    --exclude ".git" \
    --exclude ".venv" \
    --exclude "work" \
    --exclude "logs" \
    --exclude "keystore" \
    --exclude "secrets.json" \
    --exclude "users.json" \
    --exclude ".version" \
    --exclude "tests" \
    "${SCRIPT_DIR}/" "${INSTALL_DIR}/"
  chown -R "${USER_NAME}:${USER_NAME}" "${INSTALL_DIR}"
}

update_deps() {
  if [[ "${SKIP_DEPS}" == "1" ]]; then
    log "SKIP_DEPS=1: no se tocan las dependencias Python."
    return 0
  fi
  log "Actualizando dependencias Python..."
  sudo -u "${USER_NAME}" -H "${INSTALL_DIR}/.venv/bin/pip" install -q -U pip
  sudo -u "${USER_NAME}" -H "${INSTALL_DIR}/.venv/bin/pip" install -q -U -r "${INSTALL_DIR}/requirements.txt"
  log "Instaladas: $(sudo -u "${USER_NAME}" -H "${INSTALL_DIR}/.venv/bin/pip" list --format=freeze 2>/dev/null | grep -iE '^(flask|gunicorn|qrcode|pillow)=' | tr '\n' ' ')"
}

update_units() {
  log "Actualizando unidades de systemd y nginx..."
  cp "${INSTALL_DIR}/systemd/"*.service /etc/systemd/system/
  cp "${INSTALL_DIR}/systemd/"*.timer /etc/systemd/system/
  systemctl daemon-reload

  if [[ -f "${INSTALL_DIR}/nginx/apk-signer.conf" ]]; then
    cp "${INSTALL_DIR}/nginx/apk-signer.conf" /etc/nginx/sites-available/apk-signer
    if nginx -t >/dev/null 2>&1; then
      systemctl reload nginx
    else
      warn "La nueva configuracion de nginx no valida; se deja la anterior activa."
      nginx -t || true
    fi
  fi
}

restart_and_check() {
  log "Reiniciando el servicio..."
  systemctl restart apk-signer.service
  if wait_for_health 30; then
    log "Servicio arriba y respondiendo en /healthz."
    return 0
  fi
  return 1
}

post_report() {
  local version
  version="$(curl -fsS --max-time 3 http://127.0.0.1:8001/healthz 2>/dev/null \
    | python3 -c 'import json,sys; print(json.load(sys.stdin).get("version","?"))' 2>/dev/null || echo "?")"
  log "Version de la aplicacion: ${version}"

  local checks
  checks="$(curl -fsS --max-time 3 http://127.0.0.1:8001/healthz 2>/dev/null \
    | python3 -c '
import json, sys
c = json.load(sys.stdin)["checks"]
malos = [k for k, v in c.items() if v is False]
print(", ".join(malos) if malos else "todo OK")' 2>/dev/null || echo "?")"
  log "Comprobaciones: ${checks}"
}

main() {
  require_root
  require_install
  require_python
  show_plan
  make_backup

  log "Deteniendo el servicio..."
  systemctl stop apk-signer.service || true

  sync_code
  merge_new_secret_keys
  update_tool_paths
  ensure_hmac_key
  update_deps
  update_units

  if restart_and_check; then
    record_version "$(target_commit)"
    post_report
    log "OK. Actualizado a $(target_commit). Copia previa en ${BACKUP_PATH}"
  else
    warn "El servicio no respondio tras la actualizacion. Ultimos registros:"
    journalctl -u apk-signer.service -n 30 --no-pager || true
    restore_backup
    if wait_for_health 20; then
      die "Actualizacion revertida: el servicio anterior esta de nuevo en marcha."
    fi
    die "Actualizacion revertida, pero el servicio sigue sin responder. Revisa journalctl."
  fi
}

main "$@"
