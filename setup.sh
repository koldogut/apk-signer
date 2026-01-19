#!/usr/bin/env bash
set -euo pipefail

REPO_URL="${1:-}"
INSTALL_DIR="/opt/apk-signer"
USER_NAME="apk-signer"

if [[ -z "${REPO_URL}" ]]; then
  echo "Uso: sudo bash setup.sh <repo_url>"
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y git python3 python3-venv python3-pip openjdk-17-jre-headless curl unzip jq

if ! id -u "${USER_NAME}" >/dev/null 2>&1; then
  adduser --system --group --home "${INSTALL_DIR}" "${USER_NAME}"
fi

if [[ -d "${INSTALL_DIR}/.git" ]]; then
  sudo -u "${USER_NAME}" -H bash -lc "cd '${INSTALL_DIR}' && git pull --ff-only"
else
  rm -rf "${INSTALL_DIR}"
  sudo -u "${USER_NAME}" -H git clone "${REPO_URL}" "${INSTALL_DIR}"
fi

sudo -u "${USER_NAME}" -H python3 -m venv "${INSTALL_DIR}/.venv"
sudo -u "${USER_NAME}" -H "${INSTALL_DIR}/.venv/bin/pip" install -U pip
sudo -u "${USER_NAME}" -H "${INSTALL_DIR}/.venv/bin/pip" install -r "${INSTALL_DIR}/requirements.txt"

sudo -u "${USER_NAME}" -H mkdir -p \
  "${INSTALL_DIR}/work/sessions" \
  "${INSTALL_DIR}/logs" \
  "${INSTALL_DIR}/keystore" \
  "${INSTALL_DIR}/tools"

# log file must exist and be writable to avoid 500 on /inspect
sudo -u "${USER_NAME}" -H touch "${INSTALL_DIR}/logs/app.jsonl"

if [[ ! -f "${INSTALL_DIR}/secrets.json" ]]; then
  sudo -u "${USER_NAME}" -H cp "${INSTALL_DIR}/secrets.example.json" "${INSTALL_DIR}/secrets.json"
  echo "Creado ${INSTALL_DIR}/secrets.json (editar rutas/credenciales antes de arrancar)"
fi

cp "${INSTALL_DIR}/systemd/"*.service /etc/systemd/system/
cp "${INSTALL_DIR}/systemd/"*.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now apk-signer.service
systemctl enable --now apk-signer-cleanup.timer

echo "OK. Edita ${INSTALL_DIR}/secrets.json y copia apksigner.jar + KeyStore.jks reales."
