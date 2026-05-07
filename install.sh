#!/usr/bin/env bash
# Install the Rust testimonyd binary, default config, and systemd unit.

set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="${REPO_DIR}/rust/target/release"
DAEMON="${BIN_DIR}/testimonyd"
TESTCLIENT="${BIN_DIR}/testclient"
LIB="${BIN_DIR}/libtestimony.so"

if [[ ! -x "${DAEMON}" ]]; then
  echo "missing ${DAEMON}; build first with: make build" >&2
  exit 1
fi

sudo install -m 0755 "${DAEMON}" /usr/sbin/testimonyd

if [[ -x "${TESTCLIENT}" ]]; then
  sudo install -m 0755 "${TESTCLIENT}" /usr/local/bin/testimony_testclient
fi

if [[ -f "${LIB}" ]]; then
  sudo install -m 0644 "${LIB}" /usr/local/lib/libtestimony.so
  sudo install -m 0644 "${REPO_DIR}/c/testimony.h" /usr/local/include/testimony.h
  sudo ldconfig || true
fi

if [ ! -f /etc/testimony.conf ]; then
  sudo install -m 0644 "${REPO_DIR}/configs/testimony.conf" /etc/testimony.conf
fi

if [ ! -f /etc/systemd/system/testimony.service ]; then
  sudo install -m 0644 "${REPO_DIR}/configs/systemd.conf" /etc/systemd/system/testimony.service
  sudo systemctl daemon-reload || true
fi

sudo systemctl restart testimony || sudo service testimony restart || true
