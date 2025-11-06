#!/bin/sh
set -eu

cd /app

echo "[entrypoint] Ensuring xray is installed..."
if ! command -v xray >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update && apt-get install -y --no-install-recommends curl unzip ca-certificates && rm -rf /var/lib/apt/lists/*
  fi
  TMP_DIR="/root/xray-setup"
  mkdir -p "$TMP_DIR"
  curl -fsSL -o "$TMP_DIR/xray.zip" https://github.com/XTLS/Xray-core/releases/download/v1.8.4/Xray-linux-64.zip
  unzip -o "$TMP_DIR/xray.zip" -d "$TMP_DIR"
  mv "$TMP_DIR/xray" /usr/local/bin/xray
  chmod +x /usr/local/bin/xray
  rm -rf "$TMP_DIR"
fi
echo "[entrypoint] xray version: $(xray -version || true)"

echo "[entrypoint] Downloading Go modules..."
go mod download

echo "[entrypoint] Starting server..."
exec go run ./cmd/server
