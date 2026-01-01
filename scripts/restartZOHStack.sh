#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$HOME/Coding/Thesis/zigbee-on-host"
LOG_DIR="$HOME/Coding/Thesis/zigbee-fuzzer/.logs"
LOG_FILE="$LOG_DIR/dev-cli.log"
PID_FILE="$LOG_DIR/dev-cli.pid"
CMD=(npm run dev:cli -- --form yes)

mkdir -p "$LOG_DIR"
cd "$ROOT_DIR"

# pkill -f "npm run dev:cli"                  2>/dev/null || true
pkill -f "node dist/dev/cli.js form yes"    2>/dev/null || true
pkill -f "node dist/dev/cli.js form yes"    2>/dev/null || true
sleep 2

nohup npm run dev:cli form yes </dev/null >>"$LOG_FILE" 2>&1 & 
echo $! > "$PID_FILE"

echo "[restart] started, pid=$(cat "$PID_FILE")"
echo "[restart] tail -f $LOG_FILE"
