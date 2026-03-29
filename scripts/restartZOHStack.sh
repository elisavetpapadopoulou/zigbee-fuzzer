BLUE_TAG="\033[1;34m"
BLUE_MSG="\033[0;34m"
RESET="\033[0m"
GREEN="\033[1;32m"
RED="\033[1;31m"
RESET="\033[0m"
#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$HOME/Coding/Thesis/suts/zigbee-on-host"
LOG_DIR="$HOME/Coding/Thesis/zigbee-fuzzer/.logs"
LOG_FILE="$LOG_DIR/dev-cli.log"
PID_FILE="$LOG_DIR/dev-cli.pid"
CMD=(npm run dev:cli -- --form yes)

mkdir -p "$LOG_DIR"
cd "$ROOT_DIR"

# pkill -f "npm run dev:cli"                  2>/dev/null || true
pkill -f "node dist/dev/cli.js form yes"    2>/dev/null || true
pkill -f "node dist/dev/cli.js form yes"    2>/dev/null || true
rm -f "$ROOT_DIR/zoh.save"
sleep 5


nohup npm run dev:cli form yes </dev/null >>"$LOG_FILE" 2>&1 & 
echo $! > "$PID_FILE"

echo -e "${BLUE_TAG}[restart] ${BLUE_MSG}started, pid=$(cat "$PID_FILE")"
echo -e "${BLUE_TAG}[restart] ${BLUE_MSG}tail -f $LOG_FILE"
