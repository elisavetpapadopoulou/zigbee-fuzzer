BLUE_TAG="\033[1;34m"
BLUE_MSG="\033[0;34m"
GRAY="\033[90m"
RESET="\033[0m"
GREEN="\033[1;32m"
RED="\033[1;31m"
#!/usr/bin/env bash
set -euo pipefail

set -e
ROOT_DIR="$HOME/Coding/Thesis/hardware_setup"
LOG_DIR="$HOME/Coding/Thesis/zigbee-fuzzer/.logs"
LOG_FILE="$LOG_DIR/dev-cli.log"
PID_FILE="$LOG_DIR/dev-cli.pid"

BACKUP_FILE="$ROOT_DIR/baseline_backup.json"
PORT="/dev/ttyUSB0"

mkdir -p "$LOG_DIR"
cd "$ROOT_DIR"

echo -e "|           ${GRAY}[0/2] Stopping old coordinator app..."
pkill -f sonoff_coord_app.py || true
sleep 1

echo -e "|           ${GRAY}[1/2] Restoring coordinator baseline..."
python -m zigpy_znp.tools.network_restore "$PORT" -i "$BACKUP_FILE" >> "$LOG_FILE" 2>&1

echo -e "|           ${GRAY}[2/2] Starting coordinator app..."
python3 sonoff_coord_app.py >> "$LOG_FILE" 2>&1 &
echo $! > "$PID_FILE"

sleep 3
echo -e "|           ${GRAY}Done!${RESET}"
