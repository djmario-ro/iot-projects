#!/bin/bash
set -euo pipefail
FIRMWARE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
PORT="${1:-}"
if [[ -z "$PORT" ]]; then
  shopt -s nullglob
  PORTS=(/dev/cu.usbmodem*)
  if [[ ${#PORTS[@]} -ne 1 ]]; then echo 'Specify the H2 serial port as the first argument.' >&2; exit 1; fi
  PORT="${PORTS[0]}"
fi
ESPTOOL="${ESPTOOL_BIN:-}"
if [[ -z "$ESPTOOL" ]]; then
  ESPTOOL="$(command -v esptool || true)"
  if [[ -z "$ESPTOOL" ]]; then
    shopt -s nullglob
    TOOLS=("$HOME"/Library/Arduino15/packages/esp32/tools/esptool_py/*/esptool)
    if [[ ${#TOOLS[@]} -gt 0 ]]; then ESPTOOL="${TOOLS[${#TOOLS[@]}-1]}"; fi
  fi
fi
if [[ ! -x "$ESPTOOL" ]]; then echo 'Set ESPTOOL_BIN to the esptool executable.' >&2; exit 1; fi
for IMAGE in esp32-h2.ino.bootloader.bin esp32-h2.ino.partitions.bin esp32-h2.ino.bin; do
  if [[ ! -f "$FIRMWARE_DIR/build/$IMAGE" ]]; then echo 'Run tools/build.sh before flashing.' >&2; exit 1; fi
done
# Read-only target/flash check before any write. Refuse a smaller H2.
FLASH_INFO="$("$ESPTOOL" --chip esp32h2 --port "$PORT" --no-stub flash-id)"
printf '%s\n' "$FLASH_INFO"
if ! printf '%s\n' "$FLASH_INFO" | grep -Eq 'Detected flash size: (4|8|16|32)MB'; then
  echo 'Stopped: Matter + BLE build requires at least 4 MB flash.' >&2; exit 1
fi
exec "$ESPTOOL" --chip esp32h2 --port "$PORT" --baud 115200 --no-stub \
  write-flash --no-compress --flash-mode dio --flash-freq 48m --flash-size 4MB \
  0x0 "$FIRMWARE_DIR/build/esp32-h2.ino.bootloader.bin" \
  0x8000 "$FIRMWARE_DIR/build/esp32-h2.ino.partitions.bin" \
  0x10000 "$FIRMWARE_DIR/build/esp32-h2.ino.bin"
