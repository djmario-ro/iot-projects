#!/bin/bash
set -euo pipefail
FIRMWARE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
CLI="${ARDUINO_CLI:-}"
if [[ -z "$CLI" ]]; then
  CLI="$(command -v arduino-cli || true)"
  if [[ -z "$CLI" ]]; then CLI='/Applications/Arduino IDE.app/Contents/Resources/app/lib/backend/resources/arduino-cli'; fi
fi
if [[ ! -x "$CLI" ]]; then echo 'Set ARDUINO_CLI to the Arduino CLI executable.' >&2; exit 1; fi
if [[ ! -f "$FIRMWARE_DIR/auth_keys.h" ]]; then
  echo 'Missing local keys. Run tools/generate_keys.py first; see README.md.' >&2; exit 1
fi
exec "$CLI" compile \
  --fqbn esp32:esp32:esp32h2:CDCOnBoot=default,FlashSize=4M,PartitionScheme=huge_app \
  --build-path "$FIRMWARE_DIR/build" "$FIRMWARE_DIR"
