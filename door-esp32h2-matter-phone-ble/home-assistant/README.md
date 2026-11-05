# DoorKey configuration from Home Assistant OS

The H2 has no Wi-Fi. Home Assistant downloads the Manager's **public** key through
HTTPS and sends it, together with the BLE name, through the existing authenticated
Matter-over-Thread connection. The H2's private key never leaves the device.

## Install

1. Flash the updated H2 firmware using `esp32-h2/tools/flash.sh` (normal flash, no
   erase). Existing Matter endpoint IDs are preserved; try the existing enrollment
   before removing/re-pairing anything.
2. Copy `custom_components/doorkey/` into HAOS `/config/custom_components/doorkey/`
   using your existing Studio Code Server, File editor or Samba setup.
3. Add this top-level configuration to `/config/configuration.yaml` and restart HA:

   ```yaml
   doorkey:
   ```

4. In **Developer tools → Actions**, select **DoorKey: Configure reader**. Select
   the H2 Matter device (not DIRIGERA), endpoint `1`, your BLE name (e.g. `Door-204`),
   Manager origin and expected public-key SHA-256.

   ```yaml
   action: doorkey.configure_reader
   data:
     device_id: YOUR_H2_HOME_ASSISTANT_DEVICE_ID
     endpoint: 1
     ble_name: Door-204
     manager_url: https://doorkey-staging.cloud.retreat480.com
     expected_sha256: 3db3c29fba4c846f252c3b48cd3fb07a8151a767d16ca53b5d9f3277935f0b53
   ```

   The fingerprint above is the staging Manager key, checked against the existing
   pinned iOS issuer key on 2026-11-05. SHA-256 is over the **65 raw public-key bytes**,
   not the hex text or a TLS certificate. For a different server/key, obtain its
   expected fingerprint independently from your operator configuration.

5. Watch UART: `[CONFIG] Saved BLE name=... and Manager public key`. BLE disconnects
   any current phone and restarts advertising with the new name. Allow a few seconds;
   iOS scanner caches may require disconnecting/scanning again. Run `IDENTITY` to
   print the reader public key and configured Manager fingerprint.
6. In ERA's room DoorKey settings, use the numerical **Door ID printed by IDENTITY**
   (random and persistent) and the **ESP32 public key**, not the Manager public key.

To rename BLE again without downloading/replacing the Manager key:

```yaml
action: doorkey.set_ble_name
data:
  device_id: YOUR_H2_HOME_ASSISTANT_DEVICE_ID
  endpoint: 1
  ble_name: Door-Entrance
```

Both actions are admin-only. They also work in scripts/automations. Normal HA device
registry renaming is separate: it does not write the H2's BLE name. These services
are configuration actions, not new configuration entities on the Matter device card.

Names allow 1–29 printable ASCII characters. This keeps legacy BLE scan responses
within their payload limit. The actions verify the selected device's DoorKey vendor/
product identity, refuse to overwrite unrelated labels, verify the Manager key point
and fingerprint, check Matter write status and read the saved labels back. Read-back
confirms Matter storage; the H2 applies settings on its next loop (about one second).

## Persistence / identity

- First boot generates a P-256 device key and a nonzero random 32-bit Door ID with
  the H2 random source and stores them in NVS, together with an initial `Door-XXXX`
  name derived from its public-key hash. Updating from the hardcoded-ID-12 firmware
  creates just the missing ID and preserves the existing key/name.
- Restart and normal firmware update reuse that identity. HA name/key changes do not
  regenerate the device private key. A malformed stored private key fails closed.
- No issuer key is trusted on a clean install until configured through Matter.
- Full chip erase destroys identity and enrollment. A Matter factory reset may also
  clear platform NVS; do not use it to rename the reader. Removing/re-pairing is not
  needed for a normal firmware update.
- The first update from the old static-key prototype creates a **new reader key**.
  ERA Manager reader registrations are immutable: if the old key was already saved,
  do not blindly replace it in the DB; use a newly configured test room or add an
  explicit revoke-and-replace workflow to Manager. Existing old phone permits stop working.

## Transport / verification limits

Uses standard UserLabel `endpoint/65/0`, already present on the Generic Switch,
so no custom Matter Server cluster definitions or extra endpoints are required.
The four labels are reserved for one encoded configuration record. Each label/value
is <=16 bytes. Record = version `1` + 2-hex name length + name + base64(uncompressed
65-byte key). Split into 30-byte parts; label `D0`..`D3` + first 14 bytes, value the
remaining <=16 bytes. H2 validates the full record and P-256 point before accepting.
Matter owns persistence of labels; H2 additionally persists the last accepted record.

Firmware is protocol **2**: it rejects the old `DoorKey-time-v1` proof. iOS still
needs the new enrollment/authorization flow before opening the door with Manager.
No lock GPIO or Matter access-event logic is changed by the configuration service.

Validated: firmware builds with Arduino ESP32 3.3.12, native C++ settings/proximity
checks, Python encoding/pin tests, and Python syntax checks. HA integration actions
are **not yet tested against your running HAOS**, and no board was flashed as part
of this change. Core Matter helpers are version-sensitive; report an HA traceback
if your version differs. Implementation references:

- https://github.com/matter-js/matterjs-server/blob/main/docs/websockets_api.md
- https://github.com/home-assistant/core/blob/dev/homeassistant/components/matter/helpers.py
- https://github.com/matter-js/python-matter-server/blob/main/matter_server/client/client.py
