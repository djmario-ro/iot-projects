# ESP32-H2 firmware: phone BLE and Matter over Thread

**Target:** ESP32-H2 with at least **4 MB flash**, Arduino ESP32 core **3.3.12**. The application is approximately 2.23 MB and cannot fit the 2 MB H2 variant.

## Behavior

1. Commission the H2 as a Matter-over-Thread Generic Switch.
2. After it has a Matter fabric and is attached to Thread, it advertises the custom phone BLE service.
3. The phone maintains a connection. H2 measures connection RSSI every 250 ms, using a five-sample median and stable-approach threshold.
4. H2 challenges the phone. It verifies an issuer-signed room permit, a nonce- and permit-bound signed authorization proof, and the phone's P-256 signature.
5. On success it schedules a Matter button click (InitialPress + ShortRelease). There is **no GPIO/lock actuation** in this firmware.

`ACCEPT:<Door ID>` reports successful local verification and event scheduling, not confirmation that Home Assistant received the event or opened a door. For an automation, select the press event only, not both press and release. Check the actual event received by HA before connecting an actuator; do not trigger from stale/restored entity state.

Protocol 2 requires the phone to reach DoorKey Manager for `/v1/authorize` on
each attempt. H2 verifies `DoorKey-time-v2` bound to SHA256(permit), without a v1
fallback. The iOS demo needs its corresponding update. H2 does not contact the
Manager directly: HA downloads the trusted public key and sends it over Matter;
the phone transports per-attempt authorization proofs over BLE.

## Build

Install Arduino CLI or Arduino IDE, then install **esp32 by Espressif Systems 3.3.12** through Boards Manager. The required Matter, NimBLE, Preferences and mbedTLS components are included. Do not add the Arduino BLE library or initialize a second BLE host: Matter owns NimBLE.

### Device identity and Manager trust

No `auth_keys.h` is needed or used. First boot generates the reader's P-256
private key, nonzero random 32-bit Door ID and initial `Door-XXXX` BLE name and saves them in NVS. Restart and
normal firmware update preserve them. The public key is printed at boot and by
`IDENTITY` / `STATUS`; the private key is never printed.

When updating the first dynamic-key firmware (which still used hardcoded ID 12),
only the missing Door ID is generated: the private key and BLE name are kept.
The same ID is used in signed challenges, permit checks and authorization results.
Random IDs are not mathematically guaranteed unique; Manager rejects a duplicate
registration instead of overwriting another reader. Never erase flash to rename.

On the first update from the old static-key prototype, a new identity is generated.
Register the new public key in ERA. Existing immutable reader mappings need a
revoke-and-replace workflow if they already contain the old prototype key.

Configure the BLE name and trusted Manager public key from HAOS using the
[DoorKey configuration integration](../home-assistant/README.md). H2 keeps the
last accepted name and issuer key in NVS. The clean-device state has no issuer
trusted and refuses access until configured. Never erase flash merely to rename.

The legacy `tools/generate_keys.py` utility is retained for old test material;
its files are not included by this firmware.

### Compile

```bash
bash tools/build.sh
```

The script uses Arduino CLI from PATH or the macOS Arduino IDE bundle. Set `ARDUINO_CLI` to a full executable path to override. It builds with:

```text
esp32:esp32:esp32h2:CDCOnBoot=default,FlashSize=4M,PartitionScheme=huge_app
```

Images go into ignored `build/`. No firmware binaries are committed because the application is built for local installation.

## Flash and serial console

Use the H2's native **USB** connector for flashing; its USB-to-UART bridge produced transfer errors during development. Close Serial Monitor/screen before flashing.

```bash
ls /dev/cu.*
bash tools/flash.sh /dev/cu.usbmodemXXXX
```

The script checks the target and flash capacity before writing. With no argument, it selects a port only when exactly one `/dev/cu.usbmodem*` exists. `ESPTOOL_BIN` can override the esptool executable. It uses `--no-stub`, does not erase all flash, and preserves the existing NVS commissioning data during normal updates.

For logs, move the cable to **UART** and open that port at **115200 baud**:

```bash
screen /dev/cu.usbmodemXXXX 115200
```

Press RESET to see startup output. Exit screen with Ctrl+A, K, Y. USB CDC is disabled in this build; logs use UART0. To keep logs on native USB, a separate build with CDC enabled is required.

Commands on the physical serial console:

- `PAIR`: prints the initial manual pairing code and QR URL; it does not reopen a closed commissioning window.
- `STATUS`: Matter, Thread, BLE and heap status.
- `THRESH -30`: sets the RSSI threshold until reset; edit `config.h` for a persistent build default.
- `FACTORY RESET`: removes Matter/Thread enrollment using the SDK reset path; commissioning must be repeated.

## Thread, Matter and pairing

**Thread** is the IPv6 radio mesh over IEEE 802.15.4. A **Thread Border Router** such as a compatible IKEA DIRIGERA routes between this mesh and the LAN. Thread is neither Wi-Fi nor Zigbee.

**Matter** is the application protocol and trust model running over IP. Here it runs over Thread. A Matter controller such as Home Assistant enrolls the H2 and subscribes to its standard events. DIRIGERA can also be a controller; that is a separate role from being a border router.

The QR payload (starting `MT:`) contains the setup passcode, discriminator and product/discovery information. The passcode bootstraps the initial secure commissioning channel; the discriminator helps identify the advertising device. Neither is the device's MAC address. The device name is a friendly label, not a credential.

During commissioning, a phone normally discovers the unconfigured device over BLE, opens a secure channel using the setup code, provides the Thread network dataset and installs the Matter fabric credentials. Operational Matter communication then uses Thread/IP. Discovering a device does not authorize it, and the Matter QR is unrelated to the guest's room-access credential.

### Adding to Home Assistant

1. Update DIRIGERA and confirm its Thread functionality. Existing IKEA devices visible in HA may be Zigbee devices exposed by DIRIGERA's Matter bridge; this does not prove Thread credentials are available to the phone.
2. Flash H2 and read the manual pairing code/QR URL from UART. The setup passcode/discriminator are generated locally and retained in NVS. Do not publish the setup code or full pairing logs.
3. In the Home Assistant iOS Companion app, add a **new Matter device** and use its QR/manual code. Menu labels vary by app version. The commissioner must know the Thread network credentials and be able to reach the border router.
4. A development-device trust warning can appear on iOS. This prototype uses development Matter attestation, not commercial product certification. IKEA app acceptance of this Generic Switch prototype is unverified.
5. Wait for H2 to appear online in HA and for `[MATTER] commissioned=1 thread=1` before testing access.
6. If it was enrolled first in IKEA, use that controller's **Matter sharing/Multi-Admin** workflow to add HA with the newly generated sharing code. Enrolling DIRIGERA's bridge in HA does not automatically enroll this independent H2 node.

A QR URL can send its payload to a web QR renderer when opened. Use the manual setup code if you want to keep that payload local.

## Phone protocol

This firmware preserves the current v2 phone GATT UUIDs and credential format:

- Service: `84961001-6e3a-4b9d-9ad0-781f506c1200`.
- Challenge READ: `84961002-6e3a-4b9d-9ad0-781f506c1200`.
- Command WRITE: `84961003-6e3a-4b9d-9ad0-781f506c1200`.
- Result READ/NOTIFY: `84961004-6e3a-4b9d-9ad0-781f506c1200`.
- RSSI telemetry READ/NOTIFY: `84961005-6e3a-4b9d-9ad0-781f506c1200` (`raw,median,threshold`).

After subscribing to Result, the phone writes opcode 5 (LISTEN). H2 sends READY only when proximity qualifies. The phone reads an 84-byte challenge: door LE32 + nonce16 + raw P-256 signature64 over `DoorKey-door-v1 || door || nonce`.

The authentication packet is 286 bytes:

- Permit150: version1 + door LE32 + notBefore LE64 + notAfter LE64 + phone public key X9.63(65) + issuer signature64 over the preceding 86 bytes.
- Time72: epoch LE64 + issuer signature64 over `DoorKey-time-v2 || door || nonce || epoch || SHA256(permit)`.
- Phone signature64 over `DoorKey-auth-v1 || door || nonce || SHA256(permit || time)`.

All signatures use ECDSA P-256/SHA-256, raw `r || s` format. Command opcode 1 resets the receive buffer, opcode 2 appends up to 19 bytes per write, opcode 3 verifies/consumes the challenge, and opcode 4 aborts. Use write-with-response. A challenge expires after 30 seconds and is consumed after a verification attempt, including failures.

## Proximity and background operation

Default threshold is -30 dBm, but ESP32 readings differ from iPhone scan readings; recalibrate. The serial command accepts -85 through -20 dBm and reports invalid values. At -30 dBm, rearming requires readings below -42 dBm. Five samples establish the median, followed by 800 ms of stable proximity. Final verification requires recent, sufficiently strong RSSI too. A successful attempt latches the gate until the median stays below threshold minus 12 dB for one second. Reconnection alone does not rearm it. Attempts are at least 10 seconds apart.

The current iOS prototype maintains BLE state restoration/background support. Its **Find another controller** button clears the remembered TTGO connection so it can discover H2 without replacing phone credentials. Locked-screen operation requires the background-capable key configuration and first unlock after reboot. iOS controls wakeups; force-quitting the app prevents reliable background behavior.

RSSI is an approximate proximity heuristic, not secure distance measurement or relay-attack protection. This prototype supports one connected phone and a global rearm state; multiple phones require per-credential session/rearm management.

## Validation and limitations

- Compiled with the installed Arduino ESP32 3.3.12 toolchain.
- Native proximity tests cover filtering, isolated spikes, stable approach, latch, reconnect, departure, cooldown, stale/missing RSSI and clock wrap.
- The updated configuration decoder is covered by portable C++ tests. HA transport/key fingerprint tests are in `../home-assistant/tests`; protocol 2 cryptographic integration still needs the updated mobile client and hardware testing.
- Native logic tests and a successful build do **not** validate radio coexistence, commissioning, event delivery, or iOS background execution. These still require physical testing.
- Matter's `click()` schedules an event; it does not acknowledge delivery or provide a transactional unlock request.
- The private door key is generated on the device and stored in NVS. Normal updates retain it; full flash erase loses the identity. HAOS configuration and restart persistence still require the hardware test after flashing.

Run the portable proximity test with a C++17 compiler:

```bash
c++ -std=c++17 -I. tests/proximity_test.cpp -o /tmp/doorkey-proximity-test
/tmp/doorkey-proximity-test
```

Official references:

- https://docs.espressif.com/projects/arduino-esp32/en/latest/matter/matter.html
- https://docs.espressif.com/projects/esp-matter/en/release-v1.4/esp32/faq.html
- https://www.home-assistant.io/integrations/matter/
