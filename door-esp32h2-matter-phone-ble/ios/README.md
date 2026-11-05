# DoorKey iOS

SwiftUI and CoreBluetooth app for the v2 phone GATT protocol implemented by `../esp32-h2/`. Requires a physical iPhone with Secure Enclave and iOS 17+. No external package dependencies.

## Run

1. Open `DoorKey.xcodeproj` in Xcode.
2. Under the DoorKey target's **Signing & Capabilities**, select your development Team. Personal signing-team configuration is not checked in. The bundle identifier is `com.mario.doorkey.demo`; change it if needed.
3. Connect/trust the iPhone, enable Developer Mode if requested, choose it as the destination and Run.
4. Allow Bluetooth and local-network permissions.

Bluetooth testing requires physical hardware. A simulator build cannot verify radio operation or Secure Enclave behavior.

## Trust and initial enrollment

`DoorKey/TrustConfig.swift` contains only the public issuer/door keys and the default local test-server URL from the working prototype. No private signing keys or server enrollment tokens are checked in. The device-local firmware key retained in the original development checkout matches these public keys.

For a fresh firmware checkout, `../esp32-h2/tools/generate_keys.py` generates new local keys and `.local/trust-config.json`. Update the iOS `issuerPublic` and `doorPublic` values to match, and configure the issuer service with the corresponding issuer private key. Use X9.63 uncompressed P-256 public-key bytes, not PEM text or the private scalar.

The existing prototype issuer service runs on the Mac at port 8765. It is not in this repository yet. In the app, enter its reachable URL and the setup token it displays, then tap **Install / renew permit**. The test service issues a 24-hour permit for door 12 and supplies a signed-time proof for each authentication. Mac and phone must be able to communicate over the local network. This is a local development service, not a guest-facing production enrollment flow.

The phone generates its own P-256 signing key in Secure Enclave. Its protected key reference, signed permit and enrollment token are stored in Keychain with `AfterFirstUnlockThisDeviceOnly` accessibility. After restarting the phone, unlock it once before testing locked-screen use. This deliberately allows signing without per-operation biometrics after first unlock; private key material is not exported.

## Automatic operation

- Enable automatic access. The app connects to the known controller or scans for its service; it does not decide proximity from scan RSSI.
- ESP32 measures connection RSSI and notifies READY when proximity qualifies.
- The app verifies the signed door challenge, fetches issuer-signed time, signs the request and sends it in small write-with-response chunks.
- ESP32 validates everything and reports ACCEPT:12 or DENY:reason. ACCEPT is not an acknowledgement of delivery to HA or a physical door opening.
- The BLE connection stays active; ESP32 owns rearming after departure.

**Find another controller (H2 / TTGO)** clears only the remembered BLE peripheral, not the phone key or permit. Use it when switching development boards. For H2, Matter commissioning and Thread attachment must complete before the custom BLE service advertises.

When visible, the app shows RSSI telemetry measured by ESP32. Calibrate using the firmware's serial `THRESH -50` command; the old phone-side -50 dBm threshold is not equivalent.

## Background testing

The app declares `bluetooth-central`, creates its shared manager at application launch, restores CoreBluetooth state, and leaves reconnection pending with iOS. It subscribes to authentication requests; RSSI telemetry is unsubscribed in the background. A bounded background task covers the authentication exchange and local issuer request.

Run once, enroll the permit, and confirm a foreground exchange. Move away until the controller rearms, then return with the app backgrounded or the screen locked. For realistic suspension tests, launch from the app icon without the Xcode debugger attached. After stopping a debug session, launch the app manually once.

iOS schedules discovery/wakeups and can delay them. Force-quitting the app by swiping it away prevents reliable background behavior. Pending reconnection is implemented for the remembered controller; this prototype is not a multi-door roaming implementation.

Locked-screen execution, radio behavior and controller event reception still require testing on the actual phone/H2. A successful unsigned Xcode build does not prove those behaviors.

## Development limitations

The local server is still needed for every `/time` request. Local HTTP is allowed for the prototype and the server token is entered at runtime; production needs proper authenticated enrollment and HTTPS. The app does not implement PMS reservations, revocation or Android functionality.

See `../esp32-h2/README.md` for wire formats, UUIDs, Matter pairing and physical firmware setup.
