# DoorKey iOS wallet

SwiftUI/CoreBluetooth app for the H2 + DoorKey Manager protocol 2. The design uses
ERA's night palette, serif headings, rounded cards and lime actions. The main screen
is a key wallet; BLE diagnostics live behind the top-right ellipsis menu.

## Use

1. Open `DoorKey.xcodeproj` in Xcode. Keep your development team/signing selection,
   choose the connected iPhone and Run (⌘R). Requires iOS 17+ and a physical iPhone
   with Secure Enclave. A simulator cannot enroll real credentials.
2. Empty wallet: **+** or **Scanează invitația** opens the camera. Allow camera and
   Bluetooth access. The QR comes from the ERA reservation **after check-in**.
   A pasted invitation link is available as an alternative inside the scanner.
3. The phone proves possession of its locally generated key and downloads its signed
   permit and certified reader public key. Invitation is one-use / ten minutes.
4. The card displays **Camera 204**, the property name, signed permit expiry in the
   property timezone, local validity and connection status. Room/property metadata
   comes from ERA through Manager; the BLE name is not a room display name.
5. With automatic access enabled, approach the reader. H2 measures proximity and
   sends a signed challenge. The phone requests `/v1/authorize`; Manager checks ERA
   live. H2 verifies the permit-bound approval and emits the existing Matter event.

There is no Mac Python server URL, shared enrollment token, `/permit` or `/time`
fallback. The Manager origin and issuer public key are pinned in `TrustConfig.swift`.
Untrusted QR origins, invalid certificates and redirects are rejected. QR invitation
secrets are not saved or logged. The app does not learn or export any private key.

## Keys and lifecycle

Private key generation uses Secure Enclave. The wrapped reference and wallet are
stored in Keychain with AfterFirstUnlockThisDeviceOnly accessibility. An installation
marker lives in the app container: a full uninstall/reinstall creates a new identity;
ordinary updates/restarts keep it. App offloading retains its container and identity.
Protected Keychain access failures do not silently replace keys; first-unlock delivery
retries loading credentials. Legacy local-test credentials are removed on migration.

Expired keys remain visible as expired. “În perioada de valabilitate” is based on
signed permit dates, not a promise that the booking has not been revoked since the
last online check. Manager refusal is shown as “Acces refuzat”; it never reports an
open door. Removing a card forgets that local permit; reception still manages server
revocation. A new QR is needed to enroll it again. One local permit per reader is kept.

Background Bluetooth/state restoration and a short background task during each
network authorization are retained. Unlock the phone once after reboot. Force-quitting
can prevent automatic operation; iOS controls wakeups and background time. The app
maintains one active BLE connection, reconnects the last verified reader and can
search again from Diagnostics. Multi-reader roaming while maintaining several
simultaneous BLE connections is not implemented.

## Validation

- Generic iPhone build: `xcodebuild -project DoorKey.xcodeproj -scheme DoorKey
  -destination 'generic/platform=iOS' -derivedDataPath /tmp/doorkey-build
  CODE_SIGNING_ALLOWED=NO build`.
- Native CryptoKit protocol checks: `python3 tests/run-protocol-tests.py` (macOS/Xcode).
  Exercises trusted QR parsing, signatures, reader certification, phone/nonce/permit
  binding, V1 rejection, unsigned 32-bit IDs and wallet encoding.
- No physical camera scan, Secure Enclave enrollment, BLE unlock or background
  relaunch has been verified on the phone as part of this source update. Run the
  signed app on the real iPhone for the end-to-end check.
