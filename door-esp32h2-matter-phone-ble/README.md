## Reader configuration update

H2 now generates and persists its own P-256 identity and initial `Door-XXXX` BLE
name. HAOS can download/pin the Manager public key and rename BLE over Matter;
see [HAOS setup](home-assistant/README.md). Firmware uses Manager protocol 2 and
requires the matching iOS update. No device has been flashed automatically.

# Door access: ESP32-H2, Matter over Thread and phone BLE

A prototype for phone-based access: the phone authenticates over BLE, the ESP32-H2 measures proximity and verifies the credential, then reports an authorized-access event through Matter over Thread.

- [`esp32-h2/`](esp32-h2/): firmware, build/flash tools and setup instructions.
- [`ios/`](ios/): SwiftUI/CoreBluetooth iPhone app and Xcode project.
- `android/`: reserved for a future Android app; not included yet.

The H2 needs **at least 4 MB flash** for this build. A Thread border router (such as a compatible IKEA DIRIGERA) and a Matter controller (such as Home Assistant) are required. Enrolling DIRIGERA's bridge in Home Assistant does not automatically enroll this device.

Current status: firmware compiles; native authentication/proximity tests passed during development. Matter commissioning, BLE/Thread coexistence and event reception still need validation on the physical H2 and controller. This is a development device, not a certified commercial Matter product.

The updated firmware uses DoorKey Manager protocol 2; the included iOS demo still uses the old local Python issuer flow and needs its corresponding enrollment/authorization update. Matter transport does not make authentication fully offline.

Private device/issuer keys and firmware binaries are deliberately excluded from Git. Follow the firmware README before building a fresh clone.
