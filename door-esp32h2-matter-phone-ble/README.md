# Door access: ESP32-H2, Matter over Thread and phone BLE

A prototype for phone-based access: the phone authenticates over BLE, the ESP32-H2 measures proximity and verifies the credential, then reports an authorized-access event through Matter over Thread.

- [`esp32-h2/`](esp32-h2/): firmware, build/flash tools and setup instructions.
- [`ios/`](ios/): SwiftUI/CoreBluetooth iPhone app and Xcode project.
- `android/`: reserved for a future Android app; not included yet.

The H2 needs **at least 4 MB flash** for this build. A Thread border router (such as a compatible IKEA DIRIGERA) and a Matter controller (such as Home Assistant) are required. Enrolling DIRIGERA's bridge in Home Assistant does not automatically enroll this device.

Current status: firmware compiles; native authentication/proximity tests passed during development. Matter commissioning, BLE/Thread coexistence and event reception still need validation on the physical H2 and controller. This is a development device, not a certified commercial Matter product.

The current phone protocol also requests signed time from a local issuer service on the Mac. The issuer service is not included here yet; the iOS app is included. Matter transport does not make authentication fully offline.

Private device/issuer keys and firmware binaries are deliberately excluded from Git. Follow the firmware README before building a fresh clone.
