# DoorKey for Android

Native Kotlin / Jetpack Compose companion to the iOS wallet, with the same ERA colors, QR enrollment, room cards, permit validity and BLE protocol v2. Requires **Android 12 or later**, Bluetooth LE and internet. No firmware or Home Assistant automation changes are required.

## Install and use

1. Install the debug APK on a physical Android phone. Android will ask you to allow installation from the app/browser used to open the APK. The APK is for testing; it is not a Google Play release.
2. Open DoorKey, tap **+**, allow the camera, and scan a **new** ERA check-in invitation. Invitations are single-use: the QR already redeemed by your iPhone cannot be reused. Alternatively paste the full invitation link.
3. Allow **Nearby devices** (Bluetooth), and notifications when requested. Leave **Acces automat** enabled. The persistent DoorKey notification means the background service is active.
4. Approach the H2. It measures proximity using its existing threshold and asks the app to authenticate. Every attempt is authorized online by DoorKey Manager. The existing Matter event then reaches HA.
5. Walk away to rearm before approaching again. Diagnostics includes the reader's raw/median/threshold readings and **Caută din nou**.

Disconnect the iPhone from the reader while testing Android: the prototype H2 accepts one BLE client at a time. The app maintains one reader connection and remembers the last verified reader; use **Diagnostic → Caută din nou** to switch readers. Automatic roaming between multiple connected doors is not implemented.

Background access uses a `connectedDevice` foreground service, not location tracking. It can continue while the screen is locked; reboot recovery is attempted after unlock. Force-stop, revoked Bluetooth permissions, disabled Bluetooth, vendor battery management, or Android restrictions can stop it. Reopen the app to resume; if necessary allow DoorKey unrestricted battery usage in system settings. Background behavior still needs testing on actual Android devices/OEMs. The notification's **Oprește** action disables automatic access.

## Build

Install JDK 21 and Android SDK platform 36 / build-tools 35.0.0 (Android Studio can install these). Point `ANDROID_HOME` at the SDK or create an ignored `local.properties` containing `sdk.dir=/absolute/path/to/sdk`.

```sh
cd android
./gradlew assembleDebug testDebugUnitTest lintDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

Open this directory in Android Studio to run on a USB-connected phone. The Gradle wrapper is committed. `assembleRelease`/`bundleRelease` produce unsigned release artifacts; configure a private release/upload signing key outside Git before distribution through Google Play. Keep that signing identity for future updates. Never commit a keystore or signing passwords.

## Identity and trust

- First launch creates a fresh P-256 signing key in Android Keystore. Private key material is never exported. App uninstall removes this installation's identity. It is independent of the iOS identity.
- The wallet is AES-256-GCM encrypted using another Android Keystore key, stored in `noBackupFilesDir`; app backups and device transfer are disabled.
- QR redemption and every access request use the same signed formats as iOS/H2. Permits, phone binding, reader certificates, signed challenges and online time proofs are checked locally before an AUTH frame is sent.
- The trusted Manager HTTPS origin and issuer public key are pinned in `Protocol.kt`. This build targets the current **staging** Manager. QR codes cannot replace the issuer key or redirect requests to another host. For another deployment, change both trust constants and rebuild.
- Access denied by the Manager disables that local permit. The user requests a new invitation from reception. Expired keys remain visible but cannot authorize.
- The phone displays **Acces autorizat** on the reader's matching `ACCEPT:<door ID>` response. This is not confirmation of the physical door position or a HA delivery acknowledgment.

JVM tests cover permit/phone/reader binding, expiry boundaries, unsigned 32-bit door IDs, invitation origin restrictions, nonce and permit binding of time proofs, final AUTH signatures and DER/raw ECDSA conversion. Build and lint do not replace an end-to-end test with a real phone, H2 and HA.
