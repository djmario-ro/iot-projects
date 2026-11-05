import AVFoundation
import Combine
import CoreBluetooth
import CryptoKit
import Security
import SwiftUI
import UIKit

final class AppDelegate: NSObject, UIApplicationDelegate {
  func application(
    _ application: UIApplication,
    didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil
  ) -> Bool {
    _ = DoorBluetooth.shared
    return true
  }
}
@main struct DoorKeyApp: App {
  @UIApplicationDelegateAdaptor(AppDelegate.self) var appDelegate
  var body: some Scene { WindowGroup { ContentView() } }
}

enum KeyStore {
  static func read(_ name: String) -> Data? {
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: "DoorKey.v1", kSecAttrAccount as String: name,
      kSecReturnData as String: true, kSecMatchLimit as String: kSecMatchLimitOne,
    ]
    var value: CFTypeRef?
    return SecItemCopyMatching(query as CFDictionary, &value) == errSecSuccess
      ? value as? Data : nil
  }
  static func load(_ name: String) throws -> Data? {
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: "DoorKey.v1", kSecAttrAccount as String: name,
      kSecReturnData as String: true, kSecMatchLimit as String: kSecMatchLimitOne,
    ]
    var value: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &value)
    if status == errSecItemNotFound { return nil }
    guard status == errSecSuccess else {
      throw DemoError.message("Deblochează iPhone-ul pentru a încărca cheile (\(status)).")
    }
    return value as? Data
  }
  static func delete(_ name: String) {
    SecItemDelete(
      [
        kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: "DoorKey.v1",
        kSecAttrAccount as String: name,
      ] as CFDictionary)
  }
  static func save(_ data: Data, _ name: String) throws {
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: "DoorKey.v1", kSecAttrAccount as String: name,
    ]
    let status: OSStatus
    if read(name) != nil {
      status = SecItemUpdate(
        query as CFDictionary,
        [
          kSecValueData as String: data,
          kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ] as CFDictionary)
    } else {
      var item = query
      item[kSecValueData as String] = data
      item[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
      status = SecItemAdd(item as CFDictionary, nil)
    }
    if status != errSecSuccess { throw DemoError.message("Keychain: \(status)") }
  }
}
enum DemoError: LocalizedError {
  case message(String)
  var errorDescription: String? {
    if case .message(let s) = self { return s }
    return nil
  }
}
extension Data {
  var hex: String { map { String(format: "%02x", $0) }.joined() }
  func integer(_ offset: Int, _ count: Int) -> UInt64 {
    subdata(in: offset..<offset + count).enumerated().reduce(0) {
      $0 | (UInt64($1.element) << ($1.offset * 8))
    }
  }
}
final class DoorBluetooth: NSObject, ObservableObject, CBCentralManagerDelegate,
  CBPeripheralDelegate
{
  static let shared = DoorBluetooth()
  private let telemetryID = CBUUID(string: "84961005-6e3a-4b9d-9ad0-781f506c1200")
  private let serviceID = CBUUID(string: "84961001-6e3a-4b9d-9ad0-781f506c1200")
  private let challengeID = CBUUID(string: "84961002-6e3a-4b9d-9ad0-781f506c1200")
  private let commandID = CBUUID(string: "84961003-6e3a-4b9d-9ad0-781f506c1200")
  private let resultID = CBUUID(string: "84961004-6e3a-4b9d-9ad0-781f506c1200")
  private var central: CBCentralManager!
  private var active: CBPeripheral?
  private var challenge: CBCharacteristic?
  private var command: CBCharacteristic?
  private var result: CBCharacteristic?
  private var telemetry: CBCharacteristic?
  private var writingAuth = false
  private var authTask = UIBackgroundTaskIdentifier.invalid
  private var credentialError = false
  private var restoredNeedsDiscovery = false
  private var phoneKey: SecureEnclave.P256.Signing.PrivateKey?
  @Published private(set) var keys: [WalletKey] = []
  @Published var enrollmentError: String?
  @Published var selectedKeyID: String?
  private var authenticatingKeyID: String?
  private var credentialsLoaded = false
  private var unlockObserver: NSObjectProtocol?
  private var ignoredReaders: [UUID: Date] = [:]
  private var packets: [Data] = []
  private var session = UUID()
  private var sessionTimeout: DispatchWorkItem?
  private var ticker: Timer?
  private var foreground = false

  @Published var status = "Initializare…"
  @Published var available = false
  @Published var scanning = false
  @Published var connected = false
  @Published var busy = false
  @Published var enrolled = false
  @Published var enrolling = false
  @Published var automatic = UserDefaults.standard.object(forKey: "automaticV2") as? Bool ?? true
  @Published var controllerSignal = "Astept masuratori de pe ESP32"
  @Published var nonce = ""
  @Published var logs: [String] = []

  override init() {
    super.init()
    loadCredentials()
    unlockObserver = NotificationCenter.default.addObserver(
      forName: UIApplication.protectedDataDidBecomeAvailableNotification, object: nil, queue: .main
    ) { [weak self] _ in
      self?.loadCredentials()
    }
    central = CBCentralManager(
      delegate: self, queue: .main,
      options: [CBCentralManagerOptionRestoreIdentifierKey: "DoorKey.central.v2"])
    ticker = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
      self?.tick()
    }
  }
  private func log(_ value: String) {
    logs.insert("\(Date().formatted(date: .omitted, time: .standard))  \(value)", at: 0)
    if logs.count > 100 { logs.removeLast() }
  }
  private func loadCredentials() {
    guard !credentialsLoaded else { return }
    do {
      guard SecureEnclave.isAvailable else {
        throw DemoError.message("Cheile necesită un iPhone cu Secure Enclave.")
      }
      // Probe protected Keychain before interpreting a missing installation marker.
      let saved = try KeyStore.load("phoneKey.wallet.v3")
      let folder = try FileManager.default.url(
        for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
      let marker = folder.appendingPathComponent("DoorKey.installation.v3")
      let installed = FileManager.default.fileExists(atPath: marker.path)
      if !installed {
        KeyStore.delete("phoneKey.wallet.v3")
        KeyStore.delete("wallet.v3")
        KeyStore.delete("phoneKey.background.v2")
        KeyStore.delete("permit")
        KeyStore.delete("issuerToken")
      }
      if installed, let saved {
        phoneKey = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: saved)
      } else {
        guard
          let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, .privateKeyUsage, nil)
        else { throw DemoError.message("Nu pot configura cheia telefonului.") }
        let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
        try KeyStore.save(key.dataRepresentation, "phoneKey.wallet.v3")
        phoneKey = key
        if !installed {
          try Data(UUID().uuidString.utf8).write(
            to: marker, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
        }
      }
      if let data = try KeyStore.load("wallet.v3") {
        let savedKeys = try JSONDecoder().decode([WalletKey].self, from: data)
        guard savedKeys.allSatisfy({ validKey($0, current: false) }) else {
          throw DemoError.message("Cheile salvate nu pot fi verificate.")
        }
        keys = savedKeys
      }
      credentialsLoaded = true
      credentialError = false
      enrolled = keys.contains { validKey($0) && !$0.accessDenied }
      selectedKeyID = keys.first(where: { validKey($0) && !$0.accessDenied })?.id
      status = keys.isEmpty ? "Adaugă prima cheie" : "Cheile sunt pregătite"
      if central != nil { tick() }
    } catch {
      credentialError = true
      status = error.localizedDescription
      log(status)
    }
  }
  private func validKey(_ item: WalletKey, current: Bool = true) -> Bool {
    guard let phoneKey else { return false }
    return WalletProtocol.verify(
      item, phonePublic: phoneKey.publicKey.x963Representation, current: current)
  }
  private func saveKeys(_ updated: [WalletKey]) throws {
    try KeyStore.save(try JSONEncoder().encode(updated), "wallet.v3")
    keys = updated
    enrolled = keys.contains { validKey($0) && !$0.accessDenied }
  }
  func removeKey(_ id: String) {
    do {
      try saveKeys(keys.filter { $0.id != id })
      selectedKeyID = keys.first(where: { validKey($0) && !$0.accessDenied })?.id
      pauseConnection()
      tick()
    } catch { enrollmentError = error.localizedDescription }
  }
  func selectKey(_ id: String) {
    selectedKeyID = id
    findOtherController()
  }
  func enroll(invitation: String) {
    guard !enrolling, let phoneKey, credentialsLoaded else {
      enrollmentError = "Deblochează iPhone-ul pentru a încărca cheia telefonului."
      return
    }
    do {
      let invite = try WalletProtocol.invitation(invitation)
      pauseConnection()
      enrolling = true
      enrollmentError = nil
      Task { @MainActor in
        defer {
          enrolling = false
          tick()
        }
        do {
          let pub = phoneKey.publicKey.x963Representation
          let message = Data("DoorKey-redeem-v1".utf8) + Data(invite.utf8) + pub
          let sig = try phoneKey.signature(for: message).rawRepresentation
          let response: EnrollmentResponse = try await ManagerAPI.post(
            "/v1/redeem", body: ["invite": invite, "publicKey": pub.hex, "signature": sig.hex])
          guard response.protocolVersion == 2, let permit = Data(base64Encoded: response.permit),
            let publicKey = Data(hex: response.door.publicKey),
            let certificate = Data(base64Encoded: response.door.certificate)
          else { throw DemoError.message("Răspunsul Managerului nu este valid.") }
          let item = WalletKey(
            id: response.deviceId, permit: permit, doorID: response.door.id, doorPublic: publicKey,
            certificate: certificate, readerName: response.door.name, roomName: response.room?.name,
            propertyName: response.room?.propertyName, timezone: response.room?.timezone)
          guard validKey(item), response.validUntil == item.expiresAt else {
            throw DemoError.message("Permisul sau identitatea cititorului nu poate fi verificată.")
          }
          // Renewing one reader's key replaces its old local permit, not other doors.
          try saveKeys(keys.filter { $0.doorID != item.doorID } + [item])
          selectedKeyID = item.id
          UserDefaults.standard.removeObject(forKey: "knownDoorV2")
          status = "Cheie adăugată · \(item.title)"
          log(status)
        } catch {
          enrollmentError = error.localizedDescription
          status = "Cheia nu a fost adăugată"
        }
      }
    } catch { enrollmentError = error.localizedDescription }
  }
  func setForeground(_ value: Bool) {
    foreground = value
    if let active, let telemetry { active.setNotifyValue(value, for: telemetry) }
    tick()
  }
  func findOtherController() {
    UserDefaults.standard.removeObject(forKey: "knownDoorV2")
    pauseConnection()
    status = "Caut cititorul ușii…"
    log(status)
    tick()
  }
  func modeChanged() {
    UserDefaults.standard.set(automatic, forKey: "automaticV2")
    if !automatic { pauseConnection() } else { tick() }
  }
  private func endBackgroundWork() {
    if authTask != .invalid {
      UIApplication.shared.endBackgroundTask(authTask)
      authTask = .invalid
    }
  }
  private func beginBackgroundWork() {
    endBackgroundWork()
    authTask = UIApplication.shared.beginBackgroundTask(withName: "DoorKey authentication") {
      [weak self] in
      self?.abortAuthentication("iOS a oprit timpul de executie")
    }
  }
  private func abortAuthentication(_ message: String) {
    log(message)
    status = message
    busy = false
    writingAuth = false
    packets = []
    authenticatingKeyID = nil
    session = UUID()
    sessionTimeout?.cancel()
    endBackgroundWork()
    if let active, let command { active.writeValue(Data([4]), for: command, type: .withResponse) }
  }
  private func pauseConnection() {
    stopScan()
    if let active { central.cancelPeripheralConnection(active) }
    clearSession()
  }
  private func clearSession() {
    sessionTimeout?.cancel()
    session = UUID()
    active?.delegate = nil
    active = nil
    challenge = nil
    command = nil
    result = nil
    telemetry = nil
    packets = []
    writingAuth = false
    endBackgroundWork()
    connected = false
    busy = false
    authenticatingKeyID = nil
    restoredNeedsDiscovery = false
  }
  private func tick() {
    enrolled = keys.contains { validKey($0) && !$0.accessDenied }
    guard automatic, available, enrolled, !enrolling, !credentialError else { return }
    guard active == nil else { return }
    if let saved = UserDefaults.standard.string(forKey: "knownDoorV2"),
      let id = UUID(uuidString: saved),
      let known = central.retrievePeripherals(withIdentifiers: [id]).first
    {
      connect(known)
    } else if !scanning {
      scan()
    }
  }
  func centralManager(_ central: CBCentralManager, willRestoreState dict: [String: Any]) {
    let restoredList = dict[CBCentralManagerRestoredStatePeripheralsKey] as? [CBPeripheral] ?? []
    guard automatic, enrolled else {
      for peripheral in restoredList { central.cancelPeripheralConnection(peripheral) }
      return
    }
    guard let restored = restoredList.first else { return }
    active = restored
    restored.delegate = self
    log("Conexiune BLE restaurata de iOS")
    connected = restored.state == .connected
    restoredNeedsDiscovery = true
  }
  func centralManagerDidUpdateState(_ central: CBCentralManager) {
    available = central.state == .poweredOn
    status =
      available ? "Bluetooth pregatit" : "Bluetooth indisponibil; verifica permisiunea si setarile."
    log(status)
    if available {
      if restoredNeedsDiscovery, let active {
        restoredNeedsDiscovery = false
        if active.state == .connected {
          active.discoverServices([serviceID])
        } else if active.state == .disconnected {
          central.connect(active, options: nil)
        }
      }
      tick()
    } else {
      pauseConnection()
    }
  }
  func scan() {
    guard available, automatic, enrolled, active == nil else { return }
    central.scanForPeripherals(withServices: [serviceID], options: nil)
    scanning = true
    status = "Caut controllerul BLE…"
  }
  func stopScan() {
    central?.stopScan()
    scanning = false
  }
  func centralManager(
    _ central: CBCentralManager, didDiscover peripheral: CBPeripheral,
    advertisementData: [String: Any], rssi RSSI: NSNumber
  ) {
    guard automatic, enrolled, !enrolling, active == nil else { return }
    if let until = ignoredReaders[peripheral.identifier], until > Date() { return }
    let name =
      advertisementData[CBAdvertisementDataLocalNameKey] as? String ?? peripheral.name ?? "Usa BLE"
    log("Gasit \(name). Conectez fara prag RSSI pe telefon.")
    connect(peripheral)
  }
  private func connect(_ peripheral: CBPeripheral) {
    guard automatic, enrolled else { return }
    stopScan()
    active = peripheral
    peripheral.delegate = self
    session = UUID()
    status = "Conectare BLE; astept apropierea masurata de ESP32…"
    log(status)
    // Leave pending reconnect with iOS; do not use a timer-dependent scan loop in background.
    central.connect(peripheral, options: nil)
  }
  private func fail(_ message: String) {
    status = message
    log(message)
    if let active { central.cancelPeripheralConnection(active) }
    clearSession()
  }
  func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
    guard peripheral === active else { return }
    connected = true
    peripheral.discoverServices([serviceID])
  }
  func centralManager(
    _ central: CBCentralManager, didFailToConnect peripheral: CBPeripheral, error: Error?
  ) {
    guard peripheral === active else { return }
    fail(error?.localizedDescription ?? "Conectare esuata")
  }
  func centralManager(
    _ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral, error: Error?
  ) {
    guard peripheral === active else { return }
    let previous = peripheral
    status = "Conexiune pierduta; astept revenirea usii."
    log(status)
    clearSession()
    if automatic, enrolled, !enrolling, available {
      if ignoredReaders[previous.identifier] == nil { connect(previous) } else { tick() }
    }
  }
  func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
    guard peripheral === active else { return }
    if let error {
      fail(error.localizedDescription)
      return
    }
    guard let service = peripheral.services?.first(where: { $0.uuid == serviceID }) else {
      fail("Serviciu lipsa")
      return
    }
    peripheral.discoverCharacteristics(
      [challengeID, commandID, resultID, telemetryID], for: service)
  }
  func peripheral(
    _ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService, error: Error?
  ) {
    guard peripheral === active else { return }
    if let error {
      fail(error.localizedDescription)
      return
    }
    challenge = service.characteristics?.first(where: { $0.uuid == challengeID })
    command = service.characteristics?.first(where: { $0.uuid == commandID })
    result = service.characteristics?.first(where: { $0.uuid == resultID })
    telemetry = service.characteristics?.first(where: { $0.uuid == telemetryID })
    guard challenge != nil, command != nil, let result, let telemetry else {
      fail("Actualizeaza firmware-ul ESP32 proximity v2")
      return
    }
    peripheral.setNotifyValue(true, for: result)
    peripheral.setNotifyValue(foreground, for: telemetry)
    status = "Conectat. ESP32 decide apropierea."
  }
  func peripheral(
    _ peripheral: CBPeripheral, didUpdateNotificationStateFor characteristic: CBCharacteristic,
    error: Error?
  ) {
    guard peripheral === active else { return }
    if let error {
      fail(error.localizedDescription)
      return
    }
    if characteristic.uuid == resultID, characteristic.isNotifying, let command {
      peripheral.writeValue(Data([5]), for: command, type: .withResponse)
    }
  }
  func peripheral(
    _ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: Error?
  ) {
    guard peripheral === active else { return }
    if let error {
      fail(error.localizedDescription)
      return
    }
    guard let data = characteristic.value else {
      fail("Raspuns gol")
      return
    }
    if characteristic.uuid == telemetryID {
      if let text = String(data: data, encoding: .utf8) {
        let values = text.split(separator: ",")
        if values.count == 3 {
          controllerSignal = "ESP32: raw \(values[0]), median \(values[1]), prag \(values[2]) dBm"
        }
      }
      return
    }
    if characteristic.uuid == resultID {
      let text = String(data: data, encoding: .utf8) ?? "Raspuns invalid"
      log("ESP32: \(text)")
      if text == "READY", !busy, let challenge {
        session = UUID()
        busy = true
        beginBackgroundWork()
        let work = DispatchWorkItem { [weak self] in
          self?.abortAuthentication("Autentificarea a expirat")
        }
        sessionTimeout = work
        DispatchQueue.main.asyncAfter(deadline: .now() + 20, execute: work)
        status = "ESP32 detecteaza apropierea. Autentificare…"
        peripheral.readValue(for: challenge)
      } else if busy, text.hasPrefix("ACCEPT:"), let keyID = authenticatingKeyID,
        let item = keys.first(where: { $0.id == keyID }), text == "ACCEPT:\(item.doorID)"
      {
        if let index = keys.firstIndex(where: { $0.id == keyID }) {
          var updated = keys
          updated[index].lastAuthorized = Date()
          updated[index].accessDenied = false
          try? saveKeys(updated)
        }
        status = "Acces autorizat · indeparteaza telefonul pentru rearmare"
        busy = false
        writingAuth = false
        packets = []
        session = UUID()
        sessionTimeout?.cancel()
        endBackgroundWork()
      } else if text.hasPrefix("DENY:") {
        status = text
        busy = false
        writingAuth = false
        packets = []
        session = UUID()
        sessionTimeout?.cancel()
        endBackgroundWork()
      } else if text != "READY" {
        status =
          text == "LATCHED" ? "Astept indepartarea telefonului" : "Conectat · astept apropierea"
      }
      return
    }
    guard characteristic.uuid == challengeID, let phoneKey else {
      fail("Permisul nu este disponibil")
      return
    }
    let currentSession = session
    Task { @MainActor in
      do {
        guard data.count == 84 else {
          throw DemoError.message("Provocarea cititorului nu este validă.")
        }
        let id = UInt32(data.integer(0, 4))
        guard let item = keys.first(where: { $0.doorID == id && validKey($0) && !$0.accessDenied })
        else {
          ignoredReaders[peripheral.identifier] = Date().addingTimeInterval(30)
          UserDefaults.standard.removeObject(forKey: "knownDoorV2")
          fail("Nu ai o cheie activă pentru acest cititor.")
          tick()
          return
        }
        guard WalletProtocol.verifyChallenge(data, key: item) else {
          throw DemoError.message("Identitatea ușii nu este validă.")
        }
        let door = Data(data.prefix(4))
        let random = data.subdata(in: 4..<20)
        let permitHash = Data(SHA256.hash(data: item.permit))
        nonce = random.hex
        authenticatingKeyID = item.id
        selectedKeyID = item.id
        UserDefaults.standard.set(peripheral.identifier.uuidString, forKey: "knownDoorV2")
        let signed = Data("DoorKey-authorize-v2".utf8) + permitHash + data
        let signature = try phoneKey.signature(for: signed).rawRepresentation
        let response: AuthorizationResponse
        do {
          response = try await ManagerAPI.post(
            "/v1/authorize",
            body: [
              "permit": item.permit.base64EncodedString(), "challenge": data.hex,
              "signature": signature.hex,
            ])
        } catch ManagerError.denied {
          if let index = keys.firstIndex(where: { $0.id == item.id }) {
            var updated = keys
            updated[index].accessDenied = true
            try saveKeys(updated)
          }
          throw DemoError.message("Acces refuzat. Contactează recepția pentru verificarea cheii.")
        }
        guard currentSession == session, automatic else { return }
        guard response.protocolVersion == 2,
          let timeProof = Data(base64Encoded: response.timeProof), timeProof.count == 72
        else { throw DemoError.message("Autorizarea Managerului nu este validă.") }
        guard WalletProtocol.verifyApproval(timeProof, key: item, nonce: random) else {
          throw DemoError.message("Semnătura autorizării nu este validă sau permisul a expirat.")
        }
        let body = item.permit + timeProof
        let finalMessage =
          Data("DoorKey-auth-v1".utf8) + door + random + Data(SHA256.hash(data: body))
        let auth = body + (try phoneKey.signature(for: finalMessage).rawRepresentation)
        packets = [Data([1])]
        for offset in stride(from: 0, to: auth.count, by: 19) {
          packets.append(Data([2]) + auth.subdata(in: offset..<min(offset + 19, auth.count)))
        }
        packets.append(Data([3]))
        writingAuth = true
        sendNext()
      } catch {
        if currentSession == session {
          abortAuthentication(error.localizedDescription)
          if !enrolled { pauseConnection() }
        }
      }
    }
  }
  private func sendNext() {
    guard let active, let command else { return }
    if packets.isEmpty {
      writingAuth = false
      return
    }
    active.writeValue(packets.removeFirst(), for: command, type: .withResponse)
  }
  func peripheral(
    _ peripheral: CBPeripheral, didWriteValueFor characteristic: CBCharacteristic, error: Error?
  ) {
    guard peripheral === active else { return }
    if let error {
      fail(error.localizedDescription)
      return
    }
    if writingAuth { sendNext() }
  }
}

struct WalletKey: Codable, Identifiable {
  let id: String
  let permit: Data
  let doorID: UInt32
  let doorPublic: Data
  let certificate: Data
  let readerName: String
  let roomName: String?
  let propertyName: String?
  let timezone: String?
  var lastAuthorized: Date? = nil
  var accessDenied = false
  var expiresAt: UInt64 { permit.count == 150 ? permit.integer(13, 8) : 0 }
  var expiration: Date { Date(timeIntervalSince1970: TimeInterval(expiresAt)) }
  var title: String {
    if let roomName, !roomName.isEmpty { return "Camera \(roomName)" }
    return "Cheie de acces"
  }
  var expired: Bool { Date() >= expiration }
}
struct EnrollmentResponse: Decodable {
  struct Door: Decodable {
    let id: UInt32
    let name: String
    let publicKey: String
    let certificate: String
  }
  struct Room: Decodable {
    let name: String?
    let propertyName: String?
    let timezone: String?
  }
  let deviceId: String
  let protocolVersion: Int
  let permit: String
  let validUntil: UInt64
  let door: Door
  let room: Room?
  enum CodingKeys: String, CodingKey {
    case deviceId, permit, validUntil, door, room
    case protocolVersion = "protocol"
  }
}
struct AuthorizationResponse: Decodable {
  let protocolVersion: Int
  let timeProof: String
  enum CodingKeys: String, CodingKey {
    case timeProof
    case protocolVersion = "protocol"
  }
}
extension Data {
  init?(hex: String) {
    guard hex.count % 2 == 0, hex.allSatisfy({ $0.isHexDigit }) else { return nil }
    var output = Data()
    var index = hex.startIndex
    while index < hex.endIndex {
      let end = hex.index(index, offsetBy: 2)
      guard let byte = UInt8(hex[index..<end], radix: 16) else { return nil }
      output.append(byte)
      index = end
    }
    self = output
  }
}
enum WalletProtocol {
  static func invitation(_ input: String) throws -> String {
    guard let url = URLComponents(string: input.trimmingCharacters(in: .whitespacesAndNewlines)),
      let trusted = URLComponents(string: TrustConfig.managerOrigin), url.scheme == "https",
      url.host?.lowercased() == trusted.host?.lowercased(),
      url.port == nil || url.port == 443, url.user == nil, url.password == nil,
      url.path == "/enroll", url.query == nil, let fragment = url.fragment,
      let items = URLComponents(string: "https://invitation.invalid/?" + fragment)?.queryItems,
      items.count == 1,
      items[0].name == "invite", let token = items[0].value, token.count == 43,
      token.unicodeScalars.allSatisfy({
        CharacterSet(
          charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
        ).contains($0)
      })
    else {
      throw DemoError.message("Scanează o invitație DoorKey emisă de recepție.")
    }
    return token
  }
  static func verify(
    _ item: WalletKey, phonePublic: Data, current: Bool = true,
    issuerPublic: Data = TrustConfig.issuerPublic
  ) -> Bool {
    let data = item.permit
    guard data.count == 150, data[0] == 1, data.integer(1, 4) == UInt64(item.doorID),
      item.doorID > 0,
      item.doorPublic.count == 65, item.certificate.count == 64,
      data.subdata(in: 21..<86) == phonePublic,
      data.integer(13, 8) > data.integer(5, 8),
      let issuer = try? P256.Signing.PublicKey(x963Representation: issuerPublic),
      let permitSig = try? P256.Signing.ECDSASignature(rawRepresentation: data.suffix(64)),
      issuer.isValidSignature(permitSig, for: data.prefix(86)),
      let certSig = try? P256.Signing.ECDSASignature(rawRepresentation: item.certificate),
      (try? P256.Signing.PublicKey(x963Representation: item.doorPublic)) != nil,
      issuer.isValidSignature(
        certSig, for: Data("DoorKey-device-v1".utf8) + data.subdata(in: 1..<5) + item.doorPublic)
    else { return false }
    if !current { return true }
    let now = UInt64(max(0, Date().timeIntervalSince1970))
    return now >= data.integer(5, 8) && now < data.integer(13, 8)
  }
}
extension WalletProtocol {
  static func verifyChallenge(_ data: Data, key item: WalletKey) -> Bool {
    guard data.count == 84, data.integer(0, 4) == UInt64(item.doorID),
      let pub = try? P256.Signing.PublicKey(x963Representation: item.doorPublic),
      let sig = try? P256.Signing.ECDSASignature(rawRepresentation: data.suffix(64))
    else { return false }
    return pub.isValidSignature(sig, for: Data("DoorKey-door-v1".utf8) + data.prefix(20))
  }
  static func verifyApproval(
    _ proof: Data, key item: WalletKey, nonce: Data, issuerPublic: Data = TrustConfig.issuerPublic
  ) -> Bool {
    guard proof.count == 72, nonce.count == 16, item.permit.count == 150,
      let issuer = try? P256.Signing.PublicKey(x963Representation: issuerPublic),
      let sig = try? P256.Signing.ECDSASignature(rawRepresentation: proof.suffix(64))
    else { return false }
    let stamp = proof.integer(0, 8)
    return stamp >= item.permit.integer(5, 8) && stamp < item.permit.integer(13, 8)
      && issuer.isValidSignature(
        sig,
        for: Data("DoorKey-time-v2".utf8) + item.permit.subdata(in: 1..<5) + nonce + proof.prefix(8)
          + Data(SHA256.hash(data: item.permit)))
  }
}
enum ManagerError: LocalizedError {
  case denied, invitationExpired, unavailable, rateLimited
  var errorDescription: String? {
    switch self {
    case .denied: return "Acces refuzat de recepție."
    case .invitationExpired:
      return "Invitația a expirat sau a fost deja folosită. Cere un QR nou la recepție."
    case .unavailable:
      return "Managerul nu este disponibil. Verifică accesul la internet și încearcă din nou."
    case .rateLimited: return "Prea multe încercări. Așteaptă puțin înainte să încerci din nou."
    }
  }
}
final class NoRedirects: NSObject, URLSessionTaskDelegate {
  func urlSession(
    _ session: URLSession, task: URLSessionTask,
    willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest,
    completionHandler: @escaping (URLRequest?) -> Void
  ) { completionHandler(nil) }
}
enum ManagerAPI {
  static let session: URLSession = {
    let config = URLSessionConfiguration.ephemeral
    config.urlCache = nil
    config.httpCookieStorage = nil
    config.httpShouldSetCookies = false
    return URLSession(configuration: config, delegate: NoRedirects(), delegateQueue: nil)
  }()
  static func post<T: Decodable>(_ path: String, body: [String: String]) async throws -> T {
    guard ["/v1/redeem", "/v1/authorize"].contains(path),
      let url = URL(string: TrustConfig.managerOrigin + path)
    else { throw ManagerError.unavailable }
    var request = URLRequest(url: url)
    request.httpMethod = "POST"
    request.timeoutInterval = 8
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    request.httpBody = try JSONSerialization.data(withJSONObject: body)
    let data: Data
    let response: URLResponse
    do { (data, response) = try await session.data(for: request) } catch {
      throw ManagerError.unavailable
    }
    guard let http = response as? HTTPURLResponse else { throw ManagerError.unavailable }
    if http.statusCode == 401 {
      throw path == "/v1/redeem" ? ManagerError.invitationExpired : ManagerError.denied
    }
    if http.statusCode == 429 { throw ManagerError.rateLimited }
    guard http.statusCode == 200, data.count <= 16384 else { throw ManagerError.unavailable }
    return try JSONDecoder().decode(T.self, from: data)
  }
}

// Palette mirrors ERA's night-shift web theme.
enum EraStyle {
  static let canvas = Color(red: 15 / 255, green: 18 / 255, blue: 25 / 255)
  static let surface = Color(red: 26 / 255, green: 31 / 255, blue: 43 / 255)
  static let subtle = Color(red: 34 / 255, green: 40 / 255, blue: 54 / 255)
  static let line = Color(red: 44 / 255, green: 51 / 255, blue: 67 / 255)
  static let ink = Color(red: 241 / 255, green: 238 / 255, blue: 230 / 255)
  static let muted = Color(red: 169 / 255, green: 175 / 255, blue: 188 / 255)
  static let lime = Color(red: 230 / 255, green: 239 / 255, blue: 90 / 255)
}
final class WalletPresentation: ObservableObject {
  @Published var scanner = false
  @Published var diagnostics = false
  @Published var remove: WalletKey?
}
struct ContentView: View {
  @StateObject private var bluetooth = DoorBluetooth.shared
  @Environment(\.scenePhase) private var phase
  @StateObject private var presentation = WalletPresentation()
  var body: some View {
    NavigationStack {
      ZStack {
        EraStyle.canvas.ignoresSafeArea()
        ScrollView {
          VStack(alignment: .leading, spacing: 24) {
            HStack(alignment: .top) {
              VStack(alignment: .leading, spacing: 8) {
                Text("era.").font(.system(size: 24, weight: .semibold, design: .serif))
                  .foregroundStyle(EraStyle.lime)
                Text("Cheile tale").font(.system(size: 38, weight: .regular, design: .serif))
                Text(
                  bluetooth.keys.isEmpty
                    ? "Următorul tău sejur începe aici." : "Un pas mai aproape de camera ta."
                ).font(.subheadline).foregroundStyle(EraStyle.muted)
              }
              Spacer()
              Button {
                presentation.scanner = true
              } label: {
                Image(systemName: "plus").font(.system(size: 23, weight: .medium)).frame(
                  width: 54, height: 54
                ).background(EraStyle.lime, in: Circle()).foregroundStyle(EraStyle.canvas)
              }
              .accessibilityLabel("Adaugă o cheie prin QR")
            }.padding(.top, 12)
            if bluetooth.enrolling {
              HStack(spacing: 12) {
                ProgressView().tint(EraStyle.lime)
                Text("Se adaugă cheia ta…").font(.subheadline)
              }.padding(20).frame(maxWidth: .infinity, alignment: .leading).background(
                EraStyle.surface, in: RoundedRectangle(cornerRadius: 22))
            }
            if bluetooth.keys.isEmpty {
              emptyWallet
            } else {
              TimelineView(.periodic(from: .now, by: 30)) { _ in
                VStack(spacing: 16) {
                  ForEach(bluetooth.keys) { item in
                    WalletCard(
                      item: item,
                      connected: bluetooth.connected && bluetooth.selectedKeyID == item.id,
                      selected: bluetooth.selectedKeyID == item.id,
                      remove: { presentation.remove = item }
                    )
                    .onTapGesture { bluetooth.selectKey(item.id) }
                  }
                }
              }
              VStack(alignment: .leading, spacing: 12) {
                Toggle(isOn: $bluetooth.automatic) {
                  Label("Acces automat", systemImage: "wave.3.right").font(
                    .subheadline.weight(.medium))
                }
                .tint(EraStyle.lime).onChange(of: bluetooth.automatic) { _, _ in
                  bluetooth.modeChanged()
                }
                Text(
                  "Apropie telefonul de cititor. Accesul se verifică online la fiecare încercare."
                ).font(.footnote).foregroundStyle(EraStyle.muted)
                if bluetooth.busy { ProgressView("Se verifică accesul…").tint(EraStyle.lime) }
                Text(bluetooth.status).font(.footnote).foregroundStyle(EraStyle.muted)
                  .accessibilityLabel("Stare acces: \(bluetooth.status)")
              }.padding(20).background(EraStyle.surface, in: RoundedRectangle(cornerRadius: 22))
            }
            HStack {
              Image(systemName: "lock.shield")
              Text("Cheia privată rămâne pe iPhone.")
            }.font(.caption).foregroundStyle(EraStyle.muted).frame(maxWidth: .infinity).padding(
              .top, 4)
          }.padding(24).padding(.bottom, 20)
        }
      }
      .foregroundStyle(EraStyle.ink)
      .toolbar {
        ToolbarItem(placement: .topBarTrailing) {
          Button {
            presentation.diagnostics = true
          } label: {
            Image(systemName: "ellipsis").foregroundStyle(EraStyle.muted)
          }.accessibilityLabel("Setări și diagnostic")
        }
      }
      .toolbarBackground(EraStyle.canvas, for: .navigationBar)
      .sheet(isPresented: $presentation.scanner) {
        InvitationScanner { value in
          presentation.scanner = false
          bluetooth.enroll(invitation: value)
        }.preferredColorScheme(.dark)
      }
      .sheet(isPresented: $presentation.diagnostics) {
        DiagnosticsView(bluetooth: bluetooth).preferredColorScheme(.dark)
      }
      .alert(
        "Cheia nu a fost adăugată",
        isPresented: Binding(
          get: { bluetooth.enrollmentError != nil },
          set: { if !$0 { bluetooth.enrollmentError = nil } })
      ) {
        Button("OK") { bluetooth.enrollmentError = nil }
      } message: {
        Text(bluetooth.enrollmentError ?? "")
      }
      .confirmationDialog(
        "Elimini cheia de pe acest iPhone?",
        isPresented: Binding(
          get: { presentation.remove != nil }, set: { if !$0 { presentation.remove = nil } }),
        titleVisibility: .visible
      ) {
        Button("Elimină cheia", role: .destructive) {
          if let item = presentation.remove { bluetooth.removeKey(item.id) }
          presentation.remove = nil
        }
      } message: {
        Text("Pentru a o adăuga din nou vei avea nevoie de o invitație nouă de la recepție.")
      }
      .onAppear { bluetooth.setForeground(phase == .active) }
      .onChange(of: phase) { _, new in bluetooth.setForeground(new == .active) }
    }.preferredColorScheme(.dark)
  }
  private var emptyWallet: some View {
    VStack(spacing: 22) {
      ZStack {
        Circle().fill(EraStyle.subtle).frame(width: 112, height: 112)
        Image(systemName: "key.horizontal").font(.system(size: 44, weight: .light)).foregroundStyle(
          EraStyle.lime
        ).rotationEffect(.degrees(-30))
      }.padding(.top, 30)
      VStack(spacing: 10) {
        Text("Nu ai chei încă").font(.system(size: 29, weight: .regular, design: .serif))
        Text("După check-in, scanează invitația QR\nprimită de la recepție.").font(.subheadline)
          .multilineTextAlignment(.center).foregroundStyle(EraStyle.muted).lineSpacing(4)
      }
      Button {
        presentation.scanner = true
      } label: {
        Label("Scanează invitația", systemImage: "qrcode.viewfinder").font(
          .subheadline.weight(.semibold)
        ).frame(maxWidth: .infinity).padding(.vertical, 17).background(EraStyle.lime, in: Capsule())
          .foregroundStyle(EraStyle.canvas)
      }.padding(.top, 8)
    }.padding(26).padding(.bottom, 12).frame(maxWidth: .infinity).background(
      EraStyle.surface, in: RoundedRectangle(cornerRadius: 28)
    ).overlay(RoundedRectangle(cornerRadius: 28).stroke(EraStyle.line, lineWidth: 1))
  }
}
struct WalletCard: View {
  let item: WalletKey
  let connected: Bool
  let selected: Bool
  let remove: () -> Void
  var state: String {
    item.expired ? "Expirată" : item.accessDenied ? "Acces refuzat" : "În perioada de valabilitate"
  }
  var tint: Color { item.expired || item.accessDenied ? EraStyle.muted : EraStyle.lime }
  private var expirationStyle: Date.FormatStyle {
    var style = Date.FormatStyle(date: .abbreviated, time: .shortened)
    style.timeZone = TimeZone(identifier: item.timezone ?? "") ?? .current
    style.locale = Locale(identifier: "ro_RO")
    return style
  }
  var body: some View {
    VStack(alignment: .leading, spacing: 24) {
      HStack {
        Text(item.propertyName ?? "Sejurul tău").font(.subheadline.weight(.medium)).foregroundStyle(
          EraStyle.muted)
        Spacer()
        Menu {
          Button("Elimină de pe acest iPhone", role: .destructive, action: remove)
        } label: {
          Image(systemName: "ellipsis").foregroundStyle(EraStyle.muted).padding(8)
        }.buttonStyle(.plain).accessibilityLabel("Opțiuni pentru \(item.title)")
      }
      HStack(alignment: .center) {
        VStack(alignment: .leading, spacing: 8) {
          Text(item.title).font(.system(size: 36, weight: .regular, design: .serif))
          Label(
            state, systemImage: item.expired || item.accessDenied ? "clock" : "checkmark.shield"
          ).font(.caption).foregroundStyle(tint)
        }
        Spacer()
        Image(systemName: "door.left.hand.closed").font(.system(size: 39, weight: .ultraLight))
          .foregroundStyle(tint)
      }
      Rectangle().fill(EraStyle.line).frame(height: 1)
      HStack(alignment: .bottom) {
        VStack(alignment: .leading, spacing: 6) {
          Text("VALABILĂ PÂNĂ LA").font(.system(size: 10, weight: .semibold)).tracking(1.4)
            .foregroundStyle(EraStyle.muted)
          Text(item.expiration, format: expirationStyle).font(.subheadline.weight(.medium))
        }
        Spacer()
        if connected {
          Label("Conectat", systemImage: "wave.3.right").font(.caption).foregroundStyle(
            EraStyle.lime)
        }
      }
    }.padding(24).background(EraStyle.surface, in: RoundedRectangle(cornerRadius: 26)).overlay(
      RoundedRectangle(cornerRadius: 26).stroke(
        selected ? EraStyle.lime.opacity(0.55) : EraStyle.line, lineWidth: 1))
  }
}
struct DiagnosticsView: View {
  @ObservedObject var bluetooth: DoorBluetooth
  @Environment(\.dismiss) private var dismiss
  var body: some View {
    NavigationStack {
      List {
        Section("Conexiune") {
          Text(bluetooth.status)
          Text(bluetooth.controllerSignal).font(.caption.monospaced())
          Button("Caută din nou cititorul") { bluetooth.findOtherController() }
        }
        Section("Chei") {
          Text(
            "Cheile sunt generate în Secure Enclave și păstrate pe acest iPhone. O dezinstalare completă creează o identitate nouă la reinstalare."
          ).font(.footnote)
          Text(
            "Pentru acces în fundal, aplicația nu trebuie închisă forțat. iOS decide când poate rula."
          ).font(.footnote)
        }
        Section("Jurnal local") {
          ForEach(Array(bluetooth.logs.enumerated()), id: \.offset) { _, line in
            Text(line).font(.caption.monospaced())
          }
        }
      }.navigationTitle("Diagnostic").toolbar {
        ToolbarItem(placement: .topBarTrailing) { Button("Gata") { dismiss() } }
      }
    }
  }
}
final class ScannerPresentation: ObservableObject {
  @Published var cameraError: String?
  @Published var link = ""
}
struct InvitationScanner: View {
  let onCode: (String) -> Void
  @Environment(\.dismiss) private var dismiss
  @StateObject private var presentation = ScannerPresentation()
  var body: some View {
    NavigationStack {
      ZStack {
        EraStyle.canvas.ignoresSafeArea()
        VStack(spacing: 22) {
          Text("Adaugă cheia camerei").font(.system(size: 29, weight: .regular, design: .serif))
            .foregroundStyle(EraStyle.ink)
          Text("Scanează QR-ul emis de recepție după check-in.").font(.subheadline).foregroundStyle(
            EraStyle.muted
          ).multilineTextAlignment(.center)
          ZStack {
            CameraPreview(onCode: onCode, onError: { presentation.cameraError = $0 })
            RoundedRectangle(cornerRadius: 24).stroke(EraStyle.lime, lineWidth: 2).padding(32)
          }.frame(height: 310).clipShape(RoundedRectangle(cornerRadius: 26))
          if let error = presentation.cameraError {
            Text(error).font(.footnote).foregroundStyle(EraStyle.muted)
            Button("Deschide setările") {
              if let url = URL(string: UIApplication.openSettingsURLString) {
                UIApplication.shared.open(url)
              }
            }.tint(EraStyle.lime)
          }
          DisclosureGroup("Ai primit un link de invitație?") {
            VStack(spacing: 12) {
              TextField("Lipește invitația", text: $presentation.link).textInputAutocapitalization(
                .never
              ).autocorrectionDisabled().keyboardType(.URL).textFieldStyle(.roundedBorder)
              Button("Adaugă cheia") { onCode(presentation.link) }.disabled(
                presentation.link.isEmpty
              ).tint(EraStyle.lime)
            }.padding(.top, 12)
          }.font(.footnote).foregroundStyle(EraStyle.muted)
          Spacer(minLength: 0)
        }.padding(24)
      }.toolbar {
        ToolbarItem(placement: .topBarTrailing) {
          Button("Anulează") { dismiss() }.tint(EraStyle.lime)
        }
      }
    }
  }
}
struct CameraPreview: UIViewControllerRepresentable {
  let onCode: (String) -> Void
  let onError: (String) -> Void
  func makeUIViewController(context: Context) -> CameraController {
    CameraController(onCode: onCode, onError: onError)
  }
  func updateUIViewController(_ uiViewController: CameraController, context: Context) {}
}
final class CameraController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
  let onCode: (String) -> Void
  let onError: (String) -> Void
  private let capture = AVCaptureSession()
  private let queue = DispatchQueue(label: "DoorKey.camera")
  private var preview: AVCaptureVideoPreviewLayer?
  private var completed = false
  private var visible = false
  init(onCode: @escaping (String) -> Void, onError: @escaping (String) -> Void) {
    self.onCode = onCode
    self.onError = onError
    super.init(nibName: nil, bundle: nil)
  }
  required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }
  override func viewDidLoad() {
    super.viewDidLoad()
    view.backgroundColor = .black
    AVCaptureDevice.requestAccess(for: .video) { [weak self] granted in
      DispatchQueue.main.async {
        guard let self, self.visible else { return }
        if granted {
          self.configure()
        } else {
          self.onError("Permite accesul la cameră pentru a scana invitația.")
        }
      }
    }
  }
  override func viewWillAppear(_ animated: Bool) {
    super.viewWillAppear(animated)
    visible = true
  }
  override func viewDidDisappear(_ animated: Bool) {
    super.viewDidDisappear(animated)
    visible = false
    let session = capture
    queue.async { session.stopRunning() }
  }
  override func viewDidLayoutSubviews() {
    super.viewDidLayoutSubviews()
    preview?.frame = view.bounds
  }
  private func configure() {
    guard let device = AVCaptureDevice.default(for: .video),
      let input = try? AVCaptureDeviceInput(device: device), capture.canAddInput(input)
    else {
      onError("Camera nu este disponibilă. Poți folosi linkul invitației.")
      return
    }
    capture.addInput(input)
    let output = AVCaptureMetadataOutput()
    guard capture.canAddOutput(output) else {
      onError("Scanarea QR nu este disponibilă.")
      return
    }
    capture.addOutput(output)
    output.setMetadataObjectsDelegate(self, queue: .main)
    output.metadataObjectTypes = [.qr]
    let layer = AVCaptureVideoPreviewLayer(session: capture)
    layer.videoGravity = .resizeAspectFill
    layer.frame = view.bounds
    view.layer.addSublayer(layer)
    preview = layer
    let session = capture
    queue.async { session.startRunning() }
  }
  func metadataOutput(
    _ output: AVCaptureMetadataOutput, didOutput metadataObjects: [AVMetadataObject],
    from connection: AVCaptureConnection
  ) {
    guard !completed, let code = metadataObjects.first as? AVMetadataMachineReadableCodeObject,
      let value = code.stringValue
    else { return }
    completed = true
    let session = capture
    queue.async { session.stopRunning() }
    onCode(value)
  }
}
