import SwiftUI
import CoreBluetooth
import Combine
import CryptoKit
import Security
import UIKit

final class AppDelegate: NSObject, UIApplicationDelegate {
    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil) -> Bool {
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
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "DoorKey.v1", kSecAttrAccount as String: name,
            kSecReturnData as String: true, kSecMatchLimit as String: kSecMatchLimitOne]
        var value: CFTypeRef?
        return SecItemCopyMatching(query as CFDictionary, &value) == errSecSuccess ? value as? Data : nil
    }
    static func save(_ data: Data, _ name: String) throws {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "DoorKey.v1", kSecAttrAccount as String: name]
        let status: OSStatus
        if read(name) != nil {
            status = SecItemUpdate(query as CFDictionary, [kSecValueData as String: data, kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly] as CFDictionary)
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
    var errorDescription: String? { if case let .message(s) = self { return s }; return nil }
}
extension Data {
    var hex: String { map { String(format: "%02x", $0) }.joined() }
    func integer(_ offset: Int, _ count: Int) -> UInt64 {
        subdata(in: offset..<offset+count).enumerated().reduce(0) { $0 | (UInt64($1.element) << ($1.offset*8)) }
    }
}
final class DoorBluetooth: NSObject, ObservableObject, CBCentralManagerDelegate, CBPeripheralDelegate {
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
    private var permit: Data?
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
    @Published var server = UserDefaults.standard.string(forKey: "issuerURL") ?? TrustConfig.server
    @Published var token = String(data: KeyStore.read("issuerToken") ?? Data(), encoding: .utf8) ?? ""

    override init() {
        super.init()
        do {
            guard SecureEnclave.isAvailable else { throw DemoError.message("Necesita iPhone cu Secure Enclave.") }
            if let saved = KeyStore.read("phoneKey.background.v2") {
                phoneKey = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: saved)
            } else {
                guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, .privateKeyUsage, nil) else {
                    throw DemoError.message("Nu pot configura Secure Enclave")
                }
                let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
                try KeyStore.save(key.dataRepresentation, "phoneKey.background.v2")
                phoneKey = key
            }
            if let saved = KeyStore.read("permit"), validPermit(saved) { permit = saved; enrolled = true }
            // Migrate test enrollment token accessibility for locked-screen operation.
            if let savedToken = KeyStore.read("issuerToken") { try KeyStore.save(savedToken,"issuerToken") }
        } catch { credentialError = true; log(error.localizedDescription) }
        central = CBCentralManager(delegate: self, queue: .main, options: [CBCentralManagerOptionRestoreIdentifierKey: "DoorKey.central.v2"])
        ticker = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in self?.tick() }
    }
    private func log(_ value: String) {
        logs.insert("\(Date().formatted(date: .omitted, time: .standard))  \(value)", at: 0)
        if logs.count > 100 { logs.removeLast() }
    }
    private func validPermit(_ data: Data) -> Bool {
        guard data.count == 150, data[0] == 1, data.integer(1,4) == 12,
              let phoneKey, data.subdata(in: 21..<86) == phoneKey.publicKey.x963Representation,
              let issuer = try? P256.Signing.PublicKey(x963Representation: TrustConfig.issuerPublic),
              let sig = try? P256.Signing.ECDSASignature(rawRepresentation: data.suffix(64)),
              issuer.isValidSignature(sig, for: data.prefix(86)) else { return false }
        let now = UInt64(Date().timeIntervalSince1970)
        return now >= data.integer(5,8) && now < data.integer(13,8)
    }
    private func post(_ path: String, _ body: [String: Any]) async throws -> [String: String] {
        guard let base = URL(string: server), ["http", "https"].contains(base.scheme ?? ""), base.host != nil,
              let url = URL(string: path, relativeTo: base) else { throw DemoError.message("Adresa server invalida") }
        var request = URLRequest(url: url); request.httpMethod = "POST"; request.timeoutInterval = 8
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        request.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (data, response) = try await URLSession.shared.data(for: request)
        guard (response as? HTTPURLResponse)?.statusCode == 200 else { throw DemoError.message("Server: verifica adresa si codul de configurare") }
        return try JSONDecoder().decode([String: String].self, from: data)
    }
    func enroll() {
        guard !enrolling, let phoneKey else { log("Cheia telefonului nu este disponibila"); return }
        pauseConnection()
        enrolling = true
        Task { @MainActor in
            defer { enrolling = false }
            do {
                let response = try await post("/permit", ["publicKey": phoneKey.publicKey.x963Representation.hex])
                guard let encoded = response["permit"], let data = Data(base64Encoded: encoded), validPermit(data) else {
                    throw DemoError.message("Permis invalid sau expirat")
                }
                try KeyStore.save(data,"permit"); try KeyStore.save(Data(token.utf8),"issuerToken")
                UserDefaults.standard.set(server,forKey:"issuerURL")
                permit = data; enrolled = true; status = "Permis activ pentru Door-12, 24 ore."
                log(status); tick()
            } catch { status = error.localizedDescription; log(status) }
        }
    }
    func setForeground(_ value: Bool) {
        foreground = value
        if let active, let telemetry { active.setNotifyValue(value, for: telemetry) }
        tick()
    }
    func findOtherController() {
        UserDefaults.standard.removeObject(forKey: "knownDoorV2")
        pauseConnection()
        status = "Caut alt controller (H2 / TTGO)…"
        log(status)
        tick()
    }
    func modeChanged() {
        UserDefaults.standard.set(automatic, forKey: "automaticV2")
        if !automatic { pauseConnection() } else { tick() }
    }
    private func endBackgroundWork() {
        if authTask != .invalid { UIApplication.shared.endBackgroundTask(authTask); authTask = .invalid }
    }
    private func beginBackgroundWork() {
        endBackgroundWork()
        authTask = UIApplication.shared.beginBackgroundTask(withName: "DoorKey authentication") { [weak self] in
            self?.abortAuthentication("iOS a oprit timpul de executie")
        }
    }
    private func abortAuthentication(_ message: String) {
        log(message); status = message; busy = false; writingAuth = false; packets = []; session = UUID()
        sessionTimeout?.cancel(); endBackgroundWork()
        if let active, let command { active.writeValue(Data([4]), for: command, type: .withResponse) }
    }
    private func pauseConnection() {
        stopScan()
        if let active { central.cancelPeripheralConnection(active) }
        clearSession()
    }
    private func clearSession() {
        sessionTimeout?.cancel(); session = UUID(); active?.delegate = nil
        active = nil; challenge = nil; command = nil; result = nil; telemetry = nil; packets = []; writingAuth = false
        endBackgroundWork()
        connected = false; busy = false; restoredNeedsDiscovery = false
    }
    private func tick() {
        guard automatic, available, enrolled, !enrolling, !credentialError, active == nil else { return }
        if let saved = UserDefaults.standard.string(forKey: "knownDoorV2"), let id = UUID(uuidString: saved),
           let known = central.retrievePeripherals(withIdentifiers: [id]).first {
            connect(known)
        } else if !scanning { scan() }
    }
    func centralManager(_ central: CBCentralManager, willRestoreState dict: [String: Any]) {
        let restoredList = dict[CBCentralManagerRestoredStatePeripheralsKey] as? [CBPeripheral] ?? []
        guard automatic, enrolled else {
            for peripheral in restoredList { central.cancelPeripheralConnection(peripheral) }
            return
        }
        guard let restored = restoredList.first else { return }
        active = restored; restored.delegate = self
        log("Conexiune BLE restaurata de iOS")
        connected = restored.state == .connected
        restoredNeedsDiscovery = true
    }
    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        available = central.state == .poweredOn
        status = available ? "Bluetooth pregatit" : "Bluetooth indisponibil; verifica permisiunea si setarile."
        log(status)
        if available {
            if restoredNeedsDiscovery, let active {
                restoredNeedsDiscovery = false
                if active.state == .connected { active.discoverServices([serviceID]) }
                else if active.state == .disconnected { central.connect(active,options:nil) }
            }
            tick()
        } else { pauseConnection() }
    }
    func scan() {
        guard available, automatic, enrolled, active == nil else { return }
        central.scanForPeripherals(withServices: [serviceID], options: nil)
        scanning = true; status = "Caut controllerul BLE…"
    }
    func stopScan() { central?.stopScan(); scanning = false }
    func centralManager(_ central: CBCentralManager, didDiscover peripheral: CBPeripheral,
                        advertisementData: [String: Any], rssi RSSI: NSNumber) {
        guard automatic, enrolled, !enrolling, active == nil else { return }
        let name = advertisementData[CBAdvertisementDataLocalNameKey] as? String ?? peripheral.name ?? "Usa BLE"
        log("Gasit \(name). Conectez fara prag RSSI pe telefon.")
        connect(peripheral)
    }
    private func connect(_ peripheral: CBPeripheral) {
        guard automatic, enrolled else { return }
        stopScan(); active = peripheral; peripheral.delegate = self; session = UUID()
        status = "Conectare BLE; astept apropierea masurata de ESP32…"; log(status)
        // Leave pending reconnect with iOS; do not use a timer-dependent scan loop in background.
        central.connect(peripheral,options:nil)
    }
    private func fail(_ message: String) {
        status = message; log(message)
        if let active { central.cancelPeripheralConnection(active) }
        clearSession()
    }
    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        guard peripheral === active else { return }
        connected = true; peripheral.discoverServices([serviceID])
    }
    func centralManager(_ central: CBCentralManager, didFailToConnect peripheral: CBPeripheral,error: Error?) {
        guard peripheral === active else { return }; fail(error?.localizedDescription ?? "Conectare esuata")
    }
    func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral,error: Error?) {
        guard peripheral === active else { return }
        let previous = peripheral
        status = "Conexiune pierduta; astept revenirea usii."; log(status)
        clearSession()
        if automatic, enrolled, !enrolling, available { connect(previous) }
    }
    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        if let error { fail(error.localizedDescription); return }
        guard let service = peripheral.services?.first(where:{$0.uuid == serviceID}) else { fail("Serviciu lipsa"); return }
        peripheral.discoverCharacteristics([challengeID,commandID,resultID,telemetryID],for:service)
    }
    func peripheral(_ peripheral: CBPeripheral,didDiscoverCharacteristicsFor service: CBService,error: Error?) {
        if let error { fail(error.localizedDescription); return }
        challenge = service.characteristics?.first(where:{$0.uuid == challengeID})
        command = service.characteristics?.first(where:{$0.uuid == commandID})
        result = service.characteristics?.first(where:{$0.uuid == resultID})
        telemetry = service.characteristics?.first(where:{$0.uuid == telemetryID})
        guard challenge != nil, command != nil, let result, let telemetry else { fail("Actualizeaza firmware-ul ESP32 proximity v2"); return }
        peripheral.setNotifyValue(true,for:result)
        peripheral.setNotifyValue(foreground,for:telemetry)
        status = "Conectat. ESP32 decide apropierea."
    }
    func peripheral(_ peripheral: CBPeripheral, didUpdateNotificationStateFor characteristic: CBCharacteristic, error: Error?) {
        guard peripheral === active else { return }
        if let error { fail(error.localizedDescription); return }
        if characteristic.uuid == resultID, characteristic.isNotifying, let command {
            peripheral.writeValue(Data([5]),for:command,type:.withResponse)
        }
    }
    func peripheral(_ peripheral: CBPeripheral,didUpdateValueFor characteristic: CBCharacteristic,error: Error?) {
        guard peripheral === active else { return }
        if let error { fail(error.localizedDescription); return }
        guard let data = characteristic.value else { fail("Raspuns gol"); return }
        if characteristic.uuid == telemetryID {
            if let text = String(data:data,encoding:.utf8) {
                let values = text.split(separator:",")
                if values.count == 3 { controllerSignal = "ESP32: raw \(values[0]), median \(values[1]), prag \(values[2]) dBm" }
            }
            return
        }
        if characteristic.uuid == resultID {
            let text = String(data:data,encoding:.utf8) ?? "Raspuns invalid"
            log("ESP32: \(text)")
            if text == "READY", !busy, let challenge {
                session = UUID(); busy = true; beginBackgroundWork()
                let work = DispatchWorkItem { [weak self] in self?.abortAuthentication("Autentificarea a expirat") }
                sessionTimeout = work; DispatchQueue.main.asyncAfter(deadline:.now()+20,execute:work)
                status = "ESP32 detecteaza apropierea. Autentificare…"
                peripheral.readValue(for:challenge)
            } else if text == "ACCEPT:12" {
                status = "Acces autorizat · indeparteaza telefonul pentru rearmare"
                busy = false; writingAuth = false; packets = []; session = UUID(); sessionTimeout?.cancel(); endBackgroundWork()
            } else if text.hasPrefix("DENY:") {
                status = text; busy = false; writingAuth = false; packets = []; session = UUID(); sessionTimeout?.cancel(); endBackgroundWork()
            } else if text != "READY" {
                status = text == "LATCHED" ? "Astept indepartarea telefonului" : "Conectat · astept apropierea"
            }
            return
        }
        guard characteristic.uuid == challengeID, let permit, validPermit(permit), let phoneKey else { fail("Permis lipsa/expirat"); return }
        let currentSession = session
        Task { @MainActor in
            do {
                guard data.count == 84, data.integer(0,4) == 12 else { throw DemoError.message("Usa necunoscuta") }
                let doorKey = try P256.Signing.PublicKey(x963Representation:TrustConfig.doorPublic)
                let doorSig = try P256.Signing.ECDSASignature(rawRepresentation:data.suffix(64))
                guard doorKey.isValidSignature(doorSig,for:Data("DoorKey-door-v1".utf8)+data.prefix(20)) else {
                    throw DemoError.message("Identitatea usii nu este valida")
                }
                let door = data.prefix(4), random = data.subdata(in:4..<20)
                nonce = random.hex; UserDefaults.standard.set(peripheral.identifier.uuidString,forKey:"knownDoorV2"); log("Usa verificata. Challenge: \(nonce)")
                let response = try await post("/time",["door":12,"nonce":random.hex])
                guard currentSession == session, automatic else { return }
                guard let b64 = response["timeProof"], let timeProof = Data(base64Encoded:b64),timeProof.count == 72 else {
                    throw DemoError.message("Dovada de timp invalida")
                }
                let issuer = try P256.Signing.PublicKey(x963Representation:TrustConfig.issuerPublic)
                let tsig = try P256.Signing.ECDSASignature(rawRepresentation:timeProof.suffix(64))
                guard issuer.isValidSignature(tsig,for:Data("DoorKey-time-v1".utf8)+door+random+timeProof.prefix(8)) else {
                    throw DemoError.message("Semnatura timp invalida")
                }
                let body = permit+timeProof
                let message = Data("DoorKey-auth-v1".utf8)+door+random+Data(SHA256.hash(data:body))
                let signature = try phoneKey.signature(for:message).rawRepresentation
                let auth = body+signature
                packets = [Data([1])]
                // 19 payload bytes + opcode fit the minimum BLE ATT write size.
                for offset in stride(from:0,to:auth.count,by:19) {
                    packets.append(Data([2])+auth.subdata(in:offset..<min(offset+19,auth.count)))
                }
                packets.append(Data([3])); writingAuth = true; sendNext()
            } catch { if currentSession == session { abortAuthentication(error.localizedDescription) } }
        }
    }
    private func sendNext() {
        guard let active, let command else { return }
        if packets.isEmpty { writingAuth = false; return }
        active.writeValue(packets.removeFirst(),for:command,type:.withResponse)
    }
    func peripheral(_ peripheral: CBPeripheral,didWriteValueFor characteristic: CBCharacteristic,error: Error?) {
        guard peripheral === active else { return }
        if let error { fail(error.localizedDescription); return }
        if writingAuth { sendNext() }
    }
}

struct ContentView: View {
    @StateObject private var bluetooth = DoorBluetooth.shared
    @Environment(\.scenePhase) private var phase
    var body: some View {
        NavigationStack {
            List {
                Section("Acces automat") {
                    Label(bluetooth.status,systemImage:bluetooth.connected ? "lock.open" : "sensor")
                    Toggle("Acces automat · inclusiv in fundal",isOn:$bluetooth.automatic)
                        .onChange(of:bluetooth.automatic) { _,_ in bluetooth.modeChanged() }
                    if bluetooth.busy { ProgressView("Verific permisul si telefonul…") }
                    Text(bluetooth.enrolled ? "Permis instalat pentru Door-12" : "Configureaza permisul de test mai jos")
                        .foregroundStyle(bluetooth.enrolled ? .green : .secondary)
                    Button("Cauta alt controller (H2 / TTGO)") { bluetooth.findOtherController() }
                    Text(bluetooth.controllerSignal).font(.system(.caption,design:.monospaced))
                    Text("Pragul este pe ESP32. In consola UART: THRESH -50. Calibreaza din nou; RSSI difera fata de iPhone.")
                        .font(.caption).foregroundStyle(.secondary)

                }
                Section("Configurare initiala · test local") {
                    TextField("Server",text:$bluetooth.server).textInputAutocapitalization(.never).autocorrectionDisabled().keyboardType(.URL)
                    SecureField("Cod configurare din Terminal",text:$bluetooth.token).textInputAutocapitalization(.never).autocorrectionDisabled()
                    Button(bluetooth.enrolling ? "Instalez…" : "Instaleaza / reinnoieste permisul") { bluetooth.enroll() }
                        .disabled(bluetooth.enrolling || bluetooth.token.isEmpty)
                    Text("Mac-ul emite un permis de 24 ore. Cheia privata a telefonului ramane in Secure Enclave. Serviciul Mac trebuie sa ruleze si la autentificare, pentru timpul semnat.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                if !bluetooth.nonce.isEmpty {
                    Section("Ultima provocare") { Text(bluetooth.nonce).font(.system(.caption,design:.monospaced)).textSelection(.enabled) }
                }
                Section("Jurnal") {
                    ForEach(Array(bluetooth.logs.enumerated()),id:\.offset) { _,line in
                        Text(line).font(.system(.caption,design:.monospaced)).textSelection(.enabled)
                    }
                }
            }.navigationTitle("DoorKey")
                .onAppear { bluetooth.setForeground(phase == .active) }
                .onChange(of:phase) { _,new in bluetooth.setForeground(new == .active) }
        }
    }
}
