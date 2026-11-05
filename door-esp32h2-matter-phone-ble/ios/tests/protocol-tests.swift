func expect(_ ok: @autoclosure () -> Bool, _ message: String) { if !ok() { fatalError(message) } }
func rejects(_ value: String) -> Bool {
  do {
    _ = try WalletProtocol.invitation(value)
    return false
  } catch { return true }
}
let token = String(repeating: "a", count: 43)
expect(
  (try? WalletProtocol.invitation(TrustConfig.managerOrigin + "/enroll#invite=" + token)) == token,
  "valid invitation")
for url in [
  "http://doorkey-staging.cloud.retreat480.com/enroll#invite=" + token,
  "https://evil.example/enroll#invite=" + token,
  TrustConfig.managerOrigin + "/enroll#invite=" + token + "&extra=1",
  TrustConfig.managerOrigin + "/enroll?invite=" + token,
  TrustConfig.managerOrigin + "/enroll#invite=short",
  "https://user@doorkey-staging.cloud.retreat480.com/enroll#invite=" + token,
] { expect(rejects(url), "untrusted/malformed invitation") }
let issuer = P256.Signing.PrivateKey()
let phone = P256.Signing.PrivateKey()
let reader = P256.Signing.PrivateKey()
let root = issuer.publicKey.x963Representation
func sign(_ key: P256.Signing.PrivateKey, _ data: Data) -> Data {
  try! key.signature(for: data).rawRepresentation
}
func le(_ number: UInt64, _ count: Int) -> Data {
  Data((0..<count).map { UInt8(truncatingIfNeeded: number >> ($0 * 8)) })
}
let wireID: UInt32 = 4_039_142_175
let now = UInt64(Date().timeIntervalSince1970)
let door = le(UInt64(wireID), 4)
let nonce = Data(repeating: 0x5a, count: 16)
let payload =
  Data([1]) + door + le(now - 30, 8) + le(now + 3600, 8) + phone.publicKey.x963Representation
let permit = payload + sign(issuer, payload)
let cert = sign(issuer, Data("DoorKey-device-v1".utf8) + door + reader.publicKey.x963Representation)
let item = WalletKey(
  id: "test", permit: permit, doorID: wireID, doorPublic: reader.publicKey.x963Representation,
  certificate: cert, readerName: "Door-BB03", roomName: "204", propertyName: "Retreat",
  timezone: "Europe/Bucharest")
expect(
  WalletProtocol.verify(item, phonePublic: phone.publicKey.x963Representation, issuerPublic: root),
  "signed permit and reader certificate")
expect(item.title == "Camera 204", "ERA room name")
expect(
  !WalletProtocol.verify(
    item, phonePublic: P256.Signing.PrivateKey().publicKey.x963Representation, issuerPublic: root),
  "phone binding")
expect(
  !WalletProtocol.verify(
    item, phonePublic: phone.publicKey.x963Representation,
    issuerPublic: reader.publicKey.x963Representation), "issuer pin")
let challengePayload = door + nonce
let challenge = challengePayload + sign(reader, Data("DoorKey-door-v1".utf8) + challengePayload)
expect(WalletProtocol.verifyChallenge(challenge, key: item), "reader challenge")
var badChallenge = challenge
badChallenge[10] ^= 1
expect(!WalletProtocol.verifyChallenge(badChallenge, key: item), "tampered reader challenge")
let stamp = le(now, 8)
let timeMessage =
  Data("DoorKey-time-v2".utf8) + door + nonce + stamp + Data(SHA256.hash(data: permit))
let proof = stamp + sign(issuer, timeMessage)
expect(
  WalletProtocol.verifyApproval(proof, key: item, nonce: nonce, issuerPublic: root), "V2 approval")
expect(
  !WalletProtocol.verifyApproval(
    proof, key: item, nonce: Data(repeating: 0, count: 16), issuerPublic: root), "nonce binding")
let oldProof = stamp + sign(issuer, Data("DoorKey-time-v1".utf8) + door + nonce + stamp)
expect(
  !WalletProtocol.verifyApproval(oldProof, key: item, nonce: nonce, issuerPublic: root),
  "no V1 fallback")
var changedPermit = permit
changedPermit[21] ^= 1
let changed = WalletKey(
  id: "changed", permit: changedPermit, doorID: wireID, doorPublic: item.doorPublic,
  certificate: cert, readerName: "Reader", roomName: nil, propertyName: nil, timezone: nil)
expect(
  !WalletProtocol.verifyApproval(proof, key: changed, nonce: nonce, issuerPublic: root),
  "permit-specific approval")
let decoded = try! JSONDecoder().decode(WalletKey.self, from: JSONEncoder().encode(item))
expect(
  decoded.permit == permit && decoded.doorID == wireID, "wallet persistence and unsigned 32-bit ID")
print(
  "PASS: invitation origin, QR token parsing, phone binding, reader certificate, random 32-bit Door ID, signed challenge, V2 nonce/permit binding, V1 rejection, wallet persistence, ERA metadata"
)
var badProof = proof
badProof[30] ^= 1
expect(
  !WalletProtocol.verifyApproval(badProof, key: item, nonce: nonce, issuerPublic: root),
  "tampered approval")
let expiredPayload =
  Data([1]) + door + le(now - 3600, 8) + le(now - 60, 8) + phone.publicKey.x963Representation
let expired = WalletKey(
  id: "expired", permit: expiredPayload + sign(issuer, expiredPayload), doorID: wireID,
  doorPublic: item.doorPublic, certificate: cert, readerName: "Reader", roomName: "204",
  propertyName: nil, timezone: nil)
expect(
  !WalletProtocol.verify(
    expired, phonePublic: phone.publicKey.x963Representation, issuerPublic: root), "expired permit")
expect(
  WalletProtocol.verify(
    expired, phonePublic: phone.publicKey.x963Representation, current: false, issuerPublic: root),
  "expired signed key stays displayable")
