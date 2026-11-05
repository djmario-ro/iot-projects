package com.era.doorkey

import org.junit.Assert.*
import org.junit.Test
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec

class ProtocolTest {
    private fun pair() = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    private fun pub(k: KeyPair) = Protocol.uncompressed(k.public)
    private fun sign(k: KeyPair, bytes: ByteArray) = Signature.getInstance("SHA256withECDSA").run { initSign(k.private); update(bytes); Protocol.derToRaw(sign()) }
    private fun text(s: String) = s.toByteArray()
    private val issuer = pair()
    private val phone = pair()
    private val reader = pair()
    private val door = 4039142175L
    private fun key(start: Long = 1000, end: Long = 2000): WalletKey {
        val payload = byteArrayOf(1) + door.littleEndian(4) + start.littleEndian(8) + end.littleEndian(8) + pub(phone)
        return WalletKey("device", (payload + sign(issuer, payload)).b64(), door, pub(reader).hex(), sign(issuer, text("DoorKey-device-v1") + door.littleEndian(4) + pub(reader)).b64(), "Door-BB03", "204")
    }
    @Test fun signedPermitAndCertifiedReaderAreBoundToPhoneAndWindow() {
        val key = key()
        assertTrue(Protocol.validKey(key, pub(phone), issuer = pub(issuer), now = 1000))
        assertTrue(Protocol.validKey(key, pub(phone), issuer = pub(issuer), now = 1999))
        assertFalse(Protocol.validKey(key, pub(phone), issuer = pub(issuer), now = 999))
        assertFalse(Protocol.validKey(key, pub(phone), issuer = pub(issuer), now = 2000))
        assertFalse(Protocol.validKey(key, pub(pair()), issuer = pub(issuer), now = 1500))
        assertFalse(Protocol.validKey(key, pub(phone), issuer = pub(pair()), now = 1500))
        assertFalse(Protocol.validKey(key.copy(doorPublic = pub(pair()).hex()), pub(phone), issuer = pub(issuer), now = 1500))
        assertTrue(Protocol.validKey(key, pub(phone), current = false, issuer = pub(issuer), now = 3000))
        assertEquals(door, key.permit.unbase64().le(1, 4))
    }
    @Test fun challengeTimeProofAndFinalFrameUseFirmwareWireFormat() {
        val key = key(); val nonce = ByteArray(16) { it.toByte() }
        val header = door.littleEndian(4) + nonce
        val challenge = header + sign(reader, text("DoorKey-door-v1") + header)
        assertTrue(Protocol.validChallenge(challenge, key))
        assertFalse(Protocol.validChallenge(challenge.clone().apply { this[4] = 99 }, key))
        val epoch = 1500L.littleEndian(8)
        val proof = epoch + sign(issuer, text("DoorKey-time-v2") + header + epoch + Protocol.hash(key.permit.unbase64()))
        assertTrue(Protocol.validApproval(proof, key, nonce, pub(issuer)))
        assertFalse(Protocol.validApproval(proof, key, ByteArray(16), pub(issuer)))
        assertFalse(Protocol.validApproval(proof, key(1000, 2100), nonce, pub(issuer)))
        val frame = Protocol.authFrame(key, challenge, proof) { sign(phone, it) }
        assertEquals(286, frame.size)
        assertArrayEquals(key.permit.unbase64() + proof, frame.copyOfRange(0, 222))
        assertTrue(Protocol.verify(pub(phone), text("DoorKey-auth-v1") + header + Protocol.hash(frame.copyOfRange(0, 222)), frame.copyOfRange(222, 286)))
        assertArrayEquals(text("DoorKey-authorize-v2") + Protocol.hash(key.permit.unbase64()) + challenge, Protocol.authorizeMessage(key.permit.unbase64(), challenge))
    }
    @Test fun derRawRoundTripIncludesSignPaddingAndRejectsOversizeInteger() {
        repeat(100) { val message = "message$it".toByteArray(); val raw = sign(phone, message); assertEquals(64, raw.size); assertArrayEquals(raw, Protocol.derToRaw(Protocol.rawToDer(raw))); assertTrue(Protocol.verify(pub(phone), message, raw)) }
        val oversized = byteArrayOf(0x30, 38, 2, 33) + ByteArray(33) { 1 } + byteArrayOf(2, 1, 1)
        assertThrows(IllegalArgumentException::class.java) { Protocol.derToRaw(oversized) }
    }
    @Test fun invitationOnlyAcceptsPinnedHttpsOriginAndSingleToken() {
        val token = "a".repeat(43); val good = Trust.MANAGER + "/enroll#invite=" + token
        assertEquals(token, Protocol.invitation(good))
        listOf(good.replace("https:", "http:"), good.replace("/enroll", "/other"), good.replace(".com/", ".com.evil/"), "$good&invite=$token", Trust.MANAGER + "/enroll?evil=1#invite=$token", Trust.MANAGER + "/enroll#invite=short").forEach { link -> assertThrows(IllegalArgumentException::class.java) { Protocol.invitation(link) } }
        assertArrayEquals(text("DoorKey-redeem-v1") + text(token) + pub(phone), Protocol.redeemMessage(token, pub(phone)))
    }
}
