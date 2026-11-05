package com.era.doorkey

import java.net.URI
import java.net.URLDecoder
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.PublicKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

object Trust {
    const val MANAGER = "https://doorkey-staging.cloud.retreat480.com"
    val issuer = "044ce210f2fb38c52069f1ac351929a624d39fc2957223a814047a35a9d404811cb234b30703a3bd2b5202c0c2e47128f8702ca144b39fd0de790f77a561d3b5d5".hexBytes()
}
fun String.hexBytes(): ByteArray { require(length % 2 == 0 && matches(Regex("[0-9a-fA-F]*"))); return chunked(2).map { it.toInt(16).toByte() }.toByteArray() }
fun ByteArray.hex(): String = joinToString("") { "%02x".format(it.toInt() and 255) }
fun ByteArray.b64(): String = Base64.getEncoder().encodeToString(this)
fun String.unbase64(): ByteArray = Base64.getDecoder().decode(this)
fun ByteArray.le(offset: Int, size: Int): Long { require(size in 1..8 && offset >= 0 && offset + size <= this.size); return (0 until size).fold(0L) { n, i -> n or ((this[offset + i].toLong() and 255) shl (8 * i)) } }
fun Long.littleEndian(size: Int): ByteArray = ByteArray(size) { (this ushr (8 * it)).toByte() }

data class WalletKey(
    val id: String, val permit: String, val doorId: Long, val doorPublic: String,
    val certificate: String, val readerName: String, val roomName: String? = null,
    val propertyName: String? = null, val timezone: String? = null,
    val accessDenied: Boolean = false, val lastAuthorized: Long? = null,
) {
    val title: String get() = roomName?.takeIf { it.isNotBlank() }?.let { "Camera $it" } ?: "Cheie de acces"
    val expiresAt: Long get() = runCatching { permit.unbase64().takeIf { it.size == 150 }?.le(13, 8) ?: 0L }.getOrDefault(0L)
    fun expired(now: Long = System.currentTimeMillis() / 1000): Boolean = now >= expiresAt
}
object Protocol {
    private fun domain(value: String) = value.toByteArray(Charsets.UTF_8)
    fun hash(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)
    fun invitation(input: String): String {
        val url = URI(input.trim()); val trusted = URI(Trust.MANAGER)
        require(url.scheme == "https" && url.host.equals(trusted.host, true) && url.port in listOf(-1, 443) && url.userInfo == null && url.path == "/enroll" && url.rawQuery == null)
        val fragment = requireNotNull(url.rawFragment)
        val parts = fragment.split('&'); require(parts.size == 1)
        val pair = parts.single().split('=', limit = 2); require(pair.size == 2 && URLDecoder.decode(pair[0], "UTF-8") == "invite")
        return URLDecoder.decode(pair[1], "UTF-8").also { require(it.matches(Regex("[A-Za-z0-9_-]{43}"))) }
    }
    fun publicKey(raw: ByteArray): PublicKey {
        require(raw.size == 65 && raw[0] == 4.toByte())
        return KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec("3059301306072a8648ce3d020106082a8648ce3d030107034200".hexBytes() + raw))
    }
    fun uncompressed(key: PublicKey): ByteArray {
        val ec = key as ECPublicKey
        fun coordinate(value: java.math.BigInteger) = value.toByteArray().let { if (it.size > 32) it.copyOfRange(it.size - 32, it.size) else ByteArray(32 - it.size) + it }
        return byteArrayOf(4) + coordinate(ec.w.affineX) + coordinate(ec.w.affineY)
    }
    fun rawToDer(raw: ByteArray): ByteArray {
        require(raw.size == 64)
        fun integer(bytes: ByteArray): ByteArray {
            val trimmed = bytes.dropWhile { it == 0.toByte() }.toByteArray().let { if (it.isEmpty()) byteArrayOf(0) else it }
            val positive = if (trimmed[0].toInt() and 128 != 0) byteArrayOf(0) + trimmed else trimmed
            return byteArrayOf(2, positive.size.toByte()) + positive
        }
        val pair = integer(raw.copyOfRange(0, 32)) + integer(raw.copyOfRange(32, 64))
        return byteArrayOf(0x30, pair.size.toByte()) + pair
    }
    fun derToRaw(der: ByteArray): ByteArray {
        require(der.size in 8..72 && der[0] == 0x30.toByte() && (der[1].toInt() and 255) == der.size - 2)
        var pos = 2
        fun integer(): ByteArray {
            require(pos + 2 <= der.size && der[pos++] == 2.toByte())
            val len = der[pos++].toInt() and 255; require(len in 1..33 && pos + len <= der.size)
            val value = der.copyOfRange(pos, pos + len); pos += len
            require(value[0].toInt() and 128 == 0 && (len <= 32 || value[0] == 0.toByte()))
            if (len > 1 && value[0] == 0.toByte()) require(value[1].toInt() and 128 != 0)
            val unsigned = if (value.size == 33) value.copyOfRange(1, 33) else value
            require(unsigned.size <= 32)
            return ByteArray(32 - unsigned.size) + unsigned
        }
        val raw = integer() + integer(); require(pos == der.size); return raw
    }
    fun verify(pub: ByteArray, message: ByteArray, signature: ByteArray): Boolean = runCatching {
        Signature.getInstance("SHA256withECDSA").run { initVerify(publicKey(pub)); update(message); verify(rawToDer(signature)) }
    }.getOrDefault(false)
    fun validKey(key: WalletKey, phone: ByteArray, current: Boolean = true, issuer: ByteArray = Trust.issuer, now: Long = System.currentTimeMillis() / 1000): Boolean = runCatching {
        val permit = key.permit.unbase64(); val reader = key.doorPublic.hexBytes(); val cert = key.certificate.unbase64()
        require(permit.size == 150 && permit[0] == 1.toByte() && key.doorId in 1..0xffffffffL && permit.le(1, 4) == key.doorId)
        require(permit.copyOfRange(21, 86).contentEquals(phone) && permit.le(13, 8) > permit.le(5, 8))
        publicKey(reader)
        verify(issuer, permit.copyOfRange(0, 86), permit.copyOfRange(86, 150)) &&
            verify(issuer, domain("DoorKey-device-v1") + key.doorId.littleEndian(4) + reader, cert) &&
            (!current || now >= permit.le(5, 8) && now < permit.le(13, 8))
    }.getOrDefault(false)
    fun validChallenge(challenge: ByteArray, key: WalletKey): Boolean = challenge.size == 84 && challenge.le(0, 4) == key.doorId &&
        verify(key.doorPublic.hexBytes(), domain("DoorKey-door-v1") + challenge.copyOfRange(0, 20), challenge.copyOfRange(20, 84))
    fun validApproval(proof: ByteArray, key: WalletKey, nonce: ByteArray, issuer: ByteArray = Trust.issuer): Boolean = runCatching {
        val permit = key.permit.unbase64(); require(proof.size == 72 && nonce.size == 16 && permit.size == 150)
        val now = proof.le(0, 8)
        now >= permit.le(5, 8) && now < permit.le(13, 8) && verify(issuer, domain("DoorKey-time-v2") + key.doorId.littleEndian(4) + nonce + proof.copyOfRange(0, 8) + hash(permit), proof.copyOfRange(8, 72))
    }.getOrDefault(false)
    fun redeemMessage(token: String, phone: ByteArray) = domain("DoorKey-redeem-v1") + domain(token) + phone
    fun authorizeMessage(permit: ByteArray, challenge: ByteArray) = domain("DoorKey-authorize-v2") + hash(permit) + challenge
    fun authFrame(key: WalletKey, challenge: ByteArray, proof: ByteArray, sign: (ByteArray) -> ByteArray): ByteArray {
        require(challenge.size == 84 && proof.size == 72)
        val body = key.permit.unbase64() + proof
        return body + sign(domain("DoorKey-auth-v1") + challenge.copyOfRange(0, 20) + hash(body))
    }
}
