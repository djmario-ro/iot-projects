package com.era.doorkey

import android.app.Application
import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class DoorKeyApplication : Application() {
    val wallet: WalletStore by lazy { WalletStore(this) }
}
data class WalletState(
    val keys: List<WalletKey> = emptyList(), val automatic: Boolean = true,
    val status: String = "Adaugă prima cheie", val enrolling: Boolean = false, val busy: Boolean = false,
    val connected: Boolean = false, val activeKeyId: String? = null,
    val signal: String = "Aștept măsurători de la cititor", val error: String? = null,
    val logs: List<String> = emptyList(),
)
class WalletStore(context: Context) {
    private val prefs = context.getSharedPreferences("doorkey", Context.MODE_PRIVATE)
    private val file = AtomicFile(File(context.noBackupFilesDir, "wallet.enc"))
    private val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    private val mutable = MutableStateFlow(WalletState(automatic = prefs.getBoolean("automatic", true)))
    val state = mutable.asStateFlow()
    @Volatile var uiVisible = false
    init {
        runCatching {
            // A lost/corrupt key must not silently replace an existing wallet identity.
            if (!keyStore.containsAlias(PHONE_ALIAS)) {
                check(!file.baseFile.exists()) { "Cheia telefonului nu mai este disponibilă. Reinstalează aplicația și cere o invitație nouă." }
                KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").apply {
                    initialize(KeyGenParameterSpec.Builder(PHONE_ALIAS, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
                        .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                        .setDigests(KeyProperties.DIGEST_SHA256).setUserAuthenticationRequired(false).build())
                }.generateKeyPair()
            }
            if (file.baseFile.exists()) {
                val encrypted = file.openRead().use { it.readBytes() }; check(encrypted.size in 29..262144)
                val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.DECRYPT_MODE, encryptionKey(false), GCMParameterSpec(128, encrypted.copyOfRange(0, 12))) }
                val json = JSONArray(String(cipher.doFinal(encrypted.copyOfRange(12, encrypted.size)), Charsets.UTF_8))
                val keys = (0 until json.length()).map { decode(json.getJSONObject(it)) }
                check(keys.all { Protocol.validKey(it, phonePublic(), current = false) }) { "Cheile salvate nu pot fi verificate." }
                mutable.value = mutable.value.copy(keys = keys, status = "Cheile sunt pregătite")
            }
        }.onFailure { mutable.value = mutable.value.copy(error = it.message ?: "Nu pot încărca cheile telefonului.") }
    }
    fun phonePublic(): ByteArray = Protocol.uncompressed(requireNotNull(keyStore.getCertificate(PHONE_ALIAS)).publicKey)
    fun sign(message: ByteArray): ByteArray = Signature.getInstance("SHA256withECDSA").run {
        initSign(keyStore.getKey(PHONE_ALIAS, null) as java.security.PrivateKey); update(message); Protocol.derToRaw(sign())
    }
    private fun encryptionKey(create: Boolean): SecretKey {
        (keyStore.getKey(WALLET_ALIAS, null) as? SecretKey)?.let { return it }
        check(create) { "Cheia portofelului nu mai este disponibilă." }
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
            init(KeyGenParameterSpec.Builder(WALLET_ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setKeySize(256).setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setUserAuthenticationRequired(false).build())
        }.generateKey()
    }
    @Synchronized fun save(keys: List<WalletKey>) {
        val json = JSONArray().apply { keys.forEach { put(encode(it)) } }.toString().toByteArray()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, encryptionKey(true)) }
        val encrypted = cipher.iv + cipher.doFinal(json)
        val out = file.startWrite()
        try { out.write(encrypted); file.finishWrite(out) } catch (e: Exception) { file.failWrite(out); throw e }
        mutable.value = mutable.value.copy(keys = keys)
    }
    @Synchronized fun patch(block: (WalletState) -> WalletState) { mutable.value = block(mutable.value) }
    fun error(message: String?) = patch { it.copy(error = message, enrolling = false) }
    fun log(message: String) = patch { it.copy(logs = (listOf(message) + it.logs).take(80)) }
    fun automatic(enabled: Boolean) { prefs.edit().putBoolean("automatic", enabled).apply(); patch { it.copy(automatic = enabled) } }
    fun remove(id: String) { save(state.value.keys.filterNot { it.id == id }) }
    fun markDenied(id: String) { save(state.value.keys.map { if (it.id == id) it.copy(accessDenied = true) else it }) }
    fun accepted(id: String) { save(state.value.keys.map { if (it.id == id) it.copy(accessDenied = false, lastAuthorized = System.currentTimeMillis()) else it }) }
    fun activeKeys(): List<WalletKey> = state.value.keys.filter { !it.accessDenied && Protocol.validKey(it, phonePublic()) }
    fun lastAddress(): String? = prefs.getString("reader", null)
    fun rememberReader(address: String?) { prefs.edit().apply { if (address == null) remove("reader") else putString("reader", address) }.apply() }
    suspend fun enroll(link: String) {
        if (state.value.enrolling) return
        patch { it.copy(enrolling = true, error = null) }
        try {
            val token = try { Protocol.invitation(link) } catch (_: Exception) { throw IllegalArgumentException("Scanează o invitație DoorKey emisă de recepție.") }
            val public = phonePublic()
            val response = ManagerClient.post("/v1/redeem", mapOf("invite" to token, "publicKey" to public.hex(), "signature" to sign(Protocol.redeemMessage(token, public)).hex()))
            check(response.getInt("protocol") == 2)
            val door = response.getJSONObject("door"); val room = response.optJSONObject("room")
            val key = WalletKey(response.getString("deviceId"), response.getString("permit"), door.getLong("id"), door.getString("publicKey"), door.getString("certificate"), door.getString("name"), room?.nullable("name"), room?.nullable("propertyName"), room?.nullable("timezone"))
            check(Protocol.validKey(key, public) && response.getLong("validUntil") == key.expiresAt) { "Permisul sau identitatea cititorului nu poate fi verificată." }
            save(state.value.keys.filterNot { it.doorId == key.doorId } + key)
            rememberReader(null)
            patch { it.copy(enrolling = false, status = "Cheie adăugată · ${key.title}", activeKeyId = key.id) }
        } catch (e: Exception) { error(e.message ?: "Cheia nu a fost adăugată.") }
    }
    companion object {
        private const val PHONE_ALIAS = "DoorKey.phone.v1"
        private const val WALLET_ALIAS = "DoorKey.wallet.v1"
        private fun encode(k: WalletKey) = JSONObject().apply {
            put("id", k.id); put("permit", k.permit); put("doorId", k.doorId); put("doorPublic", k.doorPublic); put("certificate", k.certificate); put("readerName", k.readerName)
            put("roomName", k.roomName); put("propertyName", k.propertyName); put("timezone", k.timezone); put("accessDenied", k.accessDenied); put("lastAuthorized", k.lastAuthorized)
        }
        private fun decode(o: JSONObject) = WalletKey(o.getString("id"), o.getString("permit"), o.getLong("doorId"), o.getString("doorPublic"), o.getString("certificate"), o.getString("readerName"), o.nullable("roomName"), o.nullable("propertyName"), o.nullable("timezone"), o.optBoolean("accessDenied"), if (o.isNull("lastAuthorized")) null else o.getLong("lastAuthorized"))
    }
}
private fun JSONObject.nullable(name: String): String? = if (isNull(name)) null else optString(name).takeIf { it.isNotBlank() }
class AccessDenied : Exception("Acces refuzat. Contactează recepția pentru verificarea cheii.")
object ManagerClient {
    suspend fun post(path: String, body: Map<String, String>): JSONObject = withContext(Dispatchers.IO) {
        require(path in listOf("/v1/redeem", "/v1/authorize"))
        val connection = URL(Trust.MANAGER + path).openConnection() as javax.net.ssl.HttpsURLConnection
        try {
            connection.instanceFollowRedirects = false; connection.requestMethod = "POST"; connection.connectTimeout = 8000; connection.readTimeout = 8000
            connection.doOutput = true; connection.useCaches = false; connection.setRequestProperty("Content-Type", "application/json")
            connection.outputStream.use { it.write(JSONObject(body).toString().toByteArray(Charsets.UTF_8)) }
            when (connection.responseCode) {
                HttpURLConnection.HTTP_UNAUTHORIZED -> if (path == "/v1/redeem") error("Invitația a expirat sau a fost deja folosită. Cere un QR nou la recepție.") else throw AccessDenied()
                429 -> error("Prea multe încercări. Așteaptă puțin înainte să încerci din nou.")
                200 -> Unit
                else -> error("Managerul nu este disponibil. Încearcă din nou.")
            }
            val bytes = connection.inputStream.use { stream ->
                val out = java.io.ByteArrayOutputStream(); val buffer = ByteArray(1024)
                while (true) { val count = stream.read(buffer); if (count < 0) break; check(out.size() + count <= 16384); out.write(buffer, 0, count) }
                out.toByteArray()
            }
            JSONObject(String(bytes, Charsets.UTF_8))
        } catch (e: java.io.IOException) { throw IllegalStateException("Verifică accesul la internet și încearcă din nou.", e) }
        finally { connection.disconnect() }
    }
}
