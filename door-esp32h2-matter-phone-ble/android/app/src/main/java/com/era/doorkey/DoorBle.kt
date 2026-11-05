package com.era.doorkey

import android.annotation.SuppressLint
import android.bluetooth.*
import android.bluetooth.le.*
import android.content.Context
import android.os.Handler
import android.os.Looper
import android.os.ParcelUuid
import kotlinx.coroutines.*
import java.util.ArrayDeque
import java.util.UUID

/** One GATT operation at a time; callbacks and session state are serialized on main. */
@SuppressLint("MissingPermission")
@Suppress("DEPRECATION")
class DoorBle(private val context: Context, private val wallet: WalletStore, private val scope: CoroutineScope) {
    private val handler = Handler(Looper.getMainLooper())
    private val adapter get() = context.getSystemService(BluetoothManager::class.java)?.adapter
    private var gatt: BluetoothGatt? = null
    private var scanning = false
    private var started = false
    private var command: BluetoothGattCharacteristic? = null
    private var result: BluetoothGattCharacteristic? = null
    private var challenge: BluetoothGattCharacteristic? = null
    private var telemetry: BluetoothGattCharacteristic? = null
    private data class Op(val kind: String, val start: () -> Boolean, val done: (Int, ByteArray?) -> Unit = { _, _ -> })
    private val queue = ArrayDeque<Op>()
    private var inFlight: Op? = null
    private var operationTimeout: Job? = null
    private var connectTimeout: Job? = null
    private var retry: Job? = null
    private var authentication: Job? = null
    private var authTimeout: Job? = null
    private var session = 0L
    private var authKey: WalletKey? = null
    private val ignored = mutableMapOf<String, Long>()
    fun start() {
        if (started) return
        started = true
        if (!DoorAccessService.allowed(context)) return
        if (adapter?.isEnabled != true) { setStatus("Activează Bluetooth pentru acces automat"); return }
        val address = wallet.lastAddress()
        if (address != null && BluetoothAdapter.checkBluetoothAddress(address)) connect(adapter!!.getRemoteDevice(address)) else scan()
    }
    fun pause() { started = false; retry?.cancel(); stopScan(); disconnect() }
    fun restart() { pause(); if (wallet.state.value.automatic && wallet.activeKeys().isNotEmpty()) start() }
    fun close() { pause() }
    private fun setStatus(text: String) { wallet.patch { it.copy(status = text) } }
    private fun scan() {
        if (!started || scanning || gatt != null || adapter?.isEnabled != true) return
        try {
            adapter?.bluetoothLeScanner?.startScan(listOf(ScanFilter.Builder().setServiceUuid(ParcelUuid(SERVICE)).build()), ScanSettings.Builder().setScanMode(ScanSettings.SCAN_MODE_LOW_POWER).build(), scans)
            scanning = true; setStatus("Caut cititorul ușii…")
        } catch (e: Exception) { setStatus("Nu pot porni scanarea Bluetooth"); wallet.log(e.javaClass.simpleName) }
    }
    private fun stopScan() { if (scanning && DoorAccessService.allowed(context)) runCatching { adapter?.bluetoothLeScanner?.stopScan(scans) }; scanning = false }
    private val scans = object : ScanCallback() {
        override fun onScanResult(callbackType: Int, scanResult: ScanResult) { handler.post {
            if (started && gatt == null && (ignored[scanResult.device.address] ?: 0L) <= System.currentTimeMillis()) connect(scanResult.device)
        } }
        override fun onScanFailed(errorCode: Int) { handler.post { scanning = false; setStatus("Scanare indisponibilă ($errorCode)"); scheduleScan(10000) } }
    }
    private fun connect(device: BluetoothDevice) {
        if (!started || gatt != null) return
        stopScan(); setStatus("Conectare la cititor…")
        gatt = device.connectGatt(context, false, callbacks, BluetoothDevice.TRANSPORT_LE)
        connectTimeout?.cancel(); connectTimeout = scope.launch { delay(20000); if (gatt != null && command == null) fail("Cititorul nu răspunde", forget = true) }
    }
    private fun scheduleScan(delayMillis: Long = 2500) { retry?.cancel(); retry = scope.launch { delay(delayMillis); if (started) scan() } }
    private fun disconnect() {
        session++; authentication?.cancel(); authTimeout?.cancel(); connectTimeout?.cancel(); operationTimeout?.cancel()
        authKey = null; inFlight = null; queue.clear(); command = null; challenge = null; result = null; telemetry = null
        val old = gatt; gatt = null
        if (DoorAccessService.allowed(context)) runCatching { old?.disconnect(); old?.close() }
        wallet.patch { it.copy(connected = false, busy = false) }
    }
    private fun fail(message: String, forget: Boolean = false) {
        setStatus(message); wallet.log(message)
        if (forget) { gatt?.device?.address?.let { ignored[it] = System.currentTimeMillis() + 30000 }; wallet.rememberReader(null) }
        disconnect(); if (started) scheduleScan()
    }
    private fun enqueue(op: Op) { queue.add(op); next() }
    private fun next() {
        if (inFlight != null || queue.isEmpty() || gatt == null) return
        val op = queue.removeFirst(); inFlight = op
        try { if (!op.start()) { fail("Operațiunea Bluetooth nu a pornit"); return } }
        catch (_: Exception) { fail("Bluetooth indisponibil"); return }
        operationTimeout?.cancel(); operationTimeout = scope.launch { delay(8000); if (inFlight === op) fail("Cititorul nu a confirmat operațiunea") }
    }
    private fun finish(kind: String, status: Int, bytes: ByteArray? = null) {
        val op = inFlight ?: return
        if (op.kind != kind) return
        operationTimeout?.cancel(); inFlight = null
        if (status != BluetoothGatt.GATT_SUCCESS) { fail("Cititorul a refuzat operațiunea ($status)"); return }
        op.done(status, bytes); next()
    }
    private fun write(bytes: ByteArray) {
        val characteristic = command ?: return
        enqueue(Op("write:${characteristic.uuid}", { characteristic.writeType = BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT; characteristic.value = bytes; gatt?.writeCharacteristic(characteristic) == true }))
    }
    private fun subscribe(characteristic: BluetoothGattCharacteristic): Boolean {
        val descriptor = characteristic.getDescriptor(CCC) ?: run { fail("Notificările cititorului nu sunt disponibile"); return false }
        if (gatt?.setCharacteristicNotification(characteristic, true) != true) { fail("Nu pot activa notificările"); return false }
        enqueue(Op("descriptor:${characteristic.uuid}", { descriptor.value = BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE; gatt?.writeDescriptor(descriptor) == true }))
        return gatt != null
    }
    private val callbacks = object : BluetoothGattCallback() {
        override fun onConnectionStateChange(deviceGatt: BluetoothGatt, status: Int, newState: Int) { handler.post {
            if (gatt !== deviceGatt) { deviceGatt.close(); return@post }
            if (status == BluetoothGatt.GATT_SUCCESS && newState == BluetoothProfile.STATE_CONNECTED) {
                wallet.patch { it.copy(connected = true, activeKeyId = null) }
                if (!deviceGatt.discoverServices()) fail("Serviciile BLE nu sunt disponibile")
            } else if (newState == BluetoothProfile.STATE_DISCONNECTED || status != BluetoothGatt.GATT_SUCCESS) fail("Conexiune pierdută; caut din nou cititorul")
        } }
        override fun onServicesDiscovered(deviceGatt: BluetoothGatt, status: Int) { handler.post {
            if (gatt !== deviceGatt) return@post
            if (status != BluetoothGatt.GATT_SUCCESS) { fail("Serviciile BLE nu sunt disponibile"); return@post }
            val service = deviceGatt.getService(SERVICE)
            command = service?.getCharacteristic(COMMAND); challenge = service?.getCharacteristic(CHALLENGE); result = service?.getCharacteristic(RESULT); telemetry = service?.getCharacteristic(TELEMETRY)
            if (command == null || challenge == null || result == null || telemetry == null) { fail("Cititor incompatibil cu DoorKey", forget = true); return@post }
            connectTimeout?.cancel(); if (!subscribe(result!!)) return@post; if (!subscribe(telemetry!!)) return@post; write(byteArrayOf(5)); setStatus("Conectat · aștept apropierea")
        } }
        override fun onDescriptorWrite(deviceGatt: BluetoothGatt, descriptor: BluetoothGattDescriptor, status: Int) { handler.post { if (gatt === deviceGatt) finish("descriptor:${descriptor.characteristic.uuid}", status) } }
        override fun onCharacteristicWrite(deviceGatt: BluetoothGatt, characteristic: BluetoothGattCharacteristic, status: Int) { handler.post { if (gatt === deviceGatt) finish("write:${characteristic.uuid}", status) } }
        override fun onCharacteristicRead(deviceGatt: BluetoothGatt, characteristic: BluetoothGattCharacteristic, status: Int) = read(deviceGatt, characteristic, characteristic.value?.clone() ?: byteArrayOf(), status)
        override fun onCharacteristicRead(deviceGatt: BluetoothGatt, characteristic: BluetoothGattCharacteristic, value: ByteArray, status: Int) = read(deviceGatt, characteristic, value.clone(), status)
        private fun read(deviceGatt: BluetoothGatt, characteristic: BluetoothGattCharacteristic, bytes: ByteArray, status: Int) { handler.post { if (gatt === deviceGatt) finish("read:${characteristic.uuid}", status, bytes) } }
        override fun onCharacteristicChanged(deviceGatt: BluetoothGatt, characteristic: BluetoothGattCharacteristic) = changed(deviceGatt, characteristic, characteristic.value?.clone() ?: byteArrayOf())
        override fun onCharacteristicChanged(deviceGatt: BluetoothGatt, characteristic: BluetoothGattCharacteristic, value: ByteArray) = changed(deviceGatt, characteristic, value.clone())
        private fun changed(deviceGatt: BluetoothGatt, characteristic: BluetoothGattCharacteristic, value: ByteArray) { handler.post {
            if (gatt !== deviceGatt) return@post
            when (characteristic.uuid) {
                TELEMETRY -> wallet.patch { it.copy(signal = "ESP32: ${value.toString(Charsets.UTF_8)} dBm (raw, mediană, prag)") }
                RESULT -> result(value.toString(Charsets.UTF_8))
            }
        } }
    }
    private fun result(text: String) {
        wallet.log("ESP32: $text")
        when {
            text == "READY" && !wallet.state.value.busy -> {
                val characteristic = challenge ?: return
                wallet.patch { it.copy(busy = true, status = "Se verifică accesul…") }
                session++; val token = session
                authTimeout?.cancel(); authTimeout = scope.launch { delay(20000); if (session == token) abort("Autentificarea a expirat") }
                enqueue(Op("read:${characteristic.uuid}", { gatt?.readCharacteristic(characteristic) == true }, { _, bytes -> authorize(bytes ?: byteArrayOf(), token) }))
            }
            text.startsWith("ACCEPT:") && wallet.state.value.busy && authKey != null && text == "ACCEPT:${authKey!!.doorId}" -> {
                runCatching { wallet.accepted(authKey!!.id) }; authTimeout?.cancel(); authKey = null
                wallet.patch { it.copy(busy = false, status = "Acces autorizat · îndepărtează telefonul pentru rearmare") }
            }
            text.startsWith("DENY:") -> { queue.clear(); authTimeout?.cancel(); authentication?.cancel(); session++; authKey = null; wallet.patch { it.copy(busy = false, status = text) } }
            text == "LATCHED" -> setStatus("Aștept îndepărtarea telefonului")
            text == "REARMED" -> setStatus("Conectat · pregătit pentru apropiere")
        }
    }
    private fun authorize(bytes: ByteArray, token: Long) {
        authentication?.cancel(); authentication = scope.launch {
            try {
                require(bytes.size == 84) { "Provocarea cititorului nu este validă" }
                val key = wallet.activeKeys().firstOrNull { it.doorId == bytes.le(0, 4) }
                if (key == null) { fail("Nu ai o cheie activă pentru acest cititor", forget = true); return@launch }
                check(Protocol.validChallenge(bytes, key)) { "Identitatea ușii nu este validă" }
                authKey = key; wallet.patch { it.copy(activeKeyId = key.id) }; gatt?.device?.address?.let { wallet.rememberReader(it) }
                val permit = key.permit.unbase64()
                val response = try { ManagerClient.post("/v1/authorize", mapOf("permit" to key.permit, "challenge" to bytes.hex(), "signature" to wallet.sign(Protocol.authorizeMessage(permit, bytes)).hex())) }
                catch (e: AccessDenied) { wallet.markDenied(key.id); throw e }
                if (session != token || !started) return@launch
                val proof = response.getString("timeProof").unbase64()
                check(response.getInt("protocol") == 2 && Protocol.validApproval(proof, key, bytes.copyOfRange(4, 20))) { "Semnătura autorizării nu este validă" }
                val frame = Protocol.authFrame(key, bytes, proof, wallet::sign)
                check(frame.size == 286)
                write(byteArrayOf(1)); frame.toList().chunked(19).forEach { write(byteArrayOf(2) + it.toByteArray()) }; write(byteArrayOf(3))
            } catch (_: CancellationException) { }
            catch (e: Exception) { if (session == token) abort(e.message ?: "Accesul nu a putut fi verificat") }
        }
    }
    private fun abort(message: String) {
        session++; authTimeout?.cancel(); authentication?.cancel(); authKey = null
        // Drop pending AUTH fragments; let an already-started GATT write finish before sending ABORT.
        queue.clear(); write(byteArrayOf(4)); wallet.patch { it.copy(busy = false, status = message) }; wallet.log(message)
    }
    companion object {
        private fun uuid(n: Int) = UUID.fromString("8496100$n-6e3a-4b9d-9ad0-781f506c1200")
        val SERVICE = uuid(1); private val CHALLENGE = uuid(2); private val COMMAND = uuid(3); private val RESULT = uuid(4); private val TELEMETRY = uuid(5)
        private val CCC = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")
    }
}
