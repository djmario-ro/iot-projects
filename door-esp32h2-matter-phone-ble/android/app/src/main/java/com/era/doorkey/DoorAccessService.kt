package com.era.doorkey

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.bluetooth.BluetoothAdapter
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch

class DoorAccessService : Service() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private lateinit var wallet: WalletStore
    private lateinit var controller: DoorBle
    private val bluetoothState = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) { if (::controller.isInitialized) controller.restart() }
    }
    override fun onCreate() {
        super.onCreate(); wallet = (application as DoorKeyApplication).wallet
        controller = DoorBle(this, wallet, scope)
        getSystemService(NotificationManager::class.java).createNotificationChannel(NotificationChannel(CHANNEL, "Acces automat DoorKey", NotificationManager.IMPORTANCE_LOW))
        ContextCompat.registerReceiver(this, bluetoothState, IntentFilter(BluetoothAdapter.ACTION_STATE_CHANGED), ContextCompat.RECEIVER_EXPORTED)
        scope.launch {
            wallet.state.map { Triple(it.automatic, it.keys, it.enrolling) }.distinctUntilChanged().collect { state ->
                if (!state.first || !allowed(this@DoorAccessService) || wallet.activeKeys().isEmpty()) stopSelf()
                else if (state.third) controller.pause() else controller.start()
            }
        }
        scope.launch { while (true) { delay(60000); if (wallet.activeKeys().isEmpty()) stopSelf() } }
    }
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == PAUSE) { wallet.automatic(false); stopSelf(); return START_NOT_STICKY }
        if (!allowed(this) || !wallet.state.value.automatic || wallet.activeKeys().isEmpty()) { stopSelf(); return START_NOT_STICKY }
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val pause = PendingIntent.getService(this, 1, Intent(this, DoorAccessService::class.java).setAction(PAUSE), PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val notification = NotificationCompat.Builder(this, CHANNEL).setSmallIcon(R.drawable.ic_notification)
            .setContentTitle("DoorKey · acces automat").setContentText("Pregătit pentru apropierea de cititor")
            .setContentIntent(open).setOngoing(true).setSilent(true).addAction(0, "Oprește", pause).build()
        ServiceCompat.startForeground(this, 21, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE)
        controller.start()
        return START_STICKY
    }
    override fun onDestroy() { controller.close(); scope.cancel(); unregisterReceiver(bluetoothState); super.onDestroy() }
    override fun onBind(intent: Intent?): IBinder? = null
    companion object {
        const val PAUSE = "com.era.doorkey.PAUSE"
        private const val CHANNEL = "doorkey.access"
        fun allowed(context: Context) = listOf(Manifest.permission.BLUETOOTH_SCAN, Manifest.permission.BLUETOOTH_CONNECT).all { ContextCompat.checkSelfPermission(context, it) == PackageManager.PERMISSION_GRANTED }
        fun start(context: Context) { ContextCompat.startForegroundService(context, Intent(context, DoorAccessService::class.java)) }
    }
}
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED || !DoorAccessService.allowed(context)) return
        val wallet = (context.applicationContext as DoorKeyApplication).wallet
        if (wallet.state.value.automatic && wallet.activeKeys().isNotEmpty()) runCatching { DoorAccessService.start(context) }
            .onFailure { wallet.log("Deschide aplicația pentru a reactiva accesul automat.") }
    }
}
