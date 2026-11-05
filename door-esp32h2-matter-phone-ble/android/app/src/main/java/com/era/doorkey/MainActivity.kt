package com.era.doorkey

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.Locale

private val Canvas = Color(0xff0f1219)
private val Surface = Color(0xff1a1f2b)
private val Ink = Color(0xfff1eee6)
private val Muted = Color(0xffa9afbc)
private val Lime = Color(0xffe6ef5a)
private val Line = Color(0xff2c3343)
class MainActivity : ComponentActivity() {
    private val wallet get() = (application as DoorKeyApplication).wallet
    private val bluetooth = registerForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { grants ->
        if (DoorAccessService.allowed(this)) startAccess() else wallet.error("Permite accesul la dispozitive din apropiere pentru Bluetooth.")
    }
    private val notification = registerForActivityResult(ActivityResultContracts.RequestPermission()) { startAccess() }
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme(colorScheme = darkColorScheme(primary = Lime, onPrimary = Canvas, background = Canvas, surface = Surface, onSurface = Ink, onBackground = Ink, onSurfaceVariant = Muted)) {
                WalletScreen(wallet, ::enableAccess, { stopService(Intent(this, DoorAccessService::class.java)) }, {
                    wallet.rememberReader(null); stopService(Intent(this, DoorAccessService::class.java)); startAccess()
                })
            }
        }
    }
    override fun onResume() { super.onResume(); wallet.uiVisible = true; if (DoorAccessService.allowed(this)) startAccess() }
    override fun onPause() { wallet.uiVisible = false; super.onPause() }
    private fun startAccess() {
        if (wallet.state.value.automatic && wallet.activeKeys().isNotEmpty() && DoorAccessService.allowed(this)) {
            runCatching { DoorAccessService.start(this) }.onFailure { wallet.error("Deschide aplicația pentru a reactiva accesul automat: ${it.message}") }
        }
    }
    private fun enableAccess() {
        if (!DoorAccessService.allowed(this)) bluetooth.launch(arrayOf(Manifest.permission.BLUETOOTH_SCAN, Manifest.permission.BLUETOOTH_CONNECT))
        else if (Build.VERSION.SDK_INT >= 33 && ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) notification.launch(Manifest.permission.POST_NOTIFICATIONS)
        else startAccess()
    }
}
@Composable private fun WalletScreen(wallet: WalletStore, enable: () -> Unit, stop: () -> Unit, search: () -> Unit) {
    val state by wallet.state.collectAsStateWithLifecycle()
    val scope = rememberCoroutineScope()
    var scanner by remember { mutableStateOf(false) }
    var diagnostics by remember { mutableStateOf(false) }
    var removing by remember { mutableStateOf<WalletKey?>(null) }
    var now by remember { mutableLongStateOf(System.currentTimeMillis() / 1000) }
    LaunchedEffect(Unit) { while (true) { delay(30000); now = System.currentTimeMillis() / 1000 } }
    LaunchedEffect(state.keys, state.enrolling) { if (!state.enrolling && state.keys.isNotEmpty()) enable() }
    fun add(link: String) { scanner = false; scope.launch { wallet.enroll(link); enable() } }
    Scaffold(containerColor = Canvas) { padding ->
        LazyColumn(Modifier.fillMaxSize().padding(padding), contentPadding = PaddingValues(22.dp), verticalArrangement = Arrangement.spacedBy(20.dp)) {
            item {
                Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text("era.", color = Lime, fontFamily = FontFamily.Serif, fontSize = 30.sp)
                        Spacer(Modifier.height(12.dp))
                        Text("Cheile tale", fontFamily = FontFamily.Serif, fontSize = 38.sp)
                        Text("Un sejur. Acces simplu.", color = Muted, fontSize = 15.sp)
                    }
                    FilledIconButton(onClick = { scanner = true }, enabled = !state.enrolling, modifier = Modifier.size(54.dp), shape = CircleShape) { Icon(Icons.Outlined.Add, "Adaugă o cheie", Modifier.size(28.dp)) }
                }
            }
            if (state.enrolling) item { Panel { Row(verticalAlignment = Alignment.CenterVertically) { CircularProgressIndicator(Modifier.size(24.dp), color = Lime); Spacer(Modifier.width(16.dp)); Text("Se descarcă și se verifică cheia…") } } }
            if (state.keys.isEmpty() && !state.enrolling) item {
                Panel {
                    Box(Modifier.size(64.dp).background(Lime.copy(alpha = .10f), CircleShape), contentAlignment = Alignment.Center) { Icon(Icons.Outlined.Key, null, Modifier.size(32.dp), tint = Lime) }
                    Spacer(Modifier.height(24.dp)); Text("Nu ai chei încă", fontFamily = FontFamily.Serif, fontSize = 28.sp)
                    Spacer(Modifier.height(10.dp)); Text("După check-in, scanează invitația QR primită de la recepție.", color = Muted, lineHeight = 23.sp)
                    Spacer(Modifier.height(24.dp)); Button(onClick = { scanner = true }, modifier = Modifier.fillMaxWidth().height(52.dp)) { Icon(Icons.Outlined.QrCodeScanner, null); Spacer(Modifier.width(10.dp)); Text("Scanează invitația") }
                }
            }
            items(state.keys, key = { it.id }) { key ->
                KeyCard(key, state, now, { removing = key })
            }
            if (state.keys.isNotEmpty()) item {
                Panel {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) { Text("Acces automat", fontWeight = FontWeight.Medium); Text("Inclusiv cu ecranul blocat", color = Muted, fontSize = 13.sp) }
                        Switch(state.automatic, onCheckedChange = { wallet.automatic(it); if (it) enable() else stop() })
                    }
                    HorizontalDivider(Modifier.padding(vertical = 16.dp), color = Line)
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        if (state.busy) CircularProgressIndicator(Modifier.size(16.dp), strokeWidth = 2.dp) else Icon(Icons.Outlined.Bluetooth, null, Modifier.size(20.dp), tint = Lime)
                        Spacer(Modifier.width(10.dp)); Text(if (state.automatic) state.status else "Accesul automat este oprit", fontSize = 14.sp)
                    }
                    Spacer(Modifier.height(12.dp)); Text("Apropie telefonul de cititor. Accesul se verifică online la fiecare încercare.", color = Muted, fontSize = 13.sp, lineHeight = 20.sp)
                }
            }
            item {
                Text("Cheia privată rămâne pe telefonul tău.", color = Muted, fontSize = 12.sp)
                TextButton(onClick = { diagnostics = true }, contentPadding = PaddingValues(vertical = 8.dp)) { Text("Diagnostic", color = Muted, fontSize = 12.sp) }
            }
        }
    }
    if (scanner) QrScanner(onDismiss = { scanner = false }, onCode = ::add)
    if (state.error != null) AlertDialog(onDismissRequest = { wallet.error(null) }, title = { Text("DoorKey") }, text = { Text(state.error!!) }, confirmButton = { TextButton(onClick = { wallet.error(null) }) { Text("Am înțeles") } })
    removing?.let { key -> AlertDialog(onDismissRequest = { removing = null }, title = { Text("Ștergi cheia?") }, text = { Text("Pentru ${key.title} vei avea nevoie de o invitație nouă de la recepție.") }, confirmButton = { TextButton(onClick = { runCatching { wallet.remove(key.id) }.onFailure { wallet.error("Cheia nu a putut fi ștearsă") }; removing = null }) { Text("Șterge") } }, dismissButton = { TextButton(onClick = { removing = null }) { Text("Anulează") } }) }
    if (diagnostics) AlertDialog(onDismissRequest = { diagnostics = false }, title = { Text("Diagnostic Bluetooth") }, text = {
        LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            item { Text(state.status); Text(state.signal, color = Muted) }
            item { Text("O singură conexiune cu un cititor este activă. Pentru altă ușă, caută din nou. Închide conexiunea iOS dacă testezi aceeași placă.", color = Muted, fontSize = 13.sp) }
            items(state.logs.take(20)) { Text(it, fontSize = 11.sp) }
        }
    }, confirmButton = { TextButton(onClick = { diagnostics = false; search() }) { Text("Caută din nou") } }, dismissButton = { TextButton(onClick = { diagnostics = false }) { Text("Închide") } })
}
@Composable private fun Panel(content: @Composable ColumnScope.() -> Unit) {
    Column(Modifier.fillMaxWidth().background(Surface, RoundedCornerShape(26.dp)).border(1.dp, Line, RoundedCornerShape(26.dp)).padding(22.dp), content = content)
}
@Composable private fun KeyCard(key: WalletKey, state: WalletState, now: Long, remove: () -> Unit) {
    val validFrom = remember(key.permit) { runCatching { key.permit.unbase64().le(5, 8) }.getOrDefault(0) }
    val expired = key.expired(now)
    val stateLabel = when { key.accessDenied -> "Acces refuzat"; expired -> "Expirată"; now < validFrom -> "Valabilă în curând"; else -> "În perioada de valabilitate" }
    val formatter = remember(key.timezone) { DateTimeFormatter.ofPattern("d MMM yyyy, HH:mm", Locale.forLanguageTag("ro-RO")).withZone(runCatching { ZoneId.of(key.timezone ?: "Europe/Bucharest") }.getOrDefault(ZoneId.of("Europe/Bucharest"))) }
    Panel {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Outlined.Key, null, tint = Lime, modifier = Modifier.size(28.dp)); Spacer(Modifier.width(10.dp))
            Text(key.propertyName ?: "era. retreat", color = Muted, modifier = Modifier.weight(1f), fontSize = 13.sp)
            IconButton(onClick = remove, modifier = Modifier.size(32.dp)) { Icon(Icons.Outlined.MoreHoriz, "Șterge cheia", tint = Muted) }
        }
        Spacer(Modifier.height(22.dp)); Text(key.title, fontFamily = FontFamily.Serif, fontSize = 36.sp)
        Spacer(Modifier.height(12.dp)); Text(stateLabel, color = if (expired || key.accessDenied) Muted else Lime, fontSize = 13.sp)
        HorizontalDivider(Modifier.padding(vertical = 20.dp), color = Line)
        Text("VALABILĂ PÂNĂ LA", fontSize = 10.sp, color = Muted, letterSpacing = 1.sp)
        Spacer(Modifier.height(6.dp)); Text(formatter.format(Instant.ofEpochSecond(key.expiresAt)), fontSize = 16.sp)
        if (now < validFrom) Text("Din ${formatter.format(Instant.ofEpochSecond(validFrom))}", color = Muted, fontSize = 12.sp)
        if (state.connected && state.activeKeyId == key.id) { Spacer(Modifier.height(16.dp)); Text("●  Conectat la cititor", color = Lime, fontSize = 12.sp) }
        key.lastAuthorized?.let { Spacer(Modifier.height(12.dp)); Text("Ultimul acces autorizat: ${formatter.format(Instant.ofEpochMilli(it))}", color = Muted, fontSize = 11.sp) }
    }
}
