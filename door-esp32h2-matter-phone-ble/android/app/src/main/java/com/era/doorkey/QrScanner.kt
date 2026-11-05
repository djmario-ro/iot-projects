package com.era.doorkey

import android.Manifest
import android.content.pm.PackageManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.google.zxing.BinaryBitmap
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

@Composable fun QrScanner(onDismiss: () -> Unit, onCode: (String) -> Unit) {
    val context = LocalContext.current
    var permitted by remember { mutableStateOf(ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) }
    var link by remember { mutableStateOf("") }
    val permission = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { permitted = it }
    LaunchedEffect(Unit) { if (!permitted) permission.launch(Manifest.permission.CAMERA) }
    Dialog(onDismissRequest = onDismiss, properties = DialogProperties(usePlatformDefaultWidth = false)) {
        Surface(Modifier.fillMaxSize()) {
            Column(Modifier.windowInsetsPadding(WindowInsets.safeDrawing).padding(22.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
                Text("Adaugă o cheie", style = MaterialTheme.typography.headlineMedium)
                Text("Scanează invitația QR primită de la recepție.", color = MaterialTheme.colorScheme.onSurfaceVariant)
                if (permitted) CameraQr(Modifier.fillMaxWidth().weight(1f), onCode)
                else { Text("Permite accesul la cameră sau lipește linkul invitației."); TextButton(onClick = { permission.launch(Manifest.permission.CAMERA) }) { Text("Permite camera") }; Spacer(Modifier.weight(1f)) }
                OutlinedTextField(link, onValueChange = { link = it }, label = { Text("Sau lipește linkul invitației") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                Button(onClick = { onCode(link) }, enabled = link.isNotBlank(), modifier = Modifier.fillMaxWidth()) { Text("Descarcă cheia") }
                TextButton(onClick = onDismiss, modifier = Modifier.fillMaxWidth()) { Text("Anulează") }
            }
        }
    }
}
@Composable private fun CameraQr(modifier: Modifier, onCode: (String) -> Unit) {
    val context = LocalContext.current
    val lifecycle = LocalLifecycleOwner.current
    val currentCode by rememberUpdatedState(onCode)
    val view = remember { PreviewView(context) }
    val executor = remember { Executors.newSingleThreadExecutor() }
    val delivered = remember { AtomicBoolean(false) }
    var cameraError by remember { mutableStateOf(false) }
    DisposableEffect(lifecycle) {
        val future = ProcessCameraProvider.getInstance(context)
        var disposed = false
        var provider: ProcessCameraProvider? = null
        val preview = Preview.Builder().build().also { it.setSurfaceProvider(view.surfaceProvider) }
        val analysis = ImageAnalysis.Builder().setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST).build()
        val reader = QRCodeReader()
        analysis.setAnalyzer(executor) { image ->
            try {
                if (!delivered.get()) {
                    val plane = image.planes[0]; val buffer = plane.buffer
                    val data = ByteArray(buffer.remaining()); buffer.get(data)
                    val gray = ByteArray(image.width * image.height)
                    for (y in 0 until image.height) for (x in 0 until image.width) gray[y * image.width + x] = data[y * plane.rowStride + x * plane.pixelStride]
                    val source = PlanarYUVLuminanceSource(gray, image.width, image.height, 0, 0, image.width, image.height, false)
                    val result = reader.decode(BinaryBitmap(HybridBinarizer(source)))
                    if (delivered.compareAndSet(false, true)) ContextCompat.getMainExecutor(context).execute { if (!disposed) currentCode(result.text) }
                }
            } catch (_: Exception) { /* No QR in this frame. */ }
            finally { reader.reset(); image.close() }
        }
        future.addListener({
            if (!disposed) runCatching { provider = future.get(); provider!!.bindToLifecycle(lifecycle, CameraSelector.DEFAULT_BACK_CAMERA, preview, analysis) }.onFailure { cameraError = true }
        }, ContextCompat.getMainExecutor(context))
        onDispose { disposed = true; analysis.clearAnalyzer(); provider?.unbind(preview, analysis); executor.shutdown() }
    }
    if (cameraError) Text("Camera nu este disponibilă. Lipește linkul invitației.", modifier = modifier)
    else AndroidView(factory = { view }, modifier = modifier)
}
