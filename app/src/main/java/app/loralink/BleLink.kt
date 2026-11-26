package app.loralink

import android.annotation.SuppressLint
import android.bluetooth.*
import android.bluetooth.le.*
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.os.ParcelUuid
import java.io.ByteArrayOutputStream
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Semaphore
import java.util.concurrent.TimeUnit

/**
 * BLE link to the LoRa Link device.
 * Wire format (both ways): [u32 length, little endian][length bytes of raw HTTP text].
 * One request at a time; request() blocks, so call it from a background thread.
 */
@SuppressLint("MissingPermission")
class BleLink(private val ctx: Context) {
    companion object {
        val SVC: UUID = UUID.fromString("6E400001-B5A3-F393-E0A9-E50E24DCCA9E")
        val RX: UUID = UUID.fromString("6E400002-B5A3-F393-E0A9-E50E24DCCA9E")   // app -> device
        val TX: UUID = UUID.fromString("6E400003-B5A3-F393-E0A9-E50E24DCCA9E")   // device -> app
        val CCCD: UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")
    }

    interface Listener {
        fun onFound(dev: BluetoothDevice, name: String)
        fun onState(text: String, connected: Boolean)
    }

    var listener: Listener? = null
    private val adapter: BluetoothAdapter? = (ctx.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager).adapter
    private var scanner: BluetoothLeScanner? = null
    private var gatt: BluetoothGatt? = null
    private var rxChar: BluetoothGattCharacteristic? = null
    @Volatile private var mtu = 23
    @Volatile var connected = false
        private set
    @Volatile private var connecting = false
    @Volatile var wrongPin = false
    private var lastDev: BluetoothDevice? = null
    private var seq = 0
    var pin: String = "123456"

    private val writeDone = Semaphore(0)
    private var readyLatch = CountDownLatch(1)
    private val inBuf = ByteArrayOutputStream()
    private val inLock = Any()
    private val reqLock = Object()

    // ------------------------------------------------------------ scan
    private val scanCb = object : ScanCallback() {
        override fun onScanResult(type: Int, r: ScanResult) {
            listener?.onFound(r.device, r.device.name ?: r.scanRecord?.deviceName ?: r.device.address)
        }
        override fun onScanFailed(code: Int) { listener?.onState("Scan failed ($code)", false) }
    }

    fun startScan() {
        val ad = adapter ?: run { listener?.onState("This phone has no Bluetooth", false); return }
        if (!ad.isEnabled) { listener?.onState("Turn Bluetooth on", false); return }
        scanner = ad.bluetoothLeScanner
        val f = ScanFilter.Builder().setServiceUuid(ParcelUuid(SVC)).build()
        val s = ScanSettings.Builder().setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY).build()
        scanner?.startScan(listOf(f), s, scanCb)
        listener?.onState("Scanning...", false)
    }

    fun stopScan() { try { scanner?.stopScan(scanCb) } catch (_: Exception) {} }

    // ------------------------------------------------------------ connect (pairs with the PIN the first time)
    /** Reconnects to the last device (used after the Bluetooth link dropped). */
    fun reconnect() { val d = lastDev ?: return; if (!connected && !connecting) connect(d) }

    fun connect(dev: BluetoothDevice) {
        stopScan()
        if (connecting) return
        connecting = true
        wrongPin = false
        lastDev = dev
        Thread {
            try {
                try { gatt?.close() } catch (_: Exception) {}
                gatt = null
                listener?.onState("Connecting...", false)
                readyLatch = CountDownLatch(1)
                gatt = if (Build.VERSION.SDK_INT >= 23) dev.connectGatt(ctx, false, gattCb, BluetoothDevice.TRANSPORT_LE)
                       else dev.connectGatt(ctx, false, gattCb)
                if (!readyLatch.await(25, TimeUnit.SECONDS)) {
                    try { gatt?.close() } catch (_: Exception) {}
                    gatt = null
                    connecting = false
                    listener?.onState("Could not connect", false)
                }
            } catch (e: Exception) { connecting = false; listener?.onState("Error: ${e.message}", false) }
        }.start()
    }

    private fun bond(dev: BluetoothDevice): Boolean {
        val latch = CountDownLatch(1)
        var ok = false
        val rc = object : BroadcastReceiver() {
            override fun onReceive(c: Context, i: Intent) {
                val d = i.getParcelableExtra<BluetoothDevice>(BluetoothDevice.EXTRA_DEVICE)
                if (d?.address != dev.address) return
                when (i.getIntExtra(BluetoothDevice.EXTRA_BOND_STATE, -1)) {
                    BluetoothDevice.BOND_BONDED -> { ok = true; latch.countDown() }
                    BluetoothDevice.BOND_NONE -> latch.countDown()
                }
            }
        }
        ctx.registerReceiver(rc, IntentFilter(BluetoothDevice.ACTION_BOND_STATE_CHANGED))
        try {
            if (!dev.createBond()) return false
            latch.await(90, TimeUnit.SECONDS)
        } finally { try { ctx.unregisterReceiver(rc) } catch (_: Exception) {} }
        return ok
    }

    fun disconnect() {
        connected = false
        try { gatt?.disconnect(); gatt?.close() } catch (_: Exception) {}
        gatt = null
    }

    private val gattCb = object : BluetoothGattCallback() {
        override fun onConnectionStateChange(g: BluetoothGatt, status: Int, newState: Int) {
            if (newState == BluetoothProfile.STATE_CONNECTED) {
                g.requestMtu(247)
            } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                val was = connected
                connected = false
                connecting = false
                if (!was) readyLatch.countDown()
                synchronized(inLock) { (inLock as Object).notifyAll() }
                writeDone.release()
                if (!wrongPin) listener?.onState(if (was) "Disconnected (code $status)" else "Could not connect (code $status)", false)
                try { g.close() } catch (_: Exception) {}
            }
        }
        override fun onMtuChanged(g: BluetoothGatt, m: Int, status: Int) { mtu = m; g.discoverServices() }
        override fun onServicesDiscovered(g: BluetoothGatt, status: Int) {
            val svc = g.getService(SVC)
            if (svc == null) { listener?.onState("This is not a LoRa Link device", false); disconnect(); return }
            rxChar = svc.getCharacteristic(RX)
            val tx = svc.getCharacteristic(TX)
            g.setCharacteristicNotification(tx, true)
            val d = tx.getDescriptor(CCCD)
            d.value = BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
            g.writeDescriptor(d)
        }
        override fun onDescriptorWrite(g: BluetoothGatt, d: BluetoothGattDescriptor, status: Int) {
            connected = true
            Thread {
                // the first frame must be the PIN
                val a = request(("AUTH " + pin).toByteArray(), 8000)
                val code = if (a == null) -1 else HttpRaw.parse(a).status
                connecting = false
                if (code == 200) {
                    listener?.onState("Connected", true)
                    readyLatch.countDown()
                } else {
                    val msg = when (code) { 401 -> "Wrong PIN"; 429 -> "Too many wrong PINs - wait a minute"; else -> "No answer from the device" }
                    listener?.onState(msg, false)
                    wrongPin = (code == 401 || code == 429)
                    readyLatch.countDown()
                    disconnect()
                }
            }.start()
        }
        override fun onCharacteristicWrite(g: BluetoothGatt, c: BluetoothGattCharacteristic, status: Int) { writeDone.release() }
        override fun onCharacteristicChanged(g: BluetoothGatt, c: BluetoothGattCharacteristic) {
            synchronized(inLock) { inBuf.write(c.value); (inLock as Object).notifyAll() }
        }
    }

    // ------------------------------------------------------------ request / response
    /** Sends raw HTTP text and returns the raw HTTP answer (null on failure / timeout). */
    fun request(raw: ByteArray, timeoutMs: Long = 20000): ByteArray? {
        synchronized(reqLock) {
            val g = gatt ?: return null
            val rx = rxChar ?: return null
            if (!connected) return null
            synchronized(inLock) { inBuf.reset() }
            seq = (seq + 1) and 255
            val mySeq = seq
            val frame = ByteArray(5 + raw.size)
            frame[0] = mySeq.toByte()
            frame[1] = (raw.size and 255).toByte(); frame[2] = ((raw.size shr 8) and 255).toByte()
            frame[3] = ((raw.size shr 16) and 255).toByte(); frame[4] = ((raw.size shr 24) and 255).toByte()
            System.arraycopy(raw, 0, frame, 5, raw.size)
            val chunk = maxOf(20, mtu - 3)
            var off = 0
            writeDone.drainPermits()
            while (off < frame.size) {
                val end = minOf(frame.size, off + chunk)
                rx.writeType = BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT
                rx.value = frame.copyOfRange(off, end)
                if (!g.writeCharacteristic(rx)) return null
                if (!writeDone.tryAcquire(5, TimeUnit.SECONDS)) return null
                off = end
            }
            val deadline = System.currentTimeMillis() + timeoutMs
            synchronized(inLock) {
                while (true) {
                    val b = inBuf.toByteArray()
                    // look for our answer: [seq][len4][data]; stale bytes of an earlier (timed out) answer are skipped
                    var i = 0
                    while (i + 5 <= b.size) {
                        if ((b[i].toInt() and 255) == mySeq) {
                            val len = (b[i + 1].toInt() and 255) or ((b[i + 2].toInt() and 255) shl 8) or
                                    ((b[i + 3].toInt() and 255) shl 16) or ((b[i + 4].toInt() and 255) shl 24)
                            if (len in 1..2_000_000) {
                                if (b.size >= i + 5 + len) return b.copyOfRange(i + 5, i + 5 + len)
                                break
                            }
                        }
                        i++
                    }
                    val left = deadline - System.currentTimeMillis()
                    if (left <= 0 || !connected) return null
                    (inLock as Object).wait(left)
                }
            }
        }
    }
}
