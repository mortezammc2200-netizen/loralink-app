package app.loralink

import java.io.ByteArrayOutputStream

/** Builds raw HTTP requests for the device and parses its answers. */
object HttpRaw {
    class Resp(val status: Int, val reason: String, val headers: Map<String, String>, val body: ByteArray) {
        val contentType: String get() = headers["content-type"] ?: "application/octet-stream"
    }

    fun build(method: String, path: String, headers: Map<String, String>, body: ByteArray?): ByteArray {
        val o = ByteArrayOutputStream()
        val sb = StringBuilder()
        sb.append(method).append(' ').append(path).append(" HTTP/1.1\r\n")
        sb.append("Host: 192.168.4.1\r\n")
        for ((k, v) in headers) {
            val kl = k.lowercase()
            if (kl == "host" || kl == "content-length" || kl == "connection" || kl == "accept-encoding") continue
            sb.append(k).append(": ").append(v.replace("\r", "").replace("\n", "")).append("\r\n")
        }
        if (body != null) sb.append("Content-Length: ").append(body.size).append("\r\n")
        sb.append("Connection: close\r\n\r\n")
        o.write(sb.toString().toByteArray(Charsets.ISO_8859_1))
        if (body != null) o.write(body)
        return o.toByteArray()
    }

    fun parse(raw: ByteArray): Resp {
        var he = -1
        for (i in 0 until raw.size - 3) {
            if (raw[i] == 13.toByte() && raw[i + 1] == 10.toByte() && raw[i + 2] == 13.toByte() && raw[i + 3] == 10.toByte()) { he = i; break }
        }
        if (he < 0) return Resp(502, "Bad Gateway", emptyMap(), ByteArray(0))
        val head = String(raw, 0, he, Charsets.ISO_8859_1).split("\r\n")
        val st = head[0].split(' ', limit = 3)
        val status = st.getOrNull(1)?.toIntOrNull() ?: 502
        val reason = st.getOrNull(2) ?: ""
        val h = HashMap<String, String>()
        for (i in 1 until head.size) {
            val c = head[i].indexOf(':')
            if (c > 0) h[head[i].substring(0, c).trim().lowercase()] = head[i].substring(c + 1).trim()
        }
        var body = raw.copyOfRange(he + 4, raw.size)
        if (h["transfer-encoding"]?.contains("chunked") == true) body = dechunk(body)
        else h["content-length"]?.toIntOrNull()?.let { if (it < body.size) body = body.copyOf(it) }
        return Resp(status, reason, h, body)
    }

    private fun dechunk(b: ByteArray): ByteArray {
        val o = ByteArrayOutputStream()
        var p = 0
        while (p < b.size) {
            var e = p
            while (e < b.size - 1 && !(b[e] == 13.toByte() && b[e + 1] == 10.toByte())) e++
            val n = String(b, p, e - p, Charsets.ISO_8859_1).trim().substringBefore(';').toIntOrNull(16) ?: break
            if (n == 0) break
            p = e + 2
            if (p + n > b.size) { o.write(b, p, b.size - p); break }
            o.write(b, p, n)
            p += n + 2
        }
        return o.toByteArray()
    }
}
