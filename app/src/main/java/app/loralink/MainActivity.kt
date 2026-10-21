package app.loralink

import android.Manifest
import android.annotation.SuppressLint
import android.bluetooth.BluetoothDevice
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.webkit.*
import android.widget.*
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.util.concurrent.Executors

/**
 * LoRa Link Android app: the device's own web page (bundled in assets/index.html) shown in a WebView,
 * with every /api/... request carried over Bluetooth LE instead of Wi-Fi.
 */
class MainActivity : AppCompatActivity(), BleLink.Listener {
    private val HOST = "https://lora.app"
    private lateinit var link: BleLink
    private lateinit var root: FrameLayout
    private lateinit var pickerView: LinearLayout
    private lateinit var status: TextView
    private lateinit var list: ListView
    private lateinit var slugBox: EditText
    private var web: WebView? = null
    private val found = ArrayList<BluetoothDevice>()
    private val names = ArrayList<String>()
    private lateinit var adapter: ArrayAdapter<String>
    private val pool = Executors.newFixedThreadPool(2)
    private var fileCb: ValueCallback<Array<Uri>>? = null
    private val prefs by lazy { getSharedPreferences("loralink", Context.MODE_PRIVATE) }

    private val permLauncher = registerForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { startScanNow() }
    private val fileLauncher = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { r ->
        val d = r.data
        val u: Array<Uri>? = if (r.resultCode == RESULT_OK && d != null) WebChromeClient.FileChooserParams.parseResult(r.resultCode, d) else null
        fileCb?.onReceiveValue(u); fileCb = null
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        link = BleLink(this).also { it.listener = this }
        root = FrameLayout(this)
        setContentView(root)
        buildPicker()
    }

    // ---------------------------------------------------------------- device picker
    private fun buildPicker() {
        pickerView = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(40, 80, 40, 40) }
        val title = TextView(this).apply { text = "LoRa Link"; textSize = 26f }
        status = TextView(this).apply { text = "Tap Scan, then choose your device."; setPadding(0, 16, 0, 16) }
        slugBox = EditText(this).apply {
            hint = "Personal link name, e.g. a1 (empty = admin)"
            setText(prefs.getString("slug", ""))
            setSingleLine(true)
        }
        val scan = Button(this).apply { text = "Scan"; setOnClickListener { askPermissionsAndScan() } }
        adapter = ArrayAdapter(this, android.R.layout.simple_list_item_1, names)
        list = ListView(this).apply {
            this.adapter = this@MainActivity.adapter
            setOnItemClickListener { _, _, i, _ ->
                prefs.edit().putString("slug", slugBox.text.toString().trim().trim('/')).apply()
                prefs.edit().putString("last", found[i].address).apply()
                link.connect(found[i])
            }
        }
        pickerView.addView(title); pickerView.addView(status); pickerView.addView(slugBox); pickerView.addView(scan)
        pickerView.addView(list, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f))
        root.addView(pickerView)
    }

    private fun askPermissionsAndScan() {
        val p = ArrayList<String>()
        if (Build.VERSION.SDK_INT >= 31) { p.add(Manifest.permission.BLUETOOTH_SCAN); p.add(Manifest.permission.BLUETOOTH_CONNECT) }
        p.add(Manifest.permission.ACCESS_FINE_LOCATION)
        p.add(Manifest.permission.RECORD_AUDIO)
        permLauncher.launch(p.toTypedArray())
    }

    private fun startScanNow() { found.clear(); names.clear(); adapter.notifyDataSetChanged(); link.startScan() }

    override fun onFound(dev: BluetoothDevice, name: String) = runOnUiThread {
        if (found.none { it.address == dev.address }) { found.add(dev); names.add("$name\n${dev.address}"); adapter.notifyDataSetChanged() }
    }

    override fun onState(text: String, connected: Boolean) = runOnUiThread {
        status.text = text
        if (connected) showWeb()
        else if (web != null && text == "Disconnected") {
            Toast.makeText(this, "Bluetooth disconnected", Toast.LENGTH_SHORT).show()
            root.removeView(web); web?.destroy(); web = null
            pickerView.visibility = View.VISIBLE
        }
    }

    // ---------------------------------------------------------------- web view
    private fun shim(): String = """
<script>(function(){
var cb={},n=0,of=window.fetch;
window.__bleResp=function(id,st,hd,body){var c=cb[id];if(!c)return;delete cb[id];
  var init={status:st>=200&&st<=599?st:502,headers:JSON.parse(hd||'{}')};
  if(init.status===204||init.status===205||init.status===304)body=null;
  c.res(new Response(body,init));};
window.__bleErr=function(id,m){var c=cb[id];if(!c)return;delete cb[id];c.rej(new TypeError(m||'Bluetooth error'));};
window.fetch=function(u,o){
  var url=(typeof u==='string')?u:(u&&u.url)||'';
  if(url.indexOf('/api/')<0)return of.apply(this,arguments);
  o=o||{};var h={};
  if(o.headers){if(typeof o.headers.forEach==='function'&&!Array.isArray(o.headers)){o.headers.forEach(function(v,k){h[k]=v;});}else{for(var k in o.headers)h[k]=o.headers[k];}}
  var m=(o.method||'GET').toUpperCase(),b=(o.body==null)?'':String(o.body);
  var p=url.replace(/^https?:\/\/[^\/]+/,'');
  return new Promise(function(res,rej){var id=++n;cb[id]={res:res,rej:rej};
    try{Android.req(id,m,p,JSON.stringify(h),b);}catch(e){delete cb[id];rej(e);}});
};
})();</script>
"""

    @SuppressLint("SetJavaScriptEnabled", "JavascriptInterface")
    private fun showWeb() {
        if (web != null) return
        val w = WebView(this)
        w.settings.javaScriptEnabled = true
        w.settings.domStorageEnabled = true
        w.settings.mediaPlaybackRequiresUserGesture = false
        w.settings.setGeolocationEnabled(true)
        w.settings.allowFileAccess = false
        w.addJavascriptInterface(Bridge(), "Android")
        w.webViewClient = object : WebViewClient() {
            override fun shouldInterceptRequest(v: WebView, r: WebResourceRequest): WebResourceResponse? {
                val u = r.url
                if (u.host != "lora.app") return null
                val path = u.encodedPath ?: "/"
                if (path.startsWith("/api/")) {
                    val q = u.encodedQuery?.let { "?$it" } ?: ""
                    val raw = HttpRaw.build(r.method, path + q, r.requestHeaders, null)
                    val ans = link.request(raw) ?: return err(504)
                    val p = HttpRaw.parse(ans)
                    val ct = p.contentType.substringBefore(';').trim()
                    val hdr = HashMap<String, String>(); hdr["Cache-Control"] = "no-store"
                    return WebResourceResponse(ct, "utf-8", p.status, p.reason.ifEmpty { "OK" }, hdr, ByteArrayInputStream(p.body))
                }
                if (path == "/sw.js" || path == "/favicon.ico") return err(404)
                val html = assets.open("index.html").bufferedReader().readText().replaceFirst("<head>", "<head>" + shim())
                return WebResourceResponse("text/html", "utf-8", ByteArrayInputStream(html.toByteArray()))
            }
            private fun err(code: Int) = WebResourceResponse("text/plain", "utf-8", code, "Error", emptyMap(), ByteArrayInputStream(ByteArray(0)))

            override fun shouldOverrideUrlLoading(v: WebView, r: WebResourceRequest): Boolean {
                val u = r.url
                if (u.host == "lora.app") return false
                try {
                    val i = if (u.scheme == "intent") Intent.parseUri(u.toString(), Intent.URI_INTENT_SCHEME) else Intent(Intent.ACTION_VIEW, u)
                    startActivity(i)
                } catch (e: Exception) {
                    try {   // intent: with a fallback url, or no app installed
                        val fb = Uri.parse(u.toString()).let { if (u.scheme == "intent") Intent.parseUri(u.toString(), Intent.URI_INTENT_SCHEME).getStringExtra("browser_fallback_url") else null }
                        if (fb != null) startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(fb)))
                    } catch (_: Exception) {}
                }
                return true
            }
        }
        w.webChromeClient = object : WebChromeClient() {
            override fun onGeolocationPermissionsShowPrompt(origin: String, cb: GeolocationPermissions.Callback) { cb.invoke(origin, true, false) }
            override fun onPermissionRequest(req: PermissionRequest) { runOnUiThread { req.grant(req.resources) } }
            override fun onShowFileChooser(v: WebView, cb: ValueCallback<Array<Uri>>, p: FileChooserParams): Boolean {
                fileCb?.onReceiveValue(null); fileCb = cb
                return try { fileLauncher.launch(p.createIntent()); true } catch (e: Exception) { fileCb = null; false }
            }
        }
        w.setDownloadListener { url, _, cd, mime, _ ->
            Toast.makeText(this, "Open the file in the chat to save it", Toast.LENGTH_SHORT).show()
        }
        web = w
        root.addView(w, FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT))
        pickerView.visibility = View.GONE
        val slug = (prefs.getString("slug", "") ?: "").trim('/')
        w.loadUrl("$HOST/$slug")
    }

    /** JavaScript -> Bluetooth: the page's fetch('/api/...') ends up here. */
    inner class Bridge {
        @JavascriptInterface
        fun req(id: Int, method: String, path: String, headersJson: String, body: String) {
            pool.execute {
                val wv = web ?: return@execute
                try {
                    val hj = JSONObject(headersJson)
                    val hm = HashMap<String, String>()
                    for (k in hj.keys()) hm[k] = hj.getString(k)
                    val b = if (method == "GET" || method == "HEAD") null else body.toByteArray(Charsets.UTF_8)
                    val raw = HttpRaw.build(method, path, hm, b)
                    val ans = link.request(raw)
                    if (ans == null) { post(wv, "__bleErr($id,${JSONObject.quote("No answer over Bluetooth")})"); return@execute }
                    val p = HttpRaw.parse(ans)
                    val hdr = JSONObject(); hdr.put("Content-Type", p.contentType)
                    post(wv, "__bleResp($id,${p.status},${JSONObject.quote(hdr.toString())},${JSONObject.quote(String(p.body, Charsets.UTF_8))})")
                } catch (e: Exception) {
                    post(wv, "__bleErr($id,${JSONObject.quote(e.message ?: "error")})")
                }
            }
        }
        private fun post(wv: WebView, js: String) = wv.post { wv.evaluateJavascript(js, null) }
    }

    @Deprecated("Deprecated in Java")
    override fun onBackPressed() {
        val w = web
        if (w != null && w.canGoBack()) w.goBack() else if (w != null) w.evaluateJavascript("history.back()", null) else super.onBackPressed()
    }

    override fun onDestroy() { link.disconnect(); super.onDestroy() }
}
