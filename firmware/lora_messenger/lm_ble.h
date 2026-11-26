// ===========================================================================
//  Bluetooth (BLE) bridge for the Android app.
//  The app speaks to this device over BLE instead of Wi-Fi. Every request of the web page is wrapped as a raw HTTP text,
//  sent through BLE, forwarded to this device's own web server (so every handler, login and the user rules stay exactly
//  the same) and the answer comes back the same way.
//
//  Wire format (both directions):  [u8 sequence][u32 length, little endian][length bytes of raw HTTP]   (the answer repeats the request's sequence)
//  BLE service (Nordic-UART-like):
//    service 6E400001-B5A3-F393-E0A9-E50E24DCCA9E
//    RX (app -> device, write)   6E400002-...
//    TX (device -> app, notify)  6E400003-...
//  Pairing: the link must be encrypted; Android asks for the 6-digit PIN shown in Settings > Bluetooth (admin only).
//
//  Needs the library "NimBLE-Arduino" (Library Manager) and  #define USE_BLE_BRIDGE 1  in the main sketch.
// ===========================================================================
#include <NimBLEDevice.h>
// NimBLE-Arduino 2.x (has NimBLEConnInfo.h) and 1.4.x have slightly different callback signatures
#if defined(__has_include)
#if __has_include(<NimBLEConnInfo.h>)
#define BLE_V2 1
#endif
#endif
#ifndef BLE_V2
#define BLE_V2 0
#endif

#define BLE_SVC_UUID "6E400001-B5A3-F393-E0A9-E50E24DCCA9E"
#define BLE_RX_UUID  "6E400002-B5A3-F393-E0A9-E50E24DCCA9E"
#define BLE_TX_UUID  "6E400003-B5A3-F393-E0A9-E50E24DCCA9E"
#define BLE_RING     12288
#define BLE_MAX_REQ  9000
#define BLE_MAX_RESP 24000

static uint8_t  bleRing[BLE_RING];
static volatile uint16_t bleHead = 0, bleTail = 0;          // single producer (BLE task) / single consumer (loop)
static NimBLEServer* bleSrv = nullptr;
static NimBLECharacteristic* bleTx = nullptr;
static volatile bool bleConn = false;
static volatile uint16_t bleConnHandle = 0;
static uint32_t blePin = 123456;
static bool bleReady = false;

static uint16_t bleCount() { return (uint16_t)((bleHead + BLE_RING - bleTail) % BLE_RING); }

static void bleFeed(const uint8_t* d, size_t n) {
  for (size_t i = 0; i < n; i++) {
    uint16_t nx = (uint16_t)((bleHead + 1) % BLE_RING);
    if (nx == bleTail) break;                                // overflow: drop (the app retries after a timeout)
    bleRing[bleHead] = d[i];
    bleHead = nx;
  }
}

class BleRxCb : public NimBLECharacteristicCallbacks {
#if BLE_V2
  void onWrite(NimBLECharacteristic* c, NimBLEConnInfo& info) {
#else
  void onWrite(NimBLECharacteristic* c) {
#endif
    auto v = c->getValue();
    bleFeed((const uint8_t*)v.data(), v.length());
  }
};

class BleSrvCb : public NimBLEServerCallbacks {
#if BLE_V2
  void onConnect(NimBLEServer* s, NimBLEConnInfo& info) {
    bleConnHandle = info.getConnHandle();
#else
  void onConnect(NimBLEServer* s, ble_gap_conn_desc* d) {
    bleConnHandle = d->conn_handle;
#endif
    bleConn = true;
    bleHead = bleTail = 0;
    bleSrv->updateConnParams(bleConnHandle, 24, 48, 0, 400);        // 30-60 ms interval, 4 s supervision timeout: survives Wi-Fi coexistence
  }
#if BLE_V2
  void onDisconnect(NimBLEServer* s, NimBLEConnInfo& info, int reason) {
#else
  void onDisconnect(NimBLEServer* s) {
#endif
    bleConn = false;
    bleHead = bleTail = 0;
    NimBLEDevice::startAdvertising();
  }
};

void bleInit() {
  uint32_t p = prefs.getUInt("blepin2", 123456);              // default PIN 123456 - change it in Settings > Bluetooth
  if (p < 100000 || p > 999999) p = 123456;
  blePin = p;
  Serial.printf("Bluetooth ready. Pairing PIN: %06u\n", (unsigned)blePin);
  String nm = String("LoRaLink-") + hex8(myUid).substring(4);
  NimBLEDevice::init(nm.c_str());
  NimBLEDevice::setMTU(247);
  NimBLEDevice::setSecurityAuth(true, true, true);                 // bonding + MITM + secure connections
  NimBLEDevice::setSecurityIOCap(BLE_HS_IO_DISPLAY_ONLY);
  NimBLEDevice::setSecurityPasskey(blePin);
  bleSrv = NimBLEDevice::createServer();
  bleSrv->setCallbacks(new BleSrvCb());
  NimBLEService* svc = bleSrv->createService(BLE_SVC_UUID);
  NimBLECharacteristic* rx = svc->createCharacteristic(BLE_RX_UUID, NIMBLE_PROPERTY::WRITE | NIMBLE_PROPERTY::WRITE_NR | NIMBLE_PROPERTY::WRITE_ENC | NIMBLE_PROPERTY::WRITE_AUTHEN);
  rx->setCallbacks(new BleRxCb());
  bleTx = svc->createCharacteristic(BLE_TX_UUID, NIMBLE_PROPERTY::NOTIFY | NIMBLE_PROPERTY::READ | NIMBLE_PROPERTY::READ_ENC | NIMBLE_PROPERTY::READ_AUTHEN);
  svc->start();
  NimBLEAdvertising* adv = NimBLEDevice::getAdvertising();
  adv->addServiceUUID(BLE_SVC_UUID);
#if BLE_V2
  adv->enableScanResponse(true);
#else
  adv->setScanResponse(true);
#endif
  adv->start();
  bleReady = true;
}

static void bleSend(const uint8_t* d, size_t n) {
  if (!bleConn || !bleTx) return;
  int mtu = bleSrv->getPeerMTU(bleConnHandle);
  size_t chunk = (mtu > 23 ? mtu - 3 : 20);
  if (chunk > 240) chunk = 240;
  for (size_t off = 0; off < n && bleConn; off += chunk) {
    size_t l = n - off < chunk ? n - off : chunk;
    bleTx->setValue(d + off, l);
    int tries = 0;
    while (!bleTx->notify() && bleConn && tries++ < 200) delay(4);   // the stack's queue is full for a moment
    delay(2);
  }
}

// forwards one raw HTTP request to our own web server and returns the raw answer
static void bleForward(uint8_t seq, const uint8_t* req, size_t rl) {
  WiFiClient cl;
  String resp;
  resp.reserve(2048);
  bool okc = cl.connect(IPAddress(127, 0, 0, 1), 80);                  // own web server through the loopback ...
  if (!okc) okc = cl.connect(WiFi.softAPIP(), 80);                      // ... or through the access-point address
  Serial.printf("BLE request %u bytes, connect to own web server: %s\n", (unsigned)rl, okc ? "ok" : "FAILED");
  if (okc) {
    cl.write(req, rl);
    uint32_t t0 = millis();
    while (cl.connected() || cl.available()) {
      server.handleClient();                                  // let the web server answer our own request
      while (cl.available()) {
        char b[256];
        int r = cl.read((uint8_t*)b, sizeof(b));
        if (r <= 0) break;
        if (resp.length() + r > BLE_MAX_RESP) break;
        for (int k = 0; k < r; k++) resp += b[k];
      }
      if (millis() - t0 > 9000) break;
      if (!cl.connected() && !cl.available()) break;
      delay(1);
    }
    cl.stop();
  }
  Serial.printf("BLE answer %u bytes\n", (unsigned)resp.length());
  if (!resp.length()) resp = "HTTP/1.1 504 Gateway Timeout\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
  uint8_t hd[5];
  uint32_t n = resp.length();
  hd[0] = seq; hd[1] = n & 255; hd[2] = (n >> 8) & 255; hd[3] = (n >> 16) & 255; hd[4] = (n >> 24) & 255;
  bleSend(hd, 5);
  bleSend((const uint8_t*)resp.c_str(), n);
}

void bleService() {
  static bool wasConn = false;
  if (bleConn != wasConn) { wasConn = bleConn; Serial.println(bleConn ? "BLE phone connected" : "BLE phone disconnected"); }
  if (!bleReady || !bleConn) return;
  if (bleCount() < 5) return;
  uint8_t h[5];
  for (int i = 0; i < 5; i++) h[i] = bleRing[(bleTail + i) % BLE_RING];
  uint32_t len = (uint32_t)h[1] | ((uint32_t)h[2] << 8) | ((uint32_t)h[3] << 16) | ((uint32_t)h[4] << 24);
  if (len == 0 || len > BLE_MAX_REQ) { bleTail = bleHead; return; }      // garbage: resynchronise
  if (bleCount() < 5 + len) return;                                      // still arriving
  uint8_t* buf = (uint8_t*)malloc(len);
  if (!buf) { bleTail = bleHead; return; }
  for (uint32_t i = 0; i < len; i++) buf[i] = bleRing[(bleTail + 5 + i) % BLE_RING];
  bleTail = (uint16_t)((bleTail + 5 + len) % BLE_RING);
  bleForward(h[0], buf, len);
  free(buf);
}

// GET /api/ble  (admin)  -> {"ok":1,"on":1,"pin":123456,"c":<connected>}
void handleBlePin() {                                         // POST /api/blepin  pin=<6 digits>  (admin)
  long v = server.arg("pin").toInt();
  if (v < 100000 || v > 999999) { jerr(400, "PIN must be 6 digits"); return; }
  prefs.putUInt("blepin2", (uint32_t)v);
  jokx(",\"pin\":" + String(v) + ",\"restart\":1");     // takes effect after the next restart
}

void handleBle() {
  jokx(",\"on\":1,\"pin\":" + String(blePin) + ",\"c\":" + String(bleConn ? 1 : 0) + ",\"name\":" + jstr(String("LoRaLink-") + hex8(myUid).substring(4)));
}
