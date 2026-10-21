// ==========================================================================
//  LoRa Messenger v1  -  ESP32 + RA-02 (SX1278)
// --------------------------------------------------------------------------
//  Phone chat over the ESP32's own WiFi  ->  http://192.168.4.1
//
//  Security  : AES-128-GCM (8-byte tag) on every packet, key from a shared
//              passphrase (set in the web UI), replay protection,
//              long-press button wipe.
//  Messaging : delivery ACK + retry, read receipts, reply-to, edit/delete,
//              quick replies, long messages (fragmentation), compact
//              Persian text encoding, contacts + presence beacons,
//              optional repeater mode (TTL flooding).
//  Location  : send / live-share the phone's GPS, distance + bearing,
//              map links, GPX track export, SOS.
//  Radio     : frequency selection, channel noise scan, packet statistics.
//  Meshtastic: optional interoperability mode - speaks the real Meshtastic LoRa protocol
//              (text, DMs + ACK, node info, positions, rebroadcast) so this node joins an
//              existing Meshtastic mesh. Enable it in Settings > Meshtastic.
//  UI        : minimal dark/light web app, installable (PWA).
//
//  Libraries (Library Manager):  "LoRa" by Sandeep Mistry
//  Everything else is built into the ESP32 Arduino core.
//
//  Wiring
//    RA-02  3.3V->3V3  GND->GND  SCK->18  MISO->19  MOSI->23
//           NSS->5     RST->14   DIO0->26
//    Button: GPIO4 <-> GND
//            short press = PING      hold 30 s = wipe key/settings/chat
//
//  ALL nodes must run this same version and use the same passphrase and
//  frequency.  (Private chats and channels need every node on v1; public text stays compatible with v3-v5.)
// ==========================================================================
#include <SPI.h>
#include <LoRa.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <WebServer.h>
#include <DNSServer.h>
#include <Preferences.h>
#include <mbedtls/gcm.h>
#include <mbedtls/sha256.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/base64.h>
#include <time.h>
#include "assets.h"
#include "mt_core.h"      // Meshtastic wire protocol (pure C++, no Arduino dependencies)
// Forward declarations: the Arduino builder auto-generates function prototypes near the top of the
// file, before these types are defined further down, so they must be known here.
struct GwConn;
struct GwProxy;

// ------------------------------ Pins ---------------------------------------
#define LORA_SS     5
#define LORA_RST    14
#define LORA_DIO0   26
#define LED_PIN     2
#define BTN_PIN     4
#define USE_BUTTON  1
// Bluetooth bridge for the Android app. Set to 1 only after installing the "NimBLE-Arduino" library
// (and choose a partition scheme with a bigger app, e.g. "Huge APP"). 0 = Wi-Fi only, exactly as before.
#define USE_BLE_BRIDGE 0
#ifndef SOS_BTN_PIN
#define SOS_BTN_PIN -1     // optional hardware SOS button (GPIO, to GND, hold 3 s). -1 = disabled
#endif

// ------------------------------ Radio --------------------------------------
#define LORA_SF          10
#define LORA_BW          125E3
#define LORA_CR          5
#define LORA_PREAMBLE    8
#define LORA_TX_POWER    17
#define FREQ_DEFAULT_KHZ 433175UL
#define FREQ_MIN_KHZ     433050UL
#define FREQ_MAX_KHZ     434790UL

// ------------------------------ Limits -------------------------------------
#define HDR_LEN        9       // flags/ttl(1) + uid(4) + counter(4)
#define TAG_LEN        8
#define MAX_RAW        255
#define MAX_WIRE       190
#define FRAG_DATA      100     // compressed bytes per fragment
#define MAX_FRAGS      6
#define MAX_TEXT_BYTES 500
#define MAX_TRIES      4
#define SOS_TRIES      8
#define DEFAULT_TTL    3
#define BEACON_MS      120000UL
#define MAX_CONTACTS   8
#define TRACK_MAX      100
#define MAX_MSGS       60
#define MAX_QUEUE      14
#define MAX_DEFER      10
#define MAX_FWD        4
#define MAX_ASM        3
#define MAX_READQ      12
#define MAX_CH         3       // extra channels with their own passphrase
#define MAX_ACKBY      7

enum { K_TEXT = 0, K_QUICK = 1, K_LOC = 2, K_SOS = 3, K_EDIT = 4, K_DEL = 5, K_MORSE = 6 };
// K_MORSE payload (native): 
//   byte0 = flags (bit0=untilConfirm, bit1-2=out, bit3-7 reserved)
//   byte1 = n (repeats)
//   byte2 = gapSec
//   byte3 = wpm
//   byte4.. = text (null-term, max 40)
// Status / confirm use a compact control text "§MZ:<reqId>:<status>:<done>" so Meshtastic also works.

// ------------------------------ Types --------------------------------------
// (kept above every function so the Arduino auto-prototype step can see them)
struct TrackPt { int32_t lat, lon; uint32_t t; };

struct Contact {
  bool     used;
  uint32_t uid;
  char     name[40];
  uint32_t lastCtr;
  uint32_t lastSeen;     // millis(), 0 = never
  int      rssi;
  int      snr;
  uint32_t rxCount;
  bool     relayOn;
  bool     hasLoc;
  int32_t  lat, lon;
  uint16_t acc;
  uint32_t locAt;
  uint16_t trkCount, trkHead;
  float    snrEma;       // smoothed SNR of received packets (link advisor)
  uint8_t  snrN;
  bool     avSet;        // the node announced a profile avatar (SVG icon + colour, a few bytes)
  uint8_t  avIc, avCol;
  uint8_t  gfState;      // geofence: 0 unknown, 1 inside, 2 outside
  TrackPt  trk[TRACK_MAX];
};

struct Msg {
  uint32_t seq;           // 0 = empty slot
  uint32_t rev;
  char     dir;           // 'I', 'O', 'S'
  uint8_t  kind;
  uint8_t  status;        // outgoing: 0 sending, 1 delivered, 2 failed, 3 read
  uint8_t  acks, reads, ch;
  uint32_t dst;           // 0 = public, else private message to this uid
  uint32_t ackBy[MAX_ACKBY], readBy[MAX_ACKBY];
  uint8_t  partsTotal, partsMask;
  bool     edited, deleted, readSent, hasReply, hasLoc;
  uint32_t uid;
  uint16_t id;
  uint32_t pid;           // Meshtastic packet id (0 = native message)
  uint8_t  op;            // operator profile that sent it (0 = none)
  uint8_t  lf, lt;        // private user chat: sender / recipient (1..8 = web user index+1, 255 = device owner/admin, 0 = none). Only those two may see it
  uint8_t  su;            // public/channel/remote text written by a chat-only web user (index+1): other local users see it as 'received'
  bool     gone;          // deleted locally (tombstone, tells the web UI to drop it)
  uint32_t rUid;
  uint16_t rId;
  int      rssi, snr;
  uint32_t t;
  int32_t  lat, lon;
  uint16_t acc;
  String   text;
};

struct OutItem {
  uint8_t  kind;
  uint16_t id;
  uint8_t  fragIdx, fragTotal, flags;
  uint32_t refUid;
  uint16_t refId;
  uint8_t  dlen;
  uint8_t  data[110];
  uint16_t logId;
  bool     prio;
  uint8_t  ch;
  uint32_t dst;
};

struct Pending { bool active; OutItem it; uint8_t tries, maxTries; uint32_t sentAt, timeoutMs; };

struct PingState { bool active, quiet; uint16_t id; uint32_t start, timeoutMs; uint8_t replies; uint32_t dst; };   // dst: node pinged (0 = everyone) = chat the result belongs to

struct Deferred { bool used; uint32_t due; uint8_t len; uint8_t buf[64]; uint8_t ch; };

struct Fwd { bool used; uint32_t due; int len; uint8_t buf[MAX_RAW]; uint32_t uid, ctr; };

struct RdEntry { uint32_t uid; uint16_t id; };

struct Assembly {
  bool used; uint32_t uid; uint16_t baseId; uint8_t total, mask;
  String part[MAX_FRAGS];
  bool hasReply; uint32_t rUid; uint16_t rId;
  uint32_t started; int rssi, snr;
};

WebServer server(80);
Preferences prefs;
mbedtls_gcm_context gcm;
DNSServer dnsServer;
mbedtls_gcm_context gcmCh[MAX_CH];
bool     chUsed[MAX_CH];
char     chName[MAX_CH][25];
uint8_t  chKey[MAX_CH][16];
uint8_t  txCh = 0, rxCh = 0;       // channel used for the next transmit / of the packet being handled
uint32_t curDst = 0;               // destination of the message being handled
int      preset = 0, txPower = LORA_TX_POWER;
bool     captiveOn = true;
uint32_t cSupp = 0;
const uint8_t PRESET_SF[4] = {10, 12, 7, 7};
const long    PRESET_BW[4] = {125000L, 125000L, 125000L, 250000L};

// ------------------------------ Meshtastic mode ----------------------------
bool     meshMode = false;          // true = speak the Meshtastic protocol instead of LoRa Link
int      mtPreset = 0;              // Meshtastic ModemPreset enum (0 = LongFast)
String   mtChName;                  // primary channel name ("" = preset name, like Meshtastic)
uint8_t  mtKey[32];                 // expanded channel key
int      mtKeyLen = 16;             // 0 = no encryption, 16 = AES-128, 32 = AES-256
uint8_t  mtHash = 8;                // channel hash carried in every packet
uint8_t  mtSlot = 0;                // 0 = auto (hash of channel name), else 1-based frequency slot
uint8_t  mtHop = 3;                 // hop limit for packets we send
uint32_t mtFreqOvrKhz = 0;          // 0 = computed from preset/channel, else manual frequency
long     curBW = 125000L;           // active modem settings (used for airtime maths)
int      curSF = 10, curCR = 5, curPre = 8;
// defined in meshtastic.h (needed earlier in the file)
uint32_t mtCurFreqHz();
bool     mtDutyOk();
void     mtSendNodeInfo(uint32_t to, bool wantResp);
// defined in lm_buzzer.h / lm_features.h
void hwNotify(uint8_t what);
struct Contact;
void featHeard(uint32_t uid, Contact* c, int rssi, int snr);
void featLoc(Contact* c);
void holdFlushFor(uint32_t uid);
void mtUserDirRx(Contact* c, const String& t);   // Meshtastic mode: user directory text from another device          // store-and-forward: deliver what was kept for a node that is back
void featLtNative(Contact* c, const uint8_t* p, int len, int rssi, int snr);
void featLtMesh(Contact* c, const uint8_t* pl, int len, int rssi, int snr);

// ------------------------------ Settings / identity ------------------------
uint32_t myUid = 0;
String   myName, apSsid, apPass;
bool     wifiDefault = true;
uint32_t freqKhz = FREQ_DEFAULT_KHZ;
bool     relayOn = false;
uint8_t  aesKey[16];
bool     keyIsDefault = true;
uint16_t epochNo = 0, seq16 = 0;
uint16_t msgCounter = 1;
bool     timeKnown = false;
uint32_t timeBase = 0;
uint32_t restartAt = 0, wipeAt = 0;
uint32_t ledUntil = 0;
bool     ledWarn = false;
int      unread = 0;

// ------------------------------ Counters -----------------------------------
uint32_t cTx = 0, cRx = 0, cOk = 0, cAuth = 0, cReplay = 0, cDup = 0;
uint32_t cRetry = 0, cFail = 0, cRelay = 0, cForeign = 0;
float    avgRssi = -100;
uint32_t airBucket[60];
uint32_t airLastMin = 0;

// ------------------------------ Small helpers ------------------------------
static inline void putU16(uint8_t* p, uint16_t v) { p[0] = v >> 8; p[1] = v; }
static inline uint16_t getU16(const uint8_t* p) { return ((uint16_t)p[0] << 8) | p[1]; }
static inline void putU32(uint8_t* p, uint32_t v) { p[0] = v >> 24; p[1] = v >> 16; p[2] = v >> 8; p[3] = v; }
static inline uint32_t getU32(const uint8_t* p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

String hex8(uint32_t v) { char b[9]; snprintf(b, sizeof(b), "%08X", (unsigned)v); return String(b); }

String jstr(const String& s) {
  String o;
  o.reserve(s.length() + 8);
  o += '"';
  for (unsigned i = 0; i < s.length(); i++) {
    char c = s[i];
    if (c == '"') o += "\\\"";
    else if (c == '\\') o += "\\\\";
    else if ((uint8_t)c < 0x20) { char b[8]; snprintf(b, sizeof(b), "\\u%04x", (unsigned)(uint8_t)c); o += b; }
    else o += c;
  }
  o += '"';
  return o;
}

String sanitize(String s) {
  s.replace("\r", " ");
  s.replace("\n", " ");
  s.replace("\t", " ");
  s.trim();
  return s;
}

int utf8Len(uint8_t lead) {
  if (lead < 0x80) return 1;
  if ((lead & 0xE0) == 0xC0) return 2;
  if ((lead & 0xF0) == 0xE0) return 3;
  if ((lead & 0xF8) == 0xF0) return 4;
  return 1;
}

uint32_t utf8Decode(const uint8_t* p, int len) {
  if (len == 1) return p[0];
  if (len == 2) return ((uint32_t)(p[0] & 0x1F) << 6) | (p[1] & 0x3F);
  if (len == 3) return ((uint32_t)(p[0] & 0x0F) << 12) | ((uint32_t)(p[1] & 0x3F) << 6) | (p[2] & 0x3F);
  return ((uint32_t)(p[0] & 0x07) << 18) | ((uint32_t)(p[1] & 0x3F) << 12) | ((uint32_t)(p[2] & 0x3F) << 6) | (p[3] & 0x3F);
}

void appendUtf8(String& s, uint32_t cp) {
  if (cp < 0x80) s += (char)cp;
  else if (cp < 0x800) { s += (char)(0xC0 | (cp >> 6)); s += (char)(0x80 | (cp & 0x3F)); }
  else if (cp < 0x10000) { s += (char)(0xE0 | (cp >> 12)); s += (char)(0x80 | ((cp >> 6) & 0x3F)); s += (char)(0x80 | (cp & 0x3F)); }
  else { s += (char)(0xF0 | (cp >> 18)); s += (char)(0x80 | ((cp >> 12) & 0x3F)); s += (char)(0x80 | ((cp >> 6) & 0x3F)); s += (char)(0x80 | (cp & 0x3F)); }
}

// cut to maxBytes without splitting a UTF-8 character
String clipUtf8(String s, int maxBytes) {
  if ((int)s.length() <= maxBytes) return s;
  int n = maxBytes;
  while (n > 0 && (((uint8_t)s[n]) & 0xC0) == 0x80) n--;
  return s.substring(0, n);
}

String xmlEsc(const String& s) {
  String o;
  for (unsigned i = 0; i < s.length(); i++) {
    char c = s[i];
    if (c == '&') o += "&amp;"; else if (c == '<') o += "&lt;"; else if (c == '>') o += "&gt;"; else o += c;
  }
  return o;
}

// ------------------------------ Compact Persian text -----------------------
// ASCII stays 1 byte, the 57 most common Persian/Arabic letters and signs
// become 1 byte (0x80..0xBF), anything else is escaped (0xFE + raw UTF-8).
const uint16_t PCODES[64] PROGMEM = {
  0x0627, 0x0622, 0x0628, 0x067E, 0x062A, 0x062B, 0x062C, 0x0686,
  0x062D, 0x062E, 0x062F, 0x0630, 0x0631, 0x0632, 0x0698, 0x0633,
  0x0634, 0x0635, 0x0636, 0x0637, 0x0638, 0x0639, 0x063A, 0x0641,
  0x0642, 0x06A9, 0x06AF, 0x0644, 0x0645, 0x0646, 0x0648, 0x0647,
  0x06CC, 0x0626, 0x0621, 0x0624, 0x0623, 0x0625, 0x0643, 0x064A,
  0x0629, 0x200C, 0x060C, 0x061F, 0x061B, 0x06F0, 0x06F1, 0x06F2,
  0x06F3, 0x06F4, 0x06F5, 0x06F6, 0x06F7, 0x06F8, 0x06F9, 0x00AB,
  0x00BB, 0x0640, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000
};

int findCode(uint32_t cp) {
  if (!cp) return -1;
  for (int i = 0; i < 64; i++) if (pgm_read_word(&PCODES[i]) == cp) return i;
  return -1;
}

// Split text into self-contained compressed chunks (token boundaries only).
// Returns number of chunks, or -1 if it needs more than maxChunks.
int buildChunks(const String& s, uint8_t chunks[][FRAG_DATA + 8], uint8_t lens[], int maxChunks) {
  int n = 0, cur = 0, i = 0, L = s.length();
  const uint8_t* p = (const uint8_t*)s.c_str();
  while (i < L) {
    int cl = utf8Len(p[i]);
    if (i + cl > L) cl = L - i;
    uint8_t tok[8];
    int tl = 0;
    if (cl == 1) {
      if (p[i] >= 0x20 && p[i] < 0x80) { tok[0] = p[i]; tl = 1; }
    } else {
      uint32_t cp = utf8Decode(p + i, cl);
      int idx = findCode(cp);
      if (idx >= 0) { tok[0] = 0x80 + idx; tl = 1; }
      else { tok[0] = 0xFE; memcpy(tok + 1, p + i, cl); tl = 1 + cl; }
    }
    i += cl;
    if (!tl) continue;
    if (cur + tl > FRAG_DATA) {
      if (n + 1 >= maxChunks) return -1;
      lens[n] = cur;
      n++;
      cur = 0;
    }
    memcpy(chunks[n] + cur, tok, tl);
    cur += tl;
  }
  lens[n] = cur;
  return n + 1;
}

String decodeBytes(const uint8_t* d, int n) {
  String out;
  int i = 0;
  while (i < n) {
    uint8_t b = d[i++];
    if (b < 0x80) out += (char)b;
    else if (b == 0xFE) {
      if (i >= n) break;
      int l = utf8Len(d[i]);
      for (int k = 0; k < l && i < n; k++) out += (char)d[i++];
    } else if (b <= 0xBF) {
      uint16_t cp = pgm_read_word(&PCODES[b - 0x80]);
      if (cp) appendUtf8(out, cp);
    }
  }
  return out;
}

// ------------------------------ Time ---------------------------------------
uint32_t nowEpoch() { return timeKnown ? timeBase + millis() / 1000UL : 0; }

String qualityFa(int rssi) {
  if (rssi > -80) return "Excellent";
  if (rssi > -100) return "Good";
  if (rssi > -115) return "Weak";
  return "Very weak";
}

// ------------------------------ Airtime ------------------------------------
float airtimeMs(int bytes) {
  int sf = curSF;
  float tsym = (float)(1UL << sf) / (float)curBW * 1000.0f;
  int de = (tsym > 16.0f) ? 1 : 0;
  float num = 8.0f * bytes - 4.0f * sf + 28.0f + 16.0f;
  float den = 4.0f * (sf - 2 * de);
  int nPay = 8 + max((int)ceil(num / den) * curCR, 0);
  return ((curPre + 4.25f) + nPay) * tsym;
}

void airRoll() {
  uint32_t m = millis() / 60000UL;
  if (airLastMin > m) airLastMin = m;
  while (airLastMin < m) {
    airLastMin++;
    airBucket[airLastMin % 60] = 0;
    if (m - airLastMin > 120) airLastMin = m;
  }
}
void airAdd(float ms) { airRoll(); airBucket[airLastMin % 60] += (uint32_t)ms; }
uint32_t airHour() { airRoll(); uint32_t s = 0; for (int i = 0; i < 60; i++) s += airBucket[i]; return s; }

// ------------------------------ Crypto -------------------------------------
void deriveKey(const String& pass, uint8_t out[16]) {
  const char* salt = "LoRaLink-v3";
  const int SL = 11;
  String p = pass;
  if (p.length() > 64) p = p.substring(0, 64);
  int pl = p.length();
  uint8_t first[80], buf[112], h[32];
  memcpy(first, salt, SL);
  memcpy(first + SL, p.c_str(), pl);
  mbedtls_sha256(first, SL + pl, h, 0);
  for (int i = 0; i < 4000; i++) {
    memcpy(buf, h, 32);
    memcpy(buf + 32, p.c_str(), pl);
    memcpy(buf + 32 + pl, salt, SL);
    mbedtls_sha256(buf, 32 + pl + SL, h, 0);
  }
  memcpy(out, h, 16);
}

void applyKey(const uint8_t k[16]) {
  memcpy(aesKey, k, 16);
  mbedtls_gcm_free(&gcm);
  mbedtls_gcm_init(&gcm);
  mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, aesKey, 128);
}

String keyFp() {
  uint8_t h[32];
  mbedtls_sha256(aesKey, 16, h, 0);
  char b[8];
  snprintf(b, sizeof(b), "%02X%02X", h[0], h[1]);
  return String(b);
}

mbedtls_gcm_context* ctxFor(uint8_t k) {
  if (k == 0) return &gcm;
  if (k <= MAX_CH && chUsed[k - 1]) return &gcmCh[k - 1];
  return nullptr;
}

String chanFp(int i) {
  uint8_t h[32];
  mbedtls_sha256(chKey[i], 16, h, 0);
  char b[8];
  snprintf(b, sizeof(b), "%02X%02X", h[0], h[1]);
  return String(b);
}

void setChannel(int i, const String& name, const uint8_t k[16]) {
  memcpy(chKey[i], k, 16);
  strncpy(chName[i], name.c_str(), sizeof(chName[i]) - 1);
  chName[i][sizeof(chName[i]) - 1] = 0;
  mbedtls_gcm_free(&gcmCh[i]);
  mbedtls_gcm_init(&gcmCh[i]);
  mbedtls_gcm_setkey(&gcmCh[i], MBEDTLS_CIPHER_ID_AES, chKey[i], 128);
  chUsed[i] = true;
}

void loadChannels() {
  for (int i = 0; i < MAX_CH; i++) {
    chUsed[i] = false;
    mbedtls_gcm_init(&gcmCh[i]);
    String kn = "chk" + String(i), nn = "chn" + String(i);
    uint8_t k[16];
    if (prefs.isKey(kn.c_str()) && prefs.getBytes(kn.c_str(), k, 16) == 16)
      setChannel(i, prefs.getString(nn.c_str(), "Channel"), k);
  }
}

long curFreqHz() { return meshMode ? (long)mtCurFreqHz() : (long)freqKhz * 1000L; }

// (Re)configures the whole radio for the active mode.
void applyRadio() {
  if (meshMode) {
    const MtPresetDef& d = MT_PRESETS[mtPreset];
    curSF = d.sf; curBW = (long)d.bwHz; curCR = d.cr; curPre = MT_PREAMBLE;
    LoRa.setSyncWord(MT_SYNC_WORD);
  } else {
    curSF = PRESET_SF[preset]; curBW = PRESET_BW[preset]; curCR = LORA_CR; curPre = LORA_PREAMBLE;
    LoRa.setSyncWord(0x12);
  }
  LoRa.setFrequency(curFreqHz());
  LoRa.setSpreadingFactor(curSF);
  LoRa.setSignalBandwidth(curBW);
  LoRa.setCodingRate4(curCR);
  LoRa.setPreambleLength(curPre);
  LoRa.enableCrc();
  int pw = txPower;
  if (meshMode && pw > MT_MAX_TX_DBM) pw = MT_MAX_TX_DBM;     // EU_433 limit used by Meshtastic
  LoRa.setTxPower(pw, PA_OUTPUT_PA_BOOST_PIN);
}

uint32_t nextCtr() {
  if (seq16 == 0xFFFF) { epochNo++; prefs.putUShort("epoch", epochNo); seq16 = 0; }
  seq16++;
  return ((uint32_t)epochNo << 16) | seq16;
}

void txRaw(const uint8_t* buf, int len) {
  LoRa.beginPacket();
  LoRa.write(buf, len);
  LoRa.endPacket();
  cTx++;
  airAdd(airtimeMs(len));
  ledUntil = millis() + 40;
}

bool sendSecure(const uint8_t* plain, int plen, uint8_t ttl) {
  if (meshMode) return false;                       // native packets are never sent in Meshtastic mode
  if (plen + HDR_LEN + TAG_LEN > MAX_WIRE) return false;
  uint8_t wire[MAX_RAW];
  uint32_t ctr = nextCtr();
  wire[0] = 0xA0 | (ttl & 0x0F);
  putU32(wire + 1, myUid);
  putU32(wire + 5, ctr);
  uint8_t iv[12];
  memset(iv, 0, sizeof(iv));
  putU32(iv, myUid);
  putU32(iv + 4, ctr);
  uint8_t tag[TAG_LEN];
  mbedtls_gcm_context* g = ctxFor(txCh);
  if (!g) g = &gcm;
  int rc = mbedtls_gcm_crypt_and_tag(g, MBEDTLS_GCM_ENCRYPT, plen, iv, 12, wire + 1, 8,
                                     plain, wire + HDR_LEN, TAG_LEN, tag);
  if (rc != 0) return false;
  memcpy(wire + HDR_LEN + plen, tag, TAG_LEN);
  txRaw(wire, HDR_LEN + plen + TAG_LEN);
  return true;
}

// ------------------------------ Contacts -----------------------------------
Contact contacts[MAX_CONTACTS];     // [0] = this device
uint32_t nextBeaconAt = 0, lastBeaconAt = 0;
bool     helloPending = true;       // first beacon after boot / mode switch asks neighbours to answer
uint32_t udNextAt = 30000;          // when this device announces its web users to the other nodes next
bool     usersDirty = false;        // users changed: announce them soon
bool     myAvSet = false;           // this device's profile avatar (icon 0..19, colour 0..15)
uint8_t  myAvIc = 0, myAvCol = 0;
uint32_t lastRxAt = 0, lastOkAt = 0;   // diagnostics for the connection check

Contact* findContact(uint32_t uid) {
  for (int i = 0; i < MAX_CONTACTS; i++) if (contacts[i].used && contacts[i].uid == uid) return &contacts[i];
  return nullptr;
}

void initContact(Contact* c, uint32_t uid) {
  c->used = true;
  c->uid = uid;
  snprintf(c->name, sizeof(c->name), "Node-%04X", (unsigned)(uid & 0xFFFF));
  c->lastCtr = 0; c->lastSeen = 0; c->rssi = -120; c->snr = 0; c->rxCount = 0;
  c->relayOn = false; c->hasLoc = false; c->lat = 0; c->lon = 0; c->acc = 0; c->locAt = 0;
  c->trkCount = 0; c->trkHead = 0;
  c->avSet = false; c->avIc = 0; c->avCol = 0;
  c->snrEma = 0; c->snrN = 0; c->gfState = 0;
}

Contact* addContact(uint32_t uid) {
  int slot = -1;
  for (int i = 1; i < MAX_CONTACTS; i++) if (!contacts[i].used) { slot = i; break; }
  if (slot < 0) {
    slot = 1;
    for (int i = 2; i < MAX_CONTACTS; i++) if (contacts[i].lastSeen < contacts[slot].lastSeen) slot = i;
  }
  initContact(&contacts[slot], uid);
  if (!meshMode && millis() - lastBeaconAt > 20000UL) nextBeaconAt = millis() + random(1500, 4000);   // introduce ourselves
  return &contacts[slot];
}

void setMyName(const String& n) {
  myName = n;
  strncpy(contacts[0].name, n.c_str(), sizeof(contacts[0].name) - 1);
  contacts[0].name[sizeof(contacts[0].name) - 1] = 0;
  prefs.putString("name", n);
  if (!meshMode) nextBeaconAt = millis() + 1500;     // tell the others about the new name right away
}

void addTrackPoint(Contact* c, int32_t lat, int32_t lon) {
  if (c->trkCount) {
    int last = (c->trkHead + TRACK_MAX - 1) % TRACK_MAX;
    if (c->trk[last].lat == lat && c->trk[last].lon == lon) return;
  }
  TrackPt& p = c->trk[c->trkHead];
  p.lat = lat; p.lon = lon; p.t = nowEpoch();
  c->trkHead = (c->trkHead + 1) % TRACK_MAX;
  if (c->trkCount < TRACK_MAX) c->trkCount++;
}

void setContactLoc(Contact* c, int32_t lat, int32_t lon, uint16_t acc) {
  c->hasLoc = true; c->lat = lat; c->lon = lon; c->acc = acc; c->locAt = millis();
  addTrackPoint(c, lat, lon);
  featLoc(c);
}

// ------------------------------ Message log --------------------------------
Msg      msgLog[MAX_MSGS];
int      logHead = 0;
uint32_t nextSeq = 1, revCounter = 1, clearCount = 0;

Msg* addMsg(char dir, uint8_t kind, uint32_t uid, uint16_t id) {
  Msg* m = &msgLog[logHead];
  logHead = (logHead + 1) % MAX_MSGS;
  *m = Msg();
  m->seq = nextSeq++;
  m->rev = ++revCounter;
  m->dir = dir; m->kind = kind; m->uid = uid; m->id = id;
  m->t = nowEpoch();
  return m;
}
void touch(Msg* m) { m->rev = ++revCounter; }

Msg* findMsg(uint32_t uid, uint16_t id, char dir) {
  for (int i = 0; i < MAX_MSGS; i++)
    if (msgLog[i].seq && msgLog[i].dir == dir && msgLog[i].uid == uid && msgLog[i].id == id) return &msgLog[i];
  return nullptr;
}

void sysLineTo(const String& text, uint32_t dst) {   // dst != 0: the line belongs to the private chat with that node
  Msg* m = addMsg('S', 0, myUid, 0);
  m->text = text;
  m->dst = dst;
}
void sysLine(const String& text) { sysLineTo(text, 0); }

uint16_t newIds(int n) {
  if (msgCounter == 0) msgCounter = 1;
  uint16_t base = msgCounter;
  msgCounter += n;
  return base;
}

// ------------------------------ Outgoing engine ----------------------------
OutItem outQ[MAX_QUEUE];
int     qCount = 0;

Pending pend;

PingState pingPend;
#define SILENT_DST 0xFFFFFFFEUL                     // system lines nobody should see in a chat (range test pings)
static inline uint32_t pingScope() { return pingPend.quiet ? SILENT_DST : pingPend.dst; }

Deferred defQ[MAX_DEFER];

Fwd fwdQ[MAX_FWD];

RdEntry rdQ[MAX_READQ];
int      rdCount = 0;
uint32_t lastReadAt = 0;

bool enqueue(const OutItem& it) {
  if (qCount >= MAX_QUEUE) return false;
  if (it.prio) {
    for (int i = qCount; i > 0; i--) outQ[i] = outQ[i - 1];
    outQ[0] = it;
  } else {
    outQ[qCount] = it;
  }
  qCount++;
  return true;
}

bool deferSend(uint32_t delayMs, const uint8_t* plain, uint8_t len, uint8_t ch) {
  if (len > sizeof(defQ[0].buf)) return false;
  for (int i = 0; i < MAX_DEFER; i++) {
    if (!defQ[i].used) {
      defQ[i].used = true;
      defQ[i].due = millis() + delayMs;
      defQ[i].len = len;
      defQ[i].ch = ch;
      memcpy(defQ[i].buf, plain, len);
      return true;
    }
  }
  return false;
}

uint32_t ackTimeoutMs() {
  uint32_t t = (uint32_t)airtimeMs(HDR_LEN + 7 + TAG_LEN) + 600 + 350 + 500;
  for (int i = 1; i < MAX_CONTACTS; i++) if (contacts[i].used && contacts[i].relayOn) { t += 1500; break; }
  return t + random(0, 250);
}

void transmitPending() {
  OutItem& it = pend.it;
  uint8_t b[200];
  int n = 0;
  b[n++] = 'M';
  b[n++] = it.kind;
  putU16(b + n, it.id); n += 2;
  b[n++] = it.fragIdx;
  b[n++] = it.fragTotal;
  b[n++] = it.flags;
  if (it.flags & 1) { putU32(b + n, it.refUid); n += 4; putU16(b + n, it.refId); n += 2; }
  if (it.flags & 2) { putU32(b + n, it.dst); n += 4; }
  memcpy(b + n, it.data, it.dlen);
  n += it.dlen;
  txCh = it.ch;
  sendSecure(b, n, DEFAULT_TTL);
  txCh = 0;
  if (pend.tries > 0) cRetry++;
  pend.tries++;
  pend.sentAt = millis();
  pend.timeoutMs = ackTimeoutMs();
}

void failPending() {
  cFail++;
  uint16_t logId = pend.it.logId;
  pend.active = false;
  if (logId) {
    Msg* m = findMsg(myUid, logId, 'O');
    if (m && m->dir == 'O') { m->status = 2; touch(m); }
    int w = 0;
    for (int i = 0; i < qCount; i++) if (outQ[i].logId != logId) outQ[w++] = outQ[i];
    qCount = w;
  }
}

void onAck(uint16_t id, uint32_t from) {
  for (int i = 0; i < MAX_MSGS; i++) {
    Msg& m = msgLog[i];
    if (!m.seq || m.dir != 'O') continue;
    uint16_t d = (uint16_t)(id - m.id);
    uint8_t total = m.partsTotal ? m.partsTotal : 1;
    if (d >= total) continue;
    if (d == total - 1) {
      bool known = false;
      for (int k = 0; k < MAX_ACKBY; k++) if (m.ackBy[k] == from) known = true;
      if (!known) {
        for (int k = 0; k < MAX_ACKBY; k++) if (!m.ackBy[k]) { m.ackBy[k] = from; break; }
        if (m.acks < 250) m.acks++;
      }
    }
    m.partsMask |= (uint8_t)(1u << d);
    uint8_t full = (uint8_t)((1u << total) - 1);
    if ((m.partsMask & full) == full && m.status != 3) m.status = 1;
    touch(&m);
    break;
  }
  if (pend.active && pend.it.id == id) pend.active = false;
}

void serviceOutgoing() {
  if (!pend.active) {
    if (qCount > 0) {
      pend.it = outQ[0];
      for (int i = 1; i < qCount; i++) outQ[i - 1] = outQ[i];
      qCount--;
      pend.active = true;
      pend.tries = 0;
      pend.maxTries = (pend.it.kind == K_SOS) ? SOS_TRIES : MAX_TRIES;
      transmitPending();
    }
    return;
  }
  if (millis() - pend.sentAt >= pend.timeoutMs) {
    if (pend.tries < pend.maxTries) transmitPending();
    else failPending();
  }
}

void serviceDeferred() {
  for (int i = 0; i < MAX_DEFER; i++) {
    if (defQ[i].used && (int32_t)(millis() - defQ[i].due) >= 0) {
      defQ[i].used = false;
      txCh = defQ[i].ch;
      sendSecure(defQ[i].buf, defQ[i].len, DEFAULT_TTL);
      txCh = 0;
      return;                       // one transmission per loop pass
    }
  }
}

void serviceForward() {
  for (int i = 0; i < MAX_FWD; i++) {
    if (fwdQ[i].used && (int32_t)(millis() - fwdQ[i].due) >= 0) {
      fwdQ[i].used = false;
      if (meshMode && !mtDutyOk()) return;          // out of airtime budget: skip the rebroadcast
      txRaw(fwdQ[i].buf, fwdQ[i].len);
      cRelay++;
      return;
    }
  }
}

void scheduleForward(const uint8_t* w, int n, uint8_t newTtl) {
  for (int i = 0; i < MAX_FWD; i++) {
    if (!fwdQ[i].used) {
      fwdQ[i].used = true;
      fwdQ[i].uid = getU32(w + 1);
      fwdQ[i].ctr = getU32(w + 5);
      fwdQ[i].due = millis() + random(250, 800);
      fwdQ[i].len = n;
      memcpy(fwdQ[i].buf, w, n);
      fwdQ[i].buf[0] = 0xA0 | (newTtl & 0x0F);
      return;
    }
  }
}

void cancelForward(uint32_t uid, uint32_t ctr) {
  for (int i = 0; i < MAX_FWD; i++)
    if (fwdQ[i].used && fwdQ[i].uid == uid && fwdQ[i].ctr == ctr) { fwdQ[i].used = false; cSupp++; }
}

void markVisible() {
  unread = 0;
  for (int i = 0; i < MAX_MSGS; i++) {
    Msg& m = msgLog[i];
    if (!m.seq || m.gone || m.dir != 'I' || m.readSent || m.deleted || m.kind > K_SOS || m.ch) continue;
    m.readSent = true;
    if (!meshMode && rdCount < MAX_READQ) { rdQ[rdCount].uid = m.uid; rdQ[rdCount].id = m.id; rdCount++; }
  }
}

void serviceReads() {
  if (!rdCount || millis() - lastReadAt < 3000) return;
  uint8_t b[2 + 5 * 6];
  int n = (rdCount > 5) ? 5 : rdCount;
  b[0] = 'D';
  b[1] = n;
  for (int i = 0; i < n; i++) { putU32(b + 2 + i * 6, rdQ[i].uid); putU16(b + 6 + i * 6, rdQ[i].id); }
  for (int i = n; i < rdCount; i++) rdQ[i - n] = rdQ[i];
  rdCount -= n;
  deferSend(random(300, 900), b, 2 + n * 6, 0);
  lastReadAt = millis();
}

// ------------------------------ Ping ---------------------------------------
void startPingTo(uint32_t to, bool quiet) {                    // to != 0: ping that node only, result stays in its private chat
  if (pingPend.active) return;
  pingPend.dst = to;
  pingPend.quiet = quiet;
  uint32_t sc = quiet ? SILENT_DST : to;               // chat that shows this ping's lines
  Contact* tc = to ? findContact(to) : nullptr;
  String who = to ? (tc ? String(tc->name) : String("that node")) : String("everyone");
  if (meshMode) {                                   // Meshtastic: ask node(s) to announce themselves
    pingPend.id = 0;
    pingPend.active = true;
    pingPend.start = millis();
    pingPend.replies = 0;
    pingPend.timeoutMs = 20000;
    mtSendNodeInfo(to ? to : MT_BROADCAST, true);
    sysLineTo(to ? "Ping sent to " + who + "..." : String("Ping sent: asking Meshtastic nodes in range to announce themselves..."), sc);
    return;
  }
  pingPend.id = newIds(1);
  pingPend.active = true;
  pingPend.start = millis();
  pingPend.replies = 0;
  pingPend.timeoutMs = (uint32_t)(airtimeMs(HDR_LEN + 3 + TAG_LEN) + airtimeMs(HDR_LEN + 10 + TAG_LEN) + 2500);
  uint8_t b[7];
  b[0] = 'P';
  putU16(b + 1, pingPend.id);
  int bl = 3;
  if (to) { putU32(b + 3, to); bl = 7; }            // optional target: other nodes do not answer
  sendSecure(b, bl, DEFAULT_TTL);
  sysLineTo(to ? "Ping sent to " + who + ", waiting for the reply..." : String("Ping sent, waiting for replies..."), sc);
}
void startPing() { startPingTo(0, false); }

void servicePing() {
  if (pingPend.active && millis() - pingPend.start > pingPend.timeoutMs) {
    pingPend.active = false;
    if (pingPend.replies == 0) sysLineTo("Ping got no reply (peer out of range, powered off, or on a different frequency/key)", pingScope());
  }
}

// ------------------------------ Beacon -------------------------------------
void sendBeacon() {
  if (meshMode) {                                   // Meshtastic: periodic NodeInfo announcement
    mtSendNodeInfo(MT_BROADCAST, helloPending);       // want_response on the first one: others answer right away
    helloPending = false;
    lastBeaconAt = millis();
    nextBeaconAt = millis() + 1800000UL + random(0, 60000);
    return;
  }
  uint8_t chunks[1][FRAG_DATA + 8];
  uint8_t lens[1];
  String nm = clipUtf8(myName, 20);
  if (buildChunks(nm, chunks, lens, 1) != 1) { nm = "Node"; buildChunks(nm, chunks, lens, 1); }
  uint8_t b[56];
  int n = 0;
  b[n++] = 'B';
  b[n++] = (relayOn ? 1 : 0) | (helloPending ? 2 : 0);   // bit1 = "hello, please announce yourself"
  b[n++] = lens[0];
  memcpy(b + n, chunks[0], lens[0]);
  n += lens[0];
  b[n++] = myAvSet ? (uint8_t)(0x80 | (myAvIc & 31)) : 0;     // avatar (older nodes simply ignore these two bytes)
  b[n++] = myAvCol & 15;
  for (uint8_t k = 0; k <= MAX_CH; k++) {
    if (!ctxFor(k)) continue;
    txCh = k;
    sendSecure(b, n, DEFAULT_TTL);
  }
  txCh = 0;
  helloPending = false;
  lastBeaconAt = millis();
  nextBeaconAt = millis() + BEACON_MS + random(0, 15000);
}

// ------------------------------ Incoming messages --------------------------
uint64_t seenKeys[48];
int      seenHead = 0;
bool seenBefore(uint32_t uid, uint16_t id) {
  uint64_t k = ((uint64_t)uid << 16) | id;
  for (int i = 0; i < 48; i++) if (seenKeys[i] == k) return true;
  seenKeys[seenHead] = k;
  seenHead = (seenHead + 1) % 48;
  return false;
}

Assembly asmb[MAX_ASM];

Assembly* getAsm(uint32_t uid, uint16_t base, uint8_t total) {
  for (int i = 0; i < MAX_ASM; i++) if (asmb[i].used && asmb[i].uid == uid && asmb[i].baseId == base) return &asmb[i];
  int slot = -1;
  for (int i = 0; i < MAX_ASM; i++) if (!asmb[i].used) { slot = i; break; }
  if (slot < 0) {
    slot = 0;
    for (int i = 1; i < MAX_ASM; i++) if (asmb[i].started < asmb[slot].started) slot = i;
  }
  Assembly& a = asmb[slot];
  a.used = true; a.uid = uid; a.baseId = base; a.total = total; a.mask = 0;
  for (int k = 0; k < MAX_FRAGS; k++) a.part[k] = "";
  a.hasReply = false; a.rUid = 0; a.rId = 0; a.started = millis();
  return &a;
}

void serviceAssemblies() {
  for (int i = 0; i < MAX_ASM; i++)
    if (asmb[i].used && millis() - asmb[i].started > 120000UL) asmb[i].used = false;
}

static bool quietIncoming = false;                  // control texts (status, read receipts, group delete): no beep, no unread count
static bool isCtlText(const String& t) {
  static const char* mk[4] = {"!ST!", "!RD!", "!GD!", "!UD!"};
  for (int k = 0; k < 4; k++) {
    int i = t.indexOf(mk[k]);
    if (i < 0 || i > 400) continue;
    if (i == 0 || (i >= 2 && t.substring(i - 2, i) == "] ") || (i >= 3 && t.substring(i - 3, i) == "~} ")) return true;
  }
  return false;
}
Msg* newIncoming(Contact* c, uint8_t kind, uint16_t id, int rssi, int snr) {
  Msg* m = addMsg('I', kind, c->uid, id);
  m->rssi = rssi;
  m->snr = snr;
  m->dst = curDst;
  m->ch = rxCh;
  if (!quietIncoming) {
    unread++;
    hwNotify(kind == K_SOS ? 2 : 0);                // buzzer + LED
  }
  return m;
}

void queueAck(uint32_t uid, uint16_t id, uint8_t ch) {
  uint8_t b[7];
  b[0] = 'A';
  putU32(b + 1, uid);
  putU16(b + 5, id);
  deferSend(random(250, 600), b, 7, ch);
}

void routeIncomingToUser(Msg* m);
void handleMorseWire(Contact* c, uint16_t id, const uint8_t* data, int dlen, int rssi, int snr);
bool handleMorseControlText(Contact* c, const String& t, uint16_t id, int rssi, int snr);

void handleM(Contact* c, const uint8_t* p, int len, int rssi, int snr) {
  if (len < 6) return;
  uint8_t kind = p[0];
  uint16_t id = getU16(p + 1);
  uint8_t fi = p[3], ft = p[4], flags = p[5];
  int off = 6;
  uint32_t rUid = 0;
  uint16_t rId = 0;
  bool hasReply = (flags & 1) != 0;
  if (hasReply) {
    if (len < off + 6) return;
    rUid = getU32(p + off);
    rId = getU16(p + off + 4);
    off += 6;
  }
  uint32_t dst = 0;
  if (flags & 2) {
    if (len < off + 4) return;
    dst = getU32(p + off);
    off += 4;
  }
  if (dst && dst != myUid) return;            // private message for another node: ignore, do not ack
  curDst = dst;
  const uint8_t* data = p + off;
  int dlen = len - off;

  queueAck(c->uid, id, rxCh);                       // always acknowledge (retries too)
  if (seenBefore(c->uid, id)) { cDup++; return; }

  if (kind == K_TEXT) {
    String part = decodeBytes(data, dlen);
    if (ft <= 1) {
      // intercept remote-Morse control messages (Meshtastic + status reports)
      if (handleMorseControlText(c, part, id, rssi, snr)) return;
      quietIncoming = isCtlText(part);
      Msg* m = newIncoming(c, K_TEXT, id, rssi, snr);
      quietIncoming = false;
      m->text = part;
      routeIncomingToUser(m);
      if (hasReply) { m->hasReply = true; m->rUid = rUid; m->rId = rId; }
      ledUntil = millis() + 120;
      return;
    }
    if (ft > MAX_FRAGS || fi >= ft) return;
    uint16_t base = (uint16_t)(id - fi);
    Assembly* a = getAsm(c->uid, base, ft);
    a->part[fi] = part;
    a->mask |= (uint8_t)(1u << fi);
    a->rssi = rssi; a->snr = snr;
    if (hasReply) { a->hasReply = true; a->rUid = rUid; a->rId = rId; }
    uint8_t full = (uint8_t)((1u << a->total) - 1);
    if ((a->mask & full) == full) {
      String all;
      for (int k = 0; k < a->total; k++) all += a->part[k];
      quietIncoming = isCtlText(all);
      Msg* m = newIncoming(c, K_TEXT, base, a->rssi, a->snr);
      quietIncoming = false;
      m->text = all;
      routeIncomingToUser(m);
      if (a->hasReply) { m->hasReply = true; m->rUid = a->rUid; m->rId = a->rId; }
      a->used = false;
      ledUntil = millis() + 120;
    }
  } else if (kind == K_QUICK) {
    if (dlen < 1) return;
    Msg* m = newIncoming(c, K_QUICK, id, rssi, snr);
    m->text = String((int)data[0]);
    if (hasReply) { m->hasReply = true; m->rUid = rUid; m->rId = rId; }
    ledUntil = millis() + 120;
  } else if (kind == K_LOC) {
    if (dlen < 10) return;
    int32_t la = (int32_t)getU32(data), lo = (int32_t)getU32(data + 4);
    uint16_t ac = getU16(data + 8);
    Msg* m = newIncoming(c, K_LOC, id, rssi, snr);
    m->hasLoc = true; m->lat = la; m->lon = lo; m->acc = ac;
    setContactLoc(c, la, lo, ac);
    ledUntil = millis() + 120;
  } else if (kind == K_SOS) {
    if (dlen < 11) return;
    Msg* m = newIncoming(c, K_SOS, id, rssi, snr);
    if (data[0] & 1) {
      int32_t la = (int32_t)getU32(data + 1), lo = (int32_t)getU32(data + 5);
      uint16_t ac = getU16(data + 9);
      m->hasLoc = true; m->lat = la; m->lon = lo; m->acc = ac;
      setContactLoc(c, la, lo, ac);
    }
  } else if (kind == K_EDIT) {
    if (dlen < 2) return;
    Msg* m = findMsg(c->uid, getU16(data), 'I');
    if (m && m->dir == 'I' && m->kind == K_TEXT && !m->deleted) {
      m->text = decodeBytes(data + 2, dlen - 2);
      m->edited = true;
      touch(m);
    }
  } else if (kind == K_DEL) {
    if (dlen < 2) return;
    Msg* m = findMsg(c->uid, getU16(data), 'I');
    if (m && m->dir == 'I') { m->deleted = true; m->text = ""; touch(m); }
  } else if (kind == K_MORSE) {
    handleMorseWire(c, id, data, dlen, rssi, snr);
  }
}

void handleAck(Contact* c, const uint8_t* p, int len) {
  if (len < 6) return;
  if (getU32(p) != myUid) return;
  onAck(getU16(p + 4), c->uid);
}

void handleRead(Contact* c, const uint8_t* p, int len) {
  if (len < 1) return;
  int n = p[0];
  for (int i = 0; i < n && 1 + (i + 1) * 6 <= len; i++) {
    uint32_t uid = getU32(p + 1 + i * 6);
    uint16_t id = getU16(p + 5 + i * 6);
    if (uid != myUid) continue;
    Msg* m = findMsg(myUid, id, 'O');
    if (m && m->dir == 'O') {
      bool known = false;
      for (int k = 0; k < MAX_ACKBY; k++) if (m->readBy[k] == c->uid) known = true;
      if (!known) {
        for (int k = 0; k < MAX_ACKBY; k++) if (!m->readBy[k]) { m->readBy[k] = c->uid; break; }
        if (m->reads < 250) m->reads++;
      }
      m->status = 3;
      touch(m);
    }
  }
}

void handlePing(Contact* c, const uint8_t* p, int len, int rssi, int snr) {
  if (len < 2) return;
  if (len >= 6 && getU32(p + 2) != 0 && getU32(p + 2) != myUid) return;   // aimed at another node
  uint8_t b[10];
  b[0] = 'R';
  putU32(b + 1, c->uid);
  b[5] = p[0]; b[6] = p[1];
  putU16(b + 7, (uint16_t)(int16_t)rssi);
  b[9] = (uint8_t)(int8_t)snr;
  deferSend(random(250, 650), b, 10, 0);
  sysLineTo("Ping from " + String(c->name) + " received (" + String(rssi) + " dBm, " + qualityFa(rssi) + ")", c->uid);
}

void handlePong(Contact* c, const uint8_t* p, int len, int rssi, int snr) {
  if (len < 9) return;
  if (getU32(p) != myUid) return;
  uint16_t id = getU16(p + 4);
  if (!(pingPend.active && id == pingPend.id)) return;
  if (pingPend.dst && c->uid != pingPend.dst) return;
  pingPend.replies++;
  int remRssi = (int16_t)getU16(p + 6);
  int remSnr = (int8_t)p[8];
  sysLineTo("Reply from " + String(c->name) + " | out: " + String(remRssi) + " dBm, SNR " + String(remSnr) +
          " (" + qualityFa(remRssi) + ") | back: " + String(rssi) + " dBm, SNR " + String(snr) +
          " (" + qualityFa(rssi) + ")", pingScope());
}

void handleLive(Contact* c, const uint8_t* p, int len) {
  if (len < 10) return;
  setContactLoc(c, (int32_t)getU32(p), (int32_t)getU32(p + 4), getU16(p + 8));
}

void handleBeacon(Contact* c, const uint8_t* p, int len) {
  if (len < 2) return;
  c->relayOn = (p[0] & 1) != 0;
  if ((p[0] & 2) && millis() - lastBeaconAt > 8000UL) {          // a node just (re)started: answer so it learns about us quickly
    uint32_t t = millis() + random(800, 6000);
    if ((int32_t)(nextBeaconAt - t) > 0) nextBeaconAt = t;
    udNextAt = millis() + random(15000, 30000);                  // and tell it who our users are (a little later, chat first)
  }
  int nl = p[1];
  if (nl > len - 2) nl = len - 2;
  String nm = clipUtf8(decodeBytes(p + 2, nl), 39);
  if (nm.length()) { strncpy(c->name, nm.c_str(), sizeof(c->name) - 1); c->name[sizeof(c->name) - 1] = 0; }
  int ex = 2 + p[1];
  if (len >= ex + 2 && (p[ex] & 0x80)) { c->avSet = true; c->avIc = p[ex] & 31; c->avCol = p[ex + 1] & 15; }
}

// ------------------------------ Meshtastic ---------------------------------
// forward decl – used by meshtastic.h text path
bool handleMorseControlText(Contact* c, const String& t, uint16_t id, int rssi, int snr);
#include "meshtastic.h"
#include "lm_buzzer.h"
#include "lm_morse.h"
#include "lm_features.h"

void handleMorseWire(Contact* c, uint16_t id, const uint8_t* data, int dlen, int rssi, int snr) {
  // remote Morse request (native LoRa Link)
  if (dlen < 5) return;
  uint8_t flags = data[0];
  uint8_t nRep  = data[1];
  uint8_t gapS  = data[2];
  uint8_t wpm   = data[3];
  bool untilC   = (flags & 1) != 0;
  uint8_t out   = ((flags >> 1) & 3); if (out == 0) out = 3;
  char txt[48];
  int tl = dlen - 4; if (tl > 47) tl = 47;
  memcpy(txt, data + 4, tl); txt[tl] = 0;

  // accept policy
  if (rm.acceptFrom == 0) return;                          // disabled
  if (rm.acceptFrom == 1) {
    // only known contacts – Contact* c is already a known contact
  }
  String err;
  if (!remoteMorseStart(c->uid, id, txt, out, nRep, gapS, wpm, untilC, err)) {
    // rejected – still show a system line so the owner knows
    sysLineTo("Remote Morse rejected: " + err, c->uid);
    return;
  }
  // log the request as an incoming message so it appears in chat
  Msg* m = newIncoming(c, K_TEXT, id, rssi, snr);
  m->text = String("[Morse] ") + txt +
            (untilC ? " (until confirm)" : (" ×" + String(nRep)));
  ledUntil = millis() + 200;
  // immediate "delivered" status will be sent by remoteMorseReport
}

// ------------------------------ Radio receive ------------------------------
void handleWire(uint8_t* w, int n, int rssi, float snrF) {
  cRx++;
  lastRxAt = millis();
  if (n < HDR_LEN + 1 + TAG_LEN || (w[0] & 0xF0) != 0xA0) { cForeign++; return; }
  uint8_t ttl = w[0] & 0x0F;
  uint32_t uid = getU32(w + 1), ctr = getU32(w + 5);
  if (uid == myUid) return;                         // our own packet echoed by a repeater
  int clen = n - HDR_LEN - TAG_LEN;
  uint8_t plain[MAX_RAW];
  uint8_t iv[12];
  memset(iv, 0, sizeof(iv));
  putU32(iv, uid);
  putU32(iv + 4, ctr);
  int rc = -1;
  rxCh = 0;
  for (uint8_t k = 0; k <= MAX_CH && rc != 0; k++) {
    mbedtls_gcm_context* g = ctxFor(k);
    if (!g) continue;
    rc = mbedtls_gcm_auth_decrypt(g, clen, iv, 12, w + 1, 8, w + HDR_LEN + clen, TAG_LEN,
                                  w + HDR_LEN, plain);
    if (rc == 0) rxCh = k;
  }
  if (rc != 0) { cAuth++; return; }                 // wrong key or tampered

  Contact* c = findContact(uid);
  if (!c) c = addContact(uid);
  if (ctr <= c->lastCtr) {                          // replayed / duplicate copy
    cReplay++;
    if (rssi > -100) cancelForward(uid, ctr);       // a neighbour already repeated it loudly: skip ours
    return;
  }     // replayed / duplicate copy
  c->lastCtr = ctr;
  cOk++;
  int snr = (int)lroundf(snrF);
  c->lastSeen = millis() ? millis() : 1;
  c->rssi = rssi;
  c->snr = snr;
  c->rxCount++;
  avgRssi = (avgRssi * 7.0f + rssi) / 8.0f;
  featHeard(uid, c, rssi, snr);
  lastOkAt = millis();

  const uint8_t* p = plain + 1;
  int plen = clen - 1;
  switch (plain[0]) {
    case 'M': handleM(c, p, plen, rssi, snr); break;
    case 'A': handleAck(c, p, plen); break;
    case 'D': handleRead(c, p, plen); break;
    case 'P': handlePing(c, p, plen, rssi, snr); break;
    case 'R': handlePong(c, p, plen, rssi, snr); break;
    case 'L': handleLive(c, p, plen); break;
    case 'B': handleBeacon(c, p, plen); break;
    case 'U': handleUserDir(c, p, plen); break;
    case 'T': featLtNative(c, p, plen, rssi, snr); break;
    default: break;
  }
  if (relayOn && ttl > 1) scheduleForward(w, n, ttl - 1);
}

void pollRadio() {
  int sz = LoRa.parsePacket();
  if (sz <= 0) return;
  uint8_t buf[MAX_RAW];
  int n = 0;
  while (LoRa.available() && n < MAX_RAW) buf[n++] = (uint8_t)LoRa.read();
  if (meshMode) mtHandle(buf, n, LoRa.packetRssi(), LoRa.packetSnr());
  else handleWire(buf, n, LoRa.packetRssi(), LoRa.packetSnr());
}

// ==========================================================================
//  Web server
// ==========================================================================

void jerr(int code, const String& msg) {
  server.send(code, "application/json", "{\"err\":" + jstr(msg) + "}");
}
void jokx(const String& extra) {
  server.send(200, "application/json", "{\"ok\":1" + extra + "}");
}
void jok() { jokx(""); }

String meJson() {
  String o = "{\"u\":\"" + hex8(myUid) + "\",\"n\":" + jstr(myName);
  o += ",\"fp\":\"" + keyFp() + "\"";
  o += ",\"kd\":"; o += keyIsDefault ? "1" : "0";
  o += ",\"wd\":"; o += wifiDefault ? "1" : "0";
  o += ",\"ssid\":" + jstr(apSsid);
  o += ",\"fq\":" + String(freqKhz);
  o += ",\"rl\":"; o += relayOn ? "1" : "0";
  o += ",\"tk\":"; o += timeKnown ? "1" : "0";
  o += ",\"pr\":" + String(preset) + ",\"pw\":" + String(txPower);
  o += ",\"cp\":"; o += captiveOn ? "1" : "0";
  o += ",\"mt\":"; o += meshMode ? "1" : "0";
  o += ",\"mp\":" + String(mtPreset) + ",\"mn\":" + jstr(mtEffName()) + ",\"mc\":" + jstr(mtChName);
  o += ",\"mk\":" + jstr(mtKeyKind()) + ",\"mh\":" + String(mtHop) + ",\"ms\":" + String(mtSlot);
  o += ",\"mo\":" + String(mtFreqOvrKhz) + ",\"mf\":" + String(mtCurFreqHz()) + ",\"mx\":" + String(mtHash);
  o += ",\"chs\":[";
  bool f1 = true;
  for (int i = 0; i < MAX_CH; i++) {
    if (!chUsed[i] || meshMode) continue;
    if (!f1) o += ",";
    f1 = false;
    o += "{\"i\":" + String(i + 1) + ",\"n\":" + jstr(String(chName[i])) + ",\"fp\":\"" + chanFp(i) + "\"}";
  }
  o += "]";
  o += ",\"q\":" + String(qCount + (pend.active ? 1 : 0) + mtPending());
  o += featMeJson();
  o += remUsersJson();
  o += "}";
  return o;
}

String contactJson(const Contact& c, bool me) {
  String o = "{\"u\":\"" + hex8(c.uid) + "\",\"n\":" + jstr(String(c.name));
  o += ",\"me\":"; o += me ? "1" : "0";
  long ls = me ? 0 : (c.lastSeen ? (long)((millis() - c.lastSeen) / 1000UL) : -1);
  o += ",\"ls\":" + String(ls);
  o += ",\"rs\":" + String(c.rssi);
  o += ",\"sn\":" + String(c.snr);
  o += ",\"rx\":" + String(c.rxCount);
  o += ",\"rl\":"; o += (me ? relayOn : c.relayOn) ? "1" : "0";
  o += ",\"hl\":"; o += c.hasLoc ? "1" : "0";
  o += ",\"la\":" + String(c.lat);
  o += ",\"lo\":" + String(c.lon);
  o += ",\"ac\":" + String(c.acc);
  o += ",\"lt\":" + String(c.hasLoc ? (long)((millis() - c.locAt) / 1000UL) : 0L);
  o += ",\"tp\":" + String(c.trkCount);
  if (me ? myAvSet : c.avSet) o += ",\"ic\":" + String(me ? myAvIc : c.avIc) + ",\"icol\":" + String(me ? myAvCol : c.avCol);
  o += featContactJson(c.uid);
  o += "}";
  return o;
}

// Private user chats (lf/lt set) are stored once and shown per viewer: 'O' for the sender, 'I' for the recipient.
void routeIncomingToUser(Msg* m) {
  // A LoRa private text tagged "[from→user] text" is meant for the web user of that name on this device
  if (!m->dst || m->text.length() < 5 || m->text.charAt(0) != '[') return;
  int e = m->text.indexOf(']');
  if (e < 0) return;
  String tag = m->text.substring(1, e);
  int a = tag.indexOf("\xE2\x86\x92");                           // UTF-8 arrow
  if (a < 0) return;
  String to = tag.substring(a + 3);
  to.trim();
  int ui = to.length() ? userFind(to.c_str()) : -1;
  if (ui >= 0 && users[ui].role == 0) m->lt = (uint8_t)(ui + 1);   // empty / unknown recipient = the device owner (admin)
}

// display name of a local chat identity (1..8 = web user, 255 = the device owner)
static String lcName(int code) {
  if (code == LC_ADMIN) return String(myName);
  if (code >= 1 && code <= MAX_USERS && users[code - 1].used) return String(users[code - 1].name);
  return String("?");
}

String msgJson(const Msg& m, int viewer) {
  if (m.gone) return "{\"q\":" + String(m.seq) + ",\"r\":" + String(m.rev) + ",\"g\":1}";
  int vc = viewerCode(viewer);
  bool localDm = m.lf && m.lt;
  char dirOut = m.dir;
  String name;
  int senderCode = 0;                                   // local web user (1..8) / admin (255) who wrote it, 0 = unknown / remote
  if (localDm) {                                        // chat between two people of this device (users and/or the admin)
    senderCode = m.lf;
    name = lcName(m.lf);
    dirOut = (vc == m.lf) ? 'O' : 'I';
  } else if (m.lf) {                                    // a web user writing to another node: only that user sees it
    senderCode = m.lf;
    name = lcName(m.lf);
  } else if (m.dir == 'O' && m.su >= 1 && m.su <= MAX_USERS && users[m.su - 1].used) {   // a user's public / channel text
    senderCode = m.su;
    name = lcName(m.su);
    if (vc != m.su) dirOut = 'I';                       // the other people on this device see it as received
  } else if (m.dir == 'O') {
    name = myName;
    if (m.su == 0 && vc != LC_ADMIN) dirOut = 'I';      // written by the admin: chat-only users see it as received
  } else { Contact* c = findContact(m.uid); name = c ? String(c->name) : String("?"); }
  String o;
  o.reserve(220 + m.text.length());
  o += "{\"q\":" + String(m.seq);
  o += ",\"r\":" + String(m.rev);
  o += ",\"d\":\""; o += dirOut; o += "\"";
  if (localDm) { int oc = (vc == m.lf) ? m.lt : m.lf; o += ",\"lu\":" + String(oc == LC_ADMIN ? LC_ADMIN : oc - 1); }
  if (senderCode >= 1 && senderCode <= MAX_USERS && users[senderCode - 1].used)
    o += ",\"ic\":" + String(users[senderCode - 1].iconId) + ",\"icol\":" + String(users[senderCode - 1].iconColor);
  o += ",\"k\":" + String(m.kind);
  o += ",\"u\":\"" + hex8(m.uid) + "\"";
  o += ",\"n\":" + jstr(name);
  o += ",\"i\":" + String(m.id);
  o += ",\"s\":" + String(m.status);
  o += ",\"a\":" + String(m.acks);
  o += ",\"rd\":" + String(m.reads);
  o += ",\"pt\":" + String(m.partsTotal);
  o += ",\"pm\":" + String(m.partsMask);
  o += ",\"rs\":" + String(m.rssi);
  o += ",\"sn\":" + String(m.snr);
  o += ",\"t\":" + String(m.t);
  o += ",\"e\":"; o += m.edited ? "1" : "0";
  o += ",\"x\":"; o += m.deleted ? "1" : "0";
  o += ",\"hl\":"; o += m.hasLoc ? "1" : "0";
  o += ",\"la\":" + String(m.lat);
  o += ",\"lo\":" + String(m.lon);
  o += ",\"ac\":" + String(m.acc);
  o += ",\"tx\":" + jstr(m.text);
  o += ",\"to\":\"" + hex8(m.dst) + "\",\"ch\":" + String(m.ch) + ",\"op\":" + String(m.op);
  if (m.dir == 'O') {
    o += ",\"ab\":[";
    bool fa = true;
    for (int k = 0; k < MAX_ACKBY; k++) if (m.ackBy[k]) { if (!fa) o += ","; fa = false; o += "\"" + hex8(m.ackBy[k]) + "\""; }
    o += "],\"rb\":[";
    fa = true;
    for (int k = 0; k < MAX_ACKBY; k++) if (m.readBy[k]) { if (!fa) o += ","; fa = false; o += "\"" + hex8(m.readBy[k]) + "\""; }
    o += "]";
  }
  if (m.hasReply) o += ",\"rp\":{\"u\":\"" + hex8(m.rUid) + "\",\"i\":" + String(m.rId) + "}";
  o += "}";
  return o;
}

void handleRoot() { server.send_P(200, "text/html; charset=UTF-8", PAGE_HTML); }
void handleManifest() { server.send_P(200, "application/manifest+json", MANIFEST_JSON); }
void handleSw() { server.send_P(200, "application/javascript", SW_JS); }
void handleIcon192() { server.send_P(200, "image/png", (const char*)ICON192, ICON192_LEN); }
void handleIcon512() { server.send_P(200, "image/png", (const char*)ICON512, ICON512_LEN); }

void handlePoll() {
  if (authCurrent() == -1) { jerr(401, "Login required"); return; }
  uint32_t cRev = (uint32_t)server.arg("rev").toInt();
  uint32_t cClr = (uint32_t)server.arg("clr").toInt();
  if (server.hasArg("t")) {
    uint32_t t = (uint32_t)strtoul(server.arg("t").c_str(), nullptr, 10);
    if (t > 1600000000UL) { timeBase = t - millis() / 1000UL; timeKnown = true; }
  }
  if (server.arg("vis") == "1") markVisible();
  if (cClr != clearCount) cRev = 0;

  int viewer = authCurrent();
  int vc = viewerCode(viewer);
  bool limited = (viewer >= 0 && users[viewer].role == 0);
  String o;
  o.reserve(2048);
  o += "{\"rev\":" + String(revCounter) + ",\"clr\":" + String(clearCount);
  o += ",\"me\":" + meJson();
  o += ",\"msgs\":[";
  bool first = true;
  for (int i = 0; i < MAX_MSGS; i++) {
    const Msg& m = msgLog[(logHead + i) % MAX_MSGS];
    if (!m.seq || m.rev <= cRev) continue;
    if (m.gone && cRev == 0) continue;                  // fresh page load: deleted messages are simply absent
    if (m.lf || m.lt) {                                  // private user chat: only the two people involved (a user and/or the admin)
      if (vc != m.lf && vc != m.lt) continue;
    } else if (limited && (m.dst || m.dir == 'S')) continue;   // chat-only users see public + channel chat, never what is addressed to the device owner
    if (!first) o += ",";
    first = false;
    o += msgJson(m, viewer);
  }
  o += "],\"contacts\":[";
  first = true;
  for (int i = 0; i < MAX_CONTACTS; i++) {
    if (!contacts[i].used) continue;
    if (!first) o += ",";
    first = false;
    o += contactJson(contacts[i], i == 0);
  }
  o += "]}";
  server.sendHeader("Cache-Control", "no-store");
  server.send(200, "application/json", o);
}

bool readTarget(uint8_t* ch, uint32_t* dst) {
  *ch = 0;
  *dst = 0;
  if (server.hasArg("ch") && server.arg("ch").toInt() > 0) {
    int c = server.arg("ch").toInt();
    if (c > MAX_CH || !chUsed[c - 1]) { jerr(404, "Channel not found"); return false; }
    *ch = (uint8_t)c;
  } else if (server.hasArg("to") && server.arg("to").length()) {
    uint32_t u = (uint32_t)strtoul(server.arg("to").c_str(), nullptr, 16);
    if (u == myUid || !findContact(u)) { jerr(404, "Node not found"); return false; }
    *dst = u;
  }
  return true;
}

// Sends a normal chat text (both modes). Used by /api/send and by the periodic check-in.
// ------------------------------ Store-and-forward ------------------------------
// A private text for a node we have not heard for a while is kept here (RAM) and sent as soon as that node is heard again.
#define HOLD_MAX        6
#define HOLD_OFFLINE_MS 600000UL        // not heard for 10 min = offline
#define HOLD_KEEP_MS    21600000UL      // keep at most 6 h
struct HeldMsg { bool used; uint32_t uid; uint16_t base; uint8_t n; uint32_t at; };
HeldMsg held[HOLD_MAX];
bool holdAdd(uint32_t uid, uint16_t base, uint8_t n) {
  for (int i = 0; i < HOLD_MAX; i++) if (!held[i].used) { held[i].used = true; held[i].uid = uid; held[i].base = base; held[i].n = n; held[i].at = millis(); return true; }
  return false;
}
int sendTextCore(const String& t0, uint8_t tch, uint32_t tdst, bool hr, uint32_t ru, uint16_t ri,
                 uint8_t op, String& err, uint16_t& idOut) {
  String t = t0;
  // tag only if not already tagged by the caller (handleSend tags logged-in users)
  if (op >= 1 && op <= MAX_OPS && opTag && ops[op - 1][0] && !isLockedText(t0) && t0.charAt(0) != '[')
    t = "[" + String(ops[op - 1]) + "] " + t0;
  t = clipUtf8(t, MAX_TEXT_BYTES);
  if (!t.length()) { err = "Message is empty"; return 400; }
  if (meshMode) {
    if (tch) { err = "Private channels are not available in Meshtastic mode"; return 400; }
    int rc = mtSendMsg(K_TEXT, t, t, tdst, hr, ru, ri, false, err, idOut);
    if (!rc && op) { Msg* mm = findMsg(myUid, idOut, 'O'); if (mm) mm->op = op; }
    return rc;
  }
  uint8_t chunks[MAX_FRAGS][FRAG_DATA + 8];
  uint8_t lens[MAX_FRAGS];
  int n = buildChunks(t, chunks, lens, MAX_FRAGS);
  if (n <= 0) { err = "Message is too long"; return 413; }
  if (qCount + n > MAX_QUEUE) { err = "Send queue is full, wait a moment"; return 429; }
  uint16_t base = newIds(n);
  Msg* m = addMsg('O', K_TEXT, myUid, base);
  m->ch = tch;
  m->dst = tdst;
  m->text = t;
  m->op = op;
  m->partsTotal = n;
  if (hr) { m->hasReply = true; m->rUid = ru; m->rId = ri; }
  if (tdst && !tch && !hr) {                                   // store-and-forward for an offline node
    Contact* hc = findContact(tdst);
    if (hc && (hc->lastSeen ? ((uint32_t)(millis() - hc->lastSeen) > HOLD_OFFLINE_MS) : (millis() > HOLD_OFFLINE_MS)) && holdAdd(tdst, base, (uint8_t)n)) {
      idOut = base;
      sysLineTo(String(hc->name) + " is offline - the message is saved and will be sent when it is heard again", tdst);
      return 0;
    }
  }
  for (int i = 0; i < n; i++) {
    OutItem it;
    memset(&it, 0, sizeof(it));
    it.kind = K_TEXT;
    it.id = (uint16_t)(base + i);
    it.fragIdx = i;
    it.fragTotal = n;
    it.logId = base;
    if (i == 0 && m->hasReply) { it.flags = 1; it.refUid = m->rUid; it.refId = m->rId; }
    it.ch = tch;
    if (tdst) { it.flags |= 2; it.dst = tdst; }
    memcpy(it.data, chunks[i], lens[i]);
    it.dlen = lens[i];
    enqueue(it);
  }
  idOut = base;
  return 0;
}

void handleSend() {
  int authU = authCurrent();
  if (authU == -1) { jerr(401, "Login required"); return; }
  String t = sanitize(server.arg("text"));
  if (!t.length()) { jerr(400, "Message is empty"); return; }
  uint8_t tch;
  uint32_t tdst;
  if (!readTarget(&tch, &tdst)) return;
  // local private chat on this device (the admin and every web user can talk to each other): toUser=<index> or 255 = the admin
  if (server.hasArg("toUser")) {
    int tu = server.arg("toUser").toInt();
    int fc = viewerCode(authU);
    int tc;
    if (tu == LC_ADMIN) tc = LC_ADMIN;
    else {
      if (tu < 0 || tu >= MAX_USERS || !users[tu].used || users[tu].role != 0) { jerr(404, "User not found"); return; }
      tc = tu + 1;
    }
    if (tc == fc) { jerr(400, "That is you"); return; }
    Msg* mo = addMsg('O', K_TEXT, myUid, newIds(1));   // one message, shown as 'sent' to the sender and 'received' to the recipient
    mo->text = t;
    mo->lf = (uint8_t)fc;
    mo->lt = (uint8_t)tc;
    mo->status = 1;
    jokx(",\"local\":1");
    return;
  }
  int op = server.hasArg("op") ? server.arg("op").toInt() : 0;
  if (authU >= 0) {
    // prefer logged-in user name as operator tag
    op = authU + 1;
    // ensure ops[] has the name for air tag compatibility
    if (authU < MAX_OPS) strncpy(ops[authU], users[authU].name, 16);
  }
  if (op < 0 || op > MAX_OPS || (op && !ops[op - 1][0])) op = 0;
  // tag with logged-in username when enabled
  // private LoRa text from a web user: tag "[from→recipient]" so the far device can hand it to that user only.
  // The recipient is given as rcpt=<user>, or by starting the text with "@user ".
  String rcpt = clipUtf8(sanitize(server.arg("rcpt")), 16);
  if (tdst && !rcpt.length() && t.charAt(0) == '@') {
    int sp = t.indexOf(' ');
    if (sp > 1) { rcpt = t.substring(1, sp); t = t.substring(sp + 1); t.trim(); }
  }
  rcpt.trim();
  if (!t.length()) { jerr(400, "Message is empty"); return; }
  bool userSender = (authU >= 0 && users[authU].role == 0);      // a chat-only web user (not the admin)
  // Private text to another device is tagged "[from→to] text": "from" = the web user (empty = the admin of this device),
  // "to" = the web user on the far device (empty = the admin there). The far device files it into the right conversation.
  if (tdst && (rcpt.length() || userSender)) t = "[" + (userSender ? String(users[authU].name) : String("")) + "\xE2\x86\x92" + rcpt + "] " + t;
  else if (userSender) t = "[" + String(users[authU].name) + "] " + t;      // public / channel: the others see who wrote it
  else if (authU >= 0 && opTag) t = "[" + String(users[authU].name) + "] " + t;
  else if (op && opTag && op <= MAX_OPS && ops[op - 1][0]) t = "[" + String(ops[op - 1]) + "] " + t;
  if (server.hasArg("pin") && server.arg("pin").length()) {                 // PIN-locked emergency message
    String pin = server.arg("pin");
    if (pin.length() < 4) { jerr(400, "PIN must be at least 4 characters"); return; }
    if (t.length() > PIN_MAX_PLAIN) { jerr(413, "Locked messages are limited to 100 bytes"); return; }
    t = pinEncrypt(t, pin);
  }
  bool hr = server.hasArg("ru") && server.hasArg("ri");
  uint32_t ru = hr ? (uint32_t)strtoul(server.arg("ru").c_str(), nullptr, 16) : 0;
  uint16_t ri = hr ? (uint16_t)server.arg("ri").toInt() : 0;
  String err;
  uint16_t id = 0;
  // op field on message: store user index+1 when logged in (even if > MAX_OPS)
  uint8_t opField = (authU >= 0) ? (uint8_t)(authU + 1) : (uint8_t)op;
  int rc = sendTextCore(t, tch, tdst, hr, ru, ri, opField, err, id);
  if (rc) { jerr(rc, err); return; }
  if (userSender) {
    Msg* mm = findMsg(myUid, id, 'O');
    if (mm) {
      if (tdst) mm->lf = (uint8_t)(authU + 1);          // private: only this user sees it
      else mm->su = (uint8_t)(authU + 1);               // public / channel: everybody here sees it, labelled with this user
    }
  }
  jokx(",\"id\":" + String(id));
}

void holdFlushFor(uint32_t uid) {
  for (int h = 0; h < HOLD_MAX; h++) {
    if (!held[h].used || held[h].uid != uid) continue;
    HeldMsg hm = held[h];
    held[h].used = false;
    if ((uint32_t)(millis() - hm.at) > HOLD_KEEP_MS) continue;
    Msg* m = findMsg(myUid, hm.base, 'O');
    if (!m || m->gone) continue;
    uint8_t chunks[MAX_FRAGS][FRAG_DATA + 8];
    uint8_t lens[MAX_FRAGS];
    int n = buildChunks(m->text, chunks, lens, MAX_FRAGS);
    if (n <= 0 || n != hm.n || qCount + n > MAX_QUEUE) { held[h] = hm; held[h].used = true; return; }   // try again on the next packet
    for (int i = 0; i < n; i++) {
      OutItem it;
      memset(&it, 0, sizeof(it));
      it.kind = K_TEXT;
      it.id = (uint16_t)(hm.base + i);
      it.fragIdx = i;
      it.fragTotal = n;
      it.logId = hm.base;
      it.flags = 2;
      it.dst = uid;
      memcpy(it.data, chunks[i], lens[i]);
      it.dlen = lens[i];
      enqueue(it);
    }
    sysLineTo("Saved message sent now", uid);
  }
}

void handleQuick() {
  int code = server.arg("code").toInt();
  if (code < 0 || code > 63) { jerr(400, "bad code"); return; }
  if (meshMode) {
    uint8_t tch;
    uint32_t tdst;
    if (!readTarget(&tch, &tdst)) return;
    if (tch) { jerr(400, "Private channels are not available in Meshtastic mode"); return; }
    if (code > 7) { jerr(400, "Quick reply not available in Meshtastic mode"); return; }
    String err;
    uint16_t id = 0;
    int rc = mtSendMsg(K_QUICK, String(code), String(MT_QUICK[code]), tdst, false, 0, 0, false, err, id);
    if (rc) { jerr(rc, err); return; }
    jok();
    return;
  }
  if (qCount + 1 > MAX_QUEUE) { jerr(429, "Send queue is full"); return; }
  uint8_t tch;
  uint32_t tdst;
  if (!readTarget(&tch, &tdst)) return;
  uint16_t id = newIds(1);
  Msg* m = addMsg('O', K_QUICK, myUid, id);
  m->ch = tch;
  m->dst = tdst;
  m->text = String(code);
  m->partsTotal = 1;
  { int qa = authCurrent(); if (qa >= 0 && users[qa].role == 0) { if (tdst) m->lf = (uint8_t)(qa + 1); else m->su = (uint8_t)(qa + 1); } }   // a web user's quick reply keeps its author
  OutItem it;
  memset(&it, 0, sizeof(it));
  it.kind = K_QUICK; it.id = id; it.fragTotal = 1; it.logId = id;
  it.data[0] = (uint8_t)code; it.dlen = 1;
  it.ch = tch;
  if (tdst) { it.flags |= 2; it.dst = tdst; }
  enqueue(it);
  jok();
}

void handleEdit() {
  if (meshMode) { jerr(400, "Editing is not supported in Meshtastic mode"); return; }
  uint16_t id = (uint16_t)server.arg("id").toInt();
  String t = clipUtf8(sanitize(server.arg("text")), MAX_TEXT_BYTES);
  Msg* m = findMsg(myUid, id, 'O');
  if (!m || m->dir != 'O' || m->kind != K_TEXT || m->deleted) { jerr(404, "Message not found"); return; }
  if (!t.length()) { jerr(400, "Text is empty"); return; }
  uint8_t chunks[MAX_FRAGS][FRAG_DATA + 8];
  uint8_t lens[MAX_FRAGS];
  if (buildChunks(t, chunks, lens, 1) != 1) { jerr(413, "Only short single-packet text can be edited"); return; }
  if (qCount + 1 > MAX_QUEUE) { jerr(429, "Send queue is full"); return; }
  OutItem it;
  memset(&it, 0, sizeof(it));
  it.kind = K_EDIT; it.id = newIds(1); it.fragTotal = 1;
  it.ch = m->ch;
  if (m->dst) { it.flags |= 2; it.dst = m->dst; }
  putU16(it.data, id);
  memcpy(it.data + 2, chunks[0], lens[0]);
  it.dlen = 2 + lens[0];
  enqueue(it);
  m->text = t; m->edited = true; touch(m);
  jok();
}

void handleDel() {
  if (meshMode) { jerr(400, "Deleting is not supported in Meshtastic mode"); return; }
  uint16_t id = (uint16_t)server.arg("id").toInt();
  Msg* m = findMsg(myUid, id, 'O');
  if (!m || m->dir != 'O' || m->deleted) { jerr(404, "Message not found"); return; }
  if (qCount + 1 > MAX_QUEUE) { jerr(429, "Send queue is full"); return; }
  OutItem it;
  memset(&it, 0, sizeof(it));
  it.kind = K_DEL; it.id = newIds(1); it.fragTotal = 1;
  it.ch = m->ch;
  if (m->dst) { it.flags |= 2; it.dst = m->dst; }
  putU16(it.data, id);
  it.dlen = 2;
  enqueue(it);
  m->deleted = true; m->text = ""; touch(m);
  jok();
}

bool readCoords(int32_t* la, int32_t* lo, uint16_t* acc) {
  if (!server.hasArg("lat") || !server.hasArg("lon")) return false;
  double lat = server.arg("lat").toDouble(), lon = server.arg("lon").toDouble();
  if (fabs(lat) > 90.0 || fabs(lon) > 180.0) return false;
  long a = server.arg("acc").toInt();
  if (a < 0) a = 0;
  if (a > 65535) a = 65535;
  *la = (int32_t)lround(lat * 1e6);
  *lo = (int32_t)lround(lon * 1e6);
  *acc = (uint16_t)a;
  return true;
}

void handleLoc() {
  int32_t la, lo;
  uint16_t acc;
  if (!readCoords(&la, &lo, &acc)) { jerr(400, "Invalid coordinates"); return; }
  setContactLoc(&contacts[0], la, lo, acc);
  if (meshMode) {
    if (server.arg("mode") == "live") {               // keep airtime low: one position per minute
      static uint32_t lastMtLive = 0;
      if ((lastMtLive == 0 || millis() - lastMtLive >= 60000UL) && mtFree() > 0) {
        mtSendPosition(la, lo, MT_BROADCAST, 0, 0);
        lastMtLive = millis();
      }
      jok();
      return;
    }
    uint8_t tch;
    uint32_t tdst;
    if (!readTarget(&tch, &tdst)) return;
    if (tch) { jerr(400, "Private channels are not available in Meshtastic mode"); return; }
    if (mtFree() < 1) { jerr(429, "Send queue is full"); return; }
    uint32_t pid = mtNewIds(1);
    Msg* m = addMsg('O', K_LOC, myUid, (uint16_t)pid);
    m->pid = pid; m->dst = tdst; m->partsTotal = 1;
    m->hasLoc = true; m->lat = la; m->lon = lo; m->acc = acc;
    mtSendPosition(la, lo, tdst ? tdst : MT_BROADCAST, pid, (uint16_t)pid);
    jok();
    return;
  }
  if (server.arg("mode") == "live") {
    static uint32_t lastLive = 0;
    if (millis() - lastLive >= 5000UL || lastLive == 0) {
      uint8_t b[11];
      b[0] = 'L';
      putU32(b + 1, (uint32_t)la);
      putU32(b + 5, (uint32_t)lo);
      putU16(b + 9, acc);
      sendSecure(b, 11, DEFAULT_TTL);
      lastLive = millis();
    }
    jok();
    return;
  }
  if (qCount + 1 > MAX_QUEUE) { jerr(429, "Send queue is full"); return; }
  uint8_t tch;
  uint32_t tdst;
  if (!readTarget(&tch, &tdst)) return;
  uint16_t id = newIds(1);
  Msg* m = addMsg('O', K_LOC, myUid, id);
  m->ch = tch;
  m->dst = tdst;
  m->partsTotal = 1; m->hasLoc = true; m->lat = la; m->lon = lo; m->acc = acc;
  OutItem it;
  memset(&it, 0, sizeof(it));
  it.kind = K_LOC; it.id = id; it.fragTotal = 1; it.logId = id;
  putU32(it.data, (uint32_t)la);
  putU32(it.data + 4, (uint32_t)lo);
  putU16(it.data + 8, acc);
  it.dlen = 10;
  it.ch = tch;
  if (tdst) { it.flags |= 2; it.dst = tdst; }
  enqueue(it);
  jok();
}

// Sends one SOS (both modes). Used by /api/sos, the hardware button and the repeat timer.
bool sosSendNow(bool has, int32_t la, int32_t lo, uint16_t acc, uint32_t dst, uint8_t ch, String& err, uint16_t& idOut) {
  if (meshMode) {                                    // Meshtastic has no SOS packet: text + position (to one node or to everybody)
    if (ch) { err = "Private channels are not available in Meshtastic mode"; return false; }
    String w = has ? "SOS! I need help - my position follows" : "SOS! I need help";
    int rc = mtSendMsg(K_SOS, "", w, dst, false, 0, 0, true, err, idOut);
    if (rc) return false;
    if (has) {
      Msg* sm = findMsg(myUid, idOut, 'O');
      if (sm) { sm->hasLoc = true; sm->lat = la; sm->lon = lo; sm->acc = acc; }
      if (mtFree() > 0) mtSendPosition(la, lo, dst ? dst : MT_BROADCAST, 0, 0);
    }
    return true;
  }
  if (qCount + 1 > MAX_QUEUE) { err = "Send queue is full"; return false; }
  uint16_t id = newIds(1);
  Msg* m = addMsg('O', K_SOS, myUid, id);
  m->partsTotal = 1;
  m->dst = dst;                                      // private SOS stays in that chat; dst = 0 + ch = 0 means everybody
  m->ch = ch;
  if (has) { m->hasLoc = true; m->lat = la; m->lon = lo; m->acc = acc; }
  OutItem it;
  memset(&it, 0, sizeof(it));
  it.kind = K_SOS; it.id = id; it.fragTotal = 1; it.logId = id; it.prio = true;
  it.ch = ch;
  if (dst) { it.flags |= 2; it.dst = dst; }
  it.data[0] = has ? 1 : 0;
  putU32(it.data + 1, (uint32_t)la);
  putU32(it.data + 5, (uint32_t)lo);
  putU16(it.data + 9, acc);
  it.dlen = 11;
  enqueue(it);
  idOut = id;
  return true;
}

void handleSos() {
  int32_t la = 0, lo = 0;
  uint16_t acc = 0;
  bool has = readCoords(&la, &lo, &acc);
  if (has) setContactLoc(&contacts[0], la, lo, acc);
  uint8_t tch = 0;
  uint32_t tdst = 0;
  if (!readTarget(&tch, &tdst)) return;               // SOS from a private chat / channel stays in that chat
  String err;
  uint16_t id = 0;
  if (!sosSendNow(has, la, lo, acc, tdst, tch, err, id)) { jerr(429, err); return; }
  if (!server.hasArg("rep") || server.arg("rep") != "0") sosRepStart(id, has, la, lo, acc, tdst, tch);   // repeat until acknowledged
  jok();
}

void handleApiPing() {
  uint32_t to = server.hasArg("to") ? (uint32_t)strtoul(server.arg("to").c_str(), nullptr, 16) : 0;
  startPingTo(to, server.arg("quiet") == "1");
  jok();
}

void handleCfg() {
  bool restart = false;
  if (server.hasArg("name")) {
    String n = clipUtf8(sanitize(server.arg("name")), 24);
    if (!n.length()) { jerr(400, "Name is empty"); return; }
    setMyName(n);
  }
  if (server.hasArg("pass") && server.arg("pass").length()) {
    String p = server.arg("pass");
    if (p.length() < 6) { jerr(400, "Passphrase must be at least 6 characters"); return; }
    uint8_t k[16];
    deriveKey(p, k);
    applyKey(k);
    prefs.putBytes("key", k, 16);
    keyIsDefault = false;
    for (int i = 1; i < MAX_CONTACTS; i++) contacts[i].lastCtr = 0;
  }
  if (server.hasArg("ssid") || server.hasArg("wpass")) {
    String s = server.hasArg("ssid") ? sanitize(server.arg("ssid")) : apSsid;
    String w = server.hasArg("wpass") ? server.arg("wpass") : apPass;
    if (s.length() < 1 || s.length() > 31) { jerr(400, "Network name must be 1-31 characters"); return; }
    if (w.length() < 8 || w.length() > 63) { jerr(400, "Wi-Fi password must be 8-63 characters"); return; }
    prefs.putString("ssid", s);
    prefs.putString("wpass", w);
    restart = true;
  }
  if (server.hasArg("freq")) {
    uint32_t f = (uint32_t)strtoul(server.arg("freq").c_str(), nullptr, 10);
    if (f < FREQ_MIN_KHZ || f > FREQ_MAX_KHZ) { jerr(400, "Frequency out of range"); return; }
    freqKhz = f;
    prefs.putULong("freq", f);
    applyRadio();
  }
  if (server.hasArg("relay")) {
    relayOn = server.arg("relay") == "1";
    prefs.putBool("relay", relayOn);
    nextBeaconAt = millis() + 1500;
  }
  if (server.hasArg("preset")) {
    int p = server.arg("preset").toInt();
    if (p < 0 || p > 3) { jerr(400, "Bad radio preset"); return; }
    preset = p;
    prefs.putInt("preset", p);
    applyRadio();
  }
  if (server.hasArg("txp")) {
    int p = server.arg("txp").toInt();
    if (p < 2 || p > 20) { jerr(400, "TX power must be 2-20 dBm"); return; }
    txPower = p;
    prefs.putInt("txp", p);
    applyRadio();
  }
  if (server.hasArg("cap")) {
    captiveOn = server.arg("cap") == "1";
    prefs.putBool("cap", captiveOn);
    if (captiveOn) dnsServer.start(53, "*", WiFi.softAPIP()); else dnsServer.stop();
  }
  // ---- Meshtastic settings
  bool mtChanged = false;
  if (server.hasArg("mtpre")) {
    int p = server.arg("mtpre").toInt();
    if (!mtPresetValid(p)) { jerr(400, "Bad Meshtastic preset"); return; }
    mtPreset = p; mtChanged = true;
  }
  if (server.hasArg("mtname")) {
    String n = sanitize(server.arg("mtname"));
    if (n.length() > 11) { jerr(400, "Channel name: 11 bytes at most"); return; }
    mtChName = n; mtChanged = true;
  }
  if (server.hasArg("mtpsk")) {
    if (!mtSetPsk(server.arg("mtpsk"))) { jerr(400, "Key must be base64 (16 or 32 bytes), 'default' or 'none'"); return; }
    mtChanged = true;
  }
  if (server.hasArg("mturl") && server.arg("mturl").length()) {
    if (!mtApplyUrl(server.arg("mturl"))) { jerr(400, "Not a valid Meshtastic channel link"); return; }
    mtChanged = true;
  }
  if (server.hasArg("mtslot")) {
    int sl = server.arg("mtslot").toInt();
    if (sl < 0 || sl > 99) { jerr(400, "Frequency slot must be 0 (auto) to 99"); return; }
    mtSlot = (uint8_t)sl; mtChanged = true;
  }
  if (server.hasArg("mthop")) {
    int hp = server.arg("mthop").toInt();
    if (hp < 1 || hp > 7) { jerr(400, "Hop limit must be 1-7"); return; }
    mtHop = (uint8_t)hp; mtChanged = true;
  }
  if (server.hasArg("mtfq")) {
    uint32_t f = (uint32_t)strtoul(server.arg("mtfq").c_str(), nullptr, 10);
    if (f && (f < FREQ_MIN_KHZ || f > FREQ_MAX_KHZ)) { jerr(400, "Frequency out of range"); return; }
    mtFreqOvrKhz = f; mtChanged = true;
  }
  if (server.hasArg("mode")) {
    bool mm = server.arg("mode") == "1";
    if (mm != meshMode) {
      meshMode = mm;
      mtResetState();
      featReset();
      helloPending = true;
      nextBeaconAt = millis() + random(4000, 9000);
      mtChanged = true;
      mtRecalc();
      if (meshMode) sysLine("Meshtastic mode on: " + mtEffName() + ", " + String(mtCurFreqHz() / 1e6, 3) + " MHz. LoRa Link nodes cannot hear this node until you switch back.");
      else sysLine("LoRa Link mode on.");
    }
  }
  if (mtChanged) { mtRecalc(); mtSave(); applyRadio(); }
  jokx(String(",\"restart\":") + (restart ? "1" : "0"));
}

void handleChan() {
  int i = server.arg("slot").toInt() - 1;
  if (i < 0 || i >= MAX_CH) { jerr(400, "Bad channel slot"); return; }
  String kn = "chk" + String(i), nn = "chn" + String(i);
  if (server.arg("del") == "1") {
    chUsed[i] = false;
    prefs.remove(kn.c_str());
    prefs.remove(nn.c_str());
    for (int k = 0; k < MAX_MSGS; k++) if (msgLog[k].seq && msgLog[k].ch == i + 1) msgLog[k].seq = 0;
    clearCount++;
    revCounter++;
    jok();
    return;
  }
  String n = clipUtf8(sanitize(server.arg("name")), 20);
  String p = server.arg("pass");
  if (!n.length()) { jerr(400, "Channel name is empty"); return; }
  if (p.length() < 6) { jerr(400, "Passphrase must be at least 6 characters"); return; }
  uint8_t k[16];
  deriveKey(p, k);
  setChannel(i, n, k);
  prefs.putBytes(kn.c_str(), k, 16);
  prefs.putString(nn.c_str(), n);
  jok();
}

void handleNotFound() {
  String uri = server.uri();
  // Per-user path: /x1, /y2 ... serve the same SPA; the page reads the path and asks for that user's login only
  if (server.method() == HTTP_GET && uri.length() > 1 && uri.indexOf("/api") != 0 && uri.indexOf('.') < 0) {
    String seg = uri.substring(1);
    int sl = seg.indexOf('/');
    if (sl >= 0) seg = seg.substring(0, sl);
    seg.toLowerCase();
    if (userFindSlug(seg.c_str()) >= 0) {
      server.send_P(200, "text/html; charset=UTF-8", PAGE_HTML);
      return;
    }
  }
  if (captiveOn && server.method() == HTTP_GET && uri.indexOf("/api") != 0) {
    server.sendHeader("Location", String("http://") + WiFi.softAPIP().toString() + "/", true);
    server.send(302, "text/plain", "");
    return;
  }
  server.send(404, "text/plain", "Not found");
}

void handleStats() {
  String o = "{";
  o += "\"up\":" + String(millis() / 1000UL);
  o += ",\"tx\":" + String(cTx) + ",\"rx\":" + String(cRx) + ",\"ok\":" + String(cOk);
  o += ",\"auth\":" + String(cAuth) + ",\"replay\":" + String(cReplay) + ",\"dup\":" + String(cDup);
  o += ",\"retry\":" + String(cRetry) + ",\"fail\":" + String(cFail) + ",\"relay\":" + String(cRelay) + ",\"supp\":" + String(cSupp);
  o += ",\"avg\":" + String((int)lroundf(avgRssi));
  o += ",\"air\":" + String(airHour());
  o += ",\"q\":" + String(qCount + (pend.active ? 1 : 0) + mtPending());
  o += ",\"heap\":" + String((uint32_t)ESP.getFreeHeap());
  o += "}";
  server.send(200, "application/json", o);
}

void handleScan() {
  String o = "{\"ch\":[";
  bool first = true;
  for (uint32_t k = 433050UL; k <= 434750UL; k += 100UL) {
    LoRa.setFrequency((long)k * 1000L);
    LoRa.receive();
    delay(25);
    int mx = -200;
    for (int s = 0; s < 8; s++) { int r = LoRa.rssi(); if (r > mx) mx = r; delay(4); }
    if (!first) o += ",";
    first = false;
    o += "{\"f\":" + String(k) + ",\"r\":" + String(mx) + "}";
  }
  LoRa.setFrequency(curFreqHz());
  LoRa.idle();
  o += "]}";
  server.send(200, "application/json", o);
}

void handleGpx() {
  String u = server.arg("u");
  Contact* c = (u == "me") ? &contacts[0] : findContact((uint32_t)strtoul(u.c_str(), nullptr, 16));
  if (!c || c->trkCount == 0) { server.send(404, "text/plain", "no track"); return; }
  String o;
  o.reserve(c->trkCount * 100 + 300);
  o += "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
  o += "<gpx version=\"1.1\" creator=\"LoRaLink\" xmlns=\"http://www.topografix.com/GPX/1/1\">\n";
  o += "<trk><name>" + xmlEsc(String(c->name)) + "</name><trkseg>\n";
  int start = (c->trkCount < TRACK_MAX) ? 0 : c->trkHead;
  for (int i = 0; i < c->trkCount; i++) {
    const TrackPt& p = c->trk[(start + i) % TRACK_MAX];
    char b[96];
    snprintf(b, sizeof(b), "<trkpt lat=\"%.6f\" lon=\"%.6f\">", p.lat / 1e6, p.lon / 1e6);
    o += b;
    if (p.t) {
      time_t tt = (time_t)p.t;
      struct tm tmv;
      gmtime_r(&tt, &tmv);
      char tb[32];
      strftime(tb, sizeof(tb), "%Y-%m-%dT%H:%M:%SZ", &tmv);
      o += "<time>"; o += tb; o += "</time>";
    }
    o += "</trkpt>\n";
  }
  o += "</trkseg></trk></gpx>\n";
  server.sendHeader("Content-Disposition", "attachment; filename=\"track-" + hex8(c->uid) + ".gpx\"");
  server.send(200, "application/gpx+xml", o);
}

void handleClear() {
  for (int i = 0; i < MAX_MSGS; i++) msgLog[i].seq = 0;
  logHead = 0;
  clearCount++;
  revCounter++;
  unread = 0;
  jok();
}

void handleResetCtr() {
  for (int i = 1; i < MAX_CONTACTS; i++) contacts[i].lastCtr = 0;
  jok();
}

#include "lm_features_api.h"
#include "lm_files.h"
#if USE_BLE_BRIDGE
#include "lm_ble.h"
#endif

void handleRestart() { jok(); restartAt = millis() + 800; if (!restartAt) restartAt = 1; }
void handleWipe() { jok(); wipeAt = millis() + 600; if (!wipeAt) wipeAt = 1; }

// ==========================================================================
//  Remote Morse – send request + status reports
// ==========================================================================
// Special marker used in text for Meshtastic compatibility and status packets
#define MZ_MARK "§MZ:"

// Send a remote-Morse request to one node (native packet or special text).
// Returns 0 on success, HTTP-style error otherwise.
int sendRemoteMorse(uint32_t toUid, const String& text, uint8_t out, uint8_t n,
                    uint16_t gapSec, uint8_t wpm, bool untilConfirm, String& err, uint16_t& idOut) {
  if (!toUid || toUid == myUid) { err = "Choose a destination node"; return 400; }
  if (!findContact(toUid)) { err = "Node not found"; return 404; }

  char buf[48];
  int k = 0;
  for (unsigned i = 0; i < text.length() && k < 47; i++) {
    char c = text[i];
    if (c >= 'a' && c <= 'z') c -= 32;
    if (c == ' ' || morseOf(c)) buf[k++] = c;
  }
  buf[k] = 0;
  if (!k) { err = "Nothing to send as Morse"; return 400; }
  if (out < 1 || out > 3) out = 3;
  if (n < 1) n = 1; if (n > 10) n = 10;
  if (gapSec < 5) gapSec = 5; if (gapSec > 120) gapSec = 120;
  if (wpm < 5) wpm = 5; if (wpm > 25) wpm = 25;

  idOut = newIds(1);

  if (meshMode) {
    // Meshtastic: special text that our nodes recognise
    String payload = String(MZ_MARK) + "R:" + String(idOut) + ":" + String(out) + ":" +
                     String(n) + ":" + String(gapSec) + ":" + String(wpm) + ":" +
                     (untilConfirm ? "1" : "0") + ":" + String(buf);
    int rc = mtSendMsg(K_TEXT, payload, payload, toUid, false, 0, 0, false, err, idOut);
    if (rc) return rc;
  } else {
    // Native: K_MORSE packet
    uint8_t data[50];
    data[0] = (untilConfirm ? 1 : 0) | ((out & 3) << 1);
    data[1] = n;
    data[2] = (uint8_t)gapSec;
    data[3] = wpm;
    int tl = k; if (tl > 40) tl = 40;
    memcpy(data + 4, buf, tl);
    int dlen = 4 + tl;

    OutItem it;
    memset(&it, 0, sizeof(it));
    it.kind = K_MORSE;
    it.id = idOut;
    it.fragTotal = 1;
    it.dlen = (uint8_t)dlen;
    memcpy(it.data, data, dlen);
    it.logId = idOut;
    it.dst = toUid;
    it.flags = 2;           // private destination bit (required so only the target processes it)
    it.prio = true;
    enqueue(it);
  }

  // track on sender side
  memset(&rs, 0, sizeof(rs));
  rs.active = true;
  rs.status = RS_SENT;
  rs.toUid = toUid;
  rs.reqId = idOut;
  strncpy(rs.text, buf, 47);
  rs.n = n;
  rs.done = 0;
  rs.startedAt = millis();
  rs.lastUpdate = millis();

  // also put a visible line in the private chat
  Msg* m = addMsg('O', K_TEXT, myUid, idOut);
  m->dst = toUid;
  m->text = String("[Morse →] ") + buf + (untilConfirm ? " (until confirm)" : (" ×" + String(n)));
  m->status = 0;
  return 0;
}

// Parse and handle control texts: Morse (§MZ:), Find-device (§FD:), etc.
bool handleMorseControlText(Contact* c, const String& t, uint16_t id, int rssi, int snr) {
  // Find-device remote request
  if (t.startsWith("§FD:")) {
    int sec = t.substring(strlen("§FD:")).toInt();
    if (sec < 5) sec = 5;
    if (sec > 600) sec = 600;
    findDevStart((uint16_t)sec);
    sysLineTo("Find-me requested – sounding for " + String(sec) + " s", c->uid);
    return true;
  }
  // Shared checklist sync
  if (t.startsWith("§CL:")) {
    checklistApplyRemote(t.substring(strlen("§CL:")));
    return true;
  }
  // Remote admin command
  if (t.startsWith("§AD:")) {
    adminHandleRemote(t.substring(strlen("§AD:")), c->uid);
    return true;
  }
  // Rally / assembly point
  if (t.startsWith("§RY:")) {
    rallyApplyRemote(t.substring(strlen("§RY:")));
    return true;
  }

  if (!t.startsWith(MZ_MARK)) return false;
  String body = t.substring(strlen(MZ_MARK));

  // Request: R:<reqId>:<out>:<n>:<gap>:<wpm>:<until>:<text>
  if (body.startsWith("R:")) {
    int p1 = body.indexOf(':', 2);
    int p2 = body.indexOf(':', p1 + 1);
    int p3 = body.indexOf(':', p2 + 1);
    int p4 = body.indexOf(':', p3 + 1);
    int p5 = body.indexOf(':', p4 + 1);
    int p6 = body.indexOf(':', p5 + 1);
    if (p6 < 0) return true;
    uint16_t reqId = (uint16_t)body.substring(2, p1).toInt();
    uint8_t out = (uint8_t)body.substring(p1 + 1, p2).toInt();
    uint8_t n   = (uint8_t)body.substring(p2 + 1, p3).toInt();
    uint16_t gap = (uint16_t)body.substring(p3 + 1, p4).toInt();
    uint8_t wpm = (uint8_t)body.substring(p4 + 1, p5).toInt();
    bool untilC = body.substring(p5 + 1, p6).toInt() != 0;
    String txt = body.substring(p6 + 1);
    String err;
    if (rm.acceptFrom == 0) return true;
    if (!remoteMorseStart(c->uid, reqId, txt.c_str(), out, n, gap, wpm, untilC, err)) {
      sysLineTo("Remote Morse rejected: " + err, c->uid);
      return true;
    }
    Msg* m = newIncoming(c, K_TEXT, id, rssi, snr);
    m->text = String("[Morse] ") + txt + (untilC ? " (until confirm)" : (" ×" + String(n)));
    return true;
  }

  // Status from remote: S:<reqId>:<status>:<done>
  if (body.startsWith("S:")) {
    int p1 = body.indexOf(':', 2);
    int p2 = body.indexOf(':', p1 + 1);
    if (p2 < 0) return true;
    uint16_t reqId = (uint16_t)body.substring(2, p1).toInt();
    uint8_t st = (uint8_t)body.substring(p1 + 1, p2).toInt();
    uint8_t done = (uint8_t)body.substring(p2 + 1).toInt();
    if (rs.active && rs.reqId == reqId && rs.toUid == c->uid) {
      rs.status = st;
      rs.done = done;
      rs.lastUpdate = millis();
      // feedback on this device when confirmed
      if (st == RS_CONFIRMED || st == RM_CONFIRMED) {
        hwNotify(0);
        ledFlashUntil = millis() + 400;
      } else if (st == RS_PROBLEM || st == RM_PROBLEM) {
        hwNotify(1);
      }
      // human-readable system line
      const char* lab = "?";
      if (st == RS_DELIVERED || st == RM_RECV) lab = "device received";
      else if (st == RS_PLAYING || st == RM_PLAYING) lab = "playing";
      else if (st == RS_PLAY_DONE || st == RM_DONE) lab = "play finished";
      else if (st == RS_CONFIRMED || st == RM_CONFIRMED) lab = "confirmed by person";
      else if (st == RS_PROBLEM || st == RM_PROBLEM) lab = "confirmed – PROBLEM";
      else if (st == RS_NO_CONFIRM) lab = "no one confirmed";
      sysLineTo(String("Morse #") + reqId + ": " + lab +
                (done ? (" (" + String(done) + "/" + String(rs.n) + ")") : ""), c->uid);
    }
    return true;
  }
  return false;
}

// Called from loop – sends status packets when remote session state changes,
// and times out the sender-side tracker.
static uint8_t lastRmStatus = 0xFF;
static uint8_t lastRmDone = 0xFF;

void remoteMorseTick() {
  uint32_t now = millis();

  // --- receiver side: report status changes back to sender ---
  if (rm.active || lastRmStatus != 0xFF) {
    uint8_t curSt = rm.status;            // also report the FINAL state (confirmed / done) after rm.active went false
    uint8_t curDone = rm.done;
    if (curSt != lastRmStatus || curDone != lastRmDone) {
      lastRmStatus = curSt;
      lastRmDone = curDone;
      // map internal RM_* to the RS_* values the sender understands
      uint8_t report = curSt;
      if (curSt == RM_RECV) report = RS_DELIVERED;
      else if (curSt == RM_PLAYING) report = RS_PLAYING;
      else if (curSt == RM_WAIT_GAP) report = RS_PLAYING;
      else if (curSt == RM_DONE) report = (rm.untilConfirm ? RS_NO_CONFIRM : RS_PLAY_DONE);
      else if (curSt == RM_CONFIRMED) report = RS_CONFIRMED;
      else if (curSt == RM_PROBLEM) report = RS_PROBLEM;

      String payload = String(MZ_MARK) + "S:" + String(rm.reqId) + ":" + String(report) + ":" + String(curDone);
      String err;
      uint16_t id = 0;
      // private message back to the originator
      if (meshMode) {
        mtSendMsg(K_TEXT, payload, payload, rm.fromUid, false, 0, 0, false, err, id);
      } else {
        sendTextCore(payload, 0, rm.fromUid, false, 0, 0, 0, err, id);
      }
    }
    if (!rm.active) { lastRmStatus = 0xFF; lastRmDone = 0xFF; }
  }

  // --- sender side: timeout if no update for a long time ---
  if (rs.active && (now - rs.lastUpdate) > 180000UL) {   // 3 min silence
    if (rs.status < RS_CONFIRMED) {
      rs.status = RS_NO_CONFIRM;
      sysLineTo("Morse: no confirmation received (timeout)", rs.toUid);
    }
    rs.active = false;
  }
}

// ==========================================================================
//  Hardware button : short = ping (or Morse confirm when remote active),
//                    double short = Morse "problem", hold 5 s = SOS, 30 s = factory reset
// ==========================================================================
void serviceButton() {
#if USE_BUTTON
  static bool lastState = HIGH;
  static uint32_t pressedAt = 0, lastChange = 0, lastRelease = 0;
  static bool wiped = false, sosArmed = false;
  static uint8_t clickCount = 0;
  bool s = digitalRead(BTN_PIN);
  uint32_t now = millis();

  // expire multi-click window
  if (clickCount && (now - lastRelease) > 450) {
    // process accumulated clicks
    if (rm.active && (rm.status == RM_PLAYING || rm.status == RM_WAIT_GAP || rm.status == RM_RECV)) {
      if (clickCount == 1) {
        // single click = confirmed received
        remoteMorseStop(RM_CONFIRMED);
        hwNotify(0);   // short beep + LED on sender will be triggered by status packet
        // status report is sent by remoteMorseService()
      } else if (clickCount >= 2) {
        // double click = received but problem
        remoteMorseStop(RM_PROBLEM);
        hwNotify(1);
      }
    } else if (clickCount == 1) {
      btnActionRun(btnSglAction);                    // configurable single press (default = ping)
    } else if (clickCount == 2) {
      btnActionRun(btnDblAction);                    // configurable double-click
    } else if (clickCount >= 3) {
      btnActionRun(btnTrpAction);                    // configurable triple-click
    }
    clickCount = 0;
  }

  if (s != lastState && now - lastChange > 40) {
    lastChange = now;
    lastState = s;
    if (s == LOW) { pressedAt = now; wiped = false; sosArmed = false; }
    else {
      ledWarn = false;
      uint32_t held = now - pressedAt;
      if (!wiped) {
        if (held < 5000) {
          // short release → count as click (may be multi-click)
          clickCount++;
          lastRelease = now;
        } else if (held < 30000) {                                      // hold 5-30 s = SOS (again = cancel)
          clickCount = 0;
          if (sosR.active) sosRepStop("cancelled with the button", 1);
          else {
            bool has = contacts[0].hasLoc;
            String err;
            uint16_t id = 0;
            if (sosSendNow(has, contacts[0].lat, contacts[0].lon, contacts[0].acc, 0, 0, err, id))
              sosRepStart(id, has, contacts[0].lat, contacts[0].lon, contacts[0].acc, 0, 0);
          }
        }
      }
    }
  }
  if (lastState == LOW && !wiped) {
    uint32_t held = now - pressedAt;
    if (held >= 5000 && !sosArmed) { sosArmed = true; hwNotify(1); }
    ledWarn = (held >= 5000);
    if (held >= 30000) {
      wiped = true;
      clickCount = 0;
      ledWarn = false;
      ledUntil = now + 2000;
      hwNotify(2);
      wipeAt = now + 1800;
      if (!wipeAt) wipeAt = 1;
    }
  }
#endif
}

// ==========================================================================
//  Setup / loop
// ==========================================================================
void loadSettings() {
  myUid = (uint32_t)(ESP.getEfuseMac() >> 16);
  if (myUid < 4 || myUid == 0xFFFFFFFFUL) myUid ^= 0x5A5A5A5AUL;     // 0-3 and 0xFFFFFFFF are reserved by Meshtastic
  String defName = String("Node-") + hex8(myUid).substring(4);
  myName = prefs.getString("name", defName);
  apSsid = prefs.getString("ssid", String("LoRaLink-") + hex8(myUid).substring(4));
  wifiDefault = !prefs.isKey("wpass");
  apPass = prefs.getString("wpass", "12345678");
  freqKhz = prefs.getULong("freq", FREQ_DEFAULT_KHZ);
  if (freqKhz < FREQ_MIN_KHZ || freqKhz > FREQ_MAX_KHZ) freqKhz = FREQ_DEFAULT_KHZ;
  relayOn = prefs.getBool("relay", false);
  preset = prefs.getInt("preset", 0);
  if (preset < 0 || preset > 3) preset = 0;
  txPower = prefs.getInt("txp", LORA_TX_POWER);
  if (txPower < 2 || txPower > 20) txPower = LORA_TX_POWER;
  captiveOn = prefs.getBool("cap", true);
  epochNo = prefs.getUShort("epoch", 0) + 1;
  prefs.putUShort("epoch", epochNo);

  uint8_t k[16];
  if (prefs.isKey("key") && prefs.getBytes("key", k, 16) == 16) {
    keyIsDefault = false;
  } else {
    deriveKey("changeme", k);
    keyIsDefault = true;
  }
  applyKey(k);
  mtLoad();
  featLoad();
  hwLoad();
  morseLoad();

  for (int i = 0; i < MAX_CONTACTS; i++) contacts[i].used = false;
  initContact(&contacts[0], myUid);
  strncpy(contacts[0].name, myName.c_str(), sizeof(contacts[0].name) - 1);
  contacts[0].name[sizeof(contacts[0].name) - 1] = 0;
}

void setup() {
  Serial.begin(115200);
  pinMode(LED_PIN, OUTPUT);
  pinMode(LORA_SS, OUTPUT);
  digitalWrite(LORA_SS, HIGH);
#if USE_BUTTON
  pinMode(BTN_PIN, INPUT_PULLUP);
#endif
#if SOS_BTN_PIN >= 0
  pinMode(SOS_BTN_PIN, INPUT_PULLUP);
#endif
  prefs.begin("lora3", false);
  mbedtls_gcm_init(&gcm);
  loadSettings();
  loadChannels();
  msgCounter = (uint16_t)(esp_random() % 60000) + 1;

  WiFi.mode(WIFI_AP);
  WiFi.softAP(apSsid.c_str(), apPass.c_str(), 1, 0, 4);
  Serial.printf("WiFi: %s  ->  http://%s\n", apSsid.c_str(), WiFi.softAPIP().toString().c_str());

  LoRa.setPins(LORA_SS, LORA_RST, LORA_DIO0);
  if (!LoRa.begin(curFreqHz())) {
    Serial.println("LoRa init failed. Check wiring.");
    while (true) { digitalWrite(LED_PIN, !digitalRead(LED_PIN)); delay(120); }
  }
  applyRadio();                       // modem settings for the active mode (LoRa Link or Meshtastic)

  server.on("/", HTTP_GET, handleRoot);
  server.on("/manifest.webmanifest", HTTP_GET, handleManifest);
  server.on("/sw.js", HTTP_GET, handleSw);
  server.on("/icon-192.png", HTTP_GET, handleIcon192);
  server.on("/icon-512.png", HTTP_GET, handleIcon512);
  server.on("/gpx", HTTP_GET, handleGpx);
  server.on("/api/poll", HTTP_GET, handlePoll);
  server.on("/api/stats", HTTP_GET, G(handleStats));
  server.on("/api/send", HTTP_POST, handleSend);
  server.on("/api/quick", HTTP_POST, LG(handleQuick));
  server.on("/api/edit", HTTP_POST, LG(handleEdit));
  server.on("/api/del", HTTP_POST, LG(handleDel));
  server.on("/api/loc", HTTP_POST, LG(handleLoc));
  server.on("/api/sos", HTTP_POST, LG(handleSos));
  server.on("/api/ping", HTTP_POST, LG(handleApiPing));
  server.on("/api/cfg", HTTP_POST, G(handleCfg));
  server.on("/api/scan", HTTP_POST, G(handleScan));
  server.on("/api/clear", HTTP_POST, G(handleClear));
  server.on("/api/resetctr", HTTP_POST, G(handleResetCtr));
  server.on("/api/chan", HTTP_POST, G(handleChan));
  server.on("/api/restart", HTTP_POST, G(handleRestart));
  server.on("/api/wipe", HTTP_POST, G(handleWipe));
  featRoutes();
  fileInit();
  fileRoutes();
#if USE_BLE_BRIDGE
  bleInit();
  server.on("/api/ble", HTTP_GET, G(handleBle));
#else
  server.on("/api/ble", HTTP_GET, G([]() { jokx(",\"on\":0"); }));
#endif
  server.onNotFound(handleNotFound);
  { static const char* hdrs[] = {"X-Token"}; server.collectHeaders(hdrs, 1); }   // so the login token in the header is really read
  server.begin();
  if (captiveOn) dnsServer.start(53, "*", WiFi.softAPIP());

  hwApplyPins();                      // buzzer / LED pins from the saved settings
  nextBeaconAt = millis() + random(3000, 8000);
  if (meshMode) Serial.printf("Meshtastic mode: %s  %.3f MHz\n", mtEffName().c_str(), mtCurFreqHz() / 1e6);
}

// Internet gateway: forwards selected message types (received over LoRa) to a webhook / Telegram bot
// when the home Wi-Fi is up.
static const char* const GW_QUICK_TXT[16] = {"OK", "No", "Yes", "On my way", "Waiting", "Help!", "Thanks", "Call me",
                                             "SOS", "Safe", "Come", "Need water", "Need food", "Injured", "Lost", "Found"};

static String gwNameOf(uint32_t uid) {
  Contact* c = findContact(uid);
  return c ? String(c->name) : hex8(uid);
}

static uint32_t gwLastUid = 0;                    // last node that wrote to us = default receiver for Telegram replies

static void gwScan() {
  // look at the oldest message we have not seen yet (one per call)
  Msg* best = nullptr;
  for (int i = 0; i < MAX_MSGS; i++) {
    Msg& m = msgLog[i];
    if (m.seq > gwLastSeq && (!best || m.seq < best->seq)) best = &m;
  }
  if (!best) return;
  gwLastSeq = best->seq;
  Msg& m = *best;
  if (m.dir != 'I' || m.deleted || m.gone || m.ch || m.lf || m.lt) return;   // only received, non-private-channel, non-user-chat messages
  if (m.uid && m.uid != myUid && m.kind <= K_SOS && findContact(m.uid)) gwLastUid = m.uid;
  if (m.dst && !(gwMask & GW_DM)) return;                              // private message to us: only if allowed
  String who = gwNameOf(m.uid);
  String link = "";
  if (m.hasLoc) link = " https://maps.google.com/?q=" + String(m.lat / 1e6, 6) + "," + String(m.lon / 1e6, 6);
  String out;
  if (m.kind == K_TEXT && (gwMask & GW_TEXT)) {
    out = "[" + who + "] " + m.text;
  } else if (m.kind == K_QUICK && (gwMask & GW_QUICK)) {
    int q = m.text.toInt();
    out = "[" + who + "] " + String(q >= 0 && q < 16 ? GW_QUICK_TXT[q] : "quick reply");
  } else if (m.kind == K_LOC && (gwMask & GW_LOC)) {
    out = "Location from " + who + ":" + link;
  } else if (m.kind == K_SOS && (gwMask & GW_SOS)) {
    out = "SOS from " + who + (m.hasLoc ? ":" + link : String(" (no GPS)"));
  } else return;
  gwQueue(out);
}

// ---- body of a bot request: {"chat_id":..., "text":...} (numeric chat ids are sent as numbers) ----
static String gwBodyFor(const char* chat, const String& text) {
  if (chat && chat[0]) {
    bool num = true;
    for (int i = 0; chat[i]; i++) if (!(isdigit((unsigned char)chat[i]) || (i == 0 && chat[i] == '-'))) { num = false; break; }
    return String("{\"chat_id\":") + (num ? String(chat) : "\"" + String(chat) + "\"") + ",\"text\":" + jstr(text) + "}";
  }
  return "{\"text\":" + jstr(text) + "}";
}

static bool gwParseUrl(const String& url, bool& https, String& host, uint16_t& port, String& path) {
  String u = url;
  https = u.startsWith("https://");
  if (https) u = u.substring(8); else if (u.startsWith("http://")) u = u.substring(7); else return false;
  int sl = u.indexOf('/');
  String hp = sl >= 0 ? u.substring(0, sl) : u;
  path = sl >= 0 ? u.substring(sl) : String("/");
  int cl = hp.indexOf(':');
  if (cl >= 0) { port = (uint16_t)hp.substring(cl + 1).toInt(); host = hp.substring(0, cl); }
  else { port = https ? 443 : 80; host = hp; }
  return host.length() > 0 && port > 0;
}

// ---- small TCP / TLS connection that can go through a SOCKS5 or HTTP(S) CONNECT proxy ----
#ifndef MBEDTLS_ERR_NET_CONN_RESET
#define MBEDTLS_ERR_NET_CONN_RESET -0x0050
#endif

struct GwConn {
  WiFiClient tcp;
  bool tlsUp = false, tlsInit = false;
  mbedtls_ssl_context ssl;
  mbedtls_ssl_config conf;
  mbedtls_entropy_context ent;
  mbedtls_ctr_drbg_context drbg;

  ~GwConn() { close(); }

  static int bioSend(void* ctx, const unsigned char* b, size_t n) {
    WiFiClient* c = (WiFiClient*)ctx;
    if (!c->connected()) return MBEDTLS_ERR_NET_CONN_RESET;
    size_t w = c->write(b, n);
    return w > 0 ? (int)w : MBEDTLS_ERR_SSL_WANT_WRITE;
  }
  static int bioRecv(void* ctx, unsigned char* b, size_t n) {
    WiFiClient* c = (WiFiClient*)ctx;
    int a = c->available();
    if (a <= 0) return c->connected() ? MBEDTLS_ERR_SSL_WANT_READ : MBEDTLS_ERR_NET_CONN_RESET;
    int r = c->read(b, (size_t)a < n ? (size_t)a : n);
    return r > 0 ? r : MBEDTLS_ERR_SSL_WANT_READ;
  }

  void close() {
    if (tlsInit) {
      if (tlsUp) mbedtls_ssl_close_notify(&ssl);
      mbedtls_ssl_free(&ssl); mbedtls_ssl_config_free(&conf);
      mbedtls_ctr_drbg_free(&drbg); mbedtls_entropy_free(&ent);
      tlsInit = false; tlsUp = false;
    }
    tcp.stop();
  }

  bool tcpOpen(const char* host, uint16_t port, String& err) {
    if (!tcp.connect(host, port, 8000)) { err = String("cannot connect to ") + host + ":" + String((int)port); return false; }
    tcp.setNoDelay(true);
    return true;
  }

  bool startTls(const char* host, String& err) {
    mbedtls_ssl_init(&ssl); mbedtls_ssl_config_init(&conf); mbedtls_entropy_init(&ent); mbedtls_ctr_drbg_init(&drbg);
    tlsInit = true;
    int r = mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &ent, (const unsigned char*)"loralink", 8);
    if (r) { err = "TLS init error " + String(r); return false; }
    r = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (r) { err = "TLS config error " + String(r); return false; }
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);          // same as setInsecure()
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &drbg);
    r = mbedtls_ssl_setup(&ssl, &conf);
    if (r) { err = "TLS setup error " + String(r); return false; }
    mbedtls_ssl_set_hostname(&ssl, host);
    mbedtls_ssl_set_bio(&ssl, &tcp, bioSend, bioRecv, nullptr);
    uint32_t t0 = millis();
    while ((r = mbedtls_ssl_handshake(&ssl)) != 0) {
      if (r != MBEDTLS_ERR_SSL_WANT_READ && r != MBEDTLS_ERR_SSL_WANT_WRITE) { err = "TLS handshake failed (" + String(r) + ")"; return false; }
      if (millis() - t0 > 12000) { err = "TLS handshake timeout"; return false; }
      delay(5);
    }
    tlsUp = true;
    return true;
  }

  bool writeAll(const uint8_t* d, size_t n) {
    size_t off = 0; uint32_t t0 = millis();
    while (off < n) {
      int r;
      if (tlsUp) {
        r = mbedtls_ssl_write(&ssl, d + off, n - off);
        if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE) { if (millis() - t0 > 8000) return false; delay(2); continue; }
        if (r < 0) return false;
      } else {
        r = (int)tcp.write(d + off, n - off);
        if (r <= 0) { if (!tcp.connected() || millis() - t0 > 8000) return false; delay(2); continue; }
      }
      off += r; t0 = millis();
    }
    return true;
  }
  bool writeStr(const String& s) { return writeAll((const uint8_t*)s.c_str(), s.length()); }

  // > 0 bytes read, 0 = nothing yet, -1 = closed / error
  int readSome(uint8_t* b, size_t n) {
    if (tlsUp) {
      int r = mbedtls_ssl_read(&ssl, b, n);
      if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE) return 0;
      return r > 0 ? r : -1;
    }
    int a = tcp.available();
    if (a > 0) return tcp.read(b, (size_t)a < n ? (size_t)a : n);
    return tcp.connected() ? 0 : -1;
  }
  bool readN(uint8_t* b, size_t n, uint32_t timeoutMs) {
    size_t got = 0; uint32_t t0 = millis();
    while (got < n) {
      int r = readSome(b + got, n - got);
      if (r < 0) return false;
      if (r == 0) { if (millis() - t0 > timeoutMs) return false; delay(2); continue; }
      got += r;
    }
    return true;
  }
  bool readLine(String& line, uint32_t timeoutMs) {
    line = "";
    uint8_t ch; uint32_t t0 = millis();
    for (;;) {
      int r = readSome(&ch, 1);
      if (r < 0) return line.length() > 0;
      if (r == 0) { if (millis() - t0 > timeoutMs) return false; delay(2); continue; }
      t0 = millis();
      if (ch == '\n') return true;
      if (ch != '\r' && line.length() < 300) line += (char)ch;
    }
  }

  // SOCKS5 (RFC 1928) with optional user/password (RFC 1929); the proxy resolves the host name
  bool socks5(const GwProxy& p, const char* host, uint16_t port, String& err) {
    bool auth = p.user[0] != 0;
    uint8_t g[4] = {5, (uint8_t)(auth ? 2 : 1), 0, 2};
    if (!writeAll(g, auth ? 4 : 3)) { err = "SOCKS5: send failed"; return false; }
    uint8_t r[4];
    if (!readN(r, 2, 8000) || r[0] != 5) { err = "SOCKS5: no valid answer (is this a SOCKS5 proxy?)"; return false; }
    if (r[1] == 0xFF) { err = "SOCKS5: proxy refused the login methods"; return false; }
    if (r[1] == 2) {
      if (!auth) { err = "SOCKS5: proxy needs a username and password"; return false; }
      uint8_t m[70]; int k = 0;
      int ul = strlen(p.user), pl = strlen(p.pass);
      m[k++] = 1; m[k++] = (uint8_t)ul; memcpy(m + k, p.user, ul); k += ul;
      m[k++] = (uint8_t)pl; memcpy(m + k, p.pass, pl); k += pl;
      if (!writeAll(m, k) || !readN(r, 2, 8000) || r[1] != 0) { err = "SOCKS5: wrong username or password"; return false; }
    } else if (r[1] != 0) { err = "SOCKS5: unsupported login method"; return false; }
    int hl = strlen(host);
    if (hl > 200) { err = "SOCKS5: host name too long"; return false; }
    uint8_t q[220]; int k = 0;
    q[k++] = 5; q[k++] = 1; q[k++] = 0; q[k++] = 3; q[k++] = (uint8_t)hl;
    memcpy(q + k, host, hl); k += hl;
    q[k++] = (uint8_t)(port >> 8); q[k++] = (uint8_t)(port & 0xFF);
    if (!writeAll(q, k)) { err = "SOCKS5: send failed"; return false; }
    if (!readN(r, 4, 10000) || r[0] != 5) { err = "SOCKS5: no answer to the connect request"; return false; }
    if (r[1] != 0) {
      static const char* const E[9] = {"ok", "general failure", "not allowed by proxy rules", "network unreachable", "host unreachable", "connection refused", "TTL expired", "command not supported", "address type not supported"};
      err = String("SOCKS5: ") + (r[1] < 9 ? E[r[1]] : "error") + " (" + String((int)r[1]) + ")";
      return false;
    }
    int skip = (r[3] == 1) ? 6 : (r[3] == 4) ? 18 : 0;
    if (r[3] == 3) { uint8_t l; if (!readN(&l, 1, 5000)) return false; skip = l + 2; }
    uint8_t junk[20];
    while (skip > 0) { int k = skip > 20 ? 20 : skip; if (!readN(junk, k, 5000)) return false; skip -= k; }
    return true;
  }

  // HTTP / HTTPS proxy: CONNECT host:port, optional Basic authentication
  bool httpConnect(const GwProxy& p, const char* host, uint16_t port, String& err) {
    String hp = String(host) + ":" + String((int)port);
    String req = "CONNECT " + hp + " HTTP/1.1\r\nHost: " + hp + "\r\n";
    if (p.user[0]) {
      String cred = String(p.user) + ":" + String(p.pass);
      uint8_t out[120]; size_t ol = 0;
      mbedtls_base64_encode(out, sizeof(out), &ol, (const unsigned char*)cred.c_str(), cred.length());
      String b; for (size_t i = 0; i < ol; i++) b += (char)out[i];
      req += "Proxy-Authorization: Basic " + b + "\r\n";
    }
    req += "Proxy-Connection: keep-alive\r\n\r\n";
    if (!writeStr(req)) { err = "proxy: send failed"; return false; }
    String line;
    if (!readLine(line, 10000)) { err = "proxy: no answer (is this an HTTP/HTTPS proxy?)"; return false; }
    int sp = line.indexOf(' ');
    int code = sp > 0 ? line.substring(sp + 1, sp + 4).toInt() : 0;
    String h;
    for (int i = 0; i < 40; i++) { if (!readLine(h, 8000) || h.length() == 0) break; }      // skip the headers
    if (code == 407) { err = "proxy: wrong username or password (407)"; return false; }
    if (code < 200 || code > 299) { err = "proxy refused the connection (" + line + ")"; return false; }
    return true;
  }

  // direct (px == nullptr) or through a proxy; optionally wrap the stream in TLS
  bool connectVia(const GwProxy* px, const char* host, uint16_t port, bool tls, String& err) {
    if (!px) {
      if (!tcpOpen(host, port, err)) return false;
    } else {
      String e2;
      if (!tcpOpen(px->host, px->port, e2)) { err = "proxy: " + e2; return false; }
      if (px->type == 1) { if (!socks5(*px, host, port, err)) return false; }
      else { if (!httpConnect(*px, host, port, err)) return false; }
    }
    if (tls && !startTls(host, err)) return false;
    return true;
  }
};

// one HTTP POST on an open connection; returns the HTTP status or a negative number
static int gwHttpPost(GwConn& c, const String& host, const String& path, const String& body, String& err) {
  String req = "POST " + path + " HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: LoRaLink\r\nContent-Type: application/json\r\nContent-Length: " +
               String(body.length()) + "\r\nConnection: close\r\n\r\n";
  if (!c.writeStr(req) || !c.writeStr(body)) { err = "send failed"; return -1; }
  String line;
  if (!c.readLine(line, 12000)) { err = "no answer from the server"; return -2; }
  int sp = line.indexOf(' ');
  if (sp < 0) { err = "bad answer: " + line; return -3; }
  return line.substring(sp + 1, sp + 4).toInt();
}

// ---- Telegram / Bale / webhook, direct ----
static bool gwPostDirect(const String& url, const char* chat, const String& text, String& why) {
  HTTPClient http;
  WiFiClientSecure secureClient;
  WiFiClient plainClient;
  bool ok;
  if (url.startsWith("https")) {
    secureClient.setInsecure();
    ok = http.begin(secureClient, url);
  } else {
    ok = http.begin(plainClient, url);
  }
  if (!ok) { why = "bad URL"; return false; }
  http.setTimeout(10000);
  http.addHeader("Content-Type", "application/json");
  int code = http.POST(gwBodyFor(chat, text));
  http.end();
  if (code >= 200 && code < 300) return true;
  if (code > 0) { why = "HTTP " + String(code) + ". Check the bot token and Chat ID."; return false; }
  String host = url;
  int p = host.indexOf("://"); if (p >= 0) host = host.substring(p + 3);
  int sl = host.indexOf('/'); if (sl >= 0) host = host.substring(0, sl);
  int cl = host.indexOf(':'); if (cl >= 0) host = host.substring(0, cl);
  IPAddress ip;
  if (!WiFi.hostByName(host.c_str(), ip)) why = "DNS lookup of " + host + " failed: the home Wi-Fi has no internet, or the name is blocked.";
  else why = "cannot connect to " + host + " (" + ip.toString() + "): probably blocked by your internet provider - add a proxy, or use another service.";
  return false;
}

// ---- through a proxy ----
static bool gwPostProxy(const String& url, const char* chat, const String& text, const GwProxy& px, String& why) {
  bool https; String host, path; uint16_t port;
  if (!gwParseUrl(url, https, host, port, path)) { why = "bad URL"; return false; }
  GwConn* c = new GwConn();
  if (!c) { why = "out of memory"; return false; }
  String err;
  bool ok = c->connectVia(&px, host.c_str(), port, https, err);
  int code = -9;
  if (ok) code = gwHttpPost(*c, host, path, gwBodyFor(chat, text), err);
  delete c;
  if (code >= 200 && code < 300) return true;
  why = ok ? ("HTTP " + String(code) + (err.length() ? " " + err : String("")) + (code == 404 || code == 401 ? " (check the bot token)" : "")) : err;
  return false;
}

static bool gwSendTelegram(const String& text, String& why) {
  String url = String(gwUrl);
  int order[GW_PROXIES], n = 0;
  if (gwUseProxy) {
    if (gwPxGood >= 0 && gwPx[gwPxGood].type) order[n++] = gwPxGood;
    for (int i = 0; i < GW_PROXIES; i++) if (gwPx[i].type && i != gwPxGood) order[n++] = i;
  }
  String all;
  for (int k = 0; k < n; k++) {
    String w;
    if (gwPostProxy(url, gwChat, text, gwPx[order[k]], w)) { gwPxGood = order[k]; return true; }
    all += "proxy " + String(order[k] + 1) + " (" + gwPx[order[k]].host + "): " + w + "; ";
  }
  String w;
  if (gwPostDirect(url, gwChat, text, w)) return true;
  why = n ? (all + "direct: " + w) : w;
  return false;
}

// ---- e-mail (SMTP): port 465 = SSL, 587 = STARTTLS, otherwise plain ----
static String gwB64(const uint8_t* d, size_t n) {
  size_t cap = ((n + 2) / 3) * 4 + 8, ol = 0;
  uint8_t* o = (uint8_t*)malloc(cap);
  if (!o) return "";
  mbedtls_base64_encode(o, cap, &ol, d, n);
  String s; s.reserve(ol);
  for (size_t i = 0; i < ol; i++) s += (char)o[i];
  free(o);
  return s;
}
static String gwB64s(const String& s) { return gwB64((const uint8_t*)s.c_str(), s.length()); }

static bool smtpCmd(GwConn& c, const String& cmd, int expect, String& err) {
  if (cmd.length() && !c.writeStr(cmd + "\r\n")) { err = "send failed"; return false; }
  String line; int code = 0;
  for (int i = 0; i < 40; i++) {
    if (!c.readLine(line, 12000)) { err = "no answer from the mail server"; return false; }
    if (line.length() >= 3) code = line.substring(0, 3).toInt();
    if (line.length() < 4 || line[3] != '-') break;           // last line of the reply
  }
  if (code != expect) { err = line; return false; }
  return true;
}

static bool gwSendMail(const String& text, String& why) {
  GwConn* c = new GwConn();
  if (!c) { why = "out of memory"; return false; }
  String err;
  bool ok = false;
  do {
    if (!c->connectVia(nullptr, gwMailHost, gwMailPort, gwMailPort == 465, err)) break;
    if (!smtpCmd(*c, "", 220, err)) break;
    if (!smtpCmd(*c, "EHLO loralink", 250, err)) break;
    if (gwMailPort == 587) {
      if (!smtpCmd(*c, "STARTTLS", 220, err)) break;
      if (!c->startTls(gwMailHost, err)) break;
      if (!smtpCmd(*c, "EHLO loralink", 250, err)) break;
    }
    if (gwMailUser[0]) {
      if (!smtpCmd(*c, "AUTH LOGIN", 334, err)) break;
      if (!smtpCmd(*c, gwB64s(String(gwMailUser)), 334, err)) break;
      if (!smtpCmd(*c, gwB64s(String(gwMailPass)), 235, err)) { err = "login failed: " + err; break; }
    }
    String from = gwMailFrom[0] ? String(gwMailFrom) : String(gwMailUser);
    if (!smtpCmd(*c, "MAIL FROM:<" + from + ">", 250, err)) break;
    String to = String(gwMailTo), toHdr;
    int st = 0, rcpt = 0; bool bad = false;
    for (int k = 0; k <= (int)to.length() && !bad; k++) {
      if (k == (int)to.length() || to[k] == ',' || to[k] == ';') {
        String a = to.substring(st, k); a.trim(); st = k + 1;
        if (!a.length()) continue;
        if (!smtpCmd(*c, "RCPT TO:<" + a + ">", 250, err)) { bad = true; break; }
        toHdr += (rcpt++ ? ", " : "") + String("<") + a + ">";
      }
    }
    if (bad || !rcpt) { if (!rcpt && !bad) err = "no recipient"; break; }
    if (!smtpCmd(*c, "DATA", 354, err)) break;
    String subj = "LoRa: " + clipUtf8(text, 40);
    String hdr = "From: LoRa Messenger <" + from + ">\r\nTo: " + toHdr + "\r\nSubject: =?UTF-8?B?" + gwB64s(subj) +
                 "?=\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n";
    String b = gwB64s(text + "\r\n"), body;
    for (int i = 0; i < (int)b.length(); i += 76) body += b.substring(i, i + 76) + "\r\n";
    if (!c->writeStr(hdr) || !c->writeStr(body)) { err = "send failed"; break; }
    if (!smtpCmd(*c, ".", 250, err)) break;
    String ign; smtpCmd(*c, "QUIT", 221, ign);
    ok = true;
  } while (0);
  delete c;
  if (!ok) why = err;
  return ok;
}

// ---------------------------------------------------------------------------------------------
// Telegram -> LoRa. The device polls the bot (getUpdates) through the same proxies as sending.
//   * a message written in the bot chat goes (as a private message) to the last node that wrote to us
//   * a Telegram "reply" to one of the forwarded messages ("[name] ...", "SOS from name ...") goes to that node
// Only the chat configured as Chat ID is accepted. Messages that arrived while the gateway was off
// (or while the device was off) are ignored.
// ---------------------------------------------------------------------------------------------
static long     gwTgOff = 0;
static bool     gwTgInit = false;
static uint32_t gwTgPollAt = 0;

static String gwTgUrl(const char* method) {
  String u = String(gwUrl);
  int p = u.lastIndexOf("/sendMessage");
  if (p < 0) return "";
  return u.substring(0, p) + "/" + method;
}

static bool gwCallDirect(const String& url, const String& body, String& resp, String& why) {
  HTTPClient http;
  WiFiClientSecure secureClient;
  WiFiClient plainClient;
  bool ok;
  if (url.startsWith("https")) { secureClient.setInsecure(); ok = http.begin(secureClient, url); }
  else ok = http.begin(plainClient, url);
  if (!ok) { why = "bad URL"; return false; }
  http.setConnectTimeout(4000);                     // a blocked site must not freeze the radio and the web page
  http.setTimeout(6000);
  http.addHeader("Content-Type", "application/json");
  int code = http.POST(body);
  if (code >= 200 && code < 300) { resp = http.getString(); http.end(); return true; }
  http.end();
  why = code > 0 ? "HTTP " + String(code) + (code == 409 ? " (does the bot have a webhook set?)" : "") : String("cannot connect (blocked? add a proxy)");
  return false;
}

static bool gwCallProxy(const String& url, const String& body, const GwProxy& px, String& resp, String& why) {
  bool https; String host, path; uint16_t port;
  if (!gwParseUrl(url, https, host, port, path)) { why = "bad URL"; return false; }
  GwConn* c = new GwConn();
  if (!c) { why = "out of memory"; return false; }
  String err;
  int code = -9;
  bool ok = c->connectVia(&px, host.c_str(), port, https, err);
  if (ok) {
    String req = "POST " + path + " HTTP/1.0\r\nHost: " + host + "\r\nUser-Agent: LoRaLink\r\nContent-Type: application/json\r\nContent-Length: " +
                 String(body.length()) + "\r\n\r\n";                  // HTTP/1.0: the server answers with Content-Length, no chunking
    String line;
    if (!c->writeStr(req) || !c->writeStr(body)) { err = "send failed"; ok = false; }
    else if (!c->readLine(line, 12000)) { err = "no answer from the server"; ok = false; }
    else {
      int sp = line.indexOf(' ');
      code = sp >= 0 ? (int)line.substring(sp + 1, sp + 4).toInt() : -3;
      for (int i = 0; i < 40; i++) { if (!c->readLine(line, 8000) || !line.length()) break; }   // skip the headers
      resp = "";
      uint8_t buf[256]; uint32_t t0 = millis();
      while (resp.length() < 16000 && millis() - t0 < 12000) {
        int r = c->readSome(buf, sizeof(buf));
        if (r < 0) break;
        if (r == 0) { delay(2); continue; }
        for (int i = 0; i < r; i++) resp += (char)buf[i];
      }
    }
  }
  delete c;
  if (ok && code >= 200 && code < 300) return true;
  why = ok ? "HTTP " + String(code) + (code == 409 ? " (does the bot have a webhook set?)" : "") : err;
  return false;
}

// one attempt per call; every failure moves on to the next route (proxy 1, proxy 2, ..., direct)
static bool gwTgCall(const char* method, const String& body, String& resp, String& why) {
  String url = gwTgUrl(method);
  if (!url.length()) { why = "the URL must end with /sendMessage"; return false; }
  int order[GW_PROXIES + 1], n = 0;
  if (gwUseProxy) {
    if (gwPxGood >= 0 && gwPx[gwPxGood].type) order[n++] = gwPxGood;
    for (int i = 0; i < GW_PROXIES; i++) if (gwPx[i].type && i != gwPxGood) order[n++] = i;
  }
  order[n++] = -1;                                                      // direct
  static uint8_t route = 0;
  if (route >= n) route = 0;
  int r = order[route];
  String w;
  bool ok = (r >= 0) ? gwCallProxy(url, body, gwPx[r], resp, w) : gwCallDirect(url, body, resp, w);
  if (ok && resp.indexOf("\"ok\":true") < 0) { ok = false; w = "bad answer"; }
  if (ok) { if (r >= 0) { gwPxGood = (int8_t)r; route = 0; } return true; }
  why = (r >= 0 ? "proxy " + String(r + 1) + ": " : String("direct: ")) + w;
  route = (uint8_t)((route + 1) % n);
  return false;
}

static int gwFindObjEnd(const String& s, int open) {                    // s[open] == '{'; returns the matching '}' or -1
  int depth = 0; bool in = false;
  for (int i = open; i < (int)s.length(); i++) {
    char ch = s[i];
    if (in) { if (ch == '\\') i++; else if (ch == '"') in = false; continue; }
    if (ch == '"') in = true;
    else if (ch == '{') depth++;
    else if (ch == '}') { if (--depth == 0) return i; }
  }
  return -1;
}

static void gwUtf8Add(String& o, uint32_t cp) {
  if (cp < 0x80) o += (char)cp;
  else if (cp < 0x800) { o += (char)(0xC0 | (cp >> 6)); o += (char)(0x80 | (cp & 0x3F)); }
  else if (cp < 0x10000) { o += (char)(0xE0 | (cp >> 12)); o += (char)(0x80 | ((cp >> 6) & 0x3F)); o += (char)(0x80 | (cp & 0x3F)); }
  else { o += (char)(0xF0 | (cp >> 18)); o += (char)(0x80 | ((cp >> 12) & 0x3F)); o += (char)(0x80 | ((cp >> 6) & 0x3F)); o += (char)(0x80 | (cp & 0x3F)); }
}

// first  "key":"value"  in s (JSON-unescaped, \uXXXX incl. surrogate pairs -> UTF-8); "" when missing
static String gwJsonStr(const String& s, const char* key) {
  String pat = String("\"") + key + "\":\"";
  int p = s.indexOf(pat);
  if (p < 0) return "";
  String o;
  int L = (int)s.length();
  for (int i = p + (int)pat.length(); i < L; i++) {
    char ch = s[i];
    if (ch == '"') break;
    if (ch != '\\') { o += ch; continue; }
    if (++i >= L) break;
    char e = s[i];
    if (e == 'n') o += '\n';
    else if (e == 't') o += ' ';
    else if (e == 'r') { }
    else if (e == 'u' && i + 4 < L) {
      uint32_t cp = strtoul(s.substring(i + 1, i + 5).c_str(), nullptr, 16);
      i += 4;
      if (cp >= 0xD800 && cp < 0xDC00 && i + 6 < L && s[i + 1] == '\\' && s[i + 2] == 'u') {
        uint32_t lo = strtoul(s.substring(i + 3, i + 7).c_str(), nullptr, 16);
        if (lo >= 0xDC00 && lo < 0xE000) { cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00); i += 6; }
      }
      gwUtf8Add(o, cp);
    } else o += e;                                                      // \"  \\  \/
  }
  return o;
}

// name of the node a forwarded message came from: "[name] text", "SOS from name (no GPS)", "Location from name: link"
static String gwNameFromBotText(const String& t) {
  if (t.startsWith("[")) { int e = t.indexOf(']'); return e > 1 ? t.substring(1, e) : String(""); }
  const char* pre[2] = {"SOS from ", "Location from "};
  for (int k = 0; k < 2; k++) {
    if (!t.startsWith(pre[k])) continue;
    String r = t.substring(strlen(pre[k]));
    int e = r.indexOf(" (no GPS)");
    if (e < 0) e = r.indexOf(": http");
    if (e < 0) e = r.indexOf(':');
    return e >= 0 ? r.substring(0, e) : r;
  }
  return "";
}

static Contact* gwFindByName(const String& n) {
  for (int i = 1; i < MAX_CONTACTS; i++) if (contacts[i].used && n.equalsIgnoreCase(String(contacts[i].name))) return &contacts[i];
  return nullptr;
}

// u = the JSON of one update (everything after "update_id":)
static void gwTgHandle(const String& u) {
  int mp = u.indexOf("\"message\":{");
  if (mp < 0) return;
  int mo = mp + 10;
  int me = gwFindObjEnd(u, mo);
  String msg = u.substring(mo, me >= 0 ? me + 1 : (int)u.length());
  String rep = "";
  int rp = msg.indexOf("\"reply_to_message\":{");
  if (rp >= 0) {                                                        // cut the quoted message out so its fields do not mix with ours
    int ro = rp + (int)String("\"reply_to_message\":").length();
    int re = gwFindObjEnd(msg, ro);
    rep = msg.substring(ro, re >= 0 ? re + 1 : (int)msg.length());
    msg = msg.substring(0, ro) + (re >= 0 ? msg.substring(re + 1) : String(""));
  }
  int cp = msg.indexOf("\"chat\":{\"id\":");
  if (cp < 0) return;
  cp += (int)String("\"chat\":{\"id\":").length();
  String cid;
  while (cp < (int)msg.length() && (isdigit((unsigned char)msg[cp]) || msg[cp] == '-')) cid += msg[cp++];
  if (cid != String(gwChat)) return;                                    // only our chat
  if (msg.indexOf("\"is_bot\":true") >= 0) return;
  String text = gwJsonStr(msg, "text");
  text.trim();
  if (!text.length() || text.startsWith("/start")) return;

  Contact* tc = nullptr;
  if (rep.length()) {
    String nm = gwNameFromBotText(gwJsonStr(rep, "text"));
    tc = nm.length() ? gwFindByName(nm) : nullptr;
    if (!tc) { gwQueue("Not sent: cannot tell which node that message came from. Reply to a message that starts with [name], or write without replying to answer the last sender.", GWD_TG); return; }
  } else {
    tc = gwLastUid ? findContact(gwLastUid) : nullptr;
    if (!tc || tc == &contacts[0]) { gwQueue("Not sent: nobody has written to this device yet. Reply to a message to choose the receiver.", GWD_TG); return; }
  }
  String name = String(tc->name);
  String err; uint16_t id = 0;
  int rc = sendTextCore(sanitize(text), 0, tc->uid, false, 0, 0, 0, err, id);
  if (rc) gwQueue("Not sent to " + name + ": " + err, GWD_TG);
  else gwQueue("Sent to " + name, GWD_TG);
}

// ---------------------------------------------------------------------------------------------
// All internet work (Telegram / Bale / e-mail, sending and receiving) runs in ONE background task.
// The radio / web loop never waits for the network, so a blocked site can no longer freeze the device,
// hold the buzzer on, delay LoRa messages or make them arrive twice. A failed internet delivery is simply
// dropped silently (no retry, no alert, no beep).
// ---------------------------------------------------------------------------------------------
static volatile uint8_t gwJobState = 0;       // 0 idle, 1 queued, 2 running, 3 done
static uint8_t    gwJobKind = 0;              // 1 Telegram send, 2 Bale send, 3 e-mail, 4 Telegram getUpdates
static String     gwJobText, gwJobResp, gwJobWhy;
static bool       gwJobOk = false;
static TaskHandle_t gwTask = nullptr;

static void gwWorker(void*) {
  for (;;) {
    if (gwJobState == 1) {
      gwJobState = 2;
      String why, resp;
      bool ok = false;
      if (gwJobKind == 1)      ok = gwSendTelegram(gwJobText, why);
      else if (gwJobKind == 2) ok = gwPostDirect(String(gwBaleUrl), gwBaleChat, gwJobText, why);
      else if (gwJobKind == 3) ok = gwSendMail(gwJobText, why);
      else if (gwJobKind == 4) ok = gwTgCall("getUpdates", gwJobText, resp, why);
      gwJobOk = ok; gwJobWhy = why; gwJobResp = resp;
      gwJobState = 3;
    }
    vTaskDelay(pdMS_TO_TICKS(40));
  }
}

static bool gwJobStart(uint8_t kind, const String& text) {
  if (gwJobState != 0) return false;
  if (!gwTask) xTaskCreatePinnedToCore(gwWorker, "gw", 20480, nullptr, 1, &gwTask, 0);
  if (!gwTask) return false;
  gwJobKind = kind; gwJobText = text; gwJobResp = ""; gwJobWhy = "";
  gwJobState = 1;
  return true;
}

static void gwTgPoll() {
  static uint8_t fails = 0;
  uint32_t now = millis();
  if (gwJobState == 3 && gwJobKind == 4) {                              // a getUpdates call finished
    bool ok = gwJobOk;
    String resp = gwJobResp;
    gwJobState = 0;
    if (!ok) {
      if (fails < 250) fails++;
      gwTgPollAt = now + (fails < 3 ? 15000UL : fails < 6 ? 120000UL : 600000UL);   // quiet, and ever less often; no alert
      return;
    }
    fails = 0;
    int p = resp.indexOf("\"update_id\":");
    if (p < 0) { gwTgInit = true; return; }                             // nothing new
    p += 12;
    long id = 0;
    while (p < (int)resp.length() && isdigit((unsigned char)resp[p])) id = id * 10 + (resp[p++] - '0');
    gwTgOff = id + 1;
    bool first = !gwTgInit;
    gwTgInit = true;
    if (first) return;                                                  // the first call only skips what is already waiting
    gwTgHandle(resp.substring(p));
    gwTgPollAt = now + 1500;                                            // more may be waiting
    return;
  }
  bool numeric = gwChat[0] != 0;
  for (int i = 0; gwChat[i]; i++) if (!(isdigit((unsigned char)gwChat[i]) || (i == 0 && gwChat[i] == '-'))) numeric = false;
  if (!(gwActive() & GWD_TG) || !staConnected || !numeric || !gwTgUrl("getUpdates").length()) { gwTgInit = false; return; }
  if (gwQn || gwJobState != 0) return;                                  // sending to the internet has priority
  if ((int32_t)(now - gwTgPollAt) < 0) return;
  gwTgPollAt = now + 8000;
  String body = String("{\"offset\":") + (gwTgInit ? String(gwTgOff) : String("-1")) + ",\"limit\":1,\"timeout\":0,\"allowed_updates\":[\"message\"]}";
  gwJobStart(4, body);
}

void gwService() {
  static uint32_t scanAt = 0;
  uint32_t now = millis();
  if ((int32_t)(now - scanAt) >= 0) {
    scanAt = now + 500;
    if (gwActive()) gwScan();
    else for (int i = 0; i < MAX_MSGS; i++) if (msgLog[i].seq > gwLastSeq) gwLastSeq = msgLog[i].seq;   // nothing is forwarded while off
  }
  if (gwJobState == 3 && gwJobKind != 4) gwJobState = 0;                // a send finished: success or failure, nothing to report
  gwTgPoll();
  if (gwJobState != 0 || !gwQn || !staConnected) return;
  if ((int32_t)(now - gwLastPost) < 3000) return;                      // at most one post every 3 s
  gwLastPost = now;
  String t = String(gwQ[0]);
  uint8_t d = gwQd[0];
  uint8_t bit = (d & GWD_TG) ? GWD_TG : (d & GWD_BALE) ? GWD_BALE : (d & GWD_MAIL) ? GWD_MAIL : 0;
  gwQd[0] = d & ~bit;
  if (!gwQd[0]) {                                                      // served everywhere: remove it from the queue
    for (int i = 1; i < GW_Q; i++) { memcpy(gwQ[i - 1], gwQ[i], 160); gwQd[i - 1] = gwQd[i]; }
    gwQn--;
  }
  if (!bit) return;
  gwJobStart(bit == GWD_TG ? 1 : bit == GWD_BALE ? 2 : 3, t);
}

void loop() {
  if (captiveOn) dnsServer.processNextRequest();
  server.handleClient();
#if USE_BLE_BRIDGE
  bleService();
#endif
  pollRadio();
  serviceOutgoing();
  serviceDeferred();
  serviceForward();
  mtService();
  featService();
  bzService();
  morseService();
  remoteMorseTick();          // status reports + timeout for remote sessions
  gwService();
  serviceReads();
  servicePing();
  serviceAssemblies();
  serviceButton();

  if ((int32_t)(millis() - nextBeaconAt) >= 0) sendBeacon();

  if (restartAt && (int32_t)(millis() - restartAt) >= 0) ESP.restart();
  if (wipeAt && (int32_t)(millis() - wipeAt) >= 0) {
    prefs.clear();
    delay(100);
    ESP.restart();
  }

  // LED: short pulse on traffic, slow blink while there are unread messages,
  // fast blink while the wipe button is held
  bool on = ((int32_t)(ledUntil - millis()) > 0) || (unread > 0 && ((millis() / 400) & 1)) ||
            (ledWarn && ((millis() / 100) & 1)) ||
            (((int32_t)(ledFlashUntil - millis()) > 0) && ((millis() / 90) & 1));
  // Morse owns the LED while it plays (local mj or remote rm)
  if (morseBusy) {
    uint8_t o = mzIsRemote ? rm.out : mj.out;
    if (o & 1) on = morseLed;
  }
  if (ledPinCur >= 0) digitalWrite(ledPinCur, (ledEnabled && on) ? HIGH : LOW);

  delay(1);
}
