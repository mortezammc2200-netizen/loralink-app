// lm_features.h - extra safety / diagnostics features for LoRa Messenger.
// Included by lora_messenger.ino after meshtastic.h. HTTP handlers live in lm_features_api.h.
//
//   * alerts ring (banner + vibration in the web UI)
//   * SOS that repeats (with back-off) until acknowledged or cancelled, optional hardware SOS button
//   * "silent node" watch list + periodic check-in message
//   * geofence (enter / leave alerts)
//   * PIN-protected (AES-256-GCM) emergency messages
//   * link advisor (recommends the fastest preset the weakest link can still carry)
//   * link test (packet-loss test between nodes, native + Meshtastic range-test packets)
//   * operator profiles (several people sharing one device)
#pragma once
#include <mbedtls/sha256.h>
#include <mbedtls/base64.h>
#include <math.h>

// defined later in the sketch
bool sosSendNow(bool has, int32_t la, int32_t lo, uint16_t acc, uint32_t dst, uint8_t ch, String& err, uint16_t& id);
int  sendTextCore(const String& t, uint8_t tch, uint32_t tdst, bool hr, uint32_t ru, uint16_t ri,
                  uint8_t op, String& err, uint16_t& id);
int  sendRemoteMorse(uint32_t toUid, const String& text, uint8_t out, uint8_t n,
                     uint16_t gapSec, uint8_t wpm, bool untilConfirm, String& err, uint16_t& idOut);

// ------------------------------------------------------------------ alerts ----
#define MAX_ALERTS 5
struct Alert { uint32_t id; uint8_t kind; char text[112]; };      // kind: 1 info, 2 warning, 3 danger
Alert    alerts[MAX_ALERTS];
uint32_t alertSeq = 0;

void raiseAlertTo(uint8_t kind, const String& text, uint32_t dst) {   // dst: chat that gets the system line (0 = public)
  sysLineTo(text, dst);
  if (kind >= 2) hwNotify(1);                          // buzzer + LED for warnings / dangers
  int slot = 0;
  for (int i = 0; i < MAX_ALERTS; i++) {
    if (!alerts[i].id) { slot = i; break; }
    if (alerts[i].id < alerts[slot].id) slot = i;
  }
  alerts[slot].id = ++alertSeq;
  alerts[slot].kind = kind;
  String t = clipUtf8(text, sizeof(alerts[slot].text) - 1);
  strncpy(alerts[slot].text, t.c_str(), sizeof(alerts[slot].text) - 1);
  alerts[slot].text[sizeof(alerts[slot].text) - 1] = 0;
}
void raiseAlert(uint8_t kind, const String& text) { raiseAlertTo(kind, text, 0); }

void clearAlert(uint32_t id) {
  for (int i = 0; i < MAX_ALERTS; i++) if (alerts[i].id == id) alerts[i].id = 0;
}

String alertsJson() {
  String o = "[";
  bool f = true;
  for (int i = 0; i < MAX_ALERTS; i++) {
    if (!alerts[i].id) continue;
    if (!f) o += ",";
    f = false;
    o += "{\"i\":" + String(alerts[i].id) + ",\"k\":" + String(alerts[i].kind) + ",\"t\":" + jstr(String(alerts[i].text)) + "}";
  }
  return o + "]";
}

// ----------------------------------------------------------- Quiet hours (15) ----
bool     quietHoursEnabled = false;
uint8_t  quietStartH = 22, quietStartM = 0;
uint8_t  quietEndH   = 7,  quietEndM   = 0;
bool     quietAllowMorse = false;   // if true, remote/local Morse still plays in quiet hours
bool     quietAllowSos   = true;    // SOS always allowed by default

bool isQuietNow() {
  if (!quietHoursEnabled) return false;
  time_t now = time(nullptr);
  if (now < 100000) return false;   // clock not set → not quiet
  struct tm* t = localtime(&now);
  int cur = t->tm_hour * 60 + t->tm_min;
  int s = quietStartH * 60 + quietStartM;
  int e = quietEndH * 60 + quietEndM;
  if (s <= e) return (cur >= s && cur < e);
  return (cur >= s || cur < e);     // crosses midnight
}

// gated notify: respects quiet hours (SOS always allowed if quietAllowSos)
void quietNotify(uint8_t what) {    // 0=msg, 1=alert, 2=sos
  if (isQuietNow()) {
    if (what == 2 && quietAllowSos) { hwNotify(2); return; }
    if (what < 2) return;           // suppress normal/alert in quiet hours
  }
  hwNotify(what);
}

// ----------------------------------------------------------- Find device (10) ----
// Remote node plays a loud repeating pattern so you can locate it
struct FindDev {
  bool active;
  uint32_t until;
  uint32_t nextBeep;
  uint8_t  count;
} findDev;

void findDevStart(uint16_t sec) {
  if (sec < 5) sec = 5;
  if (sec > 600) sec = 600;
  if (isQuietNow() && !quietAllowMorse) return;   // respect quiet hours
  if (morseBusy) morseAbort();
  findDev.active = true;
  findDev.until = millis() + (uint32_t)sec * 1000UL;
  findDev.nextBeep = millis();
  findDev.count = 0;
  raiseAlert(2, "Find-me: sounding for " + String(sec) + " s");
}

void findDevService() {
  if (!findDev.active) return;
  uint32_t now = millis();
  if ((int32_t)(now - findDev.until) >= 0) {
    findDev.active = false;
    bzStop();
    return;
  }
  if ((int32_t)(now - findDev.nextBeep) >= 0) {
    hwNotify(1);   // three beeps
    findDev.nextBeep = now + 2000;
    findDev.count++;
    ledFlashUntil = now + 1500;
  }
}

// ----------------------------------------------------------- Rangefinder (11) ----
// Beep rate increases as RSSI of the watched node gets stronger
struct RangeFinder {
  bool active;
  uint32_t targetUid;
  int lastRssi;
  uint32_t nextPingAt;
  uint32_t nextBeepAt;
  uint16_t pingEveryMs;   // how often we ping
} rf;

void rfStart(uint32_t uid) {
  memset(&rf, 0, sizeof(rf));
  rf.active = true;
  rf.targetUid = uid;
  rf.lastRssi = -200;
  rf.nextPingAt = millis();
  rf.pingEveryMs = 3000;
  raiseAlertTo(1, "Rangefinder ON – walk toward stronger beeps", uid);
}

void rfStop() {
  if (!rf.active) return;
  rf.active = false;
  bzStop();
  raiseAlertTo(1, "Rangefinder off", rf.targetUid);
}

// call when we hear a packet from the target (rssi updated)
void rfHeard(uint32_t uid, int rssi) {
  if (!rf.active || uid != rf.targetUid) return;
  rf.lastRssi = rssi;
  // map RSSI (-120..-40) to beep interval (1500..200 ms)
  int r = rssi;
  if (r < -120) r = -120;
  if (r > -40) r = -40;
  // stronger = higher rssi = shorter interval
  int span = (-40) - (-120);          // 80
  int pos = r - (-120);               // 0..80
  int interval = 1500 - (pos * 1300) / span;  // 1500..200
  if (interval < 200) interval = 200;
  rf.nextBeepAt = millis();           // beep soon
  // store interval in nextBeepAt delta via a static? use pingEveryMs as beep interval
  rf.pingEveryMs = (uint16_t)interval;
}

void rfService() {
  if (!rf.active) return;
  uint32_t now = millis();
  // periodic quiet ping to the target so we keep getting RSSI
  if ((int32_t)(now - rf.nextPingAt) >= 0) {
    startPingTo(rf.targetUid, true);   // quiet ping
    rf.nextPingAt = now + 4000;
  }
  // beep according to last RSSI
  if (rf.lastRssi > -190 && (int32_t)(now - rf.nextBeepAt) >= 0) {
    if (!isQuietNow() || quietAllowMorse) {
      // short single beep – rate encodes distance
      if (!morseBusy && !findDev.active) {
        const BzStep one[] = {{80, 2800}};
        // inline mini play
        if (bzPin >= 0 && bzOn) {
          bzStop();
          // use hwNotify style short
          hwNotify(0);
        }
        ledUntil = now + 60;
      }
    }
    rf.nextBeepAt = now + rf.pingEveryMs;
  }
}

// ----------------------------------------------------------- Companion distance (12) ----
#define MAX_COMP 4
struct Companion {
  bool used;
  uint32_t uid;
  uint16_t maxM;          // alert if farther than this (metres)
  bool alerted;
  char name[24];
} comps[MAX_COMP];

static float distMeters(int32_t la1, int32_t lo1, int32_t la2, int32_t lo2) {
  // la/lo are microdegrees
  double lat1 = la1 / 1e6 * 0.017453292519943295;
  double lat2 = la2 / 1e6 * 0.017453292519943295;
  double dLat = lat2 - lat1;
  double dLon = (lo2 - lo1) / 1e6 * 0.017453292519943295;
  double a = sin(dLat/2)*sin(dLat/2) + cos(lat1)*cos(lat2)*sin(dLon/2)*sin(dLon/2);
  double c = 2 * atan2(sqrt(a), sqrt(1-a));
  return (float)(6371000.0 * c);
}

void compService() {
  // need our own position
  if (!contacts[0].hasLoc) return;
  for (int i = 0; i < MAX_COMP; i++) {
    if (!comps[i].used || !comps[i].maxM) continue;
    Contact* c = findContact(comps[i].uid);
    if (!c || !c->hasLoc) continue;
    float d = distMeters(contacts[0].lat, contacts[0].lon, c->lat, c->lon);
    if (d > comps[i].maxM) {
      if (!comps[i].alerted) {
        comps[i].alerted = true;
        String nm = comps[i].name[0] ? String(comps[i].name) : String(comps[i].uid, HEX);
        raiseAlertTo(2, nm + " is " + String((int)d) + " m away (limit " + String(comps[i].maxM) + " m)", comps[i].uid);
        quietNotify(1);
      }
    } else {
      if (comps[i].alerted && d < comps[i].maxM * 0.85f) {
        comps[i].alerted = false;   // hysteresis
        String nm = comps[i].name[0] ? String(comps[i].name) : String(comps[i].uid, HEX);
        raiseAlertTo(1, nm + " is back within range (" + String((int)d) + " m)", comps[i].uid);
      }
    }
  }
}

void compSave() {
  uint8_t buf[MAX_COMP * 32];
  memset(buf, 0, sizeof(buf));
  for (int i = 0; i < MAX_COMP; i++) {
    putU32(buf + i*32, comps[i].uid);
    putU16(buf + i*32 + 4, comps[i].maxM);
    buf[i*32 + 6] = comps[i].used ? 1 : 0;
    memcpy(buf + i*32 + 7, comps[i].name, 24);
  }
  prefs.putBytes("comps", buf, sizeof(buf));
}

void compLoad() {
  memset(comps, 0, sizeof(comps));
  uint8_t buf[MAX_COMP * 32];
  size_t l = prefs.getBytesLength("comps");
  if (l == sizeof(buf) && prefs.getBytes("comps", buf, l) == l) {
    for (int i = 0; i < MAX_COMP; i++) {
      comps[i].uid = getU32(buf + i*32);
      comps[i].maxM = getU16(buf + i*32 + 4);
      comps[i].used = buf[i*32 + 6] != 0 && comps[i].uid != 0;
      memcpy(comps[i].name, buf + i*32 + 7, 24);
      comps[i].name[23] = 0;
    }
  }
}

// ----------------------------------------------------------- Sunset warning (14) ----
bool     sunsetWarnOn = false;
uint16_t sunsetWarnMin = 60;     // minutes before sunset
bool     sunsetWarnedToday = false;
uint8_t  sunsetWarnDay = 255;    // day-of-year we already warned

// sun times are computed on the phone; the phone can POST /api/sunsetwarn with the next sunset epoch
uint32_t nextSunsetEpoch = 0;    // unix time of next sunset (0 = unknown)

void sunsetService() {
  if (!sunsetWarnOn || !nextSunsetEpoch) return;
  time_t now = time(nullptr);
  if (now < 100000) return;
  struct tm* t = localtime(&now);
  uint8_t doy = t->tm_yday;
  if (doy != sunsetWarnDay) { sunsetWarnedToday = false; sunsetWarnDay = doy; }
  if (sunsetWarnedToday) return;
  int32_t left = (int32_t)(nextSunsetEpoch - (uint32_t)now);
  if (left > 0 && left <= (int32_t)sunsetWarnMin * 60) {
    sunsetWarnedToday = true;
    int m = left / 60;
    raiseAlert(2, "Sunset in " + String(m) + " min");
    quietNotify(1);
  }
}

// ----------------------------------------------------------- Daily repeat message (20) ----
// Device-side: sends a fixed text every day at HH:MM (needs clock set via NTP or phone)
struct DailyMsg {
  bool active;
  uint8_t hour, minute;
  char text[80];
  uint32_t dst;          // 0 = public
  uint8_t ch;
  uint8_t lastDay;       // day-of-year already sent
} dailyMsg;

void dailyMsgService() {
  if (!dailyMsg.active || !dailyMsg.text[0]) return;
  time_t now = time(nullptr);
  if (now < 100000) return;
  struct tm* t = localtime(&now);
  if (t->tm_hour != dailyMsg.hour || t->tm_min != dailyMsg.minute) return;
  if ((uint8_t)t->tm_yday == dailyMsg.lastDay) return;
  // only fire in the first ~90 seconds of that minute
  if (t->tm_sec > 90) return;
  dailyMsg.lastDay = (uint8_t)t->tm_yday;
  String err;
  uint16_t id = 0;
  sendTextCore(String(dailyMsg.text), dailyMsg.ch, dailyMsg.dst, false, 0, 0, 0, err, id);
  raiseAlert(1, "Daily message sent");
}

void dailyMsgSave() {
  prefs.putBool("dmon", dailyMsg.active);
  prefs.putUChar("dmh", dailyMsg.hour);
  prefs.putUChar("dmm", dailyMsg.minute);
  prefs.putString("dmtx", String(dailyMsg.text));
  prefs.putUInt("dmdst", dailyMsg.dst);
  prefs.putUChar("dmch", dailyMsg.ch);
}

void dailyMsgLoad() {
  memset(&dailyMsg, 0, sizeof(dailyMsg));
  dailyMsg.active = prefs.getBool("dmon", false);
  dailyMsg.hour = prefs.getUChar("dmh", 8);
  dailyMsg.minute = prefs.getUChar("dmm", 0);
  String t = prefs.getString("dmtx", "");
  strncpy(dailyMsg.text, t.c_str(), 79);
  dailyMsg.dst = prefs.getUInt("dmdst", 0);
  dailyMsg.ch = prefs.getUChar("dmch", 0);
  dailyMsg.lastDay = 255;
}

// ----------------------------------------------------------- Button actions (40) ----
// Map multi-click: 1=ping (fixed), 2/3 configurable
// actions: 0=none, 1=OK quick, 2=send location, 3=ping me (private), 4=SOS, 5=find-me local
uint8_t btnSglAction = 3;    // default: ping (single press)
uint8_t btnDblAction = 1;    // default: send OK
uint8_t btnTrpAction = 2;    // default: send location

struct SosRep {
  bool active; uint16_t lastId; uint32_t seqAtStart, nextAt, startedAt; uint8_t count, step;
  bool has; int32_t la, lo; uint16_t acc; uint32_t dst; uint8_t ch;      // dst/ch: where the SOS was sent (0 = everybody)
} sosR;
static const uint16_t SOS_STEP_S[6] = {45, 60, 90, 120, 180, 300};     // back-off between repeats (seconds)
void sosRepStart(uint16_t firstId, bool has, int32_t la, int32_t lo, uint16_t acc, uint32_t dst, uint8_t ch);

// Most recently heard other node (the "other party" for button actions)
Contact* lastPeerContact() {
  Contact* best = nullptr;
  for (int i = 1; i < MAX_CONTACTS; i++) {
    if (!contacts[i].used || !contacts[i].lastSeen) continue;
    if (!best || (int32_t)(contacts[i].lastSeen - best->lastSeen) > 0) best = &contacts[i];
  }
  return best;
}

// Broadcast this device's last known position (set by the phone app / manual coordinates)
bool sendMyLocationNow(String& err) {
  Contact* me = &contacts[0];
  if (!me->hasLoc) { err = "No position known yet - open the app once (or enter coordinates)"; return false; }
  if (meshMode) {
    if (mtFree() < 1) { err = "Send queue is full"; return false; }
    uint32_t pid = mtNewIds(1);
    Msg* m = addMsg('O', K_LOC, myUid, (uint16_t)pid);
    m->pid = pid; m->dst = 0; m->partsTotal = 1;
    m->hasLoc = true; m->lat = me->lat; m->lon = me->lon; m->acc = me->acc;
    mtSendPosition(me->lat, me->lon, MT_BROADCAST, pid, (uint16_t)pid);
    return true;
  }
  if (qCount + 1 > MAX_QUEUE) { err = "Send queue is full"; return false; }
  uint16_t id = newIds(1);
  Msg* m = addMsg('O', K_LOC, myUid, id);
  m->ch = 0; m->dst = 0;
  m->partsTotal = 1; m->hasLoc = true; m->lat = me->lat; m->lon = me->lon; m->acc = me->acc;
  OutItem it;
  memset(&it, 0, sizeof(it));
  it.kind = K_LOC; it.id = id; it.fragTotal = 1; it.logId = id;
  putU32(it.data, (uint32_t)me->lat);
  putU32(it.data + 4, (uint32_t)me->lon);
  putU16(it.data + 8, me->acc);
  it.dlen = 10;
  enqueue(it);
  return true;
}

void btnActionRun(uint8_t act) {
  String err; uint16_t id = 0;
  switch (act) {
    case 1:  // OK – send as short text (works in both modes)
      sendTextCore("OK", 0, 0, false, 0, 0, 0, err, id);
      hwNotify(0);
      break;
    case 2:  // send my last known location to everybody
      if (sendMyLocationNow(err)) { raiseAlert(1, "Location sent"); hwNotify(0); }
      else raiseAlert(2, "Location not sent: " + err);
      break;
    case 3:
      startPing();
      break;
    case 4:
      if (!sosR.active) {
        bool has = contacts[0].hasLoc;
        if (sosSendNow(has, contacts[0].lat, contacts[0].lon, contacts[0].acc, 0, 0, err, id))
          sosRepStart(id, has, contacts[0].lat, contacts[0].lon, contacts[0].acc, 0, 0);
      }
      break;
    case 5: {  // find the other party: make the last heard node sound
      Contact* p = lastPeerContact();
      if (!p) { raiseAlert(2, "Find partner: nobody heard yet"); break; }
      int rc = sendTextCore("§FD:60", 0, p->uid, false, 0, 0, 0, err, id);
      if (rc) raiseAlert(2, "Find partner failed: " + err);
      else raiseAlert(1, String("Find signal sent to ") + p->name);
      hwNotify(0);
      break;
    }
    case 6: {  // rangefinder toggle on the last heard node
      if (rf.active) { rfStop(); break; }
      Contact* p = lastPeerContact();
      if (!p) { raiseAlert(2, "Rangefinder: nobody heard yet"); break; }
      rfStart(p->uid);
      break;
    }
    case 7:  // quick text "COME"
      sendTextCore("COME", 0, 0, false, 0, 0, 0, err, id);
      hwNotify(0);
      break;
    default: break;
  }
}

// ----------------------------------------------------------- Home WiFi + NTP (45) ----
bool     staEnabled = false;
char     staSsid[33] = "";
char     staPass[65] = "";
bool     staConnected = false;
uint32_t staLastTry = 0;
bool     ntpDone = false;

void staService() {
  if (!staEnabled || !staSsid[0]) return;
  wl_status_t st = WiFi.status();
  // We run AP+STA: softAP is already on; enable STA side
  if (st == WL_CONNECTED) {
    if (!staConnected) {
      staConnected = true;
      sysLine("Home Wi-Fi connected: " + WiFi.localIP().toString());     // information only: no beep, no banner
    }
    if (!ntpDone) {
      configTime(0, 0, "pool.ntp.org", "time.nist.gov");
      // wait a bit for sync – checked each loop
      time_t now = time(nullptr);
      if (now > 1700000000UL) {  // after 2023
        ntpDone = true;
        sysLine("Clock set via NTP");
      }
    }
    return;
  }
  staConnected = false;
  // retry every 60 s
  if ((int32_t)(millis() - staLastTry) < 0) return;
  staLastTry = millis() + 60000UL;
  WiFi.mode(WIFI_AP_STA);
  WiFi.begin(staSsid, staPass);
}

void staLoad() {
  staEnabled = prefs.getBool("staon", false);
  String s = prefs.getString("stassid", "");
  String p = prefs.getString("stapass", "");
  strncpy(staSsid, s.c_str(), 32); staSsid[32] = 0;
  strncpy(staPass, p.c_str(), 64); staPass[64] = 0;
}

void staSave() {
  prefs.putBool("staon", staEnabled);
  prefs.putString("stassid", String(staSsid));
  prefs.putString("stapass", String(staPass));
}

// ----------------------------------------------------------- Shared checklist (25) ----
// Compact group checklist: up to 8 items, synced via special text "§CL:..."
#define MAX_CL_ITEMS 8
struct CheckItem {
  bool used;
  bool done;
  char text[40];
} checklist[MAX_CL_ITEMS];
uint32_t clRev = 0;

String checklistJson() {
  String o = "[";
  for (int i = 0; i < MAX_CL_ITEMS; i++) {
    if (i) o += ",";
    o += "{\"u\":" + String(checklist[i].used ? 1 : 0) +
         ",\"d\":" + String(checklist[i].done ? 1 : 0) +
         ",\"t\":" + jstr(String(checklist[i].text)) + "}";
  }
  return o + "]";
}

void checklistSave() {
  uint8_t buf[MAX_CL_ITEMS * 42];
  memset(buf, 0, sizeof(buf));
  for (int i = 0; i < MAX_CL_ITEMS; i++) {
    buf[i*42] = checklist[i].used ? 1 : 0;
    buf[i*42+1] = checklist[i].done ? 1 : 0;
    memcpy(buf + i*42 + 2, checklist[i].text, 40);
  }
  prefs.putBytes("clist", buf, sizeof(buf));
  prefs.putUInt("clrev", clRev);
}

void checklistLoad() {
  memset(checklist, 0, sizeof(checklist));
  uint8_t buf[MAX_CL_ITEMS * 42];
  size_t l = prefs.getBytesLength("clist");
  if (l == sizeof(buf) && prefs.getBytes("clist", buf, l) == l) {
    for (int i = 0; i < MAX_CL_ITEMS; i++) {
      checklist[i].used = buf[i*42] != 0;
      checklist[i].done = buf[i*42+1] != 0;
      memcpy(checklist[i].text, buf + i*42 + 2, 40);
      checklist[i].text[39] = 0;
    }
  }
  clRev = prefs.getUInt("clrev", 0);
}

// Broadcast checklist state as compact text (for group sync)
void checklistBroadcast() {
  String payload = "§CL:" + String(clRev);
  for (int i = 0; i < MAX_CL_ITEMS; i++) {
    if (!checklist[i].used) continue;
    payload += "|";
    payload += checklist[i].done ? "1" : "0";
    payload += checklist[i].text;
  }
  String err; uint16_t id = 0;
  sendTextCore(payload, 0, 0, false, 0, 0, 0, err, id);
}

bool checklistApplyRemote(const String& body) {
  // body is after "§CL:"
  int colon = body.indexOf('|');
  uint32_t rev = (uint32_t)body.substring(0, colon < 0 ? body.length() : colon).toInt();
  if (rev <= clRev) return true;   // older or same – ignore
  memset(checklist, 0, sizeof(checklist));
  int slot = 0;
  int start = (colon < 0) ? body.length() : colon + 1;
  while (start < (int)body.length() && slot < MAX_CL_ITEMS) {
    int bar = body.indexOf('|', start);
    String item = (bar < 0) ? body.substring(start) : body.substring(start, bar);
    if (item.length() >= 1) {
      checklist[slot].used = true;
      checklist[slot].done = item.charAt(0) == '1';
      String tx = item.substring(1);
      strncpy(checklist[slot].text, tx.c_str(), 39);
      checklist[slot].text[39] = 0;
      slot++;
    }
    if (bar < 0) break;
    start = bar + 1;
  }
  clRev = rev;
  checklistSave();
  raiseAlert(1, "Checklist updated by peer");
  return true;
}

// ----------------------------------------------------------- Remote admin (34) ----
// Admin PIN (4-8 chars). Commands: restart, power, preset
char adminPin[12] = "";
bool adminPinSet = false;

void adminLoad() {
  String p = prefs.getString("admpin", "");
  strncpy(adminPin, p.c_str(), 11); adminPin[11] = 0;
  adminPinSet = adminPin[0] != 0;
}

void adminSave() {
  prefs.putString("admpin", String(adminPin));
  adminPinSet = adminPin[0] != 0;
}

// Handle "§AD:pin:cmd:arg" from air
bool adminHandleRemote(const String& body, uint32_t fromUid) {
  // body after §AD:
  int p1 = body.indexOf(':');
  if (p1 < 0) return true;
  String pin = body.substring(0, p1);
  int p2 = body.indexOf(':', p1 + 1);
  String cmd = (p2 < 0) ? body.substring(p1 + 1) : body.substring(p1 + 1, p2);
  String arg = (p2 < 0) ? "" : body.substring(p2 + 1);
  if (!adminPinSet || pin != String(adminPin)) {
    raiseAlert(2, "Admin command rejected (bad PIN) from " + String(fromUid, HEX));
    return true;
  }
  if (cmd == "restart") {
    raiseAlert(2, "Admin: restarting in 2 s...");
    restartAt = millis() + 2000;
    if (!restartAt) restartAt = 1;
  } else if (cmd == "find") {
    findDevStart(arg.toInt() > 0 ? arg.toInt() : 30);
  } else if (cmd == "preset" && arg.length()) {
    int pr = arg.toInt();
    if (pr >= 0 && pr <= 3) {
      // store preferred preset – actual radio change is mode-specific
      prefs.putInt("admpr", pr);
      raiseAlert(1, "Admin: preset request " + String(pr) + " stored");
    }
  } else if (cmd == "power" && arg.length()) {
    int pw = constrain(arg.toInt(), 2, 20);
    prefs.putInt("admpw", pw);
    raiseAlert(1, "Admin: power request " + String(pw) + " dBm stored");
  } else {
    raiseAlert(1, "Admin: unknown command " + cmd);
  }
  return true;
}

// ----------------------------------------------------------- Path return (35) ----
struct PathHome {
  bool active;
  int32_t lat, lon;
  uint32_t startedAt;
  uint16_t pts;
} pathHome;

void pathHomeStart() {
  if (!contacts[0].hasLoc) {
    raiseAlert(2, "Path return: need your GPS position first");
    return;
  }
  pathHome.active = true;
  pathHome.lat = contacts[0].lat;
  pathHome.lon = contacts[0].lon;
  pathHome.startedAt = millis();
  pathHome.pts = contacts[0].trkCount;
  prefs.putBool("ph_on", true);
  prefs.putInt("ph_la", pathHome.lat);
  prefs.putInt("ph_lo", pathHome.lon);
  raiseAlert(1, "Path return: start point saved");
}

bool pathHomeStartAt(int32_t la, int32_t lo) {
  if (la == 0 && lo == 0) return false;
  pathHome.active = true;
  pathHome.lat = la;
  pathHome.lon = lo;
  pathHome.startedAt = millis();
  pathHome.pts = contacts[0].trkCount;
  prefs.putBool("ph_on", true);
  prefs.putInt("ph_la", pathHome.lat);
  prefs.putInt("ph_lo", pathHome.lon);
  raiseAlert(1, "Path return: start point saved");
  return true;
}

void pathHomeStop() {
  pathHome.active = false;
  prefs.putBool("ph_on", false);
  raiseAlert(1, "Path return cleared");
}

void pathHomeLoad() {
  pathHome.active = prefs.getBool("ph_on", false);
  pathHome.lat = prefs.getInt("ph_la", 0);
  pathHome.lon = prefs.getInt("ph_lo", 0);
  pathHome.startedAt = 0;
  pathHome.pts = 0;
}

// ----------------------------------------------------------- Assembly / rally point (36) ----
struct Rally {
  bool active;
  int32_t lat, lon;
  char name[32];
  uint32_t setAt;
} rally;

void rallySet(int32_t la, int32_t lo, const char* name) {
  rally.active = true;
  rally.lat = la;
  rally.lon = lo;
  strncpy(rally.name, name && name[0] ? name : "Rally", 31);
  rally.name[31] = 0;
  rally.setAt = millis();
  prefs.putBool("ry_on", true);
  prefs.putInt("ry_la", la);
  prefs.putInt("ry_lo", lo);
  prefs.putString("ry_nm", String(rally.name));
}

void rallyClear() {
  rally.active = false;
  prefs.putBool("ry_on", false);
}

void rallyLoad() {
  rally.active = prefs.getBool("ry_on", false);
  rally.lat = prefs.getInt("ry_la", 0);
  rally.lon = prefs.getInt("ry_lo", 0);
  String n = prefs.getString("ry_nm", "Rally");
  strncpy(rally.name, n.c_str(), 31); rally.name[31] = 0;
}

void rallyBroadcast() {
  if (!rally.active) return;
  String payload = String("§RY:") + String(rally.lat) + ":" + String(rally.lon) + ":" + String(rally.name);
  String err; uint16_t id = 0;
  sendTextCore(payload, 0, 0, false, 0, 0, 0, err, id);
}

bool rallyApplyRemote(const String& body) {
  int p1 = body.indexOf(':');
  if (p1 < 0) return true;
  int p2 = body.indexOf(':', p1 + 1);
  if (p2 < 0) return true;
  int32_t la = (int32_t)body.substring(0, p1).toInt();
  int32_t lo = (int32_t)body.substring(p1 + 1, p2).toInt();
  String nm = body.substring(p2 + 1);
  if (nm.length() > 31) nm = nm.substring(0, 31);
  rallySet(la, lo, nm.c_str());
  raiseAlert(2, "Rally point set: " + nm);
  quietNotify(1);
  return true;
}

// ----------------------------------------------------------- Internet gateway ----
bool     gwEnabled = false;
char     gwUrl[128] = "";
char     gwChat[48] = "";
uint32_t gwLastPost = 0;
// which message types are forwarded to the internet (bit mask)
#define GW_TEXT  1      // normal text messages
#define GW_QUICK 2      // quick replies
#define GW_LOC   4      // shared locations
#define GW_SOS   8      // SOS
#define GW_DM    16     // also private messages sent to this device
uint8_t  gwMask = GW_SOS;
uint32_t gwLastSeq = 0;           // last msgLog sequence already looked at
// destinations (bit mask)
#define GWD_TG   1      // Telegram / generic webhook (gwUrl + gwChat), optionally through a proxy
#define GWD_BALE 2      // Bale (Telegram-compatible bot API)
#define GWD_MAIL 4      // e-mail through SMTP
// proxy used for the Telegram destination (tried in order)
#define GW_PROXIES 3
struct GwProxy { uint8_t type; char host[48]; uint16_t port; char user[33]; char pass[33]; };   // type 0 = unused, 1 = SOCKS5, 2 = HTTP/HTTPS (CONNECT)
GwProxy  gwPx[GW_PROXIES];
bool     gwUseProxy = true;          // use the proxy list for Telegram when it is not empty
int8_t   gwPxGood = -1;              // proxy that worked last time (tried first)
bool     gwBaleOn = false;
char     gwBaleUrl[128] = "";
char     gwBaleChat[48] = "";
bool     gwMailOn = false;
char     gwMailHost[48] = "";
uint16_t gwMailPort = 465;           // 465 = SSL, 587 = STARTTLS, anything else = plain
char     gwMailUser[64] = "";
char     gwMailPass[64] = "";
char     gwMailFrom[64] = "";
char     gwMailTo[96] = "";          // one or more addresses separated by comma

#define GW_Q 6
char     gwQ[GW_Q][160];
uint8_t  gwQd[GW_Q];                 // destinations still to be served for each queued message
uint8_t  gwQn = 0;

static void gwCopy(char* dst, size_t n, const String& s) { strncpy(dst, s.c_str(), n - 1); dst[n - 1] = 0; }

void gwLoad() {
  gwEnabled = prefs.getBool("gwon", false);
  String u = prefs.getString("gwurl", "");
  String c = prefs.getString("gwchat", "");
  gwMask = prefs.getUChar("gwmask", GW_SOS);
  strncpy(gwUrl, u.c_str(), 127); gwUrl[127] = 0;
  strncpy(gwChat, c.c_str(), 47); gwChat[47] = 0;
  // extra destinations
  gwBaleOn = prefs.getBool("gbon", false);
  gwCopy(gwBaleUrl, sizeof(gwBaleUrl), prefs.getString("gburl", ""));
  gwCopy(gwBaleChat, sizeof(gwBaleChat), prefs.getString("gbchat", ""));
  gwMailOn = prefs.getBool("gmon", false);
  gwCopy(gwMailHost, sizeof(gwMailHost), prefs.getString("gmhost", ""));
  gwMailPort = prefs.getUShort("gmport", 465);
  gwCopy(gwMailUser, sizeof(gwMailUser), prefs.getString("gmuser", ""));
  gwCopy(gwMailPass, sizeof(gwMailPass), prefs.getString("gmpass", ""));
  gwCopy(gwMailFrom, sizeof(gwMailFrom), prefs.getString("gmfrom", ""));
  gwCopy(gwMailTo, sizeof(gwMailTo), prefs.getString("gmto", ""));
  gwUseProxy = prefs.getBool("gpuse", true);
  memset(gwPx, 0, sizeof(gwPx));
  for (int i = 0; i < GW_PROXIES; i++) {
    String v = prefs.getString((String("gpx") + i).c_str(), "");
    if (!v.length()) continue;
    String f[5]; int n = 0, st = 0;
    for (int k = 0; k <= (int)v.length() && n < 5; k++) {
      if (k == (int)v.length() || v[k] == '\t') { f[n++] = v.substring(st, k); st = k + 1; }
    }
    if (n < 3) continue;
    gwPx[i].type = (uint8_t)f[0].toInt();
    gwCopy(gwPx[i].host, sizeof(gwPx[i].host), f[1]);
    gwPx[i].port = (uint16_t)f[2].toInt();
    if (n > 3) gwCopy(gwPx[i].user, sizeof(gwPx[i].user), f[3]);
    if (n > 4) gwCopy(gwPx[i].pass, sizeof(gwPx[i].pass), f[4]);
    if (!gwPx[i].host[0] || !gwPx[i].port || (gwPx[i].type != 1 && gwPx[i].type != 2)) gwPx[i].type = 0;
  }
}

void gwSave() {
  prefs.putBool("gwon", gwEnabled);
  prefs.putString("gwurl", String(gwUrl));
  prefs.putString("gwchat", String(gwChat));
  prefs.putUChar("gwmask", gwMask);
}

void gwSaveExt() {
  prefs.putBool("gbon", gwBaleOn);
  prefs.putString("gburl", String(gwBaleUrl));
  prefs.putString("gbchat", String(gwBaleChat));
  prefs.putBool("gmon", gwMailOn);
  prefs.putString("gmhost", String(gwMailHost));
  prefs.putUShort("gmport", gwMailPort);
  prefs.putString("gmuser", String(gwMailUser));
  prefs.putString("gmpass", String(gwMailPass));
  prefs.putString("gmfrom", String(gwMailFrom));
  prefs.putString("gmto", String(gwMailTo));
  prefs.putBool("gpuse", gwUseProxy);
  for (int i = 0; i < GW_PROXIES; i++) {
    String key = String("gpx") + i;
    if (!gwPx[i].type) { prefs.putString(key.c_str(), ""); continue; }
    prefs.putString(key.c_str(), String((int)gwPx[i].type) + "\t" + gwPx[i].host + "\t" + String((int)gwPx[i].port) + "\t" + gwPx[i].user + "\t" + gwPx[i].pass);
  }
}

// destinations that are configured; "enabled" additionally needs the master switch / their own switch
uint8_t gwConfigured() {
  uint8_t m = 0;
  if (gwUrl[0]) m |= GWD_TG;
  if (gwBaleUrl[0]) m |= GWD_BALE;
  if (gwMailHost[0] && gwMailTo[0]) m |= GWD_MAIL;
  return m;
}
uint8_t gwActive() {
  uint8_t m = 0;
  if (gwEnabled && gwUrl[0]) m |= GWD_TG;               // Telegram has no own switch: it needs the master switch
  // Bale and e-mail have their own switch: ticking it is enough (it used to need the master Telegram switch as well)
  if (gwBaleOn && gwBaleUrl[0]) m |= GWD_BALE;
  if (gwMailOn && gwMailHost[0] && gwMailTo[0]) m |= GWD_MAIL;
  return m;
}

// force = true is used by the Test buttons: ignore the on/off switches
void gwQueue(const String& text, uint8_t dest = 0xFF, bool force = false) {
  uint8_t m = dest & (force ? gwConfigured() : gwActive());
  if (!m) return;
  String t = clipUtf8(text, 158);
  if (gwQn >= GW_Q) {                                   // queue full: drop the oldest
    for (int i = 1; i < GW_Q; i++) { memcpy(gwQ[i - 1], gwQ[i], 160); gwQd[i - 1] = gwQd[i]; }
    gwQn = GW_Q - 1;
  }
  strncpy(gwQ[gwQn], t.c_str(), 159); gwQ[gwQn][159] = 0;
  gwQd[gwQn] = m;
  gwQn++;
}

// ----------------------------------------------------------- SOS repeating ----

void sosRepStop(const String& why, uint8_t kind) {
  if (!sosR.active) return;
  sosR.active = false;
  raiseAlertTo(kind, "SOS repeat stopped: " + why, sosR.dst);
}

void sosRepStart(uint16_t firstId, bool has, int32_t la, int32_t lo, uint16_t acc, uint32_t dst, uint8_t ch) {
  sosR.dst = dst; sosR.ch = ch;
  sosR.active = true; sosR.lastId = firstId; sosR.seqAtStart = nextSeq - 1; sosR.count = 1; sosR.step = 0;
  sosR.startedAt = millis(); sosR.nextAt = millis() + SOS_STEP_S[0] * 1000UL;
  sosR.has = has; sosR.la = la; sosR.lo = lo; sosR.acc = acc;
  // also forward to internet gateway if home Wi-Fi is up
  String g = "SOS from " + myName;
  if (has) g += " @ " + String(la / 1e6, 5) + "," + String(lo / 1e6, 5);
  if (gwMask & GW_SOS) gwQueue(g);
}

bool sosAcknowledged(int* nodes) {
  int best = 0;
  for (int i = 0; i < MAX_MSGS; i++) {
    const Msg& m = msgLog[i];
    if (!m.seq || m.seq < sosR.seqAtStart) continue;
    if (m.dir == 'O' && m.kind == K_SOS && m.acks > best) best = m.acks;
    if (m.dir == 'I' && m.kind == K_TEXT && m.text.startsWith("SOS from " + myName + " acknowledged")) best = best ? best : 1;
  }
  if (nodes) *nodes = best;
  return best > 0;
}

void serviceSosRep() {
  if (!sosR.active || (int32_t)(millis() - sosR.nextAt) < 0) return;
  int nodes = 0;
  if (sosAcknowledged(&nodes)) { sosRepStop("acknowledged (" + String(nodes) + ")", 1); return; }
  if (sosR.count >= 40 || millis() - sosR.startedAt > 6UL * 3600UL * 1000UL) { sosRepStop("gave up after " + String(sosR.count) + " tries", 2); return; }
  bool busy = meshMode ? (mtFree() < 3) : (qCount > 0 || pend.active);
  if (busy) { sosR.nextAt = millis() + 8000UL; return; }
  if (contacts[0].hasLoc && millis() - contacts[0].locAt < 600000UL) {
    sosR.has = true; sosR.la = contacts[0].lat; sosR.lo = contacts[0].lon; sosR.acc = contacts[0].acc;
  }
  String err;
  uint16_t id = 0;
  if (sosSendNow(sosR.has, sosR.la, sosR.lo, sosR.acc, sosR.dst, sosR.ch, err, id)) { sosR.lastId = id; sosR.count++; }
  if (sosR.step < 5) sosR.step++;
  sosR.nextAt = millis() + SOS_STEP_S[sosR.step] * 1000UL;
}

// optional hardware SOS button (set SOS_BTN_PIN to a free GPIO; button to GND). Hold 3 s: send / cancel.
void serviceSosButton() {
#if SOS_BTN_PIN >= 0
  static bool last = HIGH, fired = false;
  static uint32_t pressedAt = 0, lastChange = 0;
  bool s = digitalRead(SOS_BTN_PIN);
  uint32_t now = millis();
  if (s != last && now - lastChange > 40) {
    lastChange = now; last = s;
    if (s == LOW) { pressedAt = now; fired = false; }
    else { if (!fired) ledWarn = false; }
  }
  if (last == LOW && !fired) {
    uint32_t held = now - pressedAt;
    ledWarn = (held > 800);
    if (held >= 3000) {
      fired = true; ledWarn = false; ledUntil = now + 1500;
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
#endif
}

// ------------------------------------------------- watch list + check-in ----
#define MAX_WATCH 6
struct Watch { uint32_t uid; uint16_t min; char name[24]; bool alerted; uint32_t lastHeard; bool hasLoc; int32_t lat, lon; };
Watch    watches[MAX_WATCH];
uint32_t watchStart = 0;
uint16_t ciMin = 0;
uint32_t ciNext = 0;
String   ciText = "Check-in: OK";

Watch* watchFind(uint32_t uid) {
  for (int i = 0; i < MAX_WATCH; i++) if (watches[i].uid == uid) return &watches[i];
  return nullptr;
}

void watchSave() {
  uint8_t buf[MAX_WATCH * 30];
  int n = 0;
  for (int i = 0; i < MAX_WATCH; i++) {
    if (!watches[i].uid) continue;
    putU32(buf + n, watches[i].uid); putU16(buf + n + 4, watches[i].min);
    memcpy(buf + n + 6, watches[i].name, 24);
    n += 30;
  }
  if (n) prefs.putBytes("watch", buf, n); else prefs.remove("watch");
}

// min = 0 removes the entry
bool watchSet(uint32_t uid, uint16_t min, const char* name, uint32_t lastSeenMs) {
  Watch* w = watchFind(uid);
  if (!min) { if (w) { w->uid = 0; watchSave(); } return true; }
  if (!w) {
    for (int i = 0; i < MAX_WATCH; i++) if (!watches[i].uid) { w = &watches[i]; break; }
    if (!w) return false;
    memset(w, 0, sizeof(*w));
    w->uid = uid;
  }
  if (!w->lastHeard) w->lastHeard = lastSeenMs ? lastSeenMs : (millis() ? millis() : 1);   // start counting from the last time we heard it
  w->min = min; w->alerted = false;
  strncpy(w->name, name, 23); w->name[23] = 0;
  watchSave();
  return true;
}

void serviceWatch() {
  static uint32_t lastRun = 0;
  uint32_t now = millis();
  if (now - lastRun < 10000UL) return;
  lastRun = now;
  for (int i = 0; i < MAX_WATCH; i++) {
    Watch& w = watches[i];
    if (!w.uid || w.alerted) continue;
    uint32_t ref = w.lastHeard ? w.lastHeard : watchStart;
    if (now - ref <= (uint32_t)w.min * 60000UL) continue;
    w.alerted = true;
    String t = "Warning: " + String(w.name) + " has not been heard for " + String((now - ref) / 60000UL) + " min";
    if (w.hasLoc) t += ". Last position " + String(w.lat / 1e6, 5) + "," + String(w.lon / 1e6, 5);
    raiseAlertTo(3, t, w.uid);
  }
}

void serviceCheckIn() {
  if (!ciMin || (int32_t)(millis() - ciNext) < 0) return;
  ciNext = millis() + (uint32_t)ciMin * 60000UL;
  String err;
  uint16_t id = 0;
  sendTextCore(ciText, 0, 0, false, 0, 0, 0, err, id);
}

// ---------------------------------------------------------------- geofence ----
struct Geo { uint8_t on; uint8_t mode; uint16_t pad; int32_t la, lo; uint32_t r; } geo;     // mode 0 leave, 1 enter, 2 both

float distM(int32_t la1, int32_t lo1, int32_t la2, int32_t lo2) {
  float dla = (la2 - la1) * 1e-6f * 111320.0f;
  float dlo = (lo2 - lo1) * 1e-6f * 111320.0f * cosf(la1 * 1e-6f * 0.0174533f);
  return sqrtf(dla * dla + dlo * dlo);
}

void geoReset() { for (int i = 0; i < MAX_CONTACTS; i++) contacts[i].gfState = 0; }
void geoSave() { prefs.putBytes("geo", &geo, sizeof(geo)); }

void featLoc(Contact* c) {
  if (!geo.on || !c->hasLoc) return;
  float d = distM(geo.la, geo.lo, c->lat, c->lon);
  float hys = max(10.0f, geo.r * 0.03f);
  String nm = (c == &contacts[0]) ? String("You") : String(c->name);
  if (c->gfState == 0) { c->gfState = (d <= geo.r) ? 1 : 2; return; }          // first fix: remember silently
  if (c->gfState == 1 && d > geo.r + hys) {
    c->gfState = 2;
    if (geo.mode != 1) raiseAlertTo(2, nm + " left the zone (" + String((int)d) + " m from the center)", c == &contacts[0] ? 0 : c->uid);
  } else if (c->gfState == 2 && d < geo.r - hys) {
    c->gfState = 1;
    if (geo.mode != 0) raiseAlertTo(2, nm + " entered the zone (" + String((int)d) + " m from the center)", c == &contacts[0] ? 0 : c->uid);
  }
}

// -------------------------------------------------------- PIN-locked text ----
#define PIN_ITER      4000
#define PIN_MAX_PLAIN 100                 // keeps the token inside one Meshtastic packet (200 bytes)
uint8_t  unlockFails = 0;
uint32_t unlockLockUntil = 0;

static void pinKey(const uint8_t* salt, const String& pin, uint8_t key[32]) {
  uint8_t buf[64];
  int n = 0;
  memcpy(buf, salt, 6); n = 6;
  int pl = min((int)pin.length(), 40);
  memcpy(buf + n, pin.c_str(), pl); n += pl;
  mbedtls_sha256(buf, n, key, 0);
  for (int i = 0; i < PIN_ITER; i++) {
    uint8_t t[38];
    memcpy(t, key, 32); memcpy(t + 32, salt, 6);
    mbedtls_sha256(t, 38, key, 0);
  }
}

String pinEncrypt(const String& plain, const String& pin) {
  uint8_t raw[1 + 6 + 12 + PIN_MAX_PLAIN + 12];
  int pl = plain.length();
  raw[0] = 1;
  for (int i = 0; i < 18; i += 4) { uint32_t r = esp_random(); memcpy(raw + 1 + i, &r, min(4, 18 - i)); }
  uint8_t key[32];
  pinKey(raw + 1, pin, key);
  mbedtls_gcm_context g;
  mbedtls_gcm_init(&g);
  mbedtls_gcm_setkey(&g, MBEDTLS_CIPHER_ID_AES, key, 256);
  mbedtls_gcm_crypt_and_tag(&g, MBEDTLS_GCM_ENCRYPT, pl, raw + 7, 12, raw, 7,
                            (const uint8_t*)plain.c_str(), raw + 19, 12, raw + 19 + pl);
  mbedtls_gcm_free(&g);
  size_t olen = 0;
  uint8_t b64[260];
  mbedtls_base64_encode(b64, sizeof(b64) - 1, &olen, raw, 19 + pl + 12);
  b64[olen] = 0;
  return String("#E1:") + (const char*)b64;
}

bool isLockedText(const String& t) { return t.startsWith("#E1:"); }

bool pinDecrypt(const String& token, const String& pin, String& out) {
  if (!isLockedText(token)) return false;
  uint8_t raw[1 + 6 + 12 + PIN_MAX_PLAIN + 12 + 8];
  size_t rl = 0;
  String b = token.substring(4);
  b.trim();
  if (mbedtls_base64_decode(raw, sizeof(raw), &rl, (const uint8_t*)b.c_str(), b.length()) != 0) return false;
  if (rl < 19 + 12 || raw[0] != 1) return false;
  int pl = (int)rl - 19 - 12;
  if (pl > PIN_MAX_PLAIN) return false;
  uint8_t key[32], plain[PIN_MAX_PLAIN + 1];
  pinKey(raw + 1, pin, key);
  mbedtls_gcm_context g;
  mbedtls_gcm_init(&g);
  mbedtls_gcm_setkey(&g, MBEDTLS_CIPHER_ID_AES, key, 256);
  int rc = mbedtls_gcm_auth_decrypt(&g, pl, raw + 7, 12, raw, 7, raw + 19 + pl, 12, raw + 19, plain);
  mbedtls_gcm_free(&g);
  if (rc != 0) return false;
  plain[pl] = 0;
  out = String((const char*)plain);
  return true;
}

// ----------------------------------------------------------- link advisor ----
struct AdrPreset { const char* name; int sf; long bw; int cr; int idx; };
static const float SF_REQ_SNR[13] = {0, 0, 0, 0, 0, 0, 0, -7.5f, -10.0f, -12.5f, -15.0f, -17.5f, -20.0f};

int adrPresets(AdrPreset* out) {
  int n = 0;
  if (meshMode) {
    for (int p = 0; p <= 9; p++) {
      if (!mtPresetValid(p)) continue;
      out[n++] = {MT_PRESETS[p].name, MT_PRESETS[p].sf, (long)MT_PRESETS[p].bwHz, MT_PRESETS[p].cr, p};
    }
  } else {
    static const char* nm[4] = {"Balanced", "Long range", "Fast", "Fast wide"};
    for (int p = 0; p < 4; p++) out[n++] = {nm[p], PRESET_SF[p], PRESET_BW[p], LORA_CR, p};
  }
  return n;
}

float adrBitrate(const AdrPreset& p) { return p.sf * ((float)p.bw / (float)(1UL << p.sf)) * 4.0f / p.cr; }

String advisorJson() {
  AdrPreset pr[12];
  int np = adrPresets(pr);
  int curIdx = meshMode ? mtPreset : preset;
  int cur = -1;
  for (int i = 0; i < np; i++) if (pr[i].idx == curIdx) cur = i;
  float weak = 999;
  int n = 0;
  String who = "";
  for (int i = 1; i < MAX_CONTACTS; i++) {
    const Contact& c = contacts[i];
    if (!c.used || c.snrN < 3 || !c.lastSeen || millis() - c.lastSeen > 1800000UL) continue;
    n++;
    if (c.snrEma < weak) { weak = c.snrEma; who = String(c.name); }
  }
  String o = "{\"n\":" + String(n) + ",\"mesh\":" + String(meshMode ? 1 : 0);
  if (n == 0 || cur < 0) return o + ",\"has\":0}";
  float bwNow = (float)curBW;
  float curMargin = weak - SF_REQ_SNR[pr[cur].sf];
  int rec = -1;
  float recMargin = -999;
  for (int i = 0; i < np; i++) {                                   // fastest preset that keeps a 6 dB margin
    float pred = weak - 10.0f * log10f((float)pr[i].bw / bwNow);
    float mg = pred - SF_REQ_SNR[pr[i].sf];
    if (mg >= 6.0f && (rec < 0 || adrBitrate(pr[i]) > adrBitrate(pr[rec]))) { rec = i; recMargin = mg; }
  }
  if (rec < 0) {                                                   // nothing is comfortable: pick the most robust one
    for (int i = 0; i < np; i++) {
      float pred = weak - 10.0f * log10f((float)pr[i].bw / bwNow);
      float mg = pred - SF_REQ_SNR[pr[i].sf];
      if (rec < 0 || mg > recMargin) { rec = i; recMargin = mg; }
    }
  }
  o += ",\"has\":1,\"weak\":" + String(weak, 1) + ",\"who\":" + jstr(who);
  o += ",\"cur\":" + String(pr[cur].idx) + ",\"curName\":" + jstr(String(pr[cur].name)) + ",\"curMargin\":" + String(curMargin, 1);
  o += ",\"rec\":" + String(pr[rec].idx) + ",\"recName\":" + jstr(String(pr[rec].name)) + ",\"recMargin\":" + String(recMargin, 1);
  o += ",\"speed\":" + String(adrBitrate(pr[rec]) / adrBitrate(pr[cur]), 2);
  o += ",\"same\":" + String(rec == cur ? 1 : 0) + "}";
  return o;
}

// --------------------------------------------------------------- link test ----
struct LtRx { bool used, reported; uint32_t uid; uint16_t id, total, got; uint32_t bm[4]; int rssiSum, snrSum; uint32_t lastAt, doneAt; };
struct LtRes { bool used; uint32_t uid; char name[24]; uint16_t got, total; int rssi, snr; };
struct LtTx { bool active; uint16_t id, n, sent; uint32_t nextAt, startedAt; } ltTx;
LtRx  ltRx[4];
LtRes ltRes[6];

LtRx* ltRxFor(uint32_t uid, uint16_t id) {
  LtRx* free = nullptr; LtRx* old = &ltRx[0];
  for (int i = 0; i < 4; i++) {
    if (ltRx[i].used && ltRx[i].uid == uid && ltRx[i].id == id) return &ltRx[i];
    if (!ltRx[i].used && !free) free = &ltRx[i];
    if (ltRx[i].lastAt < old->lastAt) old = &ltRx[i];
  }
  LtRx* r = free ? free : old;
  memset(r, 0, sizeof(*r));
  r->used = true; r->uid = uid; r->id = id;
  return r;
}

void ltNote(uint32_t uid, uint16_t id, uint16_t seq, uint16_t total, int rssi, int snr) {
  if (!total || total > 100 || seq >= total) return;
  LtRx* r = ltRxFor(uid, id);
  r->total = total;
  uint32_t bit = 1UL << (seq & 31);
  if (!(r->bm[seq >> 5] & bit)) {
    r->bm[seq >> 5] |= bit;
    r->got++; r->rssiSum += rssi; r->snrSum += snr;
  }
  r->lastAt = millis();
  if (seq + 1 >= total) r->doneAt = millis() + random(500, 2500);      // last probe heard: report soon
}

void ltSendReport(LtRx* r) {
  r->reported = true;
  int g = r->got ? r->got : 1;
  int rs = r->rssiSum / g, sn = r->snrSum / g;
  if (meshMode) {
    String t = "Link test: received " + String(r->got) + "/" + String(r->total) + " packets (" +
               String(100 - (int)r->got * 100 / max((int)r->total, 1)) + "% lost), avg RSSI " + String(rs) +
               " dBm, SNR " + String(sn) + " dB";
    String err;
    uint16_t id = 0;
    mtSendMsg(K_TEXT, t, t, r->uid, false, 0, 0, false, err, id);
    return;
  }
  uint8_t b[15];
  b[0] = 'T'; b[1] = 'r';
  putU32(b + 2, r->uid);
  putU16(b + 6, r->id); putU16(b + 8, r->got); putU16(b + 10, r->total);
  putU16(b + 12, (uint16_t)(int16_t)rs);
  b[14] = (uint8_t)(int8_t)sn;
  deferSend(random(300, 1500), b, 15, 0);
}

// native 'T' packet (payload after the type byte)
void featLtNative(Contact* c, const uint8_t* p, int len, int rssi, int snr) {
  if (len >= 7 && p[0] == 'p') {
    ltNote(c->uid, getU16(p + 1), getU16(p + 3), getU16(p + 5), rssi, snr);
  } else if (len >= 14 && p[0] == 'r') {
    if (getU32(p + 1) != myUid || getU16(p + 5) != ltTx.id) return;
    LtRes* r = nullptr;
    for (int i = 0; i < 6; i++) if (ltRes[i].used && ltRes[i].uid == c->uid) r = &ltRes[i];
    for (int i = 0; i < 6 && !r; i++) if (!ltRes[i].used) r = &ltRes[i];
    if (!r) return;
    r->used = true; r->uid = c->uid;
    strncpy(r->name, c->name, 23); r->name[23] = 0;
    r->got = getU16(p + 7); r->total = getU16(p + 9);
    r->rssi = (int16_t)getU16(p + 11); r->snr = (int8_t)p[13];
  }
}

// Meshtastic RANGE_TEST_APP packet: payload is text "seq N LT:<id>/<total>"
void featLtMesh(Contact* c, const uint8_t* pl, int len, int rssi, int snr) {
  char b[48];
  int l = min(len, 47);
  memcpy(b, pl, l); b[l] = 0;
  unsigned seq = 0, id = 0, tot = 0;
  if (sscanf(b, "seq %u LT:%x/%u", &seq, &id, &tot) != 3 || seq < 1) return;     // other nodes' plain range tests are ignored
  ltNote(c->uid, (uint16_t)id, (uint16_t)(seq - 1), (uint16_t)tot, rssi, snr);
}

bool ltStart(int n) {
  if (ltTx.active) return false;
  if (n < 5) n = 5;
  if (n > (meshMode ? 50 : 100)) n = meshMode ? 50 : 100;
  memset(ltRes, 0, sizeof(ltRes));
  ltTx.active = true; ltTx.id = (uint16_t)(random(1, 65000)); ltTx.n = n; ltTx.sent = 0;
  ltTx.startedAt = millis(); ltTx.nextAt = millis() + 300;
  return true;
}

void serviceLt() {
  uint32_t now = millis();
  for (int i = 0; i < 4; i++) {                                   // receiver side: send reports / expire entries
    LtRx& r = ltRx[i];
    if (!r.used) continue;
    if (!r.reported && ((r.doneAt && (int32_t)(now - r.doneAt) >= 0) || now - r.lastAt > 9000UL)) ltSendReport(&r);
    else if (r.reported && now - r.lastAt > 120000UL) r.used = false;
  }
  if (!ltTx.active || (int32_t)(now - ltTx.nextAt) < 0) return;   // sender side
  if (meshMode) {
    if (mtFree() < 2 || !mtDutyOk()) { ltTx.nextAt = now + 2000; return; }
    char pl[32];
    int n = snprintf(pl, sizeof(pl), "seq %u LT:%04x/%u", (unsigned)ltTx.sent + 1, (unsigned)ltTx.id, (unsigned)ltTx.n);
    uint8_t pkt[MT_MAX_PKT];
    uint32_t pid = mtNewIds(1);
    int len = mtMake(pkt, MT_BROADCAST, pid, false, MT_PORT_RANGETEST, (const uint8_t*)pl, n, false, 0, 0);
    if (len > 0) mtQueue(50, pkt, len, pid, MT_BROADCAST, 0, 0, false);
    ltTx.nextAt = now + 2500UL;
  } else {
    uint8_t b[8] = {'T', 'p'};
    putU16(b + 2, ltTx.id); putU16(b + 4, ltTx.sent); putU16(b + 6, ltTx.n);
    sendSecure(b, 8, 1);                                          // ttl 1: never relayed, measures the direct link
    ltTx.nextAt = now + (uint32_t)airtimeMs(25) + 200 + random(0, 120);
  }
  ltTx.sent++;
  if (ltTx.sent >= ltTx.n) { ltTx.active = false; ltTx.nextAt = now; }
}

String ltJson() {
  String o = "{\"act\":" + String(ltTx.active ? 1 : 0) + ",\"id\":" + String(ltTx.id) + ",\"n\":" + String(ltTx.n) +
             ",\"sent\":" + String(ltTx.sent) + ",\"mesh\":" + String(meshMode ? 1 : 0) + ",\"res\":[";
  bool f = true;
  for (int i = 0; i < 6; i++) {
    if (!ltRes[i].used) continue;
    if (!f) o += ",";
    f = false;
    o += "{\"u\":\"" + hex8(ltRes[i].uid) + "\",\"n\":" + jstr(String(ltRes[i].name)) + ",\"got\":" + String(ltRes[i].got) +
         ",\"tot\":" + String(ltRes[i].total) + ",\"rs\":" + String(ltRes[i].rssi) + ",\"sn\":" + String(ltRes[i].snr) + "}";
  }
  o += "],\"rx\":[";
  f = true;
  for (int i = 0; i < 4; i++) {
    if (!ltRx[i].used) continue;
    Contact* c = findContact(ltRx[i].uid);
    if (!f) o += ",";
    f = false;
    o += "{\"u\":\"" + hex8(ltRx[i].uid) + "\",\"n\":" + jstr(c ? String(c->name) : String("?")) + ",\"got\":" + String(ltRx[i].got) +
         ",\"tot\":" + String(ltRx[i].total) + ",\"done\":" + String(ltRx[i].reported ? 1 : 0) + "}";
  }
  return o + "]}";
}

// --------------------------------------------------------------- operators (legacy names) ----
#define MAX_OPS 4
char ops[MAX_OPS][17];
bool opTag = false;

int opCount() { int n = 0; for (int i = 0; i < MAX_OPS; i++) if (ops[i][0]) n++; return n; }

void opsSave() {
  String s;
  for (int i = 0; i < MAX_OPS; i++) { if (i) s += "\n"; s += ops[i]; }
  prefs.putString("ops", s);
  prefs.putBool("optag", opTag);
}

void opsLoad() {
  memset(ops, 0, sizeof(ops));
  String s = prefs.getString("ops", "");
  int i = 0, start = 0;
  while (i < MAX_OPS && start <= (int)s.length()) {
    int e = s.indexOf("\n", start);
    String p = (e < 0) ? s.substring(start) : s.substring(start, e);
    p.trim();
    strncpy(ops[i++], p.c_str(), 16);
    if (e < 0) break;
    start = e + 1;
  }
  opTag = prefs.getBool("optag", false);
}

// ----------------------------------------------------------- Multi-user network ----
// Up to 8 accounts on one device. Optional login gate.
// Hierarchical networks (e.g. home1 / home2) with per-user path slugs (/x1, /y2).
// Same-network users: LAN private chat. Cross-network: LoRa private chat.
// Admin (AP 192.168.4.1 or admin login) manages users; regular users only get chat.
#define MAX_USERS 8
#define MAX_SESS  8
#define MAX_NETS  4
struct UserAcct {
  bool used;
  char name[17];
  char slug[17];          // URL path e.g. "x1" -> http://ip/x1
  char net[17];           // network group e.g. "home1"
  uint8_t passHash[32];   // SHA-256 of password
  uint8_t role;           // 0=user (chat only), 1=admin
  uint8_t iconId;         // 0..19 character SVG icon
  uint8_t iconColor;      // 0..15 palette index
};
struct Session {
  bool used;
  uint8_t userIdx;        // index into users[]
  char token[33];         // 16 random bytes hex
  uint32_t lastSeen;
};
UserAcct users[MAX_USERS];
extern bool usersDirty;
Session  sessions[MAX_SESS];
bool     authRequired = false;   // when true, API needs valid token
char     netName[25] = "";      // optional default network/building name shown in UI
uint8_t  adminPassHash[32] = {0};      // SHA-256 of admin password (default "admin")
bool     adminPassSet = false;   // true once admin password stored
char     pathSlug[17] = "";      // current path slug from URI (set by path handler)

void userHashPass(const String& pass, uint8_t out[32]) {
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts(&ctx, 0);
  mbedtls_sha256_update(&ctx, (const unsigned char*)pass.c_str(), pass.length());
  // pepper with device uid so hashes aren't portable across nodes without knowing uid
  char pepper[12];
  snprintf(pepper, sizeof(pepper), "%08lx", (unsigned long)myUid);
  mbedtls_sha256_update(&ctx, (const unsigned char*)pepper, strlen(pepper));
  mbedtls_sha256_finish(&ctx, out);
  mbedtls_sha256_free(&ctx);
}

void adminHashPass(const String& pass, uint8_t out[32]) {
  userHashPass(pass, out);  // same scheme
}

bool adminPassOk(const String& pass) {
  uint8_t h[32];
  adminHashPass(pass.length() ? pass : String("admin"), h);
  if (!adminPassSet) {
    // default: admin / admin
    uint8_t def[32];
    adminHashPass("admin", def);
    return memcmp(h, def, 32) == 0;
  }
  return memcmp(h, adminPassHash, 32) == 0;
}

// Local chat identity of a viewer: 1..8 = chat-only web user (index+1), 255 = the device owner (admin / anonymous admin).
#define LC_ADMIN 255
int viewerCode(int viewer) {
  if (viewer >= 0 && viewer < MAX_USERS && users[viewer].used && users[viewer].role == 0) return viewer + 1;
  return LC_ADMIN;
}

int userFind(const char* name) {
  for (int i = 0; i < MAX_USERS; i++)
    if (users[i].used && strcasecmp(users[i].name, name) == 0) return i;
  return -1;
}

int userFindSlug(const char* slug) {
  if (!slug || !slug[0]) return -1;
  for (int i = 0; i < MAX_USERS; i++)
    if (users[i].used && users[i].slug[0] && strcasecmp(users[i].slug, slug) == 0) return i;
  return -1;
}

bool sameNetwork(int a, int b) {
  if (a < 0 || b < 0 || a >= MAX_USERS || b >= MAX_USERS) return false;
  if (!users[a].used || !users[b].used) return false;
  if (!users[a].net[0] || !users[b].net[0]) return false;
  return strcasecmp(users[a].net, users[b].net) == 0;
}

void usersSave() {
  usersDirty = true;      // announce the change to the other nodes
  // pack per user: 1 + 16 name + 16 slug + 16 net + 32 hash + 1 role + 1 icon + 1 color = 84
  uint8_t buf[MAX_USERS * 84];
  memset(buf, 0, sizeof(buf));
  for (int i = 0; i < MAX_USERS; i++) {
    int o = i * 84;
    buf[o] = users[i].used ? 1 : 0;
    memcpy(buf + o + 1, users[i].name, 16);
    memcpy(buf + o + 17, users[i].slug, 16);
    memcpy(buf + o + 33, users[i].net, 16);
    memcpy(buf + o + 49, users[i].passHash, 32);
    buf[o + 81] = users[i].role;
    buf[o + 82] = users[i].iconId;
    buf[o + 83] = users[i].iconColor;
  }
  prefs.putBytes("users", buf, sizeof(buf));
  prefs.putBool("authreq", authRequired);
  prefs.putString("netname", String(netName));
  if (adminPassSet) prefs.putBytes("admph", adminPassHash, 32);
  prefs.putBool("admps", adminPassSet);
}

void usersLoad() {
  memset(users, 0, sizeof(users));
  memset(sessions, 0, sizeof(sessions));
  // try new 84-byte format first
  uint8_t buf84[MAX_USERS * 84];
  size_t l = prefs.getBytesLength("users");
  if (l == sizeof(buf84) && prefs.getBytes("users", buf84, l) == l) {
    for (int i = 0; i < MAX_USERS; i++) {
      int o = i * 84;
      users[i].used = buf84[o] != 0;
      memcpy(users[i].name, buf84 + o + 1, 16); users[i].name[16] = 0;
      memcpy(users[i].slug, buf84 + o + 17, 16); users[i].slug[16] = 0;
      memcpy(users[i].net, buf84 + o + 33, 16); users[i].net[16] = 0;
      memcpy(users[i].passHash, buf84 + o + 49, 32);
      users[i].role = buf84[o + 81];
      users[i].iconId = buf84[o + 82];
      users[i].iconColor = buf84[o + 83];
    }
  } else {
    // migrate legacy 49-byte format
    uint8_t buf49[MAX_USERS * 49];
    if (l == sizeof(buf49) && prefs.getBytes("users", buf49, l) == l) {
      for (int i = 0; i < MAX_USERS; i++) {
        users[i].used = buf49[i*49] != 0;
        memcpy(users[i].name, buf49 + i*49 + 1, 16);
        users[i].name[16] = 0;
        memcpy(users[i].passHash, buf49 + i*49 + 17, 32);
        // auto-slug from name (lowercase alnum)
        int k = 0;
        for (int j = 0; users[i].name[j] && k < 16; j++) {
          char c = users[i].name[j];
          if (c >= 'A' && c <= 'Z') c += 32;
          if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) users[i].slug[k++] = c;
        }
        users[i].slug[k] = 0;
      }
    }
  }
  authRequired = prefs.getBool("authreq", false);
  String nn = prefs.getString("netname", "");
  strncpy(netName, nn.c_str(), 24); netName[24] = 0;
  adminPassSet = prefs.getBool("admps", false);
  if (adminPassSet && prefs.getBytesLength("admph") == 32)
    prefs.getBytes("admph", adminPassHash, 32);
  // migrate legacy ops names into users (no password → empty hash means "set on first login")
  for (int i = 0; i < MAX_OPS; i++) {
    if (!ops[i][0]) continue;
    if (userFind(ops[i]) >= 0) continue;
    for (int j = 0; j < MAX_USERS; j++) {
      if (users[j].used) continue;
      users[j].used = true;
      strncpy(users[j].name, ops[i], 16);
      memset(users[j].passHash, 0, 32);
      int k = 0;
      for (int p = 0; ops[i][p] && k < 16; p++) {
        char c = ops[i][p];
        if (c >= 'A' && c <= 'Z') c += 32;
        if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) users[j].slug[k++] = c;
      }
      users[j].slug[k] = 0;
      break;
    }
  }
}

int authCurrent();
// What a viewer gets to know about the users: chat-only users see names, networks and icons (no links, no admin accounts)
String usersJson() {
  int v = authCurrent();
  bool lim = (v >= 0 && users[v].role == 0);
  String o = "[";
  bool firstU = true;
  for (int i = 0; i < MAX_USERS; i++) {
    if (lim && (!users[i].used || users[i].role != 0)) continue;
    if (!firstU) o += ",";
    firstU = false;
    bool online = false;
    for (int s = 0; s < MAX_SESS; s++)
      if (sessions[s].used && sessions[s].userIdx == i &&
          (int32_t)(millis() - sessions[s].lastSeen) < 300000) online = true;
    o += "{\"i\":" + String(i) + ",\"u\":" + String(users[i].used ? 1 : 0) +
         ",\"n\":" + jstr(String(users[i].name)) +
         ",\"slug\":" + jstr(lim ? String("") : String(users[i].slug)) +
         ",\"net\":" + jstr(String(users[i].net)) +
         ",\"role\":" + String(users[i].role) +
         ",\"ic\":" + String(users[i].iconId) +
         ",\"icol\":" + String(users[i].iconColor) +
         ",\"on\":" + String(online ? 1 : 0) +
         ",\"hp\":" + String(users[i].passHash[0] || users[i].passHash[1] ? 1 : 0) + "}";
  }
  return o + "]";
}

void sessionNew(uint8_t userIdx, char tokenOut[33]) {
  // free oldest if full
  int slot = -1;
  uint32_t oldest = 0xFFFFFFFFUL;
  for (int i = 0; i < MAX_SESS; i++) {
    if (!sessions[i].used) { slot = i; break; }
    if (sessions[i].lastSeen < oldest) { oldest = sessions[i].lastSeen; slot = i; }
  }
  // random token
  uint8_t rnd[16];
  for (int i = 0; i < 16; i++) rnd[i] = (uint8_t)(esp_random() & 0xFF);
  char tok[33];
  for (int i = 0; i < 16; i++) sprintf(tok + i*2, "%02x", rnd[i]);
  tok[32] = 0;
  sessions[slot].used = true;
  sessions[slot].userIdx = userIdx;
  strncpy(sessions[slot].token, tok, 32);
  sessions[slot].token[32] = 0;
  sessions[slot].lastSeen = millis();
  strncpy(tokenOut, tok, 32);
  tokenOut[32] = 0;
}

int sessionFind(const char* token) {
  if (!token || !token[0]) return -1;
  for (int i = 0; i < MAX_SESS; i++) {
    if (!sessions[i].used) continue;
    if (strcmp(sessions[i].token, token) == 0) {
      sessions[i].lastSeen = millis();
      return i;
    }
  }
  return -1;
}

// Did this request come in through the device's own Wi-Fi (192.168.4.1)? Whoever is there is the admin.
// Requests that come through the home network (192.168.1.x) always need a login: a user (own link) or the admin password.
bool reqOnAp() {
  IPAddress a = server.client().localIP();
  return a == WiFi.softAPIP();
}

// returns the user index, -1 = login needed, -2 = anonymous admin (own Wi-Fi, login not required)
int authCurrent() {
  String tok = server.hasArg("token") ? server.arg("token") : "";
  if (!tok.length() && server.hasHeader("X-Token")) tok = server.header("X-Token");
  int s = sessionFind(tok.c_str());
  if (s >= 0) return sessions[s].userIdx;
  if (!authRequired && reqOnAp()) return -2;
  return -1;
}

// ------------------------------------------------------ hooks / glue code ----
void featHeard(uint32_t uid, Contact* c, int rssi, int snr) {
  if (uid) holdFlushFor(uid);
  if (meshMode && c) {                                    // a Meshtastic node we have not seen yet: tell it who our users are soon
    static uint32_t knownMask = 0;
    int ci = (int)(c - contacts);
    if (ci > 0 && ci < 32 && !(knownMask & (1UL << ci))) {
      knownMask |= (1UL << ci);
      uint32_t t = millis() + random(6000, 15000);
      if ((int32_t)(udNextAt - t) > 0) udNextAt = t;
    }
  }
  if (c) {
    c->snrEma = c->snrN ? c->snrEma * 0.8f + snr * 0.2f : (float)snr;
    if (c->snrN < 250) c->snrN++;
  }
  rfHeard(uid, rssi);
  Watch* w = watchFind(uid);
  if (!w) return;
  w->lastHeard = millis() ? millis() : 1;
  if (c) {
    strncpy(w->name, c->name, 23); w->name[23] = 0;
    if (c->hasLoc) { w->hasLoc = true; w->lat = c->lat; w->lon = c->lon; }
  }
  if (w->alerted) { w->alerted = false; raiseAlertTo(1, String(w->name) + " is back (heard again)", w->uid); }
}

bool mtUdOn = true;           // Meshtastic mode: announce our web users with a small text

void featLoad() {
  mtUdOn = prefs.getUChar("mtud", 1) != 0;
  watchStart = millis();
  memset(watches, 0, sizeof(watches));
  uint8_t buf[MAX_WATCH * 30];
  size_t l = prefs.getBytesLength("watch");
  if (l >= 30 && l <= sizeof(buf) && prefs.getBytes("watch", buf, l) == l) {
    for (size_t i = 0, k = 0; i + 30 <= l && k < MAX_WATCH; i += 30, k++) {
      watches[k].uid = getU32(buf + i); watches[k].min = getU16(buf + i + 4);
      memcpy(watches[k].name, buf + i + 6, 24); watches[k].name[23] = 0;
    }
  }
  memset(&geo, 0, sizeof(geo));
  if (prefs.getBytesLength("geo") == sizeof(geo)) prefs.getBytes("geo", &geo, sizeof(geo));
  ciMin = prefs.getUShort("ci", 0);
  ciText = prefs.getString("cit", "Check-in: OK");
  ciNext = millis() + (uint32_t)ciMin * 60000UL;
  quietHoursEnabled = prefs.getBool("qh", false);
  quietStartH = prefs.getUChar("qhs", 22); quietStartM = prefs.getUChar("qhm", 0);
  quietEndH   = prefs.getUChar("qhe", 7);  quietEndM   = prefs.getUChar("qen", 0);
  quietAllowMorse = prefs.getBool("qhmz", false);
  quietAllowSos   = prefs.getBool("qhso", true);
  sunsetWarnOn = prefs.getBool("swo", false);
  sunsetWarnMin = prefs.getUShort("swm", 60);
  nextSunsetEpoch = prefs.getUInt("swep", 0);
  btnSglAction = prefs.getUChar("btns", 3);
  btnDblAction = prefs.getUChar("btnd", 1);
  btnTrpAction = prefs.getUChar("btnt", 2);
  dailyMsgLoad();
  staLoad();
  checklistLoad();
  adminLoad();
  pathHomeLoad();
  rallyLoad();
  gwLoad();
  compLoad();
  opsLoad();
  usersLoad();
  myAvSet = prefs.getBool("avs", false);
  myAvIc = prefs.getUChar("avi", 0) % 20;
  myAvCol = prefs.getUChar("avc", 0) % 16;
}

// ---- User directory over LoRa: every device announces its web users (name, network, icon - never passwords),
// so other devices can list them in the chat and write to them. One small 'U' packet per user.
#define MAX_RU 24
struct RemUser { bool used; uint32_t uid; char name[17]; char net[17]; uint8_t ic, col; uint32_t seen; };
RemUser remUsers[MAX_RU];
extern uint32_t udNextAt;

void remUserAdd(Contact* c, const char* nm, const char* nt, uint8_t ic, uint8_t col) {
  int slot = -1, oldest = 0;
  for (int i = 0; i < MAX_RU; i++) {
    if (remUsers[i].used && remUsers[i].uid == c->uid && strcasecmp(remUsers[i].name, nm) == 0) { slot = i; break; }
    if (!remUsers[i].used) { if (slot < 0 || remUsers[slot].used) slot = i; }
    else if (slot < 0 && remUsers[i].seen < remUsers[oldest].seen) oldest = i;
  }
  if (slot < 0) slot = oldest;
  remUsers[slot].used = true;
  remUsers[slot].uid = c->uid;
  strncpy(remUsers[slot].name, nm, 16); remUsers[slot].name[16] = 0;
  strncpy(remUsers[slot].net, nt, 16); remUsers[slot].net[16] = 0;
  remUsers[slot].ic = ic; remUsers[slot].col = col;
  remUsers[slot].seen = millis() ? millis() : 1;
}

void handleUserDir(Contact* c, const uint8_t* p, int len) {
  if (len < 5) return;
  uint8_t ic = p[1], col = p[2];
  int nl = p[3];
  if (nl < 1 || nl > 16 || 4 + nl > len) return;
  char nm[17]; memcpy(nm, p + 4, nl); nm[nl] = 0;
  int ml = len - 4 - nl; if (ml < 0) ml = 0; if (ml > 16) ml = 16;
  char nt[17]; memcpy(nt, p + 4 + nl, ml); nt[ml] = 0;
  remUserAdd(c, nm, nt, ic, col);
}

// Meshtastic mode: the user directory travels as ONE rare text  "!UD!<net>|name:icon:colour|name:icon:colour..."
void mtUserDirRx(Contact* c, const String& t) {
  String body = t.substring(4);
  int p = body.indexOf('|');
  if (p < 0) return;
  String net = body.substring(0, p);
  net = net.substring(0, 16);
  int pos = p + 1;
  while (pos < (int)body.length()) {
    int e = body.indexOf('|', pos);
    if (e < 0) e = body.length();
    String ent = body.substring(pos, e);
    pos = e + 1;
    int c1 = ent.indexOf(':');
    int c2 = ent.indexOf(':', c1 + 1);
    if (c1 < 1 || c2 < 0) continue;
    String nm = ent.substring(0, c1);
    nm = nm.substring(0, 16);
    remUserAdd(c, nm.c_str(), net.c_str(), (uint8_t)ent.substring(c1 + 1, c2).toInt(), (uint8_t)ent.substring(c2 + 1).toInt());
  }
}

String remUsersJson() {
  String o = ",\"ru\":[";
  bool first = true;
  for (int i = 0; i < MAX_RU; i++) {
    if (!remUsers[i].used) continue;
    uint32_t age = (millis() - remUsers[i].seen) / 1000UL;
    if (age > 1500) { remUsers[i].used = false; continue; }     // not announced for 25 min: gone
    if (!first) o += ",";
    first = false;
    o += "{\"d\":\"" + hex8(remUsers[i].uid) + "\",\"n\":" + jstr(String(remUsers[i].name)) +
         ",\"net\":" + jstr(String(remUsers[i].net)) + ",\"ic\":" + String(remUsers[i].ic) +
         ",\"icol\":" + String(remUsers[i].col) + ",\"ls\":" + String(age) + "}";
  }
  o += "]";
  return o;
}

void userDirService() {
  static int udIdx = -1;
  static uint32_t udAt = 0;
  uint32_t now = millis();
  if (meshMode) {                                         // one small broadcast: soon after start / a new node appears, then every ~10 minutes
    if (!mtUdOn) return;
    if ((int32_t)(now - udNextAt) < 0 && !usersDirty) return;
    if (mtFree() < 3 || now - lastOkAt < 6000) { udNextAt = now + 5000; return; }
    String p = String("!UD!") + String(netName).substring(0, 16);
    int cnt = 0;
    for (int i = 0; i < MAX_USERS; i++) {
      if (!(users[i].used && users[i].role == 0 && users[i].name[0])) continue;
      String nm = String(users[i].name).substring(0, 16);
      nm.replace("|", "_"); nm.replace(":", "_");
      p += "|" + nm + ":" + String(users[i].iconId) + ":" + String(users[i].iconColor);
      cnt++;
    }
    usersDirty = false;
    udNextAt = now + 600000UL + random(0, 60000);
    if (!cnt) return;
    String err; uint16_t id = 0;
    mtSendMsg(K_TEXT, p, p, MT_BROADCAST, false, 0, 0, false, err, id);
    return;
  }
  if (udIdx < 0) {
    if ((int32_t)(now - udNextAt) < 0 && !usersDirty) return;
    usersDirty = false;
    udIdx = 0;
    udNextAt = now + 600000UL + random(0, 60000);       // rarely: the directory must never compete with chat
  }
  if ((int32_t)(now - udAt) < 0) return;
  if (pend.active || qCount > 0 || morseBusy || now - lastOkAt < 6000) { udAt = now + 2500; return; }     // chat traffic goes first
  while (udIdx < MAX_USERS && !(users[udIdx].used && users[udIdx].role == 0 && users[udIdx].name[0])) udIdx++;
  if (udIdx >= MAX_USERS) { udIdx = -1; return; }
  uint8_t b[40];
  int n = 0;
  b[n++] = 'U';
  b[n++] = 0;
  b[n++] = users[udIdx].iconId;
  b[n++] = users[udIdx].iconColor;
  int nl = strlen(users[udIdx].name); if (nl > 16) nl = 16;
  b[n++] = (uint8_t)nl;
  memcpy(b + n, users[udIdx].name, nl); n += nl;
  int ml = strlen(users[udIdx].net); if (ml > 16) ml = 16;
  memcpy(b + n, users[udIdx].net, ml); n += ml;
  deferSend(random(50, 300), b, (uint8_t)n, 0);
  udIdx++;
  udAt = now + 7000 + random(0, 3000);
}

void featService() {
  userDirService();
  serviceSosRep();
  serviceSosButton();
  serviceWatch();
  serviceCheckIn();
  serviceLt();
  findDevService();
  rfService();
  compService();
  sunsetService();
  dailyMsgService();
  staService();
}

void featReset() {                                   // on mode switch: forget per-mode state
  udNextAt = millis() + 25000UL;                       // announce our users soon in the new mode
  geoReset();
  memset(ltRx, 0, sizeof(ltRx));
  ltTx.active = false;
}

// extra fields appended to the "me" object of /api/poll
String featMeJson() {
  String o = ",\"al\":" + alertsJson();
  o += ",\"sos\":{\"a\":" + String(sosR.active ? 1 : 0) + ",\"n\":" + String(sosR.count) + ",\"nx\":" +
       String(sosR.active ? (int32_t)(sosR.nextAt - millis()) / 1000 : 0) + "}";
  o += ",\"gf\":{\"on\":" + String(geo.on) + ",\"m\":" + String(geo.mode) + ",\"la\":" + String(geo.la) + ",\"lo\":" + String(geo.lo) + ",\"r\":" + String(geo.r) + "}";
  o += ",\"ci\":" + String(ciMin) + ",\"cit\":" + jstr(ciText);
  o += ",\"ops\":[";
  for (int i = 0; i < MAX_OPS; i++) { if (i) o += ","; o += jstr(String(ops[i])); }
  o += "],\"opt\":" + String(opTag ? 1 : 0);
  o += ",\"auth\":" + String(authRequired ? 1 : 0);
  o += ",\"net\":" + jstr(String(netName));
  o += ",\"users\":" + usersJson();
  o += ",\"mud\":" + String(mtUdOn ? 1 : 0);
  o += ",\"sbtn\":" + String(SOS_BTN_PIN >= 0 ? 1 : 0);
  o += ",\"qh\":{\"on\":" + String(quietHoursEnabled ? 1 : 0) +
       ",\"sh\":" + String(quietStartH) + ",\"sm\":" + String(quietStartM) +
       ",\"eh\":" + String(quietEndH) + ",\"em\":" + String(quietEndM) +
       ",\"am\":" + String(quietAllowMorse ? 1 : 0) +
       ",\"as\":" + String(quietAllowSos ? 1 : 0) +
       ",\"now\":" + String(isQuietNow() ? 1 : 0) + "}";
  o += ",\"sw\":{\"on\":" + String(sunsetWarnOn ? 1 : 0) +
       ",\"m\":" + String(sunsetWarnMin) +
       ",\"ep\":" + String(nextSunsetEpoch) + "}";
  o += ",\"rf\":{\"a\":" + String(rf.active ? 1 : 0) +
       ",\"to\":" + String(rf.targetUid) +
       ",\"rssi\":" + String(rf.lastRssi) + "}";
  o += ",\"fd\":{\"a\":" + String(findDev.active ? 1 : 0) + "}";
  o += ",\"comp\":[";
  for (int i = 0; i < MAX_COMP; i++) {
    if (i) o += ",";
    o += "{\"u\":" + String(comps[i].uid) + ",\"m\":" + String(comps[i].maxM) +
         ",\"on\":" + String(comps[i].used ? 1 : 0) +
         ",\"n\":" + jstr(String(comps[i].name)) +
         ",\"al\":" + String(comps[i].alerted ? 1 : 0) + "}";
  }
  o += "]";
  o += ",\"dm\":{\"on\":" + String(dailyMsg.active ? 1 : 0) +
       ",\"h\":" + String(dailyMsg.hour) + ",\"m\":" + String(dailyMsg.minute) +
       ",\"t\":" + jstr(String(dailyMsg.text)) + "}";
  o += ",\"btn\":{\"s\":" + String(btnSglAction) + ",\"d\":" + String(btnDblAction) + ",\"t\":" + String(btnTrpAction) + "}";
  o += ",\"sta\":{\"on\":" + String(staEnabled ? 1 : 0) +
       ",\"ssid\":" + jstr(String(staSsid)) +
       ",\"ok\":" + String(staConnected ? 1 : 0) +
       ",\"ntp\":" + String(ntpDone ? 1 : 0) +
       ",\"ip\":" + jstr(staConnected ? WiFi.localIP().toString() : String("")) + "}";
  o += ",\"cl\":" + checklistJson() + ",\"clr\":" + String(clRev);
  o += ",\"adm\":" + String(adminPinSet ? 1 : 0);
  o += ",\"ph\":{\"on\":" + String(pathHome.active ? 1 : 0) +
       ",\"la\":" + String(pathHome.lat) + ",\"lo\":" + String(pathHome.lon) + "}";
  o += ",\"ry\":{\"on\":" + String(rally.active ? 1 : 0) +
       ",\"la\":" + String(rally.lat) + ",\"lo\":" + String(rally.lon) +
       ",\"n\":" + jstr(String(rally.name)) + "}";
  o += ",\"gw\":{\"on\":" + String(gwEnabled ? 1 : 0) +
       ",\"url\":" + jstr(String(gwUrl)) +
       ",\"chat\":" + jstr(String(gwChat)) +
       ",\"mask\":" + String(gwMask) +
       ",\"pu\":" + String(gwUseProxy ? 1 : 0) + ",\"px\":[";
  for (int i = 0, k = 0; i < GW_PROXIES; i++) {
    if (!gwPx[i].type) continue;
    if (k++) o += ",";
    o += "{\"i\":" + String(i) + ",\"t\":" + String((int)gwPx[i].type) + ",\"h\":" + jstr(String(gwPx[i].host)) +
         ",\"p\":" + String((int)gwPx[i].port) + ",\"u\":" + jstr(String(gwPx[i].user)) + ",\"hp\":" + String(gwPx[i].pass[0] ? 1 : 0) + "}";
  }
  o += "],\"bl\":{\"on\":" + String(gwBaleOn ? 1 : 0) + ",\"url\":" + jstr(String(gwBaleUrl)) + ",\"chat\":" + jstr(String(gwBaleChat)) + "}";
  o += ",\"ml\":{\"on\":" + String(gwMailOn ? 1 : 0) + ",\"host\":" + jstr(String(gwMailHost)) + ",\"port\":" + String((int)gwMailPort) +
       ",\"user\":" + jstr(String(gwMailUser)) + ",\"hp\":" + String(gwMailPass[0] ? 1 : 0) + ",\"from\":" + jstr(String(gwMailFrom)) +
       ",\"to\":" + jstr(String(gwMailTo)) + "}}";
  o += hwJson();
  o += morseJson();
  return o;
}

String featContactJson(uint32_t uid) {
  Watch* w = watchFind(uid);
  return ",\"wm\":" + String(w ? w->min : 0) + ",\"wa\":" + String(w && w->alerted ? 1 : 0);
}
