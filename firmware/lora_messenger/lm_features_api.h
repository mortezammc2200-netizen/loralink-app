// lm_features_api.h - web API for the features in lm_features.h.
// Included by lora_messenger.ino after jerr()/jok() exist; featRoutes() is called from setup().
#pragma once

void handleSosCancel() {
  if (sosR.active) sosRepStop("cancelled", 1);
  jok();
}

void handleAlertClr() {
  clearAlert((uint32_t)strtoul(server.arg("i").c_str(), nullptr, 10));
  jok();
}

void handleWatch() {
  uint32_t u = (uint32_t)strtoul(server.arg("u").c_str(), nullptr, 16);
  int min = server.arg("min").toInt();
  if (!u || u == myUid) { jerr(400, "Pick another node"); return; }
  if (min != 0 && (min < 5 || min > 1440)) { jerr(400, "Minutes must be 0 (off) or 5 to 1440"); return; }
  Contact* c = findContact(u);
  Watch* w = watchFind(u);
  String nm = c ? String(c->name) : (w ? String(w->name) : String("Node-") + hex8(u).substring(4));
  if (!watchSet(u, (uint16_t)min, nm.c_str(), c ? c->lastSeen : 0)) { jerr(409, "Watch list is full (6 nodes)"); return; }
  jok();
}

void handleGeo() {
  int32_t la = geo.la, lo = geo.lo;
  if (server.arg("use") == "me") {
    if (!contacts[0].hasLoc) { jerr(409, "Your position is not known yet. Share your location first."); return; }
    la = contacts[0].lat; lo = contacts[0].lon;
  } else if (server.hasArg("lat") && server.hasArg("lon")) {
    double a = server.arg("lat").toDouble(), b = server.arg("lon").toDouble();
    if (a < -90 || a > 90 || b < -180 || b > 180) { jerr(400, "Bad coordinates"); return; }
    la = (int32_t)lround(a * 1e6); lo = (int32_t)lround(b * 1e6);
  }
  long r = server.hasArg("r") ? server.arg("r").toInt() : (long)geo.r;
  if (r < 20 || r > 50000) { jerr(400, "Radius must be 20 m to 50 km"); return; }
  int m = server.hasArg("m") ? server.arg("m").toInt() : geo.mode;
  if (m < 0 || m > 2) m = 2;
  geo.la = la; geo.lo = lo; geo.r = (uint32_t)r; geo.mode = (uint8_t)m;
  if (server.hasArg("on")) geo.on = server.arg("on") == "1";
  if (geo.on && !geo.la && !geo.lo) { jerr(409, "Set the zone center first"); return; }
  geoReset();
  geoSave();
  jok();
}

void handleCheckIn() {
  int min = server.arg("min").toInt();
  if (min != 0 && (min < 5 || min > 1440)) { jerr(400, "Minutes must be 0 (off) or 5 to 1440"); return; }
  if (server.hasArg("text")) {
    String t = clipUtf8(sanitize(server.arg("text")), 60);
    if (t.length()) ciText = t;
  }
  ciMin = (uint16_t)min;
  ciNext = millis() + (uint32_t)ciMin * 60000UL;
  prefs.putUShort("ci", ciMin);
  prefs.putString("cit", ciText);
  jok();
}

void handleOps() {
  String names = server.arg("names");
  memset(ops, 0, sizeof(ops));
  int i = 0, start = 0;
  while (i < MAX_OPS && start <= (int)names.length()) {
    int e = names.indexOf("\n", start);
    String p = clipUtf8(sanitize((e < 0) ? names.substring(start) : names.substring(start, e)), 16);
    p.trim();
    if (p.length()) strncpy(ops[i++], p.c_str(), 16);
    if (e < 0) break;
    start = e + 1;
  }
  opTag = server.arg("tag") == "1";
  opsSave();
  jok();
}

// Multi-user: register / login / logout / config
static void makeSlug(const String& src, char* out, int maxLen) {
  int k = 0;
  for (unsigned i = 0; i < src.length() && k < maxLen - 1; i++) {
    char c = src[i];
    if (c >= 'A' && c <= 'Z') c += 32;
    if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) out[k++] = c;
  }
  out[k] = 0;
}

void handleAuthRegister() {
  String name = clipUtf8(sanitize(server.arg("user")), 16);
  name.trim();
  String pass = server.arg("pass");
  String net  = clipUtf8(sanitize(server.arg("net")), 16);
  net.trim();
  String slugIn = clipUtf8(sanitize(server.arg("slug")), 16);
  slugIn.trim();
  if (name.length() < 2) { jerr(400, "Username at least 2 characters"); return; }
  if (pass.length() < 4) { jerr(400, "Password at least 4 characters"); return; }
  if (userFind(name.c_str()) >= 0) { jerr(409, "Username already taken"); return; }
  // only admin (or auth off) can register new users when auth is required
  int me = authCurrent();
  if (me == -1) { jerr(401, "Login required"); return; }
  if (me >= 0 && users[me].role == 0) {
    jerr(403, "Only admin can create users"); return;
  }
  int slot = -1;
  for (int i = 0; i < MAX_USERS; i++) if (!users[i].used) { slot = i; break; }
  if (slot < 0) { jerr(409, "User limit reached (max 8)"); return; }
  users[slot].used = true;
  strncpy(users[slot].name, name.c_str(), 16);
  users[slot].name[16] = 0;
  if (slugIn.length() >= 1) {
    makeSlug(slugIn, users[slot].slug, 17);
  } else {
    makeSlug(name, users[slot].slug, 17);
  }
  if (!users[slot].slug[0]) snprintf(users[slot].slug, 17, "u%d", slot);
  // ensure unique slug
  if (userFindSlug(users[slot].slug) >= 0 && userFindSlug(users[slot].slug) != slot) {
    char tmp[17];
    snprintf(tmp, 17, "%s%d", users[slot].slug, slot);
    strncpy(users[slot].slug, tmp, 16);
  }
  strncpy(users[slot].net, netName, 16);               // the building name of this device
  users[slot].net[16] = 0;
  users[slot].role = 0;
  users[slot].iconId = (uint8_t)((slot * 7 + 1) % 20);          // a different default avatar for each user
  users[slot].iconColor = (uint8_t)((slot * 5 + 2) % 16);
  userHashPass(pass, users[slot].passHash);
  usersSave();
  char tok[33];
  sessionNew((uint8_t)slot, tok);
  jokx(",\"token\":" + jstr(String(tok)) + ",\"user\":" + jstr(name) +
       ",\"i\":" + String(slot) + ",\"slug\":" + jstr(String(users[slot].slug)) +
       ",\"net\":" + jstr(String(users[slot].net)));
}

void handleAuthLogin() {
  String name = clipUtf8(sanitize(server.arg("user")), 16);
  name.trim();
  String pass = server.arg("pass");
  // path slug login: if slug arg present, only allow that user
  String slug = clipUtf8(sanitize(server.arg("slug")), 16);
  slug.trim();
  int idx = -1;
  if (slug.length()) {
    idx = userFindSlug(slug.c_str());
    if (idx < 0) { delay(400); jerr(403, "Unknown path / user"); return; }
    // if username given, must match
    if (name.length() && strcasecmp(users[idx].name, name.c_str()) != 0) {
      delay(400); jerr(403, "Wrong username or password"); return;
    }
  } else {
    idx = userFind(name.c_str());
  }
  if (idx < 0) { delay(400); jerr(403, "Wrong username or password"); return; }
  if (users[idx].role == 1 && !adminPassOk(pass)) { delay(400); jerr(403, "Wrong username or password"); return; }   // the admin account uses the admin password
  if (users[idx].role == 1) { char tk[33]; sessionNew((uint8_t)idx, tk); jokx(",\"token\":" + jstr(String(tk)) + ",\"user\":\"admin\",\"i\":" + String(idx) + ",\"role\":1"); return; }
  // if no password set yet, set it now (first login after migrate)
  bool empty = true;
  for (int i = 0; i < 32; i++) if (users[idx].passHash[i]) { empty = false; break; }
  if (empty) {
    if (pass.length() < 4) { jerr(400, "Set a password (at least 4 characters)"); return; }
    userHashPass(pass, users[idx].passHash);
    usersSave();
  } else {
    uint8_t h[32];
    userHashPass(pass, h);
    if (memcmp(h, users[idx].passHash, 32) != 0) {
      delay(400);
      jerr(403, "Wrong username or password");
      return;
    }
  }
  char tok[33];
  sessionNew((uint8_t)idx, tok);
  jokx(",\"token\":" + jstr(String(tok)) + ",\"user\":" + jstr(String(users[idx].name)) +
       ",\"i\":" + String(idx) + ",\"slug\":" + jstr(String(users[idx].slug)) +
       ",\"net\":" + jstr(String(users[idx].net)) +
       ",\"role\":" + String(users[idx].role) +
       ",\"ic\":" + String(users[idx].iconId) +
       ",\"icol\":" + String(users[idx].iconColor));
}

void handleAuthLogout() {
  String tok = server.hasArg("token") ? server.arg("token") : "";
  for (int i = 0; i < MAX_SESS; i++) {
    if (sessions[i].used && tok.length() && strcmp(sessions[i].token, tok.c_str()) == 0)
      sessions[i].used = false;
  }
  jok();
}

void handleAuthCfg() {
  int me = authCurrent();
  if (me == -1) { jerr(401, "Login required"); return; }
  // settings changes need admin role when logged in
  if (me >= 0 && users[me].role == 0 && (server.hasArg("require") || server.hasArg("net") ||
      server.hasArg("del") || server.hasArg("adminpass") || server.hasArg("setnet") ||
      server.hasArg("setslug") || server.hasArg("setrole"))) {
    jerr(403, "Admin only"); return;
  }
  if (server.hasArg("require")) {
    authRequired = server.arg("require").toInt() != 0;
  }
  if (server.hasArg("net")) {
    String n = clipUtf8(sanitize(server.arg("net")), 24);
    strncpy(netName, n.c_str(), 24); netName[24] = 0;
    for (int i = 0; i < MAX_USERS; i++) if (users[i].used) { strncpy(users[i].net, netName, 16); users[i].net[16] = 0; }   // one building name for every user of this device
  }
  // set admin password (default was admin/admin)
  if (server.hasArg("adminpass")) {
    String ap = server.arg("adminpass");
    if (ap.length() < 4) { jerr(400, "Admin password at least 4 characters"); return; }
    adminHashPass(ap, adminPassHash);
    adminPassSet = true;
  }
  // update a user's network / slug / role / icon (admin)
  if (server.hasArg("edit")) {
    int ei = server.arg("edit").toInt();
    if (ei >= 0 && ei < MAX_USERS && users[ei].used) {
      if (server.hasArg("setnet")) {
        String n = clipUtf8(sanitize(server.arg("setnet")), 16);
        strncpy(users[ei].net, n.c_str(), 16); users[ei].net[16] = 0;
      }
      if (server.hasArg("setslug")) {
        String s = clipUtf8(sanitize(server.arg("setslug")), 16);
        char tmp[17]; makeSlug(s, tmp, 17);
        if (tmp[0]) {
          int other = userFindSlug(tmp);
          if (other >= 0 && other != ei) { jerr(409, "Slug already used"); return; }
          strncpy(users[ei].slug, tmp, 16); users[ei].slug[16] = 0;
        }
      }
      if (server.hasArg("setrole")) {
        users[ei].role = (uint8_t)(server.arg("setrole").toInt() != 0 ? 1 : 0);
      }
      if (server.hasArg("setpass")) {
        String p = server.arg("setpass");
        if (p.length() >= 4) userHashPass(p, users[ei].passHash);
      }
    }
  }
  // user self-service: icon + color
  if (server.hasArg("myicon") && me >= 0) {
    users[me].iconId = (uint8_t)constrain(server.arg("myicon").toInt(), 0, 19);
  }
  if (server.hasArg("mycolor") && me >= 0) {
    users[me].iconColor = (uint8_t)constrain(server.arg("mycolor").toInt(), 0, 15);
  }
  // delete user
  if (server.hasArg("del")) {
    int di = server.arg("del").toInt();
    if (di >= 0 && di < MAX_USERS) {
      users[di].used = false;
      users[di].name[0] = 0;
      users[di].slug[0] = 0;
      users[di].net[0] = 0;
      memset(users[di].passHash, 0, 32);
      users[di].role = 0;
      for (int s = 0; s < MAX_SESS; s++)
        if (sessions[s].used && sessions[s].userIdx == di) sessions[s].used = false;
    }
  }
  usersSave();
  jokx(",\"auth\":" + String(authRequired ? 1 : 0) + ",\"users\":" + usersJson() +
       ",\"net\":" + jstr(String(netName)));
}

void handleAuthMe() {
  int me = authCurrent();
  if (me == -1) { jerr(401, "Login required"); return; }
  if (me == -2) {
    jokx(",\"anon\":1,\"auth\":" + String(authRequired ? 1 : 0) +
         ",\"net\":" + jstr(String(netName)) + ",\"users\":" + usersJson());
    return;
  }
  jokx(",\"i\":" + String(me) + ",\"user\":" + jstr(String(users[me].name)) +
       ",\"auth\":" + String(authRequired ? 1 : 0) +
       ",\"net\":" + jstr(String(users[me].net[0] ? users[me].net : netName)) +
       ",\"slug\":" + jstr(String(users[me].slug)) +
       ",\"role\":" + String(users[me].role) +
       ",\"ic\":" + String(users[me].iconId) +
       ",\"icol\":" + String(users[me].iconColor) +
       ",\"users\":" + usersJson());
}

// Profile avatar: a light SVG icon + colour. A chat-only user changes only their own user icon;
// anyone else sets this device's avatar (announced to the other nodes with the beacon).
// Chat-only users (role 0) may only chat and change their own avatar. Everything else is for the admin.
bool adminGate() {
  int me = authCurrent();
  if (me == -1) { jerr(401, "Login required"); return false; }
  if (me >= 0 && users[me].role == 0) { jerr(403, "Admin only"); return false; }
  return true;
}
static WebServer::THandlerFunction G(void (*h)()) { return [h]() { if (!adminGate()) return; h(); }; }
// U = any logged-in person (a chat-only user too). Without login nothing works.
static WebServer::THandlerFunction LG(void (*h)()) { return [h]() { if (authCurrent() == -1) { jerr(401, "Login required"); return; } h(); }; }

void handleAvatar() {
  int me = authCurrent();
  if (me == -1) { jerr(401, "Login required"); return; }
  int ic = constrain(server.arg("ic").toInt(), 0, 19);
  int col = constrain(server.arg("col").toInt(), 0, 15);
  if (me >= 0) {
    users[me].iconId = (uint8_t)ic;
    users[me].iconColor = (uint8_t)col;
    usersSave();
  }
  if (me < 0 || users[me].role != 0) {
    myAvSet = true; myAvIc = (uint8_t)ic; myAvCol = (uint8_t)col;
    prefs.putBool("avs", true);
    prefs.putUChar("avi", myAvIc);
    prefs.putUChar("avc", myAvCol);
    if (!meshMode) nextBeaconAt = millis() + 1500;        // tell the others soon
  }
  revCounter++;
  jok();
}

// Admin login (for settings gate on AP / after modem connect)
void handleAdminLogin() {
  String pass = server.arg("pass");
  if (!adminPassOk(pass)) { delay(400); jerr(403, "Wrong admin password"); return; }
  // the admin session lives in a user slot with role 1 (created on first use, never announced to other nodes)
  int adminIdx = -1;
  for (int i = 0; i < MAX_USERS; i++) if (users[i].used && users[i].role == 1) { adminIdx = i; break; }
  if (adminIdx < 0) {
    for (int i = 0; i < MAX_USERS; i++) if (!users[i].used) { adminIdx = i; break; }
    if (adminIdx < 0) { jerr(500, "No free user slot (delete a user first)"); return; }
    memset(&users[adminIdx], 0, sizeof(users[adminIdx]));
    users[adminIdx].used = true;
    strncpy(users[adminIdx].name, "admin", 16);
    strncpy(users[adminIdx].slug, "admin", 16);
    users[adminIdx].role = 1;
    userHashPass(pass.length() ? pass : String("admin"), users[adminIdx].passHash);
    usersSave();
  }
  char tok[33];
  sessionNew((uint8_t)adminIdx, tok);
  jokx(",\"token\":" + jstr(String(tok)) + ",\"user\":\"admin\",\"i\":" + String(adminIdx) + ",\"role\":1");
}

void handleUnlock() {
  if ((int32_t)(unlockLockUntil - millis()) > 0) { jerr(429, "Too many wrong PINs. Wait a moment."); return; }
  String out;
  if (!pinDecrypt(server.arg("text"), server.arg("pin"), out)) {
    delay(600);
    if (++unlockFails >= 5) { unlockFails = 0; unlockLockUntil = millis() + 30000UL; }
    jerr(403, "Wrong PIN or damaged message");
    return;
  }
  unlockFails = 0;
  jokx(",\"text\":" + jstr(out));
}

// live spectrum: one sweep of the 433 MHz band (RSSI per step). The radio cannot receive messages while sweeping.
void handleSpec() {
  uint32_t f0 = server.hasArg("f0") ? (uint32_t)server.arg("f0").toInt() : 433050UL;
  uint32_t f1 = server.hasArg("f1") ? (uint32_t)server.arg("f1").toInt() : 434790UL;
  uint32_t st = server.hasArg("st") ? (uint32_t)server.arg("st").toInt() : 25UL;
  if (st < 10) st = 10;
  if (f0 < FREQ_MIN_KHZ) f0 = FREQ_MIN_KHZ;
  if (f1 > FREQ_MAX_KHZ) f1 = FREQ_MAX_KHZ;
  if (f1 <= f0) { jerr(400, "Bad range"); return; }
  int n = (int)((f1 - f0) / st) + 1;
  if (n > 120) { jerr(400, "Too many points"); return; }
  String o = "{\"f0\":" + String(f0) + ",\"st\":" + String(st) + ",\"cur\":" + String(curFreqHz() / 1000L) + ",\"r\":[";
  for (int i = 0; i < n; i++) {
    LoRa.setFrequency((long)(f0 + (uint32_t)i * st) * 1000L);
    LoRa.receive();
    delay(2);
    int mx = -200;
    for (int s = 0; s < 2; s++) { int r = LoRa.rssi(); if (r > mx) mx = r; delay(1); }
    if (i) o += ",";
    o += String(mx);
  }
  LoRa.setFrequency(curFreqHz());
  LoRa.idle();
  o += "]}";
  server.sendHeader("Cache-Control", "no-store");
  server.send(200, "application/json", o);
}

void handleLtest() {
  int n = server.hasArg("n") ? server.arg("n").toInt() : 20;
  if (!ltStart(n)) { jerr(409, "A test is already running"); return; }
  jok();
}
void handleLtStat() { server.sendHeader("Cache-Control", "no-store"); server.send(200, "application/json", ltJson()); }
void handleAdr() { server.sendHeader("Cache-Control", "no-store"); server.send(200, "application/json", advisorJson()); }

// data for the "connection check" in the UI
void handleDoctor() {
  int nodes = 0;
  for (int i = 1; i < MAX_CONTACTS; i++) if (contacts[i].used && contacts[i].lastSeen) nodes++;
  uint32_t now = millis();
  String o = "{\"mt\":" + String(meshMode ? 1 : 0) + ",\"fq\":" + String(curFreqHz() / 1000L) + ",\"sf\":" + String(curSF) + ",\"bw\":" + String(curBW);
  o += ",\"up\":" + String(now / 1000UL) + ",\"rx\":" + String(cRx) + ",\"ok\":" + String(cOk) + ",\"auth\":" + String(cAuth) + ",\"foreign\":" + String(cForeign);
  o += ",\"nodes\":" + String(nodes) + ",\"rxAgo\":" + String(lastRxAt ? (int32_t)((now - lastRxAt) / 1000UL) : -1);
  o += ",\"okAgo\":" + String(lastOkAt ? (int32_t)((now - lastOkAt) / 1000UL) : -1) + "}";
  server.sendHeader("Cache-Control", "no-store");
  server.send(200, "application/json", o);
}

// buzzer / LED settings (-1 = unchanged for the switches and type, -2 = unchanged for the pins)
void handleHw() {
  int bz = server.hasArg("bz") ? server.arg("bz").toInt() : -1;
  int bp = server.hasArg("bp") ? server.arg("bp").toInt() : -2;
  int bt = server.hasArg("bt") ? server.arg("bt").toInt() : -1;
  int ld = server.hasArg("ld") ? server.arg("ld").toInt() : -1;
  int lp = server.hasArg("lp") ? server.arg("lp").toInt() : -2;
  String err;
  if (!hwConfigure(bz, bp, bt, ld, lp, err)) { jerr(400, err); return; }
  jok();
}

void handleHwTest() {
  String err;
  if (!hwTest(server.arg("what"), err)) { jerr(409, err); return; }
  jok();
}

// local deletion of messages (tombstones: the web UI drops them on the next poll)
void handleMsgDel() {
  String q = server.arg("q");
  int n = 0, start = 0;
  while (start < (int)q.length() && n < 120) {
    int e = q.indexOf(",", start);
    String tok = (e < 0) ? q.substring(start) : q.substring(start, e);
    uint32_t sq = (uint32_t)strtoul(tok.c_str(), nullptr, 10);
    if (sq) {
      for (int i = 0; i < MAX_MSGS; i++) {
        Msg& m = msgLog[i];
        if (m.seq == sq && !m.gone) { m.gone = true; m.text = ""; touch(&m); n++; break; }
      }
    }
    if (e < 0) break;
    start = e + 1;
  }
  jokx(",\"n\":" + String(n));
}

// Morse signal on the LED / buzzer (local)
void handleMorse() {
  String err;
  int out = server.arg("out").toInt();
  int n = server.hasArg("n") ? server.arg("n").toInt() : 1;
  int every = server.hasArg("every") ? server.arg("every").toInt() : 5;
  int wpm = server.hasArg("wpm") ? server.arg("wpm").toInt() : 12;
  if (!morseStart(server.arg("text"), out, n, every, wpm, err)) { jerr(409, err); return; }
  jok();
}
void handleMorseStop() { morseAbort(); jok(); }

// Remote Morse: play on another device (A → B)
// POST /api/morseremote  text, to (hex uid), out, n, gap (sec), wpm, until (0/1)
void handleMorseRemote() {
  String err;
  uint32_t to = 0;
  if (server.hasArg("to") && server.arg("to").length())
    to = (uint32_t)strtoul(server.arg("to").c_str(), nullptr, 16);
  int out = server.hasArg("out") ? server.arg("out").toInt() : 3;
  int n = server.hasArg("n") ? server.arg("n").toInt() : 3;
  int gap = server.hasArg("gap") ? server.arg("gap").toInt() : 15;
  int wpm = server.hasArg("wpm") ? server.arg("wpm").toInt() : 12;
  bool untilC = server.hasArg("until") && server.arg("until").toInt() != 0;
  uint16_t id = 0;
  int rc = sendRemoteMorse(to, server.arg("text"), (uint8_t)out, (uint8_t)n,
                           (uint16_t)gap, (uint8_t)wpm, untilC, err, id);
  if (rc) { jerr(rc, err); return; }
  jokx(",\"id\":" + String(id));
}

// Remote Morse accept policy + ceilings
void handleMorseRemoteCfg() {
  if (server.hasArg("acc")) {
    int a = server.arg("acc").toInt();
    if (a < 0) a = 0; if (a > 2) a = 2;
    rm.acceptFrom = (uint8_t)a;
    prefs.putUChar("rmacc", rm.acceptFrom);
  }
  if (server.hasArg("max")) {
    int m = server.arg("max").toInt();
    if (m < 1) m = 1; if (m > 20) m = 20;
    rm.maxRepeats = (uint8_t)m;
    prefs.putUChar("rmmax", rm.maxRepeats);
  }
  if (server.hasArg("tot")) {
    int t = server.arg("tot").toInt();
    if (t < 30) t = 30; if (t > 1800) t = 1800;
    rm.maxTotalSec = (uint16_t)t;
    prefs.putUShort("rmtot", rm.maxTotalSec);
  }
  jokx(",\"acc\":" + String(rm.acceptFrom) + ",\"max\":" + String(rm.maxRepeats) +
       ",\"tot\":" + String(rm.maxTotalSec));
}

// Quiet hours
void handleQuiet() {
  if (server.hasArg("on")) quietHoursEnabled = server.arg("on").toInt() != 0;
  if (server.hasArg("sh")) quietStartH = (uint8_t)constrain(server.arg("sh").toInt(), 0, 23);
  if (server.hasArg("sm")) quietStartM = (uint8_t)constrain(server.arg("sm").toInt(), 0, 59);
  if (server.hasArg("eh")) quietEndH   = (uint8_t)constrain(server.arg("eh").toInt(), 0, 23);
  if (server.hasArg("em")) quietEndM   = (uint8_t)constrain(server.arg("em").toInt(), 0, 59);
  if (server.hasArg("am")) quietAllowMorse = server.arg("am").toInt() != 0;
  if (server.hasArg("as")) quietAllowSos   = server.arg("as").toInt() != 0;
  prefs.putBool("qh", quietHoursEnabled);
  prefs.putUChar("qhs", quietStartH); prefs.putUChar("qhm", quietStartM);
  prefs.putUChar("qhe", quietEndH);   prefs.putUChar("qen", quietEndM);
  prefs.putBool("qhmz", quietAllowMorse); prefs.putBool("qhso", quietAllowSos);
  jokx(",\"on\":" + String(quietHoursEnabled ? 1 : 0) + ",\"now\":" + String(isQuietNow() ? 1 : 0));
}

// Find device: make a remote node sound so you can locate it
// POST /api/finddev  to=<hex uid>  sec=5..120
// Also accepts local: no "to" → this device sounds
void handleMtUd() {
  mtUdOn = server.arg("on").toInt() != 0;
  prefs.putUChar("mtud", mtUdOn ? 1 : 0);
  if (mtUdOn) { udNextAt = millis() + 3000; usersDirty = true; }
  jokx(",\"on\":" + String(mtUdOn ? 1 : 0));
}

void handleFindDev() {
  int sec = server.hasArg("sec") ? server.arg("sec").toInt() : 30;
  if (sec < 5) sec = 5; if (sec > 600) sec = 600;
  if (server.hasArg("to") && server.arg("to").length()) {
    uint32_t to = (uint32_t)strtoul(server.arg("to").c_str(), nullptr, 16);
    if (!to || !findContact(to)) { jerr(404, "Node not found"); return; }
    String payload = String("§FD:") + String(sec);
    String err; uint16_t id = 0;
    int rc = sendTextCore(payload, 0, to, false, 0, 0, 0, err, id);
    if (rc) { jerr(rc, err); return; }
    jokx(",\"sent\":1,\"sec\":" + String(sec));
  } else {
    findDevStart((uint16_t)sec);
    jokx(",\"local\":1,\"sec\":" + String(sec));
  }
}

// Rangefinder: beep faster as signal gets stronger
// POST /api/rf  to=<hex>  action=start|stop
void handleRf() {
  String act = server.arg("action");
  if (act == "stop") { rfStop(); jok(); return; }
  uint32_t to = 0;
  if (server.hasArg("to") && server.arg("to").length())
    to = (uint32_t)strtoul(server.arg("to").c_str(), nullptr, 16);
  if (!to || !findContact(to)) { jerr(404, "Node not found"); return; }
  rfStart(to);
  jokx(",\"to\":" + String(to));
}

// Companion distance alert
// POST /api/comp  uid=<hex>  max=<metres>  on=0|1  name=...
void handleComp() {
  uint32_t uid = 0;
  if (server.hasArg("uid") && server.arg("uid").length())
    uid = (uint32_t)strtoul(server.arg("uid").c_str(), nullptr, 16);
  if (!uid) { jerr(400, "uid required"); return; }
  int slot = -1, empty = -1;
  for (int i = 0; i < MAX_COMP; i++) {
    if (comps[i].used && comps[i].uid == uid) { slot = i; break; }
    if (!comps[i].used && empty < 0) empty = i;
  }
  bool on = !server.hasArg("on") || server.arg("on").toInt() != 0;
  if (!on) {
    if (slot >= 0) { comps[slot].used = false; comps[slot].uid = 0; compSave(); }
    jok(); return;
  }
  if (slot < 0) {
    if (empty < 0) { jerr(409, "Companion list full (max 4)"); return; }
    slot = empty;
  }
  comps[slot].used = true;
  comps[slot].uid = uid;
  comps[slot].maxM = server.hasArg("max") ? (uint16_t)constrain(server.arg("max").toInt(), 10, 50000) : 200;
  comps[slot].alerted = false;
  if (server.hasArg("name")) {
    String nm = clipUtf8(server.arg("name"), 23);
    strncpy(comps[slot].name, nm.c_str(), 23); comps[slot].name[23] = 0;
  } else {
    Contact* c = findContact(uid);
    if (c && c->name[0]) { strncpy(comps[slot].name, c->name, 23); comps[slot].name[23] = 0; }
  }
  compSave();
  jokx(",\"m\":" + String(comps[slot].maxM));
}

// Sunset warning – phone posts the next sunset unix time
void handleSunsetWarn() {
  if (server.hasArg("on")) {
    sunsetWarnOn = server.arg("on").toInt() != 0;
    prefs.putBool("swo", sunsetWarnOn);
  }
  if (server.hasArg("m")) {
    sunsetWarnMin = (uint16_t)constrain(server.arg("m").toInt(), 5, 180);
    prefs.putUShort("swm", sunsetWarnMin);
  }
  if (server.hasArg("ep")) {
    nextSunsetEpoch = (uint32_t)strtoul(server.arg("ep").c_str(), nullptr, 10);
    prefs.putUInt("swep", nextSunsetEpoch);
    sunsetWarnedToday = false;
  }
  jokx(",\"on\":" + String(sunsetWarnOn ? 1 : 0) + ",\"m\":" + String(sunsetWarnMin) +
       ",\"ep\":" + String(nextSunsetEpoch));
}

// Daily repeating message
void handleDailyMsg() {
  if (server.hasArg("on")) dailyMsg.active = server.arg("on").toInt() != 0;
  if (server.hasArg("h")) dailyMsg.hour = (uint8_t)constrain(server.arg("h").toInt(), 0, 23);
  if (server.hasArg("m")) dailyMsg.minute = (uint8_t)constrain(server.arg("m").toInt(), 0, 59);
  if (server.hasArg("text")) {
    String tx = clipUtf8(server.arg("text"), 79);
    strncpy(dailyMsg.text, tx.c_str(), 79); dailyMsg.text[79] = 0;
  }
  dailyMsg.lastDay = 255;
  dailyMsgSave();
  jokx(",\"on\":" + String(dailyMsg.active ? 1 : 0));
}

// Button action mapping
void handleBtnMap() {
  if (server.hasArg("s")) btnSglAction = (uint8_t)constrain(server.arg("s").toInt(), 0, 7);
  if (server.hasArg("d")) btnDblAction = (uint8_t)constrain(server.arg("d").toInt(), 0, 7);
  if (server.hasArg("t")) btnTrpAction = (uint8_t)constrain(server.arg("t").toInt(), 0, 7);
  prefs.putUChar("btns", btnSglAction);
  prefs.putUChar("btnd", btnDblAction);
  prefs.putUChar("btnt", btnTrpAction);
  jokx(",\"s\":" + String(btnSglAction) + ",\"d\":" + String(btnDblAction) + ",\"t\":" + String(btnTrpAction));
}

// Home Wi-Fi STA + NTP
void handleSta() {
  if (server.hasArg("on")) staEnabled = server.arg("on").toInt() != 0;
  if (server.hasArg("ssid")) {
    String s = server.arg("ssid");
    s = s.substring(0, 32);
    strncpy(staSsid, s.c_str(), 32); staSsid[32] = 0;
  }
  if (server.hasArg("pass")) {
    String p = server.arg("pass");
    p = p.substring(0, 64);
    strncpy(staPass, p.c_str(), 64); staPass[64] = 0;
  }
  staSave();
  ntpDone = false;
  staConnected = false;
  staLastTry = millis();   // try soon
  if (staEnabled && staSsid[0]) {
    WiFi.mode(WIFI_AP_STA);
    WiFi.begin(staSsid, staPass);
  }
  jokx(",\"on\":" + String(staEnabled ? 1 : 0) + ",\"ok\":" + String(WiFi.status() == WL_CONNECTED ? 1 : 0));
}

// Shared checklist
void handleChecklist() {
  // action: set|toggle|clear|sync
  String act = server.arg("action");
  if (act == "clear") {
    memset(checklist, 0, sizeof(checklist));
    clRev++;
    checklistSave();
    if (server.arg("sync") != "0") checklistBroadcast();
    jokx(",\"cl\":" + checklistJson());
    return;
  }
  if (act == "sync") {
    checklistBroadcast();
    jok();
    return;
  }
  int idx = server.hasArg("i") ? server.arg("i").toInt() : -1;
  if (act == "toggle" && idx >= 0 && idx < MAX_CL_ITEMS && checklist[idx].used) {
    checklist[idx].done = !checklist[idx].done;
    clRev++;
    checklistSave();
    if (server.arg("sync") != "0") checklistBroadcast();
    jokx(",\"cl\":" + checklistJson());
    return;
  }
  if (act == "del" && idx >= 0 && idx < MAX_CL_ITEMS) {
    checklist[idx].used = false;
    checklist[idx].done = false;
    checklist[idx].text[0] = 0;
    clRev++;
    checklistSave();
    if (server.arg("sync") != "0") checklistBroadcast();
    jokx(",\"cl\":" + checklistJson());
    return;
  }
  // add / set text
  if (server.hasArg("text")) {
    String tx = clipUtf8(server.arg("text"), 39);
    if (idx < 0) {
      for (int i = 0; i < MAX_CL_ITEMS; i++) if (!checklist[i].used) { idx = i; break; }
    }
    if (idx < 0 || idx >= MAX_CL_ITEMS) { jerr(409, "Checklist full (max 8)"); return; }
    checklist[idx].used = true;
    checklist[idx].done = server.hasArg("done") && server.arg("done").toInt() != 0;
    strncpy(checklist[idx].text, tx.c_str(), 39);
    checklist[idx].text[39] = 0;
    clRev++;
    checklistSave();
    if (server.arg("sync") != "0") checklistBroadcast();
  }
  jokx(",\"cl\":" + checklistJson() + ",\"clr\":" + String(clRev));
}

// Admin PIN + remote command from this device
void handleAdmin() {
  if (server.hasArg("pin")) {
    String p = server.arg("pin");
    p.trim();
    if (p.length() < 4 || p.length() > 10) { jerr(400, "PIN must be 4–10 characters"); return; }
    strncpy(adminPin, p.c_str(), 11); adminPin[11] = 0;
    adminSave();
    jokx(",\"set\":1");
    return;
  }
  if (server.hasArg("clear") && server.arg("clear").toInt()) {
    adminPin[0] = 0;
    adminSave();
    jokx(",\"set\":0");
    return;
  }
  // send remote admin command: to, pin, cmd, arg
  if (server.hasArg("to") && server.hasArg("cmd") && server.hasArg("pin")) {
    uint32_t to = (uint32_t)strtoul(server.arg("to").c_str(), nullptr, 16);
    String payload = String("§AD:") + server.arg("pin") + ":" + server.arg("cmd");
    if (server.hasArg("arg")) payload += ":" + server.arg("arg");
    String err; uint16_t id = 0;
    int rc = sendTextCore(payload, 0, to, false, 0, 0, 0, err, id);
    if (rc) { jerr(rc, err); return; }
    jokx(",\"sent\":1");
    return;
  }
  jokx(",\"set\":" + String(adminPinSet ? 1 : 0));
}

void handlePathHome() {
  String act = server.arg("action");
  if (act == "stop" || act == "clear") { pathHomeStop(); jok(); return; }
  if (server.hasArg("la") && server.hasArg("lo")) {
    int32_t la = (int32_t)(server.arg("la").toDouble() * 1e6);
    int32_t lo = (int32_t)(server.arg("lo").toDouble() * 1e6);
    if (!pathHomeStartAt(la, lo)) { jerr(400, "Invalid position"); return; }
  } else if (contacts[0].hasLoc) {
    pathHomeStart();
  } else {
    jerr(400, "No GPS position yet. Allow location in the browser first.");
    return;
  }
  jokx(",\"la\":" + String(pathHome.lat) + ",\"lo\":" + String(pathHome.lon));
}

void handleRally() {
  String act = server.arg("action");
  if (act == "clear") { rallyClear(); jok(); return; }
  if (act == "sync") { rallyBroadcast(); jok(); return; }
  int32_t la = 0, lo = 0;
  if (server.hasArg("la") && server.hasArg("lo")) {
    // accept microdegrees or degrees
    double dla = server.arg("la").toDouble();
    double dlo = server.arg("lo").toDouble();
    if (fabs(dla) <= 90 && fabs(dlo) <= 180) { la = (int32_t)(dla * 1e6); lo = (int32_t)(dlo * 1e6); }
    else { la = (int32_t)dla; lo = (int32_t)dlo; }
  } else if (contacts[0].hasLoc) {
    la = contacts[0].lat; lo = contacts[0].lon;
  } else {
    jerr(400, "Need coordinates or your GPS position");
    return;
  }
  String nm = server.hasArg("name") ? clipUtf8(server.arg("name"), 31) : String("Rally");
  rallySet(la, lo, nm.c_str());
  if (server.arg("sync") != "0") rallyBroadcast();
  jokx(",\"la\":" + String(la) + ",\"lo\":" + String(lo));
}

void handleGateway() {
  if (server.hasArg("on")) {
    bool on = server.arg("on").toInt() != 0;
    if (on && !gwEnabled) {                       // just switched on: do not forward old history
      for (int i = 0; i < MAX_MSGS; i++) if (msgLog[i].seq > gwLastSeq) gwLastSeq = msgLog[i].seq;
    }
    gwEnabled = on;
  }
  if (server.hasArg("mask")) gwMask = (uint8_t)(server.arg("mask").toInt() & 0x1F);
  if (server.hasArg("url")) {
    String u = server.arg("url");
    u = u.substring(0, 127);
    strncpy(gwUrl, u.c_str(), 127); gwUrl[127] = 0;
  }
  if (server.hasArg("chat")) {
    String c = server.arg("chat");
    c = c.substring(0, 47);
    strncpy(gwChat, c.c_str(), 47); gwChat[47] = 0;
  }
  gwSave();
  if (server.hasArg("test") && server.arg("test").toInt()) {
    if (!gwUrl[0]) { jerr(400, "Enter the webhook URL first"); return; }
    if (!staConnected) { jerr(409, "Home Wi-Fi is not connected yet (see Home Wi-Fi & NTP)"); return; }
    gwQueue("LoRa Messenger gateway test from " + myName, GWD_TG, true);
  }
  jokx(",\"on\":" + String(gwEnabled ? 1 : 0) + ",\"mask\":" + String(gwMask));
}

static bool gwTestReady(const char* what) {
  if (!staConnected) { jerr(409, "Home Wi-Fi is not connected yet (see Home Wi-Fi & NTP)"); return false; }
  return true;
}

// Bale: Telegram-compatible bot API (works without a VPN in Iran)
void handleGwBale() {
  if (server.hasArg("on")) gwBaleOn = server.arg("on").toInt() != 0;
  if (server.hasArg("url")) gwCopy(gwBaleUrl, sizeof(gwBaleUrl), server.arg("url").substring(0, 127));
  if (server.hasArg("chat")) gwCopy(gwBaleChat, sizeof(gwBaleChat), server.arg("chat").substring(0, 47));
  gwSaveExt();
  if (server.hasArg("test") && server.arg("test").toInt()) {
    if (!gwBaleUrl[0]) { jerr(400, "Enter the Bale URL first"); return; }
    if (!gwTestReady("Bale")) return;
    gwQueue("LoRa Messenger gateway test from " + myName, GWD_BALE, true);
  }
  jokx(",\"on\":" + String(gwBaleOn ? 1 : 0));
}

// E-mail (SMTP)
void handleGwMail() {
  if (server.hasArg("on")) gwMailOn = server.arg("on").toInt() != 0;
  if (server.hasArg("host")) { String h = server.arg("host"); h.trim(); gwCopy(gwMailHost, sizeof(gwMailHost), h.substring(0, 47)); }
  if (server.hasArg("port")) { int p = server.arg("port").toInt(); gwMailPort = (p > 0 && p < 65536) ? (uint16_t)p : 465; }
  if (server.hasArg("user")) gwCopy(gwMailUser, sizeof(gwMailUser), server.arg("user").substring(0, 63));
  if (server.hasArg("pass") && server.arg("pass").length()) gwCopy(gwMailPass, sizeof(gwMailPass), server.arg("pass").substring(0, 63));
  if (server.hasArg("clearpass") && server.arg("clearpass").toInt()) gwMailPass[0] = 0;
  if (server.hasArg("from")) { String f = server.arg("from"); f.trim(); gwCopy(gwMailFrom, sizeof(gwMailFrom), f.substring(0, 63)); }
  if (server.hasArg("to")) { String t = server.arg("to"); t.trim(); gwCopy(gwMailTo, sizeof(gwMailTo), t.substring(0, 95)); }
  gwSaveExt();
  if (server.hasArg("test") && server.arg("test").toInt()) {
    if (!gwMailHost[0] || !gwMailTo[0]) { jerr(400, "Enter the SMTP server and the recipient first"); return; }
    if (!gwTestReady("E-mail")) return;
    gwQueue("LoRa Messenger gateway test from " + myName, GWD_MAIL, true);
  }
  jokx(",\"on\":" + String(gwMailOn ? 1 : 0));
}

// Proxy list for Telegram. action=add (type,host,port,user,pass) | del (i) | use (on)
void handleGwProxy() {
  String act = server.arg("action");
  if (act == "use") {
    gwUseProxy = server.arg("on").toInt() != 0;
  } else if (act == "del") {
    int i = server.arg("i").toInt();
    if (i >= 0 && i < GW_PROXIES) { memset(&gwPx[i], 0, sizeof(gwPx[i])); gwPxGood = -1; }
  } else if (act == "add") {
    int type = server.arg("type").toInt();
    String host = server.arg("host"); host.trim();
    int port = server.arg("port").toInt();
    if (type != 1 && type != 2) { jerr(400, "Choose SOCKS5 or HTTP/HTTPS"); return; }
    if (host.length() < 3) { jerr(400, "Enter the proxy address"); return; }
    if (port < 1 || port > 65535) { jerr(400, "Enter a valid proxy port (1-65535)"); return; }
    int slot = -1;
    for (int i = 0; i < GW_PROXIES; i++) if (!gwPx[i].type) { slot = i; break; }
    if (slot < 0) { jerr(409, "Up to 3 proxies. Delete one first."); return; }
    host.replace("\t", ""); host.replace("\n", "");
    String user = server.arg("user"), pass = server.arg("pass");
    user.replace("\t", ""); pass.replace("\t", "");
    memset(&gwPx[slot], 0, sizeof(gwPx[slot]));
    gwPx[slot].type = (uint8_t)type;
    gwCopy(gwPx[slot].host, sizeof(gwPx[slot].host), host.substring(0, 47));
    gwPx[slot].port = (uint16_t)port;
    gwCopy(gwPx[slot].user, sizeof(gwPx[slot].user), user.substring(0, 32));
    gwCopy(gwPx[slot].pass, sizeof(gwPx[slot].pass), pass.substring(0, 32));
  } else {
    jerr(400, "Unknown action");
    return;
  }
  gwSaveExt();
  jok();
}

void featRoutes() {
  server.on("/api/msgdel", HTTP_POST, LG(handleMsgDel));
  server.on("/api/morse", HTTP_POST, G(handleMorse));
  server.on("/api/morsestop", HTTP_POST, G(handleMorseStop));
  server.on("/api/morseremote", HTTP_POST, G(handleMorseRemote));
  server.on("/api/morseremotecfg", HTTP_POST, G(handleMorseRemoteCfg));
  server.on("/api/quiet", HTTP_POST, G(handleQuiet));
  server.on("/api/finddev", HTTP_POST, G(handleFindDev));
  server.on("/api/mtud", HTTP_POST, G(handleMtUd));
  server.on("/api/rf", HTTP_POST, G(handleRf));
  server.on("/api/comp", HTTP_POST, G(handleComp));
  server.on("/api/sunsetwarn", HTTP_POST, G(handleSunsetWarn));
  server.on("/api/daily", HTTP_POST, G(handleDailyMsg));
  server.on("/api/btnmap", HTTP_POST, G(handleBtnMap));
  server.on("/api/sta", HTTP_POST, G(handleSta));
  server.on("/api/checklist", HTTP_POST, G(handleChecklist));
  server.on("/api/admin", HTTP_POST, G(handleAdmin));
  server.on("/api/pathhome", HTTP_POST, G(handlePathHome));
  server.on("/api/rally", HTTP_POST, G(handleRally));
  server.on("/api/gateway", HTTP_POST, G(handleGateway));
  server.on("/api/gwbale", HTTP_POST, G(handleGwBale));
  server.on("/api/gwmail", HTTP_POST, G(handleGwMail));
  server.on("/api/gwproxy", HTTP_POST, G(handleGwProxy));
  server.on("/api/hw", HTTP_POST, G(handleHw));
  server.on("/api/hwtest", HTTP_POST, G(handleHwTest));
  server.on("/api/doctor", HTTP_GET, G(handleDoctor));
  server.on("/api/soscancel", HTTP_POST, LG(handleSosCancel));
  server.on("/api/alertclr", HTTP_POST, G(handleAlertClr));
  server.on("/api/watch", HTTP_POST, G(handleWatch));
  server.on("/api/geo", HTTP_POST, G(handleGeo));
  server.on("/api/ci", HTTP_POST, G(handleCheckIn));
  server.on("/api/ops", HTTP_POST, G(handleOps));
  server.on("/api/auth/register", HTTP_POST, handleAuthRegister);
  server.on("/api/auth/login", HTTP_POST, handleAuthLogin);
  server.on("/api/auth/logout", HTTP_POST, handleAuthLogout);
  server.on("/api/auth/cfg", HTTP_POST, handleAuthCfg);
  server.on("/api/auth/me", HTTP_GET, handleAuthMe);
  server.on("/api/auth/admin", HTTP_POST, handleAdminLogin);
  server.on("/api/avatar", HTTP_POST, handleAvatar);
  server.on("/api/unlock", HTTP_POST, LG(handleUnlock));
  server.on("/api/spec", HTTP_GET, G(handleSpec));
  server.on("/api/ltest", HTTP_POST, G(handleLtest));
  server.on("/api/ltstat", HTTP_GET, G(handleLtStat));
  server.on("/api/adr", HTTP_GET, G(handleAdr));
}
