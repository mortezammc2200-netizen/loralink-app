// meshtastic.h - Meshtastic interoperability layer for LoRa Messenger.
// Included by lora_messenger.ino after the message log / contacts / forward queue exist.
//
// When "Meshtastic mode" is on the radio speaks the real Meshtastic over-the-air protocol,
// so this node shows up as a normal node on a Meshtastic mesh:
//   * text messages (public channel + direct messages with ACK/retry), replies
//   * node discovery (NodeInfo), positions (map / distance / bearing), ping
//   * optional rebroadcast (hop-limited flooding) with duplicate suppression
// Not available in this mode (Meshtastic has no equivalent): edit, delete, read receipts,
// private channels, long-text fragmentation (long texts are split into separate messages).
#pragma once
#include "mt_core.h"

#define MT_TEXT_MAX      200            // bytes of text per packet (same limit the Meshtastic apps use)
#define MT_Q             6
#define MT_MAX_SENDS     4              // first transmission + 3 retries (same as Meshtastic)
#define MT_DUTY_MS       360000UL       // 10 % duty cycle (EU_433 limit used by Meshtastic): ms per hour

struct MtOut {
  bool used, wantAck;
  uint8_t len, part, sends;
  uint32_t due, pid, to;
  uint16_t logId;                        // id16 of the log message (0 = untracked)
  uint8_t buf[MT_MAX_PKT];
};
MtOut    mtQ[MT_Q];
uint64_t mtSeen[64];
int      mtSeenHead = 0;
uint32_t mtIdCtr = 0;
uint8_t  mtRaw[32];                      // PSK as the user gave it (1 byte = Meshtastic "short key" index)
int      mtRawLen = 1;

static const char* const MT_QUICK[8] = {"OK", "No", "Yes", "On my way", "Waiting", "Help!", "Thanks", "Call me"};

// ---------------------------------------------------------------- settings ----
String mtEffName() { return mtChName.length() ? mtChName : String(MT_PRESETS[mtPreset].name); }

void mtRecalc() {
  mtKeyLen = mtExpandKey(mtRaw, mtRawLen, mtKey);
  String n = mtEffName();
  mtHash = mtChannelHash(n.c_str(), mtKey, mtKeyLen);
}

uint32_t mtCurFreqHz() {
  if (mtFreqOvrKhz) return mtFreqOvrKhz * 1000UL;
  String n = mtEffName();
  return mtFreqHz(mtPreset, n.c_str(), mtSlot);
}

void mtSave() {
  prefs.putBool("mmode", meshMode);
  prefs.putInt("mtpre", mtPreset);
  prefs.putString("mtname", mtChName);
  prefs.putBytes("mtpsk", mtRaw, mtRawLen);
  prefs.putUChar("mtslot", mtSlot);
  prefs.putUChar("mthop", mtHop);
  prefs.putULong("mtfq", mtFreqOvrKhz);
}

void mtLoad() {
  meshMode = prefs.getBool("mmode", false);
  mtPreset = prefs.getInt("mtpre", 0);
  if (!mtPresetValid(mtPreset)) mtPreset = 0;
  mtChName = prefs.getString("mtname", "");
  size_t l = prefs.getBytesLength("mtpsk");
  if (l >= 1 && l <= 32 && prefs.getBytes("mtpsk", mtRaw, l) == l) mtRawLen = (int)l;
  else { mtRaw[0] = 1; mtRawLen = 1; }
  mtSlot = prefs.getUChar("mtslot", 0);
  mtHop = prefs.getUChar("mthop", 3);
  if (mtHop < 1 || mtHop > 7) mtHop = 3;
  mtFreqOvrKhz = prefs.getULong("mtfq", 0);
  if (mtFreqOvrKhz && (mtFreqOvrKhz < FREQ_MIN_KHZ || mtFreqOvrKhz > FREQ_MAX_KHZ)) mtFreqOvrKhz = 0;
  mtIdCtr = esp_random();
  mtRecalc();
}

// "default" / "" -> public default key, "none" -> no encryption, otherwise base64 (16 or 32 byte key)
bool mtSetPsk(String s) {
  s.trim();
  String low = s;
  low.toLowerCase();
  if (low == "" || low == "default" || low == "aq==" || low == "aq") { mtRaw[0] = 1; mtRawLen = 1; return true; }
  if (low == "none" || low == "off" || low == "aa==") { mtRaw[0] = 0; mtRawLen = 1; return true; }
  uint8_t tmp[40];
  int n = mtB64Decode(s.c_str(), s.length(), tmp, 33);
  if (n < 1 || n > 32) return false;
  memcpy(mtRaw, tmp, n);
  mtRawLen = n;
  return true;
}

// Accepts a Meshtastic share link (https://meshtastic.org/e/#...) or the bare base64 part.
bool mtApplyUrl(String u) {
  u.trim();
  int h = u.lastIndexOf('#');
  if (h >= 0) u = u.substring(h + 1);
  uint8_t raw[300];
  int n = mtB64Decode(u.c_str(), u.length(), raw, sizeof(raw));
  if (n < 2) return false;
  MtChanCfg c;
  if (!mtParseChannelSet(raw, n, c)) return false;
  if (c.hasPreset) mtPreset = mtPresetValid(c.preset) ? c.preset : 0;
  mtChName = String(c.name);
  if (c.keyLen == 0) { mtRaw[0] = 0; mtRawLen = 1; }       // empty PSK in a channel = encryption off
  else { memcpy(mtRaw, c.key, c.keyLen); mtRawLen = c.keyLen; }
  if (c.hasHop) mtHop = c.hop;
  mtSlot = c.hasSlot ? (uint8_t)c.slot : 0;
  mtFreqOvrKhz = 0;
  return true;
}

String mtKeyKind() {
  if (mtRawLen == 1 && mtRaw[0] == 0) return "none";
  if (mtRawLen == 1) return mtRaw[0] == 1 ? "default" : "default+" + String(mtRaw[0] - 1);
  return String(mtKeyLen * 8) + "-bit";
}

// -------------------------------------------------------------------- misc ----
bool mtDutyOk() { return airHour() < MT_DUTY_MS; }

int mtPending() {
  int n = 0;
  for (int i = 0; i < MT_Q; i++) if (mtQ[i].used) n++;
  return n;
}
int mtFree() { return MT_Q - mtPending(); }

uint32_t mtNewIds(int n) {
  uint32_t base = mtIdCtr + 1;
  if (base == 0) base = 1;
  mtIdCtr = base + n - 1;
  return base;
}

bool mtSeenBefore(uint32_t from, uint32_t id) {
  uint64_t k = ((uint64_t)from << 32) | id;
  for (int i = 0; i < 64; i++) if (mtSeen[i] == k) return true;
  mtSeen[mtSeenHead] = k;
  mtSeenHead = (mtSeenHead + 1) & 63;
  return false;
}

Msg* mtFindByPid(uint32_t pid, uint8_t* part) {
  for (int i = 0; i < MAX_MSGS; i++) {
    Msg& m = msgLog[i];
    if (!m.seq || m.dir != 'O' || !m.pid) continue;
    uint32_t d = pid - m.pid;
    if (d < (uint32_t)(m.partsTotal ? m.partsTotal : 1)) { if (part) *part = (uint8_t)d; return &m; }
  }
  return nullptr;
}

Msg* mtFindAny(uint32_t uid, uint16_t id) {
  for (int i = 0; i < MAX_MSGS; i++)
    if (msgLog[i].seq && msgLog[i].dir != 'S' && msgLog[i].uid == uid && msgLog[i].id == id) return &msgLog[i];
  return nullptr;
}

Contact* mtContact(uint32_t node) {
  Contact* c = findContact(node);
  if (!c) {
    c = addContact(node);
    snprintf(c->name, sizeof(c->name), "!%08x", (unsigned)node);
  }
  return c;
}

// ------------------------------------------------------------------ queueing ----
int mtQueue(uint32_t delayMs, const uint8_t* pkt, int len, uint32_t pid, uint32_t to,
            uint16_t logId, uint8_t part, bool wantAck) {
  for (int i = 0; i < MT_Q; i++) {
    if (mtQ[i].used) continue;
    MtOut& o = mtQ[i];
    o.used = true; o.wantAck = wantAck; o.len = len; o.part = part; o.sends = 0;
    o.due = millis() + delayMs; o.pid = pid; o.to = to; o.logId = logId;
    memcpy(o.buf, pkt, len);
    return i;
  }
  return -1;
}

int mtMake(uint8_t* out, uint32_t to, uint32_t id, bool wantAck, uint32_t port, const uint8_t* pl, int plen,
           bool wantResp, uint32_t reqId, uint32_t replyId) {
  uint8_t d[MT_MAX_PKT];
  int dl = mtBuildData(d, sizeof(d), port, pl, plen, wantResp, reqId, replyId);
  if (dl < 0) return -1;
  return mtBuildPacket(out, to, myUid, id, mtHop, wantAck, mtHash, (uint8_t)myUid, mtKey, mtKeyLen, d, dl);
}

void mtSendAck(uint32_t to, uint32_t reqId) {
  uint8_t r[2] = {0x18, 0x00};                       // Routing { error_reason = NONE }
  uint8_t pkt[MT_MAX_PKT];
  uint32_t id = mtNewIds(1);
  int n = mtMake(pkt, to, id, false, MT_PORT_ROUTING, r, 2, false, reqId, 0);
  if (n > 0) mtQueue(random(120, 500), pkt, n, id, to, 0, 0, false);
}

void mtSendNodeInfo(uint32_t to, bool wantResp) {
  char id[12], sn[8];
  snprintf(id, sizeof(id), "!%08x", (unsigned)myUid);
  snprintf(sn, sizeof(sn), "%04x", (unsigned)(myUid & 0xFFFF));
  uint8_t u[96];
  String ln = clipUtf8(myName, 24);
  int ul = mtBuildUser(u, sizeof(u), id, ln.c_str(), sn);
  if (ul < 0) return;
  uint8_t pkt[MT_MAX_PKT];
  uint32_t pid = mtNewIds(1);
  int n = mtMake(pkt, to, pid, false, MT_PORT_NODEINFO, u, ul, wantResp, 0, 0);
  if (n > 0) mtQueue(random(200, 1200), pkt, n, pid, to, 0, 0, false);
}

// la / lo are degrees * 1e6 (the sketch's format); Meshtastic wants degrees * 1e7.
// pid = 0 allocates a new packet id; logId != 0 links the packet to a log message (marked sent after TX).
void mtSendPosition(int32_t la, int32_t lo, uint32_t to, uint32_t pid, uint16_t logId) {
  uint8_t p[24];
  int pl = mtBuildPosition(p, la * 10, lo * 10, nowEpoch());
  uint8_t pkt[MT_MAX_PKT];
  if (!pid) pid = mtNewIds(1);
  int n = mtMake(pkt, to, pid, false, MT_PORT_POSITION, p, pl, false, 0, 0);
  if (n > 0) mtQueue(random(100, 600), pkt, n, pid, to, logId, 0, false);
}

// Splits UTF-8 text into <= MT_TEXT_MAX byte pieces without cutting a character.
int mtSplit(const String& t, int starts[], int lens[], int maxParts) {
  int n = t.length(), pos = 0, parts = 0;
  while (pos < n) {
    if (parts >= maxParts) return -1;
    int end = pos + MT_TEXT_MAX;
    if (end >= n) end = n;
    else while (end > pos && (((uint8_t)t[end]) & 0xC0) == 0x80) end--;
    if (end <= pos) return -1;
    starts[parts] = pos; lens[parts] = end - pos; parts++;
    pos = end;
  }
  return parts;
}

// Sends a text-based chat message and logs it. Returns 0 on success, otherwise an HTTP-style error code.
int mtSendMsg(uint8_t kind, const String& uiText, const String& wire, uint32_t dst, bool hasReply,
              uint32_t rUid, uint16_t rId, bool reliable, String& err, uint16_t& idOut) {
  int st[3], ln[3];
  int np = mtSplit(wire, st, ln, 3);
  if (np <= 0) { err = "Message is too long"; return 413; }
  if (mtFree() < np + 1) { err = "Send queue is full, wait a moment"; return 429; }
  uint32_t to = dst ? dst : MT_BROADCAST;
  uint32_t replyPid = 0;
  if (hasReply) { Msg* r = mtFindAny(rUid, rId); if (r && r->pid) replyPid = r->pid; }
  uint32_t base = mtNewIds(np);
  Msg* m = addMsg('O', kind, myUid, (uint16_t)base);
  m->pid = base; m->dst = dst; m->partsTotal = np; m->text = uiText;
  if (hasReply) { m->hasReply = true; m->rUid = rUid; m->rId = rId; }
  bool ack = (dst != 0) || reliable;                  // DMs: explicit ACK; reliable broadcast: heard-back by a relay
  uint32_t d0 = 60 + random(0, 200);                  // same start for all parts: they must go out in order (no reassembly in Meshtastic)
  for (int i = 0; i < np; i++) {
    uint8_t pkt[MT_MAX_PKT];
    String piece = wire.substring(st[i], st[i] + ln[i]);
    int n = mtMake(pkt, to, base + i, ack, MT_PORT_TEXT, (const uint8_t*)piece.c_str(), ln[i], false, 0, i == 0 ? replyPid : 0);
    if (n < 0) { err = "Message is too long"; m->status = 2; return 413; }
    mtQueue(d0 + i * 40, pkt, n, base + i, to, (uint16_t)base, (uint8_t)i, ack);
  }
  idOut = (uint16_t)base;
  return 0;
}

// --------------------------------------------------------------- ack handling ----
void mtDropMsgSlots(uint16_t logId) {
  for (int i = 0; i < MT_Q; i++) if (mtQ[i].used && mtQ[i].logId == logId) mtQ[i].used = false;
}

void mtMarkPart(Msg* m, uint8_t part, uint32_t from) {
  if (from) {
    bool known = false;
    for (int k = 0; k < MAX_ACKBY; k++) if (m->ackBy[k] == from) known = true;
    if (!known) for (int k = 0; k < MAX_ACKBY; k++) if (!m->ackBy[k]) { m->ackBy[k] = from; break; }
  }
  if (m->acks < 250) m->acks++;
  m->partsMask |= (uint8_t)(1u << part);
  uint8_t total = m->partsTotal ? m->partsTotal : 1;
  uint8_t full = (uint8_t)((1u << total) - 1);
  if ((m->partsMask & full) == full && m->status == 0) m->status = 1;
  touch(m);
}

void mtOnAck(uint32_t from, uint32_t pid, bool ok) {
  for (int i = 0; i < MT_Q; i++) {
    if (!mtQ[i].used || !mtQ[i].wantAck || mtQ[i].pid != pid) continue;
    uint16_t logId = mtQ[i].logId;
    mtQ[i].used = false;
    uint8_t part = 0;
    Msg* m = mtFindByPid(pid, &part);
    if (m) {
      if (ok) mtMarkPart(m, part, from);
      else { m->status = 2; touch(m); cFail++; if (logId) mtDropMsgSlots(logId); }
    }
    return;
  }
}

// our own packet heard again from a neighbour that rebroadcast it (= implicit ACK)
void mtOnEcho(const MtHdr& h) {
  for (int i = 0; i < MT_Q; i++) {
    if (mtQ[i].used && mtQ[i].wantAck && mtQ[i].pid == h.id && mtQ[i].to == MT_BROADCAST) { mtOnAck(0, h.id, true); return; }
  }
  Msg* m = mtFindByPid(h.id, nullptr);
  if (m && m->acks < 250) { m->acks++; touch(m); }
}

// --------------------------------------------------------------------- relay ----
void mtScheduleRelay(const uint8_t* w, int n, const MtHdr& h) {
  for (int i = 0; i < MAX_FWD; i++) {
    if (fwdQ[i].used) continue;
    fwdQ[i].used = true;
    fwdQ[i].uid = h.from;
    fwdQ[i].ctr = h.id;
    fwdQ[i].len = n;
    fwdQ[i].due = millis() + random(400, 2200);
    memcpy(fwdQ[i].buf, w, n);
    fwdQ[i].buf[12] = (uint8_t)((w[12] & 0xF8) | (h.hopLimit - 1));    // hop_start / want_ack / mqtt bits unchanged
    fwdQ[i].buf[15] = (uint8_t)myUid;                                   // relay_node
    return;
  }
}

// ------------------------------------------------------------------- receive ----
void mtHandle(uint8_t* w, int n, int rssi, float snrF) {
  cRx++;
  lastRxAt = millis();
  MtHdr h;
  if (!mtParseHeader(w, n, h)) { cForeign++; return; }
  if (h.from == myUid) { mtOnEcho(h); return; }
  if (h.chan != mtHash) { cForeign++; return; }        // another channel / key on this frequency
  bool forMe = (h.to == myUid), bcast = (h.to == MT_BROADCAST);
  if (mtSeenBefore(h.from, h.id)) {
    cDup++;
    cancelForward(h.from, h.id);                        // somebody already relayed it
    if (forMe && h.wantAck) mtSendAck(h.from, h.id);    // our ACK may have been lost
    return;
  }
  int plen = n - MT_HDR;
  uint8_t plain[MT_MAX_PKT];
  memcpy(plain, w + MT_HDR, plen);
  mtCrypt(mtKey, mtKeyLen, h.from, h.id, plain, plen);
  MtData d;
  if (!mtParseData(plain, plen, d)) { cAuth++; return; }    // wrong key or not a Meshtastic packet
  cOk++;
  int snr = (int)lroundf(snrF);
  Contact* c = mtContact(h.from);
  c->lastSeen = millis() ? millis() : 1;
  c->rssi = rssi; c->snr = snr; c->rxCount++;
  avgRssi = (avgRssi * 7.0f + rssi) / 8.0f;
  featHeard(h.from, c, rssi, snr);
  lastOkAt = millis();

  if (forMe || bcast) {
    switch (d.port) {
      case MT_PORT_TEXT: {
        if (d.plen <= 0) break;
        String t;
        t.reserve(d.plen);
        for (int i = 0; i < d.plen; i++) t += (char)d.pl[i];
        t = clipUtf8(t, MAX_TEXT_BYTES);
        t.trim();
        if (!t.length()) break;
        curDst = forMe ? myUid : 0;
        if (t.startsWith("!UD!")) { mtUserDirRx(c, t); break; }       // user directory of the other device (its web users)
        // remote Morse control / status (Meshtastic path)
        if (handleMorseControlText(c, t, (uint16_t)h.id, rssi, snr)) {
          if (forMe && h.wantAck) mtSendAck(h.from, h.id);
          break;
        }
        quietIncoming = isCtlText(t);
        Msg* m = newIncoming(c, K_TEXT, (uint16_t)h.id, rssi, snr);
        quietIncoming = false;
        m->pid = h.id;
        m->text = t;
        routeIncomingToUser(m);                                        // "[from→user] text" goes to that web user only
        if (d.replyId) {
          for (int i = 0; i < MAX_MSGS; i++) {
            Msg& r = msgLog[i];
            if (r.seq && r.pid == d.replyId && r.dir != 'S') { m->hasReply = true; m->rUid = r.uid; m->rId = r.id; break; }
          }
        }
        ledUntil = millis() + 120;
        if (forMe && h.wantAck) mtSendAck(h.from, h.id);
        break;
      }
      case MT_PORT_POSITION: {
        int32_t la, lo;
        if (mtParsePosition(d.pl, d.plen, la, lo)) setContactLoc(c, la / 10, lo / 10, 0);
        break;
      }
      case MT_PORT_NODEINFO: {
        MtUser u;
        if (mtParseUser(d.pl, d.plen, u)) {
          String nm = clipUtf8(String(u.longName[0] ? u.longName : u.shortName), 39);
          if (nm.length()) { strncpy(c->name, nm.c_str(), sizeof(c->name) - 1); c->name[sizeof(c->name) - 1] = 0; }
        }
        if (pingPend.active && (!pingPend.dst || pingPend.dst == c->uid)) {
          pingPend.replies++;
          sysLineTo("Reply from " + String(c->name) + " | " + String(rssi) + " dBm, SNR " + String(snr) + " (" + qualityFa(rssi) + ")", pingScope());
        }
        if (d.wantResp) mtSendNodeInfo(h.from, false);
        break;
      }
      case MT_PORT_RANGETEST:
        if (bcast) featLtMesh(c, d.pl, d.plen, rssi, snr);
        break;
      case MT_PORT_ROUTING:
        if (forMe && d.reqId) mtOnAck(h.from, d.reqId, mtRoutingIsAck(d.pl, d.plen));
        break;
      default: break;
    }
  }
  if (relayOn && !forMe && h.hopLimit > 0) mtScheduleRelay(w, n, h);
}

// ------------------------------------------------------------------- service ----
void mtService() {
  uint32_t now = millis();
  for (int i = 0; i < MT_Q; i++) {
    MtOut& o = mtQ[i];
    if (!o.used || (int32_t)(now - o.due) < 0) continue;
    if (!mtDutyOk()) { o.due = now + 30000UL; continue; }          // out of airtime budget: wait
    txRaw(o.buf, o.len);
    o.sends++;
    if (o.wantAck) {
      if (o.sends > 1) cRetry++;
      if (o.sends >= MT_MAX_SENDS) {                                // gave up
        uint16_t logId = o.logId;
        uint8_t part = o.part;
        (void)part;
        Msg* m = logId ? findMsg(myUid, logId, 'O') : nullptr;
        if (m && m->status == 0) { m->status = 2; touch(m); cFail++; }
        if (logId) mtDropMsgSlots(logId); else o.used = false;
      } else {
        o.due = millis() + 7000UL + (uint32_t)airtimeMs(o.len) * 2 + random(0, 3000);
      }
    } else {
      o.used = false;
      if (o.logId) {                                                // plain broadcast: sent = done
        Msg* m = findMsg(myUid, o.logId, 'O');
        if (m) mtMarkPart(m, o.part, 0);
      }
    }
    return;                                                         // one transmission per loop pass
  }
}

// Contacts of the mode we are leaving are kept (lightweight copy) and restored when we come back.
struct StashC { uint32_t uid, lastCtr; char name[40]; bool relayOn, hasLoc; int32_t lat, lon; uint16_t acc; };
StashC cstash[2][MAX_CONTACTS];                 // [0] = LoRa Link, [1] = Meshtastic

void mtStashSwap() {                            // call after meshMode has been changed
  int from = meshMode ? 0 : 1, to = meshMode ? 1 : 0, k = 0;
  memset(cstash[from], 0, sizeof(cstash[from]));
  for (int i = 1; i < MAX_CONTACTS; i++) {
    if (!contacts[i].used) continue;
    StashC& s = cstash[from][k++];
    s.uid = contacts[i].uid; s.lastCtr = contacts[i].lastCtr; s.relayOn = contacts[i].relayOn;
    s.hasLoc = contacts[i].hasLoc; s.lat = contacts[i].lat; s.lon = contacts[i].lon; s.acc = contacts[i].acc;
    strncpy(s.name, contacts[i].name, sizeof(s.name) - 1);
    contacts[i].used = false;
  }
  for (int j = 0, slot = 1; j < MAX_CONTACTS && slot < MAX_CONTACTS; j++) {
    const StashC& s = cstash[to][j];
    if (!s.uid) continue;
    Contact* c = &contacts[slot++];
    initContact(c, s.uid);                      // lastSeen = 0: shown as "not heard yet" until it talks again
    strncpy(c->name, s.name, sizeof(c->name) - 1);
    c->lastCtr = s.lastCtr; c->relayOn = s.relayOn; c->hasLoc = s.hasLoc; c->lat = s.lat; c->lon = s.lon; c->acc = s.acc;
  }
}

// Called when switching between native and Meshtastic mode: drop everything that belongs to the old mode.
void mtResetState() {
  for (int i = 0; i < MT_Q; i++) mtQ[i].used = false;
  for (int i = 0; i < MAX_FWD; i++) fwdQ[i].used = false;
  for (int i = 0; i < MAX_DEFER; i++) defQ[i].used = false;
  mtStashSwap();
  for (int i = 0; i < MAX_ASM; i++) asmb[i].used = false;
  memset(mtSeen, 0, sizeof(mtSeen));
  qCount = 0; pend.active = false; rdCount = 0; pingPend.active = false;
}
