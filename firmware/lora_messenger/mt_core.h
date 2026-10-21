// mt_core.h - Meshtastic wire-protocol core (no Arduino dependencies).
// Verified against github.com/meshtastic/firmware (RadioInterface / CryptoEngine /
// Channels) and meshtastic/protobufs.
//
//  LoRa packet = 16-byte header (little endian) + AES-CTR encrypted protobuf "Data"
//    to(4) from(4) id(4) flags(1) channelHash(1) nextHop(1) relayNode(1)
//    flags : bits0-2 hop_limit, bit3 want_ack, bit4 via_mqtt, bits5-7 hop_start
//  AES-CTR nonce (16 B) = id(8, LE) | from(4, LE) | 0(4)
//  Channel hash = xor(name bytes) ^ xor(expanded key bytes)
//  PHY: sync word 0x2B, preamble 16, CRC on, explicit header.
#pragma once
#include <stdint.h>
#include <string.h>
#include <mbedtls/aes.h>

#define MT_BROADCAST   0xFFFFFFFFUL
#define MT_HDR         16
#define MT_MAX_PKT     255
#define MT_SYNC_WORD   0x2B
#define MT_PREAMBLE    16

// Power cap applied in Meshtastic mode (EU_433 limit used by the Meshtastic firmware). Raise at your own risk.
#define MT_MAX_TX_DBM    10

#define MT_PORT_TEXT     1
#define MT_PORT_POSITION 3
#define MT_PORT_NODEINFO 4
#define MT_PORT_ROUTING  5
#define MT_PORT_RANGETEST 66

// EU_433 region as defined by Meshtastic: 433.000 - 434.000 MHz
#define MT_REGION_START_HZ 433000000UL
#define MT_REGION_SPAN_HZ    1000000UL

static const uint8_t MT_DEFAULT_PSK[16] = {0xd4, 0xf1, 0xbb, 0x3a, 0x20, 0x29, 0x07, 0x59,
                                           0xf0, 0xbc, 0xff, 0xab, 0xcf, 0x4e, 0x69, 0x01};

// ---------------------------------------------------------------- presets ----
// Index = Meshtastic ModemPreset enum value. 2 (VERY_LONG_SLOW) behaves as LongFast.
struct MtPresetDef { const char* name; uint32_t bwHz; uint8_t sf; uint8_t cr; };
static const MtPresetDef MT_PRESETS[10] = {
  {"LongFast",   250000, 11, 5},   // 0
  {"LongSlow",   125000, 12, 8},   // 1
  {"LongFast",   250000, 11, 5},   // 2 (deprecated)
  {"MediumSlow", 250000, 10, 5},   // 3
  {"MediumFast", 250000,  9, 5},   // 4
  {"ShortSlow",  250000,  8, 5},   // 5
  {"ShortFast",  250000,  7, 5},   // 6
  {"LongMod",    125000, 11, 8},   // 7
  {"ShortTurbo", 500000,  7, 5},   // 8
  {"LongTurbo",  500000, 11, 8},   // 9
};
static inline bool mtPresetValid(int p) { return p >= 0 && p <= 9 && p != 2; }

static inline uint32_t mtDjb2(const char* s) {
  uint32_t h = 5381;
  while (*s) h = ((h << 5) + h) + (uint8_t)(*s++);
  return h;
}

// slotOverride: 0 = derive from the channel name, otherwise 1-based like LoRaConfig.channel_num
static inline uint32_t mtFreqHz(int preset, const char* chName, uint8_t slotOverride) {
  const MtPresetDef& d = MT_PRESETS[(preset >= 0 && preset <= 9) ? preset : 0];
  uint32_t n = MT_REGION_SPAN_HZ / d.bwHz;
  if (n < 1) n = 1;
  uint32_t slot = (slotOverride ? (uint32_t)(slotOverride - 1) : mtDjb2(chName)) % n;
  return MT_REGION_START_HZ + d.bwHz / 2 + slot * d.bwHz;
}

// -------------------------------------------------------------------- keys ----
static inline uint8_t mtXor(const uint8_t* p, int n) { uint8_t x = 0; while (n-- > 0) x ^= *p++; return x; }

// Expand a PSK exactly like Channels::getKey(). Returns key length: 0 (no encryption), 16 or 32.
static inline int mtExpandKey(const uint8_t* in, int inLen, uint8_t out[32]) {
  memset(out, 0, 32);
  if (inLen <= 0) return 0;
  if (inLen == 1) {
    if (in[0] == 0) return 0;
    memcpy(out, MT_DEFAULT_PSK, 16);
    out[15] = (uint8_t)(out[15] + in[0] - 1);
    return 16;
  }
  if (inLen > 32) inLen = 32;
  memcpy(out, in, inLen);
  if (inLen <= 16) return 16;      // short key: zero padded to AES-128
  return 32;                       // 17..32 bytes: zero padded to AES-256
}

static inline uint8_t mtChannelHash(const char* name, const uint8_t* key, int keyLen) {
  return mtXor((const uint8_t*)name, (int)strlen(name)) ^ mtXor(key, keyLen);
}

// ------------------------------------------------------------------ crypto ----
static inline void mtCrypt(const uint8_t* key, int keyLen, uint32_t from, uint32_t id, uint8_t* data, int len) {
  if (keyLen != 16 && keyLen != 32) return;      // 0 = channel without encryption
  if (len <= 0) return;
  uint8_t nonce[16];
  memset(nonce, 0, sizeof(nonce));
  nonce[0] = id; nonce[1] = id >> 8; nonce[2] = id >> 16; nonce[3] = id >> 24;     // bytes 4-7 stay 0
  nonce[8] = from; nonce[9] = from >> 8; nonce[10] = from >> 16; nonce[11] = from >> 24;
  uint8_t stream[16];
  size_t off = 0;
  mbedtls_aes_context ctx;
  mbedtls_aes_init(&ctx);
  mbedtls_aes_setkey_enc(&ctx, key, keyLen * 8);
  mbedtls_aes_crypt_ctr(&ctx, (size_t)len, &off, nonce, stream, data, data);
  mbedtls_aes_free(&ctx);
}

// ------------------------------------------------------------------ header ----
struct MtHdr { uint32_t to, from, id; uint8_t hopLimit, hopStart; bool wantAck, viaMqtt; uint8_t chan, nextHop, relay; };

static inline uint32_t mtLE32(const uint8_t* p) { return p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }
static inline void mtPutLE32(uint8_t* p, uint32_t v) { p[0] = v; p[1] = v >> 8; p[2] = v >> 16; p[3] = v >> 24; }

static inline bool mtParseHeader(const uint8_t* b, int n, MtHdr& h) {
  if (n < MT_HDR + 1) return false;
  h.to = mtLE32(b); h.from = mtLE32(b + 4); h.id = mtLE32(b + 8);
  uint8_t f = b[12];
  h.hopLimit = f & 7; h.wantAck = (f & 0x08) != 0; h.viaMqtt = (f & 0x10) != 0; h.hopStart = f >> 5;
  h.chan = b[13]; h.nextHop = b[14]; h.relay = b[15];
  return true;
}

// Builds a complete over-the-air packet; `data` is the plain protobuf Data message.
static inline int mtBuildPacket(uint8_t* out, uint32_t to, uint32_t from, uint32_t id, uint8_t hopLimit,
                                bool wantAck, uint8_t chanHash, uint8_t relayNode,
                                const uint8_t* key, int keyLen, const uint8_t* data, int dlen) {
  if (dlen < 0 || MT_HDR + dlen > MT_MAX_PKT) return -1;
  if (hopLimit > 7) hopLimit = 7;
  mtPutLE32(out, to); mtPutLE32(out + 4, from); mtPutLE32(out + 8, id);
  out[12] = (hopLimit & 7) | (wantAck ? 0x08 : 0) | (uint8_t)(hopLimit << 5);   // hop_start = hop_limit at origin
  out[13] = chanHash; out[14] = 0; out[15] = relayNode;
  memcpy(out + MT_HDR, data, dlen);
  mtCrypt(key, keyLen, from, id, out + MT_HDR, dlen);
  return MT_HDR + dlen;
}

// ---------------------------------------------------------------- protobuf ----
static inline int mtPutVarint(uint8_t* o, uint64_t v) {
  int n = 0;
  while (v >= 0x80) { o[n++] = (uint8_t)(v | 0x80); v >>= 7; }
  o[n++] = (uint8_t)v;
  return n;
}
static inline bool mtGetVarint(const uint8_t*& p, const uint8_t* e, uint64_t& v) {
  v = 0;
  for (int s = 0; s < 64 && p < e; s += 7) {
    uint8_t b = *p++;
    v |= (uint64_t)(b & 0x7F) << s;
    if (!(b & 0x80)) return true;
  }
  return false;
}

// Tiny field iterator. Returns false at the end / on malformed input.
struct MtField { uint32_t num; uint8_t wt; uint64_t v; const uint8_t* d; int len; };
static inline bool mtNextField(const uint8_t*& p, const uint8_t* e, MtField& f) {
  if (p >= e) return false;
  uint64_t tag;
  if (!mtGetVarint(p, e, tag)) return false;
  f.num = (uint32_t)(tag >> 3); f.wt = tag & 7; f.v = 0; f.d = nullptr; f.len = 0;
  switch (f.wt) {
    case 0: return mtGetVarint(p, e, f.v);
    case 1: if (e - p < 8) return false; f.v = (uint64_t)mtLE32(p) | ((uint64_t)mtLE32(p + 4) << 32); p += 8; return true;
    case 5: if (e - p < 4) return false; f.v = mtLE32(p); p += 4; return true;
    case 2: {
      uint64_t l;
      if (!mtGetVarint(p, e, l) || l > (uint64_t)(e - p)) return false;
      f.d = p; f.len = (int)l; p += l; return true;
    }
    default: return false;
  }
}

// meshtastic.Data
struct MtData {
  uint32_t port; const uint8_t* pl; int plen;
  bool wantResp; uint32_t dest, source, reqId, replyId, emoji;
};
static inline bool mtParseData(const uint8_t* b, int n, MtData& d) {
  memset(&d, 0, sizeof(d));
  const uint8_t* p = b; const uint8_t* e = b + n;
  MtField f;
  while (p < e) {
    if (!mtNextField(p, e, f)) return false;
    switch (f.num) {
      case 1: d.port = (uint32_t)f.v; break;
      case 2: d.pl = f.d; d.plen = f.len; break;
      case 3: d.wantResp = f.v != 0; break;
      case 4: d.dest = (uint32_t)f.v; break;
      case 5: d.source = (uint32_t)f.v; break;
      case 6: d.reqId = (uint32_t)f.v; break;
      case 7: d.replyId = (uint32_t)f.v; break;
      case 8: d.emoji = (uint32_t)f.v; break;
      default: break;
    }
  }
  return d.port != 0;      // a wrong key almost always produces garbage with port 0 / parse errors
}

static inline int mtBuildData(uint8_t* o, int cap, uint32_t port, const uint8_t* pl, int plen,
                              bool wantResp, uint32_t reqId, uint32_t replyId) {
  if (cap < plen + 24) return -1;
  int n = 0;
  o[n++] = 0x08; n += mtPutVarint(o + n, port);
  if (plen > 0) { o[n++] = 0x12; n += mtPutVarint(o + n, (uint64_t)plen); memcpy(o + n, pl, plen); n += plen; }
  if (wantResp) { o[n++] = 0x18; o[n++] = 1; }
  if (reqId)   { o[n++] = 0x35; mtPutLE32(o + n, reqId); n += 4; }
  if (replyId) { o[n++] = 0x3D; mtPutLE32(o + n, replyId); n += 4; }
  return n;
}

// meshtastic.Position (latitude_i / longitude_i are degrees * 1e7)
static inline bool mtParsePosition(const uint8_t* b, int n, int32_t& lat, int32_t& lon) {
  const uint8_t* p = b; const uint8_t* e = b + n;
  MtField f; bool la = false, lo = false;
  while (p < e && mtNextField(p, e, f)) {
    if (f.num == 1 && f.wt == 5) { lat = (int32_t)(uint32_t)f.v; la = true; }
    else if (f.num == 2 && f.wt == 5) { lon = (int32_t)(uint32_t)f.v; lo = true; }
  }
  return la && lo && !(lat == 0 && lon == 0);
}
static inline int mtBuildPosition(uint8_t* o, int32_t lat, int32_t lon, uint32_t epoch) {
  int n = 0;
  o[n++] = 0x0D; mtPutLE32(o + n, (uint32_t)lat); n += 4;
  o[n++] = 0x15; mtPutLE32(o + n, (uint32_t)lon); n += 4;
  if (epoch) { o[n++] = 0x25; mtPutLE32(o + n, epoch); n += 4; }     // field 4 time (fixed32)
  return n;
}

// meshtastic.User
struct MtUser { char longName[40]; char shortName[8]; };
static inline bool mtParseUser(const uint8_t* b, int n, MtUser& u) {
  u.longName[0] = 0; u.shortName[0] = 0;
  const uint8_t* p = b; const uint8_t* e = b + n;
  MtField f;
  while (p < e && mtNextField(p, e, f)) {
    if (f.num == 2 && f.wt == 2) { int l = f.len < 39 ? f.len : 39; memcpy(u.longName, f.d, l); u.longName[l] = 0; }
    else if (f.num == 3 && f.wt == 2) { int l = f.len < 7 ? f.len : 7; memcpy(u.shortName, f.d, l); u.shortName[l] = 0; }
  }
  return u.longName[0] || u.shortName[0];
}
static inline int mtBuildUser(uint8_t* o, int cap, const char* id, const char* longName, const char* shortName) {
  int il = strlen(id), ll = strlen(longName), sl = strlen(shortName);
  if (cap < il + ll + sl + 12) return -1;
  int n = 0;
  o[n++] = 0x0A; o[n++] = il; memcpy(o + n, id, il); n += il;
  o[n++] = 0x12; o[n++] = ll; memcpy(o + n, longName, ll); n += ll;
  o[n++] = 0x1A; o[n++] = sl; memcpy(o + n, shortName, sl); n += sl;
  o[n++] = 0x28; n += mtPutVarint(o + n, 255);                       // hw_model = PRIVATE_HW
  return n;
}

// meshtastic.Routing: returns true when it is a plain ACK (no error), false for a NAK
static inline bool mtRoutingIsAck(const uint8_t* b, int n) {
  const uint8_t* p = b; const uint8_t* e = b + n;
  MtField f;
  while (p < e && mtNextField(p, e, f)) if (f.num == 3) return f.v == 0;
  return true;
}

// ------------------------------------------------------------------ base64 ----
static inline int mtB64Val(char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '+' || c == '-') return 62;
  if (c == '/' || c == '_') return 63;
  return -1;
}
// Accepts standard and URL-safe alphabets, with or without padding. Returns bytes or -1.
static inline int mtB64Decode(const char* s, int slen, uint8_t* out, int cap) {
  int n = 0; uint32_t acc = 0; int bits = 0;
  for (int i = 0; i < slen; i++) {
    char c = s[i];
    if (c == '=' || c == ' ' || c == '\n' || c == '\r' || c == '\t') continue;
    int v = mtB64Val(c);
    if (v < 0) return -1;
    acc = (acc << 6) | v; bits += 6;
    if (bits >= 8) {
      bits -= 8;
      if (n >= cap) return -1;
      out[n++] = (uint8_t)(acc >> bits);
    }
  }
  return n;
}

// ------------------------------------------------- Meshtastic share URL -------
// https://meshtastic.org/e/#<base64url ChannelSet>  ->  primary channel + LoRa preset
struct MtChanCfg {
  char name[25]; uint8_t key[32]; int keyLen;      // keyLen: raw PSK bytes as stored in the URL (0 = none)
  int preset; int hop; int slot; bool hasPreset, hasHop, hasSlot;
};
static inline bool mtParseChannelSet(const uint8_t* b, int n, MtChanCfg& c) {
  memset(&c, 0, sizeof(c));
  c.preset = 0;
  const uint8_t* p = b; const uint8_t* e = b + n;
  MtField f; bool gotCh = false;
  while (p < e && mtNextField(p, e, f)) {
    if (f.num == 1 && f.wt == 2 && !gotCh) {                       // first ChannelSettings = primary channel
      gotCh = true;
      const uint8_t* q = f.d; const uint8_t* qe = f.d + f.len; MtField g;
      while (q < qe && mtNextField(q, qe, g)) {
        if (g.num == 2 && g.wt == 2) { c.keyLen = g.len > 32 ? 32 : g.len; memcpy(c.key, g.d, c.keyLen); }
        else if (g.num == 3 && g.wt == 2) { int l = g.len < 24 ? g.len : 24; memcpy(c.name, g.d, l); c.name[l] = 0; }
      }
    } else if (f.num == 2 && f.wt == 2) {                          // LoRaConfig
      const uint8_t* q = f.d; const uint8_t* qe = f.d + f.len; MtField g;
      bool usePreset = true;
      while (q < qe && mtNextField(q, qe, g)) {
        if (g.num == 1) usePreset = g.v != 0;
        else if (g.num == 2) { c.preset = (int)g.v; c.hasPreset = true; }
        else if (g.num == 8) { c.hop = (int)g.v; c.hasHop = c.hop >= 1 && c.hop <= 7; }
        else if (g.num == 11) { c.slot = (int)g.v; c.hasSlot = c.slot > 0 && c.slot < 256; }
      }
      if (!usePreset) c.hasPreset = false;
    }
  }
  return gotCh;
}
