// lm_morse.h - Morse code on LED / buzzer (local + remote from another node).
// Non-blocking. Supports:
//   - Local job (Settings > Morse signal): n plays every `every` minutes
//   - Remote job (from another node): n plays every `gapSec` seconds, optional
//     "until confirmed", status reports back to sender, physical button confirms.
#pragma once

// ---------- local job (unchanged behaviour) ----------
struct MorseJob {
  bool active;                // playing or waiting for next repeat
  char text[48];              // normalised (A-Z, 0-9, punctuation, spaces)
  uint8_t out;                // 1 = LED, 2 = buzzer, 3 = both
  uint8_t n, done;            // plays requested / finished
  uint16_t every;             // minutes between plays (local only)
  uint8_t wpm;
  uint32_t nextAt;
} mj;

// ---------- remote Morse session (device is the receiver) ----------
// status values for the remote session on this device
enum {
  RM_IDLE = 0,
  RM_RECV,          // packet received, about to play / playing
  RM_PLAYING,       // currently sounding
  RM_WAIT_GAP,      // finished one play, waiting gapSec
  RM_DONE,          // all plays finished (or confirmed)
  RM_CONFIRMED,     // user pressed button = received
  RM_PROBLEM        // double-press = received but problem
};

struct RemoteMorse {
  bool     active;
  uint8_t  status;            // RM_*
  char     text[48];
  uint8_t  out;               // 1 LED, 2 buzzer, 3 both
  uint8_t  n, done;           // requested / completed plays
  uint16_t gapSec;            // seconds between repeats (5..120)
  uint8_t  wpm;
  bool     untilConfirm;      // keep repeating until button confirm
  uint32_t fromUid;           // who sent the request
  uint16_t reqId;             // request id (for status packets)
  uint32_t nextAt;            // when next play starts
  uint32_t startedAt;
  uint8_t  acceptFrom;        // 0=none, 1=known contacts only, 2=anyone
  uint8_t  maxRepeats;        // hard ceiling (default 10)
  uint16_t maxTotalSec;       // hard ceiling total play window (default 600)
} rm;

// ---------- remote Morse tracker on the SENDER side ----------
// tracks status of a Morse we sent to someone else
enum {
  RS_SENT = 0,        // packet left us
  RS_DELIVERED,       // destination device got the packet
  RS_PLAYING,         // destination is playing (report n of m)
  RS_PLAY_DONE,       // all plays finished, no human confirm yet
  RS_CONFIRMED,       // human pressed button
  RS_PROBLEM,         // human double-pressed (problem)
  RS_NO_CONFIRM,      // all plays done, nobody confirmed
  RS_FAILED           // delivery failed
};

struct RemoteSend {
  bool     active;
  uint8_t  status;            // RS_*
  uint32_t toUid;
  uint16_t reqId;
  char     text[48];
  uint8_t  n, done;           // total / current play reported by remote
  uint32_t startedAt;
  uint32_t lastUpdate;
} rs;

#define MORSE_MAX_EL 760
static uint16_t mzEl[MORSE_MAX_EL];
static int      mzN = 0, mzI = 0;
static bool     mzPlay = false;
static uint32_t mzUntil = 0;
static bool     mzIsRemote = false;   // current play belongs to remote session

static const char* const MORSE_CODE[] = {
  ".-", "-...", "-.-.", "-..", ".", "..-.", "--.", "....", "..", ".---", "-.-", ".-..", "--",
  "-.", "---", ".--.", "--.-", ".-.", "...", "-", "..-", "...-", ".--", "-..-", "-.--", "--.."};
static const char* const MORSE_DIGIT[] = {"-----", ".----", "..---", "...--", "....-", ".....", "-....", "--...", "---..", "----."};

const char* morseOf(char c) {
  if (c >= 'A' && c <= 'Z') return MORSE_CODE[c - 'A'];
  if (c >= '0' && c <= '9') return MORSE_DIGIT[c - '0'];
  switch (c) {
    case '.': return ".-.-.-"; case ',': return "--..--"; case '?': return "..--.."; case '\'': return ".----.";
    case '!': return "-.-.--"; case '/': return "-..-."; case '(': return "-.--."; case ')': return "-.--.-";
    case '&': return ".-..."; case ':': return "---..."; case ';': return "-.-.-."; case '=': return "-...-";
    case '+': return ".-.-."; case '-': return "-....-"; case '_': return "..--.-"; case '"': return ".-..-.";
    case '$': return "...-..-"; case '@': return ".--.-.";
  }
  return nullptr;
}

static int morseBuild(const char* text, int wpm) {
  int unit = 1200 / (wpm < 5 ? 5 : wpm > 30 ? 30 : wpm);
  int n = 0, gap = 0;
  bool first = true;
  for (const char* p = text; *p; p++) {
    char c = *p;
    if (c >= 'a' && c <= 'z') c -= 32;
    if (c == ' ') { if (!first) gap = 7; continue; }
    const char* code = morseOf(c);
    if (!code) continue;
    if (!first && gap < 3) gap = 3;
    bool firstSym = true;
    for (const char* s = code; *s; s++) {
      if (n + 2 > MORSE_MAX_EL) return n;
      int g = firstSym ? (first ? 0 : gap) : 1;
      if (g) mzEl[n++] = (uint16_t)(g * unit);
      mzEl[n++] = (uint16_t)((*s == '.' ? 1 : 3) * unit);
      firstSym = false;
    }
    first = false; gap = 0;
  }
  return n;
}

// which outputs to drive for the current play
static uint8_t mzCurOut() {
  return mzIsRemote ? rm.out : mj.out;
}

static void mzOut(bool on) {
  uint8_t o = mzCurOut();
  if (o & 1) morseLed = on;
  if ((o & 2) && bzPin >= 0) bzHw(on ? (bzType == 0 ? 1 : 2200) : 0);
}

static void morsePlayStartLocal() {
  mzIsRemote = false;
  mzN = morseBuild(mj.text, mj.wpm);
  if (mzN <= 0) { mj.active = false; return; }
  mzI = 0; mzPlay = true; morseBusy = true;
  bzStop();
  mzUntil = millis() + mzEl[0];
  mzOut(true);
}

static void morsePlayStartRemote() {
  mzIsRemote = true;
  mzN = morseBuild(rm.text, rm.wpm);
  if (mzN <= 0) { rm.active = false; rm.status = RM_DONE; return; }
  mzI = 0; mzPlay = true; morseBusy = true;
  rm.status = RM_PLAYING;
  bzStop();
  mzUntil = millis() + mzEl[0];
  mzOut(true);
}

void morseAbort() {
  if (mzPlay) { mzOut(false); mzPlay = false; }
  morseLed = false; morseBusy = false;
  mj.active = false;
  // remote abort only if we are the player
  if (rm.active && (rm.status == RM_PLAYING || rm.status == RM_WAIT_GAP || rm.status == RM_RECV)) {
    rm.active = false;
    rm.status = RM_DONE;
  }
}

// force-stop remote session (button confirm / problem / timeout)
void remoteMorseStop(uint8_t finalStatus) {
  if (mzPlay && mzIsRemote) { mzOut(false); mzPlay = false; }
  morseLed = false; morseBusy = false;
  if (rm.active) {
    rm.status = finalStatus;
    rm.active = false;
  }
}

// ---------- quiet-hours gate (feature 15) ----------
// returns true if Morse / non-SOS buzzer+LED are allowed right now
bool morseAllowedNow() {
  // quietHoursEnabled / quietStart / quietEnd / quietAllowSos are defined in lm_features.h
  // if not yet present we treat everything as allowed
  extern bool quietHoursEnabled;
  extern uint8_t quietStartH, quietStartM, quietEndH, quietEndM;
  extern bool quietAllowMorse;
  if (!quietHoursEnabled) return true;
  if (quietAllowMorse) return true;
  // simple hour check (full implementation lives with the quiet-hours feature)
  time_t now = time(nullptr);
  if (now < 100000) return true;   // clock not set
  struct tm* t = localtime(&now);
  int cur = t->tm_hour * 60 + t->tm_min;
  int s = quietStartH * 60 + quietStartM;
  int e = quietEndH * 60 + quietEndM;
  bool inQuiet;
  if (s <= e) inQuiet = (cur >= s && cur < e);
  else        inQuiet = (cur >= s || cur < e);   // crosses midnight
  return !inQuiet;
}

void morseService() {
  uint32_t now = millis();

  // ----- active tone playback -----
  if (mzPlay) {
    if ((int32_t)(now - mzUntil) < 0) return;
    mzI++;
    if (mzI >= mzN) {                      // finished one play
      mzOut(false); mzPlay = false; morseBusy = false; morseLed = false;
      if (mzIsRemote) {
        rm.done++;
        // report progress to sender (done by caller via remoteMorseReport)
        if (rm.untilConfirm) {
          // keep going until confirm or hard limits
          if (rm.done >= rm.maxRepeats ||
              (now - rm.startedAt) / 1000 >= rm.maxTotalSec) {
            rm.status = RM_DONE;
            rm.active = false;
          } else {
            rm.status = RM_WAIT_GAP;
            rm.nextAt = now + (uint32_t)rm.gapSec * 1000UL;
          }
        } else {
          if (rm.done >= rm.n) {
            rm.status = RM_DONE;
            rm.active = false;
          } else {
            rm.status = RM_WAIT_GAP;
            rm.nextAt = now + (uint32_t)rm.gapSec * 1000UL;
          }
        }
      } else {
        mj.done++;
        if (mj.done >= mj.n) mj.active = false;
        else mj.nextAt = now + (uint32_t)mj.every * 60000UL;
      }
      return;
    }
    mzUntil = now + mzEl[mzI];
    mzOut((mzI % 2) == 0);
    return;
  }

  // ----- schedule next local play -----
  if (mj.active && (int32_t)(now - mj.nextAt) >= 0) {
    if (morseAllowedNow()) morsePlayStartLocal();
    else mj.nextAt = now + 30000UL;   // retry in 30 s if quiet hours
  }

  // ----- schedule next remote play -----
  if (rm.active && rm.status == RM_WAIT_GAP && (int32_t)(now - rm.nextAt) >= 0) {
    if (morseAllowedNow()) morsePlayStartRemote();
    else rm.nextAt = now + 15000UL;
  }
  // start first remote play
  if (rm.active && rm.status == RM_RECV && (int32_t)(now - rm.nextAt) >= 0) {
    if (morseAllowedNow()) morsePlayStartRemote();
    else rm.nextAt = now + 15000UL;
  }
}

// ---------- local start (Settings UI) ----------
bool morseStart(const String& textIn, int out, int n, int every, int wpm, String& err) {
  String t = textIn;
  t.trim();
  char buf[48];
  int k = 0;
  for (unsigned i = 0; i < t.length() && k < 47; i++) {
    char c = t[i];
    if (c >= 'a' && c <= 'z') c -= 32;
    if (c == ' ' || morseOf(c)) buf[k++] = c;
  }
  buf[k] = 0;
  if (morseBuild(buf, 15) <= 0) { err = "Nothing to send: use letters, digits or common punctuation (A-Z, 0-9)"; return false; }
  if (out < 1 || out > 3) { err = "Choose LED, buzzer or both"; return false; }
  if ((out & 1) && (!ledEnabled || ledPinCur < 0)) { err = "Switch the LED on in Buzzer & LED first"; return false; }
  if ((out & 2) && (!bzOn || bzPin < 0)) { err = "Switch the buzzer on and choose its GPIO in Buzzer & LED first"; return false; }
  if (n < 1 || n > 20) { err = "Repeats must be 1 to 20"; return false; }
  if (n > 1 && (every < 1 || every > 60)) { err = "Interval must be 1 to 60 minutes"; return false; }
  if (wpm < 5 || wpm > 25) { err = "Speed must be 5 to 25 WPM"; return false; }
  if (rm.active) { err = "A remote Morse session is active – stop it first or wait"; return false; }
  morseAbort();
  strncpy(mj.text, buf, 47); mj.text[47] = 0;
  mj.out = (uint8_t)out; mj.n = (uint8_t)n; mj.done = 0;
  mj.every = (uint16_t)(every < 1 ? 1 : every); mj.wpm = (uint8_t)wpm;
  mj.active = true;
  mj.nextAt = millis();
  prefs.putString("mztext", String(mj.text));
  prefs.putUChar("mzout", mj.out); prefs.putUChar("mzn", mj.n);
  prefs.putUShort("mzev", mj.every); prefs.putUChar("mzwpm", mj.wpm);
  morsePlayStartLocal();
  return true;
}

// ---------- remote start (called when we receive a remote-Morse packet) ----------
// acceptFrom: 0=reject all, 1=known contacts, 2=anyone
// returns false if rejected (caller should not ACK / should ignore)
bool remoteMorseStart(uint32_t fromUid, uint16_t reqId, const char* text,
                      uint8_t out, uint8_t n, uint16_t gapSec, uint8_t wpm,
                      bool untilConfirm, String& err) {
  if (rm.acceptFrom == 0) { err = "Remote Morse disabled on this device"; return false; }
  // acceptFrom==1: only known contacts – Contact* is already resolved by the packet handler
  if (!morseAllowedNow() && !untilConfirm) { err = "Quiet hours – Morse blocked"; return false; }

  char buf[48];
  int k = 0;
  for (const char* p = text; *p && k < 47; p++) {
    char c = *p;
    if (c >= 'a' && c <= 'z') c -= 32;
    if (c == ' ' || morseOf(c)) buf[k++] = c;
  }
  buf[k] = 0;
  if (morseBuild(buf, 15) <= 0) { err = "Empty Morse text"; return false; }
  if (out < 1 || out > 3) out = 3;
  if (n < 1) n = 1;
  if (n > rm.maxRepeats) n = rm.maxRepeats;
  if (gapSec < 5) gapSec = 5;
  if (gapSec > 120) gapSec = 120;
  if (wpm < 5) wpm = 5;
  if (wpm > 25) wpm = 25;

  // stop local job if running
  if (mj.active) morseAbort();

  uint8_t keepAcc = rm.acceptFrom;      // the accept policy and limits are settings, not session state: keep them across sessions
  uint8_t keepMax = rm.maxRepeats;
  uint16_t keepTot = rm.maxTotalSec;
  memset(&rm, 0, sizeof(rm));
  rm.acceptFrom = keepAcc;
  rm.maxRepeats = keepMax ? keepMax : 10;
  rm.maxTotalSec = keepTot ? keepTot : 600;
  rm.startedAt = millis();
  rm.active = true;
  rm.status = RM_RECV;
  strncpy(rm.text, buf, 47);
  rm.out = out;
  rm.n = n;
  rm.done = 0;
  rm.gapSec = gapSec;
  rm.wpm = wpm;
  rm.untilConfirm = untilConfirm;
  rm.fromUid = fromUid;
  rm.reqId = reqId;
  rm.startedAt = millis();
  rm.nextAt = millis() + 300;          // small delay so status packet can leave first
  rm.maxRepeats = prefs.getUChar("rmmax", 10);
  rm.maxTotalSec = prefs.getUShort("rmtot", 600);
  return true;
}

void morseLoad() {
  memset(&mj, 0, sizeof(mj));
  memset(&rm, 0, sizeof(rm));
  memset(&rs, 0, sizeof(rs));
  String t = prefs.getString("mztext", "SOS");
  strncpy(mj.text, t.c_str(), 47);
  mj.out = prefs.getUChar("mzout", 3); mj.n = prefs.getUChar("mzn", 3);
  mj.every = prefs.getUShort("mzev", 5); mj.wpm = prefs.getUChar("mzwpm", 12);
  rm.acceptFrom = prefs.getUChar("rmacc", 1);   // default: known contacts only
  rm.maxRepeats = prefs.getUChar("rmmax", 10);
  rm.maxTotalSec = prefs.getUShort("rmtot", 600);
}

String morseJson() {
  int nx = (mj.active && !mzPlay) ? (int)(((int32_t)(mj.nextAt - millis())) / 1000) : 0;
  if (nx < 0) nx = 0;
  String o = ",\"mo\":{\"a\":" + String(mj.active ? 1 : 0) + ",\"p\":" + String(mzPlay && !mzIsRemote ? 1 : 0) +
             ",\"d\":" + String(mj.done) + ",\"n\":" + String(mj.n) + ",\"nx\":" + String(nx) +
             ",\"t\":" + jstr(String(mj.text)) + ",\"o\":" + String(mj.out) +
             ",\"e\":" + String(mj.every) + ",\"w\":" + String(mj.wpm) + "}";

  // remote receive session
  o += ",\"rm\":{\"a\":" + String(rm.active ? 1 : 0) + ",\"st\":" + String(rm.status) +
       ",\"d\":" + String(rm.done) + ",\"n\":" + String(rm.n) +
       ",\"t\":" + jstr(String(rm.text)) + ",\"from\":" + String(rm.fromUid) +
       ",\"id\":" + String(rm.reqId) + ",\"uc\":" + String(rm.untilConfirm ? 1 : 0) +
       ",\"acc\":" + String(rm.acceptFrom) + "}";

  // remote send tracker
  o += ",\"rs\":{\"a\":" + String(rs.active ? 1 : 0) + ",\"st\":" + String(rs.status) +
       ",\"d\":" + String(rs.done) + ",\"n\":" + String(rs.n) +
       ",\"t\":" + jstr(String(rs.text)) + ",\"to\":" + String(rs.toUid) +
       ",\"id\":" + String(rs.reqId) + "}";
  return o;
}

// ready phrases (feature 1)
static const char* const MORSE_PRESETS[] = {"SOS", "OK", "HELP", "COME", "SAFE"};
static const int MORSE_PRESET_N = 5;
