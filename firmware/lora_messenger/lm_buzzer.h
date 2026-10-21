// lm_buzzer.h - hardware notifications: a 2-pin buzzer and an LED, both switchable from Settings.
//
//   Buzzer : wire one pin to a free GPIO and the other to GND.
//            "Passive" = driven with a tone (PWM, works with passive buzzers and most active ones),
//            "Active"  = plain on/off (active buzzers that have their own oscillator).
//   LED    : the board LED (GPIO 2 by default) or any free GPIO (LED + resistor to GND).
//   Patterns: new message = one short beep, alert (silent node, geofence ...) = three beeps,
//             SOS = long two-tone siren. While the buzzer plays, the LED flashes fast for alerts / SOS.
#pragma once

#define BZ_LEDC_CH 0                         // LEDC channel (ESP32 Arduino core 2.x)

bool    bzOn       = true;                   // buzzer enabled
uint8_t bzType     = 1;                      // 0 = active (on/off), 1 = passive (tone)
int     bzPin      = -1;                     // -1 = not connected
bool    ledEnabled = true;                   // LED enabled
int     ledPinCur  = LED_PIN;                // -1 = none
uint32_t ledFlashUntil = 0;                  // fast flashing for alerts / SOS

bool morseBusy = false;                      // a Morse play is running (owns the buzzer / LED)
bool morseLed  = false;                      // LED state requested by the Morse player
void morseAbort();                           // lm_morse.h

struct BzStep { uint16_t ms; uint16_t hz; };  // hz = 0: silence
static const BzStep BZ_MSG[]   = {{140, 2600}};
static const BzStep BZ_ALERT[] = {{170, 2400}, {110, 0}, {170, 2400}, {110, 0}, {170, 2400}};
static const BzStep BZ_SOS[]   = {{380, 3100}, {90, 0}, {380, 2200}, {90, 0}, {380, 3100}, {90, 0}, {380, 2200}, {90, 0}, {380, 3100}, {90, 0}, {380, 2200}};

static const BzStep* bzCur = nullptr;
static uint8_t  bzN = 0, bzI = 0, bzPrio = 0;
static bool     bzPlaying = false;
static uint32_t bzUntil = 0;

// GPIOs offered in the UI: output capable, no strapping / flash / input-only pins, none used by the sketch
static const int HW_PINS[] = {13, 15, 16, 17, 21, 22, 25, 27, 32, 33, 2};

bool hwPinOk(int p) {
  if (p < 0) return true;                    // -1 = none
  bool listed = false;
  for (unsigned i = 0; i < sizeof(HW_PINS) / sizeof(HW_PINS[0]); i++) if (HW_PINS[i] == p) listed = true;
  if (!listed) return false;
  if (p == LORA_SS || p == LORA_RST || p == LORA_DIO0 || p == BTN_PIN || p == SOS_BTN_PIN) return false;
  return true;
}

static void bzHw(int hz) {                   // hz = 0 -> silent
  if (bzPin < 0) return;
  if (bzType == 0) { digitalWrite(bzPin, hz ? HIGH : LOW); return; }
#if defined(ESP_ARDUINO_VERSION_MAJOR) && ESP_ARDUINO_VERSION_MAJOR >= 3
  ledcWriteTone(bzPin, hz);
#else
  ledcWriteTone(BZ_LEDC_CH, hz);
#endif
}

static void bzRelease(int pin, uint8_t type) {   // free the old pin before a change
  if (pin < 0) return;
  if (type == 1) {
#if defined(ESP_ARDUINO_VERSION_MAJOR) && ESP_ARDUINO_VERSION_MAJOR >= 3
    ledcDetach(pin);
#else
    ledcDetachPin(pin);
#endif
  }
  pinMode(pin, OUTPUT);
  digitalWrite(pin, LOW);
}

static void bzAttach() {
  if (bzPin < 0) return;
  pinMode(bzPin, OUTPUT);
  digitalWrite(bzPin, LOW);
  if (bzType == 1) {
#if defined(ESP_ARDUINO_VERSION_MAJOR) && ESP_ARDUINO_VERSION_MAJOR >= 3
    ledcAttach(bzPin, 2000, 8);
#else
    ledcSetup(BZ_LEDC_CH, 2000, 8);
    ledcAttachPin(bzPin, BZ_LEDC_CH);
#endif
    bzHw(0);
  }
}

static void bzPlay(const BzStep* s, uint8_t n, uint8_t prio) {
  if (!bzOn || bzPin < 0) return;
  if (morseBusy) { if (prio < 3) return; morseAbort(); }      // only an SOS may interrupt Morse
  if (bzPlaying && prio <= bzPrio) return;         // do not interrupt something equally important
  bzCur = s; bzN = n; bzI = 0; bzPrio = prio; bzPlaying = true;
  bzUntil = millis() + s[0].ms;
  bzHw(s[0].hz);
}

void bzStop() { if (bzPlaying) { bzPlaying = false; bzHw(0); } }

void bzService() {
  if (!bzPlaying || (int32_t)(millis() - bzUntil) < 0) return;
  bzI++;
  if (bzI >= bzN) { bzPlaying = false; bzHw(0); return; }
  bzUntil = millis() + bzCur[bzI].ms;
  bzHw(bzCur[bzI].hz);
}

// what: 0 message, 1 alert, 2 SOS
void hwNotify(uint8_t what) {
  if (what == 2) { bzPlay(BZ_SOS, sizeof(BZ_SOS) / sizeof(BZ_SOS[0]), 3); if (ledEnabled) ledFlashUntil = millis() + 4500; }
  else if (what == 1) { bzPlay(BZ_ALERT, sizeof(BZ_ALERT) / sizeof(BZ_ALERT[0]), 2); if (ledEnabled) ledFlashUntil = millis() + 1500; }
  else { bzPlay(BZ_MSG, sizeof(BZ_MSG) / sizeof(BZ_MSG[0]), 1); if (ledEnabled) ledUntil = millis() + 250; }
}

void hwSave() {
  prefs.putBool("bzon", bzOn);
  prefs.putUChar("bztype", bzType);
  prefs.putInt("bzpin", bzPin);
  prefs.putBool("ledon", ledEnabled);
  prefs.putInt("ledpin", ledPinCur);
}

void hwLoad() {
  bzOn = prefs.getBool("bzon", true);
  bzType = prefs.getUChar("bztype", 1) ? 1 : 0;
  bzPin = prefs.getInt("bzpin", -1);
  if (!hwPinOk(bzPin)) bzPin = -1;
  ledEnabled = prefs.getBool("ledon", true);
  ledPinCur = prefs.getInt("ledpin", LED_PIN);
  if (ledPinCur != LED_PIN && !hwPinOk(ledPinCur)) ledPinCur = LED_PIN;
  if (ledPinCur == bzPin) bzPin = -1;
}

void hwApplyPins() {                         // call once in setup()
  if (ledPinCur >= 0) { pinMode(ledPinCur, OUTPUT); digitalWrite(ledPinCur, LOW); }
  bzAttach();
}

// used by the settings API: validates everything first, then applies
bool hwConfigure(int bz, int bp, int bt, int ld, int lp, String& err) {
  if (bp != -2 && !hwPinOk(bp)) { err = "This GPIO cannot be used for the buzzer"; return false; }
  if (lp != -2 && lp != LED_PIN && !hwPinOk(lp)) { err = "This GPIO cannot be used for the LED"; return false; }
  int nbp = (bp == -2) ? bzPin : bp, nlp = (lp == -2) ? ledPinCur : lp;
  if (nbp >= 0 && nbp == nlp) { err = "Buzzer and LED need different GPIO pins"; return false; }
  int oldPin = bzPin; uint8_t oldType = bzType;
  int oldLed = ledPinCur;
  bzStop();
  if (bz != -1) bzOn = bz != 0;
  if (bt != -1) bzType = bt ? 1 : 0;
  if (ld != -1) ledEnabled = ld != 0;
  bzPin = nbp; ledPinCur = nlp;
  if (oldPin != bzPin || oldType != bzType) { bzRelease(oldPin, oldType); bzAttach(); }
  if (oldLed != ledPinCur) {
    if (oldLed >= 0) digitalWrite(oldLed, LOW);
    if (ledPinCur >= 0) { pinMode(ledPinCur, OUTPUT); digitalWrite(ledPinCur, LOW); }
  }
  hwSave();
  return true;
}

// what: "bz" short beep, "led" LED flashing, "alert", "sos"
bool hwTest(const String& what, String& err) {
  if (what == "led") {
    if (!ledEnabled) { err = "The LED is switched off"; return false; }
    if (ledPinCur < 0) { err = "Choose a GPIO for the LED first"; return false; }
    ledFlashUntil = millis() + 1600;
    return true;
  }
  if (!bzOn) { err = "The buzzer is switched off"; return false; }
  if (bzPin < 0) { err = "Choose a GPIO for the buzzer first"; return false; }
  bzStop();
  hwNotify(what == "sos" ? 2 : what == "alert" ? 1 : 0);
  return true;
}

String hwJson() {
  String o = ",\"hw\":{\"bz\":" + String(bzOn ? 1 : 0) + ",\"bp\":" + String(bzPin) + ",\"bt\":" + String(bzType) +
             ",\"ld\":" + String(ledEnabled ? 1 : 0) + ",\"lp\":" + String(ledPinCur) + ",\"pins\":[";
  bool f = true;
  for (unsigned i = 0; i < sizeof(HW_PINS) / sizeof(HW_PINS[0]); i++) {
    if (!hwPinOk(HW_PINS[i])) continue;
    if (!f) o += ",";
    f = false;
    o += String(HW_PINS[i]);
  }
  return o + "]}";
}
