// ===========================================================================
//  Local file sharing (photos, voice notes, videos, any file) between the people on THIS device's Wi-Fi.
//  Files are kept in the flash file system (LittleFS) and never go over LoRa. The chat only carries a small
//  marker  {~F|id|name|size|mime~}  that the page turns into a picture / player / download link.
//  If the board's partition scheme has no file system, everything below reports "storage not available".
// ===========================================================================
#include <LittleFS.h>

#define FILE_MAX_BYTES   (1024UL * 1024UL)       // one file
#define FILE_KEEP_FREE   (24UL * 1024UL)         // always leave some room
static bool fileFsOk = false;

void fileInit() {
  fileFsOk = LittleFS.begin(true);
}

static bool fileIdOk(const String& id) {
  if (id.length() < 6 || id.length() > 12) return false;
  for (unsigned i = 0; i < id.length(); i++) {
    char c = id.charAt(i);
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
  }
  return true;
}

// deletes the oldest stored files until `need` bytes are free
static void fileMakeRoom(size_t need) {
  for (int round = 0; round < 40; round++) {
    size_t total = LittleFS.totalBytes(), used = LittleFS.usedBytes();
    if (total > used && total - used >= need + FILE_KEEP_FREE) return;
    File root = LittleFS.open("/");
    if (!root) return;
    String oldest;
    time_t ot = 0;
    bool any = false;
    File f = root.openNextFile();
    while (f) {
      String nm = String(f.name());
      time_t lw = f.getLastWrite();
      if (!any || lw < ot) { oldest = nm; ot = lw; any = true; }
      f = root.openNextFile();
    }
    if (!any) return;
    if (!oldest.startsWith("/")) oldest = "/" + oldest;
    LittleFS.remove(oldest);
  }
}

// GET /api/fstat  -> {"ok":1,"fs":1,"free":<bytes>,"max":<bytes>}
void handleFileStat() {
  if (!fileFsOk) { jokx(",\"fs\":0,\"free\":0,\"max\":0"); return; }
  size_t total = LittleFS.totalBytes();
  size_t room = total > FILE_KEEP_FREE ? total - FILE_KEEP_FREE : 0;      // old files are removed automatically
  size_t mx = room < FILE_MAX_BYTES ? room : FILE_MAX_BYTES;
  jokx(",\"fs\":1,\"free\":" + String((unsigned long)room) + ",\"max\":" + String((unsigned long)mx));
}

// POST /api/fup?id=<hex>&off=<bytes so far>&size=<total>   body (text/plain) = base64 of the next piece
void handleFileUp() {
  if (!fileFsOk) { jerr(503, "File storage is not available on this device (choose a partition scheme with a file system)"); return; }
  String id = server.arg("id");
  if (!fileIdOk(id)) { jerr(400, "bad id"); return; }
  long off = server.arg("off").toInt();
  long size = server.arg("size").toInt();
  if (size <= 0 || (unsigned long)size > FILE_MAX_BYTES) { jerr(413, "File is too large (max 1 MB)"); return; }
  String b64 = server.arg("plain");
  if (!b64.length()) { jerr(400, "empty piece"); return; }
  String path = "/f" + id;
  if (off == 0) {
    LittleFS.remove(path);
    fileMakeRoom((size_t)size);
    size_t total = LittleFS.totalBytes(), used = LittleFS.usedBytes();
    if (total <= used || total - used < (size_t)size + 4096) { jerr(507, "Not enough free space on the device"); return; }
  }
  size_t cap = (b64.length() / 4 + 1) * 3 + 4;
  uint8_t* buf = (uint8_t*)malloc(cap);
  if (!buf) { jerr(503, "Out of memory, try a smaller file"); return; }
  size_t olen = 0;
  int rc = mbedtls_base64_decode(buf, cap, &olen, (const unsigned char*)b64.c_str(), b64.length());
  if (rc != 0) { free(buf); jerr(400, "bad data"); return; }
  File f = LittleFS.open(path, off == 0 ? "w" : "a");
  if (!f) { free(buf); jerr(500, "Cannot write file"); return; }
  if (off != 0 && (long)f.size() != off) { f.close(); free(buf); jerr(409, "Upload out of order"); return; }
  size_t w = f.write(buf, olen);
  f.close();
  free(buf);
  if (w != olen) { LittleFS.remove(path); jerr(507, "Device storage is full"); return; }
  jokx(",\"got\":" + String((unsigned long)(off + (long)olen)));
}

// GET /api/file?id=<hex>&m=<mime>&token=<token>
void handleFileGet() {
  if (!fileFsOk) { jerr(503, "File storage is not available"); return; }
  String id = server.arg("id");
  if (!fileIdOk(id)) { jerr(400, "bad id"); return; }
  File f = LittleFS.open("/f" + id, "r");
  if (!f) { jerr(404, "File not found (it may have been removed to make room)"); return; }
  String mime = server.arg("m");
  String safe;
  for (unsigned i = 0; i < mime.length() && i < 40; i++) {
    char c = mime.charAt(i);
    if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '/' || c == '-' || c == '+' || c == '.') safe += c;
  }
  if (safe.indexOf('/') < 1) safe = "application/octet-stream";
  server.sendHeader("Cache-Control", "private, max-age=86400");
  server.streamFile(f, safe);
  f.close();
}

void fileRoutes() {
  server.on("/api/fstat", HTTP_GET, LG(handleFileStat));
  server.on("/api/fup", HTTP_POST, LG(handleFileUp));
  server.on("/api/file", HTTP_GET, LG(handleFileGet));
}
