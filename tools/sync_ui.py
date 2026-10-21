#!/usr/bin/env python3
"""Copies the web UI out of the firmware (assets.h) into the Android app (app/src/main/assets/index.html).
Run it again every time you change the firmware's web page:   python3 tools/sync_ui.py [path/to/assets.h]"""
import re, sys, os
here = os.path.dirname(os.path.abspath(__file__))
src = sys.argv[1] if len(sys.argv) > 1 else os.path.join(here, '..', '..', 'lora_messenger', 'assets.h')
s = open(src, encoding='utf-8').read()
m = re.search(r'R"rawliteral\((.*?)\)rawliteral"', s, re.S)
if not m:
    sys.exit('PAGE_HTML not found in ' + src)
out = os.path.join(here, '..', 'app', 'src', 'main', 'assets', 'index.html')
open(out, 'w', encoding='utf-8').write(m.group(1))
print('wrote', out, len(m.group(1)), 'bytes')
