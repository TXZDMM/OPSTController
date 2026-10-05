# -*- coding: utf-8 -*-
import sys
sys.path.insert(0, r"C:\Users\TXZDM\Desktop\OPSTController-main\OPSTController_root")
import extension_protector as m

tests = [
    "PPS.exe",
    "AppleMusic.exe",
    r"C:\Program Files\WindowsApps\PPS_Video\PPS.exe",
    "Microsoft Edge",
    "chrome.exe",
    "微信",
    "QQ.exe",
    "steam.exe",
    "WINWORD.EXE",
    "WeChat.exe",
    "火绒安全.exe",
    "360安全卫士.exe",
]
for t in tests:
    try:
        r = m.identify_tamperer(t)
        print(t, "->", r)
    except Exception as e:
        print(t, "-> ERR", e)
