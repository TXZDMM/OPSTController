# -*- coding: utf-8 -*-
import sys
sys.path.insert(0, r"C:\Users\TXZDM\Desktop\OPSTController-main\OPSTController_root")
import extension_protector as ep

ep.USERDATA_DIR = r"C:\Users\TXZDM\Desktop\OPSTcontroller_Releasedontaction\userdata"
ep.BASELINE_FILE = ep.os.path.join(ep.USERDATA_DIR, "baseline.json")
ep.CONFIG_FILE = ep.os.path.join(ep.USERDATA_DIR, "config.json")
ep.HISTORY_DIR = ep.os.path.join(ep.USERDATA_DIR, "baseline_history")

# simulate user-level override tamper
import winreg
try:
    k = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, r"Software\Classes\.m4a\shell\open\command", 0, winreg.KEY_SET_VALUE)
    winreg.SetValueEx(k, None, 0, winreg.REG_SZ, "evil.exe")
    winreg.CloseKey(k)
except Exception as e:
    print("tamper write err:", e)
try:
    k = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, r"Software\Classes\.m4a", 0, winreg.KEY_SET_VALUE)
    winreg.SetValueEx(k, None, 0, winreg.REG_SZ, "evilProg")
    winreg.CloseKey(k)
    print("tamper set")
except Exception as e:
    print("tamper2 err:", e)

bm = ep.BaselineManager()
engine = ep.ProtectionEngine(bm)
s, f, dets = engine._recover_locked(".m4a", "WMP11.AssocFile.M4A")
print("recover:", s, "fail:", f)
for d in dets:
    print("  ", d)
mm = engine.check_extension(".m4a")
print("mismatches:", [(m[0], m[1], m[2]) for m in mm if m[0] != "new_progid_command"])
v, _ = ep.reg_read_value(winreg.HKEY_CURRENT_USER, r"Software\Classes\.m4a", "")
print("hkcu_now:", v)
v2, _ = ep.reg_read_value(winreg.HKEY_CLASSES_ROOT, ".m4a", "")
print("hkcr_now:", v2)
