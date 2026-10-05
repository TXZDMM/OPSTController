# -*- coding: utf-8 -*-
import sys, winreg, traceback
sys.path.insert(0, r"C:\Users\TXZDM\Desktop\OPSTController-main\OPSTController_root")
import extension_protector as m
try:
    print("frozen:", getattr(sys, "frozen", False))
    print("exe:", sys.executable)
    k = winreg.OpenKey(m.HKCU, m.AUTOSTART_KEY, 0, winreg.KEY_SET_VALUE)
    print("open ok (no WOW64)")
    val = '"' + sys.executable + '" -m'
    winreg.SetValueEx(k, m.APP_NAME, 0, winreg.REG_SZ, val)
    print("set ok", val)
    winreg.CloseKey(k)
    print("is_set now:", m.is_autostart_set())
except Exception as e2:
    traceback.print_exc()
    try:
        k = winreg.OpenKey(m.HKCU, m.AUTOSTART_KEY, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY)
        winreg.SetValueEx(k, m.APP_NAME, 0, winreg.REG_SZ, '"' + sys.executable + '" -m')
        winreg.CloseKey(k)
        print("set ok with WOW64 flag")
        print("is_set now:", m.is_autostart_set())
    except Exception as e3:
        traceback.print_exc()
except Exception as e:
    traceback.print_exc()
