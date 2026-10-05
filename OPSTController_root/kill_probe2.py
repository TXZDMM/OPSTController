# -*- coding: utf-8 -*-
"""kill_probe2: 提权验证 _force_kill_all_opst 能否强杀 TI 实例（写结果文件）"""
import sys, os, io
if sys.stdout is None:
    sys.stdout = io.StringIO()
out_path = r"C:\Users\TXZDM\Desktop\OPSTController-main\OPSTController_root\kill_probe_out.txt"
import ctypes
try:
    sys.path.insert(0, r"C:\Users\TXZDM\Desktop\OPSTController-main\OPSTController_root")
    import extension_protector as m
    admin = ctypes.windll.shell32.IsUserAnAdmin()
    prives = m.enable_all_privileges()
    killed = m._force_kill_all_opst()
    # 再查剩余进程
    r = m._run(['tasklist', '/FI', 'IMAGENAME eq OPSTcontroller.exe'], capture_output=True, text=True)
    left = 'OPSTcontroller.exe' in r.stdout
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(f"admin={admin} priv_enabled={prives} killed={killed} still_left={left}\n")
        f.write(r.stdout[:500])
except Exception as e:
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(f"EXC {type(e).__name__}: {e}\n")
os._exit(0)
