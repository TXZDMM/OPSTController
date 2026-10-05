# -*- coding: utf-8 -*-
"""Inject tamper into several extensions, wait, then report RuntimeError count."""
import subprocess, time, os

LOG = r"C:\Users\TXZDM\Desktop\OPSTcontroller_Releasedontaction\userdata\protector.log"
EXTS = [".docx", ".xlsx", ".png", ".jpg", ".zip"]
for ext in EXTS:
    key = "HKCR\\" + ext.lstrip(".")
    subprocess.run(["reg", "add", key, "/ve", "/d", "stress_evil", "/f"], capture_output=True, text=True)
    time.sleep(3)
print("injected", flush=True)
time.sleep(70)
log = open(LOG, encoding="utf-8").read()
out = ["RuntimeError: " + str(log.count("RuntimeError")),
       "detect: " + str(log.count("更改:检测到")),
       "restore: " + str(log.count("恢复:成功")),
       "---tail---"]
out.extend(log.splitlines()[-8:])
with open(r"C:\Users\TXZDM\Desktop\OPSTController-main\OPSTController_root\stress_out2.txt", "w", encoding="utf-8") as f:
    f.write("\n".join(out))
print("done", flush=True)
