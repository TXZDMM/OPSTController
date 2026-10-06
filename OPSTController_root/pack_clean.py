# -*- coding: utf-8 -*-
"""打包全新发行版（桌面 OPSTcontroller-v0.8.1）→ 桌面 zip（无日期、无用户数据）"""
import os, zipfile

SRC = r"C:\Users\TXZDM\Desktop\OPSTcontroller-v0.8.1"
ZIP = r"C:\Users\TXZDM\Desktop\OPSTController-main\OPSTcontroller-0.8.1.zip"

if os.path.exists(ZIP):
    try:
        os.remove(ZIP)
    except Exception:
        pass

with zipfile.ZipFile(ZIP, "w", zipfile.ZIP_DEFLATED) as z:
    for root, dirs, files in os.walk(SRC):
        for f in files:
            full = os.path.join(root, f)
            arc = os.path.relpath(full, SRC)
            z.write(full, arc)
print("entries:", len(zipfile.ZipFile(ZIP).namelist()))
print("size:", os.path.getsize(ZIP))

# 泄漏复检：zip 内不允许出现用户数据/日志/日期/本机路径
names = zipfile.ZipFile(ZIP).namelist()
bad = [n for n in names if any(k in n.lower() for k in (
    "config.json", "protector.log", "baseline.json", "history.json",
    ".pyc", "txzdm", "releasedontaction"))]
print("leak_entries:", ";" .join(bad) if bad else "NONE")
