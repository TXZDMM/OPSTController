# -*- coding: utf-8 -*-
"""Assemble release zip from the Release directory (docs + exe + runtime + program_names only)."""
import os, shutil, zipfile

REL = r"C:\Users\TXZDM\Desktop\OPSTcontroller_Release"
TMP = r"C:\Users\TXZDM\Desktop\OPSTController-main\OPSTController_root\_pkg_tmp"
ZIP = r"C:\Users\TXZDM\Desktop\OPSTcontroller-0.8.0.zip"

if os.path.exists(TMP):
    shutil.rmtree(TMP)
os.makedirs(TMP)

for f in ("README.md", "LICENSE", "CHANGELOG.md", "停止OPSTcontroller.bat", "OPSTcontroller.exe"):
    shutil.copy2(os.path.join(REL, f), os.path.join(TMP, f))
shutil.copytree(os.path.join(REL, "runtime"), os.path.join(TMP, "runtime"))
os.makedirs(os.path.join(TMP, "userdata"))
shutil.copy2(os.path.join(REL, "userdata", "program_names.json"),
             os.path.join(TMP, "userdata", "program_names.json"))

if os.path.exists(ZIP):
    os.remove(ZIP)
with zipfile.ZipFile(ZIP, "w", zipfile.ZIP_DEFLATED) as z:
    for root, dirs, files in os.walk(TMP):
        for f in files:
            full = os.path.join(root, f)
            arc = os.path.relpath(full, TMP)
            z.write(full, arc)
print("zip size:", os.path.getsize(ZIP))
print("entries:", len(zipfile.ZipFile(ZIP).namelist()))
