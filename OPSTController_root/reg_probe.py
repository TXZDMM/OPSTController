# -*- coding: utf-8 -*-
import subprocess, sys
exe = r"C:\Users\TXZDM\Desktop\OPSTcontroller_Release\OPSTcontroller.exe"
for label, dval in [
    ("escaped", f'\\"{exe}\\" -m'),
    ("plain", f"{exe} -m"),
    ("quoted", f'"{exe}" -m'),
]:
    r = subprocess.run(
        ["reg", "add", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
         "/v", "OPSTcontroller", "/d", dval, "/f"],
        capture_output=True, text=True)
    print(f"[{label}] rc={r.returncode} out={r.stdout.strip()!r} err={r.stderr.strip()!r}")
    r2 = subprocess.run(
        ["reg", "query", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
         "/v", "OPSTcontroller"],
        capture_output=True, text=True)
    print("   value:", r2.stdout.strip().splitlines()[-1] if r2.stdout.strip() else "(none)")
