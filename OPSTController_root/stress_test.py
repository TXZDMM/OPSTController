# -*- coding: utf-8 -*-
"""Continuous tamper stress: repeatedly inject tamper into a rotating set of
extensions, verify the monitor keeps detecting and restoring without hanging.
Injects via HKCU Software Classes .ext default value (reg add HKCR)."""
import subprocess, time, sys, os

EXTS = [".docx", ".xlsx", ".png", ".jpg", ".mp4", ".zip", ".txt", ".pdf"]
log_path = r"C:\Users\TXZDM\Desktop\OPSTcontroller_Releasedontaction\userdata\protector.log"

def get_log_tail():
    try:
        with open(log_path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception as e:
        return f"(read fail {e})"

start = time.time()
rounds = 0
inject_ok = 0
inject_denied = 0
while time.time() - start < 150 and rounds < 40:
    ext = EXTS[rounds % len(EXTS)]
    evil = f"evil_pid{rounds % 7}"
    # 关键：保留扩展名开头的点（监控保护的是带点的 ".ext" 注册表键）
    r = subprocess.run(["reg", "add", f"HKCR\\{ext}", "/ve", "/d", evil, "/f"],
                       capture_output=True, text=True)
    if r.returncode == 0:
        inject_ok += 1
    else:
        inject_denied += 1  # 扩展名处于 Deny ACL 锁定期：注入被拒 = 防御生效
    rounds += 1
    time.sleep(2.0)  # let monitor notice between injections

tail = get_log_tail()
detect = tail.count("更改:检测到")
restore = tail.count("恢复:成功")
lines = tail.splitlines()
last = lines[-12:] if lines else []
out = [f"rounds={rounds} elapsed={int(time.time()-start)}s",
       f"inject_ok={inject_ok} inject_denied_by_lock={inject_denied}",
       f"detect={detect} restore_ok={restore}",
       "---last12---"]
out.extend(last)
# 输出重定向冲突规避：写入独立结果文件（脚本外部重定向到 stress_out.txt 时避免自锁）
try:
    with open(r"C:\Users\TXZDM\Desktop\OPSTController-main\OPSTController_root\stress_result.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(out))
except Exception:
    print("\n".join(out))
print("done")
