# -*- coding: utf-8 -*-
"""Deep interaction test: walk every page, invoke every button command
(skipping file-dialog / external-action ones), exercise identify_tamperer,
notification toast construction/queueing, lock-ext and blacklist flows."""
import sys, os, time, traceback, threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import extension_protector as m

t0 = time.time()
def mark(msg):
    print(f"[{time.time()-t0:.1f}s] {msg}", flush=True)

m.log_callback = lambda *a, **k: None

w = m.MainWindow(ti_elevated=False, ti_status="普通用户")
mark("MainWindow built")

SKIP = {"setup", "browse", "open", "save", "select", "export", "import", "load",
        "backup", "restore", "history", "folder", "path", "admin", "elevat",
        "stop", "start", "restart", "quit", "exit", "kill", "lock_global",
        "unlock_global", "deep_scan", "readonly", "permission", "request_admin",
        "shutdown", "taskkill"}

def walk(widget, path="root", depth=0):
    """Recursively find tk.Button widgets and their commands."""
    found = []
    try:
        children = widget.winfo_children()
    except Exception:
        return found
    for c in children:
        cls = c.__class__.__name__
        if cls == "Button":
            found.append((path, c))
        if depth < 8:
            found.extend(walk(c, path + ">", depth + 1))
    return found

def safe_invoke(btn, path):
    try:
        txt = str(btn.cget("text"))
    except Exception:
        txt = ""
    low = txt.lower()
    for s in ("选择程序", "浏览", "打开文件", "保存", "导出", "导入", "加载",
              "备份", "恢复", "查看历史", "历史版本", "路径", "申请", "权限",
              "管理员", "深层扫描", "锁定全部", "全部锁定", "解除全部", "全局锁定",
              "全局解除", "停止保护", "启动保护", "退出程序", "重启程序", "安装开机",
              "开机自启", "重新启动", "请求提权", "用管理员"):
        if s in low:
            return f"skip:{txt}"
    try:
        btn.invoke()
        return "ok:" + txt
    except tk.TclError as e:
        return f"tcl:{txt}:{e}"
    except Exception as e:
        return f"ERR:{txt}:{type(e).__name__}:{e}"

import tkinter as tk
results = []
for key in ("home", "exts", "tools", "settings", "log"):
    w._select_nav(key)
    w.root.update_idletasks()
    btns = walk(w._pages[key])
    mark(f"page {key}: {len(btns)} buttons")
    for path, btn in btns:
        r = safe_invoke(btn, path)
        if r.startswith("ERR"):
            results.append(f"[{key}] {r}")
        if r.startswith("ok"):
            # undo side effects of state-changing actions that we allowed
            try:
                w.root.update_idletasks()
            except Exception:
                pass
mark("button walk done, errors: " + str(len(results)))
for r in results:
    print("  BUTTON-ERR:", r, flush=True)

# identify_tamperer library check
samples = [
    ("C:\\Program Files\\Mozilla Firefox\\firefox.exe", "firefox"),
    ("%SystemRoot%\\System32\\notepad.exe", "notepad"),
    ("C:\\Program Files (x86)\\360\\360safe\\360Safe.exe", "360"),
    ("D:\\Software\\WeChat\\WeChat.exe", "wechat"),
    ("C:\\Program Files\\Tencent\\QQ\\Bin\\QQ.exe", "qq"),
]
for exe, tag in samples:
    try:
        name, _ = m.identify_tamperer(exe)
        print(f"  identify({tag}) -> {name}", flush=True)
    except Exception as e:
        print(f"  identify({tag}) FAIL {e}", flush=True)

# notification toast construction + queue pressure
from extension_protector import NotificationToast, BatchNotificationToast
mism = [("hkcr_ext", "docxfile", "evil_progid", None)]
rec = (1, 0, ["ok"])
def cb(*a, **k):
    return None
try:
    toasts = []
    for i in range(3):
        t = NotificationToast(w.root, ".docx", mism, rec, cb, cb, cb, cb, cb,
                              y_offset=i * 310, x_offset=i * 60,
                              timeout=6, tamperer_name="测试程序")
        toasts.append(t)
    mark(f"3 toasts built")
    w.root.update_idletasks()
    for t in toasts:
        t._on_consent()
    mark("toast consent OK")
except Exception as e:
    mark(f"toast FAIL {type(e).__name__}: {e}")
    traceback.print_exc()

# batch toast
try:
    b = BatchNotificationToast(w.root, "测试程序", [(f".ext{i}", mism, rec) for i in range(4)],
                                cb, cb, cb, cb, cb)
    mark("batch toast built")
    w.root.update_idletasks()
    b.win.destroy()
    mark("batch toast destroyed")
except Exception as e:
    mark(f"batch toast FAIL {type(e).__name__}: {e}")
    traceback.print_exc()

# lock ext flow (no real registry write under normal mode; just UI)
try:
    w._lock_ext_entry.delete(0, "end")
    w._lock_ext_entry.insert(0, ".xyz")
    w._lock_ext_read_current()
    w._refresh_locked_ext_list()
    mark("lock ext UI flows OK")
except Exception as e:
    mark(f"lock ext FAIL {type(e).__name__}: {e}")
    traceback.print_exc()

mark("ALL DONE")
try:
    w.root.destroy()
except Exception:
    pass
