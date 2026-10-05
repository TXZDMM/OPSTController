# -*- coding: utf-8 -*-
"""Deep interaction test v3: mainloop-driven button invoke with auto-close of
any modal Toplevel so dialogs cannot block. Records errors."""
import sys, os, time, traceback, threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import extension_protector as m
import tkinter as tk

t0 = time.time()
def mark(msg):
    print(f"[{time.time()-t0:.1f}s] {msg}", flush=True)

m.log_callback = lambda *a, **k: None
w = m.MainWindow(ti_elevated=False, ti_status="普通用户")
mark("MainWindow built")

SKIP_TEXTS = ("选择程序", "浏览", "打开文件", "保存", "导出", "导入", "加载基准",
              "备份", "恢复", "查看历史", "历史版本", "申请提权", "管理员",
              "深层扫描", "锁定全部", "全部锁定", "解除全部", "全局锁定", "全局解除",
              "停止保护", "启动保护", "退出程序", "重启程序", "开机自启", "安装",
              "重新启动", "请求提权", "用管理员", "重置为默认")

def walk(widget, depth=0):
    found = []
    try:
        children = widget.winfo_children()
    except Exception:
        return found
    for c in children:
        if c.__class__.__name__ == "Button":
            found.append(c)
        if depth < 8:
            found.extend(walk(c, depth + 1))
    return found

jobs = []
for key in ("home", "exts", "tools", "settings", "log"):
    w._select_nav(key)
    w.root.update_idletasks()
    btns = walk(w._pages[key])
    mark(f"page {key}: {len(btns)} buttons")
    for b in btns:
        try:
            txt = str(b.cget("text"))
        except Exception:
            txt = ""
        if any(s in txt for s in SKIP_TEXTS):
            continue
        jobs.append((key, txt, b))

results = []
idx = [0]
def auto_close():
    for tl in list(w.root.winfo_children()):
        if isinstance(tl, tk.Toplevel):
            try:
                tl.destroy()
            except Exception:
                pass
    w.root.after(80, auto_close)

def step():
    if idx[0] >= len(jobs):
        mark("ALL INVOKES DONE, errors=" + str(len(results)))
        for r in results:
            print("  ERR:", r, flush=True)
        w.root.destroy()
        return
    key, txt, b = jobs[idx[0]]
    idx[0] += 1
    try:
        b.invoke()
        r = "ok"
    except tk.TclError as e:
        r = f"tcl:{e}"
    except Exception as e:
        r = f"ERR:{type(e).__name__}:{e}"
        results.append(f"[{key}] {txt} :: {r}")
    w.root.after(60, step)

w.root.after(100, auto_close)
w.root.after(150, step)
w.root.mainloop()
mark("ALL DONE")
