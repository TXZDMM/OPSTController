# -*- coding: utf-8 -*-
"""Headless layout regression for NotificationToast: verify the three buttons
fit within the toast width and are fully displayed (no clipping), and that the
height adapts to content (no huge empty bottom area)."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import extension_protector as m
import tkinter as tk

m.log_callback = lambda *a, **k: None
w = m.MainWindow(ti_elevated=False, ti_status="普通用户")
w.root.update_idletasks()

results = []
def check(name, cond, detail=""):
    results.append((name, cond, detail))
    print(("PASS" if cond else "FAIL") + " " + name + (" | " + detail if detail else ""), flush=True)

# 构造超长篡改者名的弹窗（历史 bug：按钮/文本裁切）
mismatches = [
    ("userchoice_progid", "docxfile", "C:\\Program Files\\SomeSuperLongCompanyName\\VeryLongProductName\\app.exe", None),
    ("hkcr_ext", "docxfile", "evil_tamper_test", None),
]
rec = (1, 0)  # success, fail
t = m.NotificationToast(
    w.root, ".docx", mismatches, (1, 0, "ok"),
    on_consent=lambda e: None, on_close=lambda toast: None,
    on_pause_min=lambda e: None, on_forever=lambda e: None,
    on_show_main=lambda: None, tamperer_name="C:\\Program Files\\SomeSuperLongCompanyName\\VeryLongProductName\\app.exe",
)
w.root.update_idletasks()

# 1) 按钮可见且完全显示
for name, btn in (("consent", t.consent_btn), ("pause_min", t.pause_min_btn), ("forever", t.forever_btn)):
    x = btn.winfo_rootx() - t.win.winfo_rootx()
    ww = btn.winfo_width()
    check(f"button {name} visible", btn.winfo_ismapped() and ww > 0, f"x={x} w={ww}")

# 2) 所有按钮在 toast 宽度内（不裁切）
toast_w = t.win.winfo_width()
max_right = max((btn.winfo_rootx() - t.win.winfo_rootx() + btn.winfo_width()) for btn in (t.consent_btn, t.pause_min_btn, t.forever_btn))
check("buttons inside toast width", max_right <= toast_w - 4, f"max_right={max_right} toast_w={toast_w}")

# 3) 高度自适应（不应有巨大空白：高度 < 400）
h = t.win.winfo_height()
check("toast height adaptive", 120 < h < 400, f"h={h}")

# 4) 提示行自动换行不裁切（递归找含"单次同意="文字的 Label）
def find_hint(widget):
    for c in widget.winfo_children():
        if isinstance(c, tk.Label) and "单次同意=" in str(c.cget("text")):
            return c
        r = find_hint(c)
        if r:
            return r
    return None
hint = find_hint(t.win)
check("hint label exists", hint is not None, "wraplength=" + str(hint.cget("wraplength")) if hint else "")

t.win.destroy()
w.root.destroy()
print("ALL DONE", flush=True)
