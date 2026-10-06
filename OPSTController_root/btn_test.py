# -*- coding: utf-8 -*-
"""按钮模拟点击测试：遍历所有页面按钮（除异常修复页），模拟用户点击。
确认类对话框自动返回"否/取消"（不产生系统副作用），普通按钮真实执行回调。
输出每页每按钮的 text -> OK / 异常。"""
import os, sys, json, time, traceback, tkinter as tk

ROOT = r"C:\Users\TXZDM\Desktop\OPSTController-main\OPSTController_root"
sys.path.insert(0, ROOT)
os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")

import extension_protector as ep

# ---- 桩化对话框：确认类返回 False（取消执行），提示类打印 ----
_msgs = []
def _ask(parent=None, **kw):
    _msgs.append(("ask", kw.get("message", kw.get("title", ""))))
    return False
def _askok(parent=None, **kw):
    _msgs.append(("askok", kw.get("message", kw.get("title", ""))))
    return False
def _askretry(parent=None, **kw):
    _msgs.append(("askretry", kw.get("message", kw.get("title", ""))))
    return False
def _show(parent=None, **kw):
    _msgs.append(("show", kw.get("message", kw.get("title", ""))))
def _err(parent=None, **kw):
    _msgs.append(("error", kw.get("message", kw.get("title", ""))))
def _warn(parent=None, **kw):
    _msgs.append(("warn", kw.get("message", kw.get("title", ""))))
ep.messagebox.askyesno = _ask
ep.messagebox.askokcancel = _askok
ep.messagebox.askretrycancel = _askretry
ep.messagebox.showinfo = _show
ep.messagebox.showerror = _err
ep.messagebox.showwarning = _warn

# ---- 危险/破坏性按钮（点击会改系统状态或退出程序），排除不点击 ----
DANGER_KEYWORDS = ("完全退出", "全局锁定", "解除全局锁定", "锁定为当前程序",
                  "锁定为其他程序", "解除锁定", "清空记录", "恢复", "删除",
                  "停止保护", "撤销", "清除", "卸载", "重置基准")

def collect_buttons(widget, out):
    try:
        if isinstance(widget, tk.Button):
            text = str(widget.cget("text") or "")
            out.append((text, widget))  # 保存控件引用，点击用 invoke() 等价真实点击
        for ch in widget.winfo_children():
            collect_buttons(ch, out)
    except Exception:
        pass

def main():
    app = ep.MainWindow(ti_elevated=True, ti_status="测试环境",
                        privilege_failure_detail=None, start_minimized=False)
    app.root.update_idletasks()
    app.root.update()
    report = []
    skipped_pages = ("tools",)  # 异常修复页不测
    for key, page in app._pages.items():
        if key in skipped_pages:
            report.append(f"[跳过页面] {key} (异常修复)")
            continue
        btns = []
        collect_buttons(page, btns)
        report.append(f"[页面] {key}: 共 {len(btns)} 个按钮")
        for text, btn in btns:
            if any(k in text for k in DANGER_KEYWORDS):
                report.append(f"   - [{text}] (危险/破坏性，跳过)")
                continue
            try:
                btn.invoke()
                app.root.update_idletasks()
                app.root.update()
                report.append(f"   - [{text}] OK")
            except Exception as e:
                tb = traceback.format_exc(limit=3)
                report.append(f"   - [{text}] 异常: {e} | {tb.splitlines()[-1]}")
    # 确认类对话框统计
    report.append(f"[对话框桩] 共拦截 {len(_msgs)} 次对话框: "
                  + ", ".join(set(m[0] for m in _msgs)))
    try:
        if getattr(app, "monitor", None) is not None:
            app.monitor.stop()
    except Exception:
        pass
    try:
        app.root.destroy()
    except Exception:
        pass
    out = "\n".join(report)
    with open(os.path.join(ROOT, "btn_test_report.txt"), "w", encoding="utf-8") as f:
        f.write(out)
    print("TEST DONE")

if __name__ == "__main__":
    main()
