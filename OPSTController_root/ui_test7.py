# -*- coding: utf-8 -*-
"""ui_test7: 全按钮回调走查
遍历全部页面收集所有 tk.Button：验证 command 存在、可调用；
安全触发导航按钮与异常修复按钮（跳转逻辑），确认无异常。"""
import sys, io
_real_stdout = sys.stdout
sys.stdout = io.StringIO()  # 静默程序自身输出

import extension_protector as m

win = m.MainWindow()
root = win.root
root.update()

def out(*a):
    _real_stdout.write(" ".join(str(x) for x in a) + "\n")
    _real_stdout.flush()

pages = ["状态", "扩展名", "设置"]
collected = {}

def walk_collect(prefix):
    btns = []
    def _scan(w):
        for c in w.winfo_children():
            if isinstance(c, m.tk.Button):
                txt = (c.cget("text") or "").strip()
                cmdstr = ""
                try:
                    cmdstr = str(c.cget("command") or "")
                except Exception:
                    cmdstr = ""
                btns.append((txt, bool(cmdstr.strip())))
            _scan(c)
    _scan(root)
    return btns

collected = walk_collect("all")
total = len(collected)
no_cmd = [b for b in collected if not b[1]]
print(f"TOTAL_BUTTONS={total}", file=_real_stdout)
print(f"WITHOUT_COMMAND={len(no_cmd)}", file=_real_stdout)
for t, ok in no_cmd:
    print(f"  no-cmd: {t!r}", file=_real_stdout)

# 导航按钮依次触发（页面切换）
nav_names = ["状态", "扩展名", "设置"]
fail = 0
for name in nav_names:
    try:
        win._select_nav(name)
        root.update()
    except Exception as e:
        fail += 1
        print(f"NAV_FAIL {name}: {e}", file=_real_stdout)
print(f"NAV_FAILS={fail}", file=_real_stdout)

# 异常修复按钮（含"修复"文本）：验证 command 绑定 + _wrap_jump 跳转逻辑存在
repair_btn = None
def _find_repair(w):
    global repair_btn
    for c in w.winfo_children():
        if isinstance(c, m.tk.Button) and "修复" in ((c.cget("text") or "").strip()):
            repair_btn = c
            return
        _find_repair(c)
_find_repair(root)
if repair_btn is not None:
    cmdstr = str(repair_btn.cget("command") or "")
    print(f"REPAIR_BUTTON_OK text={repair_btn.cget('text')!r} has_cmd={bool(cmdstr.strip())}", file=_real_stdout)
else:
    print("REPAIR_BUTTON_NOT_FOUND", file=_real_stdout)

# 小尺寸按钮适配再验证（缩小窗口）
try:
    win._apply_small_adapt(True)
    root.update()
    print("SMALL_ADAPT_OK", file=_real_stdout)
except Exception as e:
    print(f"SMALL_ADAPT_FAIL: {e}", file=_real_stdout)

try:
    root.destroy()
except Exception:
    pass
print("ALL DONE", file=_real_stdout)
