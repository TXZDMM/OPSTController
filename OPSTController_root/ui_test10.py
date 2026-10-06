# -*- coding: utf-8 -*-
"""ui_test10: 设置页行内对齐 + 防护记录页刷新（动态import提升后回归）"""
import sys, io
_real = sys.stdout
sys.stdout = io.StringIO()

import extension_protector as m

win = m.MainWindow()
root = win.root
root.update()

def out(*a):
    _real.write(" ".join(str(x) for x in a) + "\n")
    _real.flush()

checks = {}

# 1) 设置页行内对齐：Spinbox 与其标签应在同一行（同容器 row 且 y 相等）
win._select_nav("settings")
root.update()
try:
    lbl_y = None
    spin_y = None
    spin_w = None
    for w in root.winfo_children():
        def scan(x):
            global _found
            for c in x.winfo_children():
                if isinstance(c, m.tk.Label) and "弹窗等待时间" in (c.cget("text") or ""):
                    return ("lbl", c)
                if isinstance(c, m.tk.Spinbox) and c.cget("textvariable"):
                    return ("spin", c)
                r = scan(c)
                if r: return r
            return None
    # 直接遍历所有控件
    lbls = []; spins = []
    def walk(x):
        for c in x.winfo_children():
            if isinstance(c, m.tk.Label) and "弹窗等待时间" in (c.cget("text") or ""):
                lbls.append(c)
            if isinstance(c, m.tk.Spinbox):
                spins.append(c)
            walk(c)
    walk(root)
    if lbls and spins:
        lw = lbls[0]; sw = spins[0]
        checks["row_align"] = abs(lw.winfo_rooty() - sw.winfo_rooty()) < 30
        out(f"label_y={lw.winfo_rooty()} spin_y={sw.winfo_rooty()} same_row={checks['row_align']}")
    else:
        checks["row_align"] = False
        out(f"not found lbls={len(lbls)} spins={len(spins)}")
except Exception as e:
    checks["row_align"] = False
    out("row_align err:", e)

# 2) 防护记录页：构建 + 刷新不抛异常（顶部 import collections 生效）
try:
    win._select_nav("history")
    root.update()
    win._refresh_history_table()
    root.update()
    stat = win._hist_stat_var.get() if hasattr(win, "_hist_stat_var") else ""
    checks["history_refresh"] = "读取记录失败" not in stat
    out("history_stat:", stat[:80].replace("\n", " | "))
except Exception as e:
    checks["history_refresh"] = False
    out("history err:", e)

# 3) 配置与备份页构建（zipfile 顶部导入回归）
try:
    win._select_nav("config")
    root.update()
    checks["config_page"] = hasattr(win, "_cfg_overview")
except Exception as e:
    checks["config_page"] = False
    out("config err:", e)

print("ui_test10:", checks, file=_real)
print("ALL DONE" if all(checks.values()) else "FAIL", file=_real)
root.destroy()
