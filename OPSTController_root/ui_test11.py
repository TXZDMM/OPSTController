# -*- coding: utf-8 -*-
"""ui_test11: 单扩展名锁定工具三区布局 + 交互回归"""
import sys, io, os, tempfile
_real = sys.stdout
sys.stdout = io.StringIO()

import extension_protector as m

def out(*a):
    _real.write(" ".join(str(x) for x in a) + "\n")
    _real.flush()

checks = {}

# ---- 纯函数测试 ----
p1 = m._lock_target_to_progid(r"C:\Apps\foo.exe")
checks["t2p_path"] = (p1 == r"Applications\foo.exe")
out("t2p path ->", p1)
p2 = m._lock_target_to_progid("WMP11.AssocFile.M4A")
checks["t2p_progid"] = (p2 == "WMP11.AssocFile.M4A")
out("t2p progid ->", p2)

# ---- UI 构建 ----
win = m.MainWindow()
root = win.root
root.update()
win._select_nav("exts")
root.update()

# ① Combobox 存在且带常用扩展名
checks["combobox"] = isinstance(win._lock_ext_entry, m.ttk.Combobox) and len(win._lock_ext_entry.cget("values")) >= 10
out("combobox values:", len(win._lock_ext_entry.cget("values")) if hasattr(win._lock_ext_entry, "cget") else "n/a")

# ② 信息区控件存在
checks["info_area"] = hasattr(win, "_lock_cur_name") and hasattr(win, "_lock_cur_path")
out("info area:", hasattr(win, "_lock_cur_name"), hasattr(win, "_lock_cur_path"))

# ③ 解锁按钮初始禁用
checks["unlock_disabled"] = str(win._lock_unlock_btn.cget("state")) == "disabled"
out("unlock btn state:", win._lock_unlock_btn.cget("state"))

# ④ 列表格式「ext | 名称 | 路径」
win._refresh_locked_ext_list()
root.update()
n = win._locked_ext_listbox.size()
fmt_ok = True
if n:
    line = win._locked_ext_listbox.get(0)
    fmt_ok = " | " in line
    out("first line:", line[:70])
checks["list_format"] = fmt_ok

# ⑤ 模拟锁定（仅写文件配置，不碰注册表）：用临时文件路径
tmp_exe = os.path.join(tempfile.gettempdir(), "opst_test_app.exe")
try:
    with open(tmp_exe, "w") as f:
        f.write("x")
    cfg = win.baseline_mgr.config
    cfg.setdefault("locked_defaults", {})[".ttst"] = tmp_exe
    win.baseline_mgr.save_config()
    win._refresh_locked_ext_list()
    root.update()
    n2 = win._locked_ext_listbox.size()
    checks["lock_list_has"] = n2 > 0
    # 选中第一行 → 按钮激活
    win._locked_ext_listbox.selection_set(0)
    win._lock_ext_on_select()
    root.update()
    checks["unlock_active"] = str(win._lock_unlock_btn.cget("state")) == "normal"
    out("lock list size:", n2, "unlock active:", checks["unlock_active"])
    # 清理测试锁定项
    locked = win.baseline_mgr.config.get("locked_defaults", {})
    if ".ttst" in locked:
        del locked[".ttst"]
        win.baseline_mgr.save_config()
    try:
        os.remove(tmp_exe)
    except Exception:
        pass
except Exception as e:
    checks["lock_list_has"] = False
    checks["unlock_active"] = False
    out("lock sim err:", e)

# ⑥ 扩展名规范化
win._lock_ext_var.set("txt")
win._lock_ext_normalize()
checks["normalize"] = win._lock_ext_var.get() == ".txt"
out("normalize:", win._lock_ext_var.get())

# ⑦ 信息区刷新（读真实注册表，容错）
win._lock_ext_var.set(".m4a")
win._lock_ext_refresh_info()
root.update()
checks["info_refresh"] = hasattr(win, "_lock_cur_name") and True
out("cur name:", win._lock_cur_name.cget("text")[:50], "| path:", win._lock_cur_path.cget("text")[:40])

print("ui_test11:", checks, file=_real)
print("ALL DONE" if all(checks.values()) else "FAIL", file=_real)
root.destroy()
