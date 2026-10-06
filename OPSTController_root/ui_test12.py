# -*- coding: utf-8 -*-
"""ui_test12: 撤销按钮/禁锁校验/当前程序锁定/路径tooltip/过小浮层通知"""
import sys, io, os, tempfile
_real = sys.stdout
sys.stdout = io.StringIO()

import extension_protector as m

def out(*a):
    _real.write(" ".join(str(x) for x in a) + "\n")
    _real.flush()

checks = {}

win = m.MainWindow()
root = win.root
root.update()

# 1) 禁锁扩展名列表
checks["unlockable_list"] = all(x in m.LOCK_UNLOCKABLE_EXTS for x in (".sys", ".dll", ".exe", ".bat", ".cmd", ".vbs"))
out("unlockable exts:", len(m.LOCK_UNLOCKABLE_EXTS))

# 2) 锁定 .sys 应被拒绝（不写配置）
win._lock_ext_var.set(".sys")
win._lock_ext_normalize()
cfg = win.baseline_mgr.config
locked = cfg.setdefault("locked_defaults", {})
had = ".sys" in locked
tmp_exe = os.path.join(tempfile.gettempdir(), "opst_t12.exe")
try:
    with open(tmp_exe, "w") as f:
        f.write("x")
    win._lock_ext_lock_path(".sys", tmp_exe)
    root.update()
    checks["sys_rejected"] = (".sys" not in locked) and "不支持锁定" in win._lock_ext_status.cget("text")
    out("sys lock status:", win._lock_ext_status.cget("text")[:60])
except Exception as e:
    checks["sys_rejected"] = False
    out("sys lock err:", e)
finally:
    try:
        os.remove(tmp_exe)
    except Exception:
        pass

# 3) 撤销按钮存在
win._select_nav("history")
root.update()
btn_texts = []
def walk(x):
    for c in x.winfo_children():
        if isinstance(c, m.tk.Button):
            btn_texts.append(c.cget("text"))
        walk(c)
walk(root)
checks["revoke_btn"] = "撤销选中" in btn_texts and hasattr(win, "_history_revoke")
out("revoke btn present:", "撤销选中" in btn_texts)

# 4) tooltip 方法存在
checks["tooltip"] = hasattr(win, "_lock_tooltip_show") and hasattr(win, "_lock_tooltip_hide")
out("tooltip methods:", checks["tooltip"])

# 5) 过小浮层通知：窗口缩到最小(约840px)时通知显示，恢复正常宽度隐藏
win._select_nav("settings")
root.update()
root.geometry("840x800")
root.update()
banner_mgr_small = win._settings_banner.winfo_manager()
root.geometry("1200x800")
root.update()
banner_mgr_big = win._settings_banner.winfo_manager()
checks["banner_overlay"] = (banner_mgr_small == "place") and (banner_mgr_big == "")
out("banner mgr small/big:", banner_mgr_small, "/", banner_mgr_big)

# 5b) 基准按钮行：最小宽度下全部按钮可见（无裁切）
root.geometry("840x800")
root.update()
base_btns = []
def walk_b(x):
    for c in x.winfo_children():
        if isinstance(c, m.tk.Button) and c.cget("text") in ("备份当前基准", "深层扫描", "历史版本管理", "查看基准说明", "从文件加载基准"):
            base_btns.append(c)
        walk_b(c)
root.update()
walk_b(root)
all_visible_cnt = 0
for b in base_btns:
    try:
        if b.winfo_ismapped() == 1:
            all_visible_cnt += 1
    except Exception:
        pass
# 设置页 5 个基准按钮在最小宽度下全部可见（其余页面同名按钮未显示属正常）
checks["base_btns_visible"] = all_visible_cnt >= 5
out("base btns:", len(base_btns), "visible:", all_visible_cnt)
root.geometry("1200x800")
root.update()

# 6) 当前程序锁定（无默认时给出提示而非弹窗）
win._select_nav("exts")
root.update()
win._lock_ext_var.set(".t12x")
win._lock_ext_normalize()
# 清理可能残留的 .t12x 锁定
lc = win.baseline_mgr.config.get("locked_defaults", {})
if ".t12x" in lc:
    del lc[".t12x"]
    win.baseline_mgr.save_config()
win._lock_ext_pick_current()
root.update()
checks["pick_current_no_progid"] = "不支持锁定" not in win._lock_ext_status.cget("text")
out("pick current status:", win._lock_ext_status.cget("text")[:60])

# 7) 列表/解除按钮状态
win._refresh_locked_ext_list()
root.update()
checks["unlock_btn_exists"] = hasattr(win, "_lock_unlock_btn")
out("unlock btn state:", win._lock_unlock_btn.cget("state") if checks["unlock_btn_exists"] else "n/a")

print("ui_test12:", checks, file=_real)
print("ALL DONE" if all(checks.values()) else "FAIL", file=_real)
root.destroy()
