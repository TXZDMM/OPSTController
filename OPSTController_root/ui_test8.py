# -*- coding: utf-8 -*-
"""smoke: 新菜单（防护记录/系统诊断）快速验证"""
import sys, io
_real_stdout = sys.__stdout__
sys.stdout = io.StringIO()
import extension_protector as m

win = m.MainWindow()
root = win.root
root.update()

ok = []
# 导航注册
for key in ("history", "diag"):
    ok.append(f"page_{key}={key in win._pages}")
win._select_nav("history"); root.update()
win._refresh_history_table(); root.update()
ok.append(f"hist_tree_rows={win._hist_tree.size()}")
ok.append(f"hist_stat={'统计' in win._hist_stat_var.get()}")
win._select_nav("diag"); root.update()
win._diag_run(); root.update()
diag_txt = win._diag_text.get("1.0", "end")
ok.append(f"diag_len={len(diag_txt)}")
ok.append(f"diag_has_priv={'权限状态' in diag_txt}")
ok.append(f"diag_has_lock={'单扩展名锁定' in diag_txt}")
ok.append(f"diag_has_baseline={'基准状态' in diag_txt}")
# 全部按钮 command 检查（新页面）
btns = []
def _scan(w):
    for c in w.winfo_children():
        if isinstance(c, m.tk.Button):
            btns.append(((c.cget("text") or "").strip(), bool(str(c.cget("command") or "").strip())))
        _scan(c)
_scan(root)
no_cmd = [b for b in btns if not b[1]]
ok.append(f"total_buttons={len(btns)} no_cmd={len(no_cmd)}")
print(" | ".join(ok), file=_real_stdout)
root.destroy()
