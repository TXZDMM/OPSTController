# -*- coding: utf-8 -*-
"""ui_test9: 配置与备份菜单 smoke —— 页面注册/按钮绑定/概览渲染"""
import sys
sys.path.insert(0, r"C:\Users\TXZDM\Desktop\OPSTController-main\OPSTController_root")
import io, contextlib
import extension_protector as ep

ep.USERDATA_DIR = r"C:\Users\TXZDM\Desktop\OPSTController-main\OPSTController_root\_smoke_tmp\userdata"
ep.BASELINE_FILE = ep.os.path.join(ep.USERDATA_DIR, "baseline.json")
ep.CONFIG_FILE = ep.os.path.join(ep.USERDATA_DIR, "config.json")
ep.HISTORY_DIR = ep.os.path.join(ep.USERDATA_DIR, "baseline_history")
ep.LOG_FILE = ep.os.path.join(ep.USERDATA_DIR, "protector.log")
ep.PROGRAM_NAMES_FILE = ep.os.path.join(ep.USERDATA_DIR, "program_names.json")
import os
os.makedirs(ep.USERDATA_DIR, exist_ok=True)
ep.HISTORY_DIR = os.path.join(ep.USERDATA_DIR, "baseline_history")
os.makedirs(ep.HISTORY_DIR, exist_ok=True)

buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    with contextlib.redirect_stderr(buf):
        app = ep.MainWindow()
        app.withdraw()
        app.update_idletasks()

checks = {}
checks["nav_config"] = "config" in app._nav_buttons
checks["page_config"] = "config" in app._pages
checks["backup_btn"] = app._cfg_backup is not None
checks["restore_btn"] = app._cfg_restore is not None
checks["export_btn"] = app._cfg_export_lists is not None
checks["import_btn"] = app._cfg_import_lists is not None
checks["overview_text"] = bool(app._cfg_overview.get("1.0", tk_end := "end").strip())
total_buttons = sum(1 for b in getattr(app, "_all_buttons", []) if b.winfo_exists())
checks["total_buttons"] = total_buttons
checks["no_cmd"] = sum(1 for b in getattr(app, "_all_buttons", []) if not (b.cget("command") or ""))
navs = list(app._nav_buttons.keys())
checks["nav_order"] = navs

print("config-smoke:", {k: (v if k != "nav_order" else navs) for k, v in checks.items()})
ok = all(v is not False for k, v in checks.items() if k not in ("nav_order", "total_buttons", "no_cmd"))
print("ALL DONE" if ok else "FAIL")
app.destroy()
