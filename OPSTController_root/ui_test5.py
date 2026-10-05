# -*- coding: utf-8 -*-
"""Regression for the three new fixes: installed-program enumeration,
wheel-item click-to-activate logic, and scroll container bindings."""
import sys, os, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import extension_protector as m
import tkinter as tk
from tkinter import ttk, scrolledtext

m.log_callback = lambda *a, **k: None
w = m.MainWindow(ti_elevated=False, ti_status="普通用户")
print("built", flush=True)
w.root.update_idletasks()

# 1) enumerate installed programs (real registry on this machine)
t0 = time.time()
installed = w._enumerate_installed_programs()
print(f"installed programs: {len(installed)} in {time.time()-t0:.2f}s", flush=True)
for name, path in installed[:12]:
    print("   ", repr(name), "->", path, flush=True)

# 2) wheel items collected per page
for key in ("home", "exts", "tools", "settings", "log"):
    w._select_nav(key)
    w.root.update_idletasks()
    print(f"page {key}: wheel_items={len([x for x in w._all_wheel_items if x.winfo_exists() and x.winfo_ismapped()])}", flush=True)

# 3) simulate wheel event on a small item (unactivated -> should scroll page path)
canvas_list = list(w._scroll_canvases)
print("canvases:", len(canvas_list), flush=True)
# find one item on current page
items = [x for x in w._all_wheel_items if x.winfo_exists()]
print("total wheel items:", len(items), flush=True)

# activate simulation: click handler adds to active set
if items:
    it = items[0]
    it.event_generate("<Button-1>")
    w.root.update_idletasks()
    print("active after click:", it in w._wheel_active, flush=True)
    # simulate wheel on it -> should not scroll page (item scrolls itself)
    try:
        it.event_generate("<MouseWheel>", delta=-120)
        w.root.update_idletasks()
        print("wheel on active item OK", flush=True)
    except Exception as e:
        print("wheel on item FAIL", e, flush=True)
    # click elsewhere -> clear active
    w._wheel_active.clear()
    print("cleared active", flush=True)

# 4) picker construction (non-blocking: no grab in test mode)
try:
    win = w._pick_program(lambda n: print("picked:", n, flush=True), title="测试选择")
    w.root.update_idletasks()
    print("picker built OK", flush=True)
    win.destroy()
except Exception as e:
    print("picker FAIL", type(e).__name__, e, flush=True)
    import traceback; traceback.print_exc()

# 5) small-adapt + flow-wrap still fine
w._apply_small_adapt(900)
w.root.update_idletasks()
print("small-adapt OK", flush=True)
w._flow_wrap(w._protect_btns[0].master, w._protect_btns)
w.root.update_idletasks()
print("flow-wrap OK", flush=True)

print("ALL DONE", flush=True)
w.root.destroy()
