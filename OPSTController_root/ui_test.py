# -*- coding: utf-8 -*-
"""Headless UI construction test: builds MainWindow and exercises layout,
then auto-quits. Prints progress markers to localize any hang."""
import sys, os, time, threading, traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import extension_protector as m

m.log_callback = lambda *a, **k: None

def pump(window):
    try:
        window.root.update_idletasks()
        window.root.update()
    except Exception:
        pass

t0 = time.time()
def mark(msg):
    print(f"[{time.time()-t0:.1f}s] {msg}", flush=True)

mark("start MainWindow()")
w = m.MainWindow(ti_elevated=False, ti_status="普通用户")
mark("MainWindow constructed")
pump(w)
mark("first pump done")
# exercise page switching + layouts
for key in ("home", "exts", "tools", "settings", "log", "home"):
    w._select_nav(key)
    pump(w)
    mark(f"nav -> {key} done")
# small-adapt simulation
w._apply_small_adapt(1100)
pump(w)
mark("small_adapt 1100 done")
w._apply_small_adapt(950)
pump(w)
mark("small_adapt 950 done")
w._apply_small_adapt(800)
pump(w)
mark("small_adapt 800 done")
w._apply_small_adapt(1280)
pump(w)
mark("small_adapt restore done")
# flow wrap simulation (shrink then restore)
w._flow_wrap(w._protect_btns[0].master, w._protect_btns)
pump(w)
mark("flow_wrap re-run done")
# exercise lock ext page functions with a fake ext
try:
    w._lock_ext_entry.delete(0, "end")
    w._lock_ext_entry.insert(0, ".txt")
    w._lock_ext_read_current()
    mark("lock read ok")
except Exception as e:
    mark(f"lock read FAIL {e}")
try:
    w._refresh_locked_ext_list()
    mark("lock list refresh ok")
except Exception as e:
    mark(f"lock list FAIL {e}")
try:
    w._refresh_blacklist_ui()
    mark("blacklist ui refresh ok")
except Exception as e:
    mark(f"blacklist ui FAIL {e}")
# simulate settings auto-save path (no-op safe)
try:
    if hasattr(w, "_auto_save_fn"):
        w._auto_save_fn()
        mark("auto save ok")
except Exception as e:
    mark(f"auto save FAIL {e}")
mark("ALL DONE")
try:
    w.root.destroy()
except Exception:
    pass
