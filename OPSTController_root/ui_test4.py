# -*- coding: utf-8 -*-
"""Focused: batch toast construction + single-toast queue timeout logic."""
import sys, os, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import extension_protector as m
import tkinter as tk

m.log_callback = lambda *a, **k: None
w = m.MainWindow(ti_elevated=False, ti_status="普通用户")
print("built", flush=True)

from extension_protector import NotificationToast, BatchNotificationToast
mism = [("hkcr_ext", "docxfile", "evil_progid", None)]
rec = (1, 0, ["ok"])
def cb(*a, **k):
    return None

b = BatchNotificationToast(w.root, "测试程序", [(f".ext{i}", mism, rec) for i in range(4)],
                            cb, cb, cb, cb, cb)
w.root.update_idletasks()
print("batch toast built", flush=True)
b.win.destroy()
print("batch toast destroyed", flush=True)

# queue logic: simulate _show_single_notification path via queue process
w._popup_queue.append((".zzz", mism, rec, 0))
w._process_popup_queue()
print("queue process started", flush=True)
w.root.update()
time.sleep(0.3)
w.root.update()
print("queue processed without hang", flush=True)
w.root.destroy()
print("DONE", flush=True)
