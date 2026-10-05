# -*- coding: utf-8 -*-
"""
单扩展名锁定强锁升级 —— 锁定语义真机测试（只测不改 extension_protector.py）。
解释器: OPSTController_root\\.venv\\Scripts\\python.exe
证据写入 stdout 与 _locktest_tmp\\raw_output.txt。
"""
import os, sys, io, traceback, shutil

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

TMP = os.path.join(ROOT, "_locktest_tmp")
shutil.rmtree(TMP, ignore_errors=True)
os.makedirs(TMP, exist_ok=True)

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
RAW = open(os.path.join(TMP, "raw_output.txt"), "w", encoding="utf-8")

def out(*a):
    s = " ".join(str(x) for x in a)
    print(s)
    RAW.write(s + "\n"); RAW.flush()

import winreg
import logging

out("=" * 70)
out("STEP 0: import extension_protector")
import extension_protector as ep
out("import OK; module file:", ep.__file__)

# 关闭 import 时打开的真实 protector.log 句柄，防止测试日志写真实 userdata
for h in list(ep.logger.handlers):
    try: h.close()
    except Exception: pass
    ep.logger.removeHandler(h)

# === 数据/日志路径全部重定向到临时目录；注册表根句柄保持真实 ===
ep.USERDATA_DIR = TMP
ep.CONFIG_FILE = os.path.join(TMP, "config.json")
ep.BASELINE_FILE = os.path.join(TMP, "baseline.json")
ep.HISTORY_DIR = os.path.join(TMP, "baseline_history")
ep.LOG_FILE = os.path.join(TMP, "protector.log")
ep.PROGRAM_NAMES_FILE = os.path.join(TMP, "program_names.json")
fh = logging.FileHandler(ep.LOG_FILE, encoding="utf-8")
fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
ep.logger.addHandler(fh)

EXT = ".zzztest999"
PROGID = "TestProgId"
NONLOCKED_EXT = ".zzztest998"
UC_CLASSES = "Software" + "\\" + "Classes"

out("TMP =", TMP)
out("HKCU_REMAPPED =", ep.HKCU_REMAPPED)

def reg_get_default(root, path):
    try:
        k = winreg.OpenKeyEx(root, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
        try:
            v, t = winreg.QueryValueEx(k, None)
            return ("EXISTS_DEFAULT=%r" % v)
        except FileNotFoundError:
            return ("EXISTS_NODEDEFAULT")
        finally:
            winreg.CloseKey(k)
    except FileNotFoundError:
        return ("MISSING")
    except OSError as e:
        return ("OSERROR %r" % e)

# ---------- 权限探针 ----------
out("=" * 70)
out("权限/令牌状态")
try:
    import ctypes
    tok = ctypes.c_void_p()
    hproc = ctypes.windll.kernel32.GetCurrentProcess()
    ctypes.windll.advapi32.OpenProcessToken(hproc, 0x0008, ctypes.byref(tok))
    elev = ctypes.c_uint32(0); rl = ctypes.c_uint32(4)
    ctypes.windll.advapi32.GetTokenInformation(tok, 20, ctypes.byref(elev), 4, ctypes.byref(rl))
    out("TokenElevation=1(管理员提权):", bool(elev.value))
except Exception as e:
    out("TokenElevation 探测异常:", e)

out("KEY_SET_VALUE 模块全局是否存在:", hasattr(ep, "KEY_SET_VALUE"))
out("KEY_SET_VALUE_64 模块全局是否存在:", hasattr(ep, "KEY_SET_VALUE_64"))
out("winreg.KEY_SET_VALUE 属性值:", getattr(winreg, "KEY_SET_VALUE", "N/A"))

# ---------- 构造 BaselineManager + ProtectionEngine ----------
bm = ep.BaselineManager()
bm.config["locked_defaults"] = {EXT: PROGID}
bm.save_config()
pe = ep.ProtectionEngine(bm)
out("locked_defaults =", bm.config.get("locked_defaults"))

# ============================================================
out("=" * 70)
out("TEST 1A [原样，不打任何补丁]: recover_extension -> _recover_locked 真实 shipping 行为")
mismatches = [("userchoice_progid", {}, {}, None)]
resA = None
try:
    resA = pe.recover_extension(EXT, mismatches)
    out("return:", resA)
except Exception:
    out(">>> 抛出异常（这是 shipping 代码的真实行为，非测试脚本错误）:")
    out(traceback.format_exc())
out("-- 1A 后注册表回读 --")
out("HKCR\\%s : %s" % (EXT, reg_get_default(ep.HKCR, EXT)))
out("HKCU\\Classes\\%s : %s" % (EXT, reg_get_default(ep.HKCU, UC_CLASSES + "\\" + EXT)))

# ============================================================
out("=" * 70)
out("TEST 1B [测试进程内补注入缺失的 KEY_SET_VALUE 全局，仅作用于本测试进程]:")
out("    ep.KEY_SET_VALUE = winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY")
ep.KEY_SET_VALUE = winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY   # 仅运行时命名空间补丁，不改源文件
resB = None
try:
    s, f, details = pe.recover_extension(EXT, mismatches)
    resB = (s, f, details)
    out("return success=%s fail=%s" % (s, f))
    out("details 原文逐行:")
    for d in details:
        out("   |", d)
    out("-- assertions --")
    out("不含'基准不存在'(=> 走了 _recover_locked 分支):", "基准不存在" not in details)
    out("含'HKCR默认:已设为锁定应用':", any("HKCR默认:已设为锁定应用" in d for d in details))
    out("含'HKCR默认:写入失败':", any("HKCR默认:写入失败" in d for d in details))
    out("含'键已不存在(无需删除)':", any("键已不存在(无需删除)" in d for d in details))
    out("含'OpenWithProgids:已加入锁定应用':", any("OpenWithProgids:已加入锁定应用" in d for d in details))
    out("含'基准:已同步锁定态':", any("基准:已同步锁定态" in d for d in details))
except Exception:
    out(">>> 1B 仍异常:")
    out(traceback.format_exc())

out("-- 1B 后真实注册表回读（判断 HKCR 写入实际落到哪个根、是否成功）--")
out("HKCR\\%s : %s" % (EXT, reg_get_default(ep.HKCR, EXT)))
out("HKCU\\Classes\\%s : %s" % (EXT, reg_get_default(ep.HKCU, UC_CLASSES + "\\" + EXT)))
out("HKLM\\Classes\\%s : %s" % (EXT, reg_get_default(ep.HKLM, "SOFTWARE\\Classes\\" + EXT)))
try:
    k = winreg.OpenKeyEx(ep.HKCR, EXT + r"\OpenWithProgids", 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
    vals = []
    i = 0
    while True:
        try: vals.append(winreg.EnumValue(k, i))
        except OSError: break
        i += 1
    winreg.CloseKey(k)
    out("HKCR\\%s\\OpenWithProgids 值: %s" % (EXT, vals))
except OSError as e:
    out("HKCR\\%s\\OpenWithProgids 读不到: %r" % (EXT, e))

# ============================================================
out("=" * 70)
out("TEST 2: force_delete_userchoice('%s')" % EXT)
try:
    ret = ep.force_delete_userchoice(EXT)
    out("return:", repr(ret))
    out("断言 == (True, '键已不存在(无需删除)'):", ret == (True, "键已不存在(无需删除)"))
except Exception:
    out(traceback.format_exc())

# ============================================================
out("=" * 70)
out("TEST 3: create_baseline(mode='current') 后 _reapply_locked_defaults 重新落实锁定")
locked_before = dict(bm.config.get("locked_defaults", {}))
orig_enum = ep.enumerate_all_extensions
ep.enumerate_all_extensions = lambda: [EXT]
try:
    n = bm.create_baseline(mode="current")
    out("create_baseline ext count =", n)
    out("locked_defaults after:", bm.config.get("locked_defaults"))
    out("B1 locked_defaults 保持原值:", bm.config.get("locked_defaults") == locked_before)
    out("B2 基准中 '%s' 已同步:" % EXT, EXT in bm.baseline)
    out("B3 真实 HKCR 回读（_reapply_locked_defaults 的 HKCR 写入是否真落地）:")
    out("   HKCR\\%s : %s" % (EXT, reg_get_default(ep.HKCR, EXT)))
    out("   HKCU\\Classes\\%s : %s" % (EXT, reg_get_default(ep.HKCU, UC_CLASSES + "\\" + EXT)))
except Exception:
    out(traceback.format_exc())
finally:
    ep.enumerate_all_extensions = orig_enum

# ============================================================
out("=" * 70)
out("TEST 4: _handle_change 锁定静默分支 + allowed_this_cycle 顺序分支")
mt = ep.MonitorThread.__new__(ep.MonitorThread)
mt.engine = pe
mt._handling_exts = set()
logs = []
mt.log_callback = lambda msg, level="info": logs.append((level, str(msg)))
mt.popup_callback = lambda *a, **k: logs.append(("POPUP", str(a)))

orig_rwv = ep.MonitorThread._recover_with_verify
call_records = []
def fake_rwv(self, ext, mismatches, max_retries=3):
    call_records.append((ext, [tuple(m) for m in mismatches]))
    return (1, 0, ["ok"], True)
ep.MonitorThread._recover_with_verify = fake_rwv
try:
    call_records.clear(); logs.clear()
    mt._handle_change(EXT, [("userchoice_progid", {}, {}, None)])
    out("4a 锁定扩展名: _recover_with_verify 调用次数:", len(call_records), call_records)
    out("4a log_callback 收到:")
    for lv, msg in logs: out("    [%s] %s" % (lv, msg))
    out("4a 含'锁定中，不弹窗':", any("锁定中，不弹窗" in m for _, m in logs))
    out("4a 含 POPUP 调用(应为 False):", any(lv == "POPUP" for lv, _ in logs))

    pe.allowed_this_cycle.add(NONLOCKED_EXT)
    call_records.clear(); logs.clear()
    mt._handle_change(NONLOCKED_EXT, [("userchoice_progid", {}, {}, None)])
    out("4b 非锁定+allowed_this_cycle: _recover_with_verify 调用次数(应=0):", len(call_records))
    out("4b log_callback 条数(应=0):", len(logs))
finally:
    ep.MonitorThread._recover_with_verify = orig_rwv

# ============================================================
out("=" * 70)
out("TEST 6: 递归删除虚构扩展名注册表键")
def delete_subtree(root, path):
    det = []
    try:
        k = winreg.OpenKeyEx(root, path, 0, winreg.KEY_ALL_ACCESS | winreg.KEY_WOW64_64KEY)
    except OSError as e:
        return False, ["open %s -> %r (本就不存在)" % (path, e)]
    try:
        while True:
            try: sub = winreg.EnumKey(k, 0)
            except OSError: break
            sp = path + "\\" + sub
            delete_subtree(root, sp)
            try:
                winreg.DeleteKey(k, sub); det.append("del subkey %s" % sp)
            except OSError as e:
                det.append("FAIL subkey %s: %r" % (sp, e))
    finally:
        winreg.CloseKey(k)
    try:
        winreg.DeleteKey(root, path); det.append("del key %s" % path); return True, det
    except OSError as e:
        det.append("FAIL key %s: %r" % (path, e)); return False, det

for label, root, path in [
    ("HKCR", ep.HKCR, EXT),
    ("HKCU\\Software\\Classes", ep.HKCU, UC_CLASSES + "\\" + EXT),
    ("HKLM\\SOFTWARE\\Classes", ep.HKLM, "SOFTWARE\\Classes\\" + EXT),
]:
    ok, det = delete_subtree(root, path)
    out("清理 %s\\%s ok=%s" % (label, EXT, ok))
    for d in det: out("    ", d)

out("-- 清理后回读证明 --")
out("HKCR\\%s : %s" % (EXT, reg_get_default(ep.HKCR, EXT)))
out("HKCU\\Classes\\%s : %s" % (EXT, reg_get_default(ep.HKCU, UC_CLASSES + "\\" + EXT)))
out("HKLM\\Classes\\%s : %s" % (EXT, reg_get_default(ep.HKLM, "SOFTWARE\\Classes\\" + EXT)))

out("=" * 70)
out("DONE")
RAW.close()
