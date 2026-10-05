#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
扩展名保护卫士 (Extension Association Protector)
阻止第三方软件私自改写文件扩展名默认打开方式

保护7项注册表位置：
  1. HKCR\.ext                          (默认值)
  2. HKCU\Software\Classes\.ext         (默认值)
  3. HKLM\SOFTWARE\Classes\.ext         (默认值)
  4. UserChoice ProgId
  5. UserChoice Hash
  6. HKCR\{ProgId}\shell\open\command   (默认值)
  7. HKCU\Software\Classes\{ProgId}\shell\open\command (默认值)
"""

# SPDX-License-Identifier: MIT
# Copyright (c) 2026 OPSTcontroller contributors
# 依据 LICENSE 文件（MIT License）分发。

import winreg
import json
import os
import sys
import time
import threading
import logging
import ctypes
import shutil
import glob
import tempfile
import subprocess
from ctypes import wintypes

# 隐藏窗口的subprocess.run封装（避免弹cmd/powershell黑窗）
_HIDDEN_SI = subprocess.STARTUPINFO()
_HIDDEN_SI.dwFlags |= subprocess.STARTF_USESHOWWINDOW
_HIDDEN_SI.wShowWindow = 0  # SW_HIDE
_CREATE_NO_WINDOW = 0x08000000

def _run(cmd, **kwargs):
    """运行外部命令，完全隐藏窗口"""
    kwargs.setdefault('startupinfo', _HIDDEN_SI)
    kwargs.setdefault('creationflags', _CREATE_NO_WINDOW)
    # text 模式下统一按 UTF-8 + 替换符解码：
    # 中文系统命令输出常为 ANSI/GBK，严格 UTF-8 会在读取线程抛 UnicodeDecodeError。
    # 替换符不影响 ASCII 关键串（如进程名）的匹配。
    if kwargs.get('text', False) and 'encoding' not in kwargs:
        kwargs['encoding'] = 'utf-8'
        kwargs.setdefault('errors', 'replace')
    return subprocess.run(cmd, **kwargs)

def _popen(cmd, **kwargs):
    """Popen封装，隐藏窗口"""
    kwargs.setdefault('startupinfo', _HIDDEN_SI)
    kwargs.setdefault('creationflags', _CREATE_NO_WINDOW)
    return subprocess.Popen(cmd, **kwargs)
from datetime import datetime
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox

# ============================================================
# 配置常量 - 发行版目录结构
#   主程序.exe          (根目录)
#   runtime/            (运行时资源、说明等)
#   userdata/           (基准、配置、日志、历史版本)
# ============================================================
APP_NAME = "OPSTcontroller"
APP_VERSION = "0.8.1"
MUTEX_NAME = "OPSTcontroller_SingleInstance_Mutex"
EXIT_EVENT_NAME = "OPSTcontroller_Exit_Event"
SHOW_EVENT_NAME = "OPSTcontroller_Show_Window_Event"
AUTOSTART_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
NSUDO_ROOT = ""  # 在 RUNTIME_DIR 计算后赋值，见下方
NSUDO_CANDIDATES = ("NSudoLC.exe", "NSudoLG.exe", "NSudo.exe")

# 判断是否为 PyInstaller 打包环境
if getattr(sys, 'frozen', False):
    APP_DIR = os.path.dirname(sys.executable)
else:
    APP_DIR = os.path.dirname(os.path.abspath(__file__))

RUNTIME_DIR = os.path.join(APP_DIR, "runtime")
USERDATA_DIR = os.path.join(APP_DIR, "userdata")

# NSudo 提权工具查找根：优先运行时目录，可用环境变量 OPST_NSudo_PATH 覆盖。
# 严禁硬编码个人绝对路径（泄露开发环境信息，且换机即失效）。
NSUDO_ROOT = os.environ.get("OPST_NSudo_PATH", "") or RUNTIME_DIR

# 确保目录存在
os.makedirs(RUNTIME_DIR, exist_ok=True)
os.makedirs(USERDATA_DIR, exist_ok=True)

BASELINE_FILE = os.path.join(USERDATA_DIR, "baseline.json")
HISTORY_DIR = os.path.join(USERDATA_DIR, "baseline_history")
LOG_FILE = os.path.join(USERDATA_DIR, "protector.log")
CONFIG_FILE = os.path.join(USERDATA_DIR, "config.json")
PROGRAM_NAMES_FILE = os.path.join(USERDATA_DIR, "program_names.json")

MAX_HISTORY_VERSIONS = 5
POLL_INTERVAL = 2          # 轮询间隔(秒)
DEEP_SCAN_INTERVAL = 600   # 深层扫描间隔(秒)，7位置全量扫描较慢，10分钟一次
NOTIFY_TIMEOUT = 15         # 通知显示时长(秒)，超时默认阻止（用户要求弹窗时间不能太短）
COOLDOWN_SECONDS = 30       # 同一扩展名恢复后冷却时间(秒)，期间静默恢复不弹窗
OPERATION_MODES = [
    "normal",
    "quiet",
    "game",
    "demo",
    "silent",
    "paused",
]
AUDIT_LEVELS = ["minimal", "normal", "detailed", "full"]

# 注册表根键
HKCR = winreg.HKEY_CLASSES_ROOT
HKCU = winreg.HKEY_CURRENT_USER  # 注意：TI/SYSTEM下会被重映射到当前用户配置单元
HKLM = winreg.HKEY_LOCAL_MACHINE
HKEY_USERS = winreg.HKEY_USERS

# UserChoice 基础路径
USERCHOICE_BASE = r"Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts"

# 注册表访问权限 (64位视图)
KEY_ALL_ACCESS_64 = winreg.KEY_ALL_ACCESS | winreg.KEY_WOW64_64KEY
KEY_READ_64 = winreg.KEY_READ | winreg.KEY_WOW64_64KEY
KEY_SET_VALUE_64 = winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY

# ============================================================
# ctypes - RegNotifyChangeKeyValue 实时监控
# ============================================================
advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

LONG = ctypes.c_long
DWORD = ctypes.c_uint32
BOOL = ctypes.c_int
HKEY_T = ctypes.c_void_p
HANDLE = ctypes.c_void_p

_RegNotifyChangeKeyValue = advapi32.RegNotifyChangeKeyValue
_RegNotifyChangeKeyValue.restype = LONG
_RegNotifyChangeKeyValue.argtypes = [HKEY_T, BOOL, DWORD, HANDLE, BOOL]

_CreateEventW = kernel32.CreateEventW
_CreateEventW.restype = HANDLE
_CreateEventW.argtypes = [ctypes.c_void_p, BOOL, BOOL, ctypes.c_wchar_p]

_WaitForSingleObject = kernel32.WaitForSingleObject
_WaitForSingleObject.restype = DWORD
_WaitForSingleObject.argtypes = [HANDLE, DWORD]

# === ACL/安全描述符相关API ===
class _LUID(ctypes.Structure):
    _fields_ = [("LowPart", DWORD), ("HighPart", ctypes.c_long)]
class _LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", _LUID), ("Attributes", DWORD)]
class _TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [("PrivilegeCount", DWORD), ("Privileges", _LUID_AND_ATTRIBUTES * 1)]

_SE_PRIVILEGE_ENABLED = 0x00000002
_TOKEN_ADJUST_PRIVILEGES = 0x0020
_TOKEN_QUERY = 0x0008
_DACL_SECURITY_INFORMATION = 0x00000004
_SACL_SECURITY_INFORMATION = 0x00000008
_KEY_WRITE_DAC = 0x00040000
_KEY_READ_CONTROL = 0x00020000
_ACCESS_SYSTEM_SECURITY = 0x01000000

_OpenProcessToken = advapi32.OpenProcessToken
_OpenProcessToken.restype = BOOL
_OpenProcessToken.argtypes = [HANDLE, DWORD, ctypes.POINTER(HANDLE)]
_LookupPrivilegeValueW = advapi32.LookupPrivilegeValueW
_LookupPrivilegeValueW.restype = BOOL
_LookupPrivilegeValueW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.POINTER(_LUID)]
_AdjustTokenPrivileges = advapi32.AdjustTokenPrivileges
_AdjustTokenPrivileges.restype = BOOL
_AdjustTokenPrivileges.argtypes = [HANDLE, BOOL, ctypes.POINTER(_TOKEN_PRIVILEGES), DWORD, ctypes.c_void_p, ctypes.c_void_p]
_RegOpenKeyExW = advapi32.RegOpenKeyExW
_RegOpenKeyExW.restype = LONG
_RegOpenKeyExW.argtypes = [HKEY_T, ctypes.c_wchar_p, DWORD, DWORD, ctypes.POINTER(HKEY_T)]
_RegCloseKey = advapi32.RegCloseKey
_RegCloseKey.restype = LONG
_RegCloseKey.argtypes = [HKEY_T]
_ConvertStringSDToSD = advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW
_ConvertStringSDToSD.restype = BOOL
_ConvertStringSDToSD.argtypes = [ctypes.c_wchar_p, DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_ulong)]
_SetKernelObjectSecurity = advapi32.SetKernelObjectSecurity
_SetKernelObjectSecurity.restype = BOOL
_SetKernelObjectSecurity.argtypes = [HANDLE, DWORD, ctypes.c_void_p]
_LocalFree = kernel32.LocalFree
_LocalFree.restype = ctypes.c_void_p
_LocalFree.argtypes = [ctypes.c_void_p]

# TrustedInstaller SID
_TI_SID = "S-1-5-80-956008885-3418522649-1831038040-1699080151-2041879083"

def _enable_privilege(priv_name):
    """启用当前进程的指定特权。
    返回 True 仅当特权实际启用成功；AdjustTokenPrivileges 返回 TRUE 但
    GetLastError 为 ERROR_NOT_ALL_ASSIGNED（令牌中特权被移除）时视为失败。"""
    try:
        hToken = HANDLE()
        if not _OpenProcessToken(kernel32.GetCurrentProcess(), _TOKEN_ADJUST_PRIVILEGES | _TOKEN_QUERY, ctypes.byref(hToken)):
            return False
        luid = _LUID()
        if not _LookupPrivilegeValueW(None, priv_name, ctypes.byref(luid)):
            kernel32.CloseHandle(hToken)
            return False
        tp = _TOKEN_PRIVILEGES()
        tp.PrivilegeCount = 1
        tp.Privileges[0].Luid = luid
        tp.Privileges[0].Attributes = _SE_PRIVILEGE_ENABLED
        result = _AdjustTokenPrivileges(hToken, False, ctypes.byref(tp), 0, None, None)
        err = ctypes.get_last_error()
        kernel32.CloseHandle(hToken)
        # 成功 = 返回非0 且 未报告"特权未全部分配"(1300)。
        # 注意：AdjustTokenPrivileges 成功时并不保证把 GetLastError 清零，
        # 因此不能要求 err==0（否则会把成功误判为失败）；1300 才是真实失败信号。
        return result != 0 and err != 1300
    except Exception:
        return False

def set_registry_acl_ctypes(root, sub_key, lock=True):
    """用ctypes直接设置注册表键ACL（不依赖PowerShell）。
    lock=True: 仅SYSTEM/TI可写，拒绝Users/Administrators写入 + System完整性标签
    lock=False: 恢复宽松ACL（允许SYSTEM/BA/BU完全控制）
    返回 (success, message)"""
    # 启用必要特权
    _enable_privilege("SeSecurityPrivilege")
    _enable_privilege("SeRestorePrivilege")
    _enable_privilege("SeTakeOwnershipPrivilege")
    try:
        hKey = HKEY_T()
        access = _KEY_WRITE_DAC | _KEY_READ_CONTROL | _ACCESS_SYSTEM_SECURITY
        ret = _RegOpenKeyExW(root, sub_key, 0, access, ctypes.byref(hKey))
        if ret != 0:
            return False, f"RegOpenKeyEx失败(err={ret})"
        try:
            if lock:
                # SDDL: 允许SYSTEM和TI完全控制，拒绝Users/BA写入，System完整性标签
                sddl = (f"D:(A;;KA;;;SY)(A;;KA;;;{_TI_SID})"
                        f"(D;;SD;;;BU)(D;;SD;;;BA)"
                        f"S:(ML;;NW;;;S-1-16-16384)")
            else:
                # 解锁：允许SYSTEM/BA/BU/TI完全控制，无完整性标签
                sddl = f"D:(A;;KA;;;SY)(A;;KA;;;BA)(A;;KA;;;BU)(A;;KA;;;{_TI_SID})"
            pSD = ctypes.c_void_p()
            sdLen = ctypes.c_ulong()
            if not _ConvertStringSDToSD(sddl, 1, ctypes.byref(pSD), ctypes.byref(sdLen)):
                return False, "SDDL转换失败"
            try:
                sec_info = _DACL_SECURITY_INFORMATION
                if lock:
                    sec_info |= _SACL_SECURITY_INFORMATION
                if not _SetKernelObjectSecurity(hKey, sec_info, pSD):
                    err = ctypes.get_last_error()
                    return False, f"SetSecurity失败(err={err})"
                return True, "OK"
            finally:
                _LocalFree(pSD)
        finally:
            _RegCloseKey(hKey)
    except Exception as e:
        return False, f"异常:{str(e)[:50]}"

def protect_self_process():
    """设置当前进程ACL，防止被任务管理器/普通进程终止。
    仅SYSTEM/TI可终止，拒绝Users/Administrators的终止和挂起权限。

    分级策略（自我保护失效修复，2026-10-04）：
      - 完整模式：SeSecurityPrivilege 可用 → DACL+SACL（含 System 完整性标签）
      - 降级模式：特权被移除/不可用（如 NSudo 受限令牌）→ 仅写 DACL，
        不依赖任何特权，仍拒绝 Users/管理员 的终止/挂起（0x00000A01）。
    返回 (success, message)"""
    try:
        sec_enabled = _enable_privilege("SeSecurityPrivilege")
        _enable_privilege("SeDebugPrivilege")
        # 获取当前进程伪句柄
        hProcess = kernel32.GetCurrentProcess()
        # 完整SDDL: 允许SYSTEM和TI完全控制，拒绝Users/BA终止和挂起，System完整性标签
        # PROCESS_TERMINATE=0x1, PROCESS_SUSPEND_RESUME=0x800, PROCESS_SET_INFORMATION=0x200
        full_sddl = ("D:(A;;KA;;;SY)(A;;KA;;;" + _TI_SID + ")"
                     "(D;;0x00000A01;;;BU)(D;;0x00000A01;;;BA)"
                     "S:(ML;;NW;;;S-1-16-16384)")
        # 降级SDDL: 仅DACL，不写SACL（写SACL需要SeSecurityPrivilege）
        dacl_sddl = ("D:(A;;KA;;;SY)(A;;KA;;;" + _TI_SID + ")"
                     "(D;;0x00000A01;;;BU)(D;;0x00000A01;;;BA)")
        sddl = full_sddl
        sec_info = _DACL_SECURITY_INFORMATION | _SACL_SECURITY_INFORMATION
        mode = "完整保护（DACL+SACL+完整性标签）"
        if not sec_enabled:
            sddl = dacl_sddl
            sec_info = _DACL_SECURITY_INFORMATION
            mode = "降级保护（仅DACL，特权不可用）"
        pSD = ctypes.c_void_p()
        sdLen = ctypes.c_ulong()
        if not _ConvertStringSDToSD(sddl, 1, ctypes.byref(pSD), ctypes.byref(sdLen)):
            return False, "SDDL转换失败"
        try:
            if not _SetKernelObjectSecurity(hProcess, sec_info, pSD):
                err = ctypes.get_last_error()
                # 完整模式失败时自动再试纯DACL（防止SACL写入失败导致整体不生效）
                if sec_info & _SACL_SECURITY_INFORMATION:
                    _LocalFree(pSD)
                    pSD = ctypes.c_void_p()
                    if not _ConvertStringSDToSD(dacl_sddl, 1, ctypes.byref(pSD), ctypes.byref(sdLen)):
                        return False, "SDDL转换失败"
                    if not _SetKernelObjectSecurity(hProcess, _DACL_SECURITY_INFORMATION, pSD):
                        err2 = ctypes.get_last_error()
                        return False, f"SetSecurity失败(err={err2})"
                    return True, "进程保护已启用（降级：DACL拒绝终止，SACL不可用）"
                return False, f"SetSecurity失败(err={err})"
            return True, f"进程保护已启用（{mode}）"
        finally:
            _LocalFree(pSD)
    except Exception as e:
        return False, f"异常:{str(e)[:80]}"


_ResetEvent = kernel32.ResetEvent
_ResetEvent.restype = BOOL
_ResetEvent.argtypes = [HANDLE]

_CloseHandle = kernel32.CloseHandle
_CloseHandle.restype = BOOL
_CloseHandle.argtypes = [HANDLE]

_CreateMutexW = kernel32.CreateMutexW
_CreateMutexW.restype = HANDLE
_CreateMutexW.argtypes = [ctypes.c_void_p, BOOL, ctypes.c_wchar_p]

REG_NOTIFY_CHANGE_NAME = 0x00000001
REG_NOTIFY_CHANGE_ATTRIBUTES = 0x00000002
REG_NOTIFY_CHANGE_LAST_SET = 0x00000004
REG_NOTIFY_CHANGE_SECURITY = 0x00000008
REG_NOTIFY_FILTER = (REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET
                     | REG_NOTIFY_CHANGE_ATTRIBUTES | REG_NOTIFY_CHANGE_SECURITY)

INFINITE = 0xFFFFFFFF
WAIT_OBJECT_0 = 0x00000000
WAIT_TIMEOUT = 0x00000102

# ============================================================
# 日志系统
# ============================================================
def setup_logger():
    logger = logging.getLogger("ExtProtector")
    logger.setLevel(logging.DEBUG)
    # 安全日志轮转：写入前手动检查大小并备份（多进程共用日志文件时
    # RotatingFileHandler 的 rename 轮转会因另一进程占用句柄而异常，
    # 故采用"检查-截断-备份"的轻量轮转，不依赖文件重命名）
    fh = _SafeRotatingFileHandler(LOG_FILE, max_bytes=2 * 1024 * 1024,
                                  backup_count=3, encoding='utf-8')
    fh.setLevel(logging.DEBUG)
    fmt = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s',
                            datefmt='%Y-%m-%d %H:%M:%S')
    fh.setFormatter(fmt)
    logger.addHandler(fh)
    return logger


class _SafeRotatingFileHandler(logging.FileHandler):
    """轻量安全轮转：追加写入前检查文件大小，超限先做截断备份。
    不使用重命名（多进程下 rename 会因句柄占用抛 PermissionError）。"""

    def __init__(self, filename, max_bytes=2 * 1024 * 1024, backup_count=3,
                 encoding=None):
        self.max_bytes = max_bytes
        self.backup_count = backup_count
        super().__init__(filename, mode="a", encoding=encoding)

    def _maybe_rotate(self):
        try:
            size = os.path.getsize(self.baseFilename)
        except OSError:
            return
        if size < self.max_bytes:
            return
        try:
            # 轮转前必须先关闭本进程的打开句柄，否则 Windows 下
            # rename 被占用文件会抛 PermissionError（Python 默认共享不含 DELETE）
            if self.stream is not None:
                try:
                    self.stream.close()
                except Exception:
                    pass
                self.stream = None
            # 备份：protector.log -> protector.log.1 -> .2 -> .3
            for i in range(self.backup_count - 1, 0, -1):
                src = f"{self.baseFilename}.{i}"
                dst = f"{self.baseFilename}.{i + 1}"
                if os.path.exists(src):
                    os.replace(src, dst)
            if os.path.exists(self.baseFilename):
                os.replace(self.baseFilename, f"{self.baseFilename}.1")
        except OSError:
            pass  # 轮转失败不影响主日志记录
        finally:
            if self.stream is None:
                try:
                    self.stream = self._open()
                except Exception:
                    pass

    def emit(self, record):
        try:
            self._maybe_rotate()
        except Exception:
            pass
        try:
            super().emit(record)
        except Exception:
            pass

logger = setup_logger()


def log_event(extension, action, status, reason=""):
    """统一日志格式: 扩展名:操作:状态:原因"""
    msg = f"{extension}:{action}:{status}"
    if reason:
        msg += f":{reason}"
    logger.info(msg)
    return msg


# ============================================================
# 注册表辅助工具
# ============================================================
ROOT_MAP = {
    "HKCR": HKCR,
    "HKCU": HKCU,
    "HKLM": HKLM,
}
ROOT_NAME_MAP = {v: k for k, v in ROOT_MAP.items()}


def reg_open(root, path, access=KEY_READ_64):
    """打开注册表项，失败返回 None"""
    try:
        return winreg.OpenKey(root, path, 0, access)
    except OSError:
        return None


def reg_read_value(root, path, name=""):
    """读取注册表值，返回 (value, type) 或 (None, None)"""
    key = reg_open(root, path)
    if key is None:
        return None, None
    try:
        val, typ = winreg.QueryValueEx(key, name)
        return val, typ
    except OSError:
        return None, None
    finally:
        winreg.CloseKey(key)


def reg_write_value(root, path, name, value, typ):
    """写入注册表值，自动创建键。返回 bool"""
    try:
        key = winreg.CreateKeyEx(root, path, 0, KEY_ALL_ACCESS_64)
        winreg.SetValueEx(key, name, 0, typ, value)
        winreg.CloseKey(key)
        return True
    except OSError as e:
        logger.error(f"写入失败 {ROOT_NAME_MAP.get(root)}\\{path}\\{name}: {e}")
        return False


def reg_delete_value(root, path, name=""):
    """删除注册表值，返回 bool"""
    key = reg_open(root, path, KEY_SET_VALUE_64)
    if key is None:
        return True  # 不存在即已删除
    try:
        winreg.DeleteValue(key, name)
        winreg.CloseKey(key)
        return True
    except OSError:
        try:
            winreg.CloseKey(key)
        except OSError:
            pass
        return False


def read_hkcr_effective(path, name=""):
    """
    HKCR 合并视图读取（返回真实生效值）。
    TI/SYSTEM 下 HKEY_CLASSES_ROOT 只合并 HKLM/SOFTWARE/Classes 与 SYSTEM 自身
    HKCU/Software/Classes，不含交互用户的 HKCU/Software/Classes 覆盖。
    而 Windows 关联解析时用户 HKCU/Software/Classes 优先于 HKLM，因此
    TI 模式下必须手动合并用户覆盖；普通模式 HKCU 即当前用户，直接读 HKCR。
    """
    if HKCU_REMAPPED:
        v, t = reg_read_value(HKCU, "Software\\Classes\\" + path, name)
        if v is not None:
            return v, t
    return reg_read_value(HKCR, path, name)


def reg_delete_key(root, path):
    """删除注册表项，返回 bool。键不存在也视为成功（已删除状态）。"""
    try:
        winreg.DeleteKey(root, path)
        return True
    except FileNotFoundError:
        return True  # 键不存在，即已删除
    except OSError:
        return False


# ============================================================
# 强制刷新系统文件关联缓存
# 修改注册表后必须调用，否则 Windows 可能继续使用缓存的旧关联
# ============================================================
_Shell32 = ctypes.WinDLL('shell32', use_last_error=True)
_SHCNE_ASSOCCHANGED = 0x08000000
_SHCNF_IDLIST = 0x0000
_SHCNF_FLUSH = 0x1000

_last_refresh_time = 0
_REFRESH_DEBOUNCE = 10  # 最小刷新间隔(秒)，避免桌面图标频繁闪烁

def refresh_file_associations(force=False):
    """通知 Windows 刷新文件关联缓存。去抖处理，避免桌面图标频繁闪烁。"""
    global _last_refresh_time
    now = time.time()
    if not force and (now - _last_refresh_time) < _REFRESH_DEBOUNCE:
        return True  # 去抖：跳过本次刷新
    _last_refresh_time = now
    try:
        _Shell32.SHChangeNotify(
            _SHCNE_ASSOCCHANGED,
            _SHCNF_IDLIST | _SHCNF_FLUSH,
            None, None
        )
    except Exception:
        pass
    # 注意：不发送 WM_SETTINGCHANGE 广播，那是环境变量用的，会导致桌面额外刷新
    return True


# ============================================================
# 强制写入注册表值（使用备份/恢复权限绕过 ACL）
# 用于 UserChoice 等被 Windows 保护的注册表键
# ============================================================
_SE_BACKUP = "SeBackupPrivilege"
_SE_RESTORE = "SeRestorePrivilege"
_SE_ENABLED = 0x00000002
_REG_OPTION_BACKUP_RESTORE = 0x00000004
_KEY_ALL_ACCESS = 0xF003F
_TOKEN_ADJUST_PRIVILEGES = 0x0020
_TOKEN_QUERY = 0x0008


class _REG_LUID(ctypes.Structure):
    _fields_ = [("LowPart", ctypes.c_ulong), ("HighPart", ctypes.c_long)]


class _REG_LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", _REG_LUID), ("Attributes", ctypes.c_ulong)]


class _REG_TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [("PrivilegeCount", ctypes.c_ulong), ("Privileges", _REG_LUID_AND_ATTRIBUTES * 1)]


_advapi32_reg = ctypes.WinDLL('advapi32', use_last_error=True)
_kernel32_reg = ctypes.WinDLL('kernel32', use_last_error=True)

_RegAdjustTokenPrivileges = _advapi32_reg.AdjustTokenPrivileges
_RegAdjustTokenPrivileges.restype = LONG
_RegAdjustTokenPrivileges.argtypes = [HANDLE, BOOL, ctypes.c_void_p, DWORD, ctypes.c_void_p, ctypes.c_void_p]

_RegLookupPrivilegeValueW = _advapi32_reg.LookupPrivilegeValueW
_RegLookupPrivilegeValueW.restype = BOOL
_RegLookupPrivilegeValueW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.POINTER(_REG_LUID)]

_RegCreateKeyExW = _advapi32_reg.RegCreateKeyExW
_RegCreateKeyExW.restype = LONG
_RegCreateKeyExW.argtypes = [HKEY_T, ctypes.c_wchar_p, DWORD, ctypes.c_wchar_p, DWORD, DWORD,
                             ctypes.c_void_p, ctypes.POINTER(HKEY_T), ctypes.POINTER(DWORD)]

_RegSetValueExW = _advapi32_reg.RegSetValueExW
_RegSetValueExW.restype = LONG
_RegSetValueExW.argtypes = [HKEY_T, ctypes.c_wchar_p, DWORD, DWORD, ctypes.c_void_p, DWORD]

_RegCloseKey = _advapi32_reg.RegCloseKey
_RegCloseKey.restype = LONG
_RegCloseKey.argtypes = [HKEY_T]

_RegGetCurrentProcess = _kernel32_reg.GetCurrentProcess
_RegGetCurrentProcess.restype = HANDLE
_RegGetCurrentProcess.argtypes = []

_RegOpenProcessToken = _advapi32_reg.OpenProcessToken
_RegOpenProcessToken.restype = BOOL
_RegOpenProcessToken.argtypes = [HANDLE, DWORD, ctypes.POINTER(HANDLE)]

_RegCloseHandle = _kernel32_reg.CloseHandle
_RegCloseHandle.restype = BOOL
_RegCloseHandle.argtypes = [HANDLE]


def _enable_privilege_for_reg(priv_name):
    """启用指定权限，返回 bool"""
    hToken = HANDLE()
    if not _RegOpenProcessToken(_RegGetCurrentProcess(), _TOKEN_ADJUST_PRIVILEGES | _TOKEN_QUERY, ctypes.byref(hToken)):
        return False
    luid = _REG_LUID()
    if not _RegLookupPrivilegeValueW(None, priv_name, ctypes.byref(luid)):
        _RegCloseHandle(hToken)
        return False
    tp = _REG_TOKEN_PRIVILEGES()
    tp.PrivilegeCount = 1
    tp.Privileges[0].Luid = luid
    tp.Privileges[0].Attributes = _SE_ENABLED
    result = _RegAdjustTokenPrivileges(hToken, False, ctypes.byref(tp), 0, None, None)
    _RegCloseHandle(hToken)
    return result != 0


def force_write_reg_value(root_hkey, path, name, value, reg_type):
    """
    使用备份/恢复权限强制写入注册表值，绕过 ACL 保护。
    适用于 UserChoice 等被 Windows 保护拒绝普通写入的注册表键。
    返回 bool
    """
    # 启用备份和恢复权限
    if not _enable_privilege_for_reg(_SE_BACKUP):
        return False
    if not _enable_privilege_for_reg(_SE_RESTORE):
        return False

    # 使用 REG_OPTION_BACKUP_RESTORE 打开键（绕过 ACL）
    hKey = HKEY_T()
    disposition = DWORD()
    result = _RegCreateKeyExW(
        root_hkey, path, 0, None,
        _REG_OPTION_BACKUP_RESTORE,
        _KEY_ALL_ACCESS,
        None,
        ctypes.byref(hKey),
        ctypes.byref(disposition)
    )
    if result != 0:
        return False

    try:
        if reg_type in (winreg.REG_SZ, winreg.REG_EXPAND_SZ):
            buf = ctypes.create_unicode_buffer(str(value))
            data_size = ctypes.sizeof(buf)
            result = _RegSetValueExW(hKey, name, 0, reg_type, buf, data_size)
        elif reg_type == winreg.REG_DWORD:
            buf = ctypes.c_ulong(int(value))
            result = _RegSetValueExW(hKey, name, 0, reg_type, ctypes.byref(buf), ctypes.sizeof(buf))
        elif reg_type == winreg.REG_BINARY:
            if isinstance(value, str):
                value = value.encode('utf-8')
            buf = (ctypes.c_ubyte * len(value))(*value)
            result = _RegSetValueExW(hKey, name, 0, reg_type, buf, len(value))
        elif reg_type == winreg.REG_MULTI_SZ:
            if isinstance(value, (list, tuple)):
                s = '\x00'.join(str(v) for v in value) + '\x00\x00'
            else:
                s = str(value) + '\x00\x00'
            buf = ctypes.create_unicode_buffer(s)
            data_size = ctypes.sizeof(buf)
            result = _RegSetValueExW(hKey, name, 0, reg_type, buf, data_size)
        else:
            # 未知类型，尝试作为字符串
            buf = ctypes.create_unicode_buffer(str(value))
            data_size = ctypes.sizeof(buf)
            result = _RegSetValueExW(hKey, name, 0, winreg.REG_SZ, buf, data_size)

        return result == 0
    finally:
        _RegCloseKey(hKey)


def reg_enum_subkeys(root, path):
    """枚举子键名列表"""
    key = reg_open(root, path)
    if key is None:
        return []
    result = []
    try:
        i = 0
        while True:
            try:
                result.append(winreg.EnumKey(key, i))
                i += 1
            except OSError:
                break
    finally:
        winreg.CloseKey(key)
    return result


def get_prog_id(ext):
    """获取扩展名当前的 ProgId，优先级 UserChoice > HKCU > HKCR > HKLM"""
    # UserChoice
    val, _ = reg_read_value(HKCU, f"{USERCHOICE_BASE}\\{ext}\\UserChoice", "ProgId")
    if val:
        return val
    # HKCU Classes
    val, _ = reg_read_value(HKCU, f"Software\\Classes\\{ext}", "")
    if val:
        return val
    # HKCR
    val, _ = reg_read_value(HKCR, ext, "")
    if val:
        return val
    # HKLM
    val, _ = reg_read_value(HKLM, f"SOFTWARE\\Classes\\{ext}", "")
    if val:
        return val
    return None


# 已知ProgId模式 → 软件名称映射
_KNOWN_PROGID_MAP = [
    # 网盘/下载
    ("BaiduNetdisk", "百度网盘"),
    ("Thunder", "迅雷"),
    ("Xunlei", "迅雷"),
    ("QQDownload", "QQ旋风"),
    # 视频播放器
    ("PotPlayer", "PotPlayer"),
    ("WMP11", "Windows Media Player"),
    ("QuickTime", "QuickTime"),
    ("VLC", "VLC媒体播放器"),
    ("mpc", "MPC-HC"),
    ("KMPlayer", "KMPlayer"),
    ("GOM", "GOM Player"),
    ("QQPlayer", "QQ影音"),
    ("StormPlayer", "暴风影音"),
    ("Baofeng", "暴风影音"),
    ("XLLiveUD", "迅雷看看"),
    ("iQIYI", "爱奇艺"),
    ("QQLive", "腾讯视频"),
    ("Youku", "优酷"),
    ("MuMu", "MuMu模拟器"),
    # 音乐播放器
    ("foobar", "foobar2000"),
    ("AIMP", "AIMP"),
    ("Winamp", "Winamp"),
    ("iTunes", "iTunes"),
    ("RealPlayer", "RealPlayer"),
    ("QQMusic", "QQ音乐"),
    ("NetEaseMusic", "网易云音乐"),
    ("KuGou", "酷狗音乐"),
    ("KuWo", "酷我音乐"),
    # 文本/代码编辑器
    ("Sublime", "Sublime Text"),
    ("VSCode", "VS Code"),
    ("Code.", "VS Code"),
    ("Notepad", "记事本"),
    ("Notepad++", "Notepad++"),
    ("UltraEdit", "UltraEdit"),
    ("EmEditor", "EmEditor"),
    # 浏览器
    ("Chrome", "Chrome浏览器"),
    ("Firefox", "火狐浏览器"),
    ("MSEdge", "Edge浏览器"),
    ("Opera", "Opera浏览器"),
    ("Brave", "Brave浏览器"),
    ("360se", "360安全浏览器"),
    ("360chrome", "360极速浏览器"),
    ("QQBrowser", "QQ浏览器"),
    ("SogouExplorer", "搜狗浏览器"),
    ("Maxthon", "傲游浏览器"),
    # 压缩软件
    ("7-Zip", "7-Zip"),
    ("WinRAR", "WinRAR"),
    ("HaoZip", "好压"),
    ("Bandizip", "Bandizip"),
    ("360zip", "360压缩"),
    ("2345haozip", "2345好压"),
    ("PeaZip", "PeaZip"),
    # 图片查看/编辑
    ("Photoshop", "Photoshop"),
    ("ACDSee", "ACDSee"),
    ("XnView", "XnView"),
    ("IrfanView", "IrfanView"),
    ("Honeyview", "Honeyview"),
    ("FastStone", "FastStone"),
    ("PhotoViewer", "照片"),
    ("mspaint", "画图"),
    ("Meitu", "美图秀秀"),
    ("Lightroom", "Lightroom"),
    ("Illustrator", "Illustrator"),
    # 办公/PDF
    ("WPS", "WPS Office"),
    ("Word", "Word"),
    ("Excel", "Excel"),
    ("PowerPoint", "PowerPoint"),
    ("Acrobat", "Adobe Acrobat"),
    ("Foxit", "福昕PDF阅读器"),
    ("SumatraPDF", "Sumatra PDF"),
    ("PDFXCview", "PDF-XChange Viewer"),
    # 通讯/办公
    ("QQ", "QQ"),
    ("WeChat", "微信"),
    ("DingTalk", "钉钉"),
    ("WXWork", "企业微信"),
    ("TencentMeeting", "腾讯会议"),
    ("Zoom", "Zoom"),
    ("Feishu", "飞书"),
    # 安全/工具
    ("360safe", "360安全卫士"),
    ("QQPCMgr", "电脑管家"),
    ("Huorong", "火绒安全"),
    ("Everything", "Everything"),
    ("Listary", "Listary"),
]

def _generate_default_program_names():
    """生成默认的500+程序名映射表"""
    names = [
        # ===== 浏览器 (30) =====
        ("Chrome", "Chrome浏览器"), ("Firefox", "火狐浏览器"), ("MSEdge", "Edge浏览器"),
        ("Opera", "Opera浏览器"), ("Brave", "Brave浏览器"), ("360se", "360安全浏览器"),
        ("360chrome", "360极速浏览器"), ("QQBrowser", "QQ浏览器"), ("SogouExplorer", "搜狗浏览器"),
        ("Maxthon", "傲游浏览器"), ("Vivaldi", "Vivaldi浏览器"), ("Yandex", "Yandex浏览器"),
        ("UCWEB", "UC浏览器"), ("LieBao", "猎豹浏览器"), ("BaiduBrowser", "百度浏览器"),
        ("2345Explorer", "2345浏览器"), ("115Browser", "115浏览器"), ("Sunlogin", "向日葵浏览器"),
        ("CentBrowser", "百分浏览器"), ("7Star", "七星浏览器"), ("Chedot", "Chedot浏览器"),
        ("SuperBird", "SuperBird浏览器"), ("Torch", "Torch浏览器"), ("Epic", "Epic浏览器"),
        ("Comodo", "Comodo浏览器"), ("Avant", "Avant浏览器"), ("GreenBrowser", "绿色浏览器"),
        ("Slimjet", "Slimjet浏览器"), ("Iridium", "Iridium浏览器"), ("Waterfox", "Waterfox浏览器"),
        # ===== 视频播放器 (40) =====
        ("PotPlayer", "PotPlayer"), ("VLC", "VLC媒体播放器"), ("mpc", "MPC-HC"),
        ("MPC-HC", "MPC-HC"), ("KMPlayer", "KMPlayer"), ("GOM", "GOM Player"),
        ("QQPlayer", "QQ影音"), ("StormPlayer", "暴风影音"), ("Baofeng", "暴风影音"),
        ("XLLiveUD", "迅雷看看"), ("iQIYI", "爱奇艺"), ("QQLive", "腾讯视频"),
        ("Youku", "优酷"), ("Tudou", "土豆"), ("Letv", "乐视视频"),
        ("PPTV", "PPTV聚力"), ("PPS", "PPS影音"), ("SohuVideo", "搜狐视频"),
        ("BaiduPlayer", "百度影音"), ("RealPlayer", "RealPlayer"), ("QuickTime", "QuickTime"),
        ("WMP11", "Windows Media Player"), ("MediaPlayer", "Windows Media Player"),
        ("PowerDVD", "PowerDVD"), ("WinDVD", "WinDVD"), ("ZoomPlayer", "Zoom Player"),
        ("BSPlayer", "BS.Player"), ("SMPlayer", "SMPlayer"), ("MPV", "mpv播放器"),
        ("DivX", "DivX播放器"), ("CorelWinDVD", "WinDVD"), ("Nero", "Nero播放器"),
        ("ArcSoft", "ArcSoft播放器"), ("Splash", "Splash播放器"), ("5KPlayer", "5KPlayer"),
        ("Daum", "Daum播放器"), ("POT", "PotPlayer"), ("ALLPlayer", "ALLPlayer"),
        ("jetAudio", "jetAudio"), ("MediaMonkey", "MediaMonkey"),
        # ===== 音乐播放器 (35) =====
        ("foobar", "foobar2000"), ("AIMP", "AIMP"), ("Winamp", "Winamp"),
        ("iTunes", "iTunes"), ("QQMusic", "QQ音乐"), ("NetEaseMusic", "网易云音乐"),
        ("KuGou", "酷狗音乐"), ("KuWo", "酷我音乐"), ("BaiduMusic", "百度音乐"),
        ("XiaMi", "虾米音乐"), ("TTPlayer", "千千静听"), ("BeoPlayer", "BeoPlayer"),
        ("MusicBee", "MusicBee"), ("MediaMonkey", "MediaMonkey"), ("Songbird", "Songbird"),
        ("Spotify", "Spotify"), ("AppleMusic", "Apple Music"), ("YouTubeMusic", "YouTube Music"),
        ("AmazonMusic", "Amazon Music"), ("Pandora", "Pandora"), ("Deezer", "Deezer"),
        ("Tidal", "Tidal"), ("SoundCloud", "SoundCloud"), ("Bandcamp", "Bandcamp"),
        ("Audacious", "Audacious"), ("Clementine", "Clementine"), ("Rhythmbox", "Rhythmbox"),
        ("Banshee", "Banshee"), ("Amarok", "Amarok"), ("Exaile", "Exaile"),
        ("Guayadeque", "Guayadeque"), ("QuodLibet", "Quod Libet"), ("Lollypop", "Lollypop"),
        ("GNOMEMusic", "GNOME音乐"), ("Elisa", "Elisa音乐播放器"),
        # ===== 图片查看/编辑 (45) =====
        ("Photoshop", "Photoshop"), ("Lightroom", "Lightroom"), ("Illustrator", "Illustrator"),
        ("ACDSee", "ACDSee"), ("XnView", "XnView"), ("IrfanView", "IrfanView"),
        ("Honeyview", "Honeyview"), ("FastStone", "FastStone"), ("PhotoViewer", "照片"),
        ("mspaint", "画图"), ("Meitu", "美图秀秀"), ("Picasa", "Picasa"),
        ("GooglePhotos", "Google相册"), ("XNViewMP", "XnView MP"), ("Imagine", "Imagine"),
        ("nomacs", "nomacs"), ("qView", "qView"), ("ImageGlass", "ImageGlass"),
        ("JPEGView", "JPEGView"), ("SumatraImage", "Sumatra图像"), ("GIMP", "GIMP"),
        ("PaintNET", "Paint.NET"), ("Krita", "Krita"), ("Inkscape", "Inkscape"),
        ("Affinity", "Affinity系列"), ("CorelDRAW", "CorelDRAW"), ("Canvas", "Canvas"),
        ("PhotoScape", "PhotoScape"), ("Photoscape", "PhotoScape"), ("Pixlr", "Pixlr"),
        ("Fotor", "Fotor"), ("Canva", "Canva"), ("Figma", "Figma"),
        ("Sketch", "Sketch"), ("XD", "Adobe XD"), ("AfterEffects", "After Effects"),
        ("Premiere", "Premiere Pro"), ("DaVinci", "DaVinci Resolve"), ("Vegas", "Vegas Pro"),
        ("Camtasia", "Camtasia"), ("Snagit", "Snagit"), ("Greenshot", "Greenshot"),
        ("ShareX", "ShareX"), ("Flameshot", "Flameshot"), ("Lightshot", "Lightshot"),
        # ===== 办公软件 (40) =====
        ("WPS", "WPS Office"), ("Word", "Word"), ("Excel", "Excel"),
        ("PowerPoint", "PowerPoint"), ("Office", "Microsoft Office"), ("Outlook", "Outlook"),
        ("OneNote", "OneNote"), ("Access", "Access"), ("Publisher", "Publisher"),
        ("Visio", "Visio"), ("Project", "Project"), ("LibreOffice", "LibreOffice"),
        ("OpenOffice", "OpenOffice"), ("OnlyOffice", "ONLYOFFICE"), ("SoftMaker", "SoftMaker Office"),
        ("WordPerfect", "WordPerfect"), ("ThinkFree", "ThinkFree Office"), ("Polaris", "Polaris Office"),
        ("Zoho", "Zoho Office"), ("GoogleDocs", "Google Docs"), ("Evernote", "印象笔记"),
        ("YoudaoNote", "有道云笔记"), ("WizNote", "为知笔记"), ("Leanote", "Leanote"),
        ("Notion", "Notion"), ("Obsidian", "Obsidian"), ("Typora", "Typora"),
        ("MarkText", "MarkText"), ("Zettlr", "Zettlr"), ("Joplin", "Joplin"),
        ("Logseq", "Logseq"), ("Roam", "Roam Research"), ("Workflowy", "Workflowy"),
        ("Dynalist", "Dynalist"), ("Checkvist", "Checkvist"), ("Org-mode", "Org-mode"),
        ("Scrivener", "Scrivener"), ("Ulysses", "Ulysses"), ("iAWriter", "iA Writer"),
        ("Bear", "Bear笔记"),
        # ===== PDF阅读器 (25) =====
        ("Acrobat", "Adobe Acrobat"), ("Foxit", "福昕PDF阅读器"), ("SumatraPDF", "Sumatra PDF"),
        ("PDFXCview", "PDF-XChange Viewer"), ("PDFXEdit", "PDF-XChange Editor"), ("Nitro", "Nitro PDF"),
        ("PDFelement", "PDFelement"), ("PhantomPDF", "福昕 PhantomPDF"), ("PowerPDF", "Power PDF"),
        ("ExpertPDF", "Expert PDF"), ("PDFArchitect", "PDF Architect"), ("Infix", "Infix PDF编辑器"),
        ("MasterPDF", "Master PDF Editor"), ("PDFsam", "PDFsam"), ("PDF24", "PDF24"),
        ("PrimoPDF", "PrimoPDF"), ("doPDF", "doPDF"), ("Bullzip", "Bullzip PDF"),
        ("CutePDF", "CutePDF"), ("novaPDF", "novaPDF"), ("7-PDF", "7-PDF"),
        ("PDFill", "PDFill"), ("FreePDF", "Free PDF Reader"), ("MuPDF", "MuPDF"),
        ("Okular", "Okular"), ("Evince", "Evince"),
        # ===== 压缩软件 (20) =====
        ("7-Zip", "7-Zip"), ("WinRAR", "WinRAR"), ("HaoZip", "好压"),
        ("Bandizip", "Bandizip"), ("360zip", "360压缩"), ("2345haozip", "2345好压"),
        ("PeaZip", "PeaZip"), ("WinZip", "WinZip"), ("IZArc", "IZArc"),
        ("Ashampoo", "Ashampoo ZIP"), ("PowerArchiver", "PowerArchiver"), ("WinAce", "WinAce"),
        ("ALZip", "ALZip"), ("UniversalExtractor", "Universal Extractor"), ("7z", "7-Zip"),
        ("rar", "WinRAR"), ("zip", "压缩文件"), ("tar", "tar归档"),
        ("gzip", "gzip压缩"), ("bzip2", "bzip2压缩"),
        # ===== 网盘/下载 (25) =====
        ("BaiduNetdisk", "百度网盘"), ("Thunder", "迅雷"), ("Xunlei", "迅雷"),
        ("QQDownload", "QQ旋风"), ("IDM", "IDM下载器"), ("FreeDownloadManager", "FDM下载器"),
        ("uTorrent", "uTorrent"), ("BitTorrent", "BitTorrent"), ("qBittorrent", "qBittorrent"),
        ("Transmission", "Transmission"), ("Deluge", "Deluge"), ("Vuze", "Vuze"),
        ("aria2", "aria2"), ("Motrix", "Motrix"), ("Persepolis", "Persepolis"),
        ("Xdown", "Xdown"), ("PDown", "PDown"), ("EagleGet", "EagleGet"),
        ("FlashGet", "快车"), ("Orbit", "Orbit下载器"), ("GetRight", "GetRight"),
        ("InternetDownloadManager", "IDM"), ("JDownloader", "JDownloader"), ("FreeRapid", "FreeRapid"),
        ("Mipony", "Mipony"),
        # ===== 通讯软件 (30) =====
        ("QQ", "QQ"), ("WeChat", "微信"), ("DingTalk", "钉钉"),
        ("WXWork", "企业微信"), ("TencentMeeting", "腾讯会议"), ("Zoom", "Zoom"),
        ("Feishu", "飞书"), ("Lark", "Lark"), ("Skype", "Skype"),
        ("Teams", "Microsoft Teams"), ("Slack", "Slack"), ("Discord", "Discord"),
        ("Telegram", "Telegram"), ("WhatsApp", "WhatsApp"), ("Line", "Line"),
        ("Viber", "Viber"), ("KakaoTalk", "KakaoTalk"), ("WeCom", "企业微信"),
        ("TIM", "TIM"), ("QQInternational", "QQ国际版"), ("WeChatWork", "企业微信"),
        ("Aliwangwang", "阿里旺旺"), ("Wangwang", "旺旺"), ("DingTalkLite", "钉钉Lite"),
        ("ZoomMeeting", "Zoom会议"), ("CiscoWebex", "Webex"), ("GoToMeeting", "GoToMeeting"),
        ("BlueJeans", "BlueJeans"), ("Join.me", "Join.me"), ("Whereby", "Whereby"),
        # ===== 安全软件 (30) =====
        ("360safe", "360安全卫士"), ("QQPCMgr", "电脑管家"), ("Huorong", "火绒安全"),
        ("Kaspersky", "卡巴斯基"), ("Avast", "Avast"), ("AVG", "AVG杀毒"),
        ("Norton", "诺顿"), ("McAfee", "迈克菲"), ("Bitdefender", "Bitdefender"),
        ("ESET", "ESET NOD32"), ("Malwarebytes", "Malwarebytes"), ("Spybot", "Spybot"),
        ("AdwCleaner", "AdwCleaner"), ("Ccleaner", "CCleaner"), ("Defender", "Windows Defender"),
        ("WindowsDefender", "Windows Defender"), ("360sd", "360杀毒"), ("360Total", "360Total"),
        ("BaiduAn", "百度杀毒"), ("Kingsoft", "金山毒霸"), ("Duba", "金山毒霸"),
        ("Rising", "瑞星杀毒"), ("Jiangmin", "江民杀毒"), ("Virus", "杀毒软件"),
        ("ClamWin", "ClamWin"), ("ComodoAV", "Comodo杀毒"), ("Panda", "熊猫杀毒"),
        ("F-Secure", "F-Secure"), ("TrendMicro", "趋势科技"), ("Sophos", "Sophos"),
        # ===== 开发工具 (50) =====
        ("VSCode", "VS Code"), ("Code.", "VS Code"), ("VisualStudio", "Visual Studio"),
        ("IntelliJ", "IntelliJ IDEA"), ("PyCharm", "PyCharm"), ("WebStorm", "WebStorm"),
        ("CLion", "CLion"), ("GoLand", "GoLand"), ("Rider", "Rider"),
        ("PhpStorm", "PhpStorm"), ("RubyMine", "RubyMine"), ("AppCode", "AppCode"),
        ("DataGrip", "DataGrip"), ("AndroidStudio", "Android Studio"), ("Eclipse", "Eclipse"),
        ("NetBeans", "NetBeans"), ("Sublime", "Sublime Text"), ("Notepad++", "Notepad++"),
        ("Notepad", "记事本"), ("UltraEdit", "UltraEdit"), ("EmEditor", "EmEditor"),
        ("Vim", "Vim"), ("Neovim", "Neovim"), ("Emacs", "Emacs"),
        ("Atom", "Atom"), ("Brackets", "Brackets"), ("CodeBlocks", "Code::Blocks"),
        ("Dev-C++", "Dev-C++"), ("CodeLite", "CodeLite"), ("Geany", "Geany"),
        ("Kate", "Kate"), ("KDevelop", "KDevelop"), ("Anjuta", "Anjuta"),
        ("Xcode", "Xcode"), ("Swift", "Swift"), ("Cocoa", "Cocoa"),
        ("Unity", "Unity"), ("Unreal", "虚幻引擎"), ("Godot", "Godot引擎"),
        ("GameMaker", "GameMaker"), ("Construct", "Construct"), ("RPGMaker", "RPG Maker"),
        ("RenPy", "Ren'Py"), ("Twine", "Twine"), ("Ink", "Ink"),
        ("Git", "Git"), ("GitHub", "GitHub Desktop"), ("GitKraken", "GitKraken"),
        ("Sourcetree", "Sourcetree"), ("TortoiseGit", "TortoiseGit"), ("TortoiseSVN", "TortoiseSVN"),
        # ===== 系统工具 (40) =====
        ("Everything", "Everything"), ("Listary", "Listary"), ("Wox", "Wox"),
        ("PowerToys", "PowerToys"), ("Launchy", "Launchy"), ("Keypirinha", "Keypirinha"),
        ("utools", "uTools"), ("Quicker", "Quicker"), ("Snipaste", "Snipaste"),
        ("Ditto", "Ditto"), ("CopyQ", "CopyQ"), ("ClipX", "ClipX"),
        ("1Clipboard", "1Clipboard"), ("ClipboardFusion", "ClipboardFusion"), ("ArsClip", "ArsClip"),
        ("Revo", "Revo Uninstaller"), ("Geek", "Geek Uninstaller"), ("IObit", "IObit Uninstaller"),
        ("AshampooUninstaller", "Ashampoo卸载"), ("TotalUninstall", "Total Uninstall"), ("YourUninstaller", "Your Uninstaller"),
        ("CCleaner", "CCleaner"), ("BleachBit", "BleachBit"), ("CleanMaster", "清理大师"),
        ("WiseCare", "Wise Care 365"), ("AdvancedSystemCare", "Advanced SystemCare"), ("TuneUp", "TuneUp Utilities"),
        ("Glary", "Glary Utilities"), ("WinOptimizer", "WinOptimizer"), ("SystemMechanic", "System Mechanic"),
        ("ProcessExplorer", "Process Explorer"), ("ProcessHacker", "Process Hacker"), ("SystemInformer", "System Informer"),
        ("TaskManager", "任务管理器"), ("ResourceMonitor", "资源监视器"), ("PerformanceMonitor", "性能监视器"),
        ("Autoruns", "Autoruns"), ("ProcessMonitor", "Process Monitor"), ("Regmon", "Regmon"),
        ("Filemon", "Filemon"), ("TCPView", "TCPView"),
        # ===== 游戏平台 (20) =====
        ("Steam", "Steam"), ("EpicGames", "Epic Games"), ("Origin", "Origin"),
        ("Uplay", "Uplay"), ("GOG", "GOG Galaxy"), ("Battle.net", "战网"),
        ("WeGame", "WeGame"), ("TGP", "TGP"), ("QQGame", "QQ游戏"),
        ("GameForWindows", "Games for Windows"), ("Rockstar", "Rockstar Games Launcher"), ("Bethesda", "Bethesda.net"),
        ("Paradox", "Paradox Launcher"), ("Ankama", "Ankama Launcher"), ("Glyph", "Glyph"),
        ("RiotClient", "Riot客户端"), ("Valorant", "Valorant"), ("LeagueClient", "英雄联盟"),
        ("CrossFire", "穿越火线"), ("DNF", "地下城与勇士"),
        # ===== 虚拟机/远程 (20) =====
        ("VMware", "VMware"), ("VirtualBox", "VirtualBox"), ("Hyper-V", "Hyper-V"),
        ("Parallels", "Parallels"), ("QEMU", "QEMU"), ("KVM", "KVM"),
        ("Xen", "Xen"), ("Docker", "Docker"), ("Podman", "Podman"),
        ("WSL", "WSL"), ("TeamViewer", "TeamViewer"), ("AnyDesk", "AnyDesk"),
        ("向日葵", "向日葵远程"), ("Sunlogin", "向日葵远程"), ("ToDesk", "ToDesk"),
        ("RustDesk", "RustDesk"), ("ChromeRemote", "Chrome远程桌面"), ("RemoteDesktop", "远程桌面"),
        ("mstsc", "远程桌面"), ("VNC", "VNC"),
        # ===== 其他常用 (30) =====
        ("MuMu", "MuMu模拟器"), ("BlueStacks", "蓝叠模拟器"), ("Nox", "夜神模拟器"),
        ("LDPlayer", "雷电模拟器"), ("MEmu", "逍遥模拟器"), ("Droid4X", "海马玩模拟器"),
        ("iTools", "iTools"), ("PP助手", "PP助手"), ("爱思助手", "爱思助手"),
        ("XY助手", "XY苹果助手"), ("同步推", "同步推"), ("快用", "快用苹果助手"),
        ("Calibre", "Calibre电子书"), ("Kindle", "Kindle"), ("AdobeDigital", "Adobe Digital Editions"),
        ("FBReader", "FBReader"), ("SumatraEpub", "Sumatra电子书"), ("Icecream", "Icecream电子书"),
        ("Stellarium", "Stellarium"), ("GoogleEarth", "Google地球"), ("NASA", "NASA应用"),
        ("HandBrake", "HandBrake"), ("FormatFactory", "格式工厂"), ("XMediaRecode", "XMedia Recode"),
        ("Freemake", "Freemake视频转换器"), ("AnyVideo", "Any Video Converter"), ("WinX", "WinX视频转换器"),
        ("Movavi", "Movavi视频转换器"), ("Aiseesoft", "Aiseesoft"), ("Wondershare", "万兴"),
        # ===== 短视频/内容平台 (30) =====
        ("BiliBili", "哔哩哔哩"), ("哔哩哔哩", "哔哩哔哩"), ("bilibili", "哔哩哔哩"),
        ("JianYing", "剪映"), ("CapCut", "剪映国际版"), ("剪映", "剪映"),
        ("Douyin", "抖音"), ("TikTok", "抖音国际版"), ("抖音", "抖音"),
        ("Kwai", "快手"), ("快手", "快手"), ("XiguaVideo", "西瓜视频"), ("西瓜视频", "西瓜视频"),
        ("Toutiao", "今日头条"), ("今日头条", "今日头条"), ("Weibo", "微博"), ("微博", "微博"),
        ("Xiaohongshu", "小红书"), ("RedNote", "小红书"), ("小红书", "小红书"),
        ("Zhihu", "知乎"), ("知乎", "知乎"), ("MangoTV", "芒果TV"), ("芒果TV", "芒果TV"),
        ("Sohu", "搜狐"), ("NeteaseVideo", "网易视频"), ("163", "网易"),
        ("Quark", "夸克浏览器"), ("夸克", "夸克"), ("UCBrowser", "UC浏览器"),
        # ===== 网盘/云文档补充 (20) =====
        ("AliyunDrive", "阿里云盘"), ("aDrive", "阿里云盘"), ("阿里云盘", "阿里云盘"),
        ("TianyiCloud", "天翼云盘"), ("天翼云盘", "天翼云盘"), ("115", "115网盘"),
        ("115Pan", "115网盘"), ("QuarkPan", "夸克网盘"), ("123Pan", "123云盘"),
        ("123Yun", "123云盘"), ("TencentDocs", "腾讯文档"), ("腾讯文档", "腾讯文档"),
        ("Shimo", "石墨文档"), ("石墨文档", "石墨文档"), ("Youdao", "有道"),
        ("有道", "有道"), ("YoudaoDict", "有道词典"), ("NeteaseMail", "网易邮箱"),
        ("MailMaster", "网易邮箱大师"), ("Foxmail", "Foxmail"),
    ]
    return names


def load_program_names():
    """从配置文件加载程序名映射，合并到内置映射表"""
    global _KNOWN_PROGID_MAP
    # 先加载内置默认
    builtin = _generate_default_program_names()
    # 尝试加载配置文件
    try:
        if os.path.exists(PROGRAM_NAMES_FILE):
            with open(PROGRAM_NAMES_FILE, 'r', encoding='utf-8') as f:
                user_names = json.load(f)
            if isinstance(user_names, list):
                builtin.extend(user_names)
        else:
            # 首次运行，生成默认配置文件
            try:
                with open(PROGRAM_NAMES_FILE, 'w', encoding='utf-8') as f:
                    json.dump(builtin, f, ensure_ascii=False, indent=2)
            except Exception:
                pass
    except Exception:
        pass
    _KNOWN_PROGID_MAP = builtin
    return len(builtin)


# 启动时加载程序名
load_program_names()


_KNOWN_PROGID_MAP_SORTED = None


def _get_sorted_map():
    """返回按 keyword 长度降序缓存的识别映射（长名优先，避免重复排序）"""
    global _KNOWN_PROGID_MAP_SORTED
    if _KNOWN_PROGID_MAP_SORTED is None:
        _KNOWN_PROGID_MAP_SORTED = sorted(_KNOWN_PROGID_MAP,
                                          key=lambda kv: len(kv[0]), reverse=True)
    return _KNOWN_PROGID_MAP_SORTED


def _kw_boundary(pid_lower, kw):
    """短 keyword（≤3字符）匹配要求字符边界，避免误配。
    例："pps" 不得命中 "windowsapps"（前有字母 'a'）。"""
    idx = pid_lower.find(kw)
    while idx != -1:
        before = pid_lower[idx - 1] if idx > 0 else ""
        after = pid_lower[idx + len(kw)] if idx + len(kw) < len(pid_lower) else ""
        if (not before or not before.isalnum()) and (not after or not after.isalnum()):
            return True
        idx = pid_lower.find(kw, idx + 1)
    return False


def identify_tamperer(prog_id):
    """根据ProgId识别疑似篡改者/关联软件。
    AppX类型从注册表查应用名，已知软件直接匹配。
    返回 (名称, 可信度: 'high'/'medium'/'low')"""
    if not prog_id:
        return None, "low"
    pid_lower = prog_id.lower()
    # AppX类型（Windows商店应用）
    if pid_lower.startswith("appx"):
        try:
            # 从注册表查应用名
            for root, base in [(HKCR, prog_id), (HKCU, f"Software\\Classes\\{prog_id}")]:
                app_name, _ = reg_read_value(root, f"{base}\\Application", "ApplicationName")
                if app_name:
                    # ApplicationName可能是@{PackageFamilyName!Resource}格式，尝试提取
                    import re
                    m = re.search(r"//(.+?)$", app_name)
                    if m:
                        return m.group(1), "high"
                    return app_name, "high"
                aumid, _ = reg_read_value(root, f"{base}\\Application", "AppUserModelID")
                if aumid:
                    return f"商店应用({aumid.split('!')[0]})", "medium"
            return "Windows商店应用", "low"
        except Exception:
            return "Windows商店应用", "low"
    # 已知软件匹配：长 keyword 优先（更具体），短 keyword 需字符边界，
    # 避免 "PPS" 误配 "windowsapps"、短名误配其他路径片段
    for keyword, name in _get_sorted_map():
        kw = keyword.lower()
        if len(kw) <= 3:
            if _kw_boundary(pid_lower, kw):
                return name, "high"
        elif kw in pid_lower:
            return name, "high"
    # 从注册表查ProgId的友好名称
    try:
        if HKCU_REMAPPED:
            friendly, _ = read_hkcr_effective(prog_id, "")
        else:
            friendly, _ = reg_read_value(HKCR, prog_id, "")
        if friendly and len(friendly) < 60:
            return friendly, "medium"
    except Exception:
        pass
    return prog_id, "low"


def get_extension_paths(ext, prog_id=None):
    """
    获取扩展名对应的保护项路径定义。
    统一维护 3 个扩展名键 + 2 个 UserChoice 键 + 2 个 command 键，
    额外保留 HKLM command 作为补充验证位置，不影响主保护逻辑。
    """
    if prog_id is None:
        prog_id = get_prog_id(ext)

    paths = {
        "hkcr_ext": (HKCR, ext, ""),
        "hkcu_ext": (HKCU, f"Software\\Classes\\{ext}", ""),
        "hklm_ext": (HKLM, f"SOFTWARE\\Classes\\{ext}", ""),
        "userchoice_progid": (HKCU, f"{USERCHOICE_BASE}\\{ext}\\UserChoice", "ProgId"),
        "userchoice_hash": (HKCU, f"{USERCHOICE_BASE}\\{ext}\\UserChoice", "Hash"),
    }
    if prog_id:
        paths["hkcr_command"] = (HKCR, f"{prog_id}\\shell\\open\\command", "")
        paths["hkcu_command"] = (HKCU, f"Software\\Classes\\{prog_id}\\shell\\open\\command", "")
        paths["hklm_command"] = (HKLM, f"SOFTWARE\\Classes\\{prog_id}\\shell\\open\\command", "")
    return paths


def snapshot_extension(ext):
    """
    对单个扩展名拍摄保护项快照。
    保护项必须稳定、可比对，command 位置在无 ProgId 时保留为 None，
    不再使用错误的默认 ProgId 伪造路径。
    """
    prog_id = get_prog_id(ext)
    paths = get_extension_paths(ext, prog_id)
    snap = {}
    for key, (root, path, name) in paths.items():
        val, typ = reg_read_value(root, path, name)
        snap[key] = {
            "root": ROOT_NAME_MAP.get(root, "?"),
            "path": path,
            "name": name,
            "value": val,
            "type": typ,
            "prog_id": prog_id if key in ("hkcr_command", "hkcu_command", "hklm_command") else None,
        }

    # 只有在真正拿不到 ProgId 时，保留空命令项，避免伪造错误路径造成误判
    for key in ("hkcr_command", "hkcu_command", "hklm_command"):
        if key not in snap:
            snap[key] = {
                "root": "HKCR" if key == "hkcr_command" else "HKCU" if key == "hkcu_command" else "HKLM",
                "path": "",
                "name": "",
                "value": None,
                "type": None,
                "prog_id": None,
            }
    return snap


def enumerate_all_extensions():
    r"""
    扫描注册表中所有扩展名（以.开头的子键）。
    从 HKCR、HKCU\Software\Classes、HKLM\SOFTWARE\Classes 合并去重。
    统一转小写——Windows注册表不区分大小写，避免.M2T和.m2t被当作两个扩展名。
    """
    exts = set()
    # HKCR
    for sk in reg_enum_subkeys(HKCR, ""):
        if sk.startswith("."):
            exts.add(sk.lower())
    # HKCU
    for sk in reg_enum_subkeys(HKCU, "Software\\Classes"):
        if sk.startswith("."):
            exts.add(sk.lower())
    # HKLM
    for sk in reg_enum_subkeys(HKLM, "SOFTWARE\\Classes"):
        if sk.startswith("."):
            exts.add(sk.lower())
    # FileExts (UserChoice 存在的扩展名)
    for sk in reg_enum_subkeys(HKCU, USERCHOICE_BASE):
        if sk.startswith("."):
            exts.add(sk.lower())
    return sorted(exts)


# ============================================================
# HKCU 重映射（TI/SYSTEM下指向当前登录用户配置单元）
# ============================================================
class _SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", ctypes.c_uint32)]

class _TOKEN_USER(ctypes.Structure):
    _fields_ = [("User", _SID_AND_ATTRIBUTES)]


def get_interactive_user_sid():
    """获取当前控制台登录用户的SID字符串。
    使用WTSQuerySessionInformation取用户名+域名，再LookupAccountName转SID，
    不需要SE_TCB_NAME特权（WTSQueryUserToken需要）。
    失败时回退到枚举HKEY_USERS查找用户SID。"""
    sid = _get_sid_via_wts()
    if sid:
        return sid
    # 回退：枚举HKEY_USERS
    return _find_user_sid_by_enumeration()


def _get_sid_via_wts():
    """通过WTS API获取用户SID"""
    try:
        kernel32.WTSGetActiveConsoleSessionId.restype = ctypes.c_ulong
        session_id = kernel32.WTSGetActiveConsoleSessionId()
        if session_id == 0xFFFFFFFF:
            return None
        wtsapi32 = ctypes.WinDLL('wtsapi32', use_last_error=True)
        WTS_CURRENT_SERVER_HANDLE = 0
        WTSUserName = 5
        WTSDomainName = 7
        wtsapi32.WTSQuerySessionInformationW.restype = ctypes.c_int
        wtsapi32.WTSQuerySessionInformationW.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_ulong)]
        wtsapi32.WTSFreeMemory.restype = None
        wtsapi32.WTSFreeMemory.argtypes = [ctypes.c_void_p]
        ppBuffer = ctypes.c_void_p()
        pBytes = ctypes.c_ulong()
        # 获取用户名
        if not wtsapi32.WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, session_id, WTSUserName, ctypes.byref(ppBuffer), ctypes.byref(pBytes)):
            return None
        username = ctypes.wstring_at(ppBuffer.value) if ppBuffer.value else ""
        wtsapi32.WTSFreeMemory(ppBuffer)
        # 获取域名
        if not wtsapi32.WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, session_id, WTSDomainName, ctypes.byref(ppBuffer), ctypes.byref(pBytes)):
            domain = ""
        else:
            domain = ctypes.wstring_at(ppBuffer.value) if ppBuffer.value else ""
            wtsapi32.WTSFreeMemory(ppBuffer)
        if not username:
            return None
        # LookupAccountName 转 SID
        advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)
        sid_size = ctypes.c_ulong(256)
        sid = ctypes.create_string_buffer(sid_size.value)
        ref_domain_size = ctypes.c_ulong(256)
        ref_domain = ctypes.create_unicode_buffer(ref_domain_size.value)
        use = ctypes.c_ulong()
        if not advapi32.LookupAccountNameW(domain if domain else None, username, sid, ctypes.byref(sid_size), ref_domain, ctypes.byref(ref_domain_size), ctypes.byref(use)):
            # 重试 with correct sizes
            sid = ctypes.create_string_buffer(sid_size.value)
            ref_domain = ctypes.create_unicode_buffer(ref_domain_size.value)
            if not advapi32.LookupAccountNameW(domain if domain else None, username, sid, ctypes.byref(sid_size), ref_domain, ctypes.byref(ref_domain_size), ctypes.byref(use)):
                return None
        # ConvertSidToStringSid
        advapi32.ConvertSidToStringSidW.restype = ctypes.c_int
        advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_wchar_p)]
        sid_str = ctypes.c_wchar_p()
        if not advapi32.ConvertSidToStringSidW(sid, ctypes.byref(sid_str)):
            return None
        result = sid_str.value
        kernel32.LocalFree(sid_str)
        return result
    except Exception as e:
        logger.error(f"get_interactive_user_sid异常: {e}")
        return None


def _find_user_sid_by_enumeration():
    """备用：枚举HKEY_USERS查找当前登录用户的SID。
    排除 .DEFAULT、S-1-5-18(SYSTEM)、S-1-5-19/20(服务账号)、*_Classes。"""
    try:
        import winreg
        excluded = {".DEFAULT", "S-1-5-18", "S-1-5-19", "S-1-5-20"}
        with winreg.OpenKey(winreg.HKEY_USERS, "") as hku:
            i = 0
            while True:
                try:
                    subkey = winreg.EnumKey(hku, i)
                    i += 1
                    if subkey in excluded or subkey.endswith("_Classes"):
                        continue
                    if subkey.startswith("S-1-5-21-"):
                        # 验证：该SID下有Volatile Environment\USERNAME
                        try:
                            with winreg.OpenKey(hku, f"{subkey}\\Volatile Environment") as ve:
                                username, _ = winreg.QueryValueEx(ve, "USERNAME")
                                if username:
                                    logger.info(f"枚举HKEY_USERS找到用户: {username} -> {subkey}")
                                    return subkey
                        except OSError:
                            continue
                except OSError:
                    break
    except Exception as e:
        logger.error(f"_find_user_sid_by_enumeration异常: {e}")
    return None


HKCU_REMAPPED = False  # 全局标记：HKCU是否已成功重映射到用户配置单元

def remap_hkcu_to_interactive_user():
    """当以SYSTEM/TI运行时，将全局HKCU重映射到当前登录用户的配置单元。
    这是修复'TI下检测不全/保护失效'的核心：SYSTEM的HKCU指向.DEFAULT，
    而非当前登录用户，导致用户扩展名/UserChoice全部读不到。"""
    global HKCU, HKCU_REMAPPED
    sid = get_interactive_user_sid()
    if not sid:
        log_event("SYSTEM", "HKCU重映射", "失败", "无法获取交互式用户SID(WTS+枚举均失败)")
        return False
    try:
        user_hive = winreg.OpenKey(HKEY_USERS, sid, 0, KEY_ALL_ACCESS_64)
        # 验证：读取用户的Volatile Environment确认是正确的用户配置单元
        try:
            val, _ = reg_read_value(user_hive, "Volatile Environment", "USERNAME")
            verify_user = val or "未知"
        except Exception:
            verify_user = "未知"
        HKCU = user_hive
        # 更新ROOT_MAP/ROOT_NAME_MAP，否则snapshot_extension中ROOT_NAME_MAP[root]会KeyError
        ROOT_MAP["HKCU"] = int(user_hive)
        ROOT_NAME_MAP.clear()
        ROOT_NAME_MAP.update({v: k for k, v in ROOT_MAP.items()})
        # 验证枚举是否正常
        test_count = len(reg_enum_subkeys(HKCU, "Software\\Classes"))
        # 验证UserChoice路径可读取
        uc_count = len(reg_enum_subkeys(HKCU, USERCHOICE_BASE))
        if test_count < 100:
            log_event("SYSTEM", "HKCU重映射", "警告", f"用户={verify_user}, SID={sid}, HKCU\\Classes仅{test_count}个扩展名(可能映射错误), UserChoice下{uc_count}项")
        else:
            log_event("SYSTEM", "HKCU重映射", "成功", f"用户={verify_user}, SID={sid}, HKCU\\Classes扩展名数={test_count}, UserChoice项数={uc_count}")
        HKCU_REMAPPED = True
        remap_hkcu_to_interactive_user._last_sid = sid
        return True
    except OSError as e:
        log_event("SYSTEM", "HKCU重映射", "失败", str(e))
        return False


# ============================================================
# 基准管理器 (含5版本历史)
# ============================================================
class BaselineManager:
    def __init__(self):
        self.baseline = {}
        self.config = {}
        self._lock = threading.Lock()
        self._ensure_dirs()
        self.load()
    def _ensure_dirs(self):
        os.makedirs(HISTORY_DIR, exist_ok=True)

    def load(self):
        with self._lock:
            if os.path.exists(BASELINE_FILE):
                try:
                    with open(BASELINE_FILE, 'r', encoding='utf-8') as f:
                        self.baseline = json.load(f)
                except (json.JSONDecodeError, OSError) as e:
                    logger.error(f"加载基准失败: {e}")
                    self.baseline = {}
            if os.path.exists(CONFIG_FILE):
                try:
                    with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                        self.config = json.load(f)
                except (json.JSONDecodeError, OSError) as e:
                    self.config = {}
            # 初始化默认白名单配置
            if "whitelist_exts" not in self.config:
                self.config["whitelist_exts"] = []
            if "whitelist_programs" not in self.config:
                # 默认添加安全软件到白名单程序
                self.config["whitelist_programs"] = [
                    "火绒安全", "360安全卫士", "360杀毒", "卡巴斯基",
                    "电脑管家", "Windows Defender", "金山毒霸", "瑞星杀毒"
                ]
                try:
                    with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                        json.dump(self.config, f, ensure_ascii=False, indent=2)
                except Exception:
                    pass

    def save(self):
        with self._lock:
            try:
                with open(BASELINE_FILE, 'w', encoding='utf-8') as f:
                    json.dump(self.baseline, f, ensure_ascii=False, indent=2)
            except OSError as e:
                logger.error(f"保存基准失败: {e}")

    def save_config(self):
        with self._lock:
            try:
                with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                    json.dump(self.config, f, ensure_ascii=False, indent=2)
            except OSError as e:
                logger.error(f"保存配置失败: {e}")

    def is_initialized(self):
        return bool(self.baseline) and self.config.get("initialized", False)

    def create_baseline(self, mode="current", progress_cb=None):
        """
        创建全扩展名基准。
        mode: "current" = 以目前方式为基准; "default" = 以默认方式为基准
        progress_cb: 可选回调函数(当前索引, 总数)用于进度显示
        """
        if mode == "default":
            # 默认方式：清除所有 UserChoice，让系统回退到 HKLM 默认关联
            self._clear_all_user_choice()
            time.sleep(0.5)  # 等待系统刷新

        exts = enumerate_all_extensions()
        total = len(exts)
        new_baseline = {}
        errors = 0
        for i, ext in enumerate(exts):
            try:
                new_baseline[ext] = snapshot_extension(ext)
            except Exception as e:
                errors += 1
                logger.error(f"快照扩展名 {ext} 失败: {e}")
            if progress_cb and (i % 50 == 0 or i == total - 1):
                try:
                    progress_cb(i + 1, total)
                except Exception:
                    pass

        # 保存历史版本
        self._push_history()

        with self._lock:
            self.baseline = new_baseline
        self.save()
        self.config["initialized"] = True
        self.config["baseline_mode"] = mode
        self.config["baseline_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.config["extension_count"] = len(new_baseline)
        self.save_config()
        # 基准重建后重新落实单扩展名锁定：删除UserChoice + HKCR默认=锁定应用，
        # 使锁定不受"以目前方式为基准"重建影响
        self._reapply_locked_defaults()
        log_event("ALL", "创建基准", "成功", f"模式={mode}, 扩展名数={len(new_baseline)}, 错误={errors}")
        return len(new_baseline)

    def _reapply_locked_defaults(self):
        """基准创建/重建后重新落实单扩展名锁定（锁定优先于基准）"""
        locked = self.config.get("locked_defaults", {}) or {}
        if not locked:
            return
        ok = 0
        for ext, progid in locked.items():
            try:
                force_delete_userchoice(ext)
                with winreg.CreateKeyEx(HKCR, ext, 0, KEY_SET_VALUE_64) as k:
                    winreg.SetValueEx(k, None, 0, winreg.REG_SZ, progid)
                try:
                    self.update_extension(ext, reason="锁定重落实")  # 同步基准为锁定态
                except Exception:
                    pass
                ok += 1
            except Exception:
                continue
        if ok:
            log_event("LOCK", "重建基准后重新锁定", "成功", f"{ok}/{len(locked)}个扩展名")

    def _clear_all_user_choice(self):
        """清除所有 UserChoice 键（用于默认模式）"""
        exts = reg_enum_subkeys(HKCU, USERCHOICE_BASE)
        count = 0
        for ext in exts:
            if ext.startswith("."):
                uc_path = f"{USERCHOICE_BASE}\\{ext}\\UserChoice"
                # 删除 Hash 和 ProgId
                reg_delete_value(HKCU, uc_path, "Hash")
                reg_delete_value(HKCU, uc_path, "ProgId")
                # 删除 UserChoice 项
                reg_delete_key(HKCU, uc_path)
                count += 1
        log_event("ALL", "清除UserChoice", "成功", f"清除{count}个")
        return count

    def _push_history(self):
        """将当前基准推入历史，保留最近5个版本"""
        if not os.path.exists(BASELINE_FILE):
            return
        try:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            hist_file = os.path.join(HISTORY_DIR, f"baseline_{ts}.json")
            shutil.copy2(BASELINE_FILE, hist_file)
            # 只保留最近 N 个（从配置读取，默认MAX_HISTORY_VERSIONS）
            max_ver = self.config.get("history_versions", MAX_HISTORY_VERSIONS)
            hist_files = sorted(
                [f for f in os.listdir(HISTORY_DIR) if f.startswith("baseline_") and f.endswith(".json")],
                reverse=True
            )
            for old in hist_files[max_ver:]:
                try:
                    os.remove(os.path.join(HISTORY_DIR, old))
                except OSError:
                    pass
        except OSError as e:
            logger.error(f"历史版本保存失败: {e}")

    def list_history(self):
        """列出历史版本"""
        if not os.path.exists(HISTORY_DIR):
            return []
        files = sorted(
            [f for f in os.listdir(HISTORY_DIR) if f.startswith("baseline_") and f.endswith(".json")],
            reverse=True
        )
        return files

    def restore_history(self, filename):
        """从历史版本恢复基准"""
        path = os.path.join(HISTORY_DIR, filename)
        if not os.path.exists(path):
            return False
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            self._push_history()
            with self._lock:
                self.baseline = data
            self.save()
            log_event("ALL", "恢复历史基准", "成功", filename)
            return True
        except (json.JSONDecodeError, OSError) as e:
            log_event("ALL", "恢复历史基准", "失败", str(e))
            return False

    def update_extension(self, ext, reason="用户单次同意"):
        """
        更新单个扩展名的基准（用户单次同意或锁定同步等场景调用）。
        同时推入历史版本。
        """
        self._push_history()
        with self._lock:
            self.baseline[ext] = snapshot_extension(ext)
        self.save()
        log_event(ext, "更新基准", "成功", reason)
        return True

    def update_selected_extensions(self, ext_list):
        """批量更新选中扩展名的基准（对比选择后调用）"""
        self._push_history()
        count = 0
        with self._lock:
            for ext in ext_list:
                try:
                    self.baseline[ext] = snapshot_extension(ext)
                    count += 1
                except Exception:
                    pass
        self.save()
        log_event("SYSTEM", "批量更新基准", "成功", f"更新{count}/{len(ext_list)}个扩展名")
        return count

    def clear_userchoice(self, ext):
        """
        将基准中该扩展名的 UserChoice 项设为 None。
        因 Windows 保护 UserChoice 拒绝写入，删除键后需同步更新基准，
        避免后续扫描重复检测"缺失"。
        """
        changed = False
        with self._lock:
            if ext in self.baseline:
                for key in ("userchoice_progid", "userchoice_hash"):
                    if key in self.baseline[ext]:
                        if self.baseline[ext][key].get("value") is not None:
                            self.baseline[ext][key]["value"] = None
                            self.baseline[ext][key]["type"] = None
                            changed = True
        if changed:
            self.save()
            log_event(ext, "UserChoice", "基准已清除", "Windows保护拒绝写入,删除键后同步基准")
        return changed

    def get_protected_extensions(self):
        with self._lock:
            return list(self.baseline.keys())

    def get_baseline_item(self, ext, key):
        with self._lock:
            return self.baseline.get(ext, {}).get(key)


# ============================================================
# 更改历史记录管理器
# ============================================================
class ChangeHistoryManager:
    """记录所有扩展名关联更改，支持回看和当前状态检测"""
    MAX_RECORDS = 500

    def __init__(self, data_dir):
        self.data_dir = data_dir
        self.history_file = os.path.join(data_dir, "change_history.json")
        self.records = []
        self.audit_level = "normal"
        self._load()

    def set_audit_level(self, level):
        if level in ("minimal", "normal", "detailed", "full"):
            self.audit_level = level

    def _load(self):
        try:
            if os.path.exists(self.history_file):
                with open(self.history_file, "r", encoding="utf-8") as f:
                    self.records = json.load(f)
        except Exception:
            self.records = []

    def _save(self):
        try:
            if len(self.records) > self.MAX_RECORDS:
                self.records = self.records[-self.MAX_RECORDS:]
            with open(self.history_file, "w", encoding="utf-8") as f:
                json.dump(self.records, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    def _normalize_source(self, source=None):
        if not source:
            return {
                "process_name": "unknown",
                "process_path": "",
                "command_line": "",
                "digital_signature": "unknown",
                "parent_process": "",
                "parent_path": "",
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "registry_path": "",
                "old_value": "",
                "new_value": "",
            }
        data = {
            "process_name": source.get("process_name") or "unknown",
            "process_path": source.get("process_path") or "",
            "command_line": source.get("command_line") or "",
            "digital_signature": source.get("digital_signature") or "unknown",
            "parent_process": source.get("parent_process") or "",
            "parent_path": source.get("parent_path") or "",
            "timestamp": source.get("timestamp") or time.strftime("%Y-%m-%d %H:%M:%S"),
            "registry_path": source.get("registry_path") or "",
            "old_value": source.get("old_value") or "",
            "new_value": source.get("new_value") or "",
        }
        return data

    def add_record(self, ext, tamperer, changes, action, result, source=None, audit_level=None):
        """添加一条更改记录
        action: auto_blocked / user_consent / detected_only
        result: success / fail / partial
        source: 进程/注册表来源追踪信息
        """
        src = self._normalize_source(source)
        level = self.audit_level
        # 根据记录级别裁剪source信息
        if level == "minimal":
            src = {"process_name": src.get("process_name", "unknown")}
        elif level == "normal":
            src = {k: src.get(k) for k in ("process_name", "process_path", "timestamp")}
        elif level == "detailed":
            src = {k: src.get(k) for k in ("process_name", "process_path", "command_line", "parent_process", "timestamp")}
        # full: 保留全部
        record = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "ext": ext,
            "tamperer": tamperer or "未知",
            "changes": changes,
            "action": action,
            "result": result,
            "audit_level": level,
            "source": src,
        }
        self.records.append(record)
        self._save()

    def get_records(self, ext=None, limit=100):
        """获取更改记录，可按扩展名筛选"""
        if ext:
            filtered = [r for r in self.records if r["ext"] == ext]
        else:
            filtered = self.records
        return filtered[-limit:]

    def export_records(self, path):
        """导出审计日志为 JSON 文件"""
        payload = {
            "exported_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "records": self.records,
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        return True

    def clear(self):
        self.records = []
        self._save()


# ============================================================
# 更改检测与恢复引擎
# ============================================================
class ProtectionEngine:
    ITEM_LABELS = {
        "hkcr_ext": "HKCR扩展名关联",
        "hkcu_ext": "HKCU扩展名关联",
        "hklm_ext": "HKLM扩展名关联",
        "userchoice_progid": "UserChoice ProgId",
        "userchoice_hash": "UserChoice Hash",
        "hkcr_command": "HKCR打开命令",
        "hkcu_command": "HKCU打开命令",
        "new_progid_command": "新ProgId植入命令",
    }

    # 关联扩展名映射：更改一个时可能同时更改其他（共享同一文件类型）
    RELATED_EXTS = {
        ".jpg": [".jpeg", ".jpe", ".jfif"],
        ".jpeg": [".jpg", ".jpe", ".jfif"],
        ".jpe": [".jpg", ".jpeg", ".jfif"],
        ".jfif": [".jpg", ".jpeg", ".jpe"],
        ".htm": [".html"],
        ".html": [".htm"],
        ".mpg": [".mpeg", ".mpe"],
        ".mpeg": [".mpg", ".mpe"],
        ".mpe": [".mpg", ".mpeg"],
        ".tif": [".tiff"],
        ".tiff": [".tif"],
        ".3gp": [".3g2", ".3gpp", ".3gp2"],
        ".3g2": [".3gp", ".3gpp", ".3gp2"],
        ".3gpp": [".3gp", ".3g2", ".3gp2"],
        ".3gp2": [".3gp", ".3g2", ".3gpp"],
        ".m4a": [".m4b", ".m4p", ".m4r"],
        ".m4b": [".m4a", ".m4p", ".m4r"],
        ".m4p": [".m4a", ".m4b", ".m4r"],
        ".ogg": [".oga", ".ogv", ".ogx", ".ogm"],
        ".oga": [".ogg", ".ogv", ".ogx", ".ogm"],
        ".ogv": [".ogg", ".oga", ".ogx", ".ogm"],
        ".ts": [".m2ts", ".m2t", ".mts", ".tts"],
        ".m2ts": [".ts", ".m2t", ".mts", ".tts"],
        ".m2t": [".ts", ".m2ts", ".mts", ".tts"],
        ".mts": [".ts", ".m2ts", ".m2t", ".tts"],
        ".avi": [".divx"],
        ".divx": [".avi"],
        ".flv": [".f4v"],
        ".f4v": [".flv"],
        ".svg": [".svgz"],
        ".svgz": [".svg"],
        ".wav": [".wave"],
        ".wave": [".wav"],
        ".mov": [".movie"],
        ".movie": [".mov"],
        ".bmp": [".dib"],
        ".dib": [".bmp"],
        ".txt": [".text"],
        ".text": [".txt"],
    }

    @classmethod
    def get_related_exts(cls, ext):
        """获取关联扩展名列表（含自身）"""
        ext = ext.lower()
        related = set(cls.RELATED_EXTS.get(ext, []))
        related.add(ext)
        return related

    def __init__(self, baseline_mgr):
        self.baseline = baseline_mgr
        self._lock = threading.Lock()
        self.paused = False
        self.allowed_this_cycle = set()  # 本周期用户同意的扩展名
        self.cooldown = {}  # ext -> timestamp, 冷却期内静默恢复不弹窗
        self._uc_fail_count = {}  # ext -> UserChoice恢复连续失败次数
        self.UC_FAIL_THRESHOLD = 3  # 连续失败次数阈值，超过则判定Hash过期

    def is_in_cooldown(self, ext):
        """检查扩展名是否在冷却期内"""
        ts = self.cooldown.get(ext)
        if ts and (time.time() - ts) < COOLDOWN_SECONDS:
            return True
        return False

    def set_cooldown(self, ext):
        """设置扩展名冷却时间"""
        self.cooldown[ext] = time.time()

    def clear_cooldown(self, ext):
        """清除扩展名冷却时间（用户同意时调用）"""
        self.cooldown.pop(ext, None)

    def record_uc_failure(self, ext):
        """记录 UserChoice 恢复失败，返回是否达到阈值（Hash过期判定）"""
        self._uc_fail_count[ext] = self._uc_fail_count.get(ext, 0) + 1
        return self._uc_fail_count[ext] >= self.UC_FAIL_THRESHOLD

    def reset_uc_failure(self, ext):
        """重置 UserChoice 恢复失败计数（恢复成功时调用）"""
        self._uc_fail_count.pop(ext, None)

    def handle_uc_hash_expiry(self, ext):
        """
        UserChoice Hash 过期处理：
        将基准中 UserChoice 设为 None（接受系统默认关联），确保 HKCR/.ext 正确。
        返回 True 表示已处理。
        """
        with self._lock:
            bl = self.baseline.baseline.get(ext)
            if not bl:
                return False
            changed = False
            for key in ("userchoice_progid", "userchoice_hash"):
                item = bl.get(key)
                if item and item.get("value") is not None:
                    item["value"] = None
                    item["type"] = None
                    changed = True
            if changed:
                self.baseline.save()
                log_event(ext, "UserChoice", "Hash过期", "已自动回退到系统默认关联(HKCR)")
        # 确保 HKCR/.ext 默认值正确（系统回退关联）
        hkcr_val = read_hkcr_effective(ext, "")[0]
        if hkcr_val:
            log_event(ext, "关联", "回退", f"使用HKCR默认:{hkcr_val}")
        self.reset_uc_failure(ext)
        return True

    def check_extension(self, ext):
        """
        检查单个扩展名是否被更改。
        保护逻辑采用统一的“基准快照 vs 当前注册表值”比较；
        对 UserChoice / command 采取更稳妥的豁免规则，避免 Windows 自动重建、
        Hash 重计算等导致的误报，同时补充检测“新 ProgId command”。
        """
        bl = self.baseline.baseline.get(ext)
        if not bl:
            return []

        bl_uc_progid = bl.get("userchoice_progid", {}).get("value")
        bl_uc_hash = bl.get("userchoice_hash", {}).get("value")
        uc_baseline_none = (bl_uc_progid is None and bl_uc_hash is None)

        hkcr_default = read_hkcr_effective(ext, "")[0]
        uc_path = f"{USERCHOICE_BASE}\\{ext}\\UserChoice"
        cur_uc_progid = reg_read_value(HKCU, uc_path, "ProgId")[0]
        cur_uc_hash = reg_read_value(HKCU, uc_path, "Hash")[0]
        uc_is_system_default = (
            uc_baseline_none and cur_uc_progid is not None
            and hkcr_default is not None and cur_uc_progid == hkcr_default
        )

        mismatches = []
        cur_uc_progid_for_hash = reg_read_value(HKCU, uc_path, "ProgId")[0]
        uc_progid_matches = (cur_uc_progid_for_hash == bl_uc_progid)

        # 用快照遍历，避免并发(主线程update_extension等)修改bl时
        # 抛 "dictionary changed size during iteration"
        for key, bl_item in list(bl.items()):
            if key == "new_progid_command" or not isinstance(bl_item, dict):
                continue

            if uc_is_system_default and key in ("userchoice_progid", "userchoice_hash"):
                continue

            if key == "userchoice_hash" and uc_progid_matches and bl_uc_progid is not None:
                continue

            root_name = bl_item.get("root")
            if key in ("userchoice_progid", "userchoice_hash"):
                # UserChoice 路径固定；基线键不存在时 root='?'，此前会被整体跳过，
                # 导致"从无到有"的 UserChoice 篡改永远检测不到。这里固定读取。
                uc_path_fixed = f"{USERCHOICE_BASE}\\{ext}\\UserChoice"
                uc_name = "ProgId" if key == "userchoice_progid" else "Hash"
                cur_val, cur_type = reg_read_value(HKCU, uc_path_fixed, uc_name)
            else:
                if root_name is None:
                    continue
                root = ROOT_MAP.get(str(root_name))
                if root is None:
                    continue
                path = bl_item.get("path", "")
                if not path:
                    continue
                name = bl_item.get("name", "")
                if str(root_name) == "HKCR" and HKCU_REMAPPED:
                    # TI 下 HKCR 不含用户 HKCU\Software\Classes 覆盖，用合并视图
                    cur_val, cur_type = read_hkcr_effective(path, name)
                else:
                    cur_val, cur_type = reg_read_value(root, path, name)

            if key == "userchoice_progid" and cur_val is None and cur_uc_progid is not None:
                cur_val = cur_uc_progid
                cur_type = 1
            elif key == "userchoice_hash" and cur_val is None and cur_uc_hash is not None:
                cur_val = cur_uc_hash
                cur_type = 1

            bl_val = bl_item.get("value")
            bl_type = bl_item.get("type")
            if not self._values_equal(bl_val, cur_val, bl_type, cur_type):
                mismatches.append((key, bl_val, cur_val, cur_type))

        bl_prog_id = None
        for key in ("userchoice_progid", "hkcu_ext", "hkcr_ext", "hklm_ext"):
            item = bl.get(key)
            if item and item.get("value"):
                bl_prog_id = item["value"]
                break

        cur_prog_id = get_prog_id(ext)
        if cur_prog_id and bl_prog_id and cur_prog_id != bl_prog_id:
            for root_name, reg_path in (
                ("HKCU", f"Software\\Classes\\{cur_prog_id}\\shell\\open\\command"),
                ("HKCR", f"{cur_prog_id}\\shell\\open\\command"),
                ("HKLM", f"SOFTWARE\\Classes\\{cur_prog_id}\\shell\\open\\command"),
            ):
                root = ROOT_MAP.get(root_name)
                if root is None:
                    continue
                if root_name == "HKCR" and HKCU_REMAPPED:
                    cmd_val, _ = read_hkcr_effective(reg_path, "")
                else:
                    cmd_val, _ = reg_read_value(root, reg_path, "")
                if cmd_val is not None:
                    mismatches.append(("new_progid_command", f"(基准:{bl_prog_id})",
                                       f"{root_name} {cur_prog_id} -> {cmd_val}", None))

        return mismatches

    def _values_equal(self, v1, v2, t1, t2):
        """比较两个注册表值是否相等"""
        if v1 is None and v2 is None:
            return True
        if v1 is None or v2 is None:
            return False
        # 字符串比较（忽略末尾空字符差异）
        if isinstance(v1, str) and isinstance(v2, str):
            return v1.rstrip('\x00') == v2.rstrip('\x00')
        return v1 == v2

    def recover_extension(self, ext, mismatches):
        """
        恢复单个扩展名到基准值。
        UserChoice 采用“删除键→重建→恢复 ProgId”的稳妥方案，
        command 位置优先恢复到基准值；如果基准为空则删除当前值，
        这样可以避免伪造路径、空项误判和重复恢复循环。
        返回 (success_count, fail_count, details)
        """
        # 单扩展名锁定优先（强锁定语义）：锁定表中的扩展名走专用恢复，
        # 恢复目标为 locked_defaults 中的锁定应用，而非基准值（锁定不受基准重建影响）
        try:
            _locked = (self.baseline.config or {}).get("locked_defaults", {}) or {}
        except Exception:
            _locked = {}
        lock_progid = _locked.get(ext)
        if lock_progid:
            return self._recover_locked(ext, lock_progid)

        bl = self.baseline.baseline.get(ext)
        if not bl:
            return 0, len(mismatches), ["基准不存在"]

        success = 0
        fail = 0
        details = []
        userchoice_recovered = False
        uc_path = f"{USERCHOICE_BASE}\\{ext}\\UserChoice"

        for key, bl_val, cur_val, cur_type in mismatches:
            if key == "new_progid_command":
                details.append("新ProgId命令:已随ProgId恢复失效")
                continue

            if key in ("userchoice_progid", "userchoice_hash"):
                if not userchoice_recovered:
                    userchoice_recovered = True
                    bl_progid = bl.get("userchoice_progid", {})
                    bl_hash = bl.get("userchoice_hash", {})
                    has_progid = bl_progid.get("value") is not None
                    has_hash = bl_hash.get("value") is not None

                    if not has_progid and not has_hash:
                        del_ok, del_method = force_delete_userchoice(ext)
                        if del_ok:
                            success += 2
                            details.append(f"UserChoice:已删除({del_method})")
                        else:
                            fail += 2
                            details.append(f"UserChoice:删除失败({del_method})")
                    else:
                        uc_ok = True
                        uc_parts = []
                        del_ok, del_method = force_delete_userchoice(ext)
                        if not del_ok:
                            uc_parts.append(f"删除失败({del_method}),尝试直接写入")
                        try:
                            kh = winreg.CreateKeyEx(HKCU, uc_path, 0, KEY_ALL_ACCESS_64)
                            if has_progid:
                                winreg.SetValueEx(kh, "ProgId", 0, bl_progid["type"], bl_progid["value"])
                                uc_parts.append("ProgId已恢复")
                            if has_hash and bl_hash.get("value") is not None:
                                winreg.SetValueEx(kh, "Hash", 0, bl_hash["type"], bl_hash["value"])
                                uc_parts.append("Hash已恢复")
                            winreg.CloseKey(kh)
                        except OSError as e:
                            uc_ok = False
                            uc_parts.append(f"写入失败:{e}")

                        if uc_ok:
                            success += 2
                            details.append(f"UserChoice:{'/'.join(uc_parts) if uc_parts else 'OK'}")
                        else:
                            fail += 2
                            details.append(f"UserChoice:{'/'.join(uc_parts) if uc_parts else '失败'}")
                continue

            bl_item = bl.get(key)
            if not isinstance(bl_item, dict):
                fail += 1
                details.append(f"{key}:基准项缺失")
                continue

            root_name = bl_item.get("root") or "?"
            root = ROOT_MAP.get(str(root_name))
            if root is None:
                fail += 1
                details.append(f"{self.ITEM_LABELS.get(key, key)}:root无效({root_name})")
                continue

            path = bl_item.get("path", "")
            name = bl_item.get("name", "")
            target_val = bl_item.get("value")
            target_type = bl_item.get("type")
            if not path:
                details.append(f"{self.ITEM_LABELS.get(key, key)}:无效路径，跳过恢复")
                continue

            if target_val is None and target_type is None:
                del_ok = reg_delete_value(root, path, name)
                extra_del = ""
                if del_ok and str(root_name) == "HKCR" and HKCU_REMAPPED:
                    if reg_delete_value(HKCU, "Software\\Classes\\" + path, name):
                        extra_del = "(含用户HKCU)"
                if del_ok:
                    success += 1
                    details.append(f"{self.ITEM_LABELS.get(key, key)}:已删除{extra_del}")
                else:
                    fail += 1
                    details.append(f"{self.ITEM_LABELS.get(key, key)}:删除失败")
            else:
                write_ok = reg_write_value(root, path, name, target_val, target_type)
                extra_note = ""
                if write_ok and str(root_name) == "HKCR" and HKCU_REMAPPED:
                    # TI 下 HKCR 不含用户 HKCU\Software\Classes 覆盖；
                    # 同步写/删用户 HKCU 保证恢复值真实生效
                    user_path = "Software\\Classes\\" + path
                    if reg_write_value(HKCU, user_path, name, target_val, target_type):
                        extra_note = "(含用户HKCU)"
                if write_ok:
                    success += 1
                    details.append(f"{self.ITEM_LABELS.get(key, key)}:已恢复{extra_note}")
                else:
                    fail += 1
                    details.append(f"{self.ITEM_LABELS.get(key, key)}:恢复失败(权限不足?)")

        return success, fail, details

    def _recover_locked(self, ext, lock_progid):
        """锁定扩展名专用恢复（强锁定语义，恢复目标=锁定应用而非基准值）：
        1) 删除 UserChoice（其 Hash 与锁定 ProgId 不匹配会失效，删除后系统回退到 HKCR 默认）
        2) HKCR\\ext 默认值 = 锁定应用（无 Hash 限制，资源管理器无 UserChoice 时回退到此）
        3) OpenWithProgids 加入锁定应用（保持可选打开列表完整）
        4) 同步基准为该扩展名当前态，保证后续验证与监控口径一致
        返回 (success_count, fail_count, details)
        """
        success = 0
        fail = 0
        details = []
        # 1) 删除 UserChoice
        try:
            del_ok, del_method = force_delete_userchoice(ext)
            if del_ok:
                success += 1
                details.append(f"UserChoice:已删除({del_method})")
            else:
                fail += 1
                details.append(f"UserChoice:删除失败({del_method})")
        except Exception as e:
            fail += 1
            details.append(f"UserChoice:异常({e})")
        # 2) HKCR\ext 默认值 = 锁定应用
        try:
            with winreg.CreateKeyEx(HKCR, ext, 0, KEY_SET_VALUE_64) as k:
                winreg.SetValueEx(k, None, 0, winreg.REG_SZ, lock_progid)
            success += 1
            details.append("HKCR默认:已设为锁定应用")
        except OSError as e:
            fail += 1
            details.append(f"HKCR默认:写入失败({e})")
        # 2b) 用户级覆盖 HKCU\Software\Classes\ext 默认值 = 锁定应用
        #     （普通令牌程序篡改关联时通常经 HKCU\Software\Classes 覆盖生效，
        #      仅写 HKCR 会被用户级覆盖遮蔽，必须同步修正该覆盖键）
        try:
            uc_cls = f"Software\\Classes\\{ext}"
            with winreg.CreateKeyEx(HKCU, uc_cls, 0, KEY_SET_VALUE_64) as k:
                winreg.SetValueEx(k, None, 0, winreg.REG_SZ, lock_progid)
            success += 1
            details.append("HKCU覆盖:已设为锁定应用")
        except OSError as e:
            fail += 1
            details.append(f"HKCU覆盖:写入失败({e})")
        # 2c) 清理用户级覆盖残留的 shell\open\command（避免锁定应用被旧命令绕过）
        def _del_tree(root, path):
            try:
                k = winreg.OpenKey(root, path, 0, KEY_SET_VALUE_64)
                try:
                    subkeys = []
                    i = 0
                    while True:
                        try:
                            subkeys.append(winreg.EnumKey(k, i))
                            i += 1
                        except OSError:
                            break
                    for sk in subkeys:
                        _del_tree(root, f"{path}\\{sk}")
                finally:
                    winreg.CloseKey(k)
                winreg.DeleteKey(root, path)
                return True
            except OSError:
                return False
        try:
            uc_cmd = f"Software\\Classes\\{ext}\\shell"
            if _del_tree(HKCU, uc_cmd):
                details.append("HKCU命令:已清理残留")
            else:
                details.append("HKCU命令:无残留")
        except Exception:
            pass
        # 3) OpenWithProgids 加入锁定应用（非关键，失败不影响）
        try:
            owp = f"{ext}\\OpenWithProgids"
            with winreg.CreateKeyEx(HKCR, owp, 0, KEY_SET_VALUE_64) as k:
                winreg.SetValueEx(k, lock_progid, 0, winreg.REG_SZ, "")
            success += 1
            details.append("OpenWithProgids:已加入锁定应用")
        except OSError:
            pass
        # 4) 同步基准为该扩展名当前态（无UserChoice + HKCR=锁定），验证与监控口径一致
        try:
            self.baseline.update_extension(ext, reason="锁定同步")
            details.append("基准:已同步锁定态")
        except Exception as e:
            details.append(f"基准:同步失败({e})")
        return success, fail, details

    def scan_all(self):
        """
        全量扫描所有受保护扩展名。
        返回 dict: ext -> mismatches list
        """
        results = {}
        exts = self.baseline.get_protected_extensions()
        for ext in exts:
            mismatches = self.check_extension(ext)
            if mismatches:
                results[ext] = mismatches
        return results

    def deep_scan(self):
        """
        深层扫描：遍历注册表，检测基准外的新增扩展名关联篡改，
        以及基准内扩展名的不一致性。
        返回 (inconsistencies, new_extensions)
        """
        inconsistencies = self.scan_all()

        # 检测是否有新出现的扩展名不在基准中（可能被恶意软件注册）
        current_exts = set(enumerate_all_extensions())
        baseline_exts = set(self.baseline.get_protected_extensions())
        new_exts = current_exts - baseline_exts

        # 过滤：只报告有 UserChoice 或 open command 的新扩展名（可能是篡改）
        suspicious_new = []
        for ext in new_exts:
            has_uc = reg_read_value(HKCU, f"{USERCHOICE_BASE}\\{ext}\\UserChoice", "ProgId")[0] is not None
            prog_id = get_prog_id(ext)
            has_cmd = False
            if prog_id:
                if HKCU_REMAPPED:
                    has_cmd = read_hkcr_effective(f"{prog_id}\\shell\\open\\command", "")[0] is not None
                else:
                    has_cmd = reg_read_value(HKCR, f"{prog_id}\\shell\\open\\command", "")[0] is not None
            if has_uc or has_cmd:
                suspicious_new.append(ext)

        # 额外补充：扫描无效关联/缺失项，避免“看起来正常但实际关联已损坏”的隐藏问题
        invalid_pairs = self.scan_invalid_associations()
        for ext, reason in invalid_pairs:
            if ext not in inconsistencies:
                inconsistencies[ext] = [("invalid_association", None, reason, None)]
        return inconsistencies, suspicious_new

    def scan_invalid_associations(self, ext=None):
        """扫描无效关联、缺失键和破损命令项。返回 [(ext, reason), ...]"""
        issues = []
        targets = [ext] if ext else self.baseline.get_protected_extensions()
        for ext_name in targets:
            bl = self.baseline.baseline.get(ext_name, {})
            if not bl:
                continue
            # 缺失项：基准存在，但当前键已不存在（快照遍历防并发修改）
            for key, item in list(bl.items()):
                if not isinstance(item, dict):
                    continue
                path = item.get("path")
                if not path:
                    continue
                root_name = item.get("root")
                if root_name is None:
                    continue
                root = ROOT_MAP.get(str(root_name))
                if root is None:
                    continue
                name = item.get("name", "")
                value = item.get("value")
                cur_val, _ = reg_read_value(root, path, name)
                if value is not None and cur_val is None:
                    issues.append((ext_name, f"{key} 缺失: {root_name}\\{path}\\{name}"))
            # 无效关联：UserChoice ProgId 指向不存在的 ProgId 或命令键空值
            prog_id = get_prog_id(ext_name)
            if prog_id:
                # UWP应用(AppX开头)使用不同的激活机制，没有传统shell\open\command是正常的，跳过
                if prog_id.startswith("AppX"):
                    continue
                for root_name, reg_path in (
                    ("HKCR", f"{prog_id}\\shell\\open\\command"),
                    ("HKCU", f"Software\\Classes\\{prog_id}\\shell\\open\\command"),
                    ("HKLM", f"SOFTWARE\\Classes\\{prog_id}\\shell\\open\\command"),
                ):
                    root = ROOT_MAP.get(root_name)
                    if root is None:
                        continue
                    if root_name == "HKCR" and HKCU_REMAPPED:
                        cmd_val, _ = read_hkcr_effective(reg_path, "")
                    else:
                        cmd_val, _ = reg_read_value(root, reg_path, "")
                    if cmd_val is None:
                        issues.append((ext_name, f"无效关联: {prog_id} 命令缺失"))
                        break
            else:
                uc_prog_id, _ = reg_read_value(HKCU, f"{USERCHOICE_BASE}\\{ext_name}\\UserChoice", "ProgId")
                if uc_prog_id is not None and not uc_prog_id.startswith("AppX"):
                    issues.append((ext_name, "UserChoice 指向无效或已失效 ProgId"))
        return issues


# ============================================================
# 右下角通知 (更改通知 + 单次同意 + 15秒默认阻止)
# ============================================================
class NotificationToast:
    """右下角滑出通知，非模态，超时后默认阻止。
    三个操作按钮：单次同意 / 关闭弹窗1分钟 / 永久关闭"""
    TOAST_WIDTH = 440
    TOAST_HEIGHT = 300
    MARGIN = 50  # 离屏幕底部距离，调高让弹窗位置更高
    GAP = 10

    def __init__(self, parent, ext, mismatches, recover_result, on_consent, on_close,
                 on_pause_min, on_forever, on_show_main, y_offset=0, x_offset=0,
                 timeout=None, tamperer_name=None):
        self.ext = ext
        self.mismatches = mismatches
        self.recover_result = recover_result
        self.on_consent = on_consent
        self.on_close = on_close
        self.on_pause_min = on_pause_min
        self.on_forever = on_forever
        self.on_show_main = on_show_main
        self.y_offset = y_offset
        self.x_offset = x_offset
        self.timeout = timeout if timeout and timeout > 0 else NOTIFY_TIMEOUT
        self.remaining = self.timeout
        self._closed = False
        self.close_reason = None  # "consent" / "timeout" / "close" / "pause_min" / "forever"
        self.tamperer_name = tamperer_name
        self._build_ui(parent)

    def _build_ui(self, parent):
        self.win = tk.Toplevel(parent)
        self.win.overrideredirect(True)  # 无边框
        self.win.attributes("-topmost", True)
        self.win.attributes("-alpha", 0.92)  # 整体透明
        self.win.configure(bg="#2c3e50")

        # 计算右下角位置（堆叠时每个向左上偏移）
        sw = self.win.winfo_screenwidth()
        sh = self.win.winfo_screenheight()
        self.target_y = sh - self.TOAST_HEIGHT - self.MARGIN - self.y_offset
        x = sw - self.TOAST_WIDTH - self.MARGIN - self.x_offset
        # 初始位置在屏幕外（下方），用于滑入动画
        self.win.geometry(f"{self.TOAST_WIDTH}x{self.TOAST_HEIGHT}+{x}+{sh}")

        # 顶部红色警示线（起吸引作用）
        top_bar = tk.Frame(self.win, bg="#e74c3c", height=5)
        top_bar.pack(fill="x")
        top_bar.pack_propagate(False)

        # 内容区（深灰透明感）
        content = tk.Frame(self.win, bg="#34495e")
        content.pack(fill="both", expand=True, padx=14, pady=(10, 6))

        # 标题行：谁改了什么（长文本自动换行）
        title_frame = tk.Frame(content, bg="#34495e")
        title_frame.pack(fill="x")
        if self.tamperer_name:
            title_text = f"[{self.tamperer_name}] 更改了 {self.ext}"
        else:
            title_text = f"{self.ext} 被更改"
        tk.Label(title_frame, text=title_text,
                 font=("微软雅黑", 11, "bold"), fg="#ecf0f1",
                 bg="#34495e", anchor="w", justify="left", wraplength=390
                 ).pack(side="left")
        self.timer_label = tk.Label(title_frame, text=f"{self.remaining}秒后默认阻止",
                                     font=("微软雅黑", 8), fg="#95a5a6", bg="#34495e")
        self.timer_label.pack(side="right")

        # 更改详情：具体改了什么（最多2项，避免按钮被挤出）
        detail_parts = []
        for key, bl_val, cur_val, _ in self.mismatches[:2]:
            label = ProtectionEngine.ITEM_LABELS.get(key, key)
            detail_parts.append(f"{label}: {bl_val}→{cur_val}")
        detail_text = "；".join(detail_parts)
        if len(self.mismatches) > 2:
            detail_text += f" 等{len(self.mismatches)}项"
        tk.Label(content, text=detail_text,
                 font=("微软雅黑", 8), fg="#bdc3c7", bg="#34495e",
                 anchor="w", wraplength=400, justify="left").pack(fill="x", pady=(6, 0))

        # 操作 + 结果
        success, fail, details = self.recover_result
        if fail == 0:
            result_text = "成功"
            result_color = "#2ecc71"
        else:
            result_text = f"失败({success}成功/{fail}失败)"
            result_color = "#e67e22"
        result_frame = tk.Frame(content, bg="#34495e")
        result_frame.pack(fill="x", pady=(8, 0))
        tk.Label(result_frame, text="操作：已恢复",
                 font=("微软雅黑", 9), fg="#ecf0f1", bg="#34495e").pack(side="left")
        tk.Label(result_frame, text=f"  结果：{result_text}",
                 font=("微软雅黑", 10, "bold"), fg=result_color, bg="#34495e").pack(side="left")

        # 按钮区：单次同意 / 关闭弹窗1分钟 / 永久关闭
        # 不设固定宽度：按钮按文字自适应（文字多自动向左/右伸展），保持一行
        bottom = tk.Frame(content, bg="#34495e")
        bottom.pack(fill="x", pady=(10, 0))

        btn_row1 = tk.Frame(bottom, bg="#34495e")
        btn_row1.pack(fill="x")
        self.consent_btn = tk.Button(btn_row1, text="单次同意",
                                      font=("微软雅黑", 9, "bold"),
                                      command=self._on_consent, relief="flat",
                                      bg="#27ae60", fg="white", activebackground="#2ecc71",
                                      activeforeground="white", cursor="hand2",
                                      padx=14, pady=5)
        self.consent_btn.pack(side="left", padx=(0, 8))

        self.pause_min_btn = tk.Button(btn_row1, text="关闭弹窗1分钟",
                                        font=("微软雅黑", 9),
                                        command=self._on_pause_min, relief="flat",
                                        bg="#f39c12", fg="white", activebackground="#f5b041",
                                        activeforeground="white", cursor="hand2",
                                        padx=14, pady=5)
        self.pause_min_btn.pack(side="left", padx=(0, 8))

        self.forever_btn = tk.Button(btn_row1, text="永久关闭",
                                      font=("微软雅黑", 9),
                                      command=self._on_forever, relief="flat",
                                      bg="#7f8c8d", fg="white", activebackground="#95a5a6",
                                      activeforeground="white", cursor="hand2",
                                      padx=14, pady=5)
        self.forever_btn.pack(side="left")

        # 提示行（按钮含义，自动换行避免超宽裁切）
        tk.Label(bottom, text="单次同意=允许这次更改；关闭1分钟=暂停提醒1分钟；永久关闭=该扩展名永久忽略",
                 font=("微软雅黑", 7), fg="#7f8c8d", bg="#34495e",
                 anchor="w", justify="left", wraplength=400).pack(fill="x", pady=(6, 0))

        # 倒计时进度条（底部细线）
        self.progress = tk.Frame(self.win, bg="#e74c3c", height=2)
        self.progress.pack(fill="x", side="bottom")
        self.progress_width = self.TOAST_WIDTH

        # 高度自适应：按内容实际需求高度调整，消灭底部大片空白
        # （内容全部 pack 后计算，最小 170px 保证按钮区完整，最大 420px 防超屏）
        try:
            self.win.update_idletasks()
            self.TOAST_HEIGHT = max(self.win.winfo_reqheight(), 170)
            if self.TOAST_HEIGHT > 420:
                self.TOAST_HEIGHT = 420
        except Exception:
            pass
        # 高度可能已变化，重新计算目标位置，并重置初始位置到屏幕外供滑入
        sh = self.win.winfo_screenheight()
        sw = self.win.winfo_screenwidth()
        self.target_y = sh - self.TOAST_HEIGHT - self.MARGIN - self.y_offset
        x = sw - self.TOAST_WIDTH - self.MARGIN - self.x_offset
        self.win.geometry(f"{self.TOAST_WIDTH}x{self.TOAST_HEIGHT}+{x}+{sh}")

        # 滑入动画
        self._slide_in()
        # 确保窗口完全渲染后再启动倒计时
        try:
            self.win.update()
        except Exception:
            pass
        # 延迟启动倒计时，确保窗口已显示
        self.win.after(100, self._tick)

    def _slide_in(self):
        """从下方滑入到目标位置"""
        try:
            geo = self.win.geometry()
            cur_y = int(geo.split("+")[2])
            if cur_y > self.target_y:
                new_y = max(self.target_y, cur_y - 30)
                x = geo.split("+")[1]
                self.win.geometry(f"{self.TOAST_WIDTH}x{self.TOAST_HEIGHT}+{x}+{new_y}")
                self.win.after(10, self._slide_in)
            else:
                # 滑入完成后设置焦点，确保按钮可点击
                try:
                    self.win.focus_force()
                    self.consent_btn.focus_set()
                except Exception:
                    pass
        except tk.TclError:
            pass

    def _tick(self):
        if self._closed:
            return
        try:
            if self.remaining <= 0:
                self._on_timeout()
                return
            self.timer_label.config(text=f"{self.remaining}秒后默认阻止")
            # 更新进度条宽度
            ratio = self.remaining / self.timeout
            new_w = max(1, int(self.TOAST_WIDTH * ratio))
            self.progress.config(width=new_w)
            self.remaining -= 1
        except Exception:
            pass
        self.win.after(1000, self._tick)

    def _on_consent(self):
        if self._closed:
            return
        self._closed = True
        self.close_reason = "consent"
        try:
            self.on_consent(self.ext)
        except Exception:
            pass
        self._close()

    def _on_pause_min(self):
        """关闭弹窗1分钟：暂停弹窗提醒1分钟，期间静默阻止"""
        if self._closed:
            return
        self._closed = True
        self.close_reason = "pause_min"
        try:
            if self.on_pause_min:
                self.on_pause_min(self.ext)
        except Exception:
            pass
        self._close()

    def _on_forever(self):
        """永久关闭：该扩展名永久忽略，不再弹窗与阻止"""
        if self._closed:
            return
        self._closed = True
        self.close_reason = "forever"
        try:
            if self.on_forever:
                self.on_forever(self.ext)
        except Exception:
            pass
        self._close()

    def _on_show_main(self):
        """点击打开主程序：显示主窗口，不关闭通知"""
        try:
            if self.on_show_main:
                self.on_show_main()
        except Exception:
            pass

    def _on_timeout(self):
        if self._closed:
            return
        self._closed = True
        self.close_reason = "timeout"
        self._close()

    def _on_close_btn(self):
        """用户点击关闭弹窗：等同超时自动阻止"""
        if self._closed:
            return
        self._closed = True
        self.close_reason = "timeout"
        self._close()

    def _close(self):
        """滑出并销毁"""
        try:
            self.win.destroy()
        except tk.TclError:
            pass
        self.on_close(self)


class BatchNotificationToast:
    """批量篡改通知：同一进程短时间内篡改多个扩展名时合并显示"""
    TOAST_WIDTH = 400
    TOAST_HEIGHT = 260
    MARGIN = 50

    def __init__(self, parent, tamperer_name, items, on_block_all, on_allow_all, on_view_onebyone, on_pause, on_close):
        self.tamperer_name = tamperer_name
        self.items = items
        self.on_block_all = on_block_all
        self.on_allow_all = on_allow_all
        self.on_view_onebyone = on_view_onebyone
        self.on_pause = on_pause
        self.on_close = on_close
        self.remaining = 60
        self._closed = False
        self._build_ui(parent)

    def _build_ui(self, parent):
        self.win = tk.Toplevel(parent)
        self.win.overrideredirect(True)
        self.win.attributes("-topmost", True)
        self.win.attributes("-alpha", 0.92)
        self.win.configure(bg="#2c3e50")
        sw = self.win.winfo_screenwidth()
        sh = self.win.winfo_screenheight()
        x = sw - self.TOAST_WIDTH - self.MARGIN
        self.target_y = sh - self.TOAST_HEIGHT - self.MARGIN
        self.win.geometry(f"{self.TOAST_WIDTH}x{self.TOAST_HEIGHT}+{x}+{sh}")
        # 顶部红色警示线
        tk.Frame(self.win, bg="#e74c3c", height=5).pack(fill="x")
        content = tk.Frame(self.win, bg="#34495e")
        content.pack(fill="both", expand=True, padx=14, pady=(10, 6))
        title_frame = tk.Frame(content, bg="#34495e")
        title_frame.pack(fill="x")
        name = self.tamperer_name if self.tamperer_name else "未知程序"
        tk.Label(title_frame, text="检测到批量更改", font=("微软雅黑", 12, "bold"), fg="#ecf0f1", bg="#34495e").pack(side="left")
        self.timer_label = tk.Label(title_frame, text=f"{self.remaining}秒后全部阻止", font=("微软雅黑", 8), fg="#95a5a6", bg="#34495e")
        self.timer_label.pack(side="right")
        tk.Label(content, text=f"程序：{name}", font=("微软雅黑", 10), fg="#ecf0f1", bg="#34495e", anchor="w").pack(fill="x", pady=(8, 0))
        tk.Label(content, text=f"正在更改 {len(self.items)} 个文件的默认打开方式：", font=("微软雅黑", 9), fg="#bdc3c7", bg="#34495e", anchor="w").pack(fill="x", pady=(4, 6))
        list_frame = tk.Frame(content, bg="#2c3e50", height=60)
        list_frame.pack(fill="x")
        list_frame.pack_propagate(False)
        ext_text = tk.Text(list_frame, font=("微软雅黑", 9), bg="#2c3e50", fg="#ecf0f1", wrap="word", height=3, bd=0, padx=8, pady=4)
        ext_text.pack(fill="both", expand=True)
        exts = [item[0] for item in self.items]
        ext_text.insert("end", "  ".join(exts))
        ext_text.config(state="disabled")
        btn_frame = tk.Frame(content, bg="#34495e")
        btn_frame.pack(fill="x", pady=(10, 0))
        # 按钮不设固定宽度：按文字自适应（长文本自动伸展，避免截断/堆高）
        tk.Button(btn_frame, text="全部阻止", font=("微软雅黑", 9, "bold"), bg="#e74c3c", fg="white", relief="flat", cursor="hand2", padx=12, pady=4, command=self._on_block_all).pack(side="left", padx=2)
        tk.Button(btn_frame, text="全部允许", font=("微软雅黑", 9), bg="#27ae60", fg="white", relief="flat", cursor="hand2", padx=12, pady=4, command=self._on_allow_all).pack(side="left", padx=2)
        tk.Button(btn_frame, text="逐个查看", font=("微软雅黑", 9), bg="#3498db", fg="white", relief="flat", cursor="hand2", padx=12, pady=4, command=self._on_view_onebyone).pack(side="left", padx=2)
        btn_frame2 = tk.Frame(content, bg="#34495e")
        btn_frame2.pack(fill="x", pady=(6, 0))
        tk.Button(btn_frame2, text="暂停弹窗5分钟", font=("微软雅黑", 8), bg="#7f8c8d", fg="white", relief="flat", cursor="hand2", padx=10, pady=3, command=self._on_pause).pack(side="left", padx=2)
        tk.Button(btn_frame2, text="关闭", font=("微软雅黑", 8), bg="#95a5a6", fg="white", relief="flat", cursor="hand2", padx=10, pady=3, command=self._on_close_btn).pack(side="right", padx=2)
        self.progress = tk.Frame(self.win, bg="#e74c3c", height=2)
        self.progress.pack(fill="x", side="bottom")

        # 高度自适应：按内容实际需求高度调整，消灭底部大片空白
        # （内容全部 pack 后计算，最小 170px 保证按钮区完整，最大 420px 防超屏）
        try:
            self.win.update_idletasks()
            self.TOAST_HEIGHT = max(self.win.winfo_reqheight(), 170)
            if self.TOAST_HEIGHT > 420:
                self.TOAST_HEIGHT = 420
        except Exception:
            pass
        # 高度可能已变化，重新计算目标位置，并重置初始位置到屏幕外供滑入
        sh = self.win.winfo_screenheight()
        sw = self.win.winfo_screenwidth()
        self.target_y = sh - self.TOAST_HEIGHT - self.MARGIN
        x = sw - self.TOAST_WIDTH - self.MARGIN
        self.win.geometry(f"{self.TOAST_WIDTH}x{self.TOAST_HEIGHT}+{x}+{sh}")

        self._slide_in()
        try:
            self.win.update()
        except Exception:
            pass
        self.win.after(100, self._tick)

    def _slide_in(self):
        try:
            geo = self.win.geometry()
            cur_y = int(geo.split("+")[2])
            if cur_y > self.target_y:
                new_y = max(self.target_y, cur_y - 30)
                x = geo.split("+")[1]
                self.win.geometry(f"{self.TOAST_WIDTH}x{self.TOAST_HEIGHT}+{x}+{new_y}")
                self.win.after(10, self._slide_in)
        except Exception:
            pass

    def _tick(self):
        if self._closed:
            return
        self.remaining -= 1
        if self.remaining <= 0:
            self._on_block_all()
            return
        self.timer_label.config(text=f"{self.remaining}秒后全部阻止")
        self.win.after(1000, self._tick)

    def _on_block_all(self):
        if self._closed:
            return
        self._closed = True
        try:
            self.win.destroy()
        except Exception:
            pass
        self.on_block_all(self.tamperer_name, self.items)

    def _on_allow_all(self):
        if self._closed:
            return
        self._closed = True
        try:
            self.win.destroy()
        except Exception:
            pass
        self.on_allow_all(self.tamperer_name, self.items)

    def _on_view_onebyone(self):
        if self._closed:
            return
        self._closed = True
        try:
            self.win.destroy()
        except Exception:
            pass
        self.on_view_onebyone(self.tamperer_name, self.items)

    def _on_pause(self):
        if self._closed:
            return
        self._closed = True
        try:
            self.win.destroy()
        except Exception:
            pass
        self.on_pause()

    def _on_close_btn(self):
        if self._closed:
            return
        self._closed = True
        try:
            self.win.destroy()
        except Exception:
            pass
        self.on_close(self.tamperer_name, self.items)

    def move_up(self, delta_y, delta_x=0):
        """通知关闭时，上方通知对角线上移（上+左）"""
        if self._closed:
            return
        try:
            geo = self.win.geometry()
            parts = geo.split("+")
            cur_y = int(parts[2])
            cur_x = int(parts[1])
            new_y = cur_y - delta_y
            new_x = cur_x - delta_x
            self.win.geometry(f"{parts[0]}+{new_x}+{new_y}")
            self.target_y -= delta_y
        except (tk.TclError, IndexError):
            pass

    def move_right(self, delta_x):
        """通知关闭时，右侧通知右移填补空位"""
        if self._closed:
            return
        try:
            geo = self.win.geometry()
            parts = geo.split("+")
            cur_x = int(parts[1])
            new_x = cur_x + delta_x
            self.win.geometry(f"{parts[0]}+{new_x}+{parts[2]}")
        except (tk.TclError, IndexError):
            pass


# ============================================================
# 首次运行 - 基准校准对话框
# ============================================================
class SetupDialog:
    def __init__(self, parent, on_complete):
        self.on_complete = on_complete
        self.choice = None
        self._build_ui(parent)

    def _build_ui(self, parent):
        self.win = tk.Toplevel(parent)
        self.win.title(f"{APP_NAME} - 首次运行校准")
        self.win.geometry("520x440")
        self.win.resizable(False, False)
        self.win.attributes("-topmost", True)

        self.win.update_idletasks()
        x = (self.win.winfo_screenwidth() - 520) // 2
        y = (self.win.winfo_screenheight() - 440) // 2
        self.win.geometry(f"520x440+{x}+{y}")

        tk.Label(self.win, text=f"欢迎使用 {APP_NAME}",
                 font=("微软雅黑", 16, "bold")).pack(pady=(20, 5))
        tk.Label(self.win, text="请选择基准校准方式：",
                 font=("微软雅黑", 11)).pack(pady=(0, 15))

        # 选项1
        frame1 = tk.Frame(self.win, bd=1, relief="solid", padx=15, pady=12)
        frame1.pack(fill="x", padx=30, pady=5)
        tk.Label(frame1, text="① 以目前方式为基准",
                 font=("微软雅黑", 12, "bold"), fg="#2980b9").pack(anchor="w")
        tk.Label(frame1, text="将当前所有扩展名的打开方式作为保护基准。\n适合当前关联设置已是你想要的状态。",
                 font=("微软雅黑", 9), fg="#555", justify="left").pack(anchor="w", pady=(3, 0))
        tk.Button(frame1, text="选择此方式", font=("微软雅黑", 10),
                  bg="#3498db", fg="white", width=15,
                  command=lambda: self._choose("current")).pack(pady=(8, 0))

        # 选项2
        frame2 = tk.Frame(self.win, bd=1, relief="solid", padx=15, pady=12)
        frame2.pack(fill="x", padx=30, pady=5)
        tk.Label(frame2, text="② 以默认方式为基准",
                 font=("微软雅黑", 12, "bold"), fg="#27ae60").pack(anchor="w")
        tk.Label(frame2, text="清除所有用户自定义关联，以系统默认关联作为保护基准。\n可下载预置默认基准包导入，或直接以系统默认创建。",
                 font=("微软雅黑", 9), fg="#555", justify="left").pack(anchor="w", pady=(3, 0))
        tk.Button(frame2, text="选择此方式", font=("微软雅黑", 10),
                  bg="#27ae60", fg="white", width=15,
                  command=lambda: self._choose("default")).pack(pady=(8, 0))

        tk.Label(self.win, text="基准创建后可随时在主界面更新。基准保留5个历史版本。",
                 font=("微软雅黑", 8), fg="#999").pack(pady=(15, 0))

        self.win.grab_set()
        self.win.focus_force()

    def _choose(self, mode):
        if mode == "default":
            # 直接弹出子对话框：导入基准文件 or 系统默认创建。
            # 不打开第三方下载页——默认基准可通过"以系统默认创建"或导入自有 .json 生成。
            sub = DefaultOptionDialog(self.win)
            result = sub.show()
            if result is None:
                return  # 用户取消，不关闭主对话框
            self.choice = result  # "import" 或 "default"
        else:
            self.choice = mode
        self.win.destroy()

    def show(self):
        self.win.wait_window()
        return self.choice


class DefaultOptionDialog:
    """选择'以默认方式'后的子对话框：导入基准文件 or 系统默认创建"""
    def __init__(self, parent):
        self.result = None
        self.win = tk.Toplevel(parent)
        self.win.title("默认基准 - 选择方式")
        self.win.geometry("420x280")
        self.win.resizable(False, False)
        self.win.attributes("-topmost", True)
        self.win.transient(parent)
        self.win.grab_set()

        self.win.update_idletasks()
        x = (self.win.winfo_screenwidth() - 420) // 2
        y = (self.win.winfo_screenheight() - 280) // 2
        self.win.geometry(f"420x280+{x}+{y}")

        tk.Label(self.win, text="选择默认基准的获取方式",
                 font=("微软雅黑", 13, "bold")).pack(pady=(20, 3))
        tk.Label(self.win, text="可导入已有的 .json 基准文件，或直接以系统默认关联创建",
                 font=("微软雅黑", 9), fg="#666").pack(pady=(0, 10))

        # 选项A：导入文件
        fa = tk.Frame(self.win, bd=1, relief="solid", padx=12, pady=8)
        fa.pack(fill="x", padx=25, pady=4)
        tk.Label(fa, text="A. 导入已下载的基准文件",
                 font=("微软雅黑", 10, "bold"), fg="#2980b9").pack(anchor="w")
        tk.Label(fa, text="选择下载好的 .json 基准文件导入",
                 font=("微软雅黑", 8), fg="#555").pack(anchor="w")
        tk.Button(fa, text="选择文件导入", font=("微软雅黑", 9),
                  width=14, command=lambda: self._pick("import")).pack(pady=(5, 0))

        # 选项B：系统默认
        fb = tk.Frame(self.win, bd=1, relief="solid", padx=12, pady=8)
        fb.pack(fill="x", padx=25, pady=4)
        tk.Label(fb, text="B. 直接以系统默认创建基准",
                 font=("微软雅黑", 10, "bold"), fg="#27ae60").pack(anchor="w")
        tk.Label(fb, text="清除UserChoice，以HKLM系统默认关联为基准",
                 font=("微软雅黑", 8), fg="#555").pack(anchor="w")
        tk.Button(fb, text="使用系统默认", font=("微软雅黑", 9),
                  width=14, command=lambda: self._pick("default")).pack(pady=(5, 0))

    def _pick(self, result):
        self.result = result
        self.win.destroy()

    def show(self):
        self.win.wait_window()
        return self.result


# ============================================================
# 监控线程
# ============================================================
class MonitorThread(threading.Thread):
    GRACE_PERIOD_SECONDS = 10  # 启动后宽限期：只检测不恢复，给用户备份机会

    def __init__(self, engine, baseline_mgr, popup_callback, log_callback, root=None, process_enforcer=None):
        super().__init__(daemon=True)
        self.engine = engine
        self.baseline = baseline_mgr
        self.popup_callback = popup_callback
        self.log_callback = log_callback
        self.root = root
        self._stop_event = threading.Event()
        self._pause_event = threading.Event()
        self._last_deep_scan = time.time()
        self._last_hkcu_check = 0
        self._grace_until = time.time() + self.GRACE_PERIOD_SECONDS
        self._grace_logged = False
        self._grace_logged_exts = set()  # 宽限期已报过的扩展名，避免每2秒重复刷屏
        self._handling_exts = set()  # 正在处理的扩展名（关联检测防递归）
        # 持续篡改追踪 + 进程打击
        self.persistent_tracker = PersistentTracker()
        if process_enforcer is not None:
            # 与设置页黑名单管理共享同一实例，避免双份黑名单互不同步
            self.process_enforcer = process_enforcer
        else:
            blacklist_path = os.path.join(USERDATA_DIR, "process_blacklist.json")
            history_path = os.path.join(USERDATA_DIR, "process_blacklist_history.json")
            self.process_enforcer = ProcessEnforcer(blacklist_path, history_path)
        self._persistent_mode = False  # 是否处于持续篡改模式（缩短轮询间隔）
        self._persistent_cooldown_until = 0  # 持续模式冷却到期时间（解锁后保持30秒高速轮询）
        self._last_unlock_check = 0
        self._last_hunt_check = 0
        self._last_lock_stats_log = 0
        self._notify_extra_seconds = 0  # 批量篡改触发后弹窗额外时长（秒）
        self.last_cycle_ts = time.time()  # 监控周期心跳：主线程看门狗据此检测监控线程是否卡死/死亡

    def _verify_hkcu_mapping(self):
        """运行时验证HKCU是否正确映射到用户配置单元，失败则自动重映射。
        TI/SYSTEM下HKCU可能因配置单元卸载/重连而失效，导致保护静默失效。"""
        global HKCU, HKCU_REMAPPED
        if not HKCU_REMAPPED:
            return  # 非TI模式不需要重映射
        try:
            # 验证：读取用户Volatile Environment的USERNAME
            val, _ = reg_read_value(HKCU, "Volatile Environment", "USERNAME")
            if val and len(val) > 0:
                return  # 映射正常
        except Exception:
            pass
        # 映射失效，尝试重映射
        self.log_callback("警告：HKCU映射失效，正在重新映射...", "warn")
        if remap_hkcu_to_interactive_user():
            self.log_callback("HKCU重新映射成功", "success")
        else:
            self.log_callback("HKCU重新映射失败，保护可能失效", "error")

    def stop(self):
        self._stop_event.set()

    def pause(self):
        self._pause_event.set()

    def resume(self):
        self._pause_event.clear()

    def run(self):
        logger.info("监控线程启动")
        while not self._stop_event.is_set():
            self.last_cycle_ts = time.time()  # 心跳：每轮周期更新
            mode = self.baseline.config.get("operation_mode", "normal")
            if mode == "paused":
                self._pause_event.set()
            elif mode in ("quiet", "game", "demo", "silent"):
                self._pause_event.clear()
            if self._pause_event.is_set():
                time.sleep(1)
                continue

            try:
                self._monitor_cycle()
            except Exception as e:
                logger.error(f"监控周期异常: {e}", exc_info=True)

            # 定期深层扫描
            if time.time() - self._last_deep_scan >= DEEP_SCAN_INTERVAL:
                self._deep_scan_cycle()
                self._last_deep_scan = time.time()

            # 自动解锁检查（每5秒，锁定期间更频繁检查）
            if time.time() - self._last_unlock_check >= 5:
                self._auto_unlock_check()
                self._last_unlock_check = time.time()

            # 定期猎杀黑名单进程（每10秒）
            if time.time() - self._last_hunt_check >= 10:
                self._hunt_blacklisted()
                self._last_hunt_check = time.time()

            # 持续篡改模式或高频观察期：缩短轮询间隔到0.5秒
            need_fast = self._persistent_mode or self.persistent_tracker.has_high_freq_exts()
            interval = 0.5 if need_fast else POLL_INTERVAL
            time.sleep(interval)

        # 退出时解锁所有锁定的键
        self._unlock_all()
        logger.info("监控线程停止")

    def _auto_unlock_check(self):
        """检查并自动解锁到期的锁定键"""
        locked_before = len(self.persistent_tracker.get_locked_exts())
        to_unlock = self.persistent_tracker.check_auto_unlock()
        if to_unlock:
            self.log_callback(f"[自动解锁] {len(to_unlock)} 个扩展名锁定到期，正在解锁...", "info")
            log_event("SYSTEM", "自动解锁", "开始", f"{len(to_unlock)}个: {', '.join(to_unlock[:5])}")
        for ext in to_unlock:
            bl = self.engine.baseline.baseline.get(ext, {})
            prog_id = _get_prog_id_from_baseline(bl)
            ok_cnt, total, dets = unlock_all_protected_keys(ext, prog_id)
            status = f"{ok_cnt}/{total}位置" if ok_cnt > 0 else f"失败({dets})"
            self.log_callback(f"  {ext} 全位置解锁{status}，进入10秒高频观察期", "info")
            log_event(ext, "全位置解锁", "自动", status)
        # 如果没有锁定的键了，进入持续模式冷却（30秒后确认无篡改再关闭）
        if not self.persistent_tracker.get_locked_exts():
            if self._persistent_mode and self._persistent_cooldown_until == 0:
                self._persistent_cooldown_until = time.time() + 30
                self.log_callback("持续篡改防护进入冷却期（30秒无篡改后解除）", "info")
            elif self._persistent_mode and time.time() >= self._persistent_cooldown_until:
                self._persistent_mode = False
                self._persistent_cooldown_until = 0
                self.log_callback("持续篡改防护模式已解除", "info")
        else:
            # 还有锁定的键，重置冷却
            self._persistent_cooldown_until = 0
            if locked_before > 0:
                remaining = len(self.persistent_tracker.get_locked_exts())
                log_event("SYSTEM", "锁定巡检", "继续", f"剩余{remaining}个锁定中")

    def _unlock_all(self):
        """退出时解锁所有锁定的键（全部7个位置）"""
        for ext in self.persistent_tracker.get_locked_exts():
            try:
                bl = self.engine.baseline.baseline.get(ext, {})
                prog_id = _get_prog_id_from_baseline(bl)
                unlock_all_protected_keys(ext, prog_id)
            except Exception:
                pass

    def _hunt_blacklisted(self):
        """定期猎杀黑名单进程：找到正在运行的黑名单进程，强终止后拉出黑名单"""
        try:
            blacklist = self.process_enforcer.get_blacklist()
            if not blacklist:
                return  # 黑名单为空，跳过
            self.log_callback(f"[黑名单轮询] 开始猎杀，当前黑名单 {len(blacklist)} 项", "info")
            log_event("PROCESS", "猎杀轮询", "开始", f"黑名单={len(blacklist)}项")
            results = self.process_enforcer.hunt_blacklisted_processes()
            if not results:
                self.log_callback("[黑名单轮询] 未发现运行中的黑名单进程", "info")
                log_event("PROCESS", "猎杀轮询", "无目标", "")
            for name, terminated, method, is_red in results:
                red_tag = "[红名单]" if is_red else ""
                if terminated:
                    self.log_callback(f"[黑名单轮询] 已终止: {name} ({method}){red_tag}", "warn")
                    log_event("PROCESS", "强终止", "成功", f"{name} via {method}{red_tag}")
                else:
                    self.log_callback(f"[黑名单轮询] 终止失败: {name} ({method}){red_tag}", "error")
                    log_event("PROCESS", "强终止", "失败", f"{name} via {method}{red_tag}")
        except Exception as e:
            logger.error(f"猎杀黑名单异常: {e}")
            self.log_callback(f"[黑名单轮询] 异常: {e}", "error")

    def _monitor_cycle(self):
        """常规监控周期：检查所有受保护扩展名"""
        # 每30秒验证一次HKCU映射（TI下可能失效）
        if time.time() - self._last_hkcu_check >= 30:
            self._verify_hkcu_mapping()
            self._last_hkcu_check = time.time()

        # 宽限期：只检测不恢复，给用户备份当前状态的机会
        in_grace = time.time() < self._grace_until
        if in_grace and not self._grace_logged:
            self._grace_logged = True
            remaining = int(self._grace_until - time.time())
            self.log_callback(f"启动宽限期{remaining}秒：仅检测不恢复，如需以当前状态为基准请点击\"备份当前\"")

        exts = self.baseline.get_protected_extensions()
        locked_count = 0
        checked_count = 0
        for ext in exts:
            if self._stop_event.is_set():
                return
            # 锁定中的扩展名：仍需检测（锁定可能不完全成功，如UserChoice键没锁住）
            # 检测到更改则静默恢复，不弹窗
            is_locked = self.persistent_tracker.is_locked(ext)
            if is_locked:
                locked_count += 1
            checked_count += 1
            mismatches = self.engine.check_extension(ext)
            if mismatches:
                if in_grace:
                    # 宽限期：只日志记录，不恢复，每个扩展名只报一次
                    if ext not in self._grace_logged_exts:
                        self._grace_logged_exts.add(ext)
                        detail_parts = []
                        new_progid = None
                        for key, bl_val, cur_val, _ in mismatches[:3]:
                            label = ProtectionEngine.ITEM_LABELS.get(key, key)
                            detail_parts.append(f"{label}({bl_val}->{cur_val})")
                            if key in ("userchoice_progid", "hkcr_ext", "hkcu_ext", "hklm_ext") and cur_val:
                                new_progid = cur_val
                        tamperer = ""
                        if new_progid:
                            name, _ = identify_tamperer(new_progid)
                            if name:
                                tamperer = f" [{name}]"
                        self.log_callback(f"[宽限期] {ext} 检测到不一致: {'; '.join(detail_parts)}{tamperer}（未恢复）")
                elif is_locked:
                    # 锁定中检测到更改：说明锁定不完全生效，静默恢复
                    s, f, dets, verified = self._recover_with_verify(ext, mismatches, max_retries=3)
                    if verified:
                        log_event(ext, "恢复", "成功", "锁定中静默恢复(已验证)")
                    else:
                        log_event(ext, "恢复", "失败", f"锁定中恢复未通过: {';'.join(dets) if dets else '未知'}")
                else:
                    self._handle_change(ext, mismatches)

        # 每10秒输出一次锁定状态统计
        if locked_count > 0 and time.time() - self._last_lock_stats_log >= 10:
            self._last_lock_stats_log = time.time()
            # list() 快照：锁定巡检/恢复流程可能并发修改 _unlocked_exts，
            # 直接迭代会抛 RuntimeError: dictionary changed size during iteration
            high_freq = [e for e in list(self.persistent_tracker._unlocked_exts)
                         if self.persistent_tracker.is_in_high_freq(e)]
            self.log_callback(f"[防护状态] 锁定中:{locked_count} 高频观察:{len(high_freq)} 已检测:{checked_count}", "info")
            log_event("SYSTEM", "防护状态", "统计", f"locked={locked_count}, highfreq={len(high_freq)}, checked={checked_count}")

    def _deep_scan_cycle(self):
        """深层扫描周期"""
        in_grace = time.time() < self._grace_until
        self.log_callback("开始深层扫描...")
        inconsistencies, new_exts = self.engine.deep_scan()
        if inconsistencies:
            # 分离真实篡改和无效关联/缺失项报告
            real_tamper = {}
            report_only = {}
            for ext, mismatches in inconsistencies.items():
                if all(m[0] == "invalid_association" for m in mismatches):
                    report_only[ext] = mismatches
                else:
                    real_tamper[ext] = mismatches
            if report_only:
                self.log_callback(f"深层扫描发现 {len(report_only)} 个无效关联/缺失项（仅报告，不自动恢复，可手动深层扫描查看详情）")
            if real_tamper:
                self.log_callback(f"深层扫描发现 {len(real_tamper)} 个扩展名不一致")
                for ext, mismatches in real_tamper.items():
                    if in_grace:
                        self.log_callback(f"[宽限期] {ext}: {len(mismatches)}项不一致（未恢复）")
                    else:
                        self._handle_change(ext, mismatches)
        if new_exts:
            self.log_callback(f"深层扫描发现 {len(new_exts)} 个可疑新扩展名: {', '.join(new_exts[:10])}")
            for ext in new_exts:
                # 对新扩展名创建基准（纳入保护）
                self.baseline.update_extension(ext)
                self.log_callback(f"已将新扩展名 {ext} 纳入保护")
        if not inconsistencies and not new_exts:
            self.log_callback("深层扫描完成，未发现异常")

    def _recover_with_verify(self, ext, mismatches, max_retries=3):
        """
        执行恢复并多次验证。在0.3s/1.5s/3s三个时间点回读，
        任何一次发现被重写则重试。最多重试 max_retries 次。
        返回 (success, fail, details, verified)
        """
        total_success = 0
        total_fail = 0
        all_details = []
        verified = False
        verify_points = [0.3, 1.5, 3.0]  # 秒

        for attempt in range(max_retries):
            s, f, dets = self.engine.recover_extension(ext, mismatches)
            total_success = s
            total_fail = f
            all_details = dets

            # 刷新系统关联缓存
            refresh_file_associations()

            # 多次时间点验证
            all_passed = True
            for i, wait_sec in enumerate(verify_points):
                time.sleep(wait_sec)
                remaining = self.engine.check_extension(ext)
                # new_progid_command 是伴随合成项（ProgId 恢复后自然失效），
                # 不参与验证判定，避免系统默认程序(如照片AppX)对抗时无限重试刷屏
                remaining_real = [m for m in remaining if m[0] != "new_progid_command"]
                if remaining_real:
                    all_passed = False
                    mismatches = remaining  # 用最新不一致列表重试
                    if attempt < max_retries - 1:
                        log_event(ext, "恢复", f"重试{attempt+1}",
                                  f"{wait_sec}s后仍有{len(remaining_real)}项不一致")
                    break  # 跳出验证循环，进入重试

            if all_passed:
                verified = True
                break

        return total_success, total_fail, all_details, verified

    def _handle_change(self, ext, mismatches):
        """处理检测到的更改：持续篡改判定 → 冷却判断 → 恢复+验证 → 锁定/进程打击 → 通知"""
        # 跳过纯invalid_association（无效关联/缺失项，仅报告，不自动恢复/锁定）
        if mismatches and all(m[0] == "invalid_association" for m in mismatches):
            return
        # 单扩展名锁定优先：锁定表中的扩展名静默强制恢复为锁定应用（不弹窗、不累积持续篡改）
        try:
            _locked = (self.engine.baseline.config or {}).get("locked_defaults", {}) or {}
        except Exception:
            _locked = {}
        if ext in _locked:
            lock_target = _locked[ext]
            s, f, dets, verified = self._recover_with_verify(ext, mismatches)
            if verified:
                log_event(ext, "恢复", "成功", f"锁定强制恢复(锁定目标={lock_target})")
                self.log_callback(f"{ext} 已按锁定目标强制恢复: {lock_target}（锁定中，不弹窗）")
            else:
                log_event(ext, "恢复", "失败", f"锁定恢复未通过: {';'.join(dets) if dets else '未知'}")
                self.log_callback(f"{ext} 锁定强制恢复未通过: {'; '.join(dets) if dets else '未知'}", "warn")
            return
        # 检查是否本周期已同意
        if ext in self.engine.allowed_this_cycle:
            return

        # 关联检测：更改一个扩展名时，检查关联扩展名（如jpg↔jpeg）是否也被更改
        if ext not in self._handling_exts:
            self._handling_exts.add(ext)
            try:
                related_exts = ProtectionEngine.get_related_exts(ext)
                for rel_ext in related_exts:
                    if rel_ext != ext and rel_ext not in self._handling_exts and rel_ext not in self.engine.allowed_this_cycle:
                        rel_mismatches = self.engine.check_extension(rel_ext)
                        if rel_mismatches:
                            self.log_callback(f"[关联检测] {rel_ext} 也被更改，同步处理", "info")
                            self._handle_change(rel_ext, rel_mismatches)
            finally:
                self._handling_exts.discard(ext)

        # === 持续篡改严格判定 ===
        # 先记录之前是否已在持续模式（区分"刚判定"和"已持续"）
        was_persistent = self.persistent_tracker.is_persistent(ext)
        is_persistent, is_batch, cur_progid = self.persistent_tracker.record_change(ext, mismatches)

        # 已在持续模式中的扩展名（之前就是）：静默恢复，不重复触发批量检测/弹窗
        if was_persistent:
            s, f, dets, verified = self._recover_with_verify(ext, mismatches, max_retries=5)
            if verified:
                log_event(ext, "恢复", "成功", "持续模式静默恢复(已验证)")
            else:
                log_event(ext, "恢复", "失败", "持续模式恢复验证未通过")
                enforce_progid = None if (cur_progid and cur_progid.startswith("__")) else cur_progid
                results = self.process_enforcer.enforce(enforce_progid, action="freeze")
                for name, action, ok_action, reason in results:
                    self.log_callback(f"  升级打击: {name} {action}({'成功' if ok_action else '失败'})", "warn")
            return  # 持续模式不弹窗

        # 批量篡改：同一ProgId改多个扩展名 → 强终止进程 + 锁定所有相关扩展名 + 持续模式
        if is_batch and cur_progid:
            batch_exts = self.persistent_tracker.get_batch_exts(cur_progid)
            # 检查用户是否同意过其中任意一个扩展名
            any_allowed = any(e in self.engine.allowed_this_cycle for e in batch_exts)
            if any_allowed:
                self.log_callback(f"批量篡改: {cur_progid} 篡改{len(batch_exts)}个扩展名，但用户已同意其中之一，跳过强制锁定", "info")
                log_event("ALL", "批量篡改", "跳过", f"用户已同意, 分组={cur_progid}")
                # 用户已同意，对所有相关扩展名标记为已同意，跳过本次处理
                for e in batch_exts:
                    self.engine.allowed_this_cycle.add(e)
                return
            else:
                self._persistent_mode = True
                level = self.persistent_tracker.get_lock_level(ext)
                # 虚拟分组ID转友好名称
                batch_label = cur_progid
                if cur_progid == "__open_command_deleted__":
                    batch_label = "打开命令被批量删除"
                elif cur_progid == "__ext_progid_deleted__":
                    batch_label = "扩展名关联被批量删除"
                elif cur_progid.startswith("__"):
                    batch_label = "批量篡改(无ProgId)"
                tamperer = ""
                name = None
                if not cur_progid.startswith("__"):
                    name, _ = identify_tamperer(cur_progid)
                    if name:
                        tamperer = f" [{name}]"
                self.log_callback(f"⚠ 批量篡改: {batch_label} 涉及{len(batch_exts)}个扩展名，BH{level}{tamperer}", "warn")
                log_event("ALL", "批量篡改", "检测到", f"分组={cur_progid}, 扩展名数={len(batch_exts)}, BH{level}" + (f" 篡改者={name}" if name else ""))
                # 进程打击：虚拟分组ID不用于匹配进程，只打击黑名单
                enforce_progid = None if cur_progid.startswith("__") else cur_progid
                results = self.process_enforcer.enforce(enforce_progid, action="untrusted")
                for name, action, ok, reason in results:
                    status = "成功" if ok else "失败"
                    self.log_callback(f"  进程打击: {name} {action}{status}({reason})", "warn")
                    log_event("PROCESS", action, status, f"{name}({reason})")
                # 冻结进程（如果没开persistent_no_kill）
                if not self.baseline.config.get("persistent_no_kill", False):
                    results2 = self.process_enforcer.enforce(enforce_progid, action="freeze")
                    for name, action, ok, reason in results2:
                        status = "成功" if ok else "失败"
                        self.log_callback(f"  进程冻结: {name} {status}({reason})", "warn")
                # 强锁定所有被该ProgId篡改过的扩展名（ACL+System完整性标签）
                lock_count = 0
                for e in batch_exts:
                    self.persistent_tracker.force_persistent(e)
                    if self.persistent_tracker.should_lock(e):
                        # 获取基准中的ProgId用于锁定command键
                        bl = self.engine.baseline.baseline.get(e, {})
                        prog_id = _get_prog_id_from_baseline(bl)
                        ok_cnt, total, dets = lock_all_protected_keys(e, prog_id)
                        if ok_cnt > 0:
                            lock_count += 1
                            self.persistent_tracker.mark_locked(e)
                        log_event(e, "全位置强锁定", f"{ok_cnt}/{total}", f"批量篡改触发, {dets}")
                self.log_callback(f"  批量全位置强锁定: {lock_count}/{len(batch_exts)} 个扩展名(7个位置均锁定)", "info")
                # 弹窗时长+8秒
                self._notify_extra_seconds = 8
                return  # 批量篡改已处理，不继续弹窗

        # 单扩展名持续篡改：先恢复，再锁定注册表键 + 进程打击，静默不弹窗
        # 高频观察期内再次篡改：立即重新锁定（无需再积累3次）
        in_high_freq = self.persistent_tracker.is_in_high_freq(ext)
        if (is_persistent or in_high_freq) and self.persistent_tracker.should_lock(ext):
            self._persistent_mode = True
            level = self.persistent_tracker.get_lock_level(ext)
            reason = "高频观察期内再次篡改" if in_high_freq else "持续篡改"
            tamperer = ""
            name = None
            if cur_progid and not cur_progid.startswith("__"):
                name, _ = identify_tamperer(cur_progid)
                if name:
                    tamperer = f" [{name}]"
            self.log_callback(f"⚠ {ext} {reason}，BH{level}{tamperer}", "warn")
            log_event(ext, "持续篡改", "检测到", f"BH{level}({reason})" + (f" 篡改者={name}" if name else ""))
            # 先恢复被篡改的值
            s, f, dets, verified = self._recover_with_verify(ext, mismatches, max_retries=3)
            if verified:
                log_event(ext, "恢复", "成功", "持续篡改恢复(已验证)")
            else:
                log_event(ext, "恢复", "失败", f"持续篡改恢复未通过: {';'.join(dets) if dets else '未知'}")
            # 强锁定全部7个位置（ACL+System完整性标签）+ 关联扩展名
            bl = self.engine.baseline.baseline.get(ext, {})
            prog_id = _get_prog_id_from_baseline(bl)
            ok_cnt, total, dets = lock_all_protected_keys(ext, prog_id)
            # 关联锁定：jpg↔jpeg等
            related_exts = ProtectionEngine.get_related_exts(ext)
            rel_locked = []
            for rel_ext in related_exts:
                if rel_ext != ext and rel_ext in self.engine.baseline.baseline:
                    rel_bl = self.engine.baseline.baseline.get(rel_ext, {})
                    rel_prog = _get_prog_id_from_baseline(rel_bl)
                    r_ok, r_total, _ = lock_all_protected_keys(rel_ext, rel_prog)
                    if r_ok > 0:
                        self.persistent_tracker.mark_locked(rel_ext)
                        rel_locked.append(f"{rel_ext}({r_ok}/{r_total})")
            lock_status = f"{ok_cnt}/{total}位置" if ok_cnt > 0 else f"失败({dets})"
            rel_info = f" 关联锁定: {', '.join(rel_locked)}" if rel_locked else ""
            self.log_callback(f"  {ext} 全位置强锁定{lock_status}{rel_info}", "info")
            log_event(ext, "全位置强锁定", lock_status + rel_info, dets)
            self.persistent_tracker.mark_locked(ext)
            # 进程打击：Untrusted降权（虚拟分组ID不用于匹配进程）
            enforce_progid = None if (cur_progid and cur_progid.startswith("__")) else cur_progid
            results = self.process_enforcer.enforce(enforce_progid, action="untrusted")
            for name, action, ok_action, reason in results:
                status = "成功" if ok_action else "失败"
                self.log_callback(f"  进程打击: {name} {action}{status}({reason})", "warn")
            return  # 持续篡改静默处理，不弹窗

        # 冷却期内：静默恢复+验证，不弹窗
        if self.engine.is_in_cooldown(ext):
            s, f, dets, verified = self._recover_with_verify(ext, mismatches)
            only_uc = all(k in ("userchoice_progid", "userchoice_hash") for k, _, _, _ in mismatches)
            if verified:
                self.engine.reset_uc_failure(ext)
                log_event(ext, "恢复", "成功", "冷却期静默恢复(已验证)")
            elif only_uc and self.engine.record_uc_failure(ext):
                self.engine.handle_uc_hash_expiry(ext)
                log_event(ext, "恢复", "Hash过期", "冷却期内检测到Hash过期,已回退到系统默认")
                self.log_callback(f"{ext} UserChoice Hash 已过期，已自动回退到系统默认关联")
            else:
                self.engine.clear_cooldown(ext)
                if f == 0:
                    log_event(ext, "恢复", "失败", "冷却期验证未通过,已解除冷却")
                else:
                    log_event(ext, "恢复", "失败", f"冷却期:{';'.join(dets)},已解除冷却")
            return

        # 记录更改细节
        detail_parts = []
        new_progid = None
        for key, bl_val, cur_val, _ in mismatches:
            label = ProtectionEngine.ITEM_LABELS.get(key, key)
            detail_parts.append(f"{label}({bl_val}->{cur_val})")
            if key in ("userchoice_progid", "hkcr_ext", "hkcu_ext", "hklm_ext") and cur_val:
                new_progid = cur_val
        detail_str = "; ".join(detail_parts)
        # 篡改者识别
        tamperer = ""
        name = None
        if new_progid:
            name, conf = identify_tamperer(new_progid)
            if name:
                tamperer = f" [{name}]"
        log_event(ext, "更改", "检测到", detail_str + (f" 篡改者={name}" if name else ""))
        self.log_callback(f"检测到 {ext} 被更改: {detail_str}{tamperer}")

        # 执行恢复+验证（最多3次重试）
        s, f, dets, verified = self._recover_with_verify(ext, mismatches)
        recover_result = (s, f, dets)

        # 检查是否仅 UserChoice 项不一致（可能是 Hash 过期被 Windows 删除）
        only_uc = all(k in ("userchoice_progid", "userchoice_hash") for k, _, _, _ in mismatches)

        if verified:
            self.engine.reset_uc_failure(ext)
            log_event(ext, "恢复", "成功", "默认保护基准(已验证)")
            self.log_callback(f"{ext} 已恢复到基准(已验证) BH1")
            self.engine.set_cooldown(ext)
        elif only_uc and self.engine.record_uc_failure(ext):
            self.engine.handle_uc_hash_expiry(ext)
            log_event(ext, "恢复", "Hash过期", "UserChoice Hash已过期,自动回退到HKCR系统默认关联")
            self.log_callback(f"{ext} UserChoice Hash 已过期，已自动回退到系统默认关联（建议手动重新设置默认程序后更新基准）")
            self.engine.set_cooldown(ext)
        elif f == 0:
            log_event(ext, "恢复", "成功", "默认保护基准(验证未通过,可能被持续篡改)")
            self.log_callback(f"{ext} 已恢复但验证未通过，可能被持续篡改")
        else:
            log_event(ext, "恢复", "失败", f"成功{s}/失败{f}:{';'.join(dets)}")
            self.log_callback(f"{ext} 恢复部分失败: {'; '.join(dets)}")

        # 右下角通知（必须在主线程中执行，Tkinter非线程安全）
        extra = self._notify_extra_seconds
        if extra > 0:
            self._notify_extra_seconds = 0  # 消费一次
        if self.root:
            self.root.after(0, lambda: self.popup_callback(ext, mismatches, recover_result, extra))
        else:
            self.popup_callback(ext, mismatches, recover_result, extra)


# ============================================================
# 注册表ACL强锁定 —— 拒绝Users/Administrators写入，只允许SYSTEM/TI
# ============================================================
def _get_sid_string(sid_string):
    """将SID字符串转为PSID"""
    advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)
    psid = ctypes.c_void_p()
    advapi32.ConvertStringSidToSidW(sid_string, ctypes.byref(psid))
    return psid

def _get_uc_registry_path(ext):
    """获取UserChoice键的正确PowerShell注册表路径。
    TI/SYSTEM下HKCU被重映射到HKEY_USERS\\<SID>，PowerShell的HKCU:指向SYSTEM的.DEFAULT，
    必须用完整路径才能操作正确的键。"""
    uc_path = f"{USERCHOICE_BASE}\\{ext}\\UserChoice"
    if HKCU_REMAPPED:
        sid = getattr(remap_hkcu_to_interactive_user, '_last_sid', None)
        if sid:
            return f"Registry::HKEY_USERS\\{sid}\\{uc_path}"
    return f"HKCU:\\{uc_path}"

def force_delete_userchoice(ext):
    """强制删除UserChoice键，尝试10种方法。返回 (success, method)"""
    uc_path = f"{USERCHOICE_BASE}\\{ext}\\UserChoice"
    reg_path = _get_uc_registry_path(ext)
    # 先检查键是否存在，不存在则无需删除，直接成功
    try:
        kh = winreg.OpenKey(HKCU, uc_path, 0, KEY_READ_64)
        winreg.CloseKey(kh)
    except OSError:
        return True, "键已不存在(无需删除)"
    # 方法1: winreg DeleteKey
    try:
        winreg.DeleteKey(HKCU, uc_path)
        return True, "winreg.DeleteKey"
    except OSError:
        pass
    # 方法2: 用KEY_ALL_ACCESS打开后RegDeleteTree
    try:
        kh = winreg.OpenKey(HKCU, uc_path, 0, KEY_ALL_ACCESS_64)
        winreg.DeleteKey(kh, "")
        winreg.CloseKey(kh)
        return True, "OpenKey+Delete"
    except OSError:
        pass
    # 方法3: PowerShell Remove-Item
    try:
        r = _run(['powershell', '-NoProfile', '-Command',
                           f'Remove-Item -Path "{reg_path}" -Recurse -Force -ErrorAction Stop; Write-Output "OK"'],
                           capture_output=True, text=True, timeout=8)
        if "OK" in r.stdout:
            return True, "PowerShell Remove-Item"
    except Exception:
        pass
    # 方法4: reg.exe delete
    try:
        full_path = f"HKEY_USERS\\{getattr(remap_hkcu_to_interactive_user, '_last_sid', '')}\\{uc_path}" if HKCU_REMAPPED else f"HKCU\\{uc_path}"
        r = _run(['reg', 'delete', full_path, '/f'],
                           capture_output=True, text=True, timeout=8)
        if r.returncode == 0:
            return True, "reg.exe delete"
    except Exception:
        pass
    # 方法5: PowerShell 先TakeOwnership再删除
    try:
        ps = f'''
$path = "{reg_path}"
if (Test-Path $path) {{
    $acl = Get-Acl -Path $path
    $acl.SetAccessRuleProtection($false, $true)
    Set-Acl -Path $path -AclObject $acl
    Remove-Item -Path $path -Recurse -Force -ErrorAction Stop
    Write-Output "OK"
}}
'''
        r = _run(['powershell', '-NoProfile', '-Command', ps],
                           capture_output=True, text=True, timeout=8)
        if "OK" in r.stdout:
            return True, "重置ACL+Remove"
    except Exception:
        pass
    # 方法6: PowerShell Takeown + icacls + del
    try:
        ps2 = f'''
$path = "{reg_path}"
if (Test-Path $path) {{
    takeown /F $path /A /R /D Y 2>$null | Out-Null
    icacls $path /grant "Administrators:F" /T /C 2>$null | Out-Null
    Remove-Item -Path $path -Recurse -Force -ErrorAction Stop
    Write-Output "OK"
}}
'''
        r = _run(['powershell', '-NoProfile', '-Command', ps2],
                           capture_output=True, text=True, timeout=10)
        if "OK" in r.stdout:
            return True, "takeown+icacls+del"
    except Exception:
        pass
    # 方法7: 用winreg删除子键后再删自身
    try:
        with winreg.OpenKey(HKCU, uc_path, 0, KEY_ALL_ACCESS_64) as kh:
            try:
                i = 0
                while True:
                    sub = winreg.EnumKey(kh, i)
                    winreg.DeleteKey(kh, sub)
                    i += 1
            except OSError:
                pass
        winreg.DeleteKey(HKCU, uc_path)
        return True, "枚举子键+删除"
    except OSError:
        pass
    # 方法8: PowerShell [Microsoft.Win32.Registry]::DeleteKey
    try:
        sid = getattr(remap_hkcu_to_interactive_user, '_last_sid', '')
        net_path = f"HKEY_USERS\\{sid}\\{uc_path}" if HKCU_REMAPPED else f"HKEY_CURRENT_USER\\{uc_path}"
        ps3 = f'[Microsoft.Win32.Registry]::LocalMachine.DeleteSubKeyTree("{net_path}", $true); Write-Output "OK"'
        # 注意：用RegistryKey.DeleteSubKeyTree
        ps3 = f'''
$key = [Microsoft.Win32.Registry]::Users.OpenSubKey("{sid}\\{uc_path}", $true)
if ($key) {{ $key.DeleteSubKeyTree("UserChoice", $true); $key.Close(); Write-Output "OK" }}
'''
        r = _run(['powershell', '-NoProfile', '-Command', ps3],
                           capture_output=True, text=True, timeout=8)
        if "OK" in r.stdout:
            return True, ".NET Registry.DeleteSubKeyTree"
    except Exception:
        pass
    # 方法9: 等待500ms后重试winreg（可能是短暂锁）
    try:
        time.sleep(0.5)
        winreg.DeleteKey(HKCU, uc_path)
        return True, "延迟重试winreg"
    except OSError:
        pass
    # 方法10: 最后手段 - PowerShell Set-ItemProperty清空值（不删除键，只清空）
    try:
        ps4 = f'''
$path = "{reg_path}"
if (Test-Path $path) {{
    Remove-ItemProperty -Path $path -Name "ProgId" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $path -Name "Hash" -ErrorAction SilentlyContinue
    Write-Output "OK"
}}
'''
        r = _run(['powershell', '-NoProfile', '-Command', ps4],
                           capture_output=True, text=True, timeout=8)
        if "OK" in r.stdout:
            return True, "清空值(未删键)"
    except Exception:
        pass
    return False, "10种方法均失败"


def lock_userchoice_key(ext):
    """锁定UserChoice注册表键：拒绝Users和Administrators写入，但保留SYSTEM/TI完全控制。
    返回 (success, message)"""
    reg_path = _get_uc_registry_path(ext)
    try:
        ps_cmd = f'''
$ErrorActionPreference = "Stop"
$path = "{reg_path}"
if (Test-Path $path) {{
    $acl = Get-Acl -Path $path
    $acl.SetAccessRuleProtection($true, $false)
    # 移除现有的Users/Administrators/Everyone规则
    $rules = @($acl.Access | Where-Object {{ $_.IdentityReference -match "Users|Administrators|Everyone" }})
    foreach ($r in $rules) {{ $acl.RemoveAccessRule($r) | Out-Null }}
    # 关键：给SYSTEM和TrustedInstaller完全控制（我们自己要能写入/删除）
    $allowSystem = New-Object System.Security.AccessControl.RegistryAccessRule(
        "NT AUTHORITY\\SYSTEM", "FullControl", "ContainerInherit", "None", "Allow")
    $acl.AddAccessRule($allowSystem)
    $allowTI = New-Object System.Security.AccessControl.RegistryAccessRule(
        "NT SERVICE\\TrustedInstaller", "FullControl", "ContainerInherit", "None", "Allow")
    $acl.AddAccessRule($allowTI)
    # 拒绝Users和Administrators写入
    $denyUsers = New-Object System.Security.AccessControl.RegistryAccessRule(
        "BUILTIN\\Users", "SetValue,CreateSubKey,Delete,WriteKey", "ContainerInherit", "None", "Deny")
    $acl.AddAccessRule($denyUsers)
    $denyAdmins = New-Object System.Security.AccessControl.RegistryAccessRule(
        "BUILTIN\\Administrators", "SetValue,CreateSubKey,Delete,WriteKey", "ContainerInherit", "None", "Deny")
    $acl.AddAccessRule($denyAdmins)
    Set-Acl -Path $path -AclObject $acl
    Write-Output "OK"
}} else {{
    Write-Output "NOT_FOUND"
}}
'''
        result = _run(['powershell', '-NoProfile', '-Command', ps_cmd],
                                capture_output=True, text=True, timeout=10)
        output = result.stdout.strip()
        if "OK" in output:
            return True, "已锁定(SYSTEM/TI保留权限)"
        elif "NOT_FOUND" in output:
            return False, "键不存在"
        else:
            return False, f"PowerShell错误: {result.stderr.strip()[:100]}"
    except Exception as e:
        return False, str(e)

def unlock_userchoice_key(ext):
    """解锁UserChoice注册表键，恢复正常权限。多方法尝试。返回 (success, message)"""
    reg_path = _get_uc_registry_path(ext)
    methods = []
    # 方法1: PowerShell Set-Acl 移除Deny规则 + 清除完整性标签
    try:
        ps_cmd = f'''
$ErrorActionPreference = "Stop"
$path = "{reg_path}"
if (Test-Path $path) {{
    $acl = Get-Acl -Path $path
    $acl.SetAccessRuleProtection($false, $true)
    $rules = @($acl.Access | Where-Object {{ $_.AccessControlType -eq "Deny" }})
    foreach ($r in $rules) {{ $acl.RemoveAccessRule($r) | Out-Null }}
    Set-Acl -Path $path -AclObject $acl
    # 清除SACL中的完整性标签（Mandatory Label）
    $sd = Get-Acl -Path $path
    $sddl = $sd.Sddl
    if ($sddl -match "S:\\(ML;[^)]+\\)") {{
        $sddl = $sddl -replace "S:\\(ML;[^)]+\\)", ""
        if ($sddl -match "S:\\(\\s*\\)") {{ $sddl = $sddl -replace "S:\\(\\s*\\)", "" }}
        $sd2 = New-Object System.Security.AccessControl.RegistrySecurity
        $sd2.SetSecurityDescriptorSddlForm($sddl)
        Set-Acl -Path $path -AclObject $sd2
    }}
    Write-Output "OK"
}} else {{
    Write-Output "NOT_FOUND"
}}
'''
        result = _run(['powershell', '-NoProfile', '-Command', ps_cmd],
                                capture_output=True, text=True, timeout=10)
        if "OK" in result.stdout:
            return True, "PowerShell解锁"
        methods.append(f"PS:{result.stderr.strip()[:50] if result.stderr else 'no OK'}")
    except Exception as e:
        methods.append(f"PS异常:{str(e)[:50]}")
    # 方法2: PowerShell 重置继承+清空所有规则
    try:
        ps_cmd2 = f'''
$path = "{reg_path}"
if (Test-Path $path) {{
    $acl = Get-Acl -Path $path
    $acl.SetAccessRuleProtection($false, $false)
    Set-Acl -Path $path -AclObject $acl
    Write-Output "OK2"
}}
'''
        result2 = _run(['powershell', '-NoProfile', '-Command', ps_cmd2],
                                 capture_output=True, text=True, timeout=10)
        if "OK2" in result2.stdout:
            return True, "重置继承解锁"
        methods.append(f"PS2:{result2.stderr.strip()[:50] if result2.stderr else 'no OK'}")
    except Exception as e:
        methods.append(f"PS2异常:{str(e)[:50]}")
    return False, ";".join(methods) if methods else "未知失败"


# ============================================================
# 强防护模块 —— MIC完整性隔离 + 进程降权 + 进程冻结
# ============================================================

# 完整性级别SID
_INTEGRITY_SIDS = {
    "untrusted": "S-1-16-0",
    "low": "S-1-16-4096",
    "medium": "S-1-16-8192",
    "high": "S-1-16-12288",
    "system": "S-1-16-16384",
}
_TOKEN_INTEGRITY_LEVEL = 25  # TOKEN_INFORMATION_CLASS
_SE_GROUP_INTEGRITY = 0x00000020
_PROCESS_QUERY_INFORMATION = 0x0400
_TOKEN_ADJUST_DEFAULT = 0x0080
_TOKEN_QUERY = 0x0008


class _TOKEN_MANDATORY_LABEL(ctypes.Structure):
    _fields_ = [("Label", _SID_AND_ATTRIBUTES)]


def _get_sid_ptr(sid_string):
    """将SID字符串转换为PSID，返回(指针, 需释放的内存)"""
    sid_ptr = ctypes.c_void_p()
    if not ctypes.windll.advapi32.ConvertStringSidToSidW(ctypes.c_wchar_p(sid_string), ctypes.byref(sid_ptr)):
        return None, None
    return sid_ptr, sid_ptr


def lower_process_integrity(pid, level="untrusted"):
    """将目标进程的完整性级别降为指定级别（默认Untrusted）。
    Untrusted进程几乎无法写任何系统资源。
    返回 (success, message)"""
    sid_str = _INTEGRITY_SIDS.get(level)
    if not sid_str:
        return False, f"未知级别: {level}"
    hProcess = ctypes.windll.kernel32.OpenProcess(_PROCESS_QUERY_INFORMATION, False, pid)
    if not hProcess:
        return False, f"OpenProcess失败: {ctypes.get_last_error()}"
    try:
        hToken = ctypes.c_void_p()
        if not ctypes.windll.advapi32.OpenProcessToken(hProcess, _TOKEN_ADJUST_DEFAULT | _TOKEN_QUERY, ctypes.byref(hToken)):
            return False, f"OpenProcessToken失败: {ctypes.get_last_error()}"
        try:
            sid_ptr, _ = _get_sid_ptr(sid_str)
            if not sid_ptr:
                return False, "ConvertStringSidToSid失败"
            tml = _TOKEN_MANDATORY_LABEL()
            tml.Label.Sid = sid_ptr
            tml.Label.Attributes = _SE_GROUP_INTEGRITY
            ret = ctypes.windll.advapi32.SetTokenInformation(
                hToken, _TOKEN_INTEGRITY_LEVEL, ctypes.byref(tml), ctypes.sizeof(tml))
            ctypes.windll.kernel32.LocalFree(sid_ptr)
            if ret:
                return True, f"已降为{level}完整性"
            else:
                return False, f"SetTokenInformation失败: {ctypes.get_last_error()}"
        finally:
            ctypes.windll.kernel32.CloseHandle(hToken)
    finally:
        ctypes.windll.kernel32.CloseHandle(hProcess)


def suspend_process(pid):
    """挂起进程所有线程（NtSuspendProcess）。进程活着但完全冻结。
    返回 (success, message)"""
    hProcess = ctypes.windll.kernel32.OpenProcess(0x0001 | 0x0002, False, pid)  # PROCESS_TERMINATE|PROCESS_SUSPEND_RESUME
    if not hProcess:
        return False, f"OpenProcess失败: {ctypes.get_last_error()}"
    try:
        nt_status = ctypes.windll.ntdll.NtSuspendProcess(hProcess)
        if nt_status == 0:
            return True, "进程已冻结(所有线程挂起)"
        else:
            return False, f"NtSuspendProcess失败: 0x{nt_status:08X}"
    finally:
        ctypes.windll.kernel32.CloseHandle(hProcess)


def resume_process(pid):
    """恢复被挂起的进程。返回 (success, message)"""
    hProcess = ctypes.windll.kernel32.OpenProcess(0x0001 | 0x0002, False, pid)
    if not hProcess:
        return False, f"OpenProcess失败: {ctypes.get_last_error()}"
    try:
        nt_status = ctypes.windll.ntdll.NtResumeProcess(hProcess)
        if nt_status == 0:
            return True, "进程已恢复"
        else:
            return False, f"NtResumeProcess失败: 0x{nt_status:08X}"
    finally:
        ctypes.windll.kernel32.CloseHandle(hProcess)


def set_registry_integrity_label(reg_path, level="system"):
    """给注册表键设置完整性标签（SACL中的SYSTEM_MANDATORY_LABEL_ACE）。
    level: untrusted/low/medium/high/system
    Medium及以下进程无法写入更高完整性的键。
    返回 (success, message)"""
    sid_str = _INTEGRITY_SIDS.get(level)
    if not sid_str:
        return False, f"未知级别: {level}"
    # 用PowerShell设置（最可靠）
    ps_cmd = rf'''
$ErrorActionPreference = "Stop"
$path = "{reg_path}"
if (Test-Path $path) {{
    $acl = Get-Acl -Path $path -Audit
    $sid = New-Object System.Security.Principal.SecurityIdentifier("{sid_str}")
    $rule = New-Object System.Security.AccessControl.RegistryAuditRule(
        $sid, "ChangePermissions", "ContainerInherit", "None", "Success")
    try {{ $acl.RemoveAuditRule($rule) | Out-Null }} catch {{}}
    # 设置完整性标签需要直接操作SDDL
    $sd = Get-Acl -Path $path
    $sddl = $sd.Sddl
    # 替换或添加SACL中的完整性标签
    if ($sddl -match "S:\(ML;[^)]+\)") {{
        $sddl = $sddl -replace "S:\(ML;[^)]+\)", "S:(ML;;NW;;;{0})" -f $sid.Value
    }} else {{
        if ($sddl -match "S:") {{
            $sddl = $sddl -replace "S:", "S:(ML;;NW;;;{0})" -f $sid.Value
        }} else {{
            $sddl = $sddl + "S:(ML;;NW;;;{0})" -f $sid.Value
        }}
    }}
    $sd2 = New-Object System.Security.AccessControl.RegistrySecurity
    $sd2.SetSecurityDescriptorSddlForm($sddl)
    Set-Acl -Path $path -AclObject $sd2
    Write-Output "OK"
}} else {{
    Write-Output "NOT_FOUND"
}}
'''
    try:
        result = _run(['powershell', '-NoProfile', '-Command', ps_cmd],
                                capture_output=True, text=True, timeout=10)
        if "OK" in result.stdout:
            return True, f"完整性标签已设为{level}"
        elif "NOT_FOUND" in result.stdout:
            return False, "键不存在"
        else:
            return False, f"PS错误: {result.stderr.strip()[:100]}"
    except Exception as e:
        return False, str(e)


def lock_userchoice_strong(ext):
    """强锁定：ACL仅SYSTEM/TI + System完整性标签。
    返回 (success, message)"""
    reg_path = _get_uc_registry_path(ext)
    # 第一步：ACL强锁定
    ok1, msg1 = lock_userchoice_key(ext)
    # 第二步：设置System完整性标签
    ok2, msg2 = set_registry_integrity_label(reg_path, "system")
    if ok1 and ok2:
        return True, "强锁定(ACL+System完整性)"
    elif ok1:
        return True, f"ACL锁定成功, 完整性标签失败({msg2})"
    elif ok2:
        return True, f"完整性标签成功, ACL锁定失败({msg1})"
    else:
        return False, f"均失败: {msg1}; {msg2}"


def _get_all_protected_reg_paths(ext, prog_id=None):
    """获取扩展名所有7个保护位置的注册表键路径（PowerShell格式）。
    返回 [(key_name, reg_path), ...]"""
    if prog_id is None:
        prog_id = get_prog_id(ext)
    paths = []
    # 1. HKCR\.ext
    paths.append(("hkcr_ext", f"Registry::HKEY_CLASSES_ROOT\\{ext}"))
    # 2. HKCU\Software\Classes\.ext
    if HKCU_REMAPPED:
        sid = getattr(remap_hkcu_to_interactive_user, '_last_sid', None)
        if sid:
            paths.append(("hkcu_ext", f"Registry::HKEY_USERS\\{sid}\\Software\\Classes\\{ext}"))
        else:
            paths.append(("hkcu_ext", f"HKCU:\\Software\\Classes\\{ext}"))
    else:
        paths.append(("hkcu_ext", f"HKCU:\\Software\\Classes\\{ext}"))
    # 3. HKLM\SOFTWARE\Classes\.ext
    paths.append(("hklm_ext", "Registry::HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\" + ext))
    # 4. UserChoice键（含ProgId和Hash）
    paths.append(("userchoice", _get_uc_registry_path(ext)))
    # 5. HKCR\{ProgId}\shell\open\command + HKCU + HKLM（HKCR是合并视图，三个物理路径都锁）
    if prog_id:
        paths.append(("hkcr_command", f"Registry::HKEY_CLASSES_ROOT\\{prog_id}\\shell\\open\\command"))
        # 6. HKCU\Software\Classes\{ProgId}\shell\open\command
        if HKCU_REMAPPED:
            sid = getattr(remap_hkcu_to_interactive_user, '_last_sid', None)
            if sid:
                paths.append(("hkcu_command", f"Registry::HKEY_USERS\\{sid}\\Software\\Classes\\{prog_id}\\shell\\open\\command"))
            else:
                paths.append(("hkcu_command", f"HKCU:\\Software\\Classes\\{prog_id}\\shell\\open\\command"))
        else:
            paths.append(("hkcu_command", f"HKCU:\\Software\\Classes\\{prog_id}\\shell\\open\\command"))
        # 7. HKLM\SOFTWARE\Classes\{ProgId}\shell\open\command（HKCR合并视图的另一物理路径）
        paths.append(("hklm_command", f"Registry::HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\{prog_id}\\shell\\open\\command"))
    return paths


def _get_prog_id_from_baseline(bl):
    """从基准中获取ProgId，检查所有4个可能的位置（hkcr/hkcu/hklm/userchoice）。
    优先级：userchoice > hkcu > hkcr > hklm（与get_prog_id一致）"""
    if not bl:
        return None
    for key in ("userchoice_progid", "hkcu_ext", "hkcr_ext", "hklm_ext"):
        val = bl.get(key, {}).get("value")
        if val:
            return val
    return None


def _parse_ps_reg_path(ps_path):
    """将PowerShell注册表路径解析为 (root_handle, sub_key) 用于ctypes操作。
    支持 Registry::HKEY_xxx/path 和 HKxx:/path 格式"""
    import winreg
    ps_path = ps_path.strip()
    if ps_path.startswith("Registry::"):
        rest = ps_path[len("Registry::"):]
        if rest.startswith("HKEY_CLASSES_ROOT\\"):
            return winreg.HKEY_CLASSES_ROOT, rest[len("HKEY_CLASSES_ROOT\\"):]
        elif rest.startswith("HKEY_CURRENT_USER\\"):
            return HKCU, rest[len("HKEY_CURRENT_USER\\"):]
        elif rest.startswith("HKEY_LOCAL_MACHINE\\"):
            return winreg.HKEY_LOCAL_MACHINE, rest[len("HKEY_LOCAL_MACHINE\\"):]
        elif rest.startswith("HKEY_USERS\\"):
            return winreg.HKEY_USERS, rest[len("HKEY_USERS\\"):]
    elif ps_path.startswith("HKCU:\\"):
        return HKCU, ps_path[len("HKCU:\\"):]
    elif ps_path.startswith("HKLM:\\"):
        return winreg.HKEY_LOCAL_MACHINE, ps_path[len("HKLM:\\"):]
    elif ps_path.startswith("HKCR:\\"):
        return winreg.HKEY_CLASSES_ROOT, ps_path[len("HKCR:\\"):]
    return None, None


def lock_all_protected_keys(ext, prog_id=None):
    """强锁定扩展名所有7个保护位置（ACL仅SYSTEM/TI + System完整性标签）。
    使用ctypes直接设置ACL，不依赖PowerShell。
    返回 (success_count, total, details)"""
    paths = _get_all_protected_reg_paths(ext, prog_id)
    success = 0
    details = []
    for key_name, reg_path in paths:
        root, sub_key = _parse_ps_reg_path(reg_path)
        if root is None:
            details.append(f"{key_name}:PATH_PARSE_FAIL")
            continue
        ok, msg = set_registry_acl_ctypes(root, sub_key, lock=True)
        if ok:
            success += 1
            details.append(f"{key_name}:OK")
        else:
            details.append(f"{key_name}:{msg[:40]}")
    return success, len(paths), "; ".join(details)



def unlock_all_protected_keys(ext, prog_id=None):
    """解锁扩展名所有7个保护位置（清除ACL限制+完整性标签）。
    使用ctypes直接设置ACL。
    返回 (success_count, total, details)"""
    paths = _get_all_protected_reg_paths(ext, prog_id)
    success = 0
    details = []
    for key_name, reg_path in paths:
        root, sub_key = _parse_ps_reg_path(reg_path)
        if root is None:
            details.append(f"{key_name}:PATH_PARSE_FAIL")
            continue
        ok, msg = set_registry_acl_ctypes(root, sub_key, lock=False)
        if ok:
            success += 1
            details.append(f"{key_name}:OK")
        else:
            details.append(f"{key_name}:{msg[:40]}")
    return success, len(paths), "; ".join(details)



# ============================================================
# 持续篡改追踪器 —— 严格判定
# ============================================================
class PersistentTracker:
    """严格追踪持续篡改：
    - 同一扩展名20秒内被改到非基准值≥3次 → 单扩展名持续篡改
    - 同一ProgId在60秒内篡改≥5个不同扩展名 → 批量篡改
    - 判定后立即锁定注册表键 + 静默恢复 + 进程打击
    """
    SINGLE_WINDOW = 20      # 单扩展名判定窗口(秒)
    SINGLE_THRESHOLD = 2    # 单扩展名阈值（2次触发持续篡改）
    BATCH_WINDOW = 60       # 批量篡改判定窗口(秒)
    BATCH_THRESHOLD = 8     # 批量篡改扩展名数阈值（8个即触发）
    LOCK_DURATION_1 = 60    # 第1-2次锁定时长(秒)，延长避免频繁解锁
    LOCK_DURATION_2 = 300   # 第3次及以后锁定时长(秒)，5分钟
    HIGH_FREQ_DURATION = 20  # 解锁后高频观察期(秒)，延长

    def __init__(self):
        self._ext_history = {}   # ext -> [(timestamp, progid), ...]
        self._progid_history = {}  # progid -> [(timestamp, ext), ...]
        self._locked_exts = {}   # ext -> lock_until_time
        self._unlocked_exts = {}  # ext -> unlock_time (刚解锁，高频观察)
        self._persistent_exts = set()  # 已判定持续篡改的扩展名
        self._batch_progids = set()    # 已判定批量篡改的ProgId
        self._lock_count = {}    # ext -> 累计锁定次数

    def record_change(self, ext, mismatches):
        """记录一次更改，返回 (is_persistent, is_batch, progid)
        progid可能为真实ProgId，或虚拟分组ID（如__open_command_deleted__）"""
        now = time.time()
        # 过滤"无效关联/命令缺失"类检测项：属于关联完整性报告，不算篡改。
        # 若不过滤，单个软件的命令缺失会在多扩展名间级联，被误判为"批量篡改"并锁键。
        mismatches = [m for m in mismatches if m[0] != "invalid_association"]
        if not mismatches:
            return False, False, None
        # 提取当前被改到的ProgId
        cur_progid = None
        for key, bl_val, cur_val, _ in mismatches:
            if key == "userchoice_progid" and cur_val:
                cur_progid = cur_val
                break
        if not cur_progid:
            for key, bl_val, cur_val, _ in mismatches:
                if key in ("hkcu_ext", "hkcr_ext") and cur_val:
                    cur_progid = cur_val
                    break
        # 无ProgId时，按篡改类型生成虚拟分组ID（支持批量检测）
        if not cur_progid:
            for key, bl_val, cur_val, _ in mismatches:
                if key in ("hkcr_command", "hkcu_command") and not cur_val:
                    cur_progid = "__open_command_deleted__"
                    break
                if key in ("hkcr_ext", "hkcu_ext", "hklm_ext") and not cur_val:
                    cur_progid = "__ext_progid_deleted__"
                    break
            if not cur_progid:
                # 其他无ProgId篡改，用第一个mismatch的key作为分组
                if mismatches:
                    cur_progid = f"__{mismatches[0][0]}_changed__"

        # 记录单扩展名历史
        if ext not in self._ext_history:
            self._ext_history[ext] = []
        self._ext_history[ext].append((now, cur_progid))
        # 清理过期记录
        self._ext_history[ext] = [(t, p) for t, p in self._ext_history[ext]
                                   if now - t <= self.SINGLE_WINDOW]

        # 记录ProgId/分组历史
        if cur_progid:
            if cur_progid not in self._progid_history:
                self._progid_history[cur_progid] = []
            self._progid_history[cur_progid].append((now, ext))
            self._progid_history[cur_progid] = [(t, e) for t, e in self._progid_history[cur_progid]
                                                 if now - t <= self.BATCH_WINDOW]

        # 严格判定1：单扩展名持续篡改
        is_persistent = len(self._ext_history[ext]) >= self.SINGLE_THRESHOLD
        if is_persistent:
            self._persistent_exts.add(ext)

        # 严格判定2：批量篡改（同一ProgId/分组改多个扩展名）
        is_batch = False
        if cur_progid:
            unique_exts = set(e for _, e in self._progid_history.get(cur_progid, []))
            if len(unique_exts) >= self.BATCH_THRESHOLD:
                is_batch = True
                self._batch_progids.add(cur_progid)

        return is_persistent, is_batch, cur_progid

    def is_persistent(self, ext):
        return ext in self._persistent_exts

    def clear_ext_history(self, ext):
        """用户同意后清除该扩展名的篡改历史，避免同意后立即触发持续篡改"""
        if ext in self._ext_history:
            del self._ext_history[ext]
        self._persistent_exts.discard(ext)
        # 同时从_progid_history中移除该扩展名的记录
        for progid, records in list(self._progid_history.items()):
            self._progid_history[progid] = [(t, e) for t, e in records if e != ext]
            if not self._progid_history[progid]:
                del self._progid_history[progid]

    def force_persistent(self, ext):
        """强制标记为持续篡改（批量篡改时使用，无需积累3次）"""
        self._persistent_exts.add(ext)

    def get_batch_exts(self, progid):
        """返回被某ProgId篡改过的所有扩展名（去重）"""
        if not progid:
            return []
        return list(set(e for _, e in self._progid_history.get(progid, [])))

    def should_lock(self, ext):
        """是否应该锁定该扩展名的注册表键（未锁定或旧锁已过期）"""
        if ext not in self._persistent_exts:
            return False
        lock_until = self._locked_exts.get(ext)
        if lock_until is None:
            return True  # 从未锁定过
        return time.time() >= lock_until  # 旧锁已过期，可以重新锁定

    def mark_locked(self, ext):
        """标记为已锁定，根据锁定次数决定时长（第1-2次25秒，第3次起60秒）"""
        count = self._lock_count.get(ext, 0)
        self._lock_count[ext] = count + 1
        duration = self.LOCK_DURATION_2 if count >= 2 else self.LOCK_DURATION_1
        self._locked_exts[ext] = time.time() + duration

    def get_lock_level(self, ext):
        """返回保护强度级别（基于锁定次数，反映实际采取的措施）：
        count=0 → BH3（首次锁定: ACL+System完整性标签）
        count=1 → BH4（第二次: +进程降为Untrusted）
        count>=2 → BH5（第三次+: +NtSuspendProcess全冻结）"""
        count = self._lock_count.get(ext, 0)
        if count >= 2:
            return 5
        elif count >= 1:
            return 4
        else:
            return 3

    def is_locked(self, ext):
        """检查是否在锁定期内"""
        lock_until = self._locked_exts.get(ext)
        if lock_until is None:
            return False
        if time.time() >= lock_until:
            return False
        return True

    def is_in_high_freq(self, ext):
        """检查是否在刚解锁的高频观察期内"""
        unlock_time = self._unlocked_exts.get(ext)
        if unlock_time is None:
            return False
        if time.time() - unlock_time > self.HIGH_FREQ_DURATION:
            del self._unlocked_exts[ext]
            return False
        return True

    def has_high_freq_exts(self):
        """是否有扩展名处于高频观察期"""
        now = time.time()
        for ext, t in list(self._unlocked_exts.items()):
            if now - t <= self.HIGH_FREQ_DURATION:
                return True
        return False

    def check_auto_unlock(self):
        """检查到期的锁定键，返回需要解锁的扩展名列表"""
        now = time.time()
        to_unlock = []
        for ext, lock_until in list(self._locked_exts.items()):
            if now >= lock_until:
                to_unlock.append(ext)
                del self._locked_exts[ext]
                self._persistent_exts.discard(ext)
                self._unlocked_exts[ext] = now  # 进入高频观察期
        return to_unlock

    def get_locked_exts(self):
        return [ext for ext in self._locked_exts if self.is_locked(ext)]

    def get_batch_progids(self):
        return list(self._batch_progids)


# ============================================================
# 进程打击器 —— 检测嫌疑进程并降权/挂起/强终止/拉黑/红名单
# ============================================================
class ProcessEnforcer:
    """检测篡改关联的嫌疑进程，进行降权、挂起、强终止、拉黑。
    策略：
    - 不做宽泛关键词匹配（避免误杀正常软件）
    - 根据被篡改的ProgId精准提取软件名，只匹配直接相关进程
    - 黑名单进程（用户确认/多次关联）→ 强终止
    - 同一进程被关联≥3次篡改 → 拉入黑名单
    - 黑名单进程再次出现 → 多方式强终止，终止后拉出黑名单（记录历史）
    - 同一进程被拉黑超过10次 → 标记红名单（暂不执行，仅记录）
    """
    # ProgId关键词映射：ProgId片段 -> 进程路径关键词（精准匹配，不误杀）
    PROGID_KEYWORD_MAP = {
        "baidunetdisk": "baidunetdisk",
        "baidunetdiskimageviewer": "baidunetdisk",
        "vscode": "vscode",
        "potplayer": "potplayer",
        "xmp": "xmp",
        "thunder": "thunder",
        "qqplayer": "qqplayer",
        "kmplayer": "kmplayer",
        "gom": "gom",
        "vlc": "vlc",
        "mumu": "mumu",
        "nox": "nox",
        "bluestacks": "bluestacks",
        "msedge": "msedge",
        "chrome": "chrome",
        "firefox": "firefox",
    }
    REDLIST_THRESHOLD = 10  # 拉黑超过此次数 → 红名单

    def __init__(self, blacklist_file=None, history_file=None):
        self._blacklist = set()       # 当前黑名单（进程路径）
        self._redlist = set()         # 红名单（永久标记，暂不执行）
        self._blacklist_history = {}  # 进程路径 -> 累计被拉黑次数
        self._suspect_count = {}      # 进程路径 -> 关联篡改次数
        self._blacklist_file = blacklist_file
        self._history_file = history_file or (blacklist_file.replace(".json", "_history.json") if blacklist_file else None)
        # 加载黑名单
        if blacklist_file and os.path.exists(blacklist_file):
            try:
                with open(blacklist_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        self._blacklist = set(data.get("blacklist", []))
                        self._redlist = set(data.get("redlist", []))
                    else:
                        self._blacklist = set(data)
            except Exception:
                pass
        # 加载历史
        if self._history_file and os.path.exists(self._history_file):
            try:
                with open(self._history_file, 'r', encoding='utf-8') as f:
                    self._blacklist_history = json.load(f)
            except Exception:
                pass

    def _save(self):
        """保存黑名单+红名单+历史"""
        if self._blacklist_file:
            try:
                with open(self._blacklist_file, 'w', encoding='utf-8') as f:
                    json.dump({"blacklist": list(self._blacklist),
                               "redlist": list(self._redlist)}, f, ensure_ascii=False, indent=2)
            except Exception:
                pass
        if self._history_file:
            try:
                with open(self._history_file, 'w', encoding='utf-8') as f:
                    json.dump(self._blacklist_history, f, ensure_ascii=False, indent=2)
            except Exception:
                pass

    def enumerate_processes(self):
        """枚举所有进程，返回 [(pid, name, path, create_time), ...]"""
        procs = []
        try:
            import ctypes
            from ctypes import wintypes
            kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
            psapi = ctypes.WinDLL('psapi', use_last_error=True)

            class PROCESSENTRY32W(ctypes.Structure):
                _fields_ = [
                    ("dwSize", wintypes.DWORD),
                    ("cntUsage", wintypes.DWORD),
                    ("th32ProcessID", wintypes.DWORD),
                    ("th32DefaultHeapID", ctypes.c_void_p),
                    ("th32ModuleID", wintypes.DWORD),
                    ("cntThreads", wintypes.DWORD),
                    ("th32ParentProcessID", wintypes.DWORD),
                    ("pcPriClassBase", ctypes.c_long),
                    ("dwFlags", wintypes.DWORD),
                    ("szExeFile", ctypes.c_wchar * 260),
                ]

            snapshot = kernel32.CreateToolhelp32Snapshot(0x00000002, 0)
            if snapshot == -1:
                return procs
            entry = PROCESSENTRY32W()
            entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
            if kernel32.Process32FirstW(snapshot, ctypes.byref(entry)):
                while True:
                    pid = entry.th32ProcessID
                    name = entry.szExeFile
                    path = ""
                    try:
                        hproc = kernel32.OpenProcess(0x0400 | 0x0010, False, pid)
                        if hproc:
                            buf = ctypes.create_unicode_buffer(260)
                            size = wintypes.DWORD(260)
                            if psapi.GetModuleFileNameExW(hproc, None, buf, ctypes.byref(size)):
                                path = buf.value
                            kernel32.CloseHandle(hproc)
                    except Exception:
                        pass
                    procs.append((pid, name, path, 0))
                    if not kernel32.Process32NextW(snapshot, ctypes.byref(entry)):
                        break
            kernel32.CloseHandle(snapshot)
        except Exception:
            pass
        return procs

    def _progid_to_keywords(self, progid):
        """从ProgId提取可能的进程路径关键词。返回关键词列表。"""
        if not progid:
            return []
        progid_lower = progid.lower()
        keywords = set()
        # 精确映射
        for progid_key, path_key in self.PROGID_KEYWORD_MAP.items():
            if progid_key in progid_lower:
                keywords.add(path_key)
        # 启发式：ProgId通常是 "软件名.扩展名" 格式，取点号前的部分
        if "." in progid:
            prefix = progid.split(".")[0].lower()
            # 去掉常见后缀
            for suffix in ("associations", "file", "document", "image", "audio", "video"):
                if prefix.endswith(suffix):
                    prefix = prefix[:-len(suffix)]
            if len(prefix) >= 3:
                keywords.add(prefix)
        return list(keywords)

    def find_suspects(self, progid=None):
        """找出嫌疑进程：
        1. 黑名单中的进程（用户确认的）
        2. 与被篡改ProgId直接相关的进程（精准匹配，不误杀）
        不做宽泛关键词匹配。返回 [(pid, name, path, reason), ...]
        """
        suspects = []
        procs = self.enumerate_processes()
        # 从ProgId提取关键词
        progid_keywords = self._progid_to_keywords(progid) if progid else []

        for pid, name, path, _ in procs:
            name_lower = name.lower()
            path_lower = path.lower()
            # 黑名单进程：始终打击
            if path in self._blacklist or name_lower in self._blacklist:
                suspects.append((pid, name, path, "黑名单"))
                continue
            # 只有传入了progid且能提取到关键词时才匹配
            if progid_keywords:
                for kw in progid_keywords:
                    if kw in path_lower or kw in name_lower:
                        suspects.append((pid, name, path, f"ProgId关联({kw})"))
                        break
        return suspects

    def record_suspect(self, path):
        """记录嫌疑进程关联篡改次数，达到阈值拉黑。返回 (newly_blacklisted, is_redlist)"""
        if not path:
            return False, False
        self._suspect_count[path] = self._suspect_count.get(path, 0) + 1
        newly = False
        is_red = False
        if self._suspect_count[path] >= 3 and path not in self._blacklist:
            self._blacklist.add(path)
            newly = True
            # 记录拉黑历史
            self._blacklist_history[path] = self._blacklist_history.get(path, 0) + 1
            if self._blacklist_history[path] >= self.REDLIST_THRESHOLD:
                self._redlist.add(path)
                is_red = True
            self._save()
        return newly, is_red

    def lower_priority(self, pid):
        try:
            kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
            hproc = kernel32.OpenProcess(0x0200, False, pid)
            if hproc:
                kernel32.SetPriorityClass(hproc, 0x00000040)
                kernel32.CloseHandle(hproc)
                return True
        except Exception:
            pass
        return False

    def suspend_process(self, pid):
        try:
            kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
            ntdll = ctypes.WinDLL('ntdll', use_last_error=True)
            hproc = kernel32.OpenProcess(0x0002, False, pid)
            if hproc:
                ntdll.NtSuspendProcess(hproc)
                kernel32.CloseHandle(hproc)
                return True
        except Exception:
            pass
        return False

    def terminate_process(self, pid):
        try:
            kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
            hproc = kernel32.OpenProcess(0x0001, False, pid)
            if hproc:
                kernel32.TerminateProcess(hproc, 1)
                kernel32.CloseHandle(hproc)
                return True
        except Exception:
            pass
        return False

    def terminate_with_extreme_prejudice(self, pid, name=""):
        """多方式强终止进程：ctypes → taskkill → wmic → 再次确认。
        返回 (terminated, method)"""
        # 方法1: ctypes TerminateProcess
        if self.terminate_process(pid):
            time.sleep(0.3)
            if not self._is_process_alive(pid):
                return True, "TerminateProcess"
        # 方法2: taskkill /F /PID
        try:
            _run(['taskkill', '/F', '/PID', str(pid), '/T'],
                           capture_output=True, timeout=5)
            time.sleep(0.3)
            if not self._is_process_alive(pid):
                return True, "taskkill"
        except Exception:
            pass
        # 方法3: wmic process delete
        try:
            _run(['wmic', 'process', 'where', f'ProcessId={pid}', 'delete'],
                           capture_output=True, timeout=5)
            time.sleep(0.3)
            if not self._is_process_alive(pid):
                return True, "wmic"
        except Exception:
            pass
        # 方法4: PowerShell Stop-Process
        try:
            _run(['powershell', '-NoProfile', '-Command',
                           f'Stop-Process -Id {pid} -Force -ErrorAction SilentlyContinue'],
                           capture_output=True, timeout=5)
            time.sleep(0.3)
            if not self._is_process_alive(pid):
                return True, "PowerShell"
        except Exception:
            pass
        return False, "全部失败"

    def _is_process_alive(self, pid):
        """检查进程是否还在运行（用WaitForSingleObject判断，OpenProcess对已终止进程也会成功）"""
        try:
            kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
            hproc = kernel32.OpenProcess(0x1000, False, pid)  # SYNCHRONIZE
            if hproc:
                # WAIT_OBJECT_0=0 表示进程已终止，WAIT_TIMEOUT=258 表示仍在运行
                ret = kernel32.WaitForSingleObject(hproc, 0)
                kernel32.CloseHandle(hproc)
                return ret == 258  # 258=WAIT_TIMEOUT → 还活着
        except Exception:
            pass
        return False

    def hunt_blacklisted_processes(self):
        """猎杀黑名单进程：找到正在运行的黑名单进程，强终止后拉出黑名单。
        返回 [(name, terminated, method, is_redlist), ...]"""
        results = []
        procs = self.enumerate_processes()
        for pid, name, path, _ in procs:
            name_lower = name.lower()
            is_blacklisted = path in self._blacklist or name_lower in self._blacklist
            if not is_blacklisted:
                continue
            # 跳过系统关键进程
            if name_lower in ("system", "registry", "smss.exe", "csrss.exe",
                              "wininit.exe", "services.exe", "lsass.exe",
                              "svchost.exe", "explorer.exe"):
                continue
            # 强终止
            terminated, method = self.terminate_with_extreme_prejudice(pid, name)
            is_red = path in self._redlist or name_lower in self._redlist
            if terminated:
                # 终止成功，从当前黑名单移除（进程已结束），历史保留
                self._blacklist.discard(path)
                self._blacklist.discard(name_lower)
                self._save()
            results.append((name, terminated, method, is_red))
        return results

    def enforce(self, progid=None, action="lower"):
        """对嫌疑进程执行打击。action: lower/suspend/terminate/untrusted/freeze
        untrusted=降为Untrusted完整性, freeze=NtSuspendProcess全冻结
        返回 处理的进程列表"""
        # 先猎杀黑名单进程
        hunt_results = self.hunt_blacklisted_processes()
        results = [(n, "强终止", ok, f"{m}{'[红名单]' if red else ''}")
                   for n, ok, m, red in hunt_results]

        suspects = self.find_suspects(progid)
        for pid, name, path, reason in suspects:
            if name.lower() in ("system", "registry", "smss.exe", "csrss.exe",
                                "wininit.exe", "services.exe", "lsass.exe",
                                "svchost.exe", "explorer.exe"):
                continue
            newly_blacklisted, is_red = self.record_suspect(path)
            if action == "lower":
                ok = self.lower_priority(pid)
                results.append((name, "降权", ok, reason))
            elif action == "suspend":
                ok = self.suspend_process(pid)
                results.append((name, "挂起", ok, reason))
            elif action == "terminate":
                ok = self.terminate_process(pid)
                results.append((name, "终止", ok, reason))
            elif action == "untrusted":
                ok, msg = lower_process_integrity(pid, "untrusted")
                results.append((name, "Untrusted降权", ok, f"{reason}({msg})"))
            elif action == "freeze":
                ok, msg = suspend_process(pid)
                results.append((name, "全冻结", ok, f"{reason}({msg})"))
            if newly_blacklisted:
                red_tag = "[红名单]" if is_red else ""
                results.append((name, f"已拉黑{red_tag}", True, reason))
        return results

    def get_blacklist(self):
        return list(self._blacklist)

    def get_redlist(self):
        return list(self._redlist)


# ============================================================
# 主窗口
# ============================================================
class MainWindow:
    def __init__(self, ti_elevated=False, ti_status="未知", privilege_failure_detail=None, start_minimized=False):
        self.root = tk.Tk()
        self.root.title(f"{APP_NAME} v{APP_VERSION}")
        self.root.geometry("780x560")
        self.root.minsize(700, 500)
        self.start_minimized = start_minimized  # -m/--minimized：启动后最小化到任务栏
        self.baseline_mgr = BaselineManager()
        self.change_history = ChangeHistoryManager(USERDATA_DIR)
        self.change_history.set_audit_level(self.baseline_mgr.config.get("audit_level", "normal"))
        self.engine = ProtectionEngine(self.baseline_mgr)
        self.monitor = None
        self.active_toasts = []  # 当前活动的通知列表
        self._popup_queue = []   # 单个模式下的弹窗队列：[(ext, mismatches, recover_result, extra_timeout), ...]
        self._popup_queue_active = False  # 队列是否正在处理（有弹窗显示中）
        self._popup_last_reason = None    # 上一个弹窗关闭原因："consent"/"timeout"
        self._popup_timeout_reset_after = None  # 2s短超时恢复到正常配置的计时器
        self.ti_elevated = ti_elevated  # TrustedInstaller 提权状态
        self.ti_status = ti_status
        self.privilege_failure_detail = privilege_failure_detail
        self.exit_event = create_exit_event()  # 跨进程退出信号事件
        self.show_event = create_show_event()  # 跨进程显示窗口信号事件
        self._exiting = False
        # 看门狗（无响应监测）
        self._heartbeat_time = time.time()
        self._watchdog_thread = None
        self._watchdog_stop = threading.Event()
        self._process_protected = False
        # 批量弹窗合并
        self._batch_queue = {}  # tamperer -> [(ext, mismatches, recover_result), ...]
        self._batch_timer = None
        self._batch_popup_active = False
        self._popup_paused_until = 0  # 暂停弹窗直到的时间戳
        self._global_lock_mode = False  # 全局锁定模式
        # 共享进程打击器：监控线程与设置页黑名单管理共用同一实例（同一黑名单文件）
        try:
            _bl_p = os.path.join(USERDATA_DIR, "process_blacklist.json")
            _hist_p = os.path.join(USERDATA_DIR, "process_blacklist_history.json")
            self.process_enforcer = ProcessEnforcer(_bl_p, _hist_p)
        except Exception:
            self.process_enforcer = None
        self._build_ui()
        # 关闭按钮改为后台常驻，不退出
        self.root.protocol("WM_DELETE_WINDOW", self._hide_to_background)
        self._init_app()
        # -m/--minimized：开机自启动场景，启动后最小化到任务栏后台常驻
        if self.start_minimized:
            try:
                self.root.withdraw()
                self.root.after(1500, self._minimize_to_taskbar)
            except Exception:
                pass
        # 启动退出信号检查（每500ms检查一次）
        self._check_exit_event()
        # 线程退出看门狗：不依赖 tk 主循环。
        # TI/SYSTEM 提权实例可能无 UI 主循环（after 回调不执行），
        # 退出信号只能由独立线程轮询处理，否则 --stop 后进程卡死。
        try:
            threading.Thread(target=self._exit_watch_thread, daemon=True).start()
        except Exception:
            pass

    def _exit_watch_thread(self):
        """独立线程轮询退出信号（线程安全退出，不依赖 tk mainloop）"""
        while True:
            try:
                if self._exiting:
                    return
                if check_exit_event(self.exit_event):
                    self._append_log("收到退出信号(看门狗线程)，正在关闭...", "warn")
                    self._threadsafe_exit()
                    return
            except Exception:
                pass
            time.sleep(0.5)

    def _threadsafe_exit(self):
        """线程安全的强制退出：停监控→解锁→保存→立即退出进程。
        仅在无 tk 主循环或主循环卡死时由看门狗线程调用。
        不做长清理/长等待（监控线程退出路径自带 _unlock_all；
        _MEI 残留由下次启动的延迟清扫线程处理），避免退出卡死。"""
        try:
            if self.monitor is not None and self.monitor.is_alive():
                try:
                    self.monitor.stop()
                except Exception:
                    pass
                # 显式解锁：stop() 只置位事件，run 循环可能仍在 sleep，
                # 若不立即解锁则 os._exit 抢先导致注册表 Deny ACL 残留，
                # 下次启动扩展名会被锁死（stress 实测 40/40 注入被拒）
                try:
                    self.monitor._unlock_all()
                except Exception:
                    pass
        except Exception:
            pass
        try:
            self.baseline_mgr.save_config()
        except Exception:
            pass
        try:
            if self.exit_event:
                _CloseHandle(self.exit_event)
            if self.show_event:
                _CloseHandle(self.show_event)
        except Exception:
            pass
        self._exiting = True
        # 不依赖 tk 主循环：短暂等待监控线程收尾后立即退出，
        # 跳过 PyInstaller bootloader 清理（防 _MEI 弹窗）
        try:
            time.sleep(1.0)
        except Exception:
            pass
        try:
            os._exit(0)
        except Exception:
            pass

    def _minimize_to_taskbar(self):
        """最小化到任务栏（后台常驻，托盘图标仍在）"""
        try:
            self.root.deiconify()
            self.root.iconify()
        except Exception:
            pass

    def _build_ui(self):
        """主窗口 UI：Win11 设置深色风格（顶部标题栏 + 左侧导航 + 右侧内容页）"""
        # ===== 深色主题（Win11 设置深色近似）=====
        self.C = {
            "bg": "#202020",           # 窗口/页面背景
            "nav": "#1B1B1B",          # 左侧导航背景
            "nav_sel": "#323232",      # 导航选中项背景
            "nav_hover": "#2A2A2A",    # 导航悬停背景
            "card": "#2B2B2B",         # 卡片背景
            "card_border": "#3A3A3A",  # 卡片边框
            "btn": "#454545",          # 按钮背景
            "btn_hover": "#4F4F4F",    # 按钮悬停
            "text": "#FFFFFF",         # 主文字
            "text2": "#B8B8B8",        # 次级文字
            "text3": "#7A7A7A",        # 弱文字
            "accent": "#4CC2FF",       # 强调色
            "accent_hover": "#6ECEFF",
            "success": "#6CCB5F",
            "warn": "#FCE100",
            "error": "#FF99A4",
            "info": "#4CC2FF",
            "line": "#2E2E2E",         # 分隔线
        }
        self._setup_ttk_style()
        self.root.configure(bg=self.C["bg"])
        # 大窗口（接近全局）：TI 会话下 state("zoomed") 会导致窗口/弹窗不可见，
        # 改用大尺寸默认窗口，用户可自行最大化
        self.root.geometry("1280x800")
        self.root.minsize(840, 560)

        # ===== 顶部标题栏 =====
        header = tk.Frame(self.root, bg=self.C["bg"], height=52)
        header.pack(fill="x")
        header.pack_propagate(False)
        tk.Frame(header, bg=self.C["line"], height=1).pack(side="bottom", fill="x")
        tk.Label(header, text=f"{APP_NAME}  v{APP_VERSION}",
                 font=("微软雅黑", 13, "bold"), fg=self.C["text"],
                 bg=self.C["bg"]).pack(side="left", padx=20)
        self.priv_label = tk.Label(header, text=f"权限：{self.ti_status if self.ti_status else '未知'}",
                                   font=("微软雅黑", 9),
                                   fg=self.C["warn"], bg=self.C["bg"])
        self.priv_label.pack(side="right", padx=20)

        # ===== 主体：左侧导航 + 右侧内容 =====
        main = tk.Frame(self.root, bg=self.C["bg"])
        main.pack(fill="both", expand=True)

        # --- 左侧导航 ---
        nav = tk.Frame(main, bg=self.C["nav"], width=212)
        nav.pack(side="left", fill="y")
        nav.pack_propagate(False)
        tk.Frame(nav, bg=self.C["line"], width=1).pack(side="right", fill="y")

        self._nav_buttons = {}
        self._nav_sel = None
        # 导航：状态 / 扩展名 / 防护记录 / 异常修复 / 诊断 / 设置（日志页保留但不再出现在导航，从设置页进入）
        for key, text in [("home", "状态"), ("exts", "扩展名"),
                          ("history", "防护记录"), ("tools", "异常修复"),
                          ("diag", "诊断"), ("settings", "设置")]:
            item = self._make_nav_item(nav, key, text)
            item.pack(fill="x", padx=8, pady=2)

        nav_bottom = tk.Frame(nav, bg=self.C["nav"])
        nav_bottom.pack(side="bottom", fill="x", pady=14)
        tk.Label(nav_bottom, text="关闭窗口 = 后台常驻",
                 font=("微软雅黑", 8), fg=self.C["text3"], bg=self.C["nav"],
                 anchor="w", padx=16).pack(fill="x")
        tk.Label(nav_bottom, text="完全退出：--stop",
                 font=("微软雅黑", 8), fg=self.C["text3"], bg=self.C["nav"],
                 anchor="w", padx=16).pack(fill="x")

        # --- 右侧页面容器 ---
        content = tk.Frame(main, bg=self.C["bg"])
        content.pack(side="left", fill="both", expand=True)
        self._pages = {}
        # 滚轮交互状态：默认滚整页；单击可滚动小项后才滚动小项自身
        self._wheel_active = set()
        self._all_wheel_items = set()
        self._scroll_canvases = []
        self._scroll_bound = False
        self._build_page_home(content)
        self._build_page_exts(content)
        self._build_page_history(content)
        self._build_page_tools(content)
        self._build_page_diag(content)
        self._build_page_log(content)
        self._build_page_settings(content)
        # 所有页面构建完成后，统一收集可滚动小项并绑定“单击激活”滚轮逻辑
        # （延迟收集：小项控件在 _mk_scroll_container 之后才创建）
        for _name, _page in self._pages.items():
            for _w in self._collect_wheel_items(_page):
                self._all_wheel_items.add(_w)
                self._bind_wheel_item(_w)
        # 页面切换：仅 pack 选中页（多个 expand 会纵向均分而非叠层，tkraise 无法独占内容区）
        self._select_nav("home")

        # ===== 底部状态栏 =====
        statusbar = tk.Frame(self.root, bg=self.C["nav"], height=32)
        statusbar.pack(fill="x")
        statusbar.pack_propagate(False)
        tk.Frame(statusbar, bg=self.C["line"], height=1).pack(side="top", fill="x")
        self.bottom_label = tk.Label(statusbar, text="基准模式: - | 基准时间: -",
                                     font=("微软雅黑", 9), fg=self.C["text3"],
                                     bg=self.C["nav"], anchor="w")
        self.bottom_label.pack(side="left", padx=16)
        self.ext_count_label = tk.Label(statusbar, text="保护扩展名：0",
                                        font=("微软雅黑", 9), fg=self.C["text2"],
                                        bg=self.C["nav"])
        self.ext_count_label.pack(side="right", padx=16)

        # 窗口缩放适配：设置页小尺寸按钮（文字→「过小」→隐藏）
        self.root.bind("<Configure>", lambda e: self._apply_small_adapt(e.widget.winfo_width()))

    # ---------- UI 基础组件 ----------
    def _setup_ttk_style(self):
        """配置 ttk 深色风格（滚动条等）"""
        try:
            style = ttk.Style(self.root)
            style.theme_use("clam")
            style.configure("Vertical.TScrollbar", background=self.C["btn"],
                            troughcolor=self.C["bg"], bordercolor=self.C["bg"],
                            arrowcolor=self.C["text2"], lightcolor=self.C["btn"],
                            darkcolor=self.C["btn"])
        except Exception:
            pass

    def _make_nav_item(self, parent, key, text):
        """创建左侧导航项（悬停/选中态 + 左侧强调条）"""
        frame = tk.Frame(parent, bg=self.C["nav"], height=40, cursor="hand2")
        frame.pack_propagate(False)
        accent = tk.Frame(frame, bg=self.C["nav"], width=3)
        accent.pack(side="left", fill="y")
        label = tk.Label(frame, text=text, font=("微软雅黑", 10),
                         fg=self.C["text2"], bg=self.C["nav"], anchor="w")
        label.pack(side="left", fill="x", expand=True, padx=(12, 8))

        def _on_enter(_e):
            if self._nav_sel != key:
                for w in (frame, label):
                    w.configure(bg=self.C["nav_hover"])
        def _on_leave(_e):
            if self._nav_sel != key:
                for w in (frame, label):
                    w.configure(bg=self.C["nav"])
        def _on_click(_e):
            self._select_nav(key)
        frame.bind("<Button-1>", _on_click)
        label.bind("<Button-1>", _on_click)
        frame.bind("<Enter>", _on_enter)
        frame.bind("<Leave>", _on_leave)
        label.bind("<Enter>", _on_enter)
        label.bind("<Leave>", _on_leave)
        self._nav_buttons[key] = (frame, accent, label)
        return frame

    def _select_nav(self, key):
        """切换导航页"""
        if key not in self._pages:
            return
        self._nav_sel = key
        for k, (frame, accent, label) in self._nav_buttons.items():
            sel = (k == key)
            frame.configure(bg=self.C["nav_sel"] if sel else self.C["nav"])
            accent.configure(bg=self.C["accent"] if sel else self.C["nav"])
            label.configure(bg=self.C["nav_sel"] if sel else self.C["nav"],
                            fg=self.C["text"] if sel else self.C["text2"],
                            font=("微软雅黑", 10, "bold") if sel else ("微软雅黑", 10))
        for name, page in self._pages.items():
            if name == key:
                page.pack(fill="both", expand=True)
            else:
                page.pack_forget()
        # 切换页面后清空小项滚轮激活，恢复“滚轮滚整页”
        self._wheel_active.clear()
        if key == "exts":
            self._refresh_ext_page()

    def _set_selfprotect_label(self, ok, msg):
        """更新状态页的进程自我保护显示"""
        try:
            color = self.C["success"] if ok else self.C["error"]
            prefix = "进程自我保护：已启用" if ok else "进程自我保护：未生效"
            self._selfprotect_label.config(text=f"{prefix}\n{msg}", fg=color)
        except Exception:
            pass

    def _reenable_selfprotect(self):
        """重新启用进程自我保护（状态页按钮）"""
        if not self.ti_elevated:
            self._append_log("当前未提权，进程自我保护不可用（需 TI/SYSTEM 权限运行）", "warn")
            self._set_selfprotect_label(False, "未提权，不可用")
            return
        try:
            ok, msg = protect_self_process()
            if ok:
                self._process_protected = True
                self._append_log("进程自我保护已重新启用", "success")
                self._set_selfprotect_label(True, msg)
            else:
                self._process_protected = False
                self._append_log(f"进程自我保护启用失败: {msg}", "warn")
                self._set_selfprotect_label(False, msg)
        except Exception as e:
            self._append_log(f"进程自我保护启用异常: {e}", "error")
            self._set_selfprotect_label(False, str(e))

    def _mk_card(self, parent, title=None, desc=None):
        """创建深色卡片，返回 (card_frame, body_frame)"""
        card = tk.Frame(parent, bg=self.C["card"],
                        highlightbackground=self.C["card_border"],
                        highlightthickness=1, bd=0)
        if title:
            tk.Label(card, text=title, font=("微软雅黑", 11, "bold"),
                     fg=self.C["text"], bg=self.C["card"], anchor="w"
                     ).pack(fill="x", padx=16, pady=(12, 2))
        if desc:
            tk.Label(card, text=desc, font=("微软雅黑", 9), fg=self.C["text3"],
                     bg=self.C["card"], anchor="w", justify="left"
                     ).pack(fill="x", padx=16, pady=(0, 4))
        body = tk.Frame(card, bg=self.C["card"])
        body.pack(fill="x", padx=16, pady=(2, 14))
        card.pack(fill="x", pady=(0, 12))  # 卡片必须 pack 进父容器，否则内容不可见
        return card, body

    def _mk_button(self, parent, text, command, kind="default", width=None, height=1, small_adapt=False):
        """创建 Win11 风格按钮（悬停变色）"""
        if kind == "primary":
            bg, hover, fg = self.C["accent"], self.C["accent_hover"], "#0B2B44"
        elif kind == "danger":
            bg, hover, fg = "#C42B1C", "#D84A3B", "#FFFFFF"
        elif kind == "success":
            bg, hover, fg = "#3C8A3F", "#4CA34F", "#FFFFFF"
        else:
            bg, hover, fg = self.C["btn"], self.C["btn_hover"], self.C["text"]
        btn = tk.Button(parent, text=text, command=command, font=("微软雅黑", 9),
                        bg=bg, fg=fg, activebackground=hover, activeforeground=fg,
                        relief="flat", bd=0, highlightthickness=0, cursor="hand2",
                        width=width, height=height, padx=14, pady=5)
        btn.bind("<Enter>", lambda _e: btn.configure(bg=hover))
        btn.bind("<Leave>", lambda _e: btn.configure(bg=bg))
        # 小尺寸适配注册（设置页按钮）：窗口缩小时文字变「过小」，再缩小直接隐藏
        if small_adapt:
            btn._orig_text = text
            btn._orig_width = width
            btn._kind = kind
            if not hasattr(self, "_settings_buttons"):
                self._settings_buttons = []
            self._settings_buttons.append(btn)
        return btn

    def _apply_small_adapt(self, root_width):
        """设置页小尺寸按钮适配：窗口缩小时文字替换为「过小」，继续缩小直接隐藏。
        禁止出现按钮裁切/显示一半的异常情况。"""
        if not hasattr(self, "_settings_buttons"):
            return
        hide_threshold = 880   # 小于此宽度直接隐藏
        shrink_threshold = 1000  # 小于此宽度文字替换为「过小」
        for btn in self._settings_buttons:
            try:
                if root_width <= hide_threshold:
                    if btn.winfo_manager() == "pack":
                        try:
                            btn._pack_info = btn.pack_info()
                        except Exception:
                            btn._pack_info = {}
                        btn.pack_forget()
                    btn.configure(text="过小")
                elif root_width <= shrink_threshold:
                    if btn.winfo_manager() == "" and getattr(btn, "_pack_info", None):
                        try:
                            btn.pack(**btn._pack_info)
                        except Exception:
                            pass
                    btn.configure(text="过小")
                else:
                    if btn.winfo_manager() == "" and getattr(btn, "_pack_info", None):
                        try:
                            btn.pack(**btn._pack_info)
                        except Exception:
                            pass
                    btn.configure(text=getattr(btn, "_orig_text", "设置"))
            except Exception:
                pass

    def _mk_page_header(self, page, title, subtitle=None):
        """创建页面标题区"""
        tk.Label(page, text=title, font=("微软雅黑", 20, "bold"),
                 fg=self.C["text"], bg=self.C["bg"], anchor="w"
                 ).pack(fill="x", padx=24, pady=(20, 2))
        if subtitle:
            tk.Label(page, text=subtitle, font=("微软雅黑", 9), fg=self.C["text3"],
                     bg=self.C["bg"], anchor="w").pack(fill="x", padx=24)

    def _enumerate_installed_programs(self):
        """枚举本机已安装的程序，返回 [(显示名, exe路径或None), ...]。
        来源：注册表 App Paths / Uninstall(32+64位) / HKCR Applications。
        显示名优先采用软件识别库映射（保证与“谁更改了什么”的提示口径一致）。"""
        import winreg as _wr
        import re as _re
        found = {}  # 显示名 -> exe路径或None（同名去重）
        def _enum_keys(root, sub):
            out = []
            try:
                k = _wr.OpenKey(root, sub, 0, _wr.KEY_READ | 0x100)
            except OSError:
                return out
            try:
                i = 0
                while True:
                    try:
                        out.append(_wr.EnumKey(k, i))
                    except OSError:
                        break
                    i += 1
            finally:
                _wr.CloseKey(k)
            return out
        def _add_name(name, path=None):
            if not name or not isinstance(name, str):
                return
            name = name.strip()
            if not name or len(name) > 60:
                return
            # 显示名不应是完整路径/裸 exe 名：退化为 basename
            if os.sep in name or name.endswith(".exe"):
                name = os.path.basename(name)
                name = name[:-4] if name.lower().endswith(".exe") else name
            # 优先识别库映射（口径一致）：按 exe 名/路径识别。
            # 仅采纳 high/medium 可信度的映射；identify 未命中时返回
            # (输入串, "low")，不得把路径本身当作显示名。
            mapped = None
            conf = "low"
            try:
                if path:
                    mapped, conf = identify_tamperer(path)
                if not mapped or conf == "low":
                    mapped2, conf2 = identify_tamperer(name)
                    if mapped2 and conf2 != "low":
                        mapped, conf = mapped2, conf2
            except Exception:
                mapped = None
            final = (mapped or name) if conf != "low" else name
            if final not in found:
                found[final] = path or None
        # 1) App Paths（exe 名 → 路径）
        for root, sub in ((_wr.HKEY_LOCAL_MACHINE,
                           r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths"),
                          (_wr.HKEY_CURRENT_USER,
                           r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths")):
            for exe_name in _enum_keys(root, sub):
                path = None
                try:
                    k = _wr.OpenKey(root, sub + "\\" + exe_name, 0, _wr.KEY_READ | 0x100)
                    try:
                        path, _ = _wr.QueryValueEx(k, "")
                    except OSError:
                        path = None
                    finally:
                        _wr.CloseKey(k)
                except OSError:
                    pass
                if path and isinstance(path, str):
                    path = path.strip().strip('"')
                base = exe_name[:-4] if exe_name.lower().endswith(".exe") else exe_name
                _add_name(base, path)
        # 2) Uninstall（DisplayName + DisplayIcon）
        for root, sub in ((_wr.HKEY_LOCAL_MACHINE,
                           r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
                          (_wr.HKEY_LOCAL_MACHINE,
                           r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
                          (_wr.HKEY_CURRENT_USER,
                           r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")):
            for key_name in _enum_keys(root, sub):
                try:
                    k = _wr.OpenKey(root, sub + "\\" + key_name, 0, _wr.KEY_READ | 0x100)
                except OSError:
                    continue
                dn = icon = None
                try:
                    try:
                        dn, _ = _wr.QueryValueEx(k, "DisplayName")
                    except OSError:
                        pass
                    try:
                        icon, _ = _wr.QueryValueEx(k, "DisplayIcon")
                    except OSError:
                        pass
                finally:
                    _wr.CloseKey(k)
                if not dn:
                    continue
                base = _re.sub(r"\s*[\d.]+([a-zA-Z]?\d*)*\s*$", "", str(dn).strip()).strip() or str(dn).strip()
                # DisplayIcon 可能是 "C:\path\app.exe,0" 形式（也可能带引号）
                exe_path = None
                if icon:
                    p = str(icon).split(",")[0].strip().strip('"')
                    if p.lower().endswith(".exe") and os.path.exists(p):
                        exe_path = p
                _add_name(base, exe_path)
        # 3) HKCR\Applications（ProgID 应用）
        try:
            k = _wr.OpenKey(_wr.HKEY_LOCAL_MACHINE, r"SOFTWARE\Classes\Applications",
                            0, _wr.KEY_READ | 0x100)
            try:
                i = 0
                while True:
                    try:
                        name = _wr.EnumKey(k, i)
                    except OSError:
                        break
                    i += 1
                    base = name[:-4] if name.lower().endswith(".exe") else name
                    _add_name(base, None)
            finally:
                _wr.CloseKey(k)
        except OSError:
            pass
        return list(found.items())

    def _pick_program(self, target_callback, title="从本机程序选择"):
        """程序选择窗口：候选 = 本机已安装程序（注册表枚举，名称经识别库
        归一化，保证与“谁更改了什么”提示一致）+ 当前运行进程名。
        选中后回调 target_callback(程序名)，无需用户手动输入。"""
        win = tk.Toplevel(self.root)
        win.title(title)
        win.configure(bg=self.C["bg"])
        win.geometry("480x560")
        win.transient(self.root)
        try:
            win.grab_set()
        except Exception:
            pass
        # 候选集合：本机已安装程序 + 当前运行进程名
        candidates = {}
        for name, path in self._enumerate_installed_programs():
            candidates[name] = path
        try:
            import subprocess as _sp
            _out = _sp.run(["tasklist", "/FO", "CSV", "/NH"],
                           capture_output=True, text=True, timeout=8).stdout
            for line in _out.splitlines():
                _p = line.split('","')[0].strip('"')
                if _p and _p.lower().endswith(".exe"):
                    _base = _p[:-4]
                    if _base not in candidates:
                        candidates[_base] = None
        except Exception:
            pass
        ordered = sorted(candidates.items(), key=lambda kv: kv[0].lower())
        tk.Label(win, text="搜索并选择程序（双击或点击确定）",
                 font=("微软雅黑", 10, "bold"), fg=self.C["text"],
                 bg=self.C["bg"], anchor="w").pack(fill="x", padx=16, pady=(14, 4))
        search_var = tk.StringVar()
        entry = tk.Entry(win, textvariable=search_var, font=("微软雅黑", 9),
                         bg=self.C["btn"], fg=self.C["text"], relief="flat",
                         highlightthickness=0, insertbackground=self.C["text"])
        entry.pack(fill="x", padx=16, pady=4)
        listbox = tk.Listbox(win, font=("微软雅黑", 9), bg=self.C["btn"],
                             fg=self.C["text"], selectbackground=self.C["nav_sel"],
                             relief="flat", highlightthickness=0)
        listbox.pack(fill="both", expand=True, padx=16, pady=(2, 8))
        tk.Label(win, text=f"共 {len(ordered)} 个候选（本机已安装程序 + 当前运行进程）",
                 font=("微软雅黑", 8), fg=self.C["text3"], bg=self.C["bg"], anchor="w").pack(fill="x", padx=16)
        ops = tk.Frame(win, bg=self.C["bg"])
        ops.pack(fill="x", padx=16, pady=(4, 14))

        def _refresh(_a=None, _b=None, _c=None):
            q = search_var.get().strip().lower()
            listbox.delete(0, tk.END)
            for name, _path in ordered:
                if not q or q in name.lower():
                    listbox.insert(tk.END, name)

        def _confirm():
            sel = listbox.curselection()
            if sel:
                try:
                    target_callback(listbox.get(sel[0]))
                    win.destroy()
                except Exception:
                    win.destroy()

        search_var.trace_add("write", _refresh)
        listbox.bind("<Double-Button-1>", lambda _e: _confirm())
        entry.bind("<Return>", lambda _e: _confirm())
        self._mk_button(ops, "确定添加", _confirm, kind="primary").pack(side="left", padx=(0, 8))
        self._mk_button(ops, "取消", win.destroy).pack(side="left")
        _refresh()
        entry.focus_set()
        return win

    def _mk_scroll_container(self, page):
        """创建可滚动内容容器，返回 content_frame（页面内滚动区）
        滚轮全局响应：绑定到整个窗口，鼠标在任意子控件（按钮/卡片）上
        滚动都生效；Text/ScrolledText/Listbox 等自带滚轮的控件除外（避免双滚动）"""
        canvas = tk.Canvas(page, bg=self.C["bg"], highlightthickness=0, bd=0)
        vsb = ttk.Scrollbar(page, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True, padx=(24, 8), pady=8)
        content = tk.Frame(canvas, bg=self.C["bg"])
        cw = canvas.create_window((0, 0), window=content, anchor="nw")
        def _sync_scroll(_e):
            canvas.configure(scrollregion=canvas.bbox("all"))
        content.bind("<Configure>", _sync_scroll)
        def _sync_width(_e):
            canvas.itemconfig(cw, width=_e.width)
        canvas.bind("<Configure>", _sync_width)
        # 收集所有滚动容器 canvas，供全局滚轮分发
        if not hasattr(self, "_scroll_canvases"):
            self._scroll_canvases = []
        self._scroll_canvases.append(canvas)
        # 点击页面空白/背景时交还滚轮（清除小项激活）
        canvas.bind("<Button-1>", lambda _e: self._wheel_active.clear())
        # 全局兜底绑定（仅一次）
        if not getattr(self, "_scroll_bound", False):
            self._scroll_bound = True
            def _on_mousewheel(_e):
                # 小项自身的 handler 已 return "break" 阻断；能到这里说明
                # 鼠标不在小项上 → 滚动当前可见页面
                for c in self._scroll_canvases:
                    if c.winfo_ismapped():
                        try:
                            c.yview_scroll(int(-_e.delta / 120), "units")
                        except Exception:
                            pass
                        break
            def _on_click(_e):
                # 点击任意处：若是可滚动小项则激活（交由小项 Button-1 先执行），
                # 否则交还滚轮给页面
                w = _e.widget
                if w not in self._all_wheel_items:
                    self._wheel_active.clear()
            self.root.bind_all("<MouseWheel>", _on_mousewheel)
            self.root.bind_all("<Button-1>", _on_click, add="+")
        return content

    def _collect_wheel_items(self, widget, depth=0):
        """递归收集 widget 下所有可滚动小项控件。
        ScrolledText 拆取其内部 Text（滚轮事件实际落在 Text 上）。"""
        out = []
        try:
            children = widget.winfo_children()
        except Exception:
            return out
        for c in children:
            if isinstance(c, scrolledtext.ScrolledText):
                for sub in c.winfo_children():
                    if isinstance(sub, tk.Text):
                        out.append(sub)
                        break
            elif isinstance(c, (tk.Text, tk.Listbox, tk.Spinbox, ttk.Combobox)):
                out.append(c)
            if depth < 8:
                out.extend(self._collect_wheel_items(c, depth + 1))
        return out

    def _bind_wheel_item(self, w):
        """绑定小项滚轮：单击激活后才滚动小项自身；未激活时滚轮滚动页面。"""
        def _wheel(_e):
            if w in self._wheel_active:
                try:
                    w.yview_scroll(int(-_e.delta / 120), "units")
                except Exception:
                    pass
            else:
                for c in self._scroll_canvases:
                    if c.winfo_ismapped():
                        try:
                            c.yview_scroll(int(-_e.delta / 120), "units")
                        except Exception:
                            pass
                        break
            return "break"
        try:
            w.bind("<MouseWheel>", _wheel)
            w.bind("<Button-1>", lambda _e: self._wheel_active.add(w), add="+")
        except Exception:
            pass

    def _flow_wrap(self, parent, widgets, gap=8, anchor="left"):
        """Flow 布局：容器宽度不足时按钮自动换行（窗口缩放适配）。
        预建固定行容器 + 重入保护，避免 <Configure> 触发重排造成死循环。"""
        state = {"busy": False, "pending": False}
        rows = []
        for _i in range(max(1, len(widgets))):
            rf = tk.Frame(parent, bg=parent["bg"])
            rf.pack(fill="x", pady=2)
            rows.append(rf)
        def _relayout(_e=None):
            if state["busy"]:
                state["pending"] = True
                return
            state["busy"] = True
            try:
                avail = parent.winfo_width()
                if avail <= 1:
                    return
                widths = []
                for w in widgets:
                    try:
                        w.update_idletasks()
                        widths.append(w.winfo_reqwidth())
                    except Exception:
                        widths.append(0)
                # 贪心分行
                assignment = [[]]
                total = 0
                for w, rw in zip(widgets, widths):
                    if total + rw + gap > avail and assignment[-1]:
                        assignment.append([])
                        total = 0
                    assignment[-1].append(w)
                    total += rw + gap
                for w in widgets:
                    try:
                        w.pack_forget()
                    except Exception:
                        pass
                for ri, rw_list in enumerate(assignment):
                    if ri >= len(rows):
                        break
                    for w in rw_list:
                        try:
                            w.pack(in_=rows[ri], side="left", padx=(0, gap))
                        except Exception:
                            pass
                # 清理未使用的行容器
                for ri in range(len(assignment), len(rows)):
                    for c in list(rows[ri].winfo_children()):
                        try:
                            c.pack_forget()
                        except Exception:
                            pass
            finally:
                state["busy"] = False
                if state["pending"]:
                    state["pending"] = False
                    try:
                        parent.after_idle(_relayout)
                    except Exception:
                        pass
        parent.bind("<Configure>", _relayout)
        try:
            self.root.after(50, _relayout)
        except Exception:
            pass
        return _relayout

    # ---------- 页面：状态 ----------
    def _build_page_home(self, parent):
        page = tk.Frame(parent, bg=self.C["bg"])
        self._pages["home"] = page
        self._mk_page_header(page, "状态", "扩展名保护卫士 · 实时监控文件关联注册表")
        # 全局可滑动：整页内容放入滚动容器（窗口最大化后内容仍可完整访问）
        body = self._mk_scroll_container(page)

        # 卡片1：保护状态（状态行 + 启动/停止 + 进程自我保护合并排布，可自动换行）
        card, cb = self._mk_card(body, "保护状态", "实时监控 7 项注册表位置，阻止第三方软件篡改默认打开方式")
        self.status_label = tk.Label(cb, text="● 状态：未初始化",
                                     font=("微软雅黑", 14, "bold"),
                                     fg=self.C["text2"], bg=self.C["card"], anchor="w")
        self.status_label.pack(fill="x", pady=(4, 8))
        self._protect_btns = []
        btn_start = self._mk_button(cb, "启动保护", self._start_protection, kind="success")
        btn_stop = self._mk_button(cb, "停止保护", self._stop_protection, kind="danger")
        btn_stop.configure(state="disabled")
        self.btn_start = btn_start
        self.btn_stop = btn_stop
        # 进程自我保护状态（与启动/停止按钮合并排布、自动换行）
        self._selfprotect_label = tk.Label(cb, text="进程自我保护：—",
                                           font=("微软雅黑", 10),
                                           fg=self.C["text2"], bg=self.C["card"], anchor="w")
        btn_selfprotect = self._mk_button(cb, "重新启用", self._reenable_selfprotect, kind="default")
        self.btn_selfprotect = btn_selfprotect
        self._protect_btns += [btn_start, btn_stop, btn_selfprotect]
        self._flow_wrap(cb, self._protect_btns, gap=8)
        # 保护级说明（BH0-BH5 + 红名单），原扩展名页迁入状态页"保护状态"分类
        protect_info = (
            "BH0：仅检测不阻止 | BH1：自动恢复基准值并验证 | BH2：ACL锁定UserChoice键\n"
            "BH3：ACL锁定+System完整性标签 | BH4：强锁定+进程降为Untrusted\n"
            "BH5：强锁定+Untrusted降权+NtSuspendProcess冻结 | 红名单：进程永久拒绝注册表操作"
        )
        tk.Label(cb, text=protect_info, font=("微软雅黑", 8), fg=self.C["text3"],
                 bg=self.C["card"], anchor="w", justify="left").pack(fill="x", pady=(8, 0))

        # 卡片2：主界面输出窗口（原版风格，实时输出保护事件与状态）
        out_card = tk.Frame(body, bg=self.C["card"],
                            highlightbackground=self.C["card_border"],
                            highlightthickness=1, bd=0)
        out_card.pack(fill="x", pady=(0, 12))
        tk.Label(out_card, text="保护输出", font=("微软雅黑", 11, "bold"),
                 fg=self.C["text"], bg=self.C["card"], anchor="w"
                 ).pack(fill="x", padx=16, pady=(12, 4))
        self.status_output = scrolledtext.ScrolledText(out_card, font=("Consolas", 9),
                                                       wrap="word", state="disabled",
                                                       bg="#1A1A1A", fg="#D4D4D4",
                                                       insertbackground="#D4D4D4",
                                                       relief="flat", bd=0, height=26,
                                                       highlightbackground=self.C["card_border"],
                                                       highlightthickness=1)
        self.status_output.pack(fill="x", padx=16, pady=(0, 14))
        for tag, color in (("info", "#D4D4D4"), ("warn", "#FCE100"),
                           ("error", "#FF99A4"), ("success", "#6CCB5F")):
            self.status_output.tag_config(tag, foreground=color)

        # 底部信息栏：权限摘要 + 常用操作（按钮自动换行适配窗口缩放）
        bar = tk.Frame(body, bg=self.C["card"],
                       highlightbackground=self.C["card_border"],
                       highlightthickness=1, bd=0)
        bar.pack(fill="x")
        info_col = tk.Frame(bar, bg=self.C["card"])
        info_col.pack(side="left", padx=16, pady=10)
        self._perm_detail_label = tk.Label(info_col, text="权限：—",
                                           font=("微软雅黑", 9),
                                           fg=self.C["text3"], bg=self.C["card"], anchor="w")
        self._perm_detail_label.pack(fill="x", pady=1)
        op_col = tk.Frame(bar, bg=self.C["card"])
        op_col.pack(side="right", fill="x", expand=True, padx=16, pady=10)
        op_btns = []
        for text, cmd, kind in [
            ("备份当前基准", self._backup_current, "default"),
            ("深层扫描", self._manual_deep_scan, "default"),
            ("全局锁定 / 解除锁定", self._toggle_global_lock, "default"),
            ("历史版本管理", self._show_history, "default"),
        ]:
            # 不设固定宽度：按钮按文字自适应大小（窗口缩放时自动伸展/换行）
            op_btns.append(self._mk_button(op_col, text, cmd, kind=kind))
        self._flow_wrap(op_col, op_btns, gap=6)

    # ---------- 页面：扩展名 ----------
    def _build_page_exts(self, parent):
        page = tk.Frame(parent, bg=self.C["bg"])
        self._pages["exts"] = page
        self._mk_page_header(page, "扩展名", "保护范围与基准信息")
        body = self._mk_scroll_container(page)

        card, cb = self._mk_card(body, "统计信息")
        self._ext_info_var = tk.StringVar(value="保护扩展名：—\n基准模式：—\n基准时间：—")
        tk.Label(cb, textvariable=self._ext_info_var, font=("微软雅黑", 10),
                 fg=self.C["text2"], bg=self.C["card"], anchor="w", justify="left"
                 ).pack(fill="x", pady=2)

        # 单扩展名锁定：锁定某个扩展名的默认打开方式（配置保存在文件中）
        lock_card, lock_cb = self._mk_card(
            body, "单扩展名锁定",
            "锁定后该扩展名的默认打开方式不再随其他软件篡改而改变，配置自动保存在文件中")
        lock_row = tk.Frame(lock_cb, bg=self.C["card"])
        lock_row.pack(fill="x", pady=(2, 4))
        self._lock_ext_entry = tk.Entry(lock_row, font=("微软雅黑", 9), width=14,
                                        bg=self.C["btn"], fg=self.C["text"],
                                        relief="flat", highlightthickness=0,
                                        insertbackground=self.C["text"])
        self._lock_ext_entry.pack(side="left", padx=(0, 6))
        self._mk_button(lock_row, "读取当前", self._lock_ext_read_current, width=10).pack(side="left", padx=(0, 6))
        self._mk_button(lock_row, "锁定当前默认应用", self._lock_ext_default, kind="primary").pack(side="left", padx=(0, 6))
        self._lock_ext_status = tk.Label(lock_cb, text="", font=("微软雅黑", 9),
                                         fg=self.C["text2"], bg=self.C["card"], anchor="w", justify="left")
        self._lock_ext_status.pack(fill="x", pady=(0, 4))
        lk_list_frame = tk.Frame(lock_cb, bg=self.C["card"])
        lk_list_frame.pack(fill="x", pady=4)
        self._locked_ext_listbox = tk.Listbox(lk_list_frame, font=("微软雅黑", 9), height=4,
                                              bg=self.C["btn"], fg=self.C["text"],
                                              selectbackground=self.C["nav_sel"],
                                              relief="flat", highlightthickness=0)
        self._locked_ext_listbox.pack(side="left", fill="x", expand=True)
        tk.Scrollbar(lk_list_frame, orient="vertical",
                     command=self._locked_ext_listbox.yview).pack(side="right", fill="y")
        self._locked_ext_listbox.config(yscrollcommand=lambda *a: None)
        lk_ops = tk.Frame(lock_cb, bg=self.C["card"])
        lk_ops.pack(fill="x")
        self._mk_button(lk_ops, "解锁选中", self._lock_ext_unlock, width=10).pack(side="left", padx=(0, 8))
        self._mk_button(lk_ops, "解锁全部", self._lock_ext_unlock_all, width=10).pack(side="left", padx=(0, 8))
        self._mk_button(lk_ops, "刷新状态", self._refresh_locked_ext_list, width=10).pack(side="left")
        self._refresh_locked_ext_list()

    def _refresh_locked_ext_list(self):
        """刷新锁定扩展名列表（数据来自 config['locked_defaults']，保存在文件中）"""
        try:
            locked = self.baseline_mgr.config.get("locked_defaults", {}) or {}
            self._locked_ext_listbox.delete(0, tk.END)
            for ext in sorted(locked.keys()):
                target = locked[ext]
                status = ""
                try:
                    cur = get_prog_id(ext)
                    if cur and cur.lower() == target.lower():
                        status = "  ✓ 一致"
                    elif cur:
                        status = f"  ✗ 当前={cur}"
                    else:
                        status = "  ○ 系统默认(待落实)"
                except Exception:
                    pass
                self._locked_ext_listbox.insert(tk.END, f"{ext} → {target}{status}")
        except Exception:
            pass

    def _lock_ext_read_current(self):
        """读取输入扩展名当前的默认打开方式"""
        ext = self._lock_ext_entry.get().strip().lower()
        if not ext.startswith("."):
            self._lock_ext_status.config(text="请输入扩展名（以 . 开头，如 .txt）", fg=self.C["warn"])
            return
        try:
            progid = get_prog_id(ext)
            if progid:
                name, _ = identify_tamperer(progid)
                self._lock_ext_status.config(
                    text=f"扩展名 {ext} 当前默认: {progid}" + (f"（{name}）" if name else ""),
                    fg=self.C["text2"])
            else:
                self._lock_ext_status.config(text=f"扩展名 {ext} 当前为系统默认（无 UserChoice 记录）", fg=self.C["text2"])
        except Exception as e:
            self._lock_ext_status.config(text=f"读取失败: {e}", fg=self.C["error"])

    def _lock_ext_default(self):
        """锁定输入扩展名当前的默认打开方式：写入文件配置并同步基准"""
        ext = self._lock_ext_entry.get().strip().lower()
        if not ext.startswith("."):
            self._lock_ext_status.config(text="请输入扩展名（以 . 开头，如 .txt）", fg=self.C["warn"])
            return
        try:
            progid = get_prog_id(ext)
            if not progid:
                self._lock_ext_status.config(
                    text=f"扩展名 {ext} 没有可锁定的默认应用（请先在系统中设置默认打开方式）", fg=self.C["warn"])
                return
            cfg = self.baseline_mgr.config
            locked = cfg.setdefault("locked_defaults", {})
            if ext in locked:
                if locked[ext].lower() == progid.lower():
                    self._lock_ext_status.config(
                        text=f"{ext} 已锁定为 {progid}，无需重复锁定", fg=self.C["warn"])
                    return
                self._lock_ext_status.config(
                    text=f"更新锁定目标: {locked[ext]} → {progid}", fg=self.C["text2"])
            locked[ext] = progid
            self.baseline_mgr.save_config()
            # 同步基准：锁定值成为恢复目标
            try:
                self.baseline_mgr.update_extension(ext)
            except Exception:
                pass
            self._refresh_locked_ext_list()
            name, _ = identify_tamperer(progid)
            self._lock_ext_status.config(
                text=f"已锁定 {ext} → {progid}（{name or '未知软件'}），配置已保存到文件", fg=self.C["success"])
            self._append_log(f"已锁定扩展名默认应用: {ext} → {progid}", "success")
        except Exception as e:
            self._lock_ext_status.config(text=f"锁定失败: {e}", fg=self.C["error"])

    def _lock_ext_unlock(self):
        """解锁选中的扩展名锁定项"""
        sel = self._locked_ext_listbox.curselection()
        if not sel:
            return
        line = self._locked_ext_listbox.get(sel[0])
        ext = line.split("→")[0].strip()
        try:
            cfg = self.baseline_mgr.config
            locked = cfg.get("locked_defaults", {}) or {}
            if ext in locked:
                del locked[ext]
                self.baseline_mgr.save_config()
                # 解锁后同步基准为当前实际关联，恢复普通保护
                try:
                    self.baseline_mgr.update_extension(ext)
                except Exception:
                    pass
            self._refresh_locked_ext_list()
            self._lock_ext_status.config(text=f"已解锁 {ext}，配置已保存到文件", fg=self.C["text2"])
            self._append_log(f"已解锁扩展名: {ext}", "info")
        except Exception as e:
            self._lock_ext_status.config(text=f"解锁失败: {e}", fg=self.C["error"])

    def _lock_ext_unlock_all(self):
        """解锁全部扩展名锁定项"""
        try:
            cfg = self.baseline_mgr.config
            locked = cfg.get("locked_defaults", {}) or {}
            if not locked:
                self._lock_ext_status.config(text="当前没有已锁定的扩展名", fg=self.C["text2"])
                return
            exts = list(locked.keys())
            locked.clear()
            self.baseline_mgr.save_config()
            for ext in exts:
                try:
                    self.baseline_mgr.update_extension(ext)
                except Exception:
                    pass
            self._refresh_locked_ext_list()
            self._lock_ext_status.config(text=f"已解锁全部 {len(exts)} 个扩展名，配置已保存到文件", fg=self.C["text2"])
            self._append_log(f"已解锁全部扩展名: {', '.join(exts)}", "info")
        except Exception as e:
            self._lock_ext_status.config(text=f"解锁失败: {e}", fg=self.C["error"])

    def _add_prog_to_listbox(self, listbox, name):
        """从程序选择器添加白名单程序（去重后自动保存）"""
        try:
            exists = [listbox.get(i) for i in range(listbox.size())]
            if name and name not in exists:
                listbox.insert(tk.END, name)
                self._append_log(f"已添加白名单程序: {name}", "success")
                self._save_settings_if_ready()
        except Exception:
            pass

    def _save_settings_if_ready(self):
        """设置页已构建时触发自动保存（构建期间调用则跳过）"""
        try:
            if hasattr(self, "_settings_page_ready") and self._settings_page_ready:
                self._auto_save_fn()
        except Exception:
            pass

    def _refresh_blacklist_ui(self):
        """刷新进程黑名单列表（来源：process_blacklist.json）"""
        try:
            if not hasattr(self, "_bl_listbox"):
                return
            self._bl_listbox.delete(0, tk.END)
            pe = getattr(self, "process_enforcer", None)
            items = sorted(pe._blacklist) if pe else []
            for it in items:
                self._bl_listbox.insert(tk.END, it)
        except Exception:
            pass

    def _add_blacklist_program(self, name):
        """添加程序到进程黑名单（进程名，小写保存）"""
        try:
            pe = getattr(self, "process_enforcer", None)
            if not pe:
                return
            item = name.strip()
            if not item:
                return
            if item.lower() not in {x.lower() for x in pe._blacklist}:
                pe._blacklist.add(item.lower())
                try:
                    pe._save()
                except Exception:
                    pass
                self._append_log(f"已添加进程黑名单: {item}", "warn")
            self._refresh_blacklist_ui()
        except Exception:
            pass

    def _remove_blacklist_program(self):
        """移除选中的黑名单项"""
        try:
            pe = getattr(self, "process_enforcer", None)
            if not pe:
                return
            sel = self._bl_listbox.curselection()
            if not sel:
                return
            item = self._bl_listbox.get(sel[0])
            pe._blacklist.discard(item)
            try:
                pe._save()
            except Exception:
                pass
            self._append_log(f"已移除进程黑名单: {item}", "info")
            self._refresh_blacklist_ui()
        except Exception:
            pass

    def _clear_blacklist_ui(self):
        """清空全部进程黑名单"""
        try:
            pe = getattr(self, "process_enforcer", None)
            if not pe:
                return
            if messagebox.askyesno("确认", "确定清空全部进程黑名单？"):
                pe._blacklist.clear()
                try:
                    pe._save()
                except Exception:
                    pass
                self._append_log("进程黑名单已清空", "info")
                self._refresh_blacklist_ui()
        except Exception:
            pass

    def _refresh_ext_page(self):
        """切换到扩展名页时刷新统计"""
        try:
            count = len(self.baseline_mgr.get_protected_extensions())
            mode = self.baseline_mgr.config.get("baseline_mode", "-")
            mode_text = "目前方式" if mode == "current" else "默认方式" if mode == "default" else "-"
            btime = self.baseline_mgr.config.get("baseline_time", "-")
            self._ext_info_var.set(f"保护扩展名：{count}\n基准模式：{mode_text}\n基准时间：{btime}")
        except Exception:
            pass

    # ---------- 页面：工具（异常修复） ----------
    def _build_page_tools(self, parent):
        page = tk.Frame(parent, bg=self.C["bg"])
        self._pages["tools"] = page
        self._mk_page_header(page, "异常修复", "20 项独立修复 + 辅助工具")
        content = self._mk_scroll_container(page)

        self._repair_status_var = tk.StringVar(value="就绪 · 点击任意按钮执行对应修复，完成后自动返回状态页")
        status_bar = tk.Frame(content, bg=self.C["card"], height=34)
        status_bar.pack(fill="x", pady=(4, 8))
        status_bar.pack_propagate(False)
        tk.Label(status_bar, textvariable=self._repair_status_var, font=("微软雅黑", 9),
                 fg=self.C["text2"], bg=self.C["card"], anchor="w").pack(fill="x", padx=12)

        def make_button(parent_w, text, command, height=1):
            # 统一配色：全部使用标准深色按钮风格（取消多色混杂）
            return tk.Button(parent_w, text=text, command=command,
                             font=("微软雅黑", 9, "bold"),
                             bg=self.C["btn"], fg=self.C["text"],
                             activebackground=self.C["nav_sel"], activeforeground=self.C["text"],
                             relief="flat", cursor="hand2", bd=0,
                             highlightthickness=0, height=height,
                             padx=8, pady=6)

        def _wrap_jump(cmd):
            """执行修复命令后自动跳转至状态页（保护输出窗口）"""
            def _f():
                try:
                    cmd()
                except Exception:
                    pass
                finally:
                    try:
                        self._select_nav("home")
                    except Exception:
                        pass
            return _f

        def add_section(title):
            sec = tk.LabelFrame(content, text="", bg=self.C["card"], bd=0,
                                highlightbackground=self.C["card_border"], highlightthickness=1)
            sec.pack(fill="x", pady=(6, 2))
            head = tk.Frame(sec, bg=self.C["card"])
            head.pack(fill="x", padx=12, pady=(8, 2))
            tk.Label(head, text=title, font=("微软雅黑", 10, "bold"),
                     fg=self.C["text"], bg=self.C["card"]).pack(side="left")
            grid = tk.Frame(sec, bg=self.C["card"])
            grid.pack(fill="x", padx=12, pady=(2, 10))
            return grid

        def place_buttons(grid, buttons):
            grid.columnconfigure(0, weight=1, uniform="btn")
            grid.columnconfigure(1, weight=1, uniform="btn")
            for i, (text, command) in enumerate(buttons):
                r, c = divmod(i, 2)
                make_button(grid, text, _wrap_jump(command)).grid(row=r, column=c, sticky="ew", padx=3, pady=3)

        place_buttons(add_section("一、解除注册表锁定（最核心）"), [
            ("① 解除所有注册表锁定", self._repair_unlock_registry),
            ("② 清除锁定计数", self._repair_clear_lock_count),
        ])
        place_buttons(add_section("二、重置持续篡改追踪状态"), [
            ("③ 清除单扩展名篡改历史", self._repair_clear_ext_history),
            ("④ 清除批量篡改历史", self._repair_clear_progid_history),
            ("⑤ 清除持续篡改标记", self._repair_clear_persistent_exts),
            ("⑥ 清除批量篡改标记", self._repair_clear_batch_progids),
            ("⑦ 退出持续篡改模式", self._repair_exit_persistent_mode),
            ("⑧ 清除高频观察期", self._repair_clear_unlocked_exts),
        ])
        place_buttons(add_section("三、重置防护引擎状态"), [
            ("⑨ 清除冷却期", self._repair_clear_cooldown),
            ("⑩ 清除本周期同意记录", self._repair_clear_allowed_cycle),
            ("⑪ 清除 UserChoice 失败计数", self._repair_clear_uc_fail),
            ("⑫ 清除处理中集合", self._repair_clear_handling_exts),
        ])
        place_buttons(add_section("四、清除弹窗 / 通知状态"), [
            ("⑬ 关闭所有活动弹窗", self._repair_close_toasts),
            ("⑭ 清空弹窗队列", self._repair_clear_popup_queue),
            ("⑮ 清空批量弹窗队列", self._repair_clear_batch_queue),
            ("⑯ 取消批量计时器", self._repair_cancel_batch_timer),
            ("⑰ 解除弹窗暂停", self._repair_clear_popup_pause),
        ])
        place_buttons(add_section("五、进程打击状态"), [
            ("⑱ 清除进程黑名单", self._repair_clear_blacklist),
            ("⑲ 清除打击历史", self._repair_clear_strike_history),
        ])
        place_buttons(add_section("六、其他 / 辅助工具"), [
            ("历史版本管理", self._show_history),
            ("锁定模式 / 解除锁定", self._repair_global_lock),
            ("重置启动宽限期", self._repair_reset_grace),
        ])

        bottom = tk.Frame(content, bg=self.C["bg"])
        bottom.pack(fill="x", pady=(8, 4))
        make_button(bottom, "一键全部修复（20 项全部执行）", _wrap_jump(self._repair_all), height=2).pack(fill="x", pady=2)

    def _lighten(self, hex_color, amount=0.18):
        try:
            h = hex_color.lstrip('#')
            r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
            r = min(255, int(r + (255 - r) * amount))
            g = min(255, int(g + (255 - g) * amount))
            b = min(255, int(b + (255 - b) * amount))
            return f'#{r:02x}{g:02x}{b:02x}'
        except Exception:
            return hex_color

    # ---------- 页面：日志 ----------
    def _build_page_log(self, parent):
        page = tk.Frame(parent, bg=self.C["bg"])
        self._pages["log"] = page
        self._mk_page_header(page, "日志", "运行日志 · 实时保护事件记录")
        log_wrap = tk.Frame(page, bg=self.C["bg"])
        log_wrap.pack(fill="both", expand=True, padx=24, pady=16)
        self.log_text = scrolledtext.ScrolledText(log_wrap, font=("Consolas", 9),
                                                  wrap="word", state="disabled",
                                                  bg="#1A1A1A", fg="#D4D4D4",
                                                  insertbackground="#D4D4D4",
                                                  relief="flat", bd=0,
                                                  highlightbackground=self.C["card_border"],
                                                  highlightthickness=1)
        self.log_text.pack(fill="both", expand=True)
        self.log_text.tag_config("info", foreground="#D4D4D4")
        self.log_text.tag_config("warn", foreground="#FCE100")
        self.log_text.tag_config("error", foreground="#FF99A4")
        self.log_text.tag_config("success", foreground="#6CCB5F")

    # ---------- 页面：设置 ----------
    def _build_page_settings(self, parent):
        page = tk.Frame(parent, bg=self.C["bg"])
        self._pages["settings"] = page
        self._mk_page_header(page, "设置", "配置保护行为与运行选项")
        content = self._mk_scroll_container(page)

        cfg = self.baseline_mgr.config
        dark = self.C

        # ===== 节1：提醒 =====
        sec, body = self._mk_card(content, "提醒")
        autostart_var = tk.BooleanVar(value=cfg.get("autostart", True))
        popup_var = tk.BooleanVar(value=cfg.get("show_popup", True))
        clearlog_var = tk.BooleanVar(value=cfg.get("clear_log_on_start", False))
        nokill_var = tk.BooleanVar(value=cfg.get("persistent_no_kill", False))
        batch_popup_var = tk.StringVar(value=cfg.get("batch_popup_mode", "single"))
        mode_var = tk.StringVar(value=cfg.get("operation_mode", "normal"))
        _loaded_timeout = cfg.get("block_timeout", NOTIFY_TIMEOUT)
        if _loaded_timeout < 1: _loaded_timeout = 1
        elif _loaded_timeout > 180: _loaded_timeout = 180
        block_var = tk.IntVar(value=_loaded_timeout)

        def _row(parent_w, text, widget):
            row = tk.Frame(parent_w, bg=dark["card"])
            row.pack(fill="x", pady=3)
            tk.Label(row, text=text, font=("微软雅黑", 9), fg=dark["text2"],
                     bg=dark["card"], anchor="w").pack(side="left")
            widget.pack(side="right")
            return row

        def _check(parent_w, text, var):
            chk = tk.Checkbutton(parent_w, text=text, variable=var,
                                 font=("微软雅黑", 9), bg=dark["card"], fg=dark["text2"],
                                 selectcolor=dark["card"], activebackground=dark["card"],
                                 activeforeground=dark["text"], highlightthickness=0, bd=0)
            chk.pack(fill="x", pady=3, anchor="w")
            return chk

        _check(body, "开机自启", autostart_var)
        _check(body, "检测到更改时弹窗通知（取消则静默阻止）", popup_var)
        block_spin = tk.Spinbox(body, from_=1, to=180,
             textvariable=block_var, width=6, bg=dark["btn"], fg=dark["text"],
             buttonbackground=dark["btn"], relief="flat", highlightthickness=0)
        _row(body, "弹窗等待时间（秒）:", block_spin)
        tk.Label(body, text="范围 1-180 秒；关闭弹窗时此值强制为 1 秒",
                 font=("微软雅黑", 8), fg=dark["text3"], bg=dark["card"], anchor="w").pack(fill="x")
        _row(body, "批量弹窗模式:", self._mk_radio_row(body, batch_popup_var,
             [("single", "单个(队列)"), ("simultaneous", "同时(堆叠)")]))
        tk.Label(body, text="单个：一次弹一个，超时自动阻止后下一个缩短为6秒；同时：所有弹窗同时弹出",
                 font=("微软雅黑", 8), fg=dark["text3"], bg=dark["card"], anchor="w", justify="left").pack(fill="x")
        _row(body, "运行模式:", self._mk_radio_row(body, mode_var,
             [("normal", "正常"), ("quiet", "临时免打扰"), ("game", "游戏模式"),
              ("demo", "演示模式"), ("silent", "静默模式"), ("paused", "临时暂停")]))
        tk.Label(body, text="正常：默认弹窗；免打扰/游戏/演示/静默：关闭或压制提醒；暂停：短时停用检测",
                 font=("微软雅黑", 8), fg=dark["text3"], bg=dark["card"], anchor="w", justify="left").pack(fill="x")
        _check(body, "每次启动清空日志", clearlog_var)
        _check(body, "持续/批量篡改时不终止进程（仅锁定注册表）", nokill_var)

        # ===== 节2：基准 =====
        sec2, body2 = self._mk_card(content, "基准")
        hist_var = tk.IntVar(value=cfg.get("history_versions", MAX_HISTORY_VERSIONS))
        hist_spin = tk.Spinbox(body2, from_=1, to=20,
             textvariable=hist_var, width=6, bg=dark["btn"], fg=dark["text"],
             buttonbackground=dark["btn"], relief="flat", highlightthickness=0)
        _row(body2, "基准保留版本数:", hist_spin)
        b_ops = tk.Frame(body2, bg=dark["card"])
        b_ops.pack(fill="x", pady=6)
        self._mk_button(b_ops, "备份当前基准", self._backup_current, small_adapt=True).pack(side="left", padx=(0, 8))
        self._mk_button(b_ops, "深层扫描", self._manual_deep_scan, small_adapt=True).pack(side="left", padx=(0, 8))
        self._mk_button(b_ops, "历史版本管理", self._show_history, small_adapt=True).pack(side="left", padx=(0, 8))
        self._mk_button(b_ops, "查看基准说明", self._open_baseline_download, small_adapt=True).pack(side="left", padx=(0, 8))
        self._mk_button(b_ops, "从文件加载基准", lambda: self._load_baseline_from_file(self.root), small_adapt=True).pack(side="left")

        # ===== 节3：权限 =====
        sec3, body3 = self._mk_card(content, "权限")
        perm_var = tk.StringVar(value=cfg.get("default_permission", "t"))
        audit_level_var = tk.StringVar(value=cfg.get("audit_level", "normal"))
        _row(body3, "默认权限级别:", self._mk_radio_row(body3, perm_var,
             [("user", "普通用户"), ("administrator", "管理员"), ("system", "SYSTEM"), ("t", "TI(推荐)")]))
        tk.Label(body3, text="低于 TI 权限可能导致 UserChoice 恢复失败，保护不生效",
                 font=("微软雅黑", 8), fg=dark["error"], bg=dark["card"], anchor="w").pack(fill="x")
        _row(body3, "记录级别:", self._mk_radio_row(body3, audit_level_var,
             [("minimal", "极简"), ("normal", "普通"), ("detailed", "详细"), ("full", "完整")]))
        a_ops = tk.Frame(body3, bg=dark["card"])
        a_ops.pack(fill="x", pady=6)
        self._mk_button(a_ops, "导出审计日志", self._export_audit_log, small_adapt=True).pack(side="left", padx=(0, 8))
        self._mk_button(a_ops, "查看运行日志", lambda: self._select_nav("log"), small_adapt=True).pack(side="left")
        tk.Label(body3, text="审计日志记录：进程名/路径/命令行/数字签名/父进程/时间/注册表路径/旧值/新值",
                 font=("微软雅黑", 8), fg=dark["text3"], bg=dark["card"], anchor="w").pack(fill="x")

        # ===== 节4：白名单 =====
        sec4, body4 = self._mk_card(content, "白名单")
        tk.Label(body4, text="白名单扩展名（任意程序对该扩展名的操作自动允许）",
                 font=("微软雅黑", 9, "bold"), fg=dark["text2"], bg=dark["card"], anchor="w").pack(fill="x")
        ext_list_frame = tk.Frame(body4, bg=dark["card"])
        ext_list_frame.pack(fill="x", pady=4)
        ext_listbox = tk.Listbox(ext_list_frame, font=("微软雅黑", 9), height=5,
                                 bg=dark["btn"], fg=dark["text"],
                                 selectbackground=dark["nav_sel"], relief="flat", highlightthickness=0)
        ext_listbox.pack(side="left", fill="x", expand=True)
        tk.Scrollbar(ext_list_frame, orient="vertical", command=ext_listbox.yview).pack(side="right", fill="y")
        ext_listbox.config(yscrollcommand=lambda *a: None)
        for e in cfg.get("whitelist_exts", []):
            ext_listbox.insert(tk.END, e)
        ext_entry = tk.Entry(body4, font=("微软雅黑", 9), bg=dark["btn"], fg=dark["text"],
                             relief="flat", highlightthickness=0, insertbackground=dark["text"])
        ext_entry.pack(fill="x", pady=4)
        def add_whitelist_ext():
            val = ext_entry.get().strip().lower()
            if val and val not in [ext_listbox.get(i).lower() for i in range(ext_listbox.size())]:
                ext_listbox.insert(tk.END, val)
                ext_entry.delete(0, tk.END)
                save_settings()
        def del_whitelist_ext():
            sel = ext_listbox.curselection()
            if sel:
                ext_listbox.delete(sel[0])
                save_settings()
        ext_ops = tk.Frame(body4, bg=dark["card"])
        ext_ops.pack(fill="x")
        self._mk_button(ext_ops, "添加", add_whitelist_ext, width=8, small_adapt=True).pack(side="left", padx=(0, 8))
        self._mk_button(ext_ops, "删除选中", del_whitelist_ext, width=10, small_adapt=True).pack(side="left")

        tk.Label(body4, text="白名单程序（程序对任意扩展名的操作自动同意）",
                 font=("微软雅黑", 9, "bold"), fg=dark["text2"], bg=dark["card"], anchor="w").pack(fill="x", pady=(12, 0))
        prog_list_frame = tk.Frame(body4, bg=dark["card"])
        prog_list_frame.pack(fill="x", pady=4)
        prog_listbox = tk.Listbox(prog_list_frame, font=("微软雅黑", 9), height=5,
                                  bg=dark["btn"], fg=dark["text"],
                                  selectbackground=dark["nav_sel"], relief="flat", highlightthickness=0)
        prog_listbox.pack(side="left", fill="x", expand=True)
        tk.Scrollbar(prog_list_frame, orient="vertical", command=prog_listbox.yview).pack(side="right", fill="y")
        prog_listbox.config(yscrollcommand=lambda *a: None)
        for p in cfg.get("whitelist_programs", []):
            prog_listbox.insert(tk.END, p)
        prog_entry = tk.Entry(body4, font=("微软雅黑", 9), bg=dark["btn"], fg=dark["text"],
                              relief="flat", highlightthickness=0, insertbackground=dark["text"])
        prog_entry.pack(fill="x", pady=4)
        def add_whitelist_prog():
            val = prog_entry.get().strip()
            if val and val not in [prog_listbox.get(i) for i in range(prog_listbox.size())]:
                prog_listbox.insert(tk.END, val)
                prog_entry.delete(0, tk.END)
                save_settings()
        def del_whitelist_prog():
            sel = prog_listbox.curselection()
            if sel:
                prog_listbox.delete(sel[0])
                save_settings()
        prog_ops = tk.Frame(body4, bg=dark["card"])
        prog_ops.pack(fill="x")
        self._mk_button(prog_ops, "添加", add_whitelist_prog, width=8, small_adapt=True).pack(side="left", padx=(0, 8))
        self._mk_button(prog_ops, "删除选中", del_whitelist_prog, width=10, small_adapt=True).pack(side="left", padx=(0, 8))
        self._mk_button(prog_ops, "从本机程序选择", lambda: self._pick_program(
            lambda name: self._add_prog_to_listbox(prog_listbox, name)),
            small_adapt=True).pack(side="left")
        tk.Label(body4, text="识别对象为程序名（进程名），可从本机已安装程序或当前运行进程中选择，无需手动输入",
                 font=("微软雅黑", 8), fg=dark["text3"], bg=dark["card"], anchor="w", justify="left").pack(fill="x")

        # ===== 节4.5：进程黑名单 =====
        sec4b, body4b = self._mk_card(content, "进程黑名单")
        tk.Label(body4b, text="黑名单中的进程被识别为篡改者时将遭到强终止（进程名 / 路径）",
                 font=("微软雅黑", 9, "bold"), fg=dark["text2"], bg=dark["card"], anchor="w").pack(fill="x")
        bl_list_frame = tk.Frame(body4b, bg=dark["card"])
        bl_list_frame.pack(fill="x", pady=4)
        self._bl_listbox = tk.Listbox(bl_list_frame, font=("微软雅黑", 9), height=5,
                                      bg=dark["btn"], fg=dark["text"],
                                      selectbackground=dark["nav_sel"], relief="flat",
                                      highlightthickness=0)
        self._bl_listbox.pack(side="left", fill="x", expand=True)
        tk.Scrollbar(bl_list_frame, orient="vertical", command=self._bl_listbox.yview).pack(side="right", fill="y")
        self._bl_listbox.config(yscrollcommand=lambda *a: None)
        bl_ops = tk.Frame(body4b, bg=dark["card"])
        bl_ops.pack(fill="x", pady=4)
        self._mk_button(bl_ops, "从本机程序选择", lambda: self._pick_program(
            lambda name: self._add_blacklist_program(name)),
            small_adapt=True).pack(side="left", padx=(0, 8))
        self._mk_button(bl_ops, "移除选中", self._remove_blacklist_program, width=10, small_adapt=True).pack(side="left", padx=(0, 8))
        self._mk_button(bl_ops, "清空黑名单", self._clear_blacklist_ui, width=10, small_adapt=True).pack(side="left")
        tk.Label(body4b, text="提示：自动拉黑（关联篡改≥3次）与手动添加均保存在文件中，重启后仍然生效",
                 font=("微软雅黑", 8), fg=dark["text3"], bg=dark["card"], anchor="w", justify="left").pack(fill="x")
        self._refresh_blacklist_ui()

        # ===== 节5：更改记录 =====
        sec5, body5 = self._mk_card(content, "更改记录")
        list_frame = tk.Frame(body5, bg=dark["card"])
        list_frame.pack(fill="x")
        history_listbox = tk.Listbox(list_frame, font=("微软雅黑", 8), height=8,
                                     bg=dark["btn"], fg=dark["text"],
                                     selectbackground=dark["nav_sel"], relief="flat", highlightthickness=0)
        history_listbox.pack(fill="x")
        detail_text = tk.Text(body5, font=("微软雅黑", 8), height=6, wrap="word",
                              bg=dark["btn"], fg=dark["text"], relief="flat", highlightthickness=0)
        detail_text.pack(fill="x", pady=(6, 0))
        detail_text.configure(state="normal")
        h_ops = tk.Frame(body5, bg=dark["card"])
        h_ops.pack(fill="x", pady=6)

        def refresh_history():
            history_listbox.delete(0, tk.END)
            records = self.change_history.get_records(limit=100)
            for rec in reversed(records):
                action_text = {"user_consent": "用户同意", "auto_blocked": "自动阻止", "detected_only": "仅检测"}.get(rec["action"], rec["action"])
                history_listbox.insert(tk.END, f"{rec['timestamp']}  {rec['ext']}  [{rec['tamperer']}]  {action_text}  {rec['result']}")

        def show_history_detail(evt):
            sel = history_listbox.curselection()
            if not sel:
                return
            records = self.change_history.get_records(limit=100)
            idx = len(records) - 1 - sel[0]
            if idx < 0 or idx >= len(records):
                return
            rec = records[idx]
            detail_text.delete("1.0", tk.END)
            detail_text.insert(tk.END, f"时间: {rec['timestamp']}\n")
            detail_text.insert(tk.END, f"扩展名: {rec['ext']}\n")
            detail_text.insert(tk.END, f"篡改者: {rec['tamperer']}\n")
            detail_text.insert(tk.END, f"操作: {rec['action']}  结果: {rec['result']}\n")
            detail_text.insert(tk.END, "更改详情:\n")
            for ch in rec.get("changes", []):
                detail_text.insert(tk.END, f"  {ch['item']}: {ch['old']} → {ch['new']}\n")

        def check_current_status():
            sel = history_listbox.curselection()
            if not sel:
                return
            records = self.change_history.get_records(limit=100)
            idx = len(records) - 1 - sel[0]
            if idx < 0 or idx >= len(records):
                return
            ext = records[idx]["ext"]
            bl = self.baseline_mgr.baseline.get(ext, {})
            detail_text.delete("1.0", tk.END)
            detail_text.insert(tk.END, f"=== {ext} 当前7项状态 ===\n\n")
            item_order = ["userchoice_progid", "userchoice_hash", "hkcr_ext", "hkcu_ext", "hklm_ext", "hkcr_command", "hkcu_command"]
            mismatch_count = 0
            for key in item_order:
                bl_item = bl.get(key, {})
                label = ProtectionEngine.ITEM_LABELS.get(key, key)
                bl_val = bl_item.get("value")
                cur_val = None
                if bl_item:
                    root_name = bl_item.get("root")
                    if root_name is None:
                        continue
                    root = ROOT_MAP.get(str(root_name))
                    path = bl_item.get("path", "")
                    name = bl_item.get("name", "")
                    if root and path:
                        try:
                            cur_val, _ = reg_read_value(root, path, name)
                        except Exception:
                            cur_val = None
                if key in ("userchoice_progid", "userchoice_hash") and cur_val is None:
                    uc_path = f"{USERCHOICE_BASE}\\{ext}\\UserChoice"
                    val_name = "ProgId" if key == "userchoice_progid" else "Hash"
                    try:
                        cur_val, _ = reg_read_value(HKCU, uc_path, val_name)
                    except Exception:
                        pass
                is_diff = (bl_val != cur_val) and not (bl_val is None and cur_val is None)
                if is_diff:
                    mismatch_count += 1
                    status = "✗ 异常"
                    color_tag = "diff"
                else:
                    status = "✓ 正常"
                    color_tag = "same"
                detail_text.insert(tk.END, f"[{status}] {label}\n", color_tag)
                detail_text.insert(tk.END, f"    基准: {repr(bl_val)}\n")
                detail_text.insert(tk.END, f"    当前: {repr(cur_val)}\n\n")
            if mismatch_count == 0:
                detail_text.insert(tk.END, "结论: 全部正常（与基准一致）\n", "same")
            else:
                detail_text.insert(tk.END, f"结论: 发现 {mismatch_count} 项异常\n", "diff")
            detail_text.tag_config("same", foreground="#6CCB5F")
            detail_text.tag_config("diff", foreground="#FF99A4")
            try:
                progid = get_prog_id(ext)
                if progid:
                    name, _ = identify_tamperer(progid)
                    detail_text.insert(tk.END, f"\n当前默认打开方式: {progid}" + (f" ({name})" if name else ""))
                else:
                    detail_text.insert(tk.END, f"\n当前默认打开方式: 系统默认（无UserChoice）")
            except Exception as e:
                detail_text.insert(tk.END, f"\n获取打开方式失败: {e}")

        def clear_history():
            if messagebox.askyesno("确认", "确定清空所有更改记录？"):
                self.change_history.clear()
                refresh_history()
                detail_text.delete("1.0", tk.END)

        history_listbox.bind("<<ListboxSelect>>", show_history_detail)
        # 隐藏命令：EXIT-TXZ(强制退出) / LOG(打开日志文件) / TEST WINDOWS-TOOMUCH(弹窗压力测试)
        def _check_exit_code(evt):
            content = detail_text.get("1.0", tk.END).strip().upper()
            if "EXIT-TXZ" in content:
                try:
                    self.baseline_mgr.save()
                except Exception:
                    pass
                try:
                    if self.monitor:
                        self.monitor.stop()
                except Exception:
                    pass
                try:
                    self.root.destroy()
                except Exception:
                    pass
                os._exit(0)
                return "break"
            elif content == "LOG" or content.startswith("LOG"):
                try:
                    import subprocess
                    if os.path.exists(LOG_FILE):
                        subprocess.Popen(['notepad.exe', LOG_FILE])
                    else:
                        messagebox.showinfo(APP_NAME, "日志文件不存在")
                except Exception as e:
                    messagebox.showerror(APP_NAME, f"打开日志失败: {e}")
                return "break"
            elif "TEST WINDOWS-TOOMUCH" in content or "TEST WINDOWS TOOMUCH" in content:
                self._append_log("=== 弹窗压力测试开始 ===", "warn")
                def make_mock(ext, progid):
                    return [("userchoice_progid", "AppX43hnxtbyyps62jhe9sqpdzxn1790zetc", progid, None)]
                mock_result = (3, 0, [])
                items1 = [(e, make_mock(e, "BaiduNetdiskImageViewerAssociations"), mock_result)
                          for e in [".png", ".jpg", ".jpeg", ".bmp", ".gif"]]
                self._show_batch_popup("百度网盘", items1)
                self._append_log("  [模拟] 批量弹窗1: 百度网盘篡改5个图片格式", "info")
                items2 = [(e, make_mock(e, "WPS.Document"), mock_result)
                          for e in [".doc", ".docx", ".xls", ".xlsx"]]
                self.root.after(200, lambda: self._show_batch_popup("WPS Office", items2))
                self._append_log("  [模拟] 批量弹窗2: WPS篡改4个办公格式", "info")
                self.root.after(400, lambda: self._append_log("  [模拟] 持续篡改提示: .pdf 被持续篡改（已静默阻止）", "warn"))
                self.root.after(600, lambda: self._show_single_notification(".pdf", make_mock(".pdf", "Acrobat.Document"), mock_result))
                self.root.after(800, lambda: self._show_single_notification(".mp4", make_mock(".mp4", "PotPlayer"), mock_result))
                self.root.after(1000, lambda: self._show_single_notification(".mp3", make_mock(".mp3", "QQMusic"), mock_result))
                self._append_log("  [模拟] 正常弹窗队列: .pdf .mp4 .mp3", "info")
                self._append_log("=== 弹窗压力测试已触发 ===", "success")
                return "break"
        detail_text.bind("<KeyRelease-Return>", _check_exit_code)
        self._mk_button(h_ops, "刷新", refresh_history, width=8, small_adapt=True).pack(side="left", padx=(0, 8))
        self._mk_button(h_ops, "检测当前状态", check_current_status, width=12, small_adapt=True).pack(side="left", padx=(0, 8))
        self._mk_button(h_ops, "清空记录", clear_history, width=8, small_adapt=True).pack(side="left")
        refresh_history()

        # ===== 节6：关于 =====
        sec6, body6 = self._mk_card(content, "关于")
        tk.Label(body6, text=f"{APP_NAME} v{APP_VERSION}\n阻止第三方软件私自篡改文件扩展名默认打开方式\n保护7项注册表位置，支持基准校准与自动恢复",
                 font=("微软雅黑", 9), fg=dark["text2"], bg=dark["card"], anchor="w", justify="left").pack(fill="x")
        tk.Label(body6, text="GitHub: https://github.com/TXZDMM/OPSTController",
                 font=("微软雅黑", 9), fg=dark["info"], bg=dark["card"], anchor="w").pack(fill="x", pady=(4, 0))

        # ===== 底部：设置自动保存（无保存/放弃按钮，修改即生效） =====
        save_row = tk.Frame(content, bg=dark["bg"])
        save_row.pack(fill="x", pady=10)
        self._last_perm_prompted = None

        def save_settings(ask_perm=False):
            old_perm = cfg.get("default_permission", "t")
            new_perm = perm_var.get()
            cfg["history_versions"] = hist_var.get()
            cfg["default_permission"] = new_perm
            cfg["autostart"] = autostart_var.get()
            cfg["show_popup"] = popup_var.get()
            cfg["operation_mode"] = mode_var.get() if mode_var.get() in OPERATION_MODES else "normal"
            cfg["audit_level"] = audit_level_var.get() if audit_level_var.get() in AUDIT_LEVELS else "normal"
            self.change_history.set_audit_level(cfg["audit_level"])
            _save_timeout = block_var.get()
            if _save_timeout < 1: _save_timeout = 1
            elif _save_timeout > 180: _save_timeout = 180
            cfg["block_timeout"] = 1 if not popup_var.get() else _save_timeout
            cfg["clear_log_on_start"] = clearlog_var.get()
            cfg["persistent_no_kill"] = nokill_var.get()
            cfg["batch_popup_mode"] = batch_popup_var.get()
            cfg["whitelist_exts"] = [ext_listbox.get(i) for i in range(ext_listbox.size())]
            cfg["whitelist_programs"] = [prog_listbox.get(i) for i in range(prog_listbox.size())]
            self.baseline_mgr.save_config()
            if autostart_var.get():
                if not is_autostart_set():
                    try:
                        add_to_autostart()
                    except Exception:
                        pass
            else:
                try:
                    remove_from_autostart()
                except Exception:
                    pass
            self._append_log("设置已自动保存", "success")
            # 权限变更：询问是否立即重启生效（每次变化仅询问一次）
            if new_perm != old_perm and ask_perm and self._last_perm_prompted != new_perm:
                self._last_perm_prompted = new_perm
                perm_labels = {"user": "普通用户", "administrator": "管理员", "system": "SYSTEM", "t": "TI"}
                new_label = perm_labels.get(new_perm, new_perm)
                if messagebox.askyesno(APP_NAME, f"运行权限已自动保存为【{new_label}】。\n\n是否立即重启程序使设置生效？"):
                    self._restart_app()

        def _restart_app():
            try:
                if self.monitor is not None:
                    self.monitor.stop()
                try:
                    self.baseline_mgr.save()
                except Exception:
                    pass
                import subprocess
                exe_path = sys.executable if getattr(sys, 'frozen', False) else os.path.abspath(sys.argv[0])
                subprocess.Popen([exe_path, '--restart'], shell=False)
                os._exit(0)
            except Exception as e:
                messagebox.showerror(APP_NAME, f"重启失败: {e}\n请手动重启程序。")

        # ===== 自动保存绑定：任何设置修改立即写入文件（无需点击保存） =====
        self._auto_save_fn = save_settings
        self._settings_page_ready = True
        for _v in (autostart_var, popup_var, clearlog_var, nokill_var,
                   batch_popup_var, mode_var, audit_level_var):
            _v.trace_add("write", lambda *a: save_settings(ask_perm=False))
        perm_var.trace_add("write", lambda *a: save_settings(ask_perm=True))
        for _sb in (block_spin, hist_spin):
            _sb.configure(command=lambda: save_settings(ask_perm=False))

        tk.Label(save_row, text="* 设置修改后自动保存；运行权限更改需重启生效", font=("微软雅黑", 8),
                 fg=dark["text3"], bg=dark["bg"]).pack(side="right")
    def _mk_radio_row(self, parent, var, options):
        """创建横向单选按钮组，返回容器 frame"""
        frame = tk.Frame(parent, bg=self.C["card"])
        for val, label in options:
            rb = tk.Radiobutton(frame, text=label, variable=var, value=val,
                                font=("微软雅黑", 8), bg=self.C["card"], fg=self.C["text2"],
                                selectcolor=self.C["card"], activebackground=self.C["card"],
                                activeforeground=self.C["text"], highlightthickness=0, bd=0)
            rb.pack(side="left", padx=4)
        return frame

    def _init_app(self):
        # 右上角绝对真实权限状态：基于进程令牌SID + 完整性级别双重验证
        actual_status, actual_ti, actual_admin, actual_integrity, actual_sid = get_real_permission_detail()
        status_text = actual_status
        if actual_ti:
            fg = "#2ecc71"
            level = "success"
        elif actual_admin:
            fg = "#f39c12"
            level = "warn"
        else:
            fg = "#e67e22"
            level = "warn"

        self.ti_status = status_text
        display_text = "权限：" + status_text + " [" + actual_integrity + "]"
        self.priv_label.config(text=display_text, fg=fg)
        try:
            self._perm_detail_label.config(text=f"{display_text}\nSID: {actual_sid}")
        except Exception:
            pass
        self._append_log("当前真实权限：" + status_text + "，完整性级别：" + actual_integrity + "，SID：" + actual_sid, level)
        if self.privilege_failure_detail:
            self._append_log("提权失败原因：" + self.privilege_failure_detail, "error")
            self._append_log("提示：当前进程未真实取得 TrustedInstaller/SYSTEM token，程序仅保留当前真实 token。", "warn")

        # 启动提示
        self._append_log("按钮说明：启动保护=开启实时监控 | 停止保护=暂停监控 | 备份当前=以当前状态保存基准 | 深层扫描=全量校验 | 异常修复=工具面板(历史基准/解除锁定/重置状态) | 设置=配置选项", "info")
        self._append_log("更改记录可在 设置→更改记录 中查看，支持检测当前状态", "info")
        if is_autostart_set():
            self._append_log("已添加到开机自启", "success")
        else:
            self._append_log("未添加到开机自启（可在设置中开启）", "warn")
        self._append_log("关闭窗口=后台常驻；完全退出请运行 停止OPSTcontroller.bat 或执行 OPSTcontroller.exe --stop", "info")

        # 每次启动清空日志
        if self.baseline_mgr.config.get("clear_log_on_start", False):
            self.log_text.configure(state="normal")
            self.log_text.delete("1.0", "end")
            self.log_text.configure(state="disabled")
            # 同时清空日志文件
            try:
                open(LOG_FILE, 'w').close()
            except OSError:
                pass

        if not self.baseline_mgr.is_initialized():
            self._show_setup()
        else:
            self._refresh_status()
            self._append_log("程序已启动，基准已加载。", "info")
            self._append_log(f"保护扩展名数量: {len(self.baseline_mgr.get_protected_extensions())}", "info")
        # 进程自我保护（仅TI/SYSTEM权限下生效；失败时已自动降级仅写DACL）
        if self.ti_elevated:
            ok, msg = protect_self_process()
            if ok:
                self._process_protected = True
                self._append_log("进程自我保护已启用：普通任务管理器无法终止本进程", "success")
                self._set_selfprotect_label(True, msg)
            else:
                self._process_protected = False
                self._append_log(f"进程自我保护启用失败: {msg}", "warn")
                self._set_selfprotect_label(False, msg)
        else:
            self._append_log("当前未提权，进程自我保护不可用。", "warn")
            self._set_selfprotect_label(False, "未提权，不可用")
        # 启动无响应监测看门狗
        self._start_watchdog()
        # 启动心跳（每2秒更新一次）
        self._heartbeat()

        # 自动开启保护
        if self.baseline_mgr.is_initialized():
            self.root.after(500, self._start_protection)

    def _show_setup(self):
        self._append_log("首次运行，需要校准基准...", "warn")
        dialog = SetupDialog(self.root, None)
        choice = dialog.show()
        if choice is None:
            self._append_log("未选择基准方式，程序将退出。", "error")
            self.root.after(500, self.root.quit)
            return

        if choice == "import":
            # 用户选择导入基准文件
            self._append_log("请选择要导入的基准文件...", "info")
            from tkinter import filedialog
            path = filedialog.askopenfilename(
                title="选择基准文件",
                filetypes=[("JSON文件", "*.json"), ("所有文件", "*.*")]
            )
            if not path:
                self._append_log("未选择文件，程序将退出。", "error")
                self.root.after(500, self.root.quit)
                return
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                # 校验
                if not isinstance(data, dict) or len(data) == 0:
                    raise ValueError("文件格式不正确")
                self.baseline_mgr.baseline = data
                self.baseline_mgr.save()
                self.baseline_mgr.config["initialized"] = True
                self.baseline_mgr.config["baseline_mode"] = "default"
                self.baseline_mgr.save_config()
                self._append_log(f"已导入基准: {os.path.basename(path)} ({len(data)}个扩展名)", "success")
                self._on_setup_done(len(data))
            except Exception as e:
                self._append_log(f"导入失败: {e}", "error")
                messagebox.showerror(APP_NAME, f"导入失败: {e}")
                self.root.after(500, self.root.quit)
            return

        mode_text = '目前方式' if choice == 'current' else '默认方式'
        if choice == 'default':
            self._append_log("以系统默认方式创建基准...", "info")
        self._append_log(f"正在创建基准（模式: {mode_text}，后台执行，请稍候）...", "info")

        def progress_cb(done, total):
            self.root.after(0, lambda: self._append_log(f"基准创建进度: {done}/{total}", "info"))

        def do_create():
            try:
                count = self.baseline_mgr.create_baseline(choice, progress_cb=progress_cb)
                self.root.after(0, lambda: self._on_setup_done(count))
            except Exception as e:
                self.root.after(0, lambda: self._append_log(f"基准创建失败: {e}", "error"))

        threading.Thread(target=do_create, daemon=True).start()

    def _on_setup_done(self, count):
        self._append_log(f"基准创建完成，共保护 {count} 个扩展名。", "success")
        self._refresh_status()
        # 首次启动：等待5秒让后台软件（如PotPlayer）完成关联注册，然后自动同步基准
        self._append_log("首次启动：等待5秒让系统稳定后自动同步基准...", "info")
        self.root.after(5000, self._first_run_auto_backup)

    def _first_run_auto_backup(self):
        """首次启动专用：自动以当前状态重建基准，捕获启动后被软件修改的关联"""
        self._append_log("正在自动同步首次启动后的关联状态...", "info")
        def do_backup():
            try:
                count = self.baseline_mgr.create_baseline("current")
                self.root.after(0, lambda: self._on_first_run_backup_done(count))
            except Exception as e:
                self.root.after(0, lambda: self._append_log(f"首次同步失败: {e}", "error"))
                self.root.after(0, lambda: self.root.after(500, self._start_protection))
        threading.Thread(target=do_backup, daemon=True).start()

    def _on_first_run_backup_done(self, count):
        self._append_log(f"首次启动基准同步完成，共保护 {count} 个扩展名。", "success")
        self._append_log("提示：如遇其他软件反复篡改关联，可在 设置-关于 中反馈。", "info")
        self._refresh_status()
        # 第二次同步：再等3秒，捕获慢启动软件的关联注册
        if not hasattr(self, '_first_sync_done'):
            self._first_sync_done = True
            self.root.after(3000, self._first_run_auto_backup2)
        else:
            self.root.after(500, self._start_protection)

    def _first_run_auto_backup2(self):
        """第二次自动同步"""
        self._append_log("正在执行第二次基准同步...", "info")
        def do_backup():
            try:
                count = self.baseline_mgr.create_baseline("current")
                self.root.after(0, lambda: self._on_first_run_backup_done(count))
            except Exception as e:
                self.root.after(0, lambda: self._append_log(f"第二次同步失败: {e}", "error"))
                self.root.after(0, lambda: self.root.after(500, self._start_protection))
        threading.Thread(target=do_backup, daemon=True).start()

    def _refresh_status(self):
        count = len(self.baseline_mgr.get_protected_extensions())
        mode = self.baseline_mgr.config.get("baseline_mode", "-")
        mode_text = "目前方式" if mode == "current" else "默认方式" if mode == "default" else "-"
        btime = self.baseline_mgr.config.get("baseline_time", "-")
        self.ext_count_label.config(text=f"保护扩展名：{count}")
        self.bottom_label.config(text=f"基准模式: {mode_text} | 基准时间: {btime}")

    def _start_protection(self):
        if not self.baseline_mgr.is_initialized():
            messagebox.showwarning(APP_NAME, "请先创建基准！")
            return
        if self.monitor and self.monitor.is_alive():
            return
        self.monitor = MonitorThread(
            self.engine, self.baseline_mgr,
            popup_callback=self._show_notification,
            log_callback=self._append_log,
            root=self.root,
            process_enforcer=self.process_enforcer
        )
        self.monitor.start()
        self.engine.paused = False
        self.status_label.config(text="● 状态：保护中", fg="#2ecc71")
        self.btn_start.config(state="disabled")
        self.btn_stop.config(state="normal")
        self._append_log("实时保护已启动。", "success")

    def _stop_protection(self):
        if self.monitor:
            self.monitor.stop()
            # 等待监控线程安全退出（最多3秒），避免竞争
            try:
                self.monitor.join(timeout=3)
            except Exception:
                pass
            self.monitor = None
        self.status_label.config(text="● 状态：已停止", fg="#e74c3c")
        self.btn_start.config(state="normal")
        self.btn_stop.config(state="disabled")
        self._append_log("实时保护已停止。", "warn")

    def _heartbeat(self):
        """主线程心跳：每2秒更新一次时间戳，证明主线程响应正常"""
        if self._exiting:
            return
        self._heartbeat_time = time.time()
        self.root.after(2000, self._heartbeat)

    def _start_watchdog(self):
        """启动看门狗线程：监测主线程是否无响应，超时则自动重启"""
        self._watchdog_stop.clear()
        self._watchdog_thread = threading.Thread(target=self._watchdog_loop, daemon=True)
        self._watchdog_thread.start()
        self._append_log("无响应监测已启动（超时30秒自动重启）", "info")

    def _watchdog_loop(self):
        """看门狗循环：每5秒检查一次主线程心跳（30秒超时自动重启）；
        同时监测监控线程周期心跳，卡死/死亡则告警并重启监控（防保护静默失效）"""
        while not self._watchdog_stop.is_set():
            time.sleep(5)
            if self._exiting:
                break
            elapsed = time.time() - self._heartbeat_time
            if elapsed > 30:
                logger.error(f"看门狗：主线程无响应{elapsed:.1f}秒，执行自动重启")
                try:
                    self._append_log(f"检测到程序无响应（{elapsed:.1f}秒），正在自动重启...", "error")
                except Exception:
                    pass
                # 自动重启（直接启动，不经 cmd 中间层，避免句柄继承导致 _MEI 清理失败）
                try:
                    import subprocess
                    exe_path = sys.executable if getattr(sys, 'frozen', False) else os.path.abspath(sys.argv[0])
                    subprocess.Popen([exe_path, '--restart'], shell=False)
                except Exception:
                    pass
                time.sleep(1)
                os._exit(1)
                break
            # 监控线程心跳检查：保护静默失效检测
            mon = self.monitor
            if mon is not None:
                if not mon.is_alive():
                    log_event("SYSTEM", "监控", "异常", "监控线程已退出，保护已静默失效，正在重启...")
                    self._restart_monitor("监控线程已退出")
                elif time.time() - mon.last_cycle_ts > 30:
                    log_event("SYSTEM", "监控", "异常", f"监控线程卡死{time.time()-mon.last_cycle_ts:.0f}秒无心跳，正在重启...")
                    self._restart_monitor("监控线程卡死")

    def _restart_monitor(self, reason):
        """重启监控线程（幂等）：安全停止旧线程后重新创建"""
        try:
            old = self.monitor
            if old is not None:
                old._stop_event.set()
                try:
                    old.join(timeout=3)
                except Exception:
                    pass
            self.monitor = MonitorThread(
                self.engine, self.baseline_mgr,
                popup_callback=self._show_notification,
                log_callback=self._append_log,
                root=self.root
            )
            self.monitor.start()
            self._append_log(f"监控线程已重启（原因：{reason}）", "warn")
            log_event("SYSTEM", "监控", "重启", f"原因={reason}")
        except Exception as e:
            self._append_log(f"监控线程重启失败: {e}", "error")
            log_event("SYSTEM", "监控", "重启失败", str(e))

    def _stop_watchdog(self):
        """停止看门狗"""
        self._watchdog_stop.set()

    def _hide_to_background(self):
        """关闭按钮：隐藏窗口，后台继续保护"""
        self.root.withdraw()
        self._append_log("主窗口已隐藏，后台保护持续运行。再次运行程序可恢复窗口。", "info")

    def _show_main_window(self):
        """从后台恢复显示主窗口"""
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()
        self.root.attributes("-topmost", True)
        self.root.after(500, lambda: self.root.attributes("-topmost", False))

    def _check_exit_event(self):
        """定期检查跨进程信号：退出信号 + 显示窗口信号"""
        if self._exiting:
            return
        # 退出信号
        if check_exit_event(self.exit_event):
            self._append_log("收到退出信号，正在关闭...", "warn")
            self._exit_program()
            return
        # 显示窗口信号（第二个实例双击时触发）
        if check_exit_event(self.show_event):
            self._show_main_window()
        self.root.after(500, self._check_exit_event)

    def _exit_program(self):
        """优雅退出程序：停止监控，保存，关闭"""
        if self._exiting:
            return
        self._exiting = True
        self._stop_watchdog()
        self._append_log("正在退出程序...", "info")
        # 停止监控线程
        if self.monitor is not None and self.monitor.is_alive():
            try:
                self.monitor.stop()
            except Exception:
                pass
        # 关闭事件句柄
        try:
            if self.exit_event:
                _CloseHandle(self.exit_event)
            if self.show_event:
                _CloseHandle(self.show_event)
        except Exception:
            pass
        # 保存基准
        try:
            self.baseline_mgr.save()
        except Exception:
            pass
        self._append_log("程序已退出。", "info")
        # 销毁主窗口后强制退出进程，确保后台线程也终止。
        # 延迟 3.5 秒：给安全软件完成对 PyInstaller _MEI 解压目录的扫描，
        # 否则 bootloader 退出时清理临时目录会因文件被锁弹
        # "Failed to remove temporary directory" Warning。
        def _force_exit():
            try:
                self.root.destroy()
            except Exception:
                pass
            import os
            # 退出前最后一次尝试清理本进程残留 _MEI（当前进程已无文件句柄）
            try:
                cur_mei = os.path.normcase(getattr(sys, '_MEIPASS', '') or '')
                for d in glob.glob(os.path.join(tempfile.gettempdir(), "_MEI*")):
                    try:
                        if cur_mei and os.path.normcase(os.path.abspath(d)) == cur_mei:
                            continue
                        shutil.rmtree(d, ignore_errors=True)
                    except Exception:
                        pass
            except Exception:
                pass
            os._exit(0)
        self.root.after(3500, _force_exit)

    def _backup_current(self):
        """以当前状态备份为新基准，支持对比选择部分更新"""
        if not self.baseline_mgr.is_initialized():
            messagebox.showwarning(APP_NAME, "请先创建基准！")
            return
        # 先扫描差异
        self._append_log("正在扫描当前状态与基准的差异...", "info")
        inconsistencies, new_exts = self.engine.deep_scan()
        if not inconsistencies and not new_exts:
            messagebox.showinfo(APP_NAME, "当前状态与基准完全一致，无需更新。")
            return
        # 弹出对比选择窗口
        self._show_backup_selector(inconsistencies, new_exts)

    def _show_backup_selector(self, inconsistencies, new_exts):
        """基准对比选择窗口：用户勾选要更新的扩展名"""
        win = tk.Toplevel(self.root)
        win.title("基准对比 - 选择更新项")
        win.geometry("680x560")
        win.transient(self.root)
        win.grab_set()

        tk.Label(win, text=f"发现 {len(inconsistencies)} 个扩展名有差异，{len(new_exts)} 个新扩展名。勾选要更新的项：",
                 font=("微软雅黑", 9), wraplength=640, justify="left").pack(anchor="w", padx=10, pady=8)

        # 全选/取消全选
        btn_bar = tk.Frame(win)
        btn_bar.pack(fill="x", padx=10)
        check_vars = {}

        def select_all():
            for v in check_vars.values():
                v.set(True)

        def deselect_all():
            for v in check_vars.values():
                v.set(False)

        tk.Button(btn_bar, text="全选", command=select_all, font=("微软雅黑", 9), width=8).pack(side="left", padx=2)
        tk.Button(btn_bar, text="取消全选", command=deselect_all, font=("微软雅黑", 9), width=8).pack(side="left", padx=2)

        # 差异列表（带滚动条）
        list_frame = tk.Frame(win)
        list_frame.pack(fill="both", expand=True, padx=10, pady=8)
        canvas = tk.Canvas(list_frame)
        scrollbar = tk.Scrollbar(list_frame, orient="vertical", command=canvas.yview)
        scroll_frame = tk.Frame(canvas)
        scroll_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scroll_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # 显示差异扩展名
        row = 0
        for ext, mismatches in inconsistencies.items():
            var = tk.BooleanVar(value=True)
            check_vars[ext] = var
            detail_parts = []
            for key, bl_val, cur_val, _ in mismatches[:3]:
                label = ProtectionEngine.ITEM_LABELS.get(key, key)
                detail_parts.append(f"{label}:{bl_val}→{cur_val}")
            detail = "; ".join(detail_parts)
            if len(mismatches) > 3:
                detail += f" 等{len(mismatches)}项"
            tk.Checkbutton(scroll_frame, text=f"{ext}  {detail}", variable=var,
                           font=("微软雅黑", 8), wraplength=600, justify="left").grid(row=row, column=0, sticky="w", padx=5, pady=1)
            row += 1
        # 新扩展名
        for ext in new_exts:
            var = tk.BooleanVar(value=True)
            check_vars[ext] = var
            tk.Checkbutton(scroll_frame, text=f"{ext}  [新扩展名，基准中不存在]", variable=var,
                           font=("微软雅黑", 8), fg="#27ae60").grid(row=row, column=0, sticky="w", padx=5, pady=1)
            row += 1

        # 底部按钮
        bottom = tk.Frame(win)
        bottom.pack(fill="x", padx=10, pady=8)

        def confirm_backup():
            selected = [ext for ext, v in check_vars.items() if v.get()]
            if not selected:
                messagebox.showwarning(APP_NAME, "请至少选择一个扩展名！")
                return
            win.destroy()
            # 暂停监控
            was_running = self.monitor and self.monitor.is_alive()
            if was_running and self.monitor is not None:
                self.monitor.pause()
                time.sleep(0.5)
            self._append_log(f"正在更新 {len(selected)} 个扩展名的基准...", "info")

            def do_partial_backup():
                try:
                    count = self.baseline_mgr.update_selected_extensions(selected)
                    self.root.after(0, lambda: self._on_backup_done(count, was_running))
                except Exception as e:
                    self.root.after(0, lambda: self._on_backup_failed(str(e), was_running))

            threading.Thread(target=do_partial_backup, daemon=True).start()

        tk.Button(bottom, text="确认更新选中项", command=confirm_backup, font=("微软雅黑", 10, "bold"),
                  bg="#27ae60", fg="white", width=15).pack(side="right", padx=5)
        tk.Button(bottom, text="取消", command=win.destroy, font=("微软雅黑", 10), width=8).pack(side="right", padx=5)

    def _on_backup_done(self, count, was_running):
        self._refresh_status()
        self._append_log(f"备份完成，共 {count} 个扩展名。", "success")
        if was_running and self.monitor is not None:
            self.monitor.resume()
            self._append_log("监控已恢复。", "info")
        messagebox.showinfo(APP_NAME,
            f"备份完成，共保护 {count} 个扩展名。\n\n"
            "如遇bug，请点击停止守护，停止守护后退出程序守护将不会继续。\n"
            "守护启动时，关闭主窗口程序将继续在后台守护。")

    def _on_backup_failed(self, error, was_running):
        self._append_log(f"备份失败: {error}", "error")
        if was_running and self.monitor is not None:
            self.monitor.resume()
        messagebox.showerror(APP_NAME, f"备份失败: {error}")

    def _show_deep_scan_result(self, inconsistencies, new_exts, protecting):
        """深层扫描报告对话框：正式报告风格，含统计摘要、分类列表、详情查看、导出报告"""
        import time as _time
        scan_time = _time.strftime("%Y-%m-%d %H:%M:%S")

        win = tk.Toplevel(self.root)
        win.title("深层扫描报告")
        win.geometry("880x680")
        win.transient(self.root)
        win.grab_set()
        win.update_idletasks()
        sw, sh = win.winfo_screenwidth(), win.winfo_screenheight()
        win.geometry(f"880x680+{(sw-880)//2}+{(sh-680)//2}")

        # ===== 标题栏 =====
        title_frame = tk.Frame(win, bg="#1a5276", height=70)
        title_frame.pack(fill="x")
        title_frame.pack_propagate(False)
        tk.Label(title_frame, text="深层扫描报告", font=("微软雅黑", 16, "bold"),
                 bg="#1a5276", fg="white").pack(side="left", padx=20, pady=10)
        tk.Label(title_frame, text=f"扫描时间：{scan_time}\n版本：v{APP_VERSION}",
                 font=("微软雅黑", 9), bg="#1a5276", fg="#aed6f1", justify="right").pack(side="right", padx=20, pady=10)

        # ===== 统计摘要栏 =====
        stats_frame = tk.Frame(win, bg="#f8f9fa", bd=1, relief="solid")
        stats_frame.pack(fill="x", padx=10, pady=8)

        # 按类型统计
        type_counts = {}
        for ext, mismatches in inconsistencies.items():
            for key, _, _, _ in mismatches:
                type_counts[key] = type_counts.get(key, 0) + 1

        total_issues = len(inconsistencies)
        total_new = len(new_exts)

        stat_items = [
            ("不一致项", str(total_issues), "#e74c3c"),
            ("新扩展名", str(total_new), "#27ae60"),
            ("无效关联", str(type_counts.get("invalid_association", 0)), "#e67e22"),
            ("ProgId变更", str(type_counts.get("userchoice_progid", 0) + type_counts.get("assoc_progid", 0)), "#3498db"),
            ("命令变更", str(sum(v for k,v in type_counts.items() if "command" in k.lower())), "#9b59b6"),
            ("Hash变更", str(sum(v for k,v in type_counts.items() if "hash" in k.lower())), "#1abc9c"),
        ]
        for i, (label, val, color) in enumerate(stat_items):
            cell = tk.Frame(stats_frame, bg="#f8f9fa")
            cell.grid(row=0, column=i, padx=15, pady=8)
            tk.Label(cell, text=val, font=("微软雅黑", 14, "bold"), fg=color, bg="#f8f9fa").pack()
            tk.Label(cell, text=label, font=("微软雅黑", 8), fg="#666", bg="#f8f9fa").pack()

        # ===== 列表表头 =====
        list_frame = tk.Frame(win)
        list_frame.pack(fill="both", expand=True, padx=10, pady=(0,5))

        header_frame = tk.Frame(list_frame, bg="#2c3e50")
        header_frame.pack(fill="x")
        headers = [("序号", 50), ("扩展名", 90), ("问题类型", 280), ("严重程度", 80), ("状态", 80), ("操作", 240)]
        for text, w in headers:
            tk.Label(header_frame, text=text, font=("微软雅黑", 9, "bold"), fg="white", bg="#2c3e50",
                     width=w//8, anchor="w").pack(side="left", padx=5, pady=6)

        # 滚动列表
        canvas = tk.Canvas(list_frame, highlightthickness=0)
        sb = tk.Scrollbar(list_frame, orient="vertical", command=canvas.yview)
        scroll_frame = tk.Frame(canvas)
        scroll_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0,0), window=scroll_frame, anchor="nw", width=840)
        canvas.configure(yscrollcommand=sb.set)
        canvas.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        actions = {}

        def set_action(ext, act, label):
            actions[ext] = act
            label_map = {"recover": "[恢复]", "update": "[更新]", "ignore": "[忽略]", "add": "[纳入]"}
            label.config(text=label_map.get(act, f"[{act}]"), fg="#27ae60")

        def show_detail(ext, mismatches):
            detail_win = tk.Toplevel(win)
            detail_win.title(f"不一致详情 - {ext}")
            detail_win.geometry("650x450")
            detail_win.transient(win)
            detail_win.grab_set()
            sw2, sh2 = detail_win.winfo_screenwidth(), detail_win.winfo_screenheight()
            detail_win.geometry(f"650x450+{(sw2-650)//2}+{(sh2-450)//2}")

            # 详情标题
            tk.Label(detail_win, text=f"{ext} 不一致详情", font=("微软雅黑", 12, "bold"),
                     bg="#1a5276", fg="white").pack(fill="x", pady=(0,10))

            text = tk.Text(detail_win, font=("Consolas", 9), wrap="word", padx=10, pady=10)
            text.pack(fill="both", expand=True, padx=10, pady=(0,5))
            for i, (key, bl_val, cur_val, extra) in enumerate(mismatches, 1):
                text.insert("end", f"━━━ 第 {i} 项 ━━━\n", "header")
                text.insert("end", f"  检测项：{key}\n")
                text.insert("end", f"  基准值：{bl_val}\n")
                text.insert("end", f"  当前值：{cur_val}\n")
                if extra:
                    text.insert("end", f"  补充说明：{extra}\n")
                text.insert("end", "\n")
            text.tag_config("header", foreground="#1a5276", font=("Consolas", 9, "bold"))
            text.config(state="disabled")

            tk.Button(detail_win, text="关闭", font=("微软雅黑",9), width=12,
                      command=detail_win.destroy).pack(pady=8)

        def mismatch_summary(mismatches):
            parts = []
            for key, bl_val, cur_val, extra in mismatches:
                if key == "invalid_association":
                    parts.append(f"无效关联:{extra}")
                elif "progid" in key.lower():
                    parts.append(f"ProgId:{bl_val}→{cur_val}")
                elif "command" in key.lower():
                    parts.append("命令路径变更")
                elif "hash" in key.lower():
                    parts.append("UserChoice Hash变更")
                else:
                    parts.append(key)
            return "; ".join(parts[:2]) + (f" 等{len(mismatches)}项" if len(mismatches) > 2 else "")

        def get_severity(mismatches):
            has_invalid = any(k == "invalid_association" for k,_,_,_ in mismatches)
            has_progid = any("progid" in k.lower() for k,_,_,_ in mismatches)
            if has_invalid:
                return "高", "#e74c3c"
            elif has_progid:
                return "中", "#e67e22"
            else:
                return "低", "#f39c12"

        # 不一致项列表
        row_idx = 0
        for ext, mismatches in inconsistencies.items():
            bg = "#ffffff" if row_idx % 2 == 0 else "#f8f9fa"
            row_frame = tk.Frame(scroll_frame, bg=bg)
            row_frame.pack(fill="x")

            tk.Label(row_frame, text=str(row_idx+1), font=("微软雅黑", 9), bg=bg, width=6, anchor="center").pack(side="left", padx=2, pady=4)
            tk.Label(row_frame, text=ext, font=("微软雅黑", 9, "bold"), bg=bg, width=10, anchor="w").pack(side="left", padx=2, pady=4)
            tk.Label(row_frame, text=mismatch_summary(mismatches), font=("微软雅黑", 8), bg=bg,
                     fg="#333", width=38, anchor="w", wraplength=280).pack(side="left", padx=2, pady=4)

            sev_text, sev_color = get_severity(mismatches)
            tk.Label(row_frame, text=sev_text, font=("微软雅黑", 8, "bold"), fg="white", bg=sev_color,
                     width=6).pack(side="left", padx=5, pady=4)

            status_lbl = tk.Label(row_frame, text="[待处理]", font=("微软雅黑", 8), fg="#e67e22", bg=bg, width=8)
            status_lbl.pack(side="left", padx=2, pady=4)

            btn_frame = tk.Frame(row_frame, bg=bg)
            btn_frame.pack(side="left", padx=2, pady=4)
            tk.Button(btn_frame, text="详情", font=("微软雅黑",8), width=5,
                      command=lambda e=ext,m=mismatches: show_detail(e,m)).pack(side="left", padx=1)
            tk.Button(btn_frame, text="恢复", font=("微软雅黑",8), width=5, bg="#e74c3c", fg="white",
                      command=lambda e=ext,l=status_lbl: set_action(e,"recover",l)).pack(side="left", padx=1)
            tk.Button(btn_frame, text="更新", font=("微软雅黑",8), width=5, bg="#3498db", fg="white",
                      command=lambda e=ext,l=status_lbl: set_action(e,"update",l)).pack(side="left", padx=1)
            tk.Button(btn_frame, text="忽略", font=("微软雅黑",8), width=5,
                      command=lambda e=ext,l=status_lbl: set_action(e,"ignore",l)).pack(side="left", padx=1)
            row_idx += 1

        # 新扩展名
        for ext in new_exts:
            bg = "#eafaf1" if row_idx % 2 == 0 else "#d5f5e3"
            row_frame = tk.Frame(scroll_frame, bg=bg)
            row_frame.pack(fill="x")

            tk.Label(row_frame, text=str(row_idx+1), font=("微软雅黑", 9), bg=bg, width=6, anchor="center").pack(side="left", padx=2, pady=4)
            tk.Label(row_frame, text=ext, font=("微软雅黑", 9, "bold"), bg=bg, width=10, anchor="w").pack(side="left", padx=2, pady=4)
            tk.Label(row_frame, text="新扩展名，基准中不存在", font=("微软雅黑", 8), bg=bg,
                     fg="#27ae60", width=38, anchor="w").pack(side="left", padx=2, pady=4)
            tk.Label(row_frame, text="低", font=("微软雅黑", 8, "bold"), fg="white", bg="#27ae60",
                     width=6).pack(side="left", padx=5, pady=4)

            status_lbl = tk.Label(row_frame, text="[待处理]", font=("微软雅黑", 8), fg="#e67e22", bg=bg, width=8)
            status_lbl.pack(side="left", padx=2, pady=4)

            btn_frame = tk.Frame(row_frame, bg=bg)
            btn_frame.pack(side="left", padx=2, pady=4)
            tk.Button(btn_frame, text="纳入", font=("微软雅黑",8), width=5, bg="#27ae60", fg="white",
                      command=lambda e=ext,l=status_lbl: set_action(e,"add",l)).pack(side="left", padx=1)
            tk.Button(btn_frame, text="忽略", font=("微软雅黑",8), width=5,
                      command=lambda e=ext,l=status_lbl: set_action(e,"ignore",l)).pack(side="left", padx=1)
            row_idx += 1

        # ===== 底部操作栏 =====
        bottom_frame = tk.Frame(win, bg="#ecf0f1", bd=1, relief="solid")
        bottom_frame.pack(fill="x", side="bottom", padx=10, pady=8)

        def apply_all(act):
            for ext in inconsistencies:
                actions[ext] = act
            for ext in new_exts:
                actions[ext] = "add" if act == "recover" else act
            win.destroy()

        def do_apply():
            win.destroy()

        def ignore_invalid():
            """忽略所有仅含无效关联的项"""
            count = 0
            for ext, mismatches in inconsistencies.items():
                # 仅当所有mismatch都是invalid_association时才忽略
                if all(k == "invalid_association" for k, _, _, _ in mismatches):
                    actions[ext] = "ignore"
                    count += 1
            self._append_log(f"已忽略 {count} 个纯无效关联项", "info")
            win.destroy()

        def export_report():
            try:
                from tkinter import filedialog
                path = filedialog.asksaveasfilename(defaultextension=".txt",
                    filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")],
                    initialfile=f"深层扫描报告_{scan_time.replace(':','-')}.txt")
                if not path:
                    return
                with open(path, 'w', encoding='utf-8') as f:
                    f.write("=" * 60 + "\n")
                    f.write("          OPSTcontroller 深层扫描报告\n")
                    f.write("=" * 60 + "\n")
                    f.write(f"扫描时间：{scan_time}\n")
                    f.write(f"程序版本：v{APP_VERSION}\n")
                    f.write(f"不一致项：{total_issues}\n")
                    f.write(f"新扩展名：{total_new}\n")
                    f.write("=" * 60 + "\n\n")
                    for ext, mismatches in inconsistencies.items():
                        f.write(f"【{ext}】\n")
                        for key, bl_val, cur_val, extra in mismatches:
                            f.write(f"  - {key}: 基准={bl_val} → 当前={cur_val}")
                            if extra:
                                f.write(f" ({extra})")
                            f.write("\n")
                        f.write("\n")
                    if new_exts:
                        f.write("【新扩展名】\n")
                        for ext in new_exts:
                            f.write(f"  - {ext}\n")
                messagebox.showinfo(APP_NAME, f"报告已导出至:\n{path}")
            except Exception as e:
                messagebox.showerror(APP_NAME, f"导出失败: {e}")

        def close_ignore_all():
            """关闭并忽略所有未处理项"""
            for ext in inconsistencies:
                if ext not in actions:
                    actions[ext] = "ignore"
            for ext in new_exts:
                if ext not in actions:
                    actions[ext] = "ignore"
            win.destroy()

        tk.Button(bottom_frame, text="导出报告", font=("微软雅黑",9), width=10,
                  command=export_report).pack(side="left", padx=8, pady=8)
        tk.Button(bottom_frame, text="全部恢复", font=("微软雅黑",9), width=10, bg="#e74c3c", fg="white",
                  command=lambda: apply_all("recover")).pack(side="left", padx=5, pady=8)
        tk.Button(bottom_frame, text="全部更新基准", font=("微软雅黑",9), width=12, bg="#3498db", fg="white",
                  command=lambda: apply_all("update")).pack(side="left", padx=5, pady=8)
        tk.Button(bottom_frame, text="忽略全部空值", font=("微软雅黑",9), width=12,
                  command=ignore_invalid).pack(side="left", padx=5, pady=8)
        tk.Button(bottom_frame, text="应用选择", font=("微软雅黑",10,"bold"), width=12, bg="#27ae60", fg="white",
                  command=do_apply).pack(side="right", padx=8, pady=8)
        tk.Button(bottom_frame, text="关闭（全部忽略）", font=("微软雅黑",9), width=14,
                  command=close_ignore_all).pack(side="right", padx=5, pady=8)

        win.wait_window()

        # 执行选择的操作
        recover_count = update_count = ignore_count = add_count = 0
        for ext, act in actions.items():
            if act == "recover" and ext in inconsistencies:
                s,f,dets = self.engine.recover_extension(ext, inconsistencies[ext])
                refresh_file_associations()
                recover_count += 1
                self._append_log(f"  {ext}: 已恢复", "success" if f==0 else "warn")
            elif act == "update":
                self.baseline_mgr.update_extension(ext)
                update_count += 1
                self._append_log(f"  {ext}: 已更新为当前基准", "info")
            elif act == "add":
                self.baseline_mgr.update_extension(ext)
                add_count += 1
                self._append_log(f"  {ext}: 已纳入保护", "info")
            elif act == "ignore":
                ignore_count += 1
                self._append_log(f"  {ext}: 已忽略", "info")
        self._refresh_status()
        msg = f"恢复{recover_count}项，更新{update_count}项，新增{add_count}项，忽略{ignore_count}项"
        if recover_count + update_count + add_count + ignore_count > 0:
            messagebox.showinfo(APP_NAME, f"深层扫描处理完成：\n{msg}")

    def _manual_deep_scan(self):
        if not self.baseline_mgr.is_initialized():
            messagebox.showwarning(APP_NAME, "请先创建基准！")
            return
        protecting = self.monitor is not None
        if not protecting:
            self._append_log("保护已停止，本次扫描仅检测不自动恢复。", "warn")
        self._append_log("开始深层扫描...", "info")
        self.root.update()
        inconsistencies, new_exts = self.engine.deep_scan()
        if not inconsistencies and not new_exts:
            self._append_log("深层扫描完成，未发现异常。", "success")
            messagebox.showinfo(APP_NAME, "深层扫描完成，一切正常。")
            return
        self._append_log(f"深层扫描发现 {len(inconsistencies)} 个不一致项，{len(new_exts)} 个新扩展名", "warn")
        self._show_deep_scan_result(inconsistencies, new_exts, protecting)

    def _update_baseline(self):
        if not messagebox.askyesno(APP_NAME, "确定要以当前状态更新全部基准吗？\n这将覆盖现有基准并保存历史版本。"):
            return
        mode = self.baseline_mgr.config.get("baseline_mode", "current")
        count = self.baseline_mgr.create_baseline(mode)
        self._refresh_status()
        self._append_log(f"基准已更新，共 {count} 个扩展名。", "success")
        messagebox.showinfo(APP_NAME, f"基准更新完成，共保护 {count} 个扩展名。")

    def _show_history(self):
        files = self.baseline_mgr.list_history()
        if not files:
            messagebox.showinfo(APP_NAME, "暂无历史版本。")
            return
        win = tk.Toplevel(self.root)
        win.title("基准历史版本")
        win.geometry("450x350")
        tk.Label(win, text=f"保留最近 {MAX_HISTORY_VERSIONS} 个历史版本：",
                 font=("微软雅黑", 10)).pack(pady=10)
        listbox = tk.Listbox(win, font=("Consolas", 10), height=10)
        listbox.pack(fill="both", expand=True, padx=15, pady=5)
        for f in files:
            listbox.insert("end", f)
        btn_frame = tk.Frame(win)
        btn_frame.pack(pady=10)

        def restore_selected():
            sel = listbox.curselection()
            if not sel:
                return
            filename = listbox.get(sel[0])
            if messagebox.askyesno(APP_NAME, f"确定恢复到版本 {filename} 吗？"):
                if self.baseline_mgr.restore_history(filename):
                    self._refresh_status()
                    self._append_log(f"已恢复历史基准: {filename}", "success")
                    win.destroy()
                else:
                    messagebox.showerror(APP_NAME, "恢复失败。")

        tk.Button(btn_frame, text="恢复选中版本", font=("微软雅黑", 9),
                  command=restore_selected).pack(side="left", padx=5)
        tk.Button(btn_frame, text="关闭", font=("微软雅黑", 9),
                  command=win.destroy).pack(side="left", padx=5)

    def _update_status(self, text, color="#2ecc71"):
        """更新状态栏显示"""
        try:
            self.status_label.config(text=f"● 状态：{text}", fg=color)
        except Exception:
            pass

    def _toggle_global_lock(self):
        """切换全局锁定模式"""
        if self._global_lock_mode:
            # 已锁定 → 请求解锁（需要确认）
            if not messagebox.askyesno(APP_NAME,
                "【解锁确认】\n\n"
                "当前处于全局锁定模式，所有扩展名注册表键均被ACL保护。\n"
                "解锁后，任何程序都可以修改文件关联。\n\n"
                "确定要解除全局锁定吗？"):
                return
            self._unlock_all_extensions()
            self._global_lock_mode = False
            self._append_log("全局锁定已解除", "success")
            self._update_status("正常监控中")
        else:
            # 未锁定 → 进入锁定模式
            if not messagebox.askyesno(APP_NAME,
                "【锁定确认】\n\n"
                "全局锁定将对所有已备份扩展名的注册表键设置ACL保护，\n"
                "仅允许SYSTEM/TI写入，阻止普通程序和管理员修改文件关联。\n\n"
                "锁定后如需安装新软件或修改默认打开方式，请先解锁。\n\n"
                "确定要启用全局锁定吗？"):
                return
            locked_count = self._lock_all_extensions()
            self._global_lock_mode = True
            self._append_log(f"全局锁定已启用，共锁定 {locked_count} 个扩展名", "success")
            self._update_status("全局锁定中")

    def _lock_all_extensions(self):
        """锁定所有基准中的扩展名注册表键，返回锁定数量"""
        exts = list(self.baseline_mgr.baseline.keys())
        locked = 0
        for ext in exts:
            try:
                prog_id = None
                snap = self.baseline_mgr.baseline.get(ext, {})
                if isinstance(snap, dict):
                    prog_id = snap.get("userchoice_progid") or snap.get("hkcr_ext")
                lock_all_protected_keys(ext, prog_id)
                locked += 1
            except Exception as e:
                logger.error(f"锁定 {ext} 失败: {e}")
        return locked

    def _unlock_all_extensions(self):
        """解锁所有扩展名注册表键"""
        exts = list(self.baseline_mgr.baseline.keys())
        unlocked = 0
        for ext in exts:
            try:
                prog_id = None
                snap = self.baseline_mgr.baseline.get(ext, {})
                if isinstance(snap, dict):
                    prog_id = snap.get("userchoice_progid") or snap.get("hkcr_ext")
                unlock_all_protected_keys(ext, prog_id)
                unlocked += 1
            except Exception as e:
                logger.error(f"解锁 {ext} 失败: {e}")
        self._append_log(f"已解除 {unlocked} 个扩展名的注册表锁定", "info")
        return unlocked

    def _show_emergency_panel(self):
        """异常修复面板（兼容旧调用）：直接切换到主窗口「工具」页"""
        self._select_nav("tools")

    def _repair_set_status(self, msg):
        """更新修复面板状态"""
        try:
            self._repair_status_var.set(msg)
            self.root.update_idletasks()
        except Exception:
            pass

    def _repair_apply(self, title, fn):
        """执行单个修复动作，统一日志与状态反馈"""
        try:
            fn()
            self._repair_set_status(f"{title} · 已完成")
            self._append_log(f"[异常修复] {title} 已完成", "success")
        except Exception as e:
            logger.error(f"{title} 失败: {e}")
            self._repair_set_status(f"{title} · 失败")
            self._append_log(f"[异常修复] {title} 失败: {e}", "error")

    def _repair_pt(self):
        """返回持续篡改追踪器（可能为 None）"""
        return self.monitor.persistent_tracker if self.monitor else None

    # ============ 一、解除注册表锁定 ============
    def _repair_unlock_registry(self, win=None, confirm=True):
        """① 解除所有扩展名的注册表锁定（清除 Deny ACL 恢复可写）"""
        if confirm and not messagebox.askyesno(APP_NAME, "确定要解除所有扩展名的注册表锁定吗？\n\n将清除所有被锁定扩展名在 UserChoice 等键上的 Deny ACL，恢复可写状态。"):
            return
        count = 0
        for ext in list(self.baseline_mgr.baseline.keys()):
            try:
                prog_id = None
                snap = self.baseline_mgr.baseline.get(ext, {})
                if isinstance(snap, dict):
                    prog_id = snap.get("userchoice_progid") or snap.get("hkcr_ext")
                unlock_all_protected_keys(ext, prog_id)
                count += 1
            except Exception as e:
                logger.error(f"解锁 {ext} 失败: {e}")
        pt = self._repair_pt()
        if pt:
            pt._locked_exts.clear()
        if self._global_lock_mode:
            self._global_lock_mode = False
        self._repair_set_status(f"已解除 {count} 个扩展名的注册表锁定")
        self._append_log(f"[异常修复] 已解除 {count} 个扩展名的注册表锁定", "success")

    def _repair_clear_lock_count(self):
        """② 清除锁定计数"""
        def _do():
            pt = self._repair_pt()
            if pt:
                pt._lock_count.clear()
        self._repair_apply("清除锁定计数", _do)

    # ============ 二、重置持续篡改追踪状态 ============
    def _repair_clear_ext_history(self):
        def _do():
            pt = self._repair_pt()
            if pt:
                pt._ext_history.clear()
        self._repair_apply("清除单扩展名篡改历史", _do)

    def _repair_clear_progid_history(self):
        def _do():
            pt = self._repair_pt()
            if pt:
                pt._progid_history.clear()
        self._repair_apply("清除批量篡改历史", _do)

    def _repair_clear_persistent_exts(self):
        def _do():
            pt = self._repair_pt()
            if pt:
                pt._persistent_exts.clear()
        self._repair_apply("清除持续篡改标记", _do)

    def _repair_clear_batch_progids(self):
        def _do():
            pt = self._repair_pt()
            if pt:
                pt._batch_progids.clear()
        self._repair_apply("清除批量篡改标记", _do)

    def _repair_exit_persistent_mode(self):
        def _do():
            if self.monitor:
                self.monitor._persistent_mode = False
                self.monitor._persistent_cooldown_until = 0
        self._repair_apply("退出持续篡改模式", _do)

    def _repair_clear_unlocked_exts(self):
        def _do():
            pt = self._repair_pt()
            if pt:
                pt._unlocked_exts.clear()
        self._repair_apply("清除高频观察期", _do)

    # ============ 三、重置防护引擎状态 ============
    def _repair_clear_cooldown(self):
        self._repair_apply("清除冷却期", self.engine.cooldown.clear)

    def _repair_clear_allowed_cycle(self):
        self._repair_apply("清除本周期同意记录", self.engine.allowed_this_cycle.clear)

    def _repair_clear_uc_fail(self):
        self._repair_apply("清除 UserChoice 失败计数", self.engine._uc_fail_count.clear)

    def _repair_clear_handling_exts(self):
        def _do():
            if self.monitor:
                self.monitor._handling_exts.clear()
        self._repair_apply("清除处理中集合", _do)

    # ============ 四、清除弹窗 / 通知状态 ============
    def _repair_close_toasts(self):
        def _do():
            for toast in self.active_toasts[:]:
                try:
                    toast.destroy()
                except Exception:
                    pass
            self.active_toasts.clear()
        self._repair_apply("关闭所有活动弹窗", _do)

    def _repair_clear_popup_queue(self):
        def _do():
            self._popup_queue.clear()
            self._popup_queue_active = False
        self._repair_apply("清空弹窗队列", _do)

    def _repair_clear_batch_queue(self):
        self._repair_apply("清空批量弹窗队列", self._batch_queue.clear)

    def _repair_cancel_batch_timer(self):
        def _do():
            if self._batch_timer:
                try:
                    self.root.after_cancel(self._batch_timer)
                except Exception:
                    pass
                self._batch_timer = None
            self._batch_popup_active = False
        self._repair_apply("取消批量计时器", _do)

    def _repair_clear_popup_pause(self):
        def _do():
            self._popup_paused_until = 0
        self._repair_apply("解除弹窗暂停", _do)

    # ============ 五、进程打击状态 ============
    def _repair_clear_blacklist(self):
        """⑱ 清除进程黑名单"""
        def _do():
            if self.monitor and self.monitor.process_enforcer:
                pe = self.monitor.process_enforcer
                pe._blacklist.clear()
                pe._redlist.clear()
                pe._save()
        self._repair_apply("清除进程黑名单", _do)

    def _repair_clear_strike_history(self):
        def _do():
            if self.monitor and self.monitor.process_enforcer:
                pe = self.monitor.process_enforcer
                pe._blacklist_history.clear()
                pe._suspect_count.clear()
                pe._save()
        self._repair_apply("清除打击历史", _do)

    # ============ 其他 / 辅助 ============
    def _repair_global_lock(self, win=None):
        """锁定模式 / 解除锁定"""
        self._toggle_global_lock()
        if self._global_lock_mode:
            self._repair_set_status("全局锁定已启用")
        else:
            self._repair_set_status("全局锁定已解除")

    def _repair_reset_grace(self, win=None):
        """重置启动宽限期"""
        if self.monitor:
            self.monitor._grace_until = time.time() + self.monitor.GRACE_PERIOD_SECONDS
            self.monitor._grace_logged = False
            self.monitor._grace_logged_exts.clear()
        self._repair_set_status("启动宽限期已重置")
        self._append_log("[异常修复] 启动宽限期已重置", "success")

    # ============ 一键全部修复 ============
    def _repair_all(self, win=None):
        """一键全部修复：依次执行全部 20 项状态修复"""
        if not messagebox.askyesno(APP_NAME,
            "【一键全部修复确认】\n\n"
            "将依次执行全部 20 项修复：\n"
            "① 解除注册表锁定（含清除锁定计数）\n"
            "② 重置持续篡改追踪状态\n"
            "③ 重置防护引擎状态\n"
            "④ 清除弹窗 / 通知状态\n"
            "⑤ 清除进程黑名单与打击历史\n"
            "⑥ 重置启动宽限期\n\n"
            "确定执行吗？"):
            return
        self._append_log("=== 开始一键全部修复 ===", "warn")
        steps = [
            ("解除注册表锁定", lambda: self._repair_unlock_registry(confirm=False)),
            ("清除锁定计数", self._repair_clear_lock_count),
            ("清除单扩展名篡改历史", self._repair_clear_ext_history),
            ("清除批量篡改历史", self._repair_clear_progid_history),
            ("清除持续篡改标记", self._repair_clear_persistent_exts),
            ("清除批量篡改标记", self._repair_clear_batch_progids),
            ("退出持续篡改模式", self._repair_exit_persistent_mode),
            ("清除高频观察期", self._repair_clear_unlocked_exts),
            ("清除冷却期", self._repair_clear_cooldown),
            ("清除本周期同意记录", self._repair_clear_allowed_cycle),
            ("清除 UserChoice 失败计数", self._repair_clear_uc_fail),
            ("清除处理中集合", self._repair_clear_handling_exts),
            ("关闭所有活动弹窗", self._repair_close_toasts),
            ("清空弹窗队列", self._repair_clear_popup_queue),
            ("清空批量弹窗队列", self._repair_clear_batch_queue),
            ("取消批量计时器", self._repair_cancel_batch_timer),
            ("解除弹窗暂停", self._repair_clear_popup_pause),
            ("清除进程黑名单", self._repair_clear_blacklist),
            ("清除打击历史", self._repair_clear_strike_history),
            ("重置启动宽限期", self._repair_reset_grace),
        ]
        for i, (name, fn) in enumerate(steps, 1):
            self._repair_set_status(f"正在执行 {i}/{len(steps)}：{name}...")
            try:
                fn()
            except Exception as e:
                logger.error(f"一键修复步骤「{name}」失败: {e}")
        self._update_status("异常修复完成，正常监控中")
        self._repair_set_status("全部修复完成！")
        self._append_log("=== 一键全部修复完成 ===", "success")
        messagebox.showinfo(APP_NAME, "一键全部修复完成！\n\n全部 20 项状态已重置，保护已恢复正常。")

    def _build_page_history(self, parent):
        """页面：防护记录 —— 历史更改审计（统计概览 + 可搜索记录表格 + 详情/状态检查）"""
        page = tk.Frame(parent, bg=self.C["bg"])
        self._pages["history"] = page
        self._mk_page_header(page, "防护记录", "程序识别并处理的所有关联更改审计，自动保存在文件中")
        body = self._mk_scroll_container(page)

        # —— 统计概览 ——
        card, cb = self._mk_card(body, "统计概览", "实时汇总防护记录数据（每次刷新时重新计算）")
        self._hist_stat_var = tk.StringVar(value="统计计算中…")
        tk.Label(cb, textvariable=self._hist_stat_var, font=("微软雅黑", 9),
                 fg=self.C["text2"], bg=self.C["card"], anchor="w", justify="left"
                 ).pack(fill="x", pady=2)

        # —— 记录列表 ——
        list_card, list_cb = self._mk_card(body, "记录列表",
            "输入关键词过滤（扩展名 / 篡改者）；单击行查看摘要，双击行对比该扩展名当前注册表状态")
        search_row = tk.Frame(list_cb, bg=self.C["card"])
        search_row.pack(fill="x", pady=(0, 6))
        self._hist_search_var = tk.StringVar()
        tk.Entry(search_row, textvariable=self._hist_search_var,
                 font=("微软雅黑", 9), bg=self.C["btn"], fg=self.C["text"],
                 relief="flat", highlightthickness=0, insertbackground=self.C["text"]
                 ).pack(side="left", fill="x", expand=True, padx=(0, 8))
        self._hist_search_var.trace_add("write", lambda *a: self._refresh_history_table())

        tree_frame = tk.Frame(list_cb, bg=self.C["card"])
        tree_frame.pack(fill="x", pady=2)
        cols = ("time", "ext", "tamperer", "action", "result")
        tree = ttk.Treeview(tree_frame, columns=cols, show="headings", height=10)
        headers = {"time": "时间", "ext": "扩展名", "tamperer": "篡改者", "action": "操作", "result": "结果"}
        widths = {"time": 150, "ext": 90, "tamperer": 150, "action": 90, "result": 70}
        for c in cols:
            tree.heading(c, text=headers[c])
            tree.column(c, width=widths[c], anchor="w", stretch=True)
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=vsb.set)
        tree.pack(side="left", fill="x", expand=True)
        vsb.pack(side="right", fill="y")
        self._hist_tree = tree
        try:
            st = ttk.Style(self.root)
            st.configure("Hist.Treeview", background=self.C["btn"], fieldbackground=self.C["btn"],
                         foreground=self.C["text"], borderwidth=0, rowheight=24)
            st.configure("Hist.Treeview.Heading", background=self.C["nav"], foreground=self.C["text2"],
                         borderwidth=0, relief="flat")
            st.map("Hist.Treeview", background=[("selected", self.C["nav_sel"])],
                   foreground=[("selected", self.C["text"])])
            tree.configure(style="Hist.Treeview")
        except Exception:
            pass

        detail = tk.Text(list_cb, font=("微软雅黑", 9), height=7, wrap="word",
                         bg=self.C["btn"], fg=self.C["text"], relief="flat",
                         highlightthickness=0, state="disabled")
        detail.pack(fill="x", pady=(6, 0))
        self._hist_detail_text = detail

        ops = tk.Frame(list_cb, bg=self.C["card"])
        ops.pack(fill="x", pady=(8, 2))
        self._mk_button(ops, "刷新", self._refresh_history_table, width=8).pack(side="left", padx=(0, 8))
        self._mk_button(ops, "清空记录", self._history_clear, width=10, kind="danger").pack(side="left", padx=(0, 8))
        self._mk_button(ops, "导出记录", self._history_export, width=10).pack(side="left", padx=(0, 8))
        self._mk_button(ops, "检查当前状态", self._history_check_status, width=12).pack(side="left")
        tree.bind("<ButtonRelease-1>", lambda _e: self._history_show_detail())
        tree.bind("<Double-Button-1>", lambda _e: self._history_check_status())
        self._refresh_history_table()

    def _refresh_history_table(self):
        """刷新防护记录表格（含统计概览与搜索过滤）"""
        try:
            from collections import Counter
            q = self._hist_search_var.get().strip().lower()
            records = self.change_history.get_records(limit=100000)
            # 统计概览
            total = len(records)
            today = datetime.now().strftime("%Y-%m-%d")
            today_cnt = sum(1 for r in records if str(r.get("timestamp", "")).startswith(today))
            blocked = sum(1 for r in records if r.get("action") == "auto_blocked")
            consented = sum(1 for r in records if r.get("action") == "user_consent")
            ext_counter = Counter(str(r.get("ext", "")) for r in records)
            tam_counter = Counter(str(r.get("tamperer") or "未知") for r in records)
            top_exts = "、".join(f"{e}({c})" for e, c in ext_counter.most_common(5)) or "—"
            top_tams = "、".join(f"{t}({c})" for t, c in tam_counter.most_common(5)) or "—"
            self._hist_stat_var.set(
                f"总记录: {total}  今日: {today_cnt}  自动阻止: {blocked}  用户同意: {consented}\n"
                f"Top 扩展名: {top_exts}\nTop 篡改者: {top_tams}")
            # 表格（倒序：最新在前）
            tree = self._hist_tree
            tree.delete(*tree.get_children())
            for i, rec in enumerate(reversed(records)):
                ext = str(rec.get("ext", ""))
                tam = str(rec.get("tamperer") or "未知")
                if q and q not in ext.lower() and q not in tam.lower():
                    continue
                action_text = {"user_consent": "用户同意", "auto_blocked": "自动阻止",
                               "detected_only": "仅检测"}.get(rec.get("action"), str(rec.get("action")))
                tree.insert("", tk.END, iid=str(i), values=(
                    str(rec.get("timestamp", "")), ext, tam, action_text, str(rec.get("result", ""))))
        except Exception as e:
            if hasattr(self, "_hist_stat_var"):
                self._hist_stat_var.set(f"读取记录失败: {e}")

    def _history_rows(self):
        """返回当前表格对应的记录列表（与显示顺序一致：倒序 + 过滤）"""
        q = self._hist_search_var.get().strip().lower()
        records = self.change_history.get_records(limit=100000)
        rows = []
        for rec in reversed(records):
            ext = str(rec.get("ext", ""))
            tam = str(rec.get("tamperer") or "未知")
            if q and q not in ext.lower() and q not in tam.lower():
                continue
            rows.append(rec)
        return rows

    def _history_show_detail(self):
        """单击行显示该记录摘要"""
        try:
            sel = self._hist_tree.selection()
            if not sel:
                return
            rows = self._history_rows()
            idx = int(sel[0])
            if idx < 0 or idx >= len(rows):
                return
            rec = rows[idx]
            txt = self._hist_detail_text
            txt.configure(state="normal")
            txt.delete("1.0", tk.END)
            txt.insert(tk.END, f"时间: {rec.get('timestamp', '')}\n")
            txt.insert(tk.END, f"扩展名: {rec.get('ext', '')}   篡改者: {rec.get('tamperer') or '未知'}\n")
            txt.insert(tk.END, f"操作: {rec.get('action', '')}   结果: {rec.get('result', '')}\n")
            txt.insert(tk.END, "更改详情:\n")
            for ch in rec.get("changes", []):
                txt.insert(tk.END, f"  {ch.get('item', '')}: {ch.get('old', '')} → {ch.get('new', '')}\n")
            src = rec.get("source") or {}
            if isinstance(src, dict) and src.get("process_name"):
                txt.insert(tk.END, f"来源进程: {src.get('process_name')} {src.get('process_path') or ''}\n")
            txt.configure(state="disabled")
        except Exception:
            pass

    def _history_check_status(self):
        """双击行：对比该扩展名当前注册表状态与基准"""
        try:
            sel = self._hist_tree.selection()
            if not sel:
                return
            rows = self._history_rows()
            idx = int(sel[0])
            if idx < 0 or idx >= len(rows):
                return
            rec = rows[idx]
            ext = str(rec.get("ext", ""))
            txt = self._hist_detail_text
            txt.configure(state="normal")
            txt.delete("1.0", tk.END)
            bl = self.baseline_mgr.baseline.get(ext, {})
            txt.insert(tk.END, f"=== {ext} 当前注册表状态 ===")
            if not bl:
                txt.insert(tk.END, "\n\n该扩展名不在当前基准中（可能已移除或为新扩展名）")
                txt.configure(state="disabled")
                return
            try:
                mismatches = self.engine.check_extension(ext)
            except Exception:
                mismatches = []
            item_order = ["userchoice_progid", "userchoice_hash", "hkcr_ext",
                          "hkcu_ext", "hklm_ext", "hkcr_command", "hkcu_command"]
            labels = {"userchoice_progid": "UserChoice.ProgId", "userchoice_hash": "UserChoice.Hash",
                      "hkcr_ext": "HKCR 默认值", "hkcu_ext": "HKCU\\Software\\Classes",
                      "hklm_ext": "HKLM\\Software\\Classes", "hkcr_command": "HKCR 命令",
                      "hkcu_command": "HKCU 命令"}
            mismatch_keys = {m[0] for m in mismatches}
            for key in item_order:
                bl_item = bl.get(key, {})
                blv = bl_item.get("value") if isinstance(bl_item, dict) else None
                tag = " ✓" if key not in mismatch_keys else " ✗ 不一致"
                txt.insert(tk.END, f"\n{labels.get(key, key)}: {blv if blv is not None else '（无）'}{tag}")
            if mismatch_keys:
                txt.insert(tk.END, f"\n\n存在 {len(mismatch_keys)} 项不一致，可到「扩展名」页更新基准，或到「异常修复」页处理")
            else:
                txt.insert(tk.END, "\n\n当前状态与基准完全一致")
            txt.configure(state="disabled")
        except Exception as e:
            txt = getattr(self, "_hist_detail_text", None)
            if txt:
                txt.configure(state="normal")
                txt.delete("1.0", tk.END)
                txt.insert(tk.END, f"检查失败: {e}")
                txt.configure(state="disabled")

    def _history_clear(self):
        """清空全部防护记录"""
        if not messagebox.askyesno(APP_NAME, "确定清空全部防护记录？\n（记录保存在文件中，清空后不可恢复）"):
            return
        try:
            self.change_history.clear()
            self._refresh_history_table()
            txt = getattr(self, "_hist_detail_text", None)
            if txt:
                txt.configure(state="normal")
                txt.delete("1.0", tk.END)
                txt.configure(state="disabled")
            self._append_log("已清空全部防护记录", "warn")
            messagebox.showinfo(APP_NAME, "防护记录已清空")
        except Exception as e:
            messagebox.showerror(APP_NAME, f"清空失败: {e}")

    def _history_export(self):
        """导出防护记录（JSON 审计文件）"""
        try:
            path = filedialog.asksaveasfilename(
                title="导出防护记录", defaultextension=".json",
                initialfile="opst-protect-history.json",
                filetypes=[("JSON 文件", "*.json"), ("所有文件", "*.*")])
            if not path:
                return
            ok = self.change_history.export_records(path)
            if ok:
                messagebox.showinfo(APP_NAME, f"记录已导出到:\n{path}")
            else:
                messagebox.showerror(APP_NAME, "导出失败")
        except Exception as e:
            messagebox.showerror(APP_NAME, f"导出失败: {e}")

    def _build_page_diag(self, parent):
        """页面：系统诊断 —— 一键体检报告（权限/提权链/基准/锁定/自启动/运行健康）"""
        page = tk.Frame(parent, bg=self.C["bg"])
        self._pages["diag"] = page
        self._mk_page_header(page, "系统诊断", "一键检查权限、提权链、基准、锁定、自启动与运行健康")
        body = self._mk_scroll_container(page)
        card, cb = self._mk_card(body, "一键诊断",
            "点击「开始诊断」逐项检查并生成报告；报告可复制或保存为 txt 文件")
        ops = tk.Frame(cb, bg=self.C["card"])
        ops.pack(fill="x", pady=(0, 6))
        self._mk_button(ops, "开始诊断", self._diag_run, kind="primary").pack(side="left", padx=(0, 8))
        self._mk_button(ops, "复制报告", self._diag_copy).pack(side="left", padx=(0, 8))
        self._mk_button(ops, "保存报告", self._diag_save).pack(side="left")
        text = tk.Text(cb, font=("Consolas", 9), height=22, wrap="word",
                       bg=self.C["btn"], fg=self.C["text"], relief="flat",
                       highlightthickness=0, state="disabled")
        text.pack(fill="x")
        self._diag_text = text
        text.configure(state="normal")
        text.insert(tk.END, "尚未诊断。点击「开始诊断」生成体检报告。\n")
        text.configure(state="disabled")

    def _diag_write(self, line):
        """向诊断报告追加一行（自动滚到底部）"""
        txt = self._diag_text
        txt.configure(state="normal")
        txt.insert(tk.END, line + "\n")
        txt.see(tk.END)
        txt.configure(state="disabled")

    def _diag_run(self):
        """执行一键诊断并输出报告"""
        txt = self._diag_text
        txt.configure(state="normal")
        txt.delete("1.0", tk.END)
        txt.configure(state="disabled")
        self._diag_write(f"===== {APP_NAME} v{APP_VERSION} 诊断报告 =====")
        self._diag_write(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self._diag_write("")
        # 1) 权限与提权
        self._diag_write("[1] 权限状态")
        priv_txt = self.ti_status if self.ti_status else "未知"
        self._diag_write(f"    - 界面权限显示: {priv_txt}")
        try:
            import ctypes
            elev = bool(ctypes.windll.shell32.IsUserAnAdmin())
            self._diag_write(f"    - 进程管理员令牌: {'是' if elev else '否'}")
        except Exception:
            self._diag_write("    - 进程管理员令牌: 无法判断")
        self._diag_write("")
        # 2) 提权链
        self._diag_write("[2] 提权链（TrustedInstaller）")
        self._diag_write(f"    - 提权模式: {getattr(self, '_ti_mode_text', 'TI(SYSTEM)')}")
        self._diag_write(f"    - 自我保护: {'已启用' if self._process_protected else '未启用'}")
        self._diag_write("")
        # 3) 基准
        self._diag_write("[3] 基准状态")
        cfg = self.baseline_mgr.config
        bl = self.baseline_mgr.baseline
        self._diag_write(f"    - 保护扩展名: {len(bl)}")
        self._diag_write(f"    - 基准模式: {cfg.get('baseline_mode', '—')}")
        self._diag_write(f"    - 基准时间: {cfg.get('baseline_time', '—')}")
        self._diag_write("")
        # 4) 单扩展名锁定
        self._diag_write("[4] 单扩展名锁定")
        locked = cfg.get("locked_defaults", {}) or {}
        if locked:
            for ext, target in sorted(locked.items()):
                try:
                    cur = get_prog_id(ext)
                    mark = "一致" if cur and cur.lower() == target.lower() else ("待落实" if not cur else f"当前={cur}")
                except Exception:
                    mark = "无法读取"
                self._diag_write(f"    - {ext} → {target}  [{mark}]")
        else:
            self._diag_write("    - 未设置任何锁定")
        self._diag_write("")
        # 5) 自启动
        self._diag_write("[5] 开机自启动")
        try:
            if is_autostart_set():
                self._diag_write("    - 已设置（带 -m 最小化启动）")
            else:
                self._diag_write("    - 未设置")
        except Exception:
            self._diag_write("    - 无法读取")
        self._diag_write("")
        # 6) 日志与运行健康
        self._diag_write("[6] 日志与运行健康")
        try:
            log_path = os.path.join(USERDATA_DIR, "protector.log")
            if os.path.exists(log_path):
                sz = os.path.getsize(log_path)
                self._diag_write(f"    - 监控日志: {sz/1024:.1f} KB（超过 2MB 自动轮转）")
            else:
                self._diag_write("    - 监控日志: 尚未生成")
        except Exception:
            self._diag_write("    - 监控日志: 无法读取")
        try:
            import tempfile
            meis = [d for d in os.listdir(tempfile.gettempdir()) if d.startswith("_MEI")]
            self._diag_write(f"    - 临时 _MEI 目录: {len(meis)} 个（30s 自动清扫）")
        except Exception:
            pass
        self._diag_write("")
        # 7) 识别库
        self._diag_write("[7] 软件识别库")
        try:
            if os.path.exists(PROGRAM_NAMES_FILE):
                with open(PROGRAM_NAMES_FILE, "r", encoding="utf-8") as f:
                    names = json.load(f)
                self._diag_write(f"    - 内置名称库条目: {len(names)}")
            else:
                self._diag_write("    - 识别库文件缺失")
        except Exception:
            self._diag_write("    - 识别库读取失败")
        self._diag_write("")
        # 8) 防护记录
        self._diag_write("[8] 防护记录")
        try:
            recs = self.change_history.get_records(limit=100000)
            self._diag_write(f"    - 历史记录: {len(recs)} 条（上限 {self.change_history.MAX_RECORDS}）")
        except Exception:
            self._diag_write("    - 历史记录: 无法读取")
        self._diag_write("")
        self._diag_write("===== 诊断完成 =====")

    def _diag_copy(self):
        """复制诊断报告到剪贴板"""
        try:
            txt = self._diag_text.get("1.0", tk.END).strip()
            if not txt:
                return
            self.root.clipboard_clear()
            self.root.clipboard_append(txt)
            self._append_log("诊断报告已复制到剪贴板", "info")
        except Exception:
            pass

    def _diag_save(self):
        """保存诊断报告为 txt 文件"""
        try:
            txt = self._diag_text.get("1.0", tk.END).strip()
            if not txt:
                return
            path = filedialog.asksaveasfilename(
                title="保存诊断报告", defaultextension=".txt",
                initialfile="opst-diag-report.txt",
                filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")])
            if not path:
                return
            with open(path, "w", encoding="utf-8") as f:
                f.write(txt + "\n")
            messagebox.showinfo(APP_NAME, f"诊断报告已保存到:\n{path}")
        except Exception as e:
            messagebox.showerror(APP_NAME, f"保存失败: {e}")

    def _show_settings(self):
        """设置对话框（兼容旧调用）：直接切换到主窗口「设置」页"""
        self._select_nav("settings")

    def _open_baseline_download(self):
        """打开项目主页（默认基准说明与导入方式）"""
        url = "https://github.com/TXZDMM/OPSTController"
        opened = False
        # 方法1：用explorer.exe打开（TI下最可靠，利用用户态已运行的explorer）
        try:
            import subprocess
            _popen(['explorer.exe', url], creationflags=0x08000000)
            opened = True
        except Exception:
            pass
        # 方法2：ShellExecuteW兜底
        if not opened:
            try:
                ctypes.windll.shell32.ShellExecuteW(None, "open", url, None, None, 1)
                opened = True
            except Exception:
                pass
        if opened:
            self._append_log("已打开项目主页（基准说明）", "info")
        else:
            self._append_log("打开浏览器失败，请手动访问", "error")
            messagebox.showinfo(APP_NAME, f"请手动复制访问:\n{url}")

    def _load_baseline_from_file(self, parent_win):
        """从文件加载基准（严格校验格式）"""
        from tkinter import filedialog
        path = filedialog.askopenfilename(
            title="选择基准文件",
            filetypes=[("JSON文件", "*.json"), ("所有文件", "*.*")],
            parent=parent_win
        )
        if not path:
            return
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except Exception as e:
            messagebox.showerror(APP_NAME, f"文件读取失败: {e}")
            return
        # 严格校验：必须是dict，key必须以.开头，value必须是含7项保护字段的dict
        if not isinstance(data, dict) or len(data) == 0:
            messagebox.showerror(APP_NAME, "文件格式不正确：不是有效的基准数据。")
            return
        valid_exts = 0
        required_keys = {"root", "path", "name", "value", "type"}
        for ext, items in data.items():
            if not isinstance(ext, str) or not ext.startswith("."):
                messagebox.showerror(APP_NAME, f"文件格式不正确：扩展名'{ext}'无效。")
                return
            if not isinstance(items, dict):
                messagebox.showerror(APP_NAME, f"文件格式不正确：{ext}的数据不是字典。")
                return
            # 每个扩展名至少应有hkcr_ext项
            if "hkcr_ext" not in items:
                messagebox.showerror(APP_NAME, f"文件格式不正确：{ext}缺少hkcr_ext项。")
                return
            for item_key, item_val in items.items():
                if not isinstance(item_val, dict) or not required_keys.issubset(item_val.keys()):
                    messagebox.showerror(APP_NAME, f"文件格式不正确：{ext}的{item_key}项字段缺失。")
                    return
            valid_exts += 1
        if valid_exts == 0:
            messagebox.showerror(APP_NAME, "文件中没有有效的扩展名数据。")
            return
        # 校验通过，加载
        self.baseline_mgr._push_history()
        self.baseline_mgr.baseline = data
        self.baseline_mgr.save()
        self.baseline_mgr.config["initialized"] = True
        self.baseline_mgr.save_config()
        self._refresh_status()
        self._append_log(f"已从文件加载基准: {os.path.basename(path)} ({valid_exts}个扩展名)", "success")
        parent_win.destroy()

    def _reset_popup_timeout_reason(self):
        """10秒无新增更改后，恢复到正常配置的弹窗超时。"""
        self._popup_last_reason = None
        if self._popup_timeout_reset_after is not None:
            try:
                self.root.after_cancel(self._popup_timeout_reset_after)
            except Exception:
                pass
            self._popup_timeout_reset_after = None

    def _export_audit_log(self):
        """导出审计记录 JSON"""
        from tkinter import filedialog
        path = filedialog.asksaveasfilename(
            title="导出审计日志",
            defaultextension=".json",
            filetypes=[("JSON文件", "*.json"), ("所有文件", "*.*")],
            initialfile="opst_audit_log.json",
        )
        if not path:
            return
        try:
            ok = self.change_history.export_records(path)
            if ok:
                self._append_log(f"审计日志已导出: {path}", "success")
                messagebox.showinfo(APP_NAME, f"审计日志已导出至:\n{path}")
        except Exception as e:
            self._append_log(f"导出审计日志失败: {e}", "error")
            messagebox.showerror(APP_NAME, f"导出失败: {e}")

    def _show_notification(self, ext, mismatches, recover_result, extra_timeout=0):
        """监控线程调用：在主线程显示右下角通知。
        支持两种批量弹窗模式：
        - simultaneous（同时）：所有弹窗同时弹出，各自独立计时
        - single（单个，默认）：队列式，一次只显示最上面一个，只有它计时；
          上一个超时自动阻止→下一个缩短为2秒；10秒内无新更改时恢复正常超时
        批量合并：同一进程5秒内篡改≥3个扩展名时，合并为一个批量弹窗"""
        if threading.current_thread() is not threading.main_thread():
            self.root.after(0, self._show_notification, ext, mismatches, recover_result, extra_timeout)
            return

        # 持续篡改模式下，静默恢复且不弹窗，避免重复打扰
        if self.monitor is not None and self.monitor.persistent_tracker.is_persistent(ext):
            self._append_log(f"{ext} 处于持续篡改观察中，静默恢复且不弹窗", "warn")
            return

        mode = self.baseline_mgr.config.get("operation_mode", "normal")
        if mode in ("quiet", "game", "demo", "silent", "paused"):
            self._append_log(f"{ext} 当前运行模式={mode}，已压制弹窗提醒，继续静默阻止。", "warn")
            if mode == "paused":
                self._append_log(f"{ext} 暂停保护模式已启用，实时监测已临时停用。", "warn")
            return

        # 检查是否弹窗
        show_popup = self.baseline_mgr.config.get("show_popup", True)
        if not show_popup:
            self._append_log(f"{ext} 检测到更改，静默阻止（弹窗已关闭）", "warn")
            return

        # 检查是否暂停弹窗
        if time.time() < self._popup_paused_until:
            self._append_log(f"{ext} 弹窗暂停中，静默阻止", "warn")
            return

        # 白名单检查：白名单扩展名或白名单程序 → 自动允许
        whitelist_exts = self.baseline_mgr.config.get("whitelist_exts", [])
        whitelist_programs = self.baseline_mgr.config.get("whitelist_programs", [])
        # 识别篡改者
        _tamperer_for_whitelist = None
        for key, bl_val, cur_val, _ in mismatches:
            if key in ("userchoice_progid", "hkcr_ext", "hkcu_ext", "hklm_ext") and cur_val:
                _tamperer_for_whitelist, _ = identify_tamperer(cur_val)
                break
        # 检查扩展名白名单
        if ext.lower() in [e.lower() for e in whitelist_exts]:
            self.baseline_mgr.update_extension(ext)
            self.engine.clear_cooldown(ext)
            self.engine.allowed_this_cycle.add(ext)
            if self.monitor is not None:
                self.monitor.persistent_tracker.clear_ext_history(ext)
            self._append_log(f"{ext} 在白名单扩展名中，自动允许更改", "success")
            self.root.after(10000, lambda: self.engine.allowed_this_cycle.discard(ext))
            return
        # 检查程序白名单
        if _tamperer_for_whitelist and _tamperer_for_whitelist in whitelist_programs:
            self.baseline_mgr.update_extension(ext)
            self.engine.clear_cooldown(ext)
            self.engine.allowed_this_cycle.add(ext)
            if self.monitor is not None:
                self.monitor.persistent_tracker.clear_ext_history(ext)
            self._append_log(f"{ext} 被白名单程序[{_tamperer_for_whitelist}]更改，自动允许", "success")
            self.root.after(10000, lambda: self.engine.allowed_this_cycle.discard(ext))
            return

        # 识别篡改者
        tamperer_name = None
        for key, bl_val, cur_val, _ in mismatches:
            if key in ("userchoice_progid", "hkcr_ext", "hkcu_ext", "hklm_ext") and cur_val:
                tamperer_name, _ = identify_tamperer(cur_val)
                break
        tamperer_key = tamperer_name if tamperer_name else "__unknown__"

        # 批量合并：加入队列
        if tamperer_key not in self._batch_queue:
            self._batch_queue[tamperer_key] = []
        self._batch_queue[tamperer_key].append((ext, mismatches, recover_result))

        # 如果已有≥3个，立即触发批量弹窗
        if len(self._batch_queue[tamperer_key]) >= 3:
            self._trigger_batch_popup(tamperer_key)
            return

        # 否则启动/重置5秒定时器
        if self._batch_timer is not None:
            try:
                self.root.after_cancel(self._batch_timer)
            except Exception:
                pass
        self._batch_timer = self.root.after(5000, lambda: self._flush_batch_queue())

        self._append_log(f"{ext} 已加入批量队列（{tamperer_name}，当前{len(self._batch_queue[tamperer_key])}个）", "info")
        return

    def _flush_batch_queue(self):
        """5秒无新增后，检查每个篡改者的队列，≥3个弹批量弹窗，<3个弹单个弹窗"""
        self._batch_timer = None
        for tamperer_key in list(self._batch_queue.keys()):
            items = self._batch_queue.pop(tamperer_key, [])
            if not items:
                continue
            if len(items) >= 3:
                # 批量弹窗
                tamperer_name = items[0][1] and None
                # 从第一个item的mismatches中获取tamperer_name
                for key, bl_val, cur_val, _ in items[0][1]:
                    if key in ("userchoice_progid", "hkcr_ext", "hkcu_ext", "hklm_ext") and cur_val:
                        tamperer_name, _ = identify_tamperer(cur_val)
                        break
                self._show_batch_popup(tamperer_name, items)
            else:
                # 逐个弹单个弹窗
                for ext, mismatches, recover_result in items:
                    self._show_single_notification(ext, mismatches, recover_result)

    def _trigger_batch_popup(self, tamperer_key):
        """立即触发某个篡改者的批量弹窗"""
        items = self._batch_queue.pop(tamperer_key, [])
        if not items:
            return
        tamperer_name = None
        for key, bl_val, cur_val, _ in items[0][1]:
            if key in ("userchoice_progid", "hkcr_ext", "hkcu_ext", "hklm_ext") and cur_val:
                tamperer_name, _ = identify_tamperer(cur_val)
                break
        self._show_batch_popup(tamperer_name, items)

    def _show_batch_popup(self, tamperer_name, items):
        """显示批量弹窗"""
        if self._batch_popup_active:
            # 已有批量弹窗，加入队列
            for ext, mismatches, recover_result in items:
                self._popup_queue.append((ext, mismatches, recover_result, 0))
            return
        self._batch_popup_active = True
        self._append_log(f"批量弹窗：{tamperer_name} 更改了 {len(items)} 个扩展名", "warn")

        def on_block_all(tname, its):
            self._batch_popup_active = False
            for ext, mismatches, recover_result in its:
                self._append_log(f"  {ext}: 已阻止", "success")
                # 记录历史
                changes = []
                for key, bl_val, cur_val, _ in mismatches:
                    label = ProtectionEngine.ITEM_LABELS.get(key, key)
                    changes.append({"item": label, "old": str(bl_val), "new": str(cur_val)})
                s, f, _ = recover_result
                result = "success" if f == 0 else ("partial" if s > 0 else "fail")
                self.change_history.add_record(ext, tname, changes, "auto_blocked", result)
            self._append_log(f"批量阻止完成，共 {len(its)} 项", "success")
            self._process_remaining_batch()

        def on_allow_all(tname, its):
            self._batch_popup_active = False
            for ext, mismatches, recover_result in its:
                self.baseline_mgr.update_extension(ext)
                self.engine.clear_cooldown(ext)
                self.engine.allowed_this_cycle.add(ext)
                if self.monitor is not None:
                    self.monitor.persistent_tracker.clear_ext_history(ext)
                changes = []
                for key, bl_val, cur_val, _ in mismatches:
                    label = ProtectionEngine.ITEM_LABELS.get(key, key)
                    changes.append({"item": label, "old": str(bl_val), "new": str(cur_val)})
                self.change_history.add_record(ext, tname, changes, "user_consent", "success")
                self._append_log(f"  {ext}: 已允许", "info")
            self._append_log(f"批量允许完成，共 {len(its)} 项", "info")
            self._process_remaining_batch()

        def on_view_onebyone(tname, its):
            self._batch_popup_active = False
            # 加入单个弹窗队列
            for ext, mismatches, recover_result in its:
                self._popup_queue.append((ext, mismatches, recover_result, 0))
            if not self.active_toasts:
                self._process_popup_queue()

        def on_pause():
            self._batch_popup_active = False
            self._popup_paused_until = time.time() + 300
            self._append_log("弹窗已暂停5分钟，期间静默阻止", "warn")
            # 清空所有队列
            self._batch_queue.clear()
            self._popup_queue.clear()

        def on_close(tname, its):
            self._batch_popup_active = False
            # 关闭等同全部阻止
            for ext, mismatches, recover_result in its:
                changes = []
                for key, bl_val, cur_val, _ in mismatches:
                    label = ProtectionEngine.ITEM_LABELS.get(key, key)
                    changes.append({"item": label, "old": str(bl_val), "new": str(cur_val)})
                s, f, _ = recover_result
                result = "success" if f == 0 else ("partial" if s > 0 else "fail")
                self.change_history.add_record(ext, tname, changes, "auto_blocked", result)
            self._append_log(f"批量弹窗关闭，已阻止 {len(its)} 项", "warn")
            self._process_remaining_batch()

        toast = BatchNotificationToast(self.root, tamperer_name, items,
                                       on_block_all, on_allow_all, on_view_onebyone, on_pause, on_close)

    def _process_remaining_batch(self):
        """处理剩余的批量队列"""
        if self._batch_queue:
            self.root.after(300, self._flush_batch_queue)

    def _show_single_notification(self, ext, mismatches, recover_result, extra_timeout=0):
        """显示单个弹窗（原_show_notification的核心逻辑）"""
        popup_mode = self.baseline_mgr.config.get("batch_popup_mode", "single")

        # 构造更改详情列表（用于历史记录）
        changes_for_history = []
        for key, bl_val, cur_val, _ in mismatches:
            label = ProtectionEngine.ITEM_LABELS.get(key, key)
            changes_for_history.append({"item": label, "old": str(bl_val), "new": str(cur_val)})

        def on_consent(extension):
            self.baseline_mgr.update_extension(extension)
            self.engine.clear_cooldown(extension)
            self.engine.allowed_this_cycle.add(extension)
            if self.monitor is not None:
                self.monitor.persistent_tracker.clear_ext_history(extension)
            self.change_history.add_record(extension, tamperer_name, changes_for_history, "user_consent", "success")
            self._append_log(f"用户同意 {extension} 的更改，已更新基准并重置篡改计数。", "warn")
            log_event(extension, "更改", "已同意", "用户单次同意")
            self._popup_last_reason = "consent"  # 用户同意→下一个弹窗恢复正常超时
            self.root.after(10000, lambda: self.engine.allowed_this_cycle.discard(extension))

        def on_close(toast):
            if toast in self.active_toasts:
                idx = self.active_toasts.index(toast)
                self.active_toasts.remove(toast)
                if popup_mode == "simultaneous":
                    # 关闭后，后面的弹窗向右移动填补空位
                    delta_x = NotificationToast.TOAST_WIDTH + 10
                    for t in self.active_toasts[idx:]:
                        t.move_right(delta_x)
            self._append_log(f"{toast.ext} 通知已关闭，保持恢复状态。", "info")
            # 记录更改历史：超时自动阻止
            if toast.close_reason == "timeout":
                s, f, _ = recover_result
                result = "success" if f == 0 else ("partial" if s > 0 else "fail")
                self.change_history.add_record(toast.ext, toast.tamperer_name, changes_for_history, "auto_blocked", result)
                self._popup_last_reason = "timeout"
                if self._popup_timeout_reset_after is not None:
                    try:
                        self.root.after_cancel(self._popup_timeout_reset_after)
                    except Exception:
                        pass
                self._popup_timeout_reset_after = self.root.after(10000, self._reset_popup_timeout_reason)
            else:
                self._popup_last_reason = toast.close_reason
            # 单个模式：记录关闭原因，处理队列中下一个
            if popup_mode == "single":
                if self._popup_queue:
                    self.root.after(300, self._process_popup_queue)
                else:
                    self._popup_queue_active = False

        def on_pause_min(extension):
            """关闭弹窗1分钟：暂停弹窗提醒60秒，期间静默阻止"""
            self._popup_paused_until = time.time() + 60
            self._append_log(f"{extension} 弹窗已关闭1分钟，期间静默阻止", "warn")
            log_event(extension, "弹窗", "暂停1分钟", "用户选择关闭弹窗1分钟")

        def on_forever(extension):
            """永久关闭：该扩展名永久忽略（加入白名单），不再弹窗与阻止"""
            whitelist = self.baseline_mgr.config.get("whitelist_exts", [])
            if not any(e.lower() == extension.lower() for e in whitelist):
                whitelist.append(extension)
                self.baseline_mgr.config["whitelist_exts"] = whitelist
                try:
                    self.baseline_mgr.save()
                except Exception:
                    pass
            self.baseline_mgr.update_extension(extension)
            self.engine.clear_cooldown(extension)
            self.engine.allowed_this_cycle.add(extension)
            if self.monitor is not None:
                self.monitor.persistent_tracker.clear_ext_history(extension)
            self.change_history.add_record(extension, tamperer_name, changes_for_history, "forever_ignore", "success")
            self._append_log(f"已永久关闭 {extension} 的弹窗提醒（加入白名单，不再阻止）", "warn")
            log_event(extension, "更改", "永久忽略", "用户永久关闭弹窗")

        # 单个模式：如果当前有活动弹窗，加入队列不立即显示
        if popup_mode == "single" and self.active_toasts:
            self._popup_queue.append((ext, mismatches, recover_result, extra_timeout))
            self._append_log(f"{ext} 已加入弹窗队列（当前{len(self._popup_queue)}个等待）", "info")
            return

        # 识别篡改者
        tamperer_name = None
        for key, bl_val, cur_val, _ in mismatches:
            if key in ("userchoice_progid", "hkcr_ext", "hkcu_ext", "hklm_ext") and cur_val:
                tamperer_name, _ = identify_tamperer(cur_val)
                break

        # 计算超时时间
        if popup_mode == "single" and self._popup_last_reason == "timeout":
            timeout = 6  # 上一个超时自动阻止 → 下一个缩短为6秒（用户反馈2秒太短）
            self._append_log(f"上一个弹窗超时自动阻止，本次弹窗超时缩短为6秒", "info")
        else:
            _cfg_timeout = self.baseline_mgr.config.get("block_timeout", NOTIFY_TIMEOUT)
            if _cfg_timeout < 1: _cfg_timeout = 1
            elif _cfg_timeout > 180: _cfg_timeout = 180
            timeout = _cfg_timeout + extra_timeout
            if extra_timeout > 0:
                self._append_log(f"批量篡改防护生效，本次弹窗自动阻止时间+{extra_timeout}秒", "info")

        # 同时模式：向右水平扩展（不重叠）；单个模式：固定位置
        if popup_mode == "simultaneous":
            stack_count = len(self.active_toasts)
            y_offset = 0
            x_offset = stack_count * (NotificationToast.TOAST_WIDTH + 10)
        else:
            y_offset = 0
            x_offset = 0

        toast = NotificationToast(self.root, ext, mismatches, recover_result,
                                  on_consent, on_close, on_pause_min, on_forever,
                                  self._show_main_window,
                                  y_offset=y_offset, x_offset=x_offset, timeout=timeout,
                                  tamperer_name=tamperer_name)
        self.active_toasts.append(toast)
        self._popup_queue_active = True

    def _process_popup_queue(self):
        """单个模式：从队列取出下一个弹窗显示"""
        if not self._popup_queue:
            self._popup_queue_active = False
            # 不重置_popup_last_reason，保留到下一个弹窗使用
            return
        ext, mismatches, recover_result, extra_timeout = self._popup_queue.pop(0)
        # 递归调用_show_notification，此时active_toasts为空，会直接显示
        self._show_notification(ext, mismatches, recover_result, extra_timeout)

    def _append_log(self, msg, level="info"):
        # 线程安全：非主线程调用时通过 after 调度到主线程
        if threading.current_thread() is not threading.main_thread():
            self.root.after(0, self._append_log, msg, level)
            return
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.configure(state="normal")
        self.log_text.insert("end", f"[{timestamp}] {msg}\n", level)
        self.log_text.see("end")
        self.log_text.configure(state="disabled")
        # 主界面输出窗口（状态页"保护输出"）同步显示
        so = getattr(self, "status_output", None)
        if so is not None:
            try:
                so.configure(state="normal")
                so.insert("end", f"[{timestamp}] {msg}\n", level)
                so.see("end")
                so.configure(state="disabled")
            except Exception:
                pass

    def run(self):
        self.root.mainloop()


# ============================================================
# 单实例检测 + 自启动 + 激活已有实例
# ============================================================
def create_single_instance_mutex():
    """创建命名互斥体，返回 (mutex_handle, is_first_instance)"""
    mutex = _CreateMutexW(None, False, MUTEX_NAME)
    is_first = (ctypes.get_last_error() != 183)  # 183 = ERROR_ALREADY_EXISTS
    return mutex, is_first


def activate_existing_instance():
    """第二个实例启动时，通过命名事件通知已有实例显示主窗口，然后退出。
    命名事件比 FindWindowW 更可靠（不依赖窗口标题，对隐藏窗口有效）。"""
    if signal_show_window():
        sys.exit(0)
    # 事件方式失败，尝试 FindWindowW 兜底
    user32 = ctypes.WinDLL('user32', use_last_error=True)
    user32.FindWindowW.restype = ctypes.c_void_p
    user32.ShowWindow.restype = ctypes.c_int
    user32.SetForegroundWindow.restype = ctypes.c_int
    hwnd = user32.FindWindowW(None, f"{APP_NAME} v{APP_VERSION}")
    if hwnd:
        user32.ShowWindow(hwnd, 5)  # SW_SHOW
        user32.SetForegroundWindow(hwnd)
        sys.exit(0)
    # 完全找不到：可能残留互斥体，释放并正常启动
    return None


def create_exit_event():
    """创建退出信号事件（自动重置），返回句柄"""
    _CreateEventW = kernel32.CreateEventW
    _CreateEventW.restype = ctypes.c_void_p
    _CreateEventW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_wchar_p]
    # bManualReset=False(自动重置), bInitialState=False
    return _CreateEventW(None, False, False, EXIT_EVENT_NAME)


def signal_exit():
    """设置退出事件，通知运行中的实例退出。返回是否成功"""
    _OpenEventW = kernel32.OpenEventW
    _OpenEventW.restype = ctypes.c_void_p
    _OpenEventW.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_wchar_p]
    _SetEvent = kernel32.SetEvent
    _SetEvent.restype = ctypes.c_int
    _SetEvent.argtypes = [ctypes.c_void_p]
    _CloseHandle = kernel32.CloseHandle
    _CloseHandle.restype = ctypes.c_int
    _CloseHandle.argtypes = [ctypes.c_void_p]
    EVENT_MODIFY_STATE = 0x0002
    h = _OpenEventW(EVENT_MODIFY_STATE, False, EXIT_EVENT_NAME)
    if h:
        _SetEvent(h)
        _CloseHandle(h)
        return True
    return False


def check_exit_event(hEvent):
    """检查退出事件是否被触发。返回 True 表示收到退出信号"""
    if not hEvent:
        return False
    WAIT_OBJECT_0 = 0
    WAIT_TIMEOUT = 258
    ret = _WaitForSingleObject(hEvent, 0)  # 0超时，不阻塞
    return ret == WAIT_OBJECT_0


def create_show_event():
    """创建显示窗口事件（自动重置）"""
    _CreateEventW = kernel32.CreateEventW
    _CreateEventW.restype = ctypes.c_void_p
    _CreateEventW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_wchar_p]
    return _CreateEventW(None, False, False, SHOW_EVENT_NAME)


def signal_show_window():
    """设置显示窗口事件，通知运行中的实例显示主窗口。返回是否成功"""
    _OpenEventW = kernel32.OpenEventW
    _OpenEventW.restype = ctypes.c_void_p
    _OpenEventW.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_wchar_p]
    _SetEvent = kernel32.SetEvent
    _SetEvent.restype = ctypes.c_int
    _SetEvent.argtypes = [ctypes.c_void_p]
    _CloseHandle = kernel32.CloseHandle
    _CloseHandle.restype = ctypes.c_int
    _CloseHandle.argtypes = [ctypes.c_void_p]
    EVENT_MODIFY_STATE = 0x0002
    h = _OpenEventW(EVENT_MODIFY_STATE, False, SHOW_EVENT_NAME)
    if h:
        _SetEvent(h)
        _CloseHandle(h)
        return True
    return False


def add_to_autostart():
    """添加到开机自启动（HKCU Run），返回 bool"""
    exe_path = None
    try:
        if getattr(sys, 'frozen', False):
            exe_path = sys.executable
        else:
            exe_path = os.path.abspath(sys.argv[0])
        key = winreg.OpenKey(HKCU, AUTOSTART_KEY, 0, winreg.KEY_SET_VALUE | KEY_READ_64)
        # 开机自启动带 -m 最小化参数：后台常驻，不打扰
        winreg.SetValueEx(key, APP_NAME, 0, winreg.REG_SZ, f'"{exe_path}" -m')
        winreg.CloseKey(key)
        return True
    except OSError as e:
        logger.error(f"添加自启动失败(winreg): {e}")
        # 兜底：部分受限环境 winreg 打开被拒时改用 reg 命令
        # （/d 值内引号需以 \" 转义，reg 才能写入带引号的路径）
        try:
            import subprocess
            if exe_path is None:
                exe_path = sys.executable
            r = subprocess.run(
                ["reg", "add", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                 "/v", APP_NAME, "/d", f'\\"{exe_path}\\" -m', "/f"],
                capture_output=True, text=True)
            return r.returncode == 0
        except Exception as e2:
            logger.error(f"添加自启动失败(reg兜底): {e2}")
            return False


def is_autostart_set():
    """检查是否已添加自启动（值必须带 -m 最小化参数才算有效）"""
    try:
        key = winreg.OpenKey(HKCU, AUTOSTART_KEY, 0, KEY_READ_64)
        val, _ = winreg.QueryValueEx(key, APP_NAME)
        winreg.CloseKey(key)
        if not val:
            return False
        # 旧版本写入的裸路径（不带 -m）视为未设置，启动时自动升级为带 -m 的启动项
        if "-m" not in str(val):
            return False
        return True
    except OSError:
        return False


def remove_from_autostart():
    """从开机自启动移除，返回 bool"""
    try:
        key = winreg.OpenKey(HKCU, AUTOSTART_KEY, 0, winreg.KEY_SET_VALUE | KEY_READ_64)
        winreg.DeleteValue(key, APP_NAME)
        winreg.CloseKey(key)
        return True
    except OSError:
        # 兜底：reg 命令删除
        try:
            import subprocess
            r = subprocess.run(
                ["reg", "delete", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                 "/v", APP_NAME, "/f"],
                capture_output=True, text=True)
            return r.returncode == 0
        except Exception:
            return False


# ============================================================
# 管理员权限检查
# ============================================================
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False


def _kill_opst_except_self():
    """taskkill 所有 OPSTcontroller 进程（排除自身 PID）。
    修复：taskkill /IM 会误杀 --stop 实例自己，导致提权强杀流程中断。"""
    try:
        r = _run(['tasklist', '/FI', 'IMAGENAME eq OPSTcontroller.exe', '/FO', 'CSV'],
                 capture_output=True, text=True)
        pids = []
        for line in r.stdout.splitlines():
            if 'OPSTcontroller.exe' not in line:
                continue
            parts = line.split('","')
            if len(parts) >= 2:
                pid = parts[1].strip('"').strip()
                if pid.isdigit() and int(pid) != os.getpid():
                    pids.append(pid)
        for pid in pids:
            _run(['taskkill', '/F', '/PID', pid], capture_output=True)
        return len(pids)
    except Exception:
        return 0


def _force_kill_all_opst():
    """管理员+SeDebug 强杀所有 OPSTcontroller 进程（排除自身）。
    自我保护实例对普通令牌返回 ACCESS_DENIED；管理员启用 SeDebugPrivilege
    后可绕过 Deny ACL 完成 TerminateProcess（与 kill_admin.py 同机制）。"""
    try:
        kernel32 = ctypes.windll.kernel32
        enable_all_privileges()
        self_pid = os.getpid()
        TH32CS_SNAPPROCESS = 0x00000002
        class _PE32(ctypes.Structure):
            _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
                        ("th32ProcessID", wintypes.DWORD),
                        ("th32DefaultHeapID", ctypes.c_void_p),
                        ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
                        ("th32ParentProcessID", wintypes.DWORD),
                        ("pcPriClassBase", ctypes.c_long), ("dwFlags", wintypes.DWORD),
                        ("szExeFile", ctypes.c_wchar * 260)]
        snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if snapshot in (-1, 0):
            return 0
        killed = 0
        pe = _PE32()
        pe.dwSize = ctypes.sizeof(_PE32)
        if kernel32.Process32FirstW(snapshot, ctypes.byref(pe)):
            while True:
                if pe.szExeFile.lower() == "opstcontroller.exe" and pe.th32ProcessID != self_pid:
                    h = kernel32.OpenProcess(0x1001, False, pe.th32ProcessID)  # TERMINATE|QUERY
                    if h:
                        if kernel32.TerminateProcess(h, 1):
                            killed += 1
                        kernel32.CloseHandle(h)
                if not kernel32.Process32NextW(snapshot, ctypes.byref(pe)):
                    break
        kernel32.CloseHandle(snapshot)
        try:
            log_event("KillAdmin", "完成", f"强杀结果", f"killed={killed} admin={is_admin()}")
        except Exception:
            pass
        return killed
    except Exception as e:
        try:
            log_event("KillAdmin", "异常", "强杀失败", repr(e))
        except Exception:
            pass
        return -1


def run_as_admin():
    """以管理员权限重新启动程序"""
    try:
        if getattr(sys, 'frozen', False):
            # 打包后：直接以管理员身份运行 exe
            params = ' '.join([f'"{arg}"' for arg in sys.argv[1:]])
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, params, None, 1
            )
        else:
            # 脚本模式：python script.py
            script = os.path.abspath(sys.argv[0])
            params = ' '.join([f'"{arg}"' for arg in sys.argv[1:]])
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, f'"{script}" {params}', None, 1
            )
    except Exception as e:
        print(f"无法提升权限: {e}")


def get_current_token_privileges():
    """返回当前进程令牌中已启用特权的名称列表。用于判断提权前置条件是否满足。"""
    try:
        advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)
        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        HANDLE = ctypes.c_void_p
        DWORD = ctypes.c_uint32
        BOOL = ctypes.c_int
        LUID = ctypes.c_ulonglong
        TOKEN_PRIVILEGES = ctypes.c_void_p

        kernel32.GetCurrentProcess.restype = HANDLE
        kernel32.GetCurrentProcess.argtypes = []
        kernel32.CloseHandle.restype = BOOL
        kernel32.CloseHandle.argtypes = [HANDLE]
        advapi32.OpenProcessToken.restype = BOOL
        advapi32.OpenProcessToken.argtypes = [HANDLE, DWORD, ctypes.POINTER(HANDLE)]
        advapi32.GetTokenInformation.restype = BOOL
        advapi32.GetTokenInformation.argtypes = [HANDLE, ctypes.c_uint, ctypes.c_void_p, DWORD, ctypes.POINTER(DWORD)]
        advapi32.LookupPrivilegeNameW.restype = BOOL
        advapi32.LookupPrivilegeNameW.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(LUID), ctypes.c_void_p, ctypes.POINTER(DWORD)]

        hToken = HANDLE()
        if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), 0x0020, ctypes.byref(hToken)):
            return []

        class LUID_AND_ATTRIBUTES(ctypes.Structure):
            # Windows 实际布局 12 字节/条，数组型结构必须 pack=4
            _pack_ = 4
            _fields_ = [("Luid", LUID), ("Attributes", DWORD)]
        class TOKEN_PRIVILEGES_STRUCT(ctypes.Structure):
            _fields_ = [("PrivilegeCount", DWORD), ("Privileges", LUID_AND_ATTRIBUTES * 64)]

        token_privs = TOKEN_PRIVILEGES_STRUCT()
        needed = DWORD()
        if not advapi32.GetTokenInformation(hToken, 3, ctypes.byref(token_privs), ctypes.sizeof(token_privs), ctypes.byref(needed)):
            kernel32.CloseHandle(hToken)
            return []

        enabled = []
        for i in range(token_privs.PrivilegeCount):
            attr = token_privs.Privileges[i].Attributes
            if not attr & 0x00000002:
                continue
            luid = token_privs.Privileges[i].Luid
            name_buf = ctypes.create_unicode_buffer(256)
            name_len = DWORD(256)
            # 仅输出已启用的，避免误报
            if advapi32.LookupPrivilegeNameW(None, ctypes.byref(luid), name_buf, ctypes.byref(name_len)):
                enabled.append(name_buf.value)

        kernel32.CloseHandle(hToken)
        return enabled
    except Exception:
        return []


def get_ti_precheck_failure_reason():
    """返回真实的提权前置条件失败原因，供日志输出。"""
    reasons = []
    if not is_admin():
        reasons.append("当前会话不是一个真实管理员 token（IsUserAnAdmin=False）")
    enabled = set(get_current_token_privileges())
    required = [
        "SeImpersonatePrivilege",
        "SeAssignPrimaryTokenPrivilege",
        "SeIncreaseQuotaPrivilege",
        "SeDebugPrivilege",
        "SeTcbPrivilege",
    ]
    missing = [p for p in required if p not in enabled]
    if missing:
        reasons.append(f"当前会话缺少关键提权特权：{', '.join(missing)}")
    nsudo_exe = _find_nsudo_exe()
    if not nsudo_exe:
        reasons.append("备用提权链路缺失：runtime 和项目候选目录中未发现 NSudoLC.exe/NSudoLG.exe")
    if not reasons:
        reasons.append("当前会话已具备管理员/特权上下文，但 TrustedInstaller token 仍未建立")
    return "; ".join(reasons)


# ============================================================
# TrustedInstaller 提权（无视权限模式）
# 原理：获取 TrustedInstaller 服务的进程令牌，以该令牌启动自身
# ============================================================
def get_real_permission_detail():
    """绝对真实地检测当前进程权限状态。
    返回 (status_text, is_ti_system, is_admin, integrity_level, user_sid)
    status_text: "TI(TrustedInstaller)" / "SYSTEM" / "管理员" / "普通用户"
    检测依据：进程令牌的用户SID + 完整性级别 + IsUserAnAdmin，三重验证。
    """
    try:
        advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)
        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        HANDLE = ctypes.c_void_p
        DWORD = ctypes.c_uint32
        BOOL = ctypes.c_int

        kernel32.GetCurrentProcess.restype = HANDLE
        kernel32.GetCurrentProcess.argtypes = []
        kernel32.CloseHandle.restype = BOOL
        kernel32.CloseHandle.argtypes = [HANDLE]
        advapi32.OpenProcessToken.restype = BOOL
        advapi32.OpenProcessToken.argtypes = [HANDLE, DWORD, ctypes.POINTER(HANDLE)]
        advapi32.GetTokenInformation.restype = BOOL
        advapi32.GetTokenInformation.argtypes = [HANDLE, ctypes.c_uint, ctypes.c_void_p, DWORD, ctypes.POINTER(DWORD)]
        advapi32.ConvertSidToStringSidW.restype = BOOL
        advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_wchar_p)]

        hToken = HANDLE()
        if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), 0x0018, ctypes.byref(hToken)):
            return "普通用户", False, False, "未知", ""

        class SID_AND_ATTRIBUTES(ctypes.Structure):
            # Windows x64 实际布局 16 字节/条（PSID 8 对齐到8 + Attributes 4 + 尾部填充4）。
            # 含指针成员不能 pack=4（那会变成 12，数组型 TokenGroups 读错位）。
            _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", DWORD)]
        class TOKEN_USER(ctypes.Structure):
            _fields_ = [("User", SID_AND_ATTRIBUTES)]

        tuser = TOKEN_USER()
        needed = DWORD()
        user_sid = ""
        if not advapi32.GetTokenInformation(hToken, 1, ctypes.byref(tuser), ctypes.sizeof(tuser), ctypes.byref(needed)):
            buf_size = max(needed.value if needed.value else 4096, ctypes.sizeof(tuser))
            tuser_buf = ctypes.create_string_buffer(buf_size)
            if advapi32.GetTokenInformation(hToken, 1, tuser_buf, buf_size, ctypes.byref(needed)):
                user_ptr = ctypes.cast(tuser_buf, ctypes.POINTER(TOKEN_USER)).contents.User.Sid
                sid_str = ctypes.c_wchar_p()
                if advapi32.ConvertSidToStringSidW(user_ptr, ctypes.byref(sid_str)) and sid_str.value:
                    user_sid = sid_str.value
        else:
            user_ptr = tuser.User.Sid
            sid_str = ctypes.c_wchar_p()
            if advapi32.ConvertSidToStringSidW(user_ptr, ctypes.byref(sid_str)) and sid_str.value:
                user_sid = sid_str.value

        integrity = "未知"
        try:
            class TOKEN_MANDATORY_LABEL(ctypes.Structure):
                _fields_ = [("Label", SID_AND_ATTRIBUTES)]
            tml_buf = ctypes.create_string_buffer(256)
            tml_needed = DWORD()
            if advapi32.GetTokenInformation(hToken, 25, tml_buf, 256, ctypes.byref(tml_needed)):
                label_sid = ctypes.cast(tml_buf, ctypes.POINTER(TOKEN_MANDATORY_LABEL)).contents.Label.Sid
                il_sid_str = ctypes.c_wchar_p()
                if advapi32.ConvertSidToStringSidW(label_sid, ctypes.byref(il_sid_str)) and il_sid_str.value:
                    il = il_sid_str.value
                    if il.endswith("-16384"):
                        integrity = "System"
                    elif il.endswith("-12288"):
                        integrity = "High"
                    elif il.endswith("-8192"):
                        integrity = "Medium"
                    elif il.endswith("-4096"):
                        integrity = "Low"
                    else:
                        integrity = il.split("-")[-1]
        except Exception:
            pass

        # 枚举令牌组：检测 TI 服务组（S-1-5-80-956008885-...）。
        # NSudo 8.2 的 -U:T 实际产出"SYSTEM 身份 + TI 组"令牌（能力等同 TrustedInstaller 服务），
        # 仅看 user SID 会误判为普通 SYSTEM，导致界面显示"SYSTEM"而非 TI。
        ti_group_present = False
        try:
            class TOKEN_GROUPS(ctypes.Structure):
                _fields_ = [("GroupCount", DWORD), ("Groups", SID_AND_ATTRIBUTES * 64)]
            tg = TOKEN_GROUPS()
            tg_needed = DWORD()
            if advapi32.GetTokenInformation(hToken, 2, ctypes.byref(tg), ctypes.sizeof(tg), ctypes.byref(tg_needed)):
                for gi in range(min(tg.GroupCount, 64)):
                    g_sid = tg.Groups[gi].Sid
                    g_str = ctypes.c_wchar_p()
                    if (g_sid and advapi32.ConvertSidToStringSidW(g_sid, ctypes.byref(g_str))
                            and g_str.value and g_str.value.startswith("S-1-5-80-956008885-")):
                        ti_group_present = True
                        break
        except Exception:
            pass

        kernel32.CloseHandle(hToken)

        is_ti_system = False
        is_admin = False
        status = "普通用户"

        if user_sid == "S-1-5-18":
            status = "SYSTEM"
            is_ti_system = True
            if ti_group_present:
                # SYSTEM 身份 + TI 服务组 = TrustedInstaller 能力（NSudo 8.2 -U:T 形态）
                status = "TI/SYSTEM"
        elif user_sid.startswith("S-1-5-80-956008885-"):
            status = "TI(TrustedInstaller)"
            is_ti_system = True
        elif user_sid.startswith("S-1-5-80-"):
            status = "TI(TrustedInstaller)"
            is_ti_system = True
        else:
            try:
                is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
            except Exception:
                is_admin = False
            if is_admin:
                status = "管理员"
            else:
                status = "普通用户"

        if is_ti_system and integrity and integrity != "System" and integrity != "未知":
            status = status + "(完整性" + integrity + ")"

        return status, is_ti_system, is_admin, integrity, user_sid
    except Exception:
        return "普通用户", False, False, "未知", ""


def is_system_or_ti():
    """检查当前是否以 SYSTEM 或 TrustedInstaller 权限运行。基于真实令牌SID检测。"""
    _, is_ti_sys, _, _, _ = get_real_permission_detail()
    return is_ti_sys


def get_current_permission_status():
    """返回 (状态文本, 是否为 TI/SYSTEM, 是否为管理员)。严格按当前进程真实令牌判断。"""
    status, is_ti_sys, is_admin, _, _ = get_real_permission_detail()
    return status, is_ti_sys, is_admin


def get_runtime_permission_label(base_status, ti_attempt_failed=False):
    """把当前权限状态显式化：真实权限优先，失败的 TI 提权不混进状态文字中。"""
    if base_status == "TI/SYSTEM":
        return "TI/SYSTEM"
    if base_status == "管理员":
        return "管理员"
    return "普通用户"


def run_as_trustedinstaller():
    """
    以 TrustedInstaller 权限重新启动程序。
    返回 True 表示已发起提权重启（当前进程应退出），False 表示提权失败。
    所有错误写入日志文件（windowed模式下print不可见）。
    所有Win32 API均显式声明argtypes+restype，避免64位句柄截断/溢出。
    """
    try:
        advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)
        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

        # ===== 所有API完整类型声明（64位安全）=====
        LPWSTR = ctypes.c_wchar_p
        DWORD = ctypes.c_uint32
        BOOL = ctypes.c_int
        HANDLE = ctypes.c_void_p
        LPVOID = ctypes.c_void_p
        LPDWORD = ctypes.POINTER(DWORD)

        # 结构体
        class LUID(ctypes.Structure):
            _fields_ = [("LowPart", DWORD), ("HighPart", ctypes.c_long)]
        class LUID_AND_ATTRIBUTES(ctypes.Structure):
            # Windows 实际布局 12 字节/条，pack=4 保持一致
            _pack_ = 4
            _fields_ = [("Luid", LUID), ("Attributes", DWORD)]
        class TOKEN_PRIVILEGES(ctypes.Structure):
            _fields_ = [("PrivilegeCount", DWORD), ("Privileges", LUID_AND_ATTRIBUTES * 1)]
        class SERVICE_STATUS_PROCESS(ctypes.Structure):
            _fields_ = [
                ("dwServiceType", DWORD), ("dwCurrentState", DWORD),
                ("dwControlsAccepted", DWORD), ("dwWin32ExitCode", DWORD),
                ("dwServiceSpecificExitCode", DWORD), ("dwCheckPoint", DWORD),
                ("dwWaitHint", DWORD), ("dwProcessId", DWORD), ("dwServiceFlags", DWORD),
            ]
        class STARTUPINFOW(ctypes.Structure):
            _fields_ = [
                ("cb", DWORD), ("lpReserved", LPWSTR), ("lpDesktop", LPWSTR),
                ("lpTitle", LPWSTR), ("dwX", DWORD), ("dwY", DWORD),
                ("dwXSize", DWORD), ("dwYSize", DWORD),
                ("dwXCountChars", DWORD), ("dwYCountChars", DWORD),
                ("dwFillAttribute", DWORD), ("dwFlags", DWORD),
                ("wShowWindow", ctypes.c_ushort), ("cbReserved2", ctypes.c_ushort),
                ("lpReserved2", LPVOID), ("hStdInput", HANDLE),
                ("hStdOutput", HANDLE), ("hStdError", HANDLE),
            ]
        class PROCESS_INFORMATION(ctypes.Structure):
            _fields_ = [("hProcess", HANDLE), ("hThread", HANDLE),
                        ("dwProcessId", DWORD), ("dwThreadId", DWORD)]

        # API 原型声明
        advapi32.OpenSCManagerW.restype = HANDLE
        advapi32.OpenSCManagerW.argtypes = [LPWSTR, LPWSTR, DWORD]
        advapi32.OpenServiceW.restype = HANDLE
        advapi32.OpenServiceW.argtypes = [HANDLE, LPWSTR, DWORD]
        advapi32.CloseServiceHandle.restype = BOOL
        advapi32.CloseServiceHandle.argtypes = [HANDLE]
        advapi32.QueryServiceStatusEx.restype = BOOL
        advapi32.QueryServiceStatusEx.argtypes = [HANDLE, DWORD, LPVOID, DWORD, LPDWORD]
        advapi32.StartServiceW.restype = BOOL
        advapi32.StartServiceW.argtypes = [HANDLE, DWORD, ctypes.POINTER(LPWSTR)]
        kernel32.OpenProcess.restype = HANDLE
        kernel32.OpenProcess.argtypes = [DWORD, BOOL, DWORD]
        kernel32.CloseHandle.restype = BOOL
        kernel32.CloseHandle.argtypes = [HANDLE]
        kernel32.GetCurrentProcess.restype = HANDLE
        kernel32.GetCurrentProcess.argtypes = []
        advapi32.OpenProcessToken.restype = BOOL
        advapi32.OpenProcessToken.argtypes = [HANDLE, DWORD, ctypes.POINTER(HANDLE)]
        advapi32.DuplicateTokenEx.restype = BOOL
        advapi32.DuplicateTokenEx.argtypes = [HANDLE, DWORD, LPVOID, ctypes.c_int, ctypes.c_int, ctypes.POINTER(HANDLE)]
        advapi32.LookupPrivilegeValueW.restype = BOOL
        advapi32.LookupPrivilegeValueW.argtypes = [LPWSTR, LPWSTR, ctypes.POINTER(LUID)]
        advapi32.AdjustTokenPrivileges.restype = BOOL
        advapi32.AdjustTokenPrivileges.argtypes = [HANDLE, BOOL, ctypes.POINTER(TOKEN_PRIVILEGES), DWORD, LPVOID, LPDWORD]
        advapi32.CreateProcessWithTokenW.restype = BOOL
        advapi32.CreateProcessWithTokenW.argtypes = [HANDLE, DWORD, LPWSTR, LPWSTR, DWORD, LPVOID, LPWSTR, ctypes.POINTER(STARTUPINFOW), ctypes.POINTER(PROCESS_INFORMATION)]
        advapi32.CreateProcessAsUserW.restype = BOOL
        advapi32.CreateProcessAsUserW.argtypes = [HANDLE, LPWSTR, LPWSTR, LPVOID, LPVOID, BOOL, DWORD, LPVOID, LPWSTR, ctypes.POINTER(STARTUPINFOW), ctypes.POINTER(PROCESS_INFORMATION)]

        def _log(msg):
            try:
                log_event("TI提权", "步骤", msg, "")
            except Exception:
                pass

        # 1. 打开服务控制管理器
        scm = advapi32.OpenSCManagerW(None, None, 0x0001)  # SC_MANAGER_CONNECT
        if not scm:
            _log(f"OpenSCManager失败,错误码:{ctypes.get_last_error()}")
            return False
        _log("已打开服务控制管理器")

        # 2. 打开 TrustedInstaller 服务
        service = advapi32.OpenServiceW(scm, "TrustedInstaller", 0x0010 | 0x0020 | 0x0008)
        advapi32.CloseServiceHandle(scm)
        if not service:
            _log(f"OpenService失败,错误码:{ctypes.get_last_error()}")
            return False
        _log("已打开TrustedInstaller服务")

        # 3. 查询服务状态，如果未运行则启动
        ssp = SERVICE_STATUS_PROCESS()
        bytes_needed = DWORD()
        qok = advapi32.QueryServiceStatusEx(service, 0, ctypes.byref(ssp), ctypes.sizeof(ssp), ctypes.byref(bytes_needed))
        if not qok:
            _log(f"QueryServiceStatusEx失败,错误码:{ctypes.get_last_error()},内置方法放弃,将使用NSudo")
            advapi32.CloseServiceHandle(service)
            return False

        if ssp.dwCurrentState != 4:  # SERVICE_RUNNING
            _log(f"TrustedInstaller服务未运行(状态:{ssp.dwCurrentState}),正在启动...")
            start_ok = advapi32.StartServiceW(service, 0, None)
            start_err = ctypes.get_last_error()
            if not start_ok and start_err != 1056:  # 1056=ERROR_SERVICE_ALREADY_RUNNING视为成功
                _log(f"StartServiceW返回失败,错误码:{start_err},尝试sc.exe方式...")
                try:
                    import subprocess
                    _run(['sc.exe', 'start', 'TrustedInstaller'], capture_output=True, timeout=10)
                except Exception as e2:
                    _log(f"sc.exe启动异常:{e2}")
            elif start_err == 1056:
                _log("StartService返回1056(服务已在运行),直接查询状态")
            for _ in range(15):  # 最多3秒，快速失败交给NSudo
                time.sleep(0.2)
                if advapi32.QueryServiceStatusEx(service, 0, ctypes.byref(ssp), ctypes.sizeof(ssp), ctypes.byref(bytes_needed)):
                    if ssp.dwCurrentState == 4:
                        break
                else:
                    _log(f"轮询中QueryServiceStatusEx失败,错误码:{ctypes.get_last_error()}")
                    break
            if ssp.dwCurrentState != 4:
                _log(f"TrustedInstaller服务启动失败,最终状态:{ssp.dwCurrentState},StartService错误码:{start_err}")
                advapi32.CloseServiceHandle(service)
                return False

        ti_pid = ssp.dwProcessId
        advapi32.CloseServiceHandle(service)
        _log(f"TrustedInstaller服务运行中,PID:{ti_pid}")

        if ti_pid == 0:
            _log("TrustedInstaller PID为0")
            return False

        # 4. 打开 TrustedInstaller 进程
        hProcess = kernel32.OpenProcess(0x0400, False, ti_pid)  # PROCESS_QUERY_INFORMATION
        if not hProcess:
            _log(f"OpenProcess失败,错误码:{ctypes.get_last_error()}")
            return False
        _log("已打开TrustedInstaller进程")

        # 5. 打开进程令牌（MAXIMUM_ALLOWED确保所有权限）
        hToken = HANDLE()
        if not advapi32.OpenProcessToken(hProcess, 0x02000000, ctypes.byref(hToken)):  # MAXIMUM_ALLOWED
            _log(f"OpenProcessToken失败,错误码:{ctypes.get_last_error()}")
            kernel32.CloseHandle(hProcess)
            return False
        kernel32.CloseHandle(hProcess)
        _log("已打开TrustedInstaller进程令牌")

        # 6. 复制令牌（主令牌）
        hDupToken = HANDLE()
        if not advapi32.DuplicateTokenEx(hToken, 0x10000000, None, 2, 1, ctypes.byref(hDupToken)):
            _log(f"DuplicateTokenEx失败,错误码:{ctypes.get_last_error()}")
            kernel32.CloseHandle(hToken)
            return False
        kernel32.CloseHandle(hToken)
        _log("已复制TrustedInstaller令牌(主令牌)")

        # 7. 启用当前进程必需特权
        hCurToken = HANDLE()
        advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), 0x0020 | 0x0008, ctypes.byref(hCurToken))
        enabled_privs = []
        for priv_name in ("SeImpersonatePrivilege", "SeAssignPrimaryTokenPrivilege", "SeIncreaseQuotaPrivilege", "SeDebugPrivilege", "SeTcbPrivilege"):
            luid = LUID()
            if advapi32.LookupPrivilegeValueW(None, priv_name, ctypes.byref(luid)):
                tp = TOKEN_PRIVILEGES()
                tp.PrivilegeCount = 1
                tp.Privileges[0].Luid = luid
                tp.Privileges[0].Attributes = 0x00000002  # SE_ENABLED
                advapi32.AdjustTokenPrivileges(hCurToken, False, ctypes.byref(tp), 0, None, None)
                if ctypes.get_last_error() == 0:
                    enabled_privs.append(priv_name)
        kernel32.CloseHandle(hCurToken)
        _log(f"已启用特权:{','.join(enabled_privs) if enabled_privs else '无'}")

        required_privs = ["SeImpersonatePrivilege", "SeAssignPrimaryTokenPrivilege", "SeIncreaseQuotaPrivilege", "SeDebugPrivilege", "SeTcbPrivilege"]
        missing_privs = [p for p in required_privs if p not in get_current_token_privileges()]
        if missing_privs:
            _log(f"提权前置条件未满足：当前令牌缺少关键特权 {missing_privs}")
            return False

        # 8. 以 TrustedInstaller 令牌启动自身
        if getattr(sys, 'frozen', False):
            exe_path = sys.executable
            cmdline = f'"{exe_path}"'
            if sys.argv[1:]:
                cmdline += ' ' + ' '.join([f'"{a}"' for a in sys.argv[1:]])
        else:
            exe_path = sys.executable
            script = os.path.abspath(sys.argv[0])
            cmdline = f'"{exe_path}" "{script}"'
            if sys.argv[1:]:
                cmdline += ' ' + ' '.join([f'"{a}"' for a in sys.argv[1:]])

        si = STARTUPINFOW()
        si.cb = ctypes.sizeof(si)

        # CreateProcessWithTokenW 的 lpCommandLine 必须是可写缓冲区
        cmdline_buf = ctypes.create_unicode_buffer(cmdline)

        def _new_pi():
            p = PROCESS_INFORMATION()
            return p

        # 方案1: CreateProcessWithTokenW (LOGON_WITH_PROFILE)
        pi = _new_pi()
        result = advapi32.CreateProcessWithTokenW(
            hDupToken, 0x1, None,  # LOGON_WITH_PROFILE=0x1
            cmdline_buf,
            0x00000010, None, None,  # CREATE_NEW_CONSOLE
            ctypes.byref(si), ctypes.byref(pi)
        )
        err1 = ctypes.get_last_error()

        # 方案2: CreateProcessWithTokenW (无logon flag)
        if not result:
            pi = _new_pi()
            result = advapi32.CreateProcessWithTokenW(
                hDupToken, 0, None,
                cmdline_buf,
                0x00000010, None, None,
                ctypes.byref(si), ctypes.byref(pi)
            )
            err2 = ctypes.get_last_error()
        else:
            err2 = 0

        # 方案3: CreateProcessAsUserW
        if not result:
            pi = _new_pi()
            result = advapi32.CreateProcessAsUserW(
                hDupToken, None, cmdline_buf,
                None, None, False,
                0x00000010, None, None,
                ctypes.byref(si), ctypes.byref(pi)
            )
            err3 = ctypes.get_last_error()
        else:
            err3 = 0

        kernel32.CloseHandle(hDupToken)
        if pi.hProcess:
            kernel32.CloseHandle(pi.hProcess)
        if pi.hThread:
            kernel32.CloseHandle(pi.hThread)

        if result:
            _log(f"提权成功,新PID:{pi.dwProcessId}")
            return True
        else:
            _log(f"三种方案均失败: WithToken(PROFILE)={err1}, WithToken(0)={err2}, AsUser={err3}")
            return False
    except Exception as e:
        import traceback
        try:
            log_event("TI提权", "异常", f"{type(e).__name__}: {e}", traceback.format_exc()[:500])
        except Exception:
            pass
        return False


def _find_nsudo_exe():
    """严格查找 NSudo：优先运行时目录/程序目录，支持 OPST_NSudo_PATH 环境变量覆盖，拒绝模糊搜索与个人路径。"""
    roots = []
    for base in (
        os.environ.get("OPST_NSudo_PATH", ""),
        NSUDO_ROOT,
        RUNTIME_DIR,
        APP_DIR,
        os.path.dirname(APP_DIR),
    ):
        if base and os.path.isdir(base):
            roots.append(base)

    seen = set()
    for root in roots:
        if root in seen:
            continue
        seen.add(root)
        for name in NSUDO_CANDIDATES:
            path = os.path.join(root, name)
            if os.path.isfile(path):
                target = os.path.join(RUNTIME_DIR, name)
                try:
                    os.makedirs(RUNTIME_DIR, exist_ok=True)
                    if os.path.abspath(path) != os.path.abspath(target):
                        shutil.copy2(path, target)
                except Exception:
                    pass
                return target if os.path.exists(target) else path
    return None


def _nsudo_precheck():
    """严格校验启动前提：管理员身份 + 有效 NSudo 路径 + 可执行文件存在。"""
    if not is_admin():
        return False, "当前会话不是管理员 token，无法执行 NSudo 提权。"
    nsudo_exe = _find_nsudo_exe()
    if not nsudo_exe or not os.path.isfile(nsudo_exe):
        return False, "未找到有效的 NSudo 可执行文件：请将其放入程序目录 runtime/ 下，或通过环境变量 OPST_NSudo_PATH 指定所在目录。"
    return True, nsudo_exe


def ensure_nsudo_available():
    """返回 (ok, path, reason)；所有提权必须经过严格前置检查。"""
    ok, result = _nsudo_precheck()
    if not ok:
        return False, None, result
    return True, result, "OK"


def elevate_via_nsudo():
    """使用 NSudo 以 TrustedInstaller/SYSTEM 权限重启当前程序。"""
    try:
        ok, nsudo_exe, reason = ensure_nsudo_available()
        if not ok:
            log_event("NSudo", "失败", reason, NSUDO_ROOT)
            return False

        if getattr(sys, 'frozen', False):
            target = sys.executable
        else:
            target = f'{sys.executable} "{os.path.abspath(sys.argv[0])}"'

        os.environ["OPST_SKIP_TI"] = "1"
        env = os.environ.copy()

        def _try_nsudo(user_mode):
            args = [nsudo_exe, f"-U:{user_mode}", "-P:E", "-ShowWindowMode:Show", target]
            log_event("NSudo", "调用", f"尝试模式={user_mode}", " ".join(args))
            try:
                proc = _run(args, cwd=RUNTIME_DIR, env=env, capture_output=True, text=True, timeout=20)
                out = (proc.stdout or "") + (proc.stderr or "")
                log_event("NSudo", "输出", f"返回码={proc.returncode}", out[:500] if out else "(无输出)")
                if proc.returncode == 0:
                    time.sleep(1)
                    found = any('OPSTcontroller.exe' in line for line in os.popen('tasklist /FI "IMAGENAME eq OPSTcontroller.exe" /NH').read().splitlines())
                    if found:
                        log_event("NSudo", "验证", "目标进程已启动", "")
                        return True, out
                    log_event("NSudo", "验证", "目标进程未找到，NSudo 命令已返回，但未观察到新实例", "")
                    return False, out
                return False, out
            except subprocess.TimeoutExpired:
                log_event("NSudo", "超时", f"模式={user_mode} 超时，可能已启动新实例", "")
                return True, "timeout(可能已启动)"
            except Exception as e:
                log_event("NSudo", "异常", f"模式={user_mode}: {e}", "")
                return False, str(e)

        for user_mode in ("T", "S"):
            ok, _ = _try_nsudo(user_mode)
            if ok:
                log_event("NSudo", "成功", f"已通过 NSudo({user_mode}) 发起提权", "")
                return True

        log_event("NSudo", "失败", "TrustedInstaller 和 SYSTEM 都未成功发起新实例", "")
        return False
    except Exception as e:
        log_event("NSudo", "异常", str(e), "")
        return False


def elevate_via_nsudo_system_only():
    """仅使用 NSudo 以 SYSTEM 权限重启程序。"""
    try:
        ok, nsudo_exe, reason = ensure_nsudo_available()
        if not ok:
            log_event("NSudo", "失败", reason, NSUDO_ROOT)
            return False

        if getattr(sys, 'frozen', False):
            target = sys.executable
        else:
            target = f'{sys.executable} "{os.path.abspath(sys.argv[0])}"'

        os.environ["OPST_SKIP_TI"] = "1"
        env = os.environ.copy()
        args = [nsudo_exe, "-U:S", "-P:E", "-ShowWindowMode:Show", target]
        log_event("NSudo", "调用", "尝试模式=S(SYSTEM)", " ".join(args))
        proc = _run(args, cwd=RUNTIME_DIR, env=env, capture_output=True, text=True, timeout=20)
        if proc.returncode == 0:
            time.sleep(1)
            found = any('OPSTcontroller.exe' in line for line in os.popen('tasklist /FI "IMAGENAME eq OPSTcontroller.exe" /NH').read().splitlines())
            if found:
                log_event("NSudo", "成功", "已通过 NSudo(SYSTEM) 发起提权", "")
                return True
        log_event("NSudo", "失败", "NSudo SYSTEM 提权未成功发起新实例", "")
        return False
    except Exception:
        return False


def enable_all_privileges():
    """启用当前进程令牌中所有可用特权（尽可能提升权限）"""
    try:
        advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)
        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        HANDLE = ctypes.c_void_p
        DWORD = ctypes.c_uint32
        kernel32.GetCurrentProcess.restype = HANDLE
        kernel32.GetCurrentProcess.argtypes = []
        kernel32.CloseHandle.restype = ctypes.c_int
        kernel32.CloseHandle.argtypes = [HANDLE]
        advapi32.OpenProcessToken.restype = ctypes.c_int
        advapi32.OpenProcessToken.argtypes = [HANDLE, DWORD, ctypes.POINTER(HANDLE)]
        advapi32.GetTokenInformation.restype = ctypes.c_int
        advapi32.GetTokenInformation.argtypes = [HANDLE, ctypes.c_uint, ctypes.c_void_p, DWORD, ctypes.POINTER(DWORD)]
        advapi32.AdjustTokenPrivileges.restype = ctypes.c_int
        advapi32.AdjustTokenPrivileges.argtypes = [HANDLE, ctypes.c_int, ctypes.c_void_p, DWORD, ctypes.c_void_p, ctypes.POINTER(DWORD)]

        hToken = HANDLE()
        if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), 0x0020 | 0x0008, ctypes.byref(hToken)):
            return 0

        class LUID(ctypes.Structure):
            _fields_ = [("LowPart", DWORD), ("HighPart", ctypes.c_long)]
        class LUID_AND_ATTRIBUTES(ctypes.Structure):
            # Windows 实际布局 12 字节/条（LUID 8 + Attributes 4，连续无填充）。
            # 默认对齐会让 sizeof 变 16，数组型 TokenPrivileges 全部读错位，必须 pack。
            _pack_ = 4
            _fields_ = [("Luid", LUID), ("Attributes", DWORD)]
        class TOKEN_PRIVILEGES(ctypes.Structure):
            _fields_ = [("PrivilegeCount", DWORD), ("Privileges", LUID_AND_ATTRIBUTES * 64)]

        tp = TOKEN_PRIVILEGES()
        ret_len = DWORD()
        if not advapi32.GetTokenInformation(hToken, 3, ctypes.byref(tp), ctypes.sizeof(tp), ctypes.byref(ret_len)):
            kernel32.CloseHandle(hToken)
            return 0

        count = min(tp.PrivilegeCount, 64)
        if count == 0:
            kernel32.CloseHandle(hToken)
            return 0

        # 一次性请求启用全部特权（全部成功则 err==0；1300=部分特权不可用）
        all_tp = TOKEN_PRIVILEGES()
        all_tp.PrivilegeCount = count
        for i in range(count):
            p = tp.Privileges[i]
            all_tp.Privileges[i].Luid = p.Luid
            all_tp.Privileges[i].Attributes = 0x00000002  # SE_ENABLED

        ctypes.set_last_error(0)
        ok = advapi32.AdjustTokenPrivileges(hToken, False, ctypes.byref(all_tp), 0, None, None)
        err = ctypes.get_last_error()
        if ok == 0:
            kernel32.CloseHandle(hToken)
            return 0
        if err != 1300:
            kernel32.CloseHandle(hToken)
            return count

        # 部分特权不可用（1300）：逐项确认实际成功数
        enabled_count = 0
        for i in range(count):
            one = TOKEN_PRIVILEGES()
            one.PrivilegeCount = 1
            one.Privileges[0].Luid = all_tp.Privileges[i].Luid
            one.Privileges[0].Attributes = 0x00000002
            ctypes.set_last_error(0)
            r2 = advapi32.AdjustTokenPrivileges(hToken, False, ctypes.byref(one), 0, None, None)
            e2 = ctypes.get_last_error()
            if r2 != 0 and e2 != 1300:
                enabled_count += 1
        kernel32.CloseHandle(hToken)
        return enabled_count
    except Exception:
        return 0


# ============================================================
# 主入口
# ============================================================
def main():
    # -m/--minimized：开机自启动最小化启动（须在提权分支之前检测，
    # 通过环境变量 OPST_MINIMIZED 让 NSudo 子进程(TI实例)同样最小化）
    _start_minimized = ("-m" in sys.argv) or ("--minimized" in sys.argv)
    if _start_minimized:
        try:
            os.environ["OPST_MINIMIZED"] = "1"
        except Exception:
            pass
    start_minimized = _start_minimized or (os.environ.get("OPST_MINIMIZED") == "1")

    # PyInstaller onefile 解压目录 _MEI 退出清理失败(弹"Failed to remove temporary
    # directory")的常见根因：进程工作目录位于 _MEI 内或子进程继承 _MEI 句柄。
    # 启动即切换到 exe 所在目录，消除 cwd 占用，减少退出时清理失败弹窗。
    if getattr(sys, 'frozen', False):
        try:
            exe_dir = os.path.dirname(os.path.abspath(sys.executable))
            if exe_dir and os.path.isdir(exe_dir):
                os.chdir(exe_dir)
        except Exception:
            pass
        # 清理历史 _MEI 残留（当前进程 _MEIPASS 本身除外）：
        # 仅尝试删除空目录（快速失败，绝不深度遍历），避免对运行中/占用
        # 目录 rmtree 深度遍历导致启动卡住；非空残留由 bootloader 或系统清理。
        try:
            cur_mei = os.path.normcase(getattr(sys, '_MEIPASS', '') or '')
            for d in glob.glob(os.path.join(tempfile.gettempdir(), "_MEI*")):
                try:
                    if cur_mei and os.path.normcase(os.path.abspath(d)) == cur_mei:
                        continue
                    os.rmdir(d)
                except Exception:
                    pass
        except Exception:
            pass
        # 延迟清理非空 _MEI 残留（防安全软件慢扫描锁文件）：后台线程在
        # 30 秒/90 秒后各重试一次，rmtree 失败静默忽略，不阻塞启动。
        # TI 子进程的环境块可能不含用户 TEMP（gettempdir 回退 C:\Windows\Temp），
        # 因此必须全根扫描：TEMP/TMP 环境变量 + gettempdir + 系统 Temp +
        # 所有用户 profile 的 AppData\Local\Temp。
        try:
            def _mei_roots():
                roots = []
                for k in ("TEMP", "TMP"):
                    v = os.environ.get(k)
                    if v:
                        roots.append(v)
                roots.append(tempfile.gettempdir())
                roots.append(os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "Temp"))
                try:
                    for p in glob.glob(os.path.join(r"C:\Users", "*", "AppData", "Local", "Temp")):
                        roots.append(p)
                except Exception:
                    pass
                uniq = []
                for r in roots:
                    if r and r not in uniq:
                        uniq.append(r)
                return uniq

            def _sweep_mei(tag):
                try:
                    ok_n = fail_n = 0
                    seen = set()
                    for root in _mei_roots():
                        for d in glob.glob(os.path.join(root, "_MEI*")):
                            ap = os.path.normcase(os.path.abspath(d))
                            if ap in seen:
                                continue
                            seen.add(ap)
                            try:
                                if cur_mei and ap == cur_mei:
                                    continue
                                shutil.rmtree(d, ignore_errors=False)
                                ok_n += 1
                            except Exception as e:
                                fail_n += 1
                                log_event("MEIClean", "失败", tag, f"{d}: {type(e).__name__}")
                    if ok_n or fail_n:
                        log_event("MEIClean", "延迟清理", tag,
                                  f"扫描根={len(_mei_roots())} 删除={ok_n} 失败={fail_n}")
                except Exception as e:
                    log_event("MEIClean", "异常", tag, repr(e))

            def _delayed_mei_cleanup():
                log_event("MEIClean", "线程", "启动",
                          f"TEMP={os.environ.get('TEMP')} TMP={os.environ.get('TMP')} "
                          f"gettempdir={tempfile.gettempdir()}")
                time.sleep(30)
                _sweep_mei("30s")
                time.sleep(60)
                _sweep_mei("90s")
            threading.Thread(target=_delayed_mei_cleanup, daemon=True).start()
        except Exception:
            pass

    # 窗口模式（PyInstaller --windowed）下无控制台，sys.stdout 可能为 None，
    # 需先兜底，避免 --stop 等路径的 print() 抛异常中断流程。
    if sys.stdout is None:
        try:
            import io
            sys.stdout = io.StringIO()
        except Exception:
            pass

    # 处理 --stop 命令：向运行中的实例发送退出信号。
    # 自我保护实例（TI/SYSTEM + Deny ACL）无法被普通令牌终止：
    # 信号（命名事件跨会话不可见）与 taskkill 均失败时，
    # 自动经 runas 提升到管理员执行 --stop-admin 强杀（SeDebug+TerminateProcess）。
    if "--stop-admin" in sys.argv:
        _killed = _force_kill_all_opst()
        print(f"--stop-admin: 已终止 {_killed} 个 OPSTcontroller 进程")
        time.sleep(2)
        # 同样清理 _MEI 残留并跳过 bootloader 清理（防弹窗）
        try:
            time.sleep(3)
            _cur_mei = os.path.normcase(getattr(sys, '_MEIPASS', '') or '')
            for _d in glob.glob(os.path.join(tempfile.gettempdir(), "_MEI*")):
                try:
                    if _cur_mei and os.path.normcase(os.path.abspath(_d)) == _cur_mei:
                        continue
                    shutil.rmtree(_d, ignore_errors=True)
                except Exception:
                    pass
        except Exception:
            pass
        os._exit(0)
    if "--stop" in sys.argv or "/stop" in sys.argv:
        signaled = signal_exit()
        if signaled:
            print("已向 OPSTcontroller 发送退出信号，等待进程退出...")
            # 等待最多5秒确认进程退出
            import subprocess
            for _ in range(10):
                time.sleep(0.5)
                r = _run(['tasklist', '/FI', 'IMAGENAME eq OPSTcontroller.exe'],
                                   capture_output=True, text=True)
                if 'OPSTcontroller.exe' not in r.stdout:
                    print("OPSTcontroller 已成功退出。")
                    sys.exit(0)
            # 进程仍在运行，尝试 taskkill
            print("信号方式未生效，尝试强制终止...")
            _kill_opst_except_self()
            time.sleep(1)
            print("已发送强制终止命令。")
        else:
            print("未找到运行中的 OPSTcontroller 实例（命名事件不存在）。")
            # 尝试 taskkill 兜底
            import subprocess
            r = _run(['tasklist', '/FI', 'IMAGENAME eq OPSTcontroller.exe'],
                               capture_output=True, text=True)
            if 'OPSTcontroller.exe' in r.stdout:
                print("检测到进程，尝试强制终止...")
                _kill_opst_except_self()
                print("已发送强制终止命令。")
        # 信号/taskkill 可能对自我保护实例无效：若进程仍在，
        # 提升到管理员执行 --stop-admin 强杀
        try:
            time.sleep(2)
            r = _run(['tasklist', '/FI', 'IMAGENAME eq OPSTcontroller.exe'],
                               capture_output=True, text=True)
            if 'OPSTcontroller.exe' in r.stdout:
                print("自我保护实例仍存活，提升管理员权限强制终止...")
                if is_admin():
                    _killed = _force_kill_all_opst()
                    print(f"已终止 {_killed} 个进程")
                else:
                    try:
                        # UAC 完全关闭环境下 ShellExecuteW(runas) 静默失败，
                        # 改用 PowerShell -Verb RunAs 提权启动 --stop-admin
                        # （与已验证有效的 kill_admin 机制一致）。
                        import subprocess as _sp
                        _sp.Popen([
                            "powershell", "-NoProfile", "-WindowStyle", "Hidden",
                            "-Command",
                            f"Start-Process -Verb RunAs -Wait -WindowStyle Hidden "
                            f"-FilePath '{sys.executable}' -ArgumentList '--stop-admin'"
                        ])
                        print("已请求管理员权限执行 --stop-admin（PowerShell RunAs）")
                    except Exception as e:
                        print(f"提权请求失败: {e}")
        except Exception:
            pass
        # 短暂等待，让安全软件完成对 _MEI 解压文件的扫描，
        # 避免 PyInstaller 退出清理时文件被锁定导致"Failed to remove temporary directory"弹窗
        try:
            time.sleep(5)
        except Exception:
            pass
        # 尽力清理非空 _MEI 残留（忽略失败：被安全软件锁住时放弃）
        try:
            _cur_mei = os.path.normcase(getattr(sys, '_MEIPASS', '') or '')
            _roots = []
            for _k in ("TEMP", "TMP"):
                _v = os.environ.get(_k)
                if _v and _v not in _roots:
                    _roots.append(_v)
            _td = tempfile.gettempdir()
            if _td not in _roots:
                _roots.append(_td)
            _sysroot = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "Temp")
            if _sysroot not in _roots:
                _roots.append(_sysroot)
            try:
                for _p in glob.glob(os.path.join(r"C:\Users", "*", "AppData", "Local", "Temp")):
                    if _p not in _roots:
                        _roots.append(_p)
            except Exception:
                pass
            _seen = set()
            for _r in _roots:
                for _d in glob.glob(os.path.join(_r, "_MEI*")):
                    _ap = os.path.normcase(os.path.abspath(_d))
                    if _ap in _seen:
                        continue
                    _seen.add(_ap)
                    try:
                        if _cur_mei and _ap == _cur_mei:
                            continue
                        shutil.rmtree(_d, ignore_errors=True)
                    except Exception:
                        pass
        except Exception:
            pass
        # os._exit 跳过 PyInstaller bootloader 退出清理，
        # 彻底消除安全软件锁文件导致的"Failed to remove temporary directory"弹窗
        os._exit(0)

    # 单实例检测（--restart参数时跳过）
    is_restart = "--restart" in sys.argv
    mutex, is_first = create_single_instance_mutex()
    if not is_first and not is_restart:
        result = activate_existing_instance()
        if result is not None:
            return  # 已激活已有实例，退出
        # 找不到已有窗口（可能残留互斥体），继续正常启动

    # 严格重写：启动入口只负责权限检查与重启分流，不再混入伪提权
    default_perm = "t"
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                _cfg = json.load(f)
                _loaded_perm = _cfg.get("default_permission", "t")
                if _loaded_perm in ("t", "system", "administrator", "user"):
                    default_perm = _loaded_perm
                else:
                    default_perm = "t"
    except Exception:
        pass

    ti_elevated = False
    ti_status = "普通用户"
    privilege_failure_detail = None

    # 绝对真实：先检测当前进程真实权限
    actual_status, actual_ti, actual_admin, actual_integrity, actual_sid = get_real_permission_detail()
    ti_status = actual_status
    ti_elevated = actual_ti

    if default_perm == "user":
        ti_elevated = False
        ti_status = actual_status
        log_event("SYSTEM", "提权", "跳过", "用户配置 default_permission=user，按当前真实权限运行: " + actual_status)
    elif os.environ.get("OPST_SKIP_TI", "") == "1":
        # NSudo子进程已进入，重新检测真实权限（不假设一定是TI/SYSTEM）
        actual_status2, actual_ti2, actual_admin2, actual_integrity2, actual_sid2 = get_real_permission_detail()
        ti_status = actual_status2
        ti_elevated = actual_ti2
        enabled = enable_all_privileges()
        log_event("SYSTEM", "提权", "NSudo子进程", "真实权限=" + actual_status2 + "，完整性=" + actual_integrity2 + "，已启用" + str(enabled) + "项特权")
        if not actual_ti2:
            privilege_failure_detail = "NSudo子进程未获得TI/SYSTEM权限，真实权限为: " + actual_status2
    elif actual_ti:
        ti_elevated = True
        ti_status = actual_status
        log_event("SYSTEM", "提权", "已提权", "当前进程真实权限: " + actual_status + "，完整性: " + actual_integrity)
    else:
        if not is_admin():
            kernel32.CloseHandle(mutex)
            run_as_admin()
            os._exit(0)

        allowed_modes = {"t", "system", "administrator"}
        if default_perm not in allowed_modes:
            default_perm = "t"

        nsudo_ok, nsudo_path, nsudo_reason = ensure_nsudo_available()
        if not nsudo_ok:
            # NSudo不可用，保持真实管理员权限，不造假
            log_event("SYSTEM", "提权", "失败", "NSudo前置检查失败: " + nsudo_reason)
            ti_status = actual_status
            ti_elevated = False
            privilege_failure_detail = "NSudo不可用，无法提权到TI/SYSTEM。当前真实权限: " + actual_status + "。失败原因: " + nsudo_reason
        elif default_perm == "administrator":
            # 用户明确选择管理员模式，保持真实权限
            ti_elevated = False
            ti_status = actual_status
            log_event("SYSTEM", "提权", "用户选择", "default_permission=administrator，保持管理员权限运行: " + actual_status)
        elif default_perm == "system":
            kernel32.CloseHandle(mutex)
            time.sleep(0.3)
            if elevate_via_nsudo_system_only():
                log_event("SYSTEM", "提权", "成功", "NSudo已按SYSTEM模式发起重启")
                time.sleep(2)
                # os._exit 跳过 bootloader 清理，避免安全软件锁 _MEI 文件弹 Warning
                os._exit(0)
            # 提权失败，保持真实权限，不造假
            log_event("SYSTEM", "提权", "失败", "NSudo SYSTEM提权未成功发起新实例")
            ti_status = actual_status
            ti_elevated = False
            privilege_failure_detail = "NSudo SYSTEM提权失败，当前真实权限: " + actual_status
            mutex, _ = create_single_instance_mutex()
        else:
            kernel32.CloseHandle(mutex)
            time.sleep(0.3)
            if elevate_via_nsudo():
                log_event("SYSTEM", "提权", "成功", "NSudo已按TI模式发起重启")
                time.sleep(2)
                # os._exit 跳过 bootloader 清理，避免安全软件锁 _MEI 文件弹 Warning
                os._exit(0)
            # 提权失败，保持真实权限，不造假
            log_event("SYSTEM", "提权", "失败", "NSudo TI提权未成功发起新实例")
            ti_status = actual_status
            ti_elevated = False
            privilege_failure_detail = "NSudo TI提权失败，当前真实权限: " + actual_status
            mutex, _ = create_single_instance_mutex()

    if ti_elevated:
        remap_hkcu_to_interactive_user()

    # 添加开机自启
    if not is_autostart_set():
        if add_to_autostart():
            print("此程序已添加到开机自启")
            log_event("SYSTEM", "自启动", "已添加", "注册表HKCU\\Run")
        else:
            print("警告：添加开机自启失败")
    # -m/--minimized：开机自启动最小化启动（普通实例与TI实例均生效）
    app = MainWindow(ti_elevated=ti_elevated, ti_status=ti_status,
                     privilege_failure_detail=privilege_failure_detail,
                     start_minimized=start_minimized)
    app.run()
    # 保持互斥体直到程序退出
    kernel32.CloseHandle(mutex)
    # os._exit 跳过 bootloader 退出清理，避免安全软件锁 _MEI 文件弹 Warning；
    # 残留 _MEI 目录由下次启动时的空目录清理兜底
    os._exit(0)


def _global_excepthook(exc_type, exc_value, exc_traceback):
    """全局异常捕获，写入日志文件（windowed模式下stderr不可见）"""
    import traceback
    tb = ''.join(traceback.format_exception(exc_type, exc_value, exc_traceback))
    try:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(f"\n=== 未捕获异常 {time.strftime('%Y-%m-%d %H:%M:%S')} ===\n{tb}\n")
    except Exception:
        pass


if __name__ == "__main__":
    sys.excepthook = _global_excepthook
    try:
        main()
    except Exception as e:
        import traceback
        tb = traceback.format_exc()
        try:
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(f"\n=== main异常 {time.strftime('%Y-%m-%d %H:%M:%S')} ===\n{tb}\n")
        except Exception:
            pass
