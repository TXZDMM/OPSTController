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

import winreg
import json
import os
import sys
import time
import threading
import logging
import ctypes
import shutil
import subprocess
from ctypes import wintypes
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
APP_VERSION = "1.0.0"
MUTEX_NAME = "OPSTcontroller_SingleInstance_Mutex"
EXIT_EVENT_NAME = "OPSTcontroller_Exit_Event"
SHOW_EVENT_NAME = "OPSTcontroller_Show_Window_Event"
AUTOSTART_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"

# 判断是否为 PyInstaller 打包环境
if getattr(sys, 'frozen', False):
    APP_DIR = os.path.dirname(sys.executable)
else:
    APP_DIR = os.path.dirname(os.path.abspath(__file__))

RUNTIME_DIR = os.path.join(APP_DIR, "runtime")
USERDATA_DIR = os.path.join(APP_DIR, "userdata")

# 确保目录存在
os.makedirs(RUNTIME_DIR, exist_ok=True)
os.makedirs(USERDATA_DIR, exist_ok=True)

BASELINE_FILE = os.path.join(USERDATA_DIR, "baseline.json")
HISTORY_DIR = os.path.join(USERDATA_DIR, "baseline_history")
LOG_FILE = os.path.join(USERDATA_DIR, "protector.log")
CONFIG_FILE = os.path.join(USERDATA_DIR, "config.json")

MAX_HISTORY_VERSIONS = 5
POLL_INTERVAL = 2          # 轮询间隔(秒)
DEEP_SCAN_INTERVAL = 300   # 深层扫描间隔(秒)
NOTIFY_TIMEOUT = 8          # 通知显示时长(秒)，超时默认阻止
COOLDOWN_SECONDS = 30       # 同一扩展名恢复后冷却时间(秒)，期间静默恢复不弹窗

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
    fh = logging.FileHandler(LOG_FILE, encoding='utf-8')
    fh.setLevel(logging.DEBUG)
    fmt = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s',
                            datefmt='%Y-%m-%d %H:%M:%S')
    fh.setFormatter(fmt)
    logger.addHandler(fh)
    return logger

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


class _LUID(ctypes.Structure):
    _fields_ = [("LowPart", ctypes.c_ulong), ("HighPart", ctypes.c_long)]


class _LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", _LUID), ("Attributes", ctypes.c_ulong)]


class _TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [("PrivilegeCount", ctypes.c_ulong), ("Privileges", _LUID_AND_ATTRIBUTES * 1)]


_advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)
_kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

_AdjustTokenPrivileges = _advapi32.AdjustTokenPrivileges
_AdjustTokenPrivileges.restype = LONG
_AdjustTokenPrivileges.argtypes = [HANDLE, BOOL, ctypes.c_void_p, DWORD, ctypes.c_void_p, ctypes.c_void_p]

_LookupPrivilegeValueW = _advapi32.LookupPrivilegeValueW
_LookupPrivilegeValueW.restype = BOOL
_LookupPrivilegeValueW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.POINTER(_LUID)]

_RegCreateKeyExW = _advapi32.RegCreateKeyExW
_RegCreateKeyExW.restype = LONG
_RegCreateKeyExW.argtypes = [HKEY_T, ctypes.c_wchar_p, DWORD, ctypes.c_wchar_p, DWORD, DWORD,
                             ctypes.c_void_p, ctypes.POINTER(HKEY_T), ctypes.POINTER(DWORD)]

_RegSetValueExW = _advapi32.RegSetValueExW
_RegSetValueExW.restype = LONG
_RegSetValueExW.argtypes = [HKEY_T, ctypes.c_wchar_p, DWORD, DWORD, ctypes.c_void_p, DWORD]

_RegCloseKey = _advapi32.RegCloseKey
_RegCloseKey.restype = LONG
_RegCloseKey.argtypes = [HKEY_T]

_GetCurrentProcess = _kernel32.GetCurrentProcess
_GetCurrentProcess.restype = HANDLE
_GetCurrentProcess.argtypes = []

_OpenProcessToken = _advapi32.OpenProcessToken
_OpenProcessToken.restype = BOOL
_OpenProcessToken.argtypes = [HANDLE, DWORD, ctypes.POINTER(HANDLE)]

_CloseHandle_proc = _kernel32.CloseHandle
_CloseHandle_proc.restype = BOOL
_CloseHandle_proc.argtypes = [HANDLE]


def _enable_privilege(priv_name):
    """启用指定权限，返回 bool"""
    hToken = HANDLE()
    if not _OpenProcessToken(_GetCurrentProcess(), _TOKEN_ADJUST_PRIVILEGES | _TOKEN_QUERY, ctypes.byref(hToken)):
        return False
    luid = _LUID()
    if not _LookupPrivilegeValueW(None, priv_name, ctypes.byref(luid)):
        _CloseHandle_proc(hToken)
        return False
    tp = _TOKEN_PRIVILEGES()
    tp.PrivilegeCount = 1
    tp.Privileges[0].Luid = luid
    tp.Privileges[0].Attributes = _SE_ENABLED
    result = _AdjustTokenPrivileges(hToken, False, ctypes.byref(tp), 0, None, None)
    _CloseHandle_proc(hToken)
    return result != 0


def force_write_reg_value(root_hkey, path, name, value, reg_type):
    """
    使用备份/恢复权限强制写入注册表值，绕过 ACL 保护。
    适用于 UserChoice 等被 Windows 保护拒绝普通写入的注册表键。
    返回 bool
    """
    # 启用备份和恢复权限
    if not _enable_privilege(_SE_BACKUP):
        return False
    if not _enable_privilege(_SE_RESTORE):
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


def get_extension_paths(ext, prog_id=None):
    """
    获取扩展名对应的7个保护项路径定义。
    返回 dict: key -> (root, path, value_name)
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
    return paths


def snapshot_extension(ext):
    """
    对单个扩展名拍摄7项快照。
    返回 dict: key -> {"value": ..., "type": ..., "root": ..., "path": ..., "name": ...}
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
            "prog_id": prog_id if key in ("hkcr_command", "hkcu_command") else None,
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
        ROOT_MAP["HKCU"] = user_hive
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
                except (json.JSONDecodeError, OSError):
                    self.config = {}

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
        log_event("ALL", "创建基准", "成功", f"模式={mode}, 扩展名数={len(new_baseline)}, 错误={errors}")
        return len(new_baseline)

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

    def update_extension(self, ext):
        """
        更新单个扩展名的基准（用户单次同意时调用）。
        同时推入历史版本。
        """
        self._push_history()
        with self._lock:
            self.baseline[ext] = snapshot_extension(ext)
        self.save()
        log_event(ext, "更新基准", "成功", "用户单次同意")
        return True

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
        hkcr_val = reg_read_value(HKCR, ext, "")[0]
        if hkcr_val:
            log_event(ext, "关联", "回退", f"使用HKCR默认:{hkcr_val}")
        self.reset_uc_failure(ext)
        return True

    def check_extension(self, ext):
        """
        检查单个扩展名是否被更改。
        使用基准中记录的精确路径读取当前值进行比较。
        特殊处理：基准 UserChoice=None 时，若当前 UserChoice=HKCR系统默认值，
        视为正常（Windows 删除后自动重建系统默认，避免无限循环）。
        返回 list of (item_key, baseline_val, current_val, current_type)
        """
        bl = self.baseline.baseline.get(ext)
        if not bl:
            return []

        # 检查基准中 UserChoice 是否为 None
        bl_uc_progid = bl.get("userchoice_progid", {}).get("value")
        bl_uc_hash = bl.get("userchoice_hash", {}).get("value")
        uc_baseline_none = (bl_uc_progid is None and bl_uc_hash is None)

        # 获取 HKCR 系统默认 ProgId（用于判断 Windows 自动重建的系统默认）
        hkcr_default = reg_read_value(HKCR, ext, "")[0]
        cur_uc_progid = reg_read_value(HKCU, f"{USERCHOICE_BASE}\\{ext}\\UserChoice", "ProgId")[0]
        # 如果基准 UserChoice=None 且当前 UserChoice=HKCR系统默认，视为正常
        uc_is_system_default = (uc_baseline_none and cur_uc_progid is not None
                                 and hkcr_default is not None
                                 and cur_uc_progid == hkcr_default)

        mismatches = []
        for key, bl_item in bl.items():
            # UserChoice 系统默认豁免：基准 None + 当前=HKCR默认 → 不视为不一致
            if uc_is_system_default and key in ("userchoice_progid", "userchoice_hash"):
                continue

            # 始终使用基准中记录的路径读取（command 项含基准 ProgId）
            root_name = bl_item.get("root", "?")
            root = ROOT_MAP.get(root_name)
            if root is None:
                # 基准中root无效（可能旧基准），跳过该项
                continue
            path = bl_item["path"]
            name = bl_item["name"]
            cur_val, cur_type = reg_read_value(root, path, name)

            bl_val = bl_item.get("value")
            bl_type = bl_item.get("type")

            # 比较值（处理 None 和类型差异）
            if not self._values_equal(bl_val, cur_val, bl_type, cur_type):
                mismatches.append((key, bl_val, cur_val, cur_type))

        # 额外检测：如果当前 ProgId 与基准不同，检查新 ProgId 的 command 是否被植入
        # 优先级必须与 get_prog_id 一致：UserChoice > HKCU > HKCR > HKLM
        # （HKCR是合并视图，可能返回HKLM系统默认值而非用户设置）
        bl_prog_id = None
        for k in ("userchoice_progid", "hkcu_ext", "hkcr_ext", "hklm_ext"):
            item = bl.get(k)
            if item and item.get("value"):
                bl_prog_id = item["value"]
                break
        cur_prog_id = get_prog_id(ext)
        if cur_prog_id and bl_prog_id and cur_prog_id != bl_prog_id:
            # 新 ProgId 的 open command 存在即视为篡改证据
            new_cmd, _ = reg_read_value(HKCR, f"{cur_prog_id}\\shell\\open\\command", "")
            if new_cmd is not None:
                mismatches.append(("new_progid_command", f"(基准:{bl_prog_id})",
                                   f"{cur_prog_id} -> {new_cmd}", None))

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
        UserChoice 键被 Windows 保护拒绝普通写入，采用"删除键→重建→写入基准值"方案，
        既恢复用户合法设置的第三方默认程序，又不破坏用户设置。
        返回 (success_count, fail_count, details)
        """
        bl = self.baseline.baseline.get(ext)
        if not bl:
            return 0, len(mismatches), ["基准不存在"]

        success = 0
        fail = 0
        details = []
        userchoice_recovered = False  # UserChoice 两项一起处理，避免重复删除重建
        uc_path = f"{USERCHOICE_BASE}\\{ext}\\UserChoice"

        for key, bl_val, cur_val, cur_type in mismatches:
            # new_progid_command 是额外检测项，无需单独恢复
            if key == "new_progid_command":
                details.append("新ProgId命令:已随ProgId恢复失效")
                continue

            # UserChoice 项：删除键→重建→写入基准值（Windows保护拒绝直接写入）
            if key in ("userchoice_progid", "userchoice_hash"):
                if not userchoice_recovered:
                    userchoice_recovered = True
                    bl_progid = bl.get("userchoice_progid", {})
                    bl_hash = bl.get("userchoice_hash", {})
                    has_progid = bl_progid.get("value") is not None
                    has_hash = bl_hash.get("value") is not None

                    if not has_progid and not has_hash:
                        # 基准中无 UserChoice → 删除整个键（10种方法强制删除）
                        del_ok, del_method = force_delete_userchoice(ext)
                        if del_ok:
                            success += 2
                            details.append(f"UserChoice:已删除({del_method})")
                        else:
                            fail += 2
                            details.append(f"UserChoice:删除失败({del_method})")
                    else:
                        # 基准中有 UserChoice → 删除→重建→写入
                        uc_ok = True
                        uc_parts = []
                        # 1. 删除旧键（10种方法强制删除）
                        del_ok, del_method = force_delete_userchoice(ext)
                        if not del_ok:
                            uc_ok = False
                            uc_parts.append(f"删除失败({del_method})")
                        else:
                            # 2. 重建并写入基准值
                            try:
                                kh = winreg.CreateKeyEx(HKCU, uc_path, 0, KEY_ALL_ACCESS_64)
                                if has_progid:
                                    winreg.SetValueEx(kh, "ProgId", 0, bl_progid["type"], bl_progid["value"])
                                    uc_parts.append("ProgId已恢复")
                                if has_hash:
                                    winreg.SetValueEx(kh, "Hash", 0, bl_hash["type"], bl_hash["value"])
                                    uc_parts.append("Hash已恢复")
                                winreg.CloseKey(kh)
                            except OSError as e:
                                uc_ok = False
                                uc_parts.append(f"重建失败:{e}")

                        if uc_ok:
                            success += 2
                            details.append(f"UserChoice:{'/'.join(uc_parts)}")
                        else:
                            fail += 2
                            details.append(f"UserChoice:{'/'.join(uc_parts)}")
                continue

            bl_item = bl.get(key)
            if not bl_item:
                fail += 1
                details.append(f"{key}:基准项缺失")
                continue

            root_name = bl_item.get("root", "?")
            root = ROOT_MAP.get(root_name)
            if root is None:
                fail += 1
                details.append(f"{self.ITEM_LABELS.get(key,key)}:root无效({root_name})")
                continue
            path = bl_item["path"]
            name = bl_item["name"]
            target_val = bl_item["value"]
            target_type = bl_item["type"]

            if target_val is None and target_type is None:
                # 基准中不存在 → 删除当前值
                if reg_delete_value(root, path, name):
                    success += 1
                    details.append(f"{self.ITEM_LABELS.get(key,key)}:已删除")
                else:
                    fail += 1
                    details.append(f"{self.ITEM_LABELS.get(key,key)}:删除失败")
            else:
                # 写入基准值
                if reg_write_value(root, path, name, target_val, target_type):
                    success += 1
                    details.append(f"{self.ITEM_LABELS.get(key,key)}:已恢复")
                else:
                    fail += 1
                    details.append(f"{self.ITEM_LABELS.get(key,key)}:恢复失败(权限不足?)")

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
                has_cmd = reg_read_value(HKCR, f"{prog_id}\\shell\\open\\command", "")[0] is not None
            if has_uc or has_cmd:
                suspicious_new.append(ext)

        return inconsistencies, suspicious_new


# ============================================================
# 右下角通知 (更改通知 + 单次同意 + 5秒默认阻止)
# ============================================================
class NotificationToast:
    """右下角滑出通知，非模态，5秒后自动关闭默认阻止"""
    TOAST_WIDTH = 360
    TOAST_HEIGHT = 160
    MARGIN = 15
    GAP = 10

    def __init__(self, parent, ext, mismatches, recover_result, on_consent, on_close, on_show_main, y_offset=0, x_offset=0, timeout=None):
        self.ext = ext
        self.mismatches = mismatches
        self.recover_result = recover_result
        self.on_consent = on_consent
        self.on_close = on_close
        self.on_show_main = on_show_main
        self.y_offset = y_offset
        self.x_offset = x_offset
        self.timeout = timeout if timeout and timeout > 0 else NOTIFY_TIMEOUT
        self.remaining = self.timeout
        self._closed = False
        self._build_ui(parent)

    def _build_ui(self, parent):
        self.win = tk.Toplevel(parent)
        self.win.overrideredirect(True)  # 无边框
        self.win.attributes("-topmost", True)
        self.win.configure(bg="#2c3e50")

        # 计算右下角位置（堆叠时每个向左上偏移）
        sw = self.win.winfo_screenwidth()
        sh = self.win.winfo_screenheight()
        self.target_y = sh - self.TOAST_HEIGHT - self.MARGIN - self.y_offset
        x = sw - self.TOAST_WIDTH - self.MARGIN - self.x_offset
        # 初始位置在屏幕外（下方），用于滑入动画
        self.win.geometry(f"{self.TOAST_WIDTH}x{self.TOAST_HEIGHT}+{x}+{sh}")

        # 顶部色条
        top_bar = tk.Frame(self.win, bg="#e74c3c", height=4)
        top_bar.pack(fill="x")
        top_bar.pack_propagate(False)

        # 内容区
        content = tk.Frame(self.win, bg="#2c3e50")
        content.pack(fill="both", expand=True, padx=12, pady=(8, 4))

        # 标题行
        title_frame = tk.Frame(content, bg="#2c3e50")
        title_frame.pack(fill="x")
        tk.Label(title_frame, text=f"⚠ {self.ext} 被更改",
                 font=("微软雅黑", 11, "bold"), fg="#e74c3c",
                 bg="#2c3e50").pack(side="left")

        # 更改详情
        detail_parts = []
        for key, bl_val, cur_val, _ in self.mismatches[:3]:
            label = ProtectionEngine.ITEM_LABELS.get(key, key)
            detail_parts.append(label)
        detail_text = "、".join(detail_parts)
        if len(self.mismatches) > 3:
            detail_text += f" 等{len(self.mismatches)}项"
        tk.Label(content, text=f"更改项：{detail_text}",
                 font=("微软雅黑", 9), fg="#bdc3c7", bg="#2c3e50",
                 anchor="w").pack(fill="x", pady=(2, 0))

        # 恢复状态
        success, fail, details = self.recover_result
        if fail == 0:
            status_text = "✓ 已恢复到基准"
            status_color = "#2ecc71"
        else:
            status_text = f"✗ 恢复失败(成功{success}/失败{fail})"
            status_color = "#e67e22"
        tk.Label(content, text=status_text,
                 font=("微软雅黑", 10, "bold"), fg=status_color,
                 bg="#2c3e50", anchor="w").pack(fill="x", pady=(2, 0))

        # 按钮 + 倒计时
        bottom = tk.Frame(content, bg="#2c3e50")
        bottom.pack(fill="x", pady=(6, 0))

        btn_group = tk.Frame(bottom, bg="#2c3e50")
        btn_group.pack(side="left")

        self.consent_btn = tk.Button(btn_group, text="单次同意",
                                      font=("微软雅黑", 8),
                                      command=self._on_consent, width=8, relief="flat",
                                      padx=4, pady=1)
        self.consent_btn.pack(side="left", padx=(0, 4))

        self.show_main_btn = tk.Button(btn_group, text="打开主程序",
                                        font=("微软雅黑", 8),
                                        command=self._on_show_main, width=8, relief="flat",
                                        padx=4, pady=1)
        self.show_main_btn.pack(side="left")

        self.timer_label = tk.Label(bottom, text=f"{self.remaining}秒后默认阻止",
                                     font=("微软雅黑", 8), fg="#95a5a6", bg="#2c3e50")
        self.timer_label.pack(side="right")

        # 倒计时进度条
        self.progress = tk.Frame(self.win, bg="#3498db", height=3)
        self.progress.pack(fill="x", side="bottom")
        self.progress_width = self.TOAST_WIDTH

        # 滑入动画
        self._slide_in()
        # 启动倒计时
        self._tick()

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
        except tk.TclError:
            pass

    def _tick(self):
        if self._closed:
            return
        if self.remaining <= 0:
            self._on_timeout()
            return
        self.timer_label.config(text=f"{self.remaining}秒后默认阻止")
        # 更新进度条宽度
        ratio = self.remaining / self.timeout
        new_w = max(1, int(self.TOAST_WIDTH * ratio))
        self.progress.config(width=new_w)
        self.remaining -= 1
        self.win.after(1000, self._tick)

    def _on_consent(self):
        if self._closed:
            return
        self._closed = True
        self.on_consent(self.ext)
        self._close()

    def _on_show_main(self):
        """点击打开主程序：显示主窗口，不关闭通知"""
        if self.on_show_main:
            self.on_show_main()

    def _on_timeout(self):
        if self._closed:
            return
        self._closed = True
        self._close()

    def _close(self):
        """滑出并销毁"""
        try:
            self.win.destroy()
        except tk.TclError:
            pass
        self.on_close(self)

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
            # 打开浏览器下载默认基准包
            url = "https://wwbmw.lanzouq.com/b0139yjgze"
            try:
                import subprocess
                subprocess.Popen(['explorer.exe', url], creationflags=0x08000000)
            except Exception:
                try:
                    ctypes.windll.shell32.ShellExecuteW(None, "open", url, None, None, 1)
                except Exception:
                    pass
            # 弹出子对话框：导入文件 or 系统默认创建
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

        tk.Label(self.win, text="已打开默认基准下载页面",
                 font=("微软雅黑", 13, "bold")).pack(pady=(20, 3))
        tk.Label(self.win, text="密码: 52pj",
                 font=("微软雅黑", 10), fg="#e74c3c").pack(pady=(0, 10))

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

    def __init__(self, engine, baseline_mgr, popup_callback, log_callback):
        super().__init__(daemon=True)
        self.engine = engine
        self.baseline = baseline_mgr
        self.popup_callback = popup_callback
        self.log_callback = log_callback
        self._stop_event = threading.Event()
        self._pause_event = threading.Event()
        self._last_deep_scan = time.time()
        self._last_hkcu_check = 0
        self._grace_until = time.time() + self.GRACE_PERIOD_SECONDS
        self._grace_logged = False
        self._grace_logged_exts = set()  # 宽限期已报过的扩展名，避免每2秒重复刷屏
        # 持续篡改追踪 + 进程打击
        self.persistent_tracker = PersistentTracker()
        blacklist_path = os.path.join(USERDATA_DIR, "process_blacklist.json")
        history_path = os.path.join(USERDATA_DIR, "process_blacklist_history.json")
        self.process_enforcer = ProcessEnforcer(blacklist_path, history_path)
        self._persistent_mode = False  # 是否处于持续篡改模式（缩短轮询间隔）
        self._last_unlock_check = 0
        self._last_hunt_check = 0
        self._last_lock_stats_log = 0
        self._notify_extra_seconds = 0  # 批量篡改触发后弹窗额外时长（秒）

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
            ok, msg = unlock_userchoice_key(ext)
            status = "成功" if ok else f"失败({msg})"
            self.log_callback(f"  {ext} 解锁{status}，进入10秒高频观察期", "info")
            log_event(ext, "解锁", "自动", status)
        # 如果没有锁定的键了，退出持续模式
        if not self.persistent_tracker.get_locked_exts():
            if self._persistent_mode:
                self._persistent_mode = False
                self.log_callback("持续篡改防护模式已解除", "info")
        elif locked_before > 0:
            remaining = len(self.persistent_tracker.get_locked_exts())
            log_event("SYSTEM", "锁定巡检", "继续", f"剩余{remaining}个锁定中")

    def _unlock_all(self):
        """退出时解锁所有锁定的键"""
        for ext in self.persistent_tracker.get_locked_exts():
            try:
                unlock_userchoice_key(ext)
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
            # 锁定中的扩展名：ACL已拒绝写入，跳过检测（每5秒由_auto_unlock_check统一巡检）
            if self.persistent_tracker.is_locked(ext):
                locked_count += 1
                continue
            checked_count += 1
            mismatches = self.engine.check_extension(ext)
            if mismatches:
                if in_grace:
                    # 宽限期：只日志记录，不恢复，每个扩展名只报一次
                    if ext not in self._grace_logged_exts:
                        self._grace_logged_exts.add(ext)
                        detail_parts = []
                        for key, bl_val, cur_val, _ in mismatches[:3]:
                            label = ProtectionEngine.ITEM_LABELS.get(key, key)
                            detail_parts.append(f"{label}({bl_val}->{cur_val})")
                        self.log_callback(f"[宽限期] {ext} 检测到不一致: {'; '.join(detail_parts)}（未恢复）")
                else:
                    self._handle_change(ext, mismatches)

        # 每10秒输出一次锁定状态统计
        if locked_count > 0 and time.time() - self._last_lock_stats_log >= 10:
            self._last_lock_stats_log = time.time()
            high_freq = [e for e in self.persistent_tracker._unlocked_exts
                         if self.persistent_tracker.is_in_high_freq(e)]
            self.log_callback(f"[防护状态] 锁定中:{locked_count} 高频观察:{len(high_freq)} 已检测:{checked_count}", "info")
            log_event("SYSTEM", "防护状态", "统计", f"locked={locked_count}, highfreq={len(high_freq)}, checked={checked_count}")

    def _deep_scan_cycle(self):
        """深层扫描周期"""
        in_grace = time.time() < self._grace_until
        self.log_callback("开始深层扫描...")
        inconsistencies, new_exts = self.engine.deep_scan()
        if inconsistencies:
            self.log_callback(f"深层扫描发现 {len(inconsistencies)} 个扩展名不一致")
            for ext, mismatches in inconsistencies.items():
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
                if remaining:
                    all_passed = False
                    mismatches = remaining  # 用最新不一致列表重试
                    if attempt < max_retries - 1:
                        log_event(ext, "恢复", f"重试{attempt+1}",
                                  f"{wait_sec}s后仍有{len(remaining)}项不一致")
                    break  # 跳出验证循环，进入重试

            if all_passed:
                verified = True
                break

        return total_success, total_fail, all_details, verified

    def _handle_change(self, ext, mismatches):
        """处理检测到的更改：持续篡改判定 → 冷却判断 → 恢复+验证 → 锁定/进程打击 → 通知"""
        # 检查是否本周期已同意
        if ext in self.engine.allowed_this_cycle:
            return

        # === 持续篡改严格判定 ===
        is_persistent, is_batch, cur_progid = self.persistent_tracker.record_change(ext, mismatches)

        # 批量篡改：同一ProgId改多个扩展名 → 强终止进程 + 锁定所有相关扩展名 + 持续模式
        if is_batch and cur_progid:
            batch_exts = self.persistent_tracker.get_batch_exts(cur_progid)
            # 检查用户是否同意过其中任意一个扩展名
            any_allowed = any(e in self.engine.allowed_this_cycle for e in batch_exts)
            if any_allowed:
                self.log_callback(f"批量篡改: {cur_progid} 篡改{len(batch_exts)}个扩展名，但用户已同意其中之一，跳过强制锁定", "info")
                log_event("ALL", "批量篡改", "跳过", f"用户已同意, ProgId={cur_progid}")
            else:
                self._persistent_mode = True
                level = self.persistent_tracker.get_lock_level(ext)
                self.log_callback(f"⚠ 批量篡改: {cur_progid} 正在篡改{len(batch_exts)}个扩展名，保护强度{level}：强终止进程 + 批量锁定注册表", "warn")
                log_event("ALL", "批量篡改", "检测到", f"ProgId={cur_progid}, 扩展名数={len(batch_exts)}, 保护强度{level}")
                # 强终止进程（不是挂起）
                results = self.process_enforcer.enforce(cur_progid, action="terminate")
                for name, action, ok, reason in results:
                    status = "成功" if ok else "失败"
                    self.log_callback(f"  进程打击: {name} {action}{status}({reason})", "warn")
                    log_event("PROCESS", action, status, f"{name}({reason})")
                # 锁定所有被该ProgId篡改过的扩展名
                lock_count = 0
                for e in batch_exts:
                    self.persistent_tracker.force_persistent(e)
                    if self.persistent_tracker.should_lock(e):
                        ok, msg = lock_userchoice_key(e)
                        if ok:
                            lock_count += 1
                            self.persistent_tracker.mark_locked(e)
                        log_event(e, "锁定", "成功" if ok else f"失败({msg})", f"批量篡改触发, {msg}")
                self.log_callback(f"  批量锁定: {lock_count}/{len(batch_exts)} 个扩展名UserChoice键已锁定", "info")
                # 弹窗时长+8秒
                self._notify_extra_seconds = 8

        # 单扩展名持续篡改：锁定注册表键 + 进程打击
        # 高频观察期内再次篡改：立即重新锁定（无需再积累3次）
        in_high_freq = self.persistent_tracker.is_in_high_freq(ext)
        if (is_persistent or in_high_freq) and self.persistent_tracker.should_lock(ext):
            self._persistent_mode = True
            level = self.persistent_tracker.get_lock_level(ext)
            reason = "高频观察期内再次篡改" if in_high_freq else "持续篡改"
            self.log_callback(f"⚠ {ext} {reason}，保护强度{level}：锁定注册表键 + 进程打击", "warn")
            log_event(ext, "持续篡改", "检测到", f"保护强度{level}({reason})")
            # 锁定UserChoice键
            ok, msg = lock_userchoice_key(ext)
            lock_status = "成功" if ok else f"失败({msg})"
            self.log_callback(f"  {ext} UserChoice键锁定{lock_status}", "info")
            log_event(ext, "锁定", lock_status, msg)
            self.persistent_tracker.mark_locked(ext)
            # 进程打击（先降权，持续则挂起）
            results = self.process_enforcer.enforce(cur_progid, action="lower")
            for name, action, ok_action, reason in results:
                status = "成功" if ok_action else "失败"
                self.log_callback(f"  进程打击: {name} {action}{status}({reason})", "warn")

        # 已锁定的扩展名：静默恢复，不弹窗
        if self.persistent_tracker.is_persistent(ext):
            s, f, dets, verified = self._recover_with_verify(ext, mismatches, max_retries=5)
            if verified:
                log_event(ext, "恢复", "成功", "持续模式静默恢复(已验证)")
            else:
                log_event(ext, "恢复", "失败", "持续模式恢复验证未通过")
                # 恢复失败，升级打击：挂起进程
                results = self.process_enforcer.enforce(cur_progid, action="suspend")
                for name, action, ok_action, reason in results:
                    self.log_callback(f"  升级打击: {name} {action}({'成功' if ok_action else '失败'})", "warn")
            return  # 持续模式不弹窗

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
        for key, bl_val, cur_val, _ in mismatches:
            label = ProtectionEngine.ITEM_LABELS.get(key, key)
            detail_parts.append(f"{label}({bl_val}->{cur_val})")
        detail_str = "; ".join(detail_parts)
        log_event(ext, "更改", "检测到", detail_str)
        self.log_callback(f"检测到 {ext} 被更改: {detail_str}")

        # 执行恢复+验证（最多3次重试）
        s, f, dets, verified = self._recover_with_verify(ext, mismatches)
        recover_result = (s, f, dets)

        # 检查是否仅 UserChoice 项不一致（可能是 Hash 过期被 Windows 删除）
        only_uc = all(k in ("userchoice_progid", "userchoice_hash") for k, _, _, _ in mismatches)

        if verified:
            self.engine.reset_uc_failure(ext)
            log_event(ext, "恢复", "成功", "默认保护基准(已验证)")
            self.log_callback(f"{ext} 已恢复到基准(已验证)")
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

        # 右下角通知（在主线程中执行）
        extra = self._notify_extra_seconds
        if extra > 0:
            self._notify_extra_seconds = 0  # 消费一次
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
        r = subprocess.run(['powershell', '-NoProfile', '-Command',
                           f'Remove-Item -Path "{reg_path}" -Recurse -Force -ErrorAction Stop; Write-Output "OK"'],
                           capture_output=True, text=True, timeout=8)
        if "OK" in r.stdout:
            return True, "PowerShell Remove-Item"
    except Exception:
        pass
    # 方法4: reg.exe delete
    try:
        full_path = f"HKEY_USERS\\{getattr(remap_hkcu_to_interactive_user, '_last_sid', '')}\\{uc_path}" if HKCU_REMAPPED else f"HKCU\\{uc_path}"
        r = subprocess.run(['reg', 'delete', full_path, '/f'],
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
        r = subprocess.run(['powershell', '-NoProfile', '-Command', ps],
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
        r = subprocess.run(['powershell', '-NoProfile', '-Command', ps2],
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
        r = subprocess.run(['powershell', '-NoProfile', '-Command', ps3],
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
        r = subprocess.run(['powershell', '-NoProfile', '-Command', ps4],
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
        result = subprocess.run(['powershell', '-NoProfile', '-Command', ps_cmd],
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
    # 方法1: PowerShell Set-Acl 移除Deny规则
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
    Write-Output "OK"
}} else {{
    Write-Output "NOT_FOUND"
}}
'''
        result = subprocess.run(['powershell', '-NoProfile', '-Command', ps_cmd],
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
        result2 = subprocess.run(['powershell', '-NoProfile', '-Command', ps_cmd2],
                                 capture_output=True, text=True, timeout=10)
        if "OK2" in result2.stdout:
            return True, "重置继承解锁"
        methods.append(f"PS2:{result2.stderr.strip()[:50] if result2.stderr else 'no OK'}")
    except Exception as e:
        methods.append(f"PS2异常:{str(e)[:50]}")
    return False, ";".join(methods) if methods else "未知失败"


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
    SINGLE_THRESHOLD = 3    # 单扩展名阈值
    BATCH_WINDOW = 60       # 批量篡改判定窗口(秒)
    BATCH_THRESHOLD = 3     # 批量篡改扩展名数阈值（3个即触发）
    LOCK_DURATION_1 = 25    # 第1-2次锁定时长(秒)
    LOCK_DURATION_2 = 60    # 第3次及以后锁定时长(秒)
    HIGH_FREQ_DURATION = 10  # 解锁后高频观察期(秒)

    def __init__(self):
        self._ext_history = {}   # ext -> [(timestamp, progid), ...]
        self._progid_history = {}  # progid -> [(timestamp, ext), ...]
        self._locked_exts = {}   # ext -> lock_until_time
        self._unlocked_exts = {}  # ext -> unlock_time (刚解锁，高频观察)
        self._persistent_exts = set()  # 已判定持续篡改的扩展名
        self._batch_progids = set()    # 已判定批量篡改的ProgId
        self._lock_count = {}    # ext -> 累计锁定次数

    def record_change(self, ext, mismatches):
        """记录一次更改，返回 (is_persistent, is_batch, progid)"""
        now = time.time()
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

        # 记录单扩展名历史
        if ext not in self._ext_history:
            self._ext_history[ext] = []
        self._ext_history[ext].append((now, cur_progid))
        # 清理过期记录
        self._ext_history[ext] = [(t, p) for t, p in self._ext_history[ext]
                                   if now - t <= self.SINGLE_WINDOW]

        # 记录ProgId历史
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

        # 严格判定2：批量篡改（同一ProgId改多个扩展名）
        is_batch = False
        if cur_progid:
            unique_exts = set(e for _, e in self._progid_history.get(cur_progid, []))
            if len(unique_exts) >= self.BATCH_THRESHOLD:
                is_batch = True
                self._batch_progids.add(cur_progid)

        return is_persistent, is_batch, cur_progid

    def is_persistent(self, ext):
        return ext in self._persistent_exts

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
        """返回锁定级别（1=25秒, 2=60秒）"""
        count = self._lock_count.get(ext, 0)
        return 2 if count >= 2 else 1

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
            subprocess.run(['taskkill', '/F', '/PID', str(pid), '/T'],
                           capture_output=True, timeout=5)
            time.sleep(0.3)
            if not self._is_process_alive(pid):
                return True, "taskkill"
        except Exception:
            pass
        # 方法3: wmic process delete
        try:
            subprocess.run(['wmic', 'process', 'where', f'ProcessId={pid}', 'delete'],
                           capture_output=True, timeout=5)
            time.sleep(0.3)
            if not self._is_process_alive(pid):
                return True, "wmic"
        except Exception:
            pass
        # 方法4: PowerShell Stop-Process
        try:
            subprocess.run(['powershell', '-NoProfile', '-Command',
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
        """对嫌疑进程执行打击。action: lower/suspend/terminate
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
    def __init__(self, ti_elevated=False, ti_status="管理员"):
        self.root = tk.Tk()
        self.root.title(f"{APP_NAME} v{APP_VERSION}")
        self.root.geometry("780x560")
        self.root.minsize(700, 500)

        self.baseline_mgr = BaselineManager()
        self.engine = ProtectionEngine(self.baseline_mgr)
        self.monitor = None
        self.active_toasts = []  # 当前活动的通知列表
        self.ti_elevated = ti_elevated  # TrustedInstaller 提权状态
        self.ti_status = ti_status
        self.exit_event = create_exit_event()  # 跨进程退出信号事件
        self.show_event = create_show_event()  # 跨进程显示窗口信号事件
        self._exiting = False

        self._build_ui()
        # 关闭按钮改为后台常驻，不退出
        self.root.protocol("WM_DELETE_WINDOW", self._hide_to_background)
        self._init_app()
        # 启动退出信号检查（每500ms检查一次）
        self._check_exit_event()

    def _build_ui(self):
        # 顶部状态栏
        status_bar = tk.Frame(self.root, bg="#2c3e50", height=45)
        status_bar.pack(fill="x")
        status_bar.pack_propagate(False)

        self.status_label = tk.Label(status_bar, text="● 状态：未初始化",
                                     font=("微软雅黑", 11, "bold"), fg="white", bg="#2c3e50")
        self.status_label.pack(side="left", padx=15)

        self.ext_count_label = tk.Label(status_bar, text="保护扩展名：0",
                                        font=("微软雅黑", 10), fg="#bdc3c7", bg="#2c3e50")
        self.ext_count_label.pack(side="left", padx=10)

        self.priv_label = tk.Label(status_bar, text="权限：管理员",
                                    font=("微软雅黑", 9), fg="#f39c12", bg="#2c3e50")
        self.priv_label.pack(side="right", padx=15)

        # 工具栏
        toolbar = tk.Frame(self.root, height=40)
        toolbar.pack(fill="x")
        toolbar.pack_propagate(False)

        self.btn_start = tk.Button(toolbar, text="启动保护", font=("微软雅黑", 9),
                                   width=10, command=self._start_protection)
        self.btn_start.pack(side="left", padx=5, pady=5)

        self.btn_stop = tk.Button(toolbar, text="停止保护", font=("微软雅黑", 9),
                                  width=10,
                                  command=self._stop_protection, state="disabled")
        self.btn_stop.pack(side="left", padx=5, pady=5)

        tk.Button(toolbar, text="备份当前", font=("微软雅黑", 9),
                  width=10,
                  command=self._backup_current).pack(side="left", padx=5, pady=5)

        tk.Button(toolbar, text="深层扫描", font=("微软雅黑", 9),
                  width=10,
                  command=self._manual_deep_scan).pack(side="left", padx=5, pady=5)

        tk.Button(toolbar, text="历史版本", font=("微软雅黑", 9),
                  width=10,
                  command=self._show_history).pack(side="left", padx=5, pady=5)

        tk.Button(toolbar, text="设置", font=("微软雅黑", 9),
                  width=10,
                  command=self._show_settings).pack(side="right", padx=5, pady=5)

        # 日志区
        log_frame = tk.LabelFrame(self.root, text=" 运行日志 ", font=("微软雅黑", 10))
        log_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.log_text = scrolledtext.ScrolledText(log_frame, font=("Consolas", 9),
                                                  wrap="word", state="disabled",
                                                  bg="#1e1e1e", fg="#d4d4d4")
        self.log_text.pack(fill="both", expand=True, padx=5, pady=5)
        self.log_text.tag_config("info", foreground="#d4d4d4")
        self.log_text.tag_config("warn", foreground="#f39c12")
        self.log_text.tag_config("error", foreground="#e74c3c")
        self.log_text.tag_config("success", foreground="#2ecc71")

        # 底部
        bottom = tk.Frame(self.root)
        bottom.pack(fill="x", padx=10, pady=(0, 5))
        tk.Label(bottom, text=f"基准模式: - | 基准时间: -",
                 font=("微软雅黑", 8), fg="#999", anchor="w").pack(side="left")
        self.bottom_label = bottom.winfo_children()[0]

    def _init_app(self):
        # 更新权限级别标签
        if self.ti_elevated:
            status_text = getattr(self, 'ti_status', 'TI/SYSTEM')
            self.priv_label.config(text=f"权限：{status_text}", fg="#2ecc71")
            self._append_log(f"当前以 {status_text} 权限运行", "success")
        else:
            self.priv_label.config(text=f"权限：{getattr(self, 'ti_status', '管理员')}", fg="#f39c12")
            self._append_log(f"当前以{getattr(self, 'ti_status', '管理员')}权限运行", "warn")

        # 启动提示
        self._append_log("按钮说明：启动保护=开启实时监控 | 停止保护=暂停监控 | 备份当前=以当前状态保存基准 | 深层扫描=全量校验 | 历史版本=恢复旧基准 | 设置=配置选项", "info")
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
            log_callback=self._append_log
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
        self._append_log("正在退出程序...", "info")
        # 停止监控线程
        if self.monitor and self.monitor.running:
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
        self.root.after(300, self.root.destroy)

    def _backup_current(self):
        """以当前所有扩展名状态备份为新基准（后台线程执行，避免UI卡死）"""
        if not self.baseline_mgr.is_initialized():
            messagebox.showwarning(APP_NAME, "请先创建基准！")
            return
        if not messagebox.askyesno(APP_NAME, "确定要以当前状态备份为新基准吗？\n将覆盖现有基准并保存历史版本。"):
            return
        # 暂停监控线程
        was_running = self.monitor and self.monitor.is_alive()
        if was_running:
            self.monitor.pause()
            time.sleep(0.5)
        self._append_log("正在备份当前状态为新基准（后台执行，请稍候）...", "info")

        def progress_cb(done, total):
            self.root.after(0, lambda: self._append_log(f"备份进度: {done}/{total}", "info"))

        def do_backup():
            try:
                count = self.baseline_mgr.create_baseline("current", progress_cb=progress_cb)
                self.root.after(0, lambda: self._on_backup_done(count, was_running))
            except Exception as e:
                self.root.after(0, lambda: self._on_backup_failed(str(e), was_running))

        threading.Thread(target=do_backup, daemon=True).start()

    def _on_backup_done(self, count, was_running):
        self._refresh_status()
        self._append_log(f"备份完成，共 {count} 个扩展名。", "success")
        if was_running:
            self.monitor.resume()
            self._append_log("监控已恢复。", "info")
        messagebox.showinfo(APP_NAME,
            f"备份完成，共保护 {count} 个扩展名。\n\n"
            "如遇bug，请点击停止守护，停止守护后退出程序守护将不会继续。\n"
            "守护启动时，关闭主窗口程序将继续在后台守护。")

    def _on_backup_failed(self, error, was_running):
        self._append_log(f"备份失败: {error}", "error")
        if was_running:
            self.monitor.resume()
        messagebox.showerror(APP_NAME, f"备份失败: {error}")

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
        msg_parts = []
        if inconsistencies:
            self._append_log(f"深层扫描发现 {len(inconsistencies)} 个不一致项：", "warn")
            for ext, mismatches in inconsistencies.items():
                self._append_log(f"  {ext}: {len(mismatches)} 项", "warn")
                if not protecting:
                    # 保护已停止：只报告，不恢复
                    continue
                # 验证式恢复：恢复+刷新+三次回读验证
                s, f, dets = self.engine.recover_extension(ext, mismatches)
                refresh_file_associations()
                verified = True
                for wait_sec in (0.3, 1.5, 3.0):
                    time.sleep(wait_sec)
                    remaining = self.engine.check_extension(ext)
                    if remaining:
                        verified = False
                        self.engine.recover_extension(ext, remaining)
                        refresh_file_associations()
                        break
                if verified:
                    self._append_log(f"    已恢复(已验证)", "success")
                elif f == 0:
                    self._append_log(f"    已恢复但验证未通过(可能被持续篡改)", "warn")
                else:
                    self._append_log(f"    恢复失败({';'.join(dets)})", "error")
            msg_parts.append(f"不一致项: {len(inconsistencies)}")
        if new_exts:
            self._append_log(f"发现 {len(new_exts)} 个可疑新扩展名，已纳入保护：", "warn")
            for ext in new_exts:
                self.baseline_mgr.update_extension(ext)
                self._append_log(f"  {ext}", "info")
            msg_parts.append(f"新扩展名: {len(new_exts)}")
        if not msg_parts:
            self._append_log("深层扫描完成，未发现异常。", "success")
            messagebox.showinfo(APP_NAME, "深层扫描完成，一切正常。")
        else:
            self._refresh_status()
            messagebox.showinfo(APP_NAME, "深层扫描完成：" + "，".join(msg_parts))

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

    def _show_settings(self):
        """设置对话框"""
        cfg = self.baseline_mgr.config
        win = tk.Toplevel(self.root)
        win.title("设置")
        win.geometry("520x620")
        win.transient(self.root)
        win.grab_set()
        # 居中显示
        win.update_idletasks()
        sw = win.winfo_screenwidth()
        sh = win.winfo_screenheight()
        x = (sw - 520) // 2
        y = (sh - 620) // 2
        win.geometry(f"520x620+{x}+{y}")

        # 滚动区域
        canvas = tk.Canvas(win, highlightthickness=0)
        scrollbar = tk.Scrollbar(win, orient="vertical", command=canvas.yview)
        scroll_frame = tk.Frame(canvas)
        scroll_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scroll_frame, anchor="nw", width=500)
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # 鼠标滚轮
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        canvas.bind_all("<MouseWheel>", _on_mousewheel)

        row = 0

        # === 关于 ===
        tk.Label(scroll_frame, text="关于", font=("微软雅黑", 11, "bold")).grid(row=row, column=0, columnspan=2, sticky="w", padx=10, pady=(10,2))
        row += 1
        tk.Label(scroll_frame, text=f"{APP_NAME} v{APP_VERSION}\n阻止第三方软件私自篡改文件扩展名默认打开方式\n保护7项注册表位置，支持基准校准与自动恢复",
                 font=("微软雅黑", 9), justify="left").grid(row=row, column=0, columnspan=2, sticky="w", padx=15, pady=2)
        row += 1

        # === 默认基准下载 ===
        tk.Label(scroll_frame, text="基准管理", font=("微软雅黑", 11, "bold")).grid(row=row, column=0, columnspan=2, sticky="w", padx=10, pady=(10,2))
        row += 1
        tk.Button(scroll_frame, text="下载默认基准包", font=("微软雅黑", 9), width=15,
                  command=lambda: self._open_baseline_download()).grid(row=row, column=0, padx=15, pady=2, sticky="w")
        tk.Label(scroll_frame, text="密码:52pj", font=("微软雅黑", 9), fg="#e74c3c").grid(row=row, column=1, sticky="w", pady=2)
        row += 1
        tk.Button(scroll_frame, text="从文件加载基准", font=("微软雅黑", 9), width=15,
                  command=lambda: self._load_baseline_from_file(win)).grid(row=row, column=0, padx=15, pady=2, sticky="w")
        row += 1

        # === 基准保留版本数 ===
        tk.Label(scroll_frame, text="基准保留版本数:", font=("微软雅黑", 9)).grid(row=row, column=0, sticky="w", padx=15, pady=2)
        hist_var = tk.IntVar(value=cfg.get("history_versions", MAX_HISTORY_VERSIONS))
        tk.Spinbox(scroll_frame, from_=1, to=20, textvariable=hist_var, width=8).grid(row=row, column=1, sticky="w", pady=2)
        row += 1

        # === 默认权限 ===
        tk.Label(scroll_frame, text="运行权限", font=("微软雅黑", 11, "bold")).grid(row=row, column=0, columnspan=2, sticky="w", padx=10, pady=(10,2))
        row += 1
        tk.Label(scroll_frame, text="默认权限级别:", font=("微软雅黑", 9)).grid(row=row, column=0, sticky="w", padx=15, pady=2)
        perm_var = tk.StringVar(value=cfg.get("default_permission", "t"))
        perm_frame = tk.Frame(scroll_frame)
        perm_frame.grid(row=row, column=1, sticky="w", pady=2)
        for val, label in [("user", "普通用户"), ("administrator", "管理员"), ("system", "SYSTEM"), ("t", "TI(推荐)")]:
            tk.Radiobutton(perm_frame, text=label, variable=perm_var, value=val, font=("微软雅黑", 9)).pack(side="left")
        row += 1
        tk.Label(scroll_frame, text="注意：低于TI权限可能导致UserChoice恢复失败，保护不生效",
                 font=("微软雅黑", 8), fg="#e74c3c").grid(row=row, column=0, columnspan=2, sticky="w", padx=15, pady=2)
        row += 1

        # === 开机自启 ===
        tk.Label(scroll_frame, text="通用", font=("微软雅黑", 11, "bold")).grid(row=row, column=0, columnspan=2, sticky="w", padx=10, pady=(10,2))
        row += 1
        autostart_var = tk.BooleanVar(value=cfg.get("autostart", True))
        tk.Checkbutton(scroll_frame, text="开机自启", variable=autostart_var, font=("微软雅黑", 9)).grid(row=row, column=0, columnspan=2, sticky="w", padx=15, pady=2)
        row += 1

        # === 是否弹窗 ===
        popup_var = tk.BooleanVar(value=cfg.get("show_popup", True))
        tk.Checkbutton(scroll_frame, text="检测到更改时弹窗通知（取消则静默阻止）", variable=popup_var, font=("微软雅黑", 9)).grid(row=row, column=0, columnspan=2, sticky="w", padx=15, pady=2)
        row += 1

        # === 默认阻止时间 ===
        tk.Label(scroll_frame, text="默认阻止等待时间(秒):", font=("微软雅黑", 9)).grid(row=row, column=0, sticky="w", padx=15, pady=2)
        block_var = tk.IntVar(value=cfg.get("block_timeout", NOTIFY_TIMEOUT))
        tk.Spinbox(scroll_frame, from_=1, to=60, textvariable=block_var, width=8).grid(row=row, column=1, sticky="w", pady=2)
        row += 1
        tk.Label(scroll_frame, text="关闭弹窗时此值强制为1秒", font=("微软雅黑", 8), fg="#999").grid(row=row, column=0, columnspan=2, sticky="w", padx=15, pady=2)
        row += 1

        # === 每次启动清空日志 ===
        clearlog_var = tk.BooleanVar(value=cfg.get("clear_log_on_start", False))
        tk.Checkbutton(scroll_frame, text="每次启动清空日志", variable=clearlog_var, font=("微软雅黑", 9)).grid(row=row, column=0, columnspan=2, sticky="w", padx=15, pady=2)
        row += 1

        # 底部按钮区（在滚动区外，始终可见）
        bottom_frame = tk.Frame(win)
        bottom_frame.pack(side="bottom", fill="x", pady=8)

        def save_settings():
            old_perm = cfg.get("default_permission", "t")
            cfg["history_versions"] = hist_var.get()
            cfg["default_permission"] = perm_var.get()
            cfg["autostart"] = autostart_var.get()
            cfg["show_popup"] = popup_var.get()
            cfg["block_timeout"] = 1 if not popup_var.get() else block_var.get()
            cfg["clear_log_on_start"] = clearlog_var.get()
            self.baseline_mgr.save_config()
            # 应用自启设置
            if autostart_var.get():
                if not is_autostart_set():
                    add_to_autostart()
            else:
                remove_from_autostart()
            self._append_log("设置已保存", "success")
            # 权限变更需重启提示
            if perm_var.get() != old_perm:
                messagebox.showinfo(APP_NAME, "运行权限已更改，需重启程序后生效。")
            win.destroy()

        tk.Button(bottom_frame, text="保存", font=("微软雅黑", 9), width=10, command=save_settings).pack(side="left", padx=5)
        tk.Button(bottom_frame, text="取消", font=("微软雅黑", 9), width=10, command=win.destroy).pack(side="left", padx=5)
        tk.Label(bottom_frame, text="* 运行权限更改需重启生效", font=("微软雅黑", 8), fg="#999").pack(side="right", padx=10)

    def _open_baseline_download(self):
        """打开默认基准下载页面"""
        url = "https://wwbmw.lanzouq.com/b0139yjgze"
        opened = False
        # 方法1：用explorer.exe打开（TI下最可靠，利用用户态已运行的explorer）
        try:
            import subprocess
            subprocess.Popen(['explorer.exe', url], creationflags=0x08000000)
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
            self._append_log("已打开基准下载页面，密码:52pj", "info")
        else:
            self._append_log("打开浏览器失败，请手动访问", "error")
            messagebox.showinfo(APP_NAME, f"请手动复制访问:\n{url}\n密码:52pj")

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

    def _show_notification(self, ext, mismatches, recover_result, extra_timeout=0):
        """监控线程调用：在主线程显示右下角通知"""
        if threading.current_thread() is not threading.main_thread():
            self.root.after(0, self._show_notification, ext, mismatches, recover_result, extra_timeout)
            return

        def on_consent(extension):
            """用户单次同意：更新基准，清除冷却"""
            self.baseline_mgr.update_extension(extension)
            self.engine.clear_cooldown(extension)
            self.engine.allowed_this_cycle.add(extension)
            self._append_log(f"用户同意 {extension} 的更改，已更新基准。", "warn")
            log_event(extension, "更改", "已同意", "用户单次同意")
            # 10秒后从同意列表移除
            self.root.after(10000, lambda: self.engine.allowed_this_cycle.discard(extension))

        def on_close(toast):
            """通知关闭：从活动列表移除，其余通知对角线上移"""
            if toast in self.active_toasts:
                idx = self.active_toasts.index(toast)
                self.active_toasts.remove(toast)
                # 上方的通知对角线上移（上+左）
                delta_y = NotificationToast.TOAST_HEIGHT + NotificationToast.GAP
                delta_x = 18  # 每个向左偏移18像素
                for t in self.active_toasts[idx:]:
                    t.move_up(delta_y, delta_x)
            self._append_log(f"{ext} 通知已关闭，保持恢复状态。", "info")

        # 检查是否弹窗
        show_popup = self.baseline_mgr.config.get("show_popup", True)
        if not show_popup:
            # 静默模式：不弹窗，直接记录并保持恢复
            self._append_log(f"{ext} 检测到更改，静默阻止（弹窗已关闭）", "warn")
            return

        # 计算堆叠偏移：每个向上堆叠，同时向左偏移18px
        stack_count = len(self.active_toasts)
        y_offset = stack_count * (NotificationToast.TOAST_HEIGHT + NotificationToast.GAP)
        x_offset = stack_count * 18
        timeout = self.baseline_mgr.config.get("block_timeout", NOTIFY_TIMEOUT) + extra_timeout
        if extra_timeout > 0:
            self._append_log(f"批量篡改防护生效，本次弹窗自动阻止时间+{extra_timeout}秒", "info")
        toast = NotificationToast(self.root, ext, mismatches, recover_result,
                                  on_consent, on_close, self._show_main_window,
                                  y_offset=y_offset, x_offset=x_offset, timeout=timeout)
        self.active_toasts.append(toast)

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
    try:
        if getattr(sys, 'frozen', False):
            exe_path = sys.executable
        else:
            exe_path = os.path.abspath(sys.argv[0])
        key = winreg.OpenKey(HKCU, AUTOSTART_KEY, 0, winreg.KEY_SET_VALUE | KEY_READ_64)
        winreg.SetValueEx(key, APP_NAME, 0, winreg.REG_SZ, f'"{exe_path}"')
        winreg.CloseKey(key)
        return True
    except OSError as e:
        logger.error(f"添加自启动失败: {e}")
        return False


def is_autostart_set():
    """检查是否已添加自启动"""
    try:
        key = winreg.OpenKey(HKCU, AUTOSTART_KEY, 0, KEY_READ_64)
        val, _ = winreg.QueryValueEx(key, APP_NAME)
        winreg.CloseKey(key)
        return bool(val)
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
        return False


# ============================================================
# 管理员权限检查
# ============================================================
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False


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


# ============================================================
# TrustedInstaller 提权（无视权限模式）
# 原理：获取 TrustedInstaller 服务的进程令牌，以该令牌启动自身
# ============================================================
def is_system_or_ti():
    """检查当前是否以 SYSTEM 或 TrustedInstaller 权限运行"""
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
        advapi32.ConvertSidToStringSidW.restype = ctypes.c_int
        advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_wchar_p)]

        hToken = HANDLE()
        if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), 0x0008, ctypes.byref(hToken)):
            return False
        class SID_AND_ATTRIBUTES(ctypes.Structure):
            _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", DWORD)]
        class TOKEN_USER(ctypes.Structure):
            _fields_ = [("User", SID_AND_ATTRIBUTES)]
        tu = TOKEN_USER()
        ret_len = DWORD()
        advapi32.GetTokenInformation(hToken, 1, ctypes.byref(tu), ctypes.sizeof(tu), ctypes.byref(ret_len))
        sid_str = ctypes.c_wchar_p()
        advapi32.ConvertSidToStringSidW(tu.User.Sid, ctypes.byref(sid_str))
        advapi32.CloseHandle(hToken)
        sid = sid_str.value
        return sid == "S-1-5-18" or (sid and sid.startswith("S-1-5-80-"))
    except Exception:
        return False


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
                    subprocess.run(['sc.exe', 'start', 'TrustedInstaller'], capture_output=True, timeout=10)
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
            advapi32.CloseHandle(hToken)
            return False
        advapi32.CloseHandle(hToken)
        _log("已复制TrustedInstaller令牌(主令牌)")

        # 7. 启用当前进程必需特权
        hCurToken = HANDLE()
        advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), 0x0020 | 0x0008, ctypes.byref(hCurToken))
        enabled_privs = []
        for priv_name in ("SeImpersonatePrivilege", "SeAssignPrimaryTokenPrivilege", "SeIncreaseQuotaPrivilege"):
            luid = LUID()
            if advapi32.LookupPrivilegeValueW(None, priv_name, ctypes.byref(luid)):
                tp = TOKEN_PRIVILEGES()
                tp.PrivilegeCount = 1
                tp.Privileges[0].Luid = luid
                tp.Privileges[0].Attributes = 0x00000002  # SE_ENABLED
                advapi32.AdjustTokenPrivileges(hCurToken, False, ctypes.byref(tp), 0, None, None)
                if ctypes.get_last_error() == 0:
                    enabled_privs.append(priv_name)
        advapi32.CloseHandle(hCurToken)
        _log(f"已启用特权:{','.join(enabled_privs) if enabled_privs else '无'}")

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

        advapi32.CloseHandle(hDupToken)
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
    """查找可用的NSudo可执行文件（NSudoLC优先，其次NSudoLG）"""
    for name in ("NSudoLC.exe", "NSudoLG.exe"):
        path = os.path.join(RUNTIME_DIR, name)
        if os.path.exists(path):
            return path
    return None

def elevate_via_nsudo():
    """
    使用内置 NSudo 以 TrustedInstaller/SYSTEM 权限重启程序。
    返回 True 表示已发起提权，False 表示失败。
    """
    try:
        import subprocess
        nsudo_exe = _find_nsudo_exe()
        if not nsudo_exe:
            log_event("NSudo", "失败", "NSudo可执行文件不存在", RUNTIME_DIR)
            return False

        if getattr(sys, 'frozen', False):
            target = sys.executable
        else:
            target = f'{sys.executable} "{os.path.abspath(sys.argv[0])}"'

        # 设置环境变量，防止NSudo启动的新进程再次尝试提权（无限循环）
        os.environ["OPST_SKIP_TI"] = "1"
        env = os.environ.copy()

        def _try_nsudo(user_mode):
            """尝试用指定用户模式启动，返回(成功, 输出)"""
            args = [nsudo_exe, f"-U:{user_mode}", "-P:E", "-ShowWindowMode:Show", target]
            log_event("NSudo", "调用", f"尝试模式={user_mode}", " ".join(args))
            try:
                proc = subprocess.run(
                    args, cwd=RUNTIME_DIR, env=env,
                    capture_output=True, text=True, timeout=15
                )
                out = (proc.stdout or "") + (proc.stderr or "")
                log_event("NSudo", "输出", f"返回码={proc.returncode}", out[:500] if out else "(无输出)")
                # NSudo返回0通常表示成功启动目标进程
                if proc.returncode == 0:
                    # 验证目标进程是否真的启动了
                    time.sleep(1)
                    import ctypes
                    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
                    found = False
                    for p in os.popen('tasklist /FI "IMAGENAME eq OPSTcontroller.exe" /NH').read().splitlines():
                        if 'OPSTcontroller.exe' in p:
                            found = True
                            break
                    if found:
                        log_event("NSudo", "验证", "目标进程已启动", "")
                        return True, out
                    else:
                        log_event("NSudo", "验证", "目标进程未找到,可能启动后立即退出", "")
                        return False, out
                return False, out
            except subprocess.TimeoutExpired:
                log_event("NSudo", "超时", f"模式={user_mode}超时(可能目标进程已启动并在运行)", "")
                return True, "timeout(可能已启动)"
            except Exception as e:
                log_event("NSudo", "异常", f"模式={user_mode}: {e}", "")
                return False, str(e)

        # 先尝试 TrustedInstaller，失败则尝试 SYSTEM
        ok, _ = _try_nsudo("T")
        if ok:
            log_event("NSudo", "成功", "已通过NSudo(TrustedInstaller)发起提权", "")
            return True
        log_event("NSudo", "降级", "TrustedInstaller模式失败,尝试SYSTEM模式", "")
        ok, _ = _try_nsudo("S")
        if ok:
            log_event("NSudo", "成功", "已通过NSudo(SYSTEM)发起提权", "")
            return True
        log_event("NSudo", "失败", "TrustedInstaller和SYSTEM模式均失败", "")
        return False
    except Exception as e:
        try:
            log_event("NSudo", "异常", str(e), "")
        except Exception:
            pass
        return False


def elevate_via_nsudo_system_only():
    """使用NSudo仅以SYSTEM权限重启程序（不尝试TrustedInstaller）"""
    try:
        import subprocess
        nsudo_exe = _find_nsudo_exe()
        if not nsudo_exe:
            return False
        if getattr(sys, 'frozen', False):
            target = sys.executable
        else:
            target = f'{sys.executable} "{os.path.abspath(sys.argv[0])}"'
        os.environ["OPST_SKIP_TI"] = "1"
        env = os.environ.copy()
        args = [nsudo_exe, "-U:S", "-P:E", "-ShowWindowMode:Show", target]
        log_event("NSudo", "调用", "尝试模式=S(SYSTEM)", " ".join(args))
        proc = subprocess.run(args, cwd=RUNTIME_DIR, env=env, capture_output=True, text=True, timeout=15)
        if proc.returncode == 0:
            time.sleep(1)
            found = any('OPSTcontroller.exe' in line for line in os.popen('tasklist /FI "IMAGENAME eq OPSTcontroller.exe" /NH').read().splitlines())
            if found:
                log_event("NSudo", "成功", "已通过NSudo(SYSTEM)发起提权", "")
                return True
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
            _fields_ = [("Luid", LUID), ("Attributes", DWORD)]
        class TOKEN_PRIVILEGES(ctypes.Structure):
            _fields_ = [("PrivilegeCount", DWORD), ("Privileges", LUID_AND_ATTRIBUTES * 64)]

        tp = TOKEN_PRIVILEGES()
        ret_len = DWORD()
        advapi32.GetTokenInformation(hToken, 3, ctypes.byref(tp), ctypes.sizeof(tp), ctypes.byref(ret_len))

        enabled_count = 0
        for i in range(min(tp.PrivilegeCount, 64)):
            priv = tp.Privileges[i]
            priv.Attributes = 0x00000002  # SE_ENABLED
            new_tp = TOKEN_PRIVILEGES()
            new_tp.PrivilegeCount = 1
            new_tp.Privileges[0] = priv
            advapi32.AdjustTokenPrivileges(hToken, False, ctypes.byref(new_tp), 0, None, None)
            if ctypes.get_last_error() == 0:
                enabled_count += 1

        advapi32.CloseHandle(hToken)
        return enabled_count
    except Exception:
        return 0


# ============================================================
# 主入口
# ============================================================
def main():
    # 处理 --stop 命令：向运行中的实例发送退出信号
    if "--stop" in sys.argv or "/stop" in sys.argv:
        signaled = signal_exit()
        if signaled:
            print("已向 OPSTcontroller 发送退出信号，等待进程退出...")
            # 等待最多5秒确认进程退出
            import subprocess
            for _ in range(10):
                time.sleep(0.5)
                r = subprocess.run(['tasklist', '/FI', 'IMAGENAME eq OPSTcontroller.exe'],
                                   capture_output=True, text=True)
                if 'OPSTcontroller.exe' not in r.stdout:
                    print("OPSTcontroller 已成功退出。")
                    sys.exit(0)
            # 进程仍在运行，尝试 taskkill
            print("信号方式未生效，尝试强制终止...")
            subprocess.run(['taskkill', '/F', '/IM', 'OPSTcontroller.exe'],
                          capture_output=True)
            time.sleep(1)
            print("已发送强制终止命令。")
        else:
            print("未找到运行中的 OPSTcontroller 实例（命名事件不存在）。")
            # 尝试 taskkill 兜底
            import subprocess
            r = subprocess.run(['tasklist', '/FI', 'IMAGENAME eq OPSTcontroller.exe'],
                               capture_output=True, text=True)
            if 'OPSTcontroller.exe' in r.stdout:
                print("检测到进程，尝试强制终止...")
                subprocess.run(['taskkill', '/F', '/IM', 'OPSTcontroller.exe'],
                              capture_output=True)
                print("已发送强制终止命令。")
        sys.exit(0)

    # 单实例检测
    mutex, is_first = create_single_instance_mutex()
    if not is_first:
        result = activate_existing_instance()
        if result is not None:
            return  # 已激活已有实例，退出
        # 找不到已有窗口（可能残留互斥体），继续正常启动

    # 读取默认权限配置
    default_perm = "t"
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                _cfg = json.load(f)
                default_perm = _cfg.get("default_permission", "t")
    except Exception:
        pass

    # 检查管理员权限（HKLM 写入需要）
    if not is_admin() and default_perm != "user":
        # 提升前先释放互斥体，避免提升后的进程被互斥体拦住直接退出
        kernel32.CloseHandle(mutex)
        run_as_admin()
        sys.exit(0)

    # TrustedInstaller 提权（无视权限模式）
    ti_elevated = False
    ti_status = "管理员" if default_perm != "user" else "普通用户"
    # 防循环：NSudo启动的新进程通过环境变量标记，跳过再次提权
    skip_ti = os.environ.get("OPST_SKIP_TI", "") == "1"
    if default_perm in ("user", "administrator"):
        # 用户选择不提升到TI/SYSTEM
        ti_elevated = False
        ti_status = "普通用户" if default_perm == "user" else "管理员"
        log_event("SYSTEM", "提权", "跳过", f"用户配置默认权限={default_perm},不尝试TI提权")
    elif skip_ti:
        ti_elevated = True
        ti_status = "TI/SYSTEM"
        enabled = enable_all_privileges()
        log_event("SYSTEM", "提权", "跳过", f"NSudo启动的进程,跳过再次提权,已启用{enabled}项特权")
    elif not is_system_or_ti():
        log_event("SYSTEM", "提权", "开始", "尝试内置TrustedInstaller提权")
        # 提权前先释放互斥体！否则新进程检测到互斥体已存在会立即退出
        kernel32.CloseHandle(mutex)
        time.sleep(0.3)
        if default_perm == "system":
            # 仅尝试SYSTEM模式
            if elevate_via_nsudo_system_only():
                log_event("SYSTEM", "提权", "成功", "NSudo已发起SYSTEM重启")
                time.sleep(2)
                sys.exit(0)
            else:
                enabled = enable_all_privileges()
                ti_status = f"管理员(已启用{enabled}项特权)"
                log_event("SYSTEM", "提权", "失败", "NSudo SYSTEM模式失败")
                mutex, _ = create_single_instance_mutex()
        elif run_as_trustedinstaller():
            log_event("SYSTEM", "提权", "成功", "已发起TrustedInstaller重启")
            time.sleep(1)
            sys.exit(0)
        else:
            # 内置方法失败，尝试NSudo
            log_event("SYSTEM", "提权", "备用", "内置方法失败,尝试NSudo提权")
            if elevate_via_nsudo():
                log_event("SYSTEM", "提权", "成功", "NSudo已发起TrustedInstaller重启")
                time.sleep(2)
                sys.exit(0)
            else:
                # 都失败，启用所有可用特权
                enabled = enable_all_privileges()
                ti_status = f"管理员(已启用{enabled}项特权)"
                log_event("SYSTEM", "提权", "失败", f"内置+NSudo均失败,已启用{enabled}个特权")
                # 提权失败，重新创建互斥体
                mutex, _ = create_single_instance_mutex()
    else:
        ti_elevated = True
        ti_status = "TI/SYSTEM"
        log_event("SYSTEM", "提权", "已提权", "当前以SYSTEM/TrustedInstaller权限运行")

    # 关键：TI/SYSTEM下HKCU指向SYSTEM的.DEFAULT配置单元，必须重映射到当前登录用户
    if ti_elevated:
        remap_hkcu_to_interactive_user()

    # 添加开机自启
    if not is_autostart_set():
        if add_to_autostart():
            print("此程序已添加到开机自启")
            log_event("SYSTEM", "自启动", "已添加", "注册表HKCU\\Run")
        else:
            print("警告：添加开机自启失败")

    app = MainWindow(ti_elevated=ti_elevated, ti_status=ti_status)
    app.run()

    # 保持互斥体直到程序退出
    kernel32.CloseHandle(mutex)


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
