# -*- mode: python ; coding: utf-8 -*-
# OPSTcontroller 构建配置（瘦身版）
# - 排除本程序未使用、但 PyInstaller 会顺带收集的二进制依赖（libcrypto-3.dll 等约 2MB）
# - 剔除 Tcl 时区数据库、Tk 内置 logo、tcl8 模块库（tkinter 运行时不需要）

def _keep_tk_data(name):
    n = name.replace('\\', '/')
    if n.startswith('_tcl_data/tzdata/'):   # Tcl clock 命令的时区表，程序用 Python time/datetime
        return False
    if n.startswith('_tk_data/images/'):    # Tk 内置 about 图片
        return False
    if n.startswith('tcl8/'):               # tcltest/http/msgcat 等可选模块库
        return False
    return True

a = Analysis(
    ['extension_protector.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['ssl', 'hashlib', 'hmac', 'secrets', 'socket', 'sqlite3'],
    noarchive=False,
    optimize=0,
)
a.datas = [x for x in a.datas if _keep_tk_data(x[0])]
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='OPSTcontroller',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    version='version_info.txt',
)
