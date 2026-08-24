@echo off
chcp 65001 >nul 2>&1
title 停止 OPSTcontroller
echo 正在向 OPSTcontroller 发送退出信号...
"%~dp0OPSTcontroller.exe" --stop
timeout /t 2 >nul
echo.
echo 确认进程是否已退出...
tasklist /FI "IMAGENAME eq OPSTcontroller.exe" /NH 2>nul | findstr /I "OPSTcontroller.exe" >nul
if %errorlevel% equ 0 (
    echo 进程仍在运行，尝试强制终止...
    taskkill /F /IM OPSTcontroller.exe 2>nul
    if %errorlevel% equ 0 (
        echo OPSTcontroller 已强制停止。
    ) else (
        echo 强制终止失败（可能需要管理员/SYSTEM权限）。
    )
) else (
    echo OPSTcontroller 已优雅退出。
)
timeout /t 2 >nul
