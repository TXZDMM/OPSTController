@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo 正在向 OPSTcontroller 发送退出信号...
OPSTcontroller.exe --stop
echo.
echo 操作完成。按任意键关闭本窗口。
pause >nul
