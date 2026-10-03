@echo off
chcp 65001 >nul
setlocal
set "ROOT=%~dp0"
set "OUTDIR=%USERPROFILE%\Desktop\OPSTcontroller_Release"
if not exist "%OUTDIR%" mkdir "%OUTDIR%"
echo Building OPSTcontroller...
.\.venv\Scripts\python.exe -m PyInstaller --noconfirm --clean --distpath "%OUTDIR%" OPSTcontroller.spec
if errorlevel 1 goto :fail
echo.
echo Assembling release package...
if not exist "%OUTDIR%\runtime" mkdir "%OUTDIR%\runtime"
copy /Y "..\Win32\NSudoLC.exe" "%OUTDIR%\runtime\" >nul
copy /Y "..\Win32\NSudoLG.exe" "%OUTDIR%\runtime\" >nul
copy /Y "..\Win32\NSudoAPI.dll" "%OUTDIR%\runtime\" >nul
copy /Y "..\Win32\NSudoDM.dll" "%OUTDIR%\runtime\" >nul
copy /Y "..\Win32\MoPlugin.dll" "%OUTDIR%\runtime\" >nul
copy /Y "..\Win32\NSudo-LICENSE.md" "%OUTDIR%\runtime\NSudo-LICENSE.md" >nul
if not exist "%OUTDIR%\userdata" mkdir "%OUTDIR%\userdata"
if not exist "%OUTDIR%\userdata\baseline_history" mkdir "%OUTDIR%\userdata\baseline_history"
copy /Y "..\README.md" "%OUTDIR%\README.md" >nul
copy /Y "..\CHANGELOG.md" "%OUTDIR%\CHANGELOG.md" >nul
copy /Y "LICENSE" "%OUTDIR%\LICENSE" >nul
copy /Y "停止OPSTcontroller.bat" "%OUTDIR%\停止OPSTcontroller.bat" >nul
echo.
echo Build complete. Output in %OUTDIR%
pause
exit /b 0
:fail
echo Build failed.
pause
exit /b 1
