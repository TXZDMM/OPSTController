@echo off
chcp 65001 >nul
echo Building OPSTcontroller...
python -m PyInstaller --onedir --name "OPSTcontroller" --windowed --clean --noconfirm --contents-directory runtime extension_protector.py
echo.
echo Build complete. Output in dist\OPSTcontroller\
pause
