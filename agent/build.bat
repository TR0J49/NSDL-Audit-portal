@echo off
echo ================================================
echo  Building System Audit Agent Executable
echo ================================================
echo.

pip install -r requirements.txt

echo.
echo Building EXE with PyInstaller...
echo.

pyinstaller --onefile --windowed --name "SystemAuditAgent" --hidden-import=audit_agent agent_gui.py

echo.
echo ================================================
echo  Build Complete!
echo  EXE location: dist\SystemAuditAgent.exe
echo ================================================
pause
