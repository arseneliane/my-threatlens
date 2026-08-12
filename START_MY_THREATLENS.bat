@echo off
setlocal
cd /d "%~dp0"
set "PYTHON_CMD="
where py >nul 2>&1 && set "PYTHON_CMD=py -3"
if not defined PYTHON_CMD where python >nul 2>&1 && set "PYTHON_CMD=python"
if not defined PYTHON_CMD (
  echo Python 3.11 or newer is required. Install it from https://www.python.org/downloads/
  pause
  exit /b 1
)
%PYTHON_CMD% -c "import sys; assert sys.version_info >= (3,11)" 2>nul || (
  echo Python 3.11 or newer is required.
  pause
  exit /b 1
)
if not exist ".venv\Scripts\python.exe" (
  echo Creating the local environment...
  if exist ".venv" rmdir /s /q ".venv"
  %PYTHON_CMD% -m venv .venv || goto :error
)
.venv\Scripts\python.exe -m pip install -r requirements.txt --disable-pip-version-check -q || goto :error
if not exist ".env" copy ".env.example" ".env" >nul
echo Checking for an older My ThreatLens server...
powershell -NoProfile -Command "$listener=Get-NetTCPConnection -LocalPort 8001 -State Listen -ErrorAction SilentlyContinue; if($listener){$process=Get-CimInstance Win32_Process -Filter ('ProcessId='+$listener.OwningProcess); if($process.CommandLine -match 'uvicorn.+app\.main:app'){Write-Host 'Stopping the older My ThreatLens server...'; Stop-Process -Id $listener.OwningProcess -Force; Start-Sleep -Seconds 1}else{Write-Host 'Port 8001 is used by another application.'; exit 42}}"
if errorlevel 42 (
  echo Close the other application using port 8001, then run this file again.
  pause
  exit /b 1
)
start "" powershell -NoProfile -WindowStyle Hidden -Command "Start-Sleep -Seconds 2; Start-Process 'http://127.0.0.1:8001'"
echo My ThreatLens is starting at http://127.0.0.1:8001
.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8001
exit /b %errorlevel%
:error
echo Startup failed. Review the message above, then run this file again.
pause
exit /b 1
