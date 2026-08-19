@echo off
setlocal
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\first_run_setup.ps1" -ProjectRoot "%~dp0." || goto :error
set "APP_PORT=8001"
for /f "usebackq delims=" %%P in (`powershell -NoProfile -Command "foreach($line in Get-Content -LiteralPath '.env'){if($line -match '^APP_PORT='){$value=($line -split '=',2)[1].Trim().Trim([char]34); if($value -match '^\d+$' -and [int]$value -ge 1024 -and [int]$value -le 65535){$value}; break}}"`) do set "APP_PORT=%%P"
set "PUBLIC_BASE_URL=http://127.0.0.1:%APP_PORT%"
set "PYTHON_CMD="
where py >nul 2>&1 && py -3.12 -c "import sys; assert (3,11) <= sys.version_info[:2] < (3,15)" >nul 2>&1 && set "PYTHON_CMD=py -3.12"
if not defined PYTHON_CMD where py >nul 2>&1 && py -3 -c "import sys; assert (3,11) <= sys.version_info[:2] < (3,15)" >nul 2>&1 && set "PYTHON_CMD=py -3"
if not defined PYTHON_CMD where python >nul 2>&1 && python -c "import sys; assert (3,11) <= sys.version_info[:2] < (3,15)" >nul 2>&1 && set "PYTHON_CMD=python"
if not defined PYTHON_CMD if exist "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" set "PYTHON_CMD=%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
if not defined PYTHON_CMD (
  echo A compatible Python version could not be prepared. Install Python 3.12 and retry.
  pause
  exit /b 1
)
%PYTHON_CMD% -c "import sys; assert (3,11) <= sys.version_info[:2] < (3,15); print('Using Python',sys.version.split()[0])" || (
  echo Python 3.11 through 3.14 is required.
  pause
  exit /b 1
)
if exist ".venv\Scripts\python.exe" (
  .venv\Scripts\python.exe -c "import sys; assert (3,11) <= sys.version_info[:2] < (3,15)" >nul 2>&1 || (
    echo Replacing an incompatible local Python environment...
    rmdir /s /q ".venv"
  )
)
if not exist ".venv\Scripts\python.exe" (
  echo Creating the local environment...
  if exist ".venv" rmdir /s /q ".venv"
  %PYTHON_CMD% -m venv .venv || goto :error
)
.venv\Scripts\python.exe -m pip install -r requirements.txt --disable-pip-version-check -q || goto :error
if not exist ".env" (
  echo Configuration was not created. Run this file again.
  pause
  exit /b 1
)
echo Checking for an older My ThreatLens server on port %APP_PORT%...
powershell -NoProfile -Command "$listener=Get-NetTCPConnection -LocalPort %APP_PORT% -State Listen -ErrorAction SilentlyContinue; if($listener){$process=Get-CimInstance Win32_Process -Filter ('ProcessId='+$listener.OwningProcess); if($process.CommandLine -match 'uvicorn.+app\.main:app'){Write-Host 'Stopping the older My ThreatLens server...'; Stop-Process -Id $listener.OwningProcess -Force; Start-Sleep -Seconds 1}else{Write-Host 'Port %APP_PORT% is used by another application.'; exit 42}}"
if errorlevel 42 (
  echo Close the other application using port %APP_PORT%, or change APP_PORT in .env.
  pause
  exit /b 1
)
start "" powershell -NoProfile -WindowStyle Hidden -Command "Start-Sleep -Seconds 2; Start-Process 'http://127.0.0.1:%APP_PORT%'"
echo My ThreatLens is starting at http://127.0.0.1:%APP_PORT%
.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port %APP_PORT%
exit /b %errorlevel%
:error
echo Startup failed. Review the message above, then run this file again.
pause
exit /b 1
