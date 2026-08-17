@echo off
setlocal
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\set_ollama_mode.ps1" -Mode local -ProjectRoot "%~dp0."
if errorlevel 1 echo Configuration failed. Review the message above.
pause
