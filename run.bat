@echo off
setlocal
cd /d "%~dp0"

:check_uv
if /I "%~1"=="-Help" goto launch
where uv >nul 2>nul
if errorlevel 1 (
  echo [ScreenShield] uv is not installed or is not available in PATH.
  echo Install it from https://docs.astral.sh/uv/getting-started/installation/
  pause
  exit /b 1
)

:launch
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0run.ps1" %*
exit /b %errorlevel%
