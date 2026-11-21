@echo off
REM ===================================================================
REM  sealed - one-click demo launcher
REM  Double-click this file. It starts everything and opens the demo.
REM  Close the two windows it opens to stop.
REM ===================================================================
title sealed - launcher
cd /d "%~dp0"

echo.
echo   ==============================================
echo     sealed - starting the demo
echo   ==============================================
echo.

REM ---- find python ---------------------------------------------------
set "PY="
where python >nul 2>&1 && set "PY=python"
if not defined PY if exist "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" set "PY=%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
if not defined PY if exist "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" set "PY=%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
if not defined PY if exist "C:\Program Files\Python312\python.exe" set "PY=C:\Program Files\Python312\python.exe"

if not defined PY (
  echo   [X] Python was not found.
  echo.
  echo   Install it once with this command, then run this file again:
  echo       winget install -e --id Python.Python.3.12
  echo.
  pause
  exit /b 1
)

REM ---- find node -----------------------------------------------------
where node >nul 2>&1
if errorlevel 1 (
  echo   [X] Node.js was not found - it serves the web pages.
  echo.
  echo   Install it from https://nodejs.org then run this file again.
  echo.
  pause
  exit /b 1
)

echo   [1/3] Starting the sealed system...
start "sealed - system (leave open)" cmd /k ""%PY%" -u run-local.py"

echo   [2/3] Starting the web pages...
start "sealed - website (leave open)" cmd /k "node serve-web.js"

echo   [3/3] Waiting for everything to come up...
REM give the services time to bind their ports
powershell -NoProfile -Command "$u='http://127.0.0.1:8000/health'; for($i=0;$i -lt 60;$i++){try{ if((Invoke-WebRequest $u -TimeoutSec 2 -UseBasicParsing).StatusCode -eq 200){exit 0} }catch{}; Start-Sleep -Milliseconds 700 }; exit 1"

if errorlevel 1 (
  echo.
  echo   [!] The system did not start in time.
  echo       Look at the "sealed - system" window for the reason.
  echo       Most common cause: ports 8000-8012 are already in use.
  echo.
  pause
  exit /b 1
)

echo.
echo   Ready. Opening the demo in your browser...
start "" "http://localhost:8080/console.html"

echo.
echo   ==============================================
echo     The demo is open in your browser.
echo.
echo     Leave the two "sealed - ..." windows open.
echo     Close them when you are finished.
echo   ==============================================
echo.
timeout /t 8 >nul
