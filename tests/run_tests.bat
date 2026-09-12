@echo off
rem Run the GhidraMCP test suite: offline units first, then the live e2e suite.
setlocal
cd /d "%~dp0.."

set "PY=C:\Users\artem\AppData\Local\GhidraMCP\venv\Scripts\python.exe"
if not exist "%PY%" (
    echo   [XX] the installed venv is missing; run install.bat first
    pause
    exit /b 1
)

echo === Unit tests (offline, fast) ===
"%PY%" -X utf8 -u "%~dp0test_unit.py" %*
set UNIT=%ERRORLEVEL%

echo.
echo === End-to-end tests (real server, real Ghidra, real network) ===
"%PY%" -X utf8 -u "%~dp0test_e2e.py" %*
set E2E=%ERRORLEVEL%

echo.
if "%UNIT%"=="0" if "%E2E%"=="0" (
    echo   ALL TESTS PASSED
    exit /b 0
) else (
    echo   FAILURES: unit=%UNIT% e2e=%E2E%
    exit /b 1
)
