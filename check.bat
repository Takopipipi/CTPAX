@echo off
rem ============================================================================
rem  Check the environment without installing anything.
rem ============================================================================
setlocal

title Ghidra MCP server - environment check
cd /d "%~dp0"

set "PYEXE="
py -3 -c "import sys" >nul 2>&1
if not errorlevel 1 (
    for /f "delims=" %%i in ('py -3 -c "import sys; print(sys.executable)" 2^>nul') do set "PYEXE=%%i"
)
if not defined PYEXE (
    for /f "delims=" %%i in ('python -c "import sys; print(sys.executable)" 2^>nul') do set "PYEXE=%%i"
)
if not defined PYEXE (
    echo   [XX] No Python found. Install Python 3.10+ from python.org first.
    echo.
    pause
    exit /b 1
)

"%PYEXE%" "%~dp0install.py" --check %*
set "RESULT=%ERRORLEVEL%"

echo.
pause
exit /b %RESULT%
