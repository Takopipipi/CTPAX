@echo off
rem ============================================================================
rem  Ghidra MCP server - uninstaller
rem ============================================================================
setlocal

title Ghidra MCP server - uninstaller
cd /d "%~dp0"

echo.
echo ========================================================================
echo   Removing the Ghidra MCP server
echo ========================================================================
echo.
echo  This removes the OpenCode registration and the installed environment.
echo  You will be asked before anything deletes your Ghidra analysis projects.
echo.

set "PYEXE="
py -3 -c "import sys" >nul 2>&1
if not errorlevel 1 (
    for /f "delims=" %%i in ('py -3 -c "import sys; print(sys.executable)" 2^>nul') do set "PYEXE=%%i"
)
if not defined PYEXE (
    for /f "delims=" %%i in ('python -c "import sys; print(sys.executable)" 2^>nul') do set "PYEXE=%%i"
)
if not defined PYEXE (
    echo   [XX] Python was not found, so the uninstaller cannot run.
    echo        Delete %%LOCALAPPDATA%%\GhidraMCP by hand and remove the
    echo        "ghidra" entry from the "mcp" block in your opencode config.
    echo.
    pause
    exit /b 1
)

"%PYEXE%" "%~dp0install.py" --uninstall %*
set "RESULT=%ERRORLEVEL%"

echo.
pause
exit /b %RESULT%
