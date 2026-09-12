@echo off
rem ============================================================================
rem  Ghidra MCP server - installer for OpenCode
rem
rem  Delayed expansion stays OFF on purpose: this script may live in a path
rem  containing '!', which delayed expansion would eat.
rem ============================================================================
setlocal

title Ghidra MCP server - installer
cd /d "%~dp0"

echo.
echo ========================================================================
echo   Ghidra MCP server for OpenCode
echo ========================================================================
echo.
echo  This will:
echo    - find your Ghidra installation and a JDK 21+
echo    - create a private Python environment under %%LOCALAPPDATA%%\GhidraMCP
echo    - install the server and register it in OpenCode
echo    - start it once to prove it works
echo.
echo  Nothing is registered in OpenCode unless the check succeeds.
echo  Add --cursor to also register the server in Cursor (global ~\.cursor\mcp.json).
echo.

rem --- locate a usable Python ------------------------------------------------
set "PYEXE="

py -3 -c "import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)" >nul 2>&1
if not errorlevel 1 (
    for /f "delims=" %%i in ('py -3 -c "import sys; print(sys.executable)" 2^>nul') do set "PYEXE=%%i"
)

if not defined PYEXE (
    python -c "import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)" >nul 2>&1
    if not errorlevel 1 (
        for /f "delims=" %%i in ('python -c "import sys; print(sys.executable)" 2^>nul') do set "PYEXE=%%i"
    )
)

if not defined PYEXE (
    echo   [XX] No Python 3.10 or newer was found.
    echo.
    echo   Install Python from https://www.python.org/downloads/
    echo   and tick "Add python.exe to PATH" during setup.
    echo.
    pause
    exit /b 1
)

echo   [ok] Python: %PYEXE%
echo.

rem --- run the real installer ------------------------------------------------
"%PYEXE%" "%~dp0install.py" %*
set "RESULT=%ERRORLEVEL%"

echo.
if "%RESULT%"=="0" (
    echo ========================================================================
    echo   Done. Restart OpenCode (and Cursor, if you passed --cursor)
    echo   to pick up the new tools.
    echo ========================================================================
) else if "%RESULT%"=="1" (
    echo ========================================================================
    echo   Installed, but with warnings. See the output above.
    echo ========================================================================
) else (
    echo ========================================================================
    echo   Installation failed. Nothing was registered in OpenCode.
    echo ========================================================================
    echo.
    echo   Useful options:
    echo     install.bat --check                    report on the environment only
    echo     install.bat --ghidra "D:\ghidra_11.3"  point at Ghidra explicitly
    echo     install.bat --java "C:\jdk-21"         point at a JDK explicitly
    echo     install.bat --home "C:\Tools\GhidraMCP"  install elsewhere
    echo     install.bat --cursor                   also register in Cursor
)

echo.
pause
exit /b %RESULT%
