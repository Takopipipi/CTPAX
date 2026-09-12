@echo off
chcp 65001 >nul
set "PYTHONIOENCODING=utf-8"
setlocal
title CTPAX - reverse-engineering MCP installer
cd /d "%~dp0"

where py >nul 2>nul
if %errorlevel%==0 (
    py -3 "%~dp0ctpax_setup.py" %*
    goto done
)
where python >nul 2>nul
if %errorlevel%==0 (
    python "%~dp0ctpax_setup.py" %*
    goto done
)

echo.
echo  Python 3.10+ is required to run the CTPAX installer.
echo  Install it first, for example:  winget install Python.Python.3.12
echo.
pause
exit /b 1

:done
if %errorlevel% neq 0 (
    echo.
    echo  Installer finished with an error code %errorlevel%. The output above says why.
    echo  Press any key to close...
    pause >nul
)
endlocal
