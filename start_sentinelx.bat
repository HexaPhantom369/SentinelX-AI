@echo off
setlocal
pushd "%~dp0"

powershell -NoProfile -Command "$identity = [Security.Principal.WindowsIdentity]::GetCurrent(); $principal = [Security.Principal.WindowsPrincipal]::new($identity); if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { exit 0 } else { exit 1 }" >nul 2>&1
if errorlevel 1 (
    echo Requesting Administrator privileges for local firewall response support...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "try { Start-Process -FilePath '%~f0' -Verb RunAs -ErrorAction Stop } catch { exit 1 }"
    if errorlevel 1 (
        echo Administrator elevation was canceled or could not be started.
        pause
        popd
        exit /b 1
    )
    popd
    exit /b 0
)

where py >nul 2>&1
if errorlevel 1 (
    echo Python 3.10 or later with the Windows Python launcher is required.
    pause
    popd
    exit /b 1
)
py -3 -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>&1
if errorlevel 1 (
    echo Python 3.10 or later is required. Install it from python.org and retry.
    pause
    popd
    exit /b 1
)

if not exist ".venv\Scripts\python.exe" (
    echo Creating local Python environment...
    py -3 -m venv .venv
    if errorlevel 1 (
        echo Could not create the virtual environment.
        pause
        popd
        exit /b 1
    )
)

".venv\Scripts\python.exe" -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>&1
if errorlevel 1 (
    echo The existing .venv uses Python older than 3.10. Remove that environment and retry.
    pause
    popd
    exit /b 1
)

echo Installing SentinelX dependencies...
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 (
    echo Dependency installation failed.
    pause
    popd
    exit /b 1
)

set "SENTINELX_DATABASE=%CD%\instance\sentinelx.sqlite"
set "SENTINELX_LEGACY_DATABASE=%CD%\instance\sentinelx.db"
if not exist "%SENTINELX_DATABASE%" (
    if exist "%SENTINELX_LEGACY_DATABASE%" (
        echo Preserving existing SentinelX database while upgrading to sentinelx.sqlite...
        ".venv\Scripts\python.exe" -c "import os,sqlite3; source=sqlite3.connect(os.environ['SENTINELX_LEGACY_DATABASE']); destination=sqlite3.connect(os.environ['SENTINELX_DATABASE']); source.backup(destination); destination.close(); source.close()"
        if errorlevel 1 (
            del /q "%SENTINELX_DATABASE%" "%SENTINELX_DATABASE%-wal" "%SENTINELX_DATABASE%-shm" >nul 2>&1
            echo Existing database could not be copied safely; no source database was changed.
            pause
            popd
            exit /b 1
        )
    )
)

echo Initializing or upgrading the local SentinelX database...
".venv\Scripts\python.exe" -m flask --app run.py init-db
if errorlevel 1 (
    echo Database initialization or upgrade failed.
    pause
    popd
    exit /b 1
)

echo Opening SentinelX at http://127.0.0.1:5000
timeout /t 2 /nobreak >nul
start "" "http://127.0.0.1:5000"
echo Keep this window open while SentinelX is running.
".venv\Scripts\python.exe" -m flask --app run.py run --host 127.0.0.1 --port 5000
set "SENTINELX_EXIT_CODE=%errorlevel%"
popd
exit /b %SENTINELX_EXIT_CODE%
