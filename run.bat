@echo off

setlocal enabledelayedexpansion

echo.
echo ════════════════════════════════════════════════════
echo          AVAP - VULNERABILITY ANALYSIS PIPELINE
echo ════════════════════════════════════════════════════
echo.

python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found.
    echo         Install Python 3.11+ from https://python.org
    echo         Make sure to check "Add Python to PATH" during installation.
    pause
    exit /b 1
)
for /f "tokens=*" %%i in ('python --version') do echo [OK] %%i found

docker info >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Docker is not running.
    echo         Start Docker Desktop and try again.
    pause
    exit /b 1
)
echo [OK] Docker is running

if not exist "venv\" (
    echo [INFO] Creating virtual environment...
    python -m venv venv
    echo [OK] Virtual environment created
)

call venv\Scripts\activate.bat
echo [OK] Virtual environment activated

echo [INFO] Installing dependencies...
pip install -q --upgrade pip
pip install -q -r requirements.txt
echo [OK] Dependencies installed

echo.
echo ════════════════════════════════════════════════════
echo.

if not "%~1"=="" (
    echo [INFO] Running with arguments: %*
    echo.
    python main.py %*
    goto :end
)

echo   What do you want to scan?
echo.
echo   1) OWASP Juice Shop (Docker test environment)
echo      Starts Juice Shop automatically and scans it.
echo      Includes: Nmap + ZAP + Trivy
echo.
echo   2) External target (your own application)
echo      Scans a URL that is already running.
echo      Includes: Nmap + ZAP
echo.
echo   3) Exit
echo.
set /p OPCION="  Choose an option [1/2/3]: "
echo.

if "%OPCION%"=="1" goto :juice_shop
if "%OPCION%"=="2" goto :external_target
if "%OPCION%"=="3" goto :exit

echo [ERROR] Invalid option. Run run.bat again.
exit /b 1

:juice_shop
echo [INFO] Mode: OWASP Juice Shop
echo.
set /p BROWSER="  Open the dashboard in the browser after finishing? [Y/n]: "
set BROWSER_FLAG=
if /i "%BROWSER%"=="n" set BROWSER_FLAG=--no-browser
echo.
python main.py --juice-shop %BROWSER_FLAG%
goto :end

:external_target
echo [INFO] Mode: External target
echo.
set /p TARGET_URL="  Enter the target URL (e.g. http://localhost:8080): "

if "%TARGET_URL%"=="" (
    echo [ERROR] Empty URL. Aborting.
    exit /b 1
)

set /p BROWSER="  Open the dashboard in the browser after finishing? [Y/n]: "
set BROWSER_FLAG=
if /i "%BROWSER%"=="n" set BROWSER_FLAG=--no-browser
echo.
python main.py --target "%TARGET_URL%" %BROWSER_FLAG%
goto :end

:exit
echo Exiting.
exit /b 0

:end
endlocal
