@echo off
REM run.bat
REM ─────────────────────────────────────────────────────────────────────────────
REM SCRIPT DE ARRANQUE — Windows (CMD)
REM ─────────────────────────────────────────────────────────────────────────────
REM Uso:
REM   run.bat                          → menú interactivo
REM   run.bat --juice-shop             → Juice Shop directamente
REM   run.bat --target http://mi-app.com  → target externo directamente
REM ─────────────────────────────────────────────────────────────────────────────

setlocal enabledelayedexpansion

echo.
echo ════════════════════════════════════════════════════
echo   🔐  VULNERABILITY ANALYSIS PIPELINE
echo ════════════════════════════════════════════════════
echo.

REM ── 1. Comprobar Python ──────────────────────────────────────────────────────
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python no encontrado.
    echo         Instala Python 3.11+ desde https://python.org
    echo         Asegurate de marcar "Add Python to PATH" durante la instalacion.
    pause
    exit /b 1
)
for /f "tokens=*" %%i in ('python --version') do echo [OK] %%i encontrado

REM ── 2. Comprobar Docker ──────────────────────────────────────────────────────
docker info >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Docker no esta activo.
    echo         Arranca Docker Desktop e intentalo de nuevo.
    pause
    exit /b 1
)
echo [OK] Docker activo

REM ── 3. Crear entorno virtual si no existe ────────────────────────────────────
if not exist "venv\" (
    echo [INFO] Creando entorno virtual...
    python -m venv venv
    echo [OK] Entorno virtual creado
)

REM ── 4. Activar entorno virtual ───────────────────────────────────────────────
call venv\Scripts\activate.bat
echo [OK] Entorno virtual activado

REM ── 5. Instalar dependencias ─────────────────────────────────────────────────
echo [INFO] Instalando dependencias...
pip install -q --upgrade pip
pip install -q -r requirements.txt
echo [OK] Dependencias instaladas

echo.
echo ════════════════════════════════════════════════════
echo.

REM ── 6. Determinar modo de ejecución ──────────────────────────────────────────
REM
REM Si el usuario pasó argumentos (ej: run.bat --juice-shop),
REM los pasamos directamente a Python sin preguntar nada.
REM
REM Si no pasó argumentos, mostramos el menú interactivo.

if not "%~1"=="" (
    REM El usuario pasó argumentos → los usamos directamente
    echo [INFO] Ejecutando con argumentos: %*
    echo.
    python main.py %*
    goto :end
)

REM ── Menú interactivo ─────────────────────────────────────────────────────────
echo   Que quieres escanear?
echo.
echo   1) OWASP Juice Shop (entorno de prueba Docker)
echo      Levanta Juice Shop automaticamente y lo escanea.
echo      Incluye: Nmap + ZAP + Trivy
echo.
echo   2) Target externo (tu propia aplicacion)
echo      Escanea una URL que ya este en ejecucion.
echo      Incluye: Nmap + ZAP
echo.
echo   3) Salir
echo.
set /p OPCION="  Elige una opcion [1/2/3]: "
echo.

if "%OPCION%"=="1" goto :juice_shop
if "%OPCION%"=="2" goto :external_target
if "%OPCION%"=="3" goto :salir

echo [ERROR] Opcion no valida. Ejecuta run.bat de nuevo.
exit /b 1

REM ── Opción 1: Juice Shop ─────────────────────────────────────────────────────
:juice_shop
echo [INFO] Modo: OWASP Juice Shop
echo.
set /p BROWSER="  Abrir el dashboard en el navegador al finalizar? [S/n]: "
set BROWSER_FLAG=
if /i "%BROWSER%"=="n" set BROWSER_FLAG=--no-browser
echo.
python main.py --juice-shop %BROWSER_FLAG%
goto :end

REM ── Opción 2: Target externo ─────────────────────────────────────────────────
:external_target
echo [INFO] Modo: Target externo
echo.
set /p TARGET_URL="  Introduce la URL del objetivo (ej: http://localhost:8080): "

if "%TARGET_URL%"=="" (
    echo [ERROR] URL vacia. Abortando.
    exit /b 1
)

set /p BROWSER="  Abrir el dashboard en el navegador al finalizar? [S/n]: "
set BROWSER_FLAG=
if /i "%BROWSER%"=="n" set BROWSER_FLAG=--no-browser
echo.
python main.py --target "%TARGET_URL%" %BROWSER_FLAG%
goto :end

REM ── Opción 3: Salir ──────────────────────────────────────────────────────────
:salir
echo Saliendo.
exit /b 0

:end
endlocal
