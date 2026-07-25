@echo off
setlocal enabledelayedexpansion

REM --- Auto-elevacion: si no corre como administrador, se relanza pidiendo permisos ---
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Este panel necesita permisos de administrador para el inicio automatico.
    echo Se va a pedir confirmacion de Windows...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs" >nul 2>&1
    exit /b
)

cd /d "%~dp0"

set TASK_NAME=SecureProxyAutostart
set PYTHONW=%~dp0venv\Scripts\pythonw.exe
set PYTHON=%~dp0venv\Scripts\python.exe
set RUN_SCRIPT=%~dp0scripts\run_proxy.py
set PROXY_ADDR=127.0.0.1
set PROXY_PORT=8888
set REG_KEY=HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings

if not exist "%PYTHON%" (
    echo.
    echo No encontre el entorno virtual ^(venv^). Antes de usar este menu, abri
    echo una consola en esta carpeta y corre una sola vez:
    echo.
    echo     python -m venv venv
    echo     venv\Scripts\activate
    echo     pip install -r requirements.txt
    echo     copy .env.example .env
    echo.
    pause
    exit /b 1
)

:menu
cls
echo ================================================
echo   SecureProxy - Panel de control  (admin)
echo ================================================
echo.
echo  1. Iniciar proxy  (ahora y en cada inicio de Windows)
echo  2. Detener proxy  (y desactivar el inicio automatico)
echo  3. Ver estado
echo  4. Actualizar listas de amenazas (URLhaus + OpenPhish)
echo  5. Salir
echo.
set /p opcion="Elegi una opcion (1-5): "

if "%opcion%"=="1" goto iniciar
if "%opcion%"=="2" goto detener
if "%opcion%"=="3" goto estado
if "%opcion%"=="4" goto actualizar
if "%opcion%"=="5" goto salir
goto menu

:iniciar
set HUBO_ERROR=0
echo.
echo Registrando el inicio automatico con Windows...
schtasks /create /tn "%TASK_NAME%" /tr "\"%PYTHONW%\" \"%RUN_SCRIPT%\"" /sc onlogon /rl limited /f >nul 2>&1
if %errorlevel% neq 0 (
    echo   ERROR: no se pudo registrar la tarea programada.
    set HUBO_ERROR=1
) else (
    echo   OK.
)

echo Iniciando el proxy ahora mismo...
if %HUBO_ERROR%==0 (
    schtasks /run /tn "%TASK_NAME%" >nul 2>&1
    if %errorlevel% neq 0 (
        echo   ERROR: no se pudo iniciar el proxy via la tarea programada.
        set HUBO_ERROR=1
    ) else (
        echo   OK.
    )
) else (
    echo   Se omite: la tarea no se registro en el paso anterior.
)
timeout /t 2 /nobreak >nul

echo Configurando el proxy del sistema de Windows en %PROXY_ADDR%:%PROXY_PORT% ...
reg add "%REG_KEY%" /v ProxyServer /t REG_SZ /d "%PROXY_ADDR%:%PROXY_PORT%" /f >nul 2>&1
reg add "%REG_KEY%" /v ProxyEnable /t REG_DWORD /d 1 /f >nul 2>&1
if %errorlevel% neq 0 (
    echo   ERROR: no se pudo configurar el proxy del sistema.
    set HUBO_ERROR=1
) else (
    echo   OK.
)

echo.
if %HUBO_ERROR%==0 (
    echo Listo. El proxy deberia estar corriendo, y va a arrancar solo cada vez
    echo que inicies sesion en Windows, hasta que elijas la opcion 2 para apagarlo.
) else (
    echo Hubo al menos un error arriba. Revisa el detalle antes de asumir que
    echo el proxy esta activo. Si el problema persiste, corre este .bat con
    echo clic derecho -^> "Ejecutar como administrador" y volve a intentar.
)
pause
goto menu

:detener
echo.
echo Quitando el inicio automatico...
schtasks /delete /tn "%TASK_NAME%" /f >nul 2>&1

echo Desactivando el proxy del sistema de Windows...
reg add "%REG_KEY%" /v ProxyEnable /t REG_DWORD /d 0 /f >nul 2>&1

echo Deteniendo el proceso del proxy (si estaba corriendo)...
"%PYTHON%" scripts\stop_proxy.py

echo.
echo Listo. El proxy quedo apagado y NO se va a iniciar solo la proxima vez
echo que prendas la PC.
pause
goto menu

:estado
echo.
schtasks /query /tn "%TASK_NAME%" >nul 2>&1
if %errorlevel%==0 (
    echo Inicio automatico con Windows : ACTIVADO
) else (
    echo Inicio automatico con Windows : desactivado
)

if exist "data\proxy.pid" (
    echo Proceso del proxy             : parece estar corriendo ^(PID guardado^)
) else (
    echo Proceso del proxy             : no esta corriendo
)

reg query "%REG_KEY%" /v ProxyEnable 2>nul | findstr "0x1" >nul
if %errorlevel%==0 (
    echo Proxy del sistema de Windows   : ACTIVADO
) else (
    echo Proxy del sistema de Windows   : desactivado
)
echo.
pause
goto menu

:actualizar
echo.
"%PYTHON%" scripts\update_blocklist.py
echo.
pause
goto menu

:salir
endlocal
exit /b 0
