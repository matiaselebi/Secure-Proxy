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
set DASHBOARD_URL=http://127.0.0.1:8889/
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
echo  4. Actualizar listas de amenazas (URLhaus + OpenPhish + Feodo + FireHOL)
echo  5. Agregar dominio a la lista blanca (permitir siempre)
echo  6. Agregar dominio a la lista negra (bloquear siempre)
echo  7. Borrar cache de reputacion de IPs (AbuseIPDB)
echo  8. Actualizar base de pais y proveedor por IP (una vez por mes)
echo  9. Salir
echo.
set /p opcion="Elegi una opcion (1-9): "

if "%opcion%"=="1" goto iniciar
if "%opcion%"=="2" goto detener
if "%opcion%"=="3" goto estado
if "%opcion%"=="4" goto actualizar
if "%opcion%"=="5" goto permitir
if "%opcion%"=="6" goto bloquear
if "%opcion%"=="7" goto borrar_cache
if "%opcion%"=="8" goto actualizar_geoip
if "%opcion%"=="9" goto salir
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

"%PYTHON%" -c "import sys; sys.path.insert(0, 'src'); from secureproxy.ip_reputation_cache import PersistentIPCache; print('Entradas en cache (AbuseIPDB)  :', PersistentIPCache('data/ip_reputation_cache.db').count())" 2>nul
echo.
pause
goto menu

:actualizar
echo.
"%PYTHON%" scripts\update_blocklist.py
echo.
pause
goto menu

:actualizar_geoip
echo.
echo Esto baja la base de pais / ASN / proveedor por IP (DB-IP lite, gratuita)
echo y la arma en data\geoip.db. Son varios megabytes y tarda un rato, pero
echo con hacerlo una vez por mes alcanza: las asignaciones de red no cambian
echo todos los dias.
echo.
echo El proxy funciona igual sin esta base; lo unico que pasa es que el
echo historial queda sin las columnas de pais, ASN y proveedor.
echo.
"%PYTHON%" scripts\update_geoip.py
echo.
pause
goto menu

:permitir
echo.
set /p NUEVO_DOMINIO="Dominio a permitir siempre (podes pegar la URL entera): "
if "%NUEVO_DOMINIO%"=="" (
    echo No ingresaste ningun dominio.
    pause
    goto menu
)
"%PYTHON%" scripts\agregar_dominio.py blanca "%NUEVO_DOMINIO%"
echo.
echo Si el proxy esta corriendo, el cambio se aplica solo en unos segundos
echo (recarga automatica en segundo plano), sin necesidad de reiniciarlo.
echo Tambien lo podes administrar (agregar o quitar) desde el dashboard:
echo %DASHBOARD_URL%
pause
goto menu

:bloquear
echo.
set /p NUEVO_DOMINIO="Dominio a bloquear siempre (podes pegar la URL entera): "
if "%NUEVO_DOMINIO%"=="" (
    echo No ingresaste ningun dominio.
    pause
    goto menu
)
"%PYTHON%" scripts\agregar_dominio.py negra "%NUEVO_DOMINIO%"
echo.
echo Si el proxy esta corriendo, el cambio se aplica solo en unos segundos
echo (recarga automatica en segundo plano), sin necesidad de reiniciarlo.
pause
goto menu

:borrar_cache
echo.
echo Esto borra el cache de reputacion de IPs (AbuseIPDB), tanto en memoria
echo como en disco (data\ip_reputation_cache.db). La proxima vez que se
echo consulte una IP, se le vuelve a preguntar a la API en vez de usar un
echo resultado guardado.
set /p CONFIRMA="Confirmar? (s/n): "
if /i not "%CONFIRMA%"=="s" (
    echo Cancelado.
    goto menu
)
echo.
echo Intentando borrarlo en caliente (proxy corriendo)...
powershell -NoProfile -Command "[System.Net.WebRequest]::DefaultWebProxy = $null; try { Invoke-WebRequest -Uri '%DASHBOARD_URL%clear-cache' -UseBasicParsing -TimeoutSec 3 | Out-Null; Write-Host '  OK: cache borrado.' } catch { Write-Host '  El proxy no parece estar corriendo, no se pudo borrar en caliente.'; exit 1 }"
if %errorlevel% neq 0 (
    echo.
    echo Inicia el proxy primero (opcion 1) si queres borrar el cache al
    echo instante, o dejalo asi: el cache en disco no crece indefinidamente
    echo y las entradas viejas van a volver a consultarse solas cuando venzan.
)
pause
goto menu

:salir
endlocal
exit /b 0
