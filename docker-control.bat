@echo off
setlocal
title Smart Domain Detector Docker Control
cd /d "%~dp0"

set COMPOSE_PROJECT=smart-domain-detector
set APP_URL=http://localhost:3000

:menu
cls
echo.
echo ============================================
echo   Smart Domain Detector - Docker Control
echo ============================================
echo.
call :check_docker_silent
if errorlevel 1 (
  echo Docker status : Not ready
  echo.
  echo 1. Start Docker stack
  echo 2. Stop Docker stack
  echo 3. Check Docker status
  echo 4. Exit
  echo.
) else (
  call :print_stack_status
  echo.
  echo 1. Start Docker stack
  echo 2. Stop Docker stack
  echo 3. Check Docker status
  echo 4. Exit
  echo.
)

set /p choice=Select an option: 

if "%choice%"=="1" goto start_stack
if "%choice%"=="2" goto stop_stack
if "%choice%"=="3" goto show_status
if "%choice%"=="4" goto end

echo.
echo Invalid option.
pause
goto menu

:check_docker_silent
docker version >nul 2>nul
if errorlevel 1 exit /b 1
docker compose version >nul 2>nul
if errorlevel 1 exit /b 1
exit /b 0

:ensure_docker
call :check_docker_silent
if not errorlevel 1 exit /b 0

echo.
echo Docker is not ready.
echo.
echo If Docker Desktop is installed, this script will try to open it.
echo Wait until Docker says it is running, then continue.
echo.

if exist "%ProgramFiles%\Docker\Docker\Docker Desktop.exe" (
  start "" "%ProgramFiles%\Docker\Docker\Docker Desktop.exe"
) else if exist "%LocalAppData%\Programs\Docker\Docker\Docker Desktop.exe" (
  start "" "%LocalAppData%\Programs\Docker\Docker\Docker Desktop.exe"
) else (
  echo [ERROR] Docker Desktop was not found in the usual locations.
  echo Install/start Docker Desktop, then run this file again.
  pause
  exit /b 1
)

echo Waiting for Docker engine...
set /a waited=0
:wait_loop
timeout /t 3 /nobreak >nul
set /a waited+=3
call :check_docker_silent
if not errorlevel 1 (
  echo Docker is ready.
  exit /b 0
)
if %waited% GEQ 90 (
  echo [ERROR] Docker did not become ready within 90 seconds.
  echo Start Docker Desktop manually and try again.
  pause
  exit /b 1
)
goto wait_loop

:print_stack_status
for /f "delims=" %%i in ('docker compose ps --format json 2^>nul') do set "compose_json=1"
if not defined compose_json (
  echo Docker status : Ready
  echo Stack status  : Not created
  exit /b 0
)

for /f %%i in ('docker compose ps -q 2^>nul ^| find /c /v ""') do set CONTAINER_COUNT=%%i
if "%CONTAINER_COUNT%"=="0" (
  echo Docker status : Ready
  echo Stack status  : Stopped
) else (
  echo Docker status : Ready
  echo Stack status  : Running ^(%CONTAINER_COUNT% container^)
)
set CONTAINER_COUNT=
set compose_json=
exit /b 0

:show_status
cls
echo.
echo ============================================
echo   Docker Status
echo ============================================
echo.
call :ensure_docker
if errorlevel 1 goto menu
call :print_stack_status
echo.
docker compose ps
echo.
pause
goto menu

:start_stack
cls
echo.
echo ============================================
echo   Starting Docker Stack
echo ============================================
echo.
call :ensure_docker
if errorlevel 1 goto menu

echo Building and starting Smart Domain Detector...
docker compose up --build -d
if errorlevel 1 (
  echo.
  echo [ERROR] Docker stack failed to start.
  pause
  goto menu
)

echo.
echo Smart Domain Detector is running.
echo Open: %APP_URL%
echo.
start "" "%APP_URL%"
pause
goto menu

:stop_stack
cls
echo.
echo ============================================
echo   Stopping Docker Stack
echo ============================================
echo.
call :ensure_docker
if errorlevel 1 goto menu

docker compose down
if errorlevel 1 (
  echo.
  echo [ERROR] Docker stack failed to stop cleanly.
  pause
  goto menu
)

echo.
echo Docker stack stopped safely.
pause
goto menu

:end
endlocal
exit /b 0
