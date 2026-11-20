@echo off
setlocal
title Vulnora
cd /d "%~dp0"
if "%PORT%"=="" set PORT=8787

echo.
echo  ==========================================
echo    Vulnora  -  starting...
echo  ==========================================
echo.

where node >nul 2>nul
if errorlevel 1 (
  echo  [!] Node.js was not found. It is needed to run the dashboard server.
  echo      Install it from https://nodejs.org  ^(LTS^) or run:
  echo        winget install OpenJS.NodeJS.LTS
  echo      Then double-click start.bat again.
  echo.
  pause
  exit /b 1
)

where docker >nul 2>nul
if errorlevel 1 (
  where trivy >nul 2>nul
  if errorlevel 1 (
    echo  [!] Neither Docker nor Trivy was found. The dashboard will open,
    echo      but scans need Docker Desktop ^(recommended^) or a Trivy install.
    echo.
  )
) else (
  docker info >nul 2>nul
  if errorlevel 1 (
    echo  [!] Docker is installed but not running. Start Docker Desktop to scan.
    echo.
  ) else (
    docker image inspect aquasec/trivy:latest >nul 2>nul
    if errorlevel 1 (
      echo  [i] Downloading the Trivy image ^(first run only^)...
      docker pull aquasec/trivy:latest
      echo.
    )
  )
)

echo  Opening http://127.0.0.1:%PORT%  ^(keep this window open; Ctrl+C to stop^)
start "" cmd /c "timeout /t 2 /nobreak >nul & start "" http://127.0.0.1:%PORT%"
node server.js
echo.
echo  Server stopped.
pause
