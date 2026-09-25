@echo off
title CyberSOC Shield - Web Monitoring Platform
cd /d "%~dp0"
echo ==================================================================
echo   CyberSOC Shield Web Monitoring Platform
echo ==================================================================

netstat -ano | findstr ":5050" | findstr "LISTENING" >nul
if %errorlevel% equ 0 (
    echo [*] CyberSOC Shield server is already running on port 5050!
    echo [*] Opening dashboard in default web browser...
    start http://localhost:5050
    exit /b 0
)

echo [*] Launching CyberSOC Shield Telemetry Server on Port 5050...
start http://localhost:5050
python web\server.py
if %errorlevel% neq 0 (
    echo [-] Server encountered an error. Press any key to exit.
    pause >nul
)
