@echo off
title Wazuh SOC Lab - Master Runner Console
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0run_project.ps1"
pause
