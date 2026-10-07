@echo off
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0NetworkIsolation.ps1" -Action Menu
exit /b %errorlevel%
