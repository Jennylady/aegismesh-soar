@echo off
setlocal
REM Fixed Wazuh AR entrypoint; no shell commands or user-controlled script names.
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0aegismesh-soar-ad.ps1"
exit /b %ERRORLEVEL%
