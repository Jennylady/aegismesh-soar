@echo off
setlocal
REM Wazuh passes ONE JSON line via STDIN. The script reads it, no shell commands from payload.
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0aegismesh-soar-proof.ps1"
exit /b %ERRORLEVEL%
