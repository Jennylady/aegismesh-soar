@echo off
setlocal
REM Wazuh supplies one JSON record on standard input. No input is executed as shell code.
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0aegismesh-soar-proof.ps1"
set "status=%ERRORLEVEL%"
if not "%status%"=="0" (
  REM Keep only the return code, never the incoming payload or credentials.
  >>"%~dp0..\aegismesh-soar-errors.log" echo AEGISMESH-SOAR-PROOF launcher_failed exit_code=%status%
)
exit /b %status%
