@echo off
setlocal
cd /d "%~dp0"
for /f "delims=" %%d in ('dir /b /ad /o-d results 2^>nul') do (
  if exist "results\%%d\REPORT.html" (
    echo Opening results\%%d\REPORT.html
    start "" "results\%%d\REPORT.html"
    goto :eof
  )
)
echo No report yet: run "2 - Quick check" or "3 - Full paper experiments" first.
if not "%1"=="nopause" pause
