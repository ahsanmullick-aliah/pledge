@echo off
rem Shared by "2 - Quick check" and "3 - Full paper experiments". Argument: quick or full.
setlocal
cd /d "%~dp0.."
chcp 65001 >nul
set PYTHONUTF8=1
set MODE=%1
if not exist "tools\python\python.exe" goto :nosetup
call :hasdocker
if "%DOCKER%"=="1" goto :docker

:native
echo.
echo  Running the %MODE% experiments on Windows. The Hyperledger Fabric
echo  experiments need Docker Desktop and are skipped; the report says so.
echo.
set PYTHONPATH=%CD%
"tools\python\python.exe" reproduce.py %MODE%
goto :open

:docker
echo.
echo  Docker Desktop is running: all %MODE% experiments, including Hyperledger
echo  Fabric, run in the Linux image, as in the paper.
echo.
docker image inspect pledge-artifact >nul 2>&1
if errorlevel 1 docker build -t pledge-artifact .
if errorlevel 1 goto :native
if not exist results mkdir results
docker run --rm -v "%CD%\results:/pledge/results" pledge-artifact %MODE%

:open
call "%~dp0..\4 - Open the latest report.bat" nopause
echo.
pause
exit /b 0

:nosetup
echo Run "1 - Setup" first.
pause
exit /b 1

:hasdocker
set DOCKER=0
where docker >nul 2>&1
if errorlevel 1 exit /b 0
docker info >nul 2>&1
if errorlevel 1 exit /b 0
set DOCKER=1
exit /b 0
