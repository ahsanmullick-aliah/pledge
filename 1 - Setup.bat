@echo off
setlocal
cd /d "%~dp0"
chcp 65001 >nul
set PYTHONUTF8=1
title PLEDGE - setup
echo.
echo  ===============================================================
echo   PLEDGE artifact - one-time setup
echo   Downloads a private Python, Java 11, HAPI FHIR 5.1.0 and the
echo   MIMIC-IV FHIR demo data into this folder. Nothing is installed
echo   system-wide. Needs an internet connection and about 2 GB.
echo  ===============================================================
echo.
if exist "tools\python\python.exe" goto :packages
echo [1/5] Downloading a private copy of Python 3.12, about 40 MB ...
if not exist tools mkdir tools
curl.exe -L --fail --retry 3 -o "tools\python.tar.gz" "https://github.com/astral-sh/python-build-standalone/releases/download/20250529/cpython-3.12.10%%2B20250529-x86_64-pc-windows-msvc-install_only.tar.gz"
if errorlevel 1 goto :fail
tar.exe -xzf "tools\python.tar.gz" -C tools
if errorlevel 1 goto :fail
del "tools\python.tar.gz"

:packages
echo [2/5] Installing Python packages ...
"tools\python\python.exe" -m pip install --disable-pip-version-check -q -r requirements.txt
if errorlevel 1 goto :fail
echo [3/5] Downloading Java 11, HAPI FHIR and the MIMIC-IV FHIR data ...
"tools\python\python.exe" scripts\fetch.py
if errorlevel 1 goto :fail
echo [4/5] Checking the installation with the unit tests, about a minute ...
set PYTHONPATH=%CD%
"tools\python\python.exe" -m unittest discover -s tests -t .
if errorlevel 1 goto :testfail
echo [5/5] Looking for Docker Desktop, needed only for the Hyperledger Fabric experiments ...
call :hasdocker
if "%DOCKER%"=="1" goto :dockerbuild
echo       Docker Desktop is not running. Everything except the Fabric experiments
echo       will run directly on Windows. To include Fabric later, install Docker
echo       Desktop from https://www.docker.com/products/docker-desktop/ , start it,
echo       and run this setup again.
goto :done

:dockerbuild
echo       Docker found. Building the Linux image with Fabric, 5-15 minutes the first time ...
docker build -t pledge-artifact .
if errorlevel 1 echo       The Docker image could not be built; Fabric experiments will be skipped.

:done
echo.
echo  Setup complete. Next: double-click "2 - Quick check", about 30 minutes,
echo  or "3 - Full paper experiments", several hours.
echo.
pause
exit /b 0

:testfail
echo.
echo  Some unit tests failed. The messages above say which. You can still run the
echo  experiments, but please send the output above to the authors.
pause
exit /b 1

:fail
echo.
echo  Setup failed: see the message above. Check the internet connection and run
echo  "1 - Setup" again; finished downloads are kept.
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
