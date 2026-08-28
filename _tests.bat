@echo off
setlocal enabledelayedexpansion

:: Tests runner: builds the DLL (if needed), the two test binaries,
:: and runs them from the repo root.  Exit code is non-zero when any
:: test fails.  Safe on machines without Sandboxie: kernel paths are
:: never exercised.
::
:: Started WITHOUT arguments (e.g. double-click) the console stays open
:: after the run so the results can be read.  Pass any argument (CI)
:: to exit immediately.

set "REPO=%~dp0."
set "OUT=%TEMP%\sbie_tests"
set "RC=0"
if not exist "%OUT%" mkdir "%OUT%"

:: ===== Toolchain (same discovery as _build.bat) =====
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
    echo [-] vswhere.exe not found. Install Visual Studio Build Tools.
    set "RC=1"
    goto done
)
for /f "usebackq delims=" %%v in (`"%VSWHERE%" -latest -products * -property installationPath`) do set "VSROOT=%%v"
if not defined VSROOT (
    echo [-] Visual Studio installation not found.
    set "RC=1"
    goto done
)
for /f "delims=" %%v in ('dir /b "%VSROOT%\VC\Tools\MSVC"') do set "MSVC_VER=%%v"
set "MSVC=%VSROOT%\VC\Tools\MSVC\%MSVC_VER%"
set "WINSDK="
for /f "delims=" %%k in ('dir /b /ad "C:\Program Files (x86)\Windows Kits\10\Include\10.*"') do (
    if exist "C:\Program Files (x86)\Windows Kits\10\Include\%%k\ucrt\stdlib.h" set "WINSDK=%%k"
)
if not defined WINSDK (
    echo [-] No complete Windows SDK found ^(with ucrt headers^).
    set "RC=1"
    goto done
)
set "CL_EXE=%MSVC%\bin\Hostx64\x64\cl.exe"
set "INCLUDE=%MSVC%\include;C:\Program Files (x86)\Windows Kits\10\Include\%WINSDK%\ucrt;C:\Program Files (x86)\Windows Kits\10\Include\%WINSDK%\um;C:\Program Files (x86)\Windows Kits\10\Include\%WINSDK%\shared"
set "LIB=%MSVC%\lib\x64;C:\Program Files (x86)\Windows Kits\10\Lib\%WINSDK%\ucrt\x64;C:\Program Files (x86)\Windows Kits\10\Lib\%WINSDK%\um\x64"

:: ===== Build the DLL under test if missing =====
if not exist "%REPO%\dist\version.dll" (
    echo [*] dist\version.dll missing - building...
    call "%REPO%\_build.bat" ci
    if errorlevel 1 (
        set "RC=1"
        goto done
    )
)

:: ===== Build test binaries =====
echo [*] Building selftest...
"%CL_EXE%" /nologo /W3 /O2 /MT "%REPO%\tests\selftest.c" bcrypt.lib advapi32.lib user32.lib /Fo"%OUT%\selftest.obj" /Fe"%OUT%\sbie_selftest.exe"
if errorlevel 1 (
    echo [-] selftest build failed
    set "RC=1"
    goto done
)

echo [*] Building proxytest...
"%CL_EXE%" /nologo /W3 /O2 /MT "%REPO%\tests\proxytest.c" user32.lib advapi32.lib /Fo"%OUT%\proxytest.obj" /Fe"%OUT%\sbie_proxytest.exe"
if errorlevel 1 (
    echo [-] proxytest build failed
    set "RC=1"
    goto done
)

:: ===== Run =====
pushd "%REPO%"
echo.
echo [*] Running selftest...
"%OUT%\sbie_selftest.exe" "dist\version.dll"
if errorlevel 1 set "RC=1"
echo.
echo [*] Running proxytest...
"%OUT%\sbie_proxytest.exe" "dist\version.dll"
if errorlevel 1 set "RC=1"
popd

:done
if not "%RC%"=="0" echo [-] TEST SUITE FAILED
if "%RC%"=="0" echo [+] TEST SUITE PASSED

:: Interactive run (no arguments): keep the console open.
if "%~1"=="" pause
exit /b %RC%

