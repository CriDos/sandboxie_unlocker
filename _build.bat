@echo off
setlocal enabledelayedexpansion

:: MSVC build script - compiles version.dll into dist\.
:: Started WITHOUT arguments (e.g. double-click) the console stays open
:: after the run so errors/results can be read.  Pass any argument (CI,
:: _tests.bat) to exit immediately.

set "RC=0"

:: Find Visual Studio via vswhere
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
    echo [-] vswhere.exe not found. Install Visual Studio Build Tools.
    set "RC=1"
    goto done
)

for /f "usebackq delims=" %%v in (`"%VSWHERE%" -latest -products * -property installationPath`) do set "VSROOT=%%v"
for /f "usebackq delims=" %%v in (`"%VSWHERE%" -latest -products * -property installationVersion`) do set "VSVER=%%v"

if not defined VSROOT (
    echo [-] Visual Studio installation not found.
    set "RC=1"
    goto done
)

:: Find MSVC toolchain version
for /f "delims=" %%v in ('dir /b "%VSROOT%\VC\Tools\MSVC"') do set "MSVC_VER=%%v"
set "MSVC=%VSROOT%\VC\Tools\MSVC\%MSVC_VER%"

:: Find Windows SDK (skip non-version folders like "wdf" and incomplete
:: driver-only kits that lack the ucrt headers needed for user-mode builds)
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
set "LINK_EXE=%MSVC%\bin\Hostx64\x64\link.exe"
set "INCLUDE=%MSVC%\include;C:\Program Files (x86)\Windows Kits\10\Include\%WINSDK%\ucrt;C:\Program Files (x86)\Windows Kits\10\Include\%WINSDK%\um;C:\Program Files (x86)\Windows Kits\10\Include\%WINSDK%\shared"
set "LIB=%MSVC%\lib\x64;C:\Program Files (x86)\Windows Kits\10\Lib\%WINSDK%\ucrt\x64;C:\Program Files (x86)\Windows Kits\10\Lib\%WINSDK%\um\x64"

set "SRCDIR=%~dp0src\"
set "OUTDIR=%~dp0dist"
if not exist "%OUTDIR%" mkdir "%OUTDIR%"

echo [*] VS: %VSVER% (%MSVC_VER%)
echo [*] WinSDK: %WINSDK%
echo [*] Building version.dll...

"%CL_EXE%" /c /O2 /MT /W4 /nologo "%SRCDIR%version_hook.c" /Fo:"%OUTDIR%\version_hook.obj"
if errorlevel 1 (
    echo [-] Compile failed
    set "RC=1"
    goto done
)

:: Find rc.exe (Windows SDK)
set "RC_EXE=C:\Program Files (x86)\Windows Kits\10\bin\%WINSDK%\x64\rc.exe"
if not exist "%RC_EXE%" (
    echo [-] rc.exe not found in Windows SDK
    set "RC=1"
    goto done
)

"%RC_EXE%" /nologo /fo "%OUTDIR%\version.res" "%SRCDIR%version.rc"
if errorlevel 1 (
    echo [-] Resource compile failed
    set "RC=1"
    goto done
)

"%LINK_EXE%" /DLL /NOLOGO /OUT:"%OUTDIR%\version.dll" "%OUTDIR%\version_hook.obj" "%OUTDIR%\version.res" bcrypt.lib user32.lib advapi32.lib ntdll.lib
if errorlevel 1 (
    echo [-] Link failed
    set "RC=1"
    goto done
)

del "%OUTDIR%\version_hook.obj" 2>nul
del "%OUTDIR%\version.exp" 2>nul
del "%OUTDIR%\version.lib" 2>nul
del "%OUTDIR%\version.res" 2>nul

echo [+] Built: %OUTDIR%\version.dll

:done
if not "%RC%"=="0" echo [-] BUILD FAILED
if "%RC%"=="0" echo [+] BUILD OK

:: Interactive run (no arguments): keep the console open.
if "%~1"=="" pause
exit /b %RC%
