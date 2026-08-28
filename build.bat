@echo off
setlocal enabledelayedexpansion

:: Find Visual Studio via vswhere
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
    echo [-] vswhere.exe not found. Install Visual Studio Build Tools.
    exit /b 1
)

for /f "usebackq delims=" %%v in (`"%VSWHERE%" -latest -products * -property installationPath`) do set "VSROOT=%%v"
for /f "usebackq delims=" %%v in (`"%VSWHERE%" -latest -products * -property installationVersion`) do set "VSVER=%%v"

if not defined VSROOT (
    echo [-] Visual Studio installation not found.
    exit /b 1
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
    exit /b 1
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
    exit /b 1
)

:: Find rc.exe (Windows SDK)
set "RC_EXE=C:\Program Files (x86)\Windows Kits\10\bin\%WINSDK%\x64\rc.exe"
if not exist "%RC_EXE%" (
    echo [-] rc.exe not found in Windows SDK
    exit /b 1
)

"%RC_EXE%" /nologo /fo "%OUTDIR%\version.res" "%SRCDIR%version.rc"
if errorlevel 1 (
    echo [-] Resource compile failed
    exit /b 1
)

"%LINK_EXE%" /DLL /NOLOGO /OUT:"%OUTDIR%\version.dll" "%OUTDIR%\version_hook.obj" "%OUTDIR%\version.res" bcrypt.lib user32.lib advapi32.lib ntdll.lib
if errorlevel 1 (
    echo [-] Link failed
    exit /b 1
)

del "%OUTDIR%\version_hook.obj" 2>nul
del "%OUTDIR%\version.exp" 2>nul
del "%OUTDIR%\version.lib" 2>nul
del "%OUTDIR%\version.res" 2>nul

echo [+] Built: %OUTDIR%\version.dll
