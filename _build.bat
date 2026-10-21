@echo off
setlocal enabledelayedexpansion

:: MSVC build script - compiles version.dll into dist\.
:: Started WITHOUT arguments (e.g. double-click) the console stays open
:: after the run so errors/results can be read.  Pass any argument (CI,
:: _tests.bat) to exit immediately.
::
:: Toolchain discovery lives in _msvc_env.bat (shared with _tests.bat and
:: _ptelive.bat), so all three scripts build with the same flags.

set "RC=0"

call "%~dp0_msvc_env.bat"
if not "%ENV_RC%"=="0" (
    set "RC=1"
    goto done
)

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

"%LINK_EXE%" /DLL /NOLOGO /OUT:"%OUTDIR%\version.dll" "%OUTDIR%\version_hook.obj" "%OUTDIR%\version.res" bcrypt.lib user32.lib advapi32.lib ntdll.lib psapi.lib
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
