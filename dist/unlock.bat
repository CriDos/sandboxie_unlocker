@echo off
setlocal enabledelayedexpansion
chcp 1251 >nul 2>&1
title Sandboxie-Plus Unlocker

:: ===== Admin check =====
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Administrator rights required.
    echo     Right-click this file and select "Run as administrator".
    echo.
    pause
    exit /b 1
)

:: ===== Resolve paths =====
set "SCRIPT_DIR=%~dp0"
set "DLL_SRC=%SCRIPT_DIR%version.dll"

:: ===== Find Sandboxie =====
set "SBIE_DIR="
for /f "tokens=2*" %%a in ('reg query "HKLM\SOFTWARE\Sandboxie-Plus" /v InstallPath 2^>nul') do set "SBIE_DIR=%%b"
if not defined SBIE_DIR (
    for /f "tokens=2*" %%a in ('reg query "HKLM\SOFTWARE\Xanasoft\Sandboxie-Plus" /v InstallPath 2^>nul') do set "SBIE_DIR=%%b"
)
if not defined SBIE_DIR (
    if exist "%ProgramFiles%\Sandboxie-Plus" set "SBIE_DIR=%ProgramFiles%\Sandboxie-Plus"
)
if not defined SBIE_DIR (
    if exist "%ProgramFiles(x86)%\Sandboxie-Plus" set "SBIE_DIR=%ProgramFiles(x86)%\Sandboxie-Plus"
)

if not defined SBIE_DIR (
    echo [!] Sandboxie-Plus installation not found.
    echo.
    pause
    exit /b 1
)

if not exist "%DLL_SRC%" (
    echo [!] version.dll not found next to unlock.bat.
    echo     If you cloned the repo, run build.bat in the repo root to build it.
    echo.
    pause
    exit /b 1
)

:: ===== KmdUtil helper =====
set "KMDUTIL=%SBIE_DIR%\KmdUtil.exe"

:menu
cls
echo ============================================================
echo                SANDBOXIE-PLUS UNLOCKER
echo ============================================================
echo.
echo   Install dir: %SBIE_DIR%
echo.
echo   [1]  Install Hook
echo        Copy version.dll, restart SandMan
echo.
echo   [2]  Remove Hook
echo        Delete version.dll, reset crash counter, restart SandMan
echo.
echo   [3]  Build DLL
echo        Compile version.dll from source (requires VS Build Tools)
echo.
echo   [4]  Reset Crash Counter
echo        Clear safe-mode lockout without removing the hook
echo.
echo   [5]  Exit
echo.
echo ------------------------------------------------------------
set /p "choice=Select option [1-5]: "

if "%choice%"=="1" goto install
if "%choice%"=="2" goto remove
if "%choice%"=="3" goto build
if "%choice%"=="4" goto reset
if "%choice%"=="5" goto end

echo Invalid choice.
timeout /t 2 >nul
goto menu

:install
cls
echo ============================================================
echo                    INSTALL HOOK
echo ============================================================
echo.

:: Stop SandMan only — keep SbieSvc running (it loaded SbieDrv with original key)
:: Our DLL will patch the key and re-sign .sig files when SandMan restarts
taskkill /IM SandMan.exe  /F >nul 2>&1
taskkill /IM SbieCtrl.exe /F >nul 2>&1
timeout /t 2 /nobreak >nul

copy /Y "%DLL_SRC%" "%SBIE_DIR%\version.dll" >nul 2>&1
if errorlevel 1 (
    echo [-] Failed to copy version.dll — file may be locked.
    echo     Close all Sandboxie processes and try again.
    pause
    goto menu
)

echo    Copied version.dll to %SBIE_DIR%
echo.

:: SbieSvc is still running — just launch SandMan
start "" "%SBIE_DIR%\SandMan.exe"
timeout /t 3 /nobreak >nul

echo [+] Hook installed. SandMan restarted.
echo    Check About dialog for certificate status.
echo.
pause
goto menu

:remove
cls
echo ============================================================
echo                    REMOVE HOOK
echo ============================================================
echo.

if not exist "%SBIE_DIR%\version.dll" (
    echo    version.dll not found — hook is not installed.
    echo.
    pause
    goto menu
)

:: === Full stop sequence (mirrors the official installer) ===

:: Step 1: Kill GUI processes
echo    Stopping processes...
taskkill /IM SandMan.exe  /F >nul 2>&1
taskkill /IM SbieCtrl.exe /F >nul 2>&1
taskkill /IM Start.exe    /F >nul 2>&1
taskkill /IM SbieDML.exe  /F >nul 2>&1

:: Step 2: Kill sandboxed processes (KmdUtil scandll_silent)
if exist "%KMDUTIL%" (
    "%KMDUTIL%" scandll_silent >nul 2>&1
    timeout /t 3 /nobreak >nul
)

:: Step 3: Stop SbieSvc and wait for STOPPED
sc.exe stop SbieSvc >nul 2>&1
set "svc_stopped=0"
for /l %%i in (1,1,15) do (
    if "!svc_stopped!"=="1" goto :svc_done
    sc.exe query SbieSvc 2>nul | find "STOPPED" >nul 2>&1
    if not errorlevel 1 (
        set "svc_stopped=1"
    ) else (
        timeout /t 1 /nobreak >nul
    )
)
:svc_done
echo    SbieSvc stopped.

:: Step 4: Unload SbieDrv via KmdUtil (needs SbieSvc fully stopped so
:: Api_UseCount == 1, otherwise driver returns STATUS_CONNECTION_IN_USE)
if exist "%KMDUTIL%" (
    "%KMDUTIL%" stop SbieDrv >nul 2>&1
)

:: Step 5: Wait for SbieDrv to actually unload (SCM state update is async)
set "drv_stopped=0"
for /l %%i in (1,1,10) do (
    if "!drv_stopped!"=="1" goto :drv_done
    sc.exe query SbieDrv 2>nul | find "STOPPED" >nul 2>&1
    if not errorlevel 1 (
        set "drv_stopped=1"
    ) else (
        timeout /t 1 /nobreak >nul
    )
)
:drv_done

if "!drv_stopped!"=="1" (
    echo    SbieDrv unloaded.
) else (
    echo    [-] SbieDrv still loaded — will require reboot.
)

:: === Delete version.dll with retry ===
set "DLL_TARGET=%SBIE_DIR%\version.dll"
set "deleted=0"
for /l %%i in (1,1,5) do (
    if "!deleted!"=="1" goto :del_done
    if not exist "!DLL_TARGET!" (
        set "deleted=1"
        goto :del_done
    )
    del /f /q "!DLL_TARGET!" >nul 2>&1
    if not exist "!DLL_TARGET!" (
        set "deleted=1"
        goto :del_done
    )
    timeout /t 1 /nobreak >nul
)
:del_done

if "!deleted!"=="1" (
    echo    Deleted version.dll
) else (
    echo    [-] Could not delete version.dll — file is still locked.
    echo        Close all Sandboxie processes and try again.
    echo.
    pause
    goto menu
)

:: Restore original .sig files from backup
if exist "%SBIE_DIR%\sig_backup" (
    echo    Restoring original .sig files...
    copy /Y "%SBIE_DIR%\sig_backup\*.sig" "%SBIE_DIR%\" >nul 2>&1
    rmdir /s /q "%SBIE_DIR%\sig_backup" >nul 2>&1
    echo    Done.
)

:: Clean up generated files
del /f /q "%SBIE_DIR%\Certificate.dat"   >nul 2>&1
del /f /q "%SBIE_DIR%\keypair.dat"       >nul 2>&1
del /f /q "%SBIE_DIR%\version_hook.log"  >nul 2>&1

:: Reset crash counter
reg delete "HKCU\SOFTWARE\sandboxie_unlocker" /f >nul 2>&1
echo    Reset crash counter

echo.

:: === Restart or reboot depending on driver state ===
if "!drv_stopped!"=="1" (
    echo    Restarting Sandboxie-Plus with original key...
    sc.exe start SbieSvc >nul 2>&1
    timeout /t 2 /nobreak >nul
    start "" "%SBIE_DIR%\SandMan.exe"
    echo [+] Hook removed. SandMan restarted.
) else (
    echo    [!] REBOOT REQUIRED
    echo    SbieDrv could not be unloaded and still has the
    echo    patched key in memory. It will unload on reboot.
    echo    Original .sig files have been restored.
    echo    After reboot, Sandboxie-Plus works normally.
    echo.
    echo [+] Hook removed. Please reboot to complete.
)
echo.
pause
goto menu

:build
cls
echo ============================================================
echo                    BUILD DLL
echo ============================================================
echo.
:: build.bat is in the repo root (parent of dist\)
set "REPO_ROOT=%SCRIPT_DIR%.."
if not exist "%REPO_ROOT%\build.bat" (
    echo [-] build.bat not found. This option only works from a repo clone.
    echo.
    pause
    goto menu
)
call "%REPO_ROOT%\build.bat"
if exist "%REPO_ROOT%\dist\version.dll" (
    echo [+] Built version.dll in dist\
) else (
    echo [-] Build may have failed — check output above.
)
echo.
pause
goto menu

:reset
cls
echo ============================================================
echo                RESET CRASH COUNTER
echo ============================================================
echo.
reg delete "HKCU\SOFTWARE\sandboxie_unlocker" /f >nul 2>&1
echo [+] Crash counter reset. Safe-mode lockout cleared.
echo.
pause
goto menu

:end
exit /b 0
