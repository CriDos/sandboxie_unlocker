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
echo        Delete version.dll, reset safe-fail state, restart SandMan
echo.
echo   [3]  Reset Safe-Fail State
echo        Clear safe-mode lockout without removing the hook
echo.
echo   [4]  Disable Vulnerable Driver Blocklist
echo        Allow loading of the embedded Dell-signed driver (reboot)
echo.
echo   [5]  Enable Vulnerable Driver Blocklist
echo        Restore the default blocklist state (reboot)
echo.
echo   [6]  Exit
echo.
echo ------------------------------------------------------------
set /p "choice=Select option [1-6]: "

if "%choice%"=="1" goto install
if "%choice%"=="2" goto remove
if "%choice%"=="3" goto reset
if "%choice%"=="4" goto blk_off
if "%choice%"=="5" goto blk_on
if "%choice%"=="6" goto end

echo Invalid choice.
timeout /t 2 >nul
goto menu

:install
cls
echo ============================================================
echo                    INSTALL HOOK
echo ============================================================
echo.

:: Stop SandMan only - keep SbieSvc running (it loaded SbieDrv with original key)
:: Our DLL will patch the key and re-sign .sig files when SandMan restarts
taskkill /IM SandMan.exe  /F >nul 2>&1
taskkill /IM SbieCtrl.exe /F >nul 2>&1
timeout /t 2 /nobreak >nul

copy /Y "%DLL_SRC%" "%SBIE_DIR%\version.dll" >nul 2>&1
if errorlevel 1 (
    echo [-] Failed to copy version.dll - file may be locked.
    echo     Close all Sandboxie processes and try again.
    pause
    goto menu
)

echo    Copied version.dll to %SBIE_DIR%
echo.

:: A surviving DLL from an interrupted removal may be in safe mode -
:: a fresh install re-arms the unlocker
reg add "HKCU\SOFTWARE\sandboxie_unlocker" /v fail_count /t REG_DWORD /d 0 /f >nul 2>&1

:: SbieSvc is still running - just launch SandMan
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

:: === Clean up staging artifacts from previous runs ===
:: Run even when the hook is already gone, so leftovers from earlier
:: versions do not accumulate
:: Temp driver files (locked ones are skipped; they are retried by the
:: DLL on its next start and after reboot)
del /f /q "%WINDIR%\Temp\sbie_unlock_*.sys" >nul 2>&1

:: Stale per-pid driver services.  Deleting a service for a RUNNING
:: driver does not unload the mapped image (mark-for-delete), so this
:: is safe.
for /f "tokens=2" %%s in ('sc query type= driver state= all ^| findstr /c:"SERVICE_NAME: sbie_unlock_"') do sc delete "%%s" >nul 2>&1

if not exist "%SBIE_DIR%\version.dll" (
    echo    version.dll not found - hook is not installed.
    echo.
    pause
    goto menu
)

set "reboot_required=0"
set "dll_locked=0"

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
    set "reboot_required=1"
    echo    [-] SbieDrv still loaded - will require reboot.
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
    set "dll_locked=1"
    set "reboot_required=1"
    echo    [-] Could not delete version.dll - file is still locked.
    echo        A helper driver from an older hook may still be mapped.
    echo        After reboot, run Remove Hook again to finish removal.
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

:: Reset safe-fail state
reg delete "HKCU\SOFTWARE\sandboxie_unlocker" /f >nul 2>&1
echo    Reset safe-fail state

:: Compatibility with hooks installed by v1.0.3 and earlier: the old DLL
:: staged the driver in version.dll:driver, so version.dll can survive
:: the removal while the helper driver is still mapped.  Raise the
:: existing crash counter to the safe-mode threshold - the surviving DLL
:: then acts as a transparent proxy and never loads the driver or
:: re-arms the kernel patch.
if "!dll_locked!"=="1" (
    reg add "HKCU\SOFTWARE\sandboxie_unlocker" /v fail_count /t REG_DWORD /d 3 /f >nul 2>&1
    echo    Raised fail_count - surviving DLL will stay in safe mode.
)

echo.

:: === Restart or reboot depending on driver state ===
if "!reboot_required!"=="0" (
    echo    Restarting Sandboxie-Plus with original key...
    sc.exe start SbieSvc >nul 2>&1
    timeout /t 2 /nobreak >nul
    start "" "%SBIE_DIR%\SandMan.exe"
    echo [+] Hook removed. SandMan restarted.
) else (
    echo    [!] REBOOT REQUIRED
    if not "!drv_stopped!"=="1" (
        echo    SbieDrv could not be unloaded and will unload on reboot.
    )
    if "!dll_locked!"=="1" (
        echo    version.dll is locked by a loaded helper driver.
        echo    After reboot, run Remove Hook again to delete it.
    )
    echo    Original .sig files have been restored.
    echo    After reboot, Sandboxie-Plus works normally.
    echo.
    echo [+] Please reboot to complete removal.
)
echo.
pause
goto menu

:reset
cls
echo ============================================================
echo                RESET SAFE-FAIL STATE
echo ============================================================
echo.
reg delete "HKCU\SOFTWARE\sandboxie_unlocker" /f >nul 2>&1
echo [+] Safe-fail state reset. Safe-mode lockout cleared.
echo.
pause
goto menu

:blk_off
cls
echo ============================================================
echo           DISABLE VULNERABLE DRIVER BLOCKLIST
echo ============================================================
echo.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CI\Config" /v VulnerableDriverBlocklistEnable /t REG_DWORD /d 0 /f
echo.
echo [+] VulnerableDriverBlocklistEnable=0 set.
echo     This allows the embedded Dell-signed helper driver
echo     (dbutil_2_3.sys) to load on systems where the Microsoft
echo     vulnerable-driver blocklist would refuse it.
echo.
echo [!] A REBOOT is required for the change to take effect.
echo     Install Hook right after the reboot.
echo.
pause
goto menu

:blk_on
cls
echo ============================================================
echo            ENABLE VULNERABLE DRIVER BLOCKLIST
echo ============================================================
echo.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CI\Config" /v VulnerableDriverBlocklistEnable /t REG_DWORD /d 1 /f
echo.
echo [+] VulnerableDriverBlocklistEnable=1 (default state restored).
echo     A REBOOT is required for the change to take effect.
echo.
pause
goto menu

:end
exit /b 0
