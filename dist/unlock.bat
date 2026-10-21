@echo off
setlocal enabledelayedexpansion
title Sandboxie-Plus Unlocker

:: ===== Admin check =====
:: net session needs the Server service, so fall back to a plain admin probe.
net session >nul 2>&1
if %errorlevel% neq 0 fltmc >nul 2>&1
if errorlevel 1 (
    echo [^^!] Administrator rights required.
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
    echo [^^!] Sandboxie-Plus installation not found.
    echo.
    pause
    exit /b 1
)

if not exist "%DLL_SRC%" (
    echo [^^!] version.dll not found next to unlock.bat.
    echo     If you cloned the repo, run _build.bat in the repo root to build it.
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
set "choice="
set /p "choice=Select option [1-6]: "
if not defined choice goto end

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
    :: put the UI the user already had back
    start "" "%SBIE_DIR%\SandMan.exe"
    pause
    goto menu
)

echo    Copied version.dll to %SBIE_DIR%
echo.

:: A surviving DLL from an interrupted removal may be in safe mode -
:: a fresh install re-arms the unlocker
reg add "HKCU\SOFTWARE\sandboxie_unlocker" /v fail_count /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\SOFTWARE\sandboxie_unlocker" /v attempt_active /t REG_DWORD /d 0 /f >nul 2>&1

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

:: A missing version.dll is not "nothing to do": an earlier session may
:: have left keypair.dat, Certificate.dat and moved-aside vendor .sig
:: files.  Without cleanup the next boot shows the certificate/signature
:: dialogs and no installed DLL is left to put them back.  The kernel
:: patch itself dies on reboot.
if exist "%SBIE_DIR%\version.dll" goto :remove_run
if exist "%SBIE_DIR%\*.sig.vendor" goto :remove_stray
if exist "%SBIE_DIR%\keypair.dat" goto :remove_stray
echo    version.dll not found - hook is not installed.
echo.
pause
goto menu

:remove_stray
echo    version.dll is gone, but files from an earlier hook remain.
:: The shadows were moved aside by the hook, so the names are ours; the
:: vendor bytes cannot be re-verified without the DLL - a corrupt one is
:: no worse than the mismatched .sig it replaces.
for %%f in ("%SBIE_DIR%\*.sig.vendor") do move /Y "%%f" "%%~dpnf" >nul 2>&1
if exist "%SBIE_DIR%\keypair.dat" del /f /q "%SBIE_DIR%\Certificate.dat" >nul 2>&1
del /f /q "%SBIE_DIR%\keypair.dat" >nul 2>&1
del /f /q "%SBIE_DIR%\unlock.boot" >nul 2>&1
del /f /q "%SBIE_DIR%\version_hook.log" >nul 2>&1
del /f /q "%SBIE_DIR%\version_hook.old.log" >nul 2>&1
reg delete "HKCU\SOFTWARE\sandboxie_unlocker" /f >nul 2>&1
echo    Vendor .sig files renamed back, generated files removed.
echo    Reboot to drop a kernel patch left by the previous session.
echo    If SandMan still reports an invalid signature, run the
echo    Sandboxie-Plus installer once ^(repair^).
echo.
pause
goto menu

:remove_run
:: === Staging artifacts need the stop sequence above ===
:: A live DLL may be between writing the temp driver and loading it;
:: deleting the file inside that window breaks the load.  After the
:: stop sequence no unlock thread is running.

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
if "!svc_stopped!"=="1" (
    echo    SbieSvc stopped.
) else (
    echo    [-] SbieSvc did not reach STOPPED state in time - continuing.
)

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

:: === Clean up staging artifacts from previous runs ===
:: Temp driver files (locked ones are skipped; they are retried by the
:: DLL on its next start and after reboot)
del /f /q "%WINDIR%\Temp\sbie_unlock_*.sys" >nul 2>&1

:: Stale per-pid driver services ("sbie_unlock_<pid>").  Deleting a
:: service for a RUNNING driver does not unload the mapped image
:: (mark-for-delete), so this is safe.
for /f "tokens=2" %%s in ('sc query type^=^ driver state^=^ all ^| findstr /c:"SERVICE_NAME: sbie_unlock"') do sc delete "%%s" >nul 2>&1

:: Restore the vendor .sig files through the DLL: it owns the signature
:: checks and puts back exactly what it moved aside at unlock time.  This
:: runs BEFORE version.dll is deleted - the DLL is the tool doing it.
set "sig_failed=0"
if not exist "%SBIE_DIR%\version.dll" goto :sig_restore_broken
echo    Restoring original .sig files...
del /f /q "%SBIE_DIR%\sig_restore.status" >nul 2>&1
rundll32 "%SBIE_DIR%\version.dll",RestoreVendorSigs
set "SIG_STATUS="
if exist "%SBIE_DIR%\sig_restore.status" set /p SIG_STATUS=<"%SBIE_DIR%\sig_restore.status"
del /f /q "%SBIE_DIR%\sig_restore.status" >nul 2>&1
if not defined SIG_STATUS goto :sig_restore_broken
echo    !SIG_STATUS!
echo !SIG_STATUS! | find "failed=0" >nul
if errorlevel 1 goto :sig_restore_broken
goto :sig_restore_done

:sig_restore_broken
set "sig_failed=1"
echo    [^^!] NOT all vendor signatures were restored.
echo        Run the Sandboxie-Plus installer once ^(repair^) to bring
echo        the vendor files back.
if "!drv_stopped!"=="0" (
    echo        Do NOT start SandMan before the reboot either - the running
    echo        driver still holds the hook's key.
)
:sig_restore_done

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
    echo        Close all Sandboxie processes, reboot, and run Remove Hook again.
)


:: Clean up generated files.  Certificate.dat is only ours when the hook
:: generated a keypair next to it - a certificate the user installed
:: themselves (a paid licence) must survive Remove Hook.
if exist "%SBIE_DIR%\keypair.dat" del /f /q "%SBIE_DIR%\Certificate.dat" >nul 2>&1
del /f /q "%SBIE_DIR%\keypair.dat" >nul 2>&1
del /f /q "%SBIE_DIR%\unlock.boot" >nul 2>&1
del /f /q "%SBIE_DIR%\version_hook.log"  >nul 2>&1
del /f /q "%SBIE_DIR%\version_hook.old.log" >nul 2>&1
:: sig_backup/ belongs to the older copy-based policy and is never used now.
rmdir /s /q "%SBIE_DIR%\sig_backup" >nul 2>&1

:: Reset safe-fail state
reg delete "HKCU\SOFTWARE\sandboxie_unlocker" /f >nul 2>&1
echo    Reset safe-fail state

:: Code Integrity keeps a per-file verdict from the patched load: after the
:: driver has been unloaded, StartService fails with 577 (ERROR_INVALID_
:: IMAGE_HASH) until the file is replaced.  Writing the same bytes back
:: gives the file a new id and clears that verdict - exactly what the
:: Sandboxie installer's repair does, without reinstalling anything.
if "!drv_stopped!"=="1" (
    copy /Y "%SBIE_DIR%\SbieDrv.sys" "%SBIE_DIR%\SbieDrv.sys.new" >nul 2>&1
    if errorlevel 1 (
        set "reboot_required=1"
        echo    [-] Cannot stage SbieDrv.sys - the driver is still loaded.
    ) else (
        move /Y "%SBIE_DIR%\SbieDrv.sys.new" "%SBIE_DIR%\SbieDrv.sys" >nul 2>&1
        if errorlevel 1 (
            del /f /q "%SBIE_DIR%\SbieDrv.sys.new" >nul 2>&1
            set "reboot_required=1"
            echo    [-] Cannot replace SbieDrv.sys - the driver is still loaded.
        ) else (
            echo    SbieDrv.sys rewritten ^(Code Integrity verdict cleared^).
        )
    )
)

echo.

:: === Restart or reboot depending on driver state ===
if "!reboot_required!"=="0" (
    echo    Restarting Sandboxie-Plus with original key...
    sc.exe start SbieSvc >nul 2>&1
    timeout /t 2 /nobreak >nul
    rem The rewrite above clears the Code Integrity verdict in almost every
    rem case; if the driver still refuses to start, only a reboot or the
    rem installer can help - say so instead of leaving a dead install.
    sc.exe query SbieDrv 2>nul | find "RUNNING" >nul 2>&1
    if errorlevel 1 (
        if exist "%KMDUTIL%" "%KMDUTIL%" start SbieDrv >nul 2>&1
        timeout /t 2 /nobreak >nul
        sc.exe query SbieDrv 2>nul | find "RUNNING" >nul 2>&1
    )
    if errorlevel 1 (
        set "reboot_required=1"
        echo.
        echo    [^^!] SbieDrv did not start again - Windows Code Integrity refused it.
        echo        Reboot, then start SandMan.  If it still fails, run the
        echo        Sandboxie-Plus installer once ^(repair^).
        echo.
    ) else (
        if "!sig_failed!"=="1" (
            echo.
            echo    [^^!] SandMan was NOT started: some .sig files are still ours.
            echo        Run the Sandboxie-Plus installer once ^(repair^), then start SandMan.
        ) else (
            start "" "%SBIE_DIR%\SandMan.exe"
            echo [+] Hook removed. SandMan restarted.
        )
    )
) else (
    echo    [^^!] REBOOT REQUIRED
    if not "!drv_stopped!"=="1" (
        echo    SbieDrv could not be unloaded and will unload on reboot.
        echo    Do NOT start SandMan before the reboot: the running driver
        echo    still holds the hook's key and SandMan would report an
        echo    invalid signature.
    )
    if "!dll_locked!"=="1" (
        echo    version.dll is still locked - after reboot, run Remove Hook again to delete it.
    )
    if "!sig_failed!"=="1" (
        echo    Original .sig files were NOT fully restored - run the
        echo    installer repair before using Sandboxie again.
    ) else (
        echo    Original .sig files have been restored.
    )
    if "!sig_failed!"=="1" (
        echo    After reboot, run the installer repair, then SandMan works normally.
    ) else (
        echo    After reboot, Sandboxie-Plus works normally.
    )
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
if errorlevel 1 (
    echo.
    echo [-] Failed to update the registry - change NOT applied.
    echo     Run this script as administrator and check AV / policy interference.
    echo.
    pause
    goto menu
)
echo.
echo [+] VulnerableDriverBlocklistEnable=0 set.
echo     This allows the embedded Dell-signed helper driver
echo     (dbutil_2_3.sys) to load on systems where the Microsoft
echo     vulnerable-driver blocklist would refuse it.
echo.
echo [^^!] A REBOOT is required for the change to take effect.
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
if errorlevel 1 (
    echo.
    echo [-] Failed to update the registry - change NOT applied.
    echo     Run this script as administrator and check AV / policy interference.
    echo.
    pause
    goto menu
)
echo.
echo [+] VulnerableDriverBlocklistEnable=1 (default state restored).
echo     A REBOOT is required for the change to take effect.
echo.
pause
goto menu

:end
exit /b 0
