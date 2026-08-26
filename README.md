# Sandboxie-Plus Unlocker v1.0.5

<p align="center">
  <img src="https://img.shields.io/badge/Windows-11_24H2_x64-0078d6?logo=windows&logoColor=white" alt="Windows 11 24H2 x64" />
  <img src="https://img.shields.io/badge/C-MSVC_2022-555555?logo=c&logoColor=white" alt="C" />
  <img src="https://img.shields.io/github/v/release/CriDos/sandboxie_unlocker?label=Release" alt="Release" />
  <img src="https://img.shields.io/github/actions/workflow/status/CriDos/sandboxie_unlocker/ci.yml?label=CI" alt="CI" />
  <img src="https://img.shields.io/badge/License-MIT-yellow" alt="MIT" />
</p>

> **EDUCATIONAL PURPOSE ONLY.** This project is a reverse-engineering research
> artifact intended solely for educational and security-research use. It
> demonstrates kernel-level ECDSA key replacement, code-signing bypass, and
> driver IOCTL exploitation in a controlled lab environment. Do **not** use
> this to circumvent licensing in any commercial or production deployment.
> The authors take no responsibility for misuse.

Full kernel-level certificate unlock for Sandboxie-Plus **1.17.x–1.18.x** (tested on 1.17.9, 1.18.0 and 1.18.2) via a single `version.dll` proxy. No test-signing, no files needed in the install directory — everything embedded in one DLL (the driver is staged transiently to `%WINDIR%\Temp`).

**Windows x64 only.** The embedded kernel R/W driver (`dbutil_2_3.sys`) is 64-bit, and the kernel module enumeration (`kmod.h`) uses x64-specific struct layouts. 32-bit Windows is not supported. Tested on Windows 11 24H2 (Build 26100).

## How it works

Sandboxie-Plus uses ECDSA P-256 to validate supporter certificates. The public key is hardcoded in `SbieDrv.sys` (`KphpTrustedPublicKey`). Without a valid certificate, security features are enforced by the kernel driver — processes are killed after 5 minutes or terminated immediately.

This tool replaces the public key in the running kernel with a freshly generated keypair, writes a self-signed `Certificate.dat`, and re-signs all `.exe.sig` files so SandMan's integrity check passes.

### Flow

1. `version.dll` placed next to `SandMan.exe` — Windows loads it before SandMan initializes (DLL search order: app directory first)
2. All 17 `version.dll` exports forwarded to real `System32\version.dll` via lazy-resolved function pointers
3. Background thread:
   - Writes embedded kernel driver (`dbutil_2_3.sys`, CVE-2021-21551, Dell-signed) to `%WINDIR%\Temp\sbie_unlock_<pid>.sys` (restrictive DACL — SYSTEM + Administrators only)
   - Loads driver as a service for kernel R/W access
   - Finds `SbieDrv.sys` base in kernel via `NtQuerySystemInformation`
   - Parses `SbieDrv.sys` on disk to find ECDSA key RVA
   - Generates ECDSA P-256 keypair via Windows CNG (`bcrypt.dll`)
   - Overwrites public key in kernel memory
   - Generates `Certificate.dat` (type: ETERNAL, all features)
   - Backs up and re-signs all `.exe.sig` files
   - Logs an OS security-state snapshot (vulnerable-driver blocklist flags, Smart App Control, VBS/HVCI, Secure Boot, Driver Verifier, active WDAC policies) so blocked loads can be diagnosed from the log alone
4. SandMan reads certificate from driver — full unlock

## Building from source

Requires Visual Studio 2022+ Build Tools with C++ workload and Windows SDK 10. `build.bat` auto-detects VS via `vswhere.exe`.

```
build.bat    # Compiles version_hook.c + version.rc → dist/version.dll
```

No external dependencies — links against `bcrypt.lib`, `user32.lib`, `advapi32.lib`, `ntdll.lib`. The driver is embedded as a C byte array (`driver_bin.h`).

## Usage

End users: download the release zip, extract `version.dll` and `unlock.bat` to the same folder, run `unlock.bat` as administrator. You can also just copy `version.dll` into the Sandboxie-Plus installation folder directly.

Developers: clone the repo, run `build.bat` to compile (outputs to `dist/`), then run `dist\unlock.bat`.

```
build.bat           # Compile version.dll into dist/ (requires VS Build Tools + Windows SDK)
dist/unlock.bat     # Menu: install / remove / reset safe-fail state
```

After reboot the kernel patch is lost — run Install Hook again. Keypair saved in `keypair.dat` is reused, so cert and .sig files don't need regeneration.

Remove Hook mirrors the official installer stop sequence: kills GUI processes, runs `KmdUtil scandll_silent` to terminate sandboxed processes, stops `SbieSvc` and polls for STOPPED, then unloads `SbieDrv` via `KmdUtil stop SbieDrv` (which calls `API_UNLOAD_DRIVER` — requires `Api_UseCount == 1`, i.e. SbieSvc fully stopped). Restores original `.sig` from `sig_backup/`, deletes generated files, restarts services. SandMan reloads `SbieDrv.sys` with the original key — no reboot required.

## Crash safety

Safe-fail state in `HKCU\SOFTWARE\sandboxie_unlocker` survives reboots. The DLL marks an active unlock attempt before the risky work starts; if the previous attempt was interrupted, the next run increments `fail_count`. After 3 interrupted attempts, the DLL enters safe mode — transparent proxy without kernel unlock.

Controlled failures clear the active marker without incrementing `fail_count`. A successful unlock resets both `attempt_active` and `fail_count`. Manual reset via `unlock.bat` option [3].

For compatibility with hooks installed by v1.0.3 and earlier (where the driver was staged in `version.dll:driver` and could keep the DLL locked), Remove Hook detects a surviving `version.dll` and raises `fail_count` to the safe-mode threshold — the surviving DLL then stays a transparent proxy and does not re-apply the kernel patch. A fresh Install resets `fail_count`; option [3] clears the whole state key.

## Technical details

### Certificate format

```
NAME: HardTest
DATE: 25.06.2026
TYPE: ETERNAL
SOFTWARE: Sandboxie-Plus
OPTIONS: SBOX,EBOX,NETI,DESK
SIGNATURE: <base64 raw R||S ECDSA P-256>
```

- UTF-8, no BOM
- SHA-256 of `name:value` pairs (excluding SIGNATURE line)
- Signature: 64-byte raw R||S (not DER), matches `BCryptVerifySignature`

### Kernel key layout

72-byte BCRYPT ECCPUBLIC_BLOB at RVA `0x39590` in `.data` section:

| Offset | Field | Value |
|--------|-------|-------|
| 0 | Magic | `ECS1` (4 bytes) |
| 4 | KeySize | `0x20` (4 bytes, LE) |
| 8 | X | 32 bytes, big-endian |
| 40 | Y | 32 bytes, big-endian |

### Driver IOCTLs (dbutil_2_3.sys, METHOD_BUFFERED)

| IOCTL | Function |
|-------|----------|
| `0x9B0C1EC4` | Kernel memory read (`memmove`) |
| `0x9B0C1EC8` | Kernel memory write (`memmove`) |

Buffer: `[cookie:8][base:8][offset:8][data:N]` — cookie=0 bypasses driver cookie check.

No SEH in driver — invalid page causes BSOD. Key RVA validated via `ECS1` magic before write.

## Source layout

```
sandboxie_unlocker/
├── dist/              # End-user release (DLL + unlock.bat)
│   ├── version.dll    # Pre-built, committed to repo
│   └── unlock.bat     # Install / remove / reset menu
├── src/
│   ├── version_hook.c   # DLL proxy + unlock thread + crash safety
│   ├── driver_bin.h     # dbutil_2_3.sys as C byte array (embedded, 14840 bytes)
│   ├── ecrypto.h        # ECDSA P-256 via CNG (bcrypt.dll), keypair save/load
│   ├── kdrv.h           # Kernel R/W via IOCTLs, service management
│   ├── kmod.h           # NtQuerySystemInformation: kernel module enumeration
│   ├── pesearch.h       # PE parsing: find key RVA, store original key
│   ├── certgen.h        # Certificate.dat generation + .sig re-signing
│   ├── sysguard.h       # OS security-state snapshot (blocklist, VBS/HVCI, WDAC, ...)
│   ├── log.h            # File logger (version_hook.log)
│   ├── version.h        # Version + author metadata
│   └── version.rc       # PE version info resource
├── build.bat          # MSVC build script (outputs to dist/)
├── .github/workflows/ # CI + release automation
└── README.md
```

## Runtime artifacts

| File | Description |
|------|-------------|
| `%WINDIR%\Temp\sbie_unlock_<pid>.sys` | Staged kernel driver; restrictive DACL, locked while mapped, cleaned on later runs |
| `Certificate.dat` | Self-signed certificate (ETERNAL, all features) |
| `keypair.dat` | Saved ECDSA P-256 private key (reused after reboot) |
| `sig_backup/` | Original `.exe.sig` files |
| `version_hook.log` | Debug log with timestamps |
