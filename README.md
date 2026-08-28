# Sandboxie-Plus Unlocker

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

Full kernel-level certificate unlock for Sandboxie-Plus **1.17.x–1.18.x** (tested on 1.17.9, 1.18.0 and 1.18.2) via a single `version.dll` proxy. No test-signing, no files needed in the install directory — everything is embedded in one DLL.

**Windows x64 only** (the embedded kernel driver is 64-bit and the module enumeration uses x64 struct layouts). Tested on Windows 11 24H2 (Build 26100).

## How it works

Sandboxie-Plus uses ECDSA P-256 to validate supporter certificates. The public key is hardcoded in `SbieDrv.sys` (`KphpTrustedPublicKey`). Without a valid certificate, security features are enforced by the kernel driver — processes are killed after 5 minutes or terminated immediately.

This tool replaces the public key in the running kernel with a freshly generated keypair, writes a self-signed `Certificate.dat`, and re-signs all `.exe.sig` files so SandMan's integrity check passes.

1. `version.dll` placed next to `SandMan.exe` — Windows loads it before SandMan initializes, and all 17 exports are forwarded to the real `System32\version.dll` via lazy-resolved function pointers
2. A background thread stages the embedded driver (Dell-signed `dbutil_2_3.sys`, CVE-2021-21551) to `%WINDIR%\Temp` with a restrictive DACL, loads it as a service, finds `SbieDrv.sys` in the kernel module list and the ECDSA key RVA in the driver image on disk
3. Generates an ECDSA P-256 keypair via Windows CNG and overwrites the public key in kernel memory
4. Writes a self-signed `Certificate.dat` (type: ETERNAL, all features), backs up and re-signs all `.exe.sig` files
5. SandMan reads the certificate from the driver — full unlock

At startup the DLL also logs an OS security-state snapshot (vulnerable-driver blocklist flags, Smart App Control, VBS/HVCI, Secure Boot, Driver Verifier, active WDAC policies) to `version_hook.log`, so blocked loads can be diagnosed from the log alone.

## Usage

**End users:** download the release zip, extract `version.dll` and `unlock.bat` to the same folder, run `unlock.bat` as administrator, pick **[1] Install Hook**. You can also just copy `version.dll` into the Sandboxie-Plus installation folder directly.

**From source:** clone the repo and run `build.bat` (requires VS 2022+ Build Tools with the C++ workload and Windows SDK 10 — auto-detected via `vswhere.exe`). Output lands in `dist/`, then run `dist\unlock.bat`. No external dependencies — links against `bcrypt.lib`, `user32.lib`, `advapi32.lib`, `ntdll.lib`; the driver is embedded as a C byte array (`driver_bin.h`).

After a reboot the kernel patch is gone — run Install Hook again. The keypair saved in `keypair.dat` is reused, so the certificate and `.sig` files do not need regeneration.

## Driver blocklist

Windows 11 22H2+ (including 24H2) ships the **Microsoft Vulnerable Driver Blocklist** enabled by default. It blocks the embedded Dell-signed helper driver (`dbutil_2_3.sys`) at load time with `StartService` error `0x800B010C`, even though the Authenticode signature is valid — the blocklist checks the binary hash, not the signature.

To use the unlocker on a machine where the blocklist refuses the driver:

1. Run `dist\unlock.bat` as administrator, option **[4] Disable Vulnerable Driver Blocklist** (or set it manually):
   ```
   reg add "HKLM\SYSTEM\CurrentControlSet\Control\CI\Config" /v VulnerableDriverBlocklistEnable /t REG_DWORD /d 0 /f
   ```
2. **Reboot** — the change only takes effect after a restart.
3. Run Install Hook ([1]) as usual.

Restore the default protection at any time with option **[5]** (also requires a reboot).

Notes:

- If **Memory Integrity (VBS/HVCI)** is turned on, the blocklist is enforced unconditionally — the registry flag is ignored. Disable Memory Integrity first (`Windows Security` → `Device security` → `Core isolation` → `Memory integrity` off, reboot), then disable the blocklist.
- Smart App Control and WDAC policies, if active, are separate mechanisms; their state is reported in `version_hook.log`.

## Removing the hook

Remove Hook mirrors the official installer stop sequence: kills GUI processes, runs `KmdUtil scandll_silent` to terminate sandboxed processes, stops `SbieSvc` and polls for STOPPED, then unloads `SbieDrv` via `KmdUtil stop SbieDrv` (which calls `API_UNLOAD_DRIVER` — requires `Api_UseCount == 1`, i.e. SbieSvc fully stopped). It restores the original `.sig` files from `sig_backup/`, deletes generated files, resets the safe-fail state and restarts services. SandMan reloads `SbieDrv.sys` with the original key — no reboot required.

## Crash safety

Safe-fail state in `HKCU\SOFTWARE\sandboxie_unlocker` survives reboots. The DLL marks an active unlock attempt before the risky work starts; if the previous attempt was interrupted, the next run increments `fail_count`. After 3 interrupted attempts, the DLL enters safe mode — a transparent proxy without kernel unlock.

Controlled failures clear the active marker without incrementing `fail_count`. A successful unlock resets both values. Remove Hook also raises `fail_count` when it detects a surviving DLL from a v1.0.3-or-earlier hook (legacy ADS staging), forcing it to stay a transparent proxy. Manual reset via `unlock.bat` option [3].

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
├── dist/              # unlock.bat + build output
│   └── unlock.bat     # Install / remove / reset menu
├── src/
│   ├── version_hook.c   # DLL proxy + unlock thread + crash safety
│   ├── driver_bin.h     # dbutil_2_3.sys as C byte array (embedded, 14840 bytes)
│   ├── ecrypto.h        # ECDSA P-256 via CNG (bcrypt.dll), keypair save/load
│   ├── fileio.h         # Read whole file into a heap buffer
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
