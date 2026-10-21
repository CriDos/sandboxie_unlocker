<h1 align="center">Sandboxie-Plus Unlocker</h1>

<p align="center">
  <img src="https://img.shields.io/badge/Windows-10_%7C_11_x64-0078d6?logo=windows&logoColor=white" alt="Windows 10 / 11 x64" />
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

Full kernel-level certificate unlock for Sandboxie-Plus **1.17.x–1.18.x** through a single `version.dll` proxy: it replaces the ECDSA public key of `SbieDrv.sys` in kernel memory, writes a matching `Certificate.dat` and re-signs the `.exe.sig` files. No test-signing and no extra input files — everything needed is embedded in the DLL.

**Windows x64 only.** Tested on Windows 10 22H2 (19045.6691) and Windows 11 24H2 (26100) with Sandboxie-Plus 1.17.9, 1.18.0, 1.18.2, 1.18.7 and 1.18.8.

## How it works

Sandboxie-Plus validates supporter certificates with ECDSA P-256; the public key is hardcoded in `SbieDrv.sys` (`KphpTrustedPublicKey`). Without a valid certificate the driver enforces its limits: processes are killed after 5 minutes or immediately.

1. `version.dll` sits next to `SandMan.exe`, loads before SandMan initializes, and forwards all 17 exports to the real `System32\version.dll`.
2. If SandMan is not elevated, `DllMain` leaves the work to SandMan's own first-start maintenance elevation (`-assist`): SandMan starts an elevated copy of itself, and that copy runs the steps below; an already elevated host runs them itself.
3. The elevated instance stages the embedded Dell-signed `dbutil_2_3.sys` (CVE-2021-21551) to `%WINDIR%\Temp` with a restrictive DACL, loads it as a service, and swaps the public key in kernel memory; read-only pages are written through a PTE alias (see [Kernel key layout](#kernel-key-layout)).
4. It writes `Certificate.dat`, moves each vendor `.exe.sig` to `X.exe.sig.vendor` and re-signs it, then asks the driver to re-read the certificate. The certificate stays on disk: later starts in the same boot reuse it, and the first start after a boot rewrites it (see [Boot and reboot cycle](#boot-and-reboot-cycle)).
5. SandMan reads the certificate from the driver: full unlock.

At startup the DLL also logs an OS security snapshot (blocklist, Smart App Control, live CI/HVCI, Secure Boot, Driver Verifier, WDAC) to `version_hook.log`, so a blocked load can be diagnosed from the log alone.

## Usage

**End users:** download the release zip and copy `version.dll` into the Sandboxie-Plus folder — that is the whole installation. On the first SandMan start after a boot, when the Sandboxie driver is not running yet, SandMan raises its own maintenance elevation (UAC); the elevated instance unlocks and starts the driver, and SandMan connects after it. Later starts in the same boot need no elevation. Sandboxie's own auto-start (`Start UI with Windows`) makes that first start happen at logon. Start SandMan before any sandboxed program: a sandboxed program started first would load the driver without the unlock, and the maintenance elevation would not run in that boot. `unlock.bat` is only needed for the blocklist switch and for removing the hook.

**From source:** run `_build.bat` (VS 2022 Build Tools with the C++ workload and Windows SDK 10, found via `vswhere.exe`); the DLL lands in `dist/`, then copy `dist\version.dll` into the installation folder. It links only against `bcrypt`, `user32`, `advapi32`, `ntdll` and `psapi`.

After a reboot the kernel patch is gone, but the hook stays in the installation folder and re-applies it on the first SandMan start of that boot (one UAC prompt, raised by SandMan's own maintenance path); the other starts reuse the unlocked state. The keypair in `keypair.dat` is reused, so previously signed files stay valid.

## Boot and reboot cycle

A fresh boot reloads `SbieDrv.sys` from disk, so the kernel key is the vendor one again while the files from the previous session are still installed. The driver checks two things against that key before a patch could land:

- **`Certificate.dat` in `DriverEntry`.** A certificate signed with our key fails the vendor check and can show *"The Certificate Signature is invalid!"*. The certificate therefore lives on disk between restarts and is rewritten at the first start of every boot: the elevated instance patches the kernel, writes a fresh certificate and asks the driver to re-read it before SandMan connects, so the UI never queries the stale state. During the session the file stays — SandMan reads it for the certificate page — and Remove Hook deletes it.
- **`SandMan.exe.sig` when SandMan connects.** A vendor key plus our re-signed `.sig` files gives *"SandMan.exe does not have a valid signature"*. A synchronous fast path in `DllMain`, before any SandMan code runs, finishes the job: an elevated host re-applies the saved key inline, an unelevated one leaves it to SandMan's maintenance elevation (`-assist`), which starts an elevated copy of SandMan; the main process waits for that copy before connecting, so the connect-time check never sees a stale state. The same code writes the certificate, signs the `.sig` files, asks the driver to reload and writes `unlock.boot`; a later start in the same boot sees the matching marker and does not ask for elevation at all.

Both paths check that the running driver is the build on disk (`TimeDateStamp` and `SizeOfImage` of the mapped headers against `SbieDrv.sys`). Right after a Sandboxie update the old image is still running with the key at a different RVA, and writing there would corrupt it, so the hook refuses with a log line until a reboot (or an `SbieSvc` restart).

The hook also refuses to patch the kernel when a vendor signature cannot be restored. The vendor `X.exe.sig` is moved to `X.exe.sig.vendor` by `ReplaceFile` in the same atomic step that installs ours, so the original bytes are never copied, rewritten or lost, and removal is a rename back. If a signature is already gone and no shadow exists, the hook does not patch at all and says so in the log — an installed hook can always be removed.

## Driver blocklist

Windows 11 22H2+ ships the **Microsoft Vulnerable Driver Blocklist** enabled; it rejects the embedded `dbutil_2_3.sys` with `StartService` error `0x800B010C` even though its Authenticode signature is valid, because it matches the binary hash. Windows 10 has the same switch (`CI\Config\VulnerableDriverBlocklistEnable`) but ships it off.

1. Run `unlock.bat` → **[4] Disable Vulnerable Driver Blocklist** (or the `reg add` below), then **reboot** — the change only takes effect after a restart.
   ```
   reg add "HKLM\SYSTEM\CurrentControlSet\Control\CI\Config" /v VulnerableDriverBlocklistEnable /t REG_DWORD /d 0 /f
   ```
2. Install the hook ([1]) as usual.

Restore the default at any time with option **[5]** (reboot required).

**Memory Integrity (VBS/HVCI)** enforces the blocklist regardless of this flag. Turn it off first (Windows Security → Device security → Core isolation → Memory integrity), reboot, then disable the blocklist. Smart App Control and WDAC are separate mechanisms; the log reports all of them.

## Removing the hook

Remove Hook follows the installer's stop sequence: kills the GUI processes, runs `KmdUtil scandll_silent`, stops `SbieSvc` and waits for STOPPED, then unloads `SbieDrv` with `KmdUtil stop SbieDrv` (it needs `Api_UseCount == 1`, i.e. SbieSvc fully stopped). The DLL (`rundll32 ... RestoreVendorSigs`) then moves every verified `.sig.vendor` back; the script deletes `version.dll`, the generated certificate, keypair and boot marker, and resets the safe-fail state. If a signature cannot be restored, it still removes the hook but leaves SandMan stopped and asks for the installer repair.

Code Integrity keeps a per-file verdict from the patched load: after the unload, `StartService` fails with 577 (`ERROR_INVALID_IMAGE_HASH`, event 3004) even though the file is byte-identical and validly signed. The script clears that by rewriting `SbieDrv.sys` with its own bytes — the new file id makes Code Integrity validate it from scratch, exactly what the installer's repair does — restarts the services and launches SandMan in the normal, unlicensed state. No reboot or repair install is needed; if the driver could not be unloaded, the script asks for a reboot instead. If `version.dll` is already gone, it renames any leftover `.sig.vendor` files back, deletes the generated files and asks for a reboot to drop the old patch.

Older installations are migrated automatically: a `sig_backup/` directory with a `verified` marker becomes `.sig.vendor` shadows before anything else runs.

## Crash safety

Safe-fail state in `HKCU\SOFTWARE\sandboxie_unlocker` survives reboots. The DLL marks an active attempt before the risky work; if the previous attempt was interrupted, the next run increments `fail_count`. After 3 interrupted attempts the DLL enters safe mode and stays a transparent proxy. Controlled failures clear the active marker without incrementing the counter; a successful unlock resets both. Reset manually with `unlock.bat` option [3].

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

UTF-8, no BOM. The signature is computed over the SHA-256 of the `name:value` pairs (the SIGNATURE line is excluded) and stored as 64-byte raw R||S rather than DER, which is what `BCryptVerifySignature` expects.

### Kernel key layout

The key is a 72-byte BCRYPT ECCPUBLIC_BLOB:

| Offset | Field | Value |
|--------|-------|-------|
| 0 | Magic | `ECS1` (4 bytes) |
| 4 | KeySize | `0x20` (4 bytes, LE) |
| 8 | X | 32 bytes, big-endian |
| 40 | Y | 32 bytes, big-endian |

SbieDrv 1.17.x–1.18.2 keep it in `.data` at RVA `0x39590`. 1.18.7 declares it `const`, which moves it into the read-only `.rdata` (RVA `0x330C0`). The helper driver's memmove has no SEH, so a direct write there bugchecks the box (0xBE); the unlocker reads the section flags from `SbieDrv.sys` on disk and writes a writable section directly, a read-only one through an alias of the same physical frame (a throwaway user page's PTE is repointed at it, so the original mapping and its TLB entries stay untouched).

The self-map base is randomized per boot since Windows 10 RS1. It is found the same way on every build: address→PTE is always a shift and a scale, so the mapped ntoskrnl is scanned for globals followed by `shr 9` / `shl 3` / `lea *8`; the busiest global with a self-map-shaped value (canonical, 64 GB aligned, PML4 index in the kernel half) is the base. No compiler idiom is matched, a miss is a controlled refusal rather than a guess, and the base is validated against a page this process owns before any write. The same global (`nt!MmPteBase`) was confirmed against Microsoft public symbols on 19045 and 26100.

Pre-RS1 kernels use the fixed classic base (gated on the OS build); 5-level paging (LA57) is refused; under Memory Integrity the alias PTE is writable but non-executable to stay within the hypervisor's W^X rule.

### Driver IOCTLs (dbutil_2_3.sys, METHOD_BUFFERED)

| IOCTL | Function |
|-------|----------|
| `0x9B0C1EC4` | Kernel memory read (`memmove`) |
| `0x9B0C1EC8` | Kernel memory write (`memmove`) |

Buffer: `[cookie:8][base:8][offset:8][data:N]`; `cookie=0` bypasses the driver's cookie check. The driver has no SEH, so an invalid page bugchecks the box — every address is validated before use, and the key blob must carry the `ECS1` magic before it is written. The driver also exposes physical memory read/write via `MmMapIoSpace` (`0x9B0C1F44` / `0x9B0C1F40`), a contiguous alloc/free pair (`0x9B0C1EC0` / `0x9B0C1ECC`) and status calls — unused here, an option only if a future SbieDrv hides the key where a PTE alias cannot reach.

## Source layout

| Path | Contents |
|------|----------|
| `src/version_hook.c` | DLL proxy, `DllMain` fast path, unlock thread, restore export |
| `src/` headers | `kdrv`/`pagemap` (kernel R/W, PTE alias), `kmod`, `pesearch`, `certgen`, `ecrypto`, `fileio`, `safety`, `sysguard`, `sbieapi`, `hostguard`, `log` |
| `src/driver_bin.h` | `dbutil_2_3.sys` as a C byte array |
| `src/version.h`, `src/version.rc` | version/author metadata and the PE version resource |
| `tests/` | `selftest.c`, `proxytest.c`, `ptelive.c`, `testfw.h` |
| `dist/unlock.bat` | install / remove / reset menu; build output also lands in `dist/` |
| `_build.bat`, `_tests.bat`, `_ptelive.bat`, `_msvc_env.bat` | build, test and live-PTE scripts |
| `.github/workflows/` | CI and release automation |
| `LICENSE` | MIT |

## Testing

`_tests.bat` builds the DLL and the test binaries and runs them; no external tools. It is safe on any machine — kernel and live-Sandboxie paths are never exercised. Started without arguments it keeps the console open after the run; pass any argument (CI) to exit immediately.

- `selftest.c` — unit and filesystem tests: CNG sign/verify, keypair save/load and public-blob recovery (boot fast path), certificate hash and layout, PE key search (original key, patched fallback, section-boundary refusal), fileio and logger edges, stale staging cleanup, restrictive DACL, safe-fail state machine, host filter, staged-driver bytes, PTE math and the self-map search, `.sig` shadows, SbieDll calls without Sandboxie, module lookup.
- `proxytest.c` — loads `dist\version.dll` into a non-SandMan process: 17 exports resolve, the version resource round-trips through the real `version.dll`, failure hosts degrade gracefully, safe-fail state stays untouched.
- `ptelive.c` (`_ptelive.bat`, admin, not part of the suite) — loads the helper driver, locates and validates `nt!MmPteBase`, then writes through a page alias into a page this process made read-only and confirms it is still read-only for user code.

CI (`.github/workflows/ci.yml`) builds the DLL, runs the suite and cppcheck on pushes to `master` and on pull requests; the release workflow runs on `v*` tags.

## Runtime artifacts

| File | Description |
|------|-------------|
| `%WINDIR%\Temp\sbie_unlock_<pid>.sys` | Staged kernel driver; restrictive DACL, locked while mapped, cleaned on later runs |
| `Certificate.dat` | Self-signed certificate (ETERNAL, all features); kept across restarts, rewritten at the first start after a boot, deleted by Remove Hook |
| `unlock.boot` | 24-byte boot marker (boot GUID plus the derived boot time as a fallback) written after a successful unlock; later starts in the same boot need no elevation |
| `keypair.dat` | Saved ECDSA P-256 private key, reused after reboot; deleted on removal |
| `*.exe.sig.vendor` | Vendor signature moved aside while the hook is active; restored on removal |
| `version_hook.log` | Debug log with timestamps, rotated to `.old.log` at 1 MB |
