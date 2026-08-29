# SandBoxie Unlocker

[![Build & Release](https://github.com/A11waysY0U/sbie_free/actions/workflows/build.yml/badge.svg)](https://github.com/A11waysY0U/sbie_free/actions/workflows/build.yml)

A Windows GUI utility for creating a hardware-locked Sandboxie-Plus sponsor certificate and applying the corresponding in-memory driver patch.

**Language:** English | [简体中文](README_zh.md)

## Overview

SandBoxie Unlocker:

1. Reads the hardware identifier of the current machine.
2. Generates an ECC key pair and a node-locked `Certificate.dat`.
3. Loads `RTCore64.sys` and patches the in-memory public key used by `SbieDrv.sys`.
4. Re-signs the Sandboxie executable signature (`.sig`) so the patched driver accepts the generated certificate.
5. Removes the temporary driver service when the operation finishes.

> **Research and educational use only.** The driver patch exists only in memory and disappears after a reboot. Modifying Windows security settings or loading a vulnerable kernel driver can destabilize the system and may cause a blue screen. Use this utility only on a test machine whose data you can afford to lose.

## Safety checks

Before starting a registration, the application checks for:

- Memory integrity (HVCI)
- Microsoft's vulnerable-driver blocklist
- Kernel-mode hardware-enforced stack protection
- Known conflicting security software, including Kaspersky, 360, and Huorong processes

The application blocks the operation when one of these conditions is detected. If the process snapshot cannot be created, the current implementation continues because no conflicting process was found.

## Repository layout

```text
.
├── CMakeLists.txt
├── README.md
├── README_zh.md
├── src/
│   ├── core.cpp                    # Certificate generation, driver patching, signing, restore
│   ├── core.h
│   ├── main.cpp                    # Win32 GUI
│   ├── windows_security_check.cpp  # Driver compatibility and security software checks
│   └── windows_security_check.h
└── third_party/
    ├── rtcore.h                    # RTCore64 ioctl wrapper
    └── RTCore64.sys
```

## Requirements

- Windows x64
- Visual Studio 2022 or Build Tools 2022 with the MSVC toolchain and Windows SDK
- CMake 3.15 or newer
- `RTCore64.sys` in `third_party/`

CMake automatically copies `RTCore64.sys` next to the executable after a successful build.

## Build

### Visual Studio generator

```powershell
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

Output:

```text
build\Release\SandBoxieUnlocker.exe
build\Release\RTCore64.sys
```

### Ninja generator

Initialize an x64 MSVC environment first. For example:

```powershell
cmd /c "call ""C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"" && cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release && cmake --build build"
```

Output:

```text
build\SandBoxieUnlocker.exe
build\RTCore64.sys
```

If you use another Visual Studio edition, adjust the path to `vcvars64.bat` accordingly.

## Usage

1. Place `SandBoxieUnlocker.exe` and `RTCore64.sys` in the Sandboxie installation directory.
2. Run `SandBoxieUnlocker.exe` as an administrator. The application requests UAC elevation automatically when required.
3. Enter a name, select a level (`STANDARD`, `ADVANCED`, `ADVANCED1`, or `HUGE`), and specify the certificate validity period in days.
4. Select **Register**.
5. Copy the generated `Certificate.dat` into the Sandboxie-Plus installation directory if it is not already there.
6. Restart Sandboxie-Plus.

### Restore

Select **Restore signature** to:

- restore every `*.sig.bak` file to `*.sig`
- remove `Certificate.dat`
- stop and remove the temporary `RTCore64` service

## Generated files

The application writes the following files to its current directory:

| File | Description |
|---|---|
| `Certificate.dat` | Generated Sandboxie-Plus certificate |
| `key.hex` | Private key used to sign the certificate |
| `mypub.hex` | Public key used by the certificate |
| `sbie_key_backup.bin` | Backup of the original driver public key |

Keep `key.hex` and `sbie_key_backup.bin` private and retain them until all changes have been restored.

## Troubleshooting

- **Driver load failure:** Check whether memory integrity, vulnerable-driver blocking, or another kernel-protection feature is enabled. Review the warning shown by the application.
- **Blue-screen risk:** Do not run the utility while Kaspersky, 360, Huorong, or other low-level security software is active.
- **No UAC prompt:** Launch the executable from Explorer or use an elevated terminal, and verify that your user is allowed to elevate.
- **Build failure:** Confirm that the x64 MSVC environment is initialized and that the Windows SDK is installed.

## Contributing

Issues and pull requests are welcome. For code changes, please keep the UI and core logic separated and make sure the Release build passes before submitting.