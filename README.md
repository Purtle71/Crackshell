# CrackShell

CrackShell is a Windows PowerShell application for authorized OpenStego password recovery and local hash comparison. It provides separate OpenStego and hash-solver workspaces in one WinForms interface.

## Features

- OpenStego wordlist-based password recovery
- Current attempt, elapsed time, progress, pause, cancel, and run history
- Local MD5, SHA-1, SHA-256, SHA-384, and SHA-512 comparison
- AES comparison with 128-, 192-, or 256-bit keys and CBC, ECB, CFB, or OFB modes
- Optional prefix or suffix salt handling
- Closest-match tracking for hash attempts
- Reusable wordlist selection across both workspaces
- Dark mode and local logs

## Requirements

- Windows 10 or Windows 11
- Windows PowerShell 5.1 or PowerShell 7
- Java available through `java.exe`
- `openstego.jar` for the OpenStego workspace

## OpenStego setup

OpenStego is not bundled with this repository. Download it from the official project, then place `openstego.jar` beside `CrackShell.ps1` or select the JAR from the application.

- Homepage: https://www.openstego.com/
- Source and releases: https://github.com/syvaidya/openstego

## Run

Double-click `RUN_CRACKSHELL.bat`, or run:

```powershell
powershell -ExecutionPolicy Bypass -File .\CrackShell.ps1
```

## Authorized use

Use CrackShell only with files, hashes, keys, and wordlists you own or are explicitly authorized to test. Do not use it to access another person's data or accounts.

## Validation

```powershell
powershell -ExecutionPolicy Bypass -File .	ests\Validate-Project.ps1
```

## License

CrackShell source code is MIT licensed. OpenStego is a separate GPL-2.0 project and is not included in this repository.
