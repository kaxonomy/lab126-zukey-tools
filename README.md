# ZukeyLab

ZukeyLab is an independent community research and management tool for compatible security-key hardware.

It currently recognizes the public Amazon/Lab126 ZUKEY 2 USB model identifiers `1949:0429` and provides:

- Windows HID discovery and descriptor inspection
- FIDO2 `authenticatorGetInfo`, PIN management, and a deliberately gated reset flow
- focused OTP capture with Modhex/YubiOTP-style format analysis
- experimental, read-only legacy compatibility probing
- sanitized diagnostics that omit device-specific identifiers and credentials

This project is independent and is not affiliated with, endorsed by, or sponsored by Amazon, Lab126, Yubico, or any other vendor.

This software is intended for local research and management of hardware the user is authorized to possess and test. It does not communicate with Amazon authentication services.

## Run

```powershell
.\run.ps1
```

`run.ps1` creates `.venv`, installs pinned dependencies, and requests elevation because Windows may deny direct FIDO HID access otherwise.

## Test and build

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe .\main.py --headless-check
.\build.ps1
```

The build output is `dist\ZukeyLab.exe`. Headless output and copied diagnostics are sanitized by default.

See [security data handling](docs/SECURITY_DATA_HANDLING.md), [safety controls](docs/safety.md), and [contributing](CONTRIBUTING.md) before collecting diagnostics or committing changes.
