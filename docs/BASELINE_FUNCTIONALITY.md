# Baseline functionality

Sanitization must preserve hardware behavior. Checks were run before and after the changes on Windows with the same connected compatible device. No destructive operation, PIN change, slot write, or reset was invoked.

| Function | Before sanitization | After sanitization | Evidence / limitation |
|---|---|---|---|
| Application starts | PASS | PASS | Built executable remained running during a five-second launch check. |
| ImGui UI renders | PASS | PASS | A visible top-level window titled `ZukeyLab` was detected after launch. No screenshot was retained because the local UI displays a private serial. |
| Device discovery | PASS | PASS | Headless check reported a connected matching device. |
| Target VID/PID detection | PASS | PASS | Public `1949:0429` filtering remains unchanged. Selection now uses the connected runtime serial instead of a committed serial. |
| FIDO2 GetInfo | LIMITED | LIMITED | Non-elevated execution could not open FIDO HID before or after. Earlier private evidence recorded an elevated success, but a fresh elevated run requires user-approved UAC and remains a publication checklist item. |
| OTP capture/parsing | PASS | PASS | Parser and Enter-detection tests pass with deterministic synthetic values. Live touch capture was not repeated. |
| Modhex analysis | PASS | PASS | Round-trip and 44-character structure tests pass. |
| Sanitized diagnostic export | FAIL | PASS | Baseline export exposed device fields. Shared redaction tests and a real-device headless export now prove the serial, username, full OTP-shaped values, and public-ID fields are absent/redacted. |
| Experimental/read-only legacy probing | PASS | PASS | Descriptor gate and 9-byte response parser remain tested; connected device reports `Not detected` without issuing a feature request when feature length is zero. |
| Tests | PASS (7/7) | PASS (10/10) | `python -m unittest discover -s tests -v` |
| Packaging/build | PASS | PASS | PyInstaller produced `dist\ZukeyLab.exe`; optional demo-module warnings do not affect this application. |
| Destructive safety gates | PASS | PASS | Unknown legacy writes remain blocked; Slot 2 requires all launch-local safety switches; reset still requires phrase, displayed runtime serial, timing acknowledgement, and final click. |

## Hardware abstraction inventory

- `app/device.py`: Windows PnP/HID enumeration and report-cap discovery.
- `app/fido_backend.py`: `python-fido2` device listing, runtime serial/path authorization, GetInfo, PIN, and reset operations.
- `app/legacy.py`: descriptor-gated read-only legacy status probing; no write transport.
- `app/otp.py`: passive focused-input analysis; it sends no device command.
- `app/safety.py`: operation classification and write/destructive authorization gates.
- `app/sanitize.py`: shared export and log redaction boundary.

## Reproduce

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe .\main.py --headless-check --output "$env:TEMP\zukeylab-check.json"
.\build.ps1
```
