# Protocol

## Standard FIDO2

ZukeyLab uses `python-fido2` for CTAPHID and CTAP2. It does not reimplement CTAP2.

Read-only operation:

- Enumerate `CtapHidDevice`.
- Filter exact `1949:0429`.
- Send CTAP2 `authenticatorGetInfo` through `Ctap2.get_info()`.

Persistent standard operations:

- `ClientPin.set_pin()`
- `ClientPin.change_pin()`
- `Ctap2.reset()`

Methods remain outside rendering code and require explicit UI action.

## Keyboard OTP capture

No device command is sent. User focuses one ImGui input and activates token. Parser:

- strips trailing CR/LF for analysis
- records whether Enter submitted field
- validates Modhex alphabet `cbdefghijklnrtuv`
- extracts first 12 characters as public ID candidate
- reports remaining length
- stores only redacted sample text

## Yubico legacy reference protocol

Official `yubikey-personalization` Windows backend:

- opens keyboard HID interface
- uses report ID `0`
- uses 9-byte buffer: report ID plus 8-byte payload
- calls `HidD_GetFeature` for status
- parses firmware bytes, programming sequence, and touch-level bitmask

Status bits:

- `0x01`: configuration/Slot 1 valid
- `0x02`: configuration/Slot 2 valid
- `0x04`: Slot 1 requires touch
- `0x08`: Slot 2 requires touch

## ZUKEY 2 result

`MI_01` HID caps:

```text
Usage page:           0x0001
Usage:                0x0006
Input report bytes:   9
Output report bytes:  2
Feature report bytes: 0
```

Feature-report length is zero, so app does not send `HidD_GetFeature`. No Yubico status frame exists according to exposed report descriptor. Output report size `2` matches ordinary keyboard LED output and is not treated as configuration channel.

No `SetFeature`, slot-write, mode-change, reset, fuzzing, or unknown report is sent.

