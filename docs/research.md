# Public Research

This document preserves public references and independently observed protocol behavior without device-specific captures.

## Sources

- https://developers.yubico.com/Developer_Program/Guides/Touch_triggered_OTP.html
  - YubiKey reference behavior: Slot 1 uses short touch; Slot 2 uses long touch; supported configurations include Yubico OTP, HOTP, static password, and challenge-response.
- https://developers.yubico.com/Mobile/Concepts.html
  - OTP USB connection uses HID feature reports. Slot writes overwrite selected slot.
- https://developers.yubico.com/yubikey-personalization/Manuals/ykinfo.1.html
  - Read-only status exposes firmware, programming sequence, and slot configured bits.
- https://github.com/Yubico/yubikey-personalization
  - `ykcore/ykcore_windows.c` reads a 9-byte feature report with `HidD_GetFeature`; `ykdef.h` defines status and slot-valid bits.
- https://github.com/Yubico/yubikey-manager
  - Maintained Yubico management implementation; device recognition and modern management remain Yubico-device-specific.
- https://github.com/Yubico/python-fido2
  - Maintained CTAP2 implementation used by ZukeyLab.
- https://devicehunt.com/view/type/usb/vendor/1949/device/0417
  - Public USB database labels older Lab126 PID `0417` as an Amazon Zukey resembling YubiKey 4 OTP+U2F. This does not establish behavior for PID `0429`.
- https://the-sz.com/products/usbid/index.php?v=0x1949
  - Public USB ID database associates vendor `1949` with Lab126; no exact `0429` entry found during research.

## Conclusions

- **CONFIRMED:** observed `MI_01` descriptors advertise zero feature-report bytes; standard Yubico OTP configuration/status transport requires feature reports.
- **CONFIRMED:** legacy YubiKey protocol status was not detected on the exposed keyboard collection.
- **INFERRED:** 44-character Modhex and timed touch behavior are consistent with YubiOTP-style output.
- **UNKNOWN:** short-touch Slot 1 presence, emptiness, writability, and independent mapping.
- ZukeyLab refuses Slot 1 programming. Add writes only after documented ZUKEY-specific protocol evidence or compatible read-only status response proves slot separation.

