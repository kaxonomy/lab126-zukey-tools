# Device behavior

## Public model identifiers

- Product family: Amazon / Lab126 ZUKEY 2
- VID/PID: `1949:0429`
- Composite descriptor: `ZUKEY 2 FIDO`
- HID product: `ZUKEY 2 HID`

Individual serial numbers and instance paths are local private device data and are intentionally absent here.

## Confirmed Windows enumeration

- `MI_00`: FIDO HID, usage `F1D0:0001`
- `MI_01`: keyboard HID, usage page `0x0001`, usage `0x0006`
- observed `MI_01` HID caps: input report `9`, output report `2`, feature report `0`
- `hidapi` exposes the keyboard collection
- `python-fido2` access may require an elevated process on Windows

## Confirmed CTAP2 information

- Version: `FIDO_2_0`
- CTAPHID version: `2`
- Public AAGUID: `cab7fd818362ce9d2ca9bdebc7d61c4c`
- Extension: `hmac-secret`
- Options: resident credentials and client PIN
- PIN/UV protocol: `1`
- Minimum PIN length: `4`
- Maximum message size: `2200`
- Biometric enrollment, built-in UV, and credential management were not advertised

## Touch behavior

- **CONFIRMED:** a long touch can produce a changing 44-character Modhex-looking value plus Enter.
- **INFERRED:** output is consistent with YubiOTP-style Modhex.
- **UNKNOWN:** short-touch slot presence, writability, and independent slot mapping.

No captured OTP, public ID, or individual serial is included in this repository.
