# ZUKEY 2 OTP/touch reverse-engineering findings

## Confirmed

- Target: Amazon/Lab126 USB `1949:0429`, product `ZUKEY 2 FIDO` / `ZUKEY 2 HID`.
- USB exposes exactly two HID interfaces: CTAPHID and a standard boot keyboard. It exposes no HID feature report, CCID, WebUSB, DFU, BOS, or vendor collection.
- CTAPHID protocol version is 2; firmware tuple is 1.3.0; capabilities are WINK + CBOR + NMSG.
- Raw CTAP2 GetInfo contains `FIDO_2_0`, `hmac-secret`, AAGUID, `rk=true`, `clientPin=true`, max message size 2200, and PIN protocol 1.
- Read-only ClientPIN probes succeeded (`getRetries` returned eight; `getKeyAgreement` returned 81 bytes) without consuming a retry.
- Direct attestation identifies the model as `Fathom 1`, issued by `Amazon U2F Root CA 1`; the leaf certificate is dated 2022-05-24.
- The attestation leaf is 679-byte X.509 v3, SHA-256 `df2e4a51925286816b53b08aca050c6ec13116fcdb37bd733b8da51ab237d4e5`, serial `5`, P-256, RSA/SHA-256 issuer signature, valid through 2071-05-12.
- GetInfo ordering, keyboard descriptor, ClientPIN response, and parser behavior match CanoKey core after commit `0812029` and before its CTAP2.1 rewrite, with Amazon-specific changes.
- Historical CanoKey management used OATH/admin APDUs over CCID or WebUSB. The target exposes neither transport and returns `6e00` to harmless SELECT/version APDUs sent through CTAPHID.MSG.
- Windows binds only generic Microsoft HID, keyboard, and FIDO drivers; no OEM provisioning interface is installed or advertised.
- Public CanoKey forks contain no Amazon/ZUKEY touch or OTP changes.
- Offline audit found no safe response-side memory disclosure suitable for firmware extraction.
- The official FIDO Metadata Service catalog contains no matching AAGUID, `Fathom 1` description, Amazon U2F root subject, or matching root key identifier.

## Safety conclusion

The factory command remains private and undiscovered. Blind CBOR/vendor commands, keyboard-output sequences, reset, DFU, and firmware writes are excluded because they could erase credentials or provisioning. The next safe step is physical controller/debug-pad identification using clear exterior/package photos and preferably a sacrificial SAA903. Firmware readout must precede any write attempt on the live key.

## Where work stopped

- Goal incomplete: no verified OTP/touch write transport exists.
- The live target remains healthy: both HID interfaces enumerate normally and CTAP2 GetInfo succeeds.
- The temporary WebAuthn server was stopped; the browser probe created one non-resident diagnostic credential and retained no identifier.
- Resume with sharp front/back/connector/seam/packaging photos and confirmation of a sacrificial SAA903, then identify the controller and read-protection state before selecting a readout method.
