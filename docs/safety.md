# Safety Classification

## Implemented operations

| Operation | Classification | Default | Notes |
|---|---|---:|---|
| Windows PnP enumeration | Read-only | Enabled | Exact public VID/PID filter |
| HID descriptor/caps read | Read-only | Enabled | No output or feature write |
| CTAP2 `authenticatorGetInfo` | Read-only | Enabled | Runtime serial/path match for the connected VID/PID device |
| Focused OTP field capture | Read-only/passive | Enabled | No global hook; full OTP memory-only |
| Yubico status descriptor check | Read-only | User/refresh | Stops when feature length is zero |
| Set FIDO PIN | Persistent | Manual | Displayed runtime serial typed; PIN never logged |
| Change FIDO PIN | Persistent | Manual | Displayed runtime serial typed; PIN never logged |
| FIDO factory reset | Destructive | Manual, gated | `RESET`, serial, timing acknowledgement, final click |
| Legacy Slot 1 programming | Unknown | Blocked | No compatible transport proven |
| Legacy Slot 2 programming | Unknown | Blocked | Launch-local allow switch defaults off; no implementation |

## Never autonomous

- FIDO reset
- PIN changes
- legacy slot writes/deletes
- access-code changes
- mode changes
- firmware operations
- unknown HID commands
- USB fuzzing
- OTP secret extraction
- remote OTP validation

## Evidence labels

- `CONFIRMED`: direct descriptor or protocol response.
- `INFERRED`: behavior supports claim but protocol does not prove it.
- `UNKNOWN`: insufficient evidence.

