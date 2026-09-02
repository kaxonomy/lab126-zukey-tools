# Security data handling

## Private device data

Individual serial numbers, OTPs and their public IDs, PINs, access codes, credential material, hmac-secret outputs, USB instance paths, raw captures, internal URLs, and personal machine paths are sensitive. They must not enter source control, issues, screenshots, CI artifacts, or shared diagnostics.

## Sanitized application output

`app/sanitize.py` is the shared redaction boundary for logs, copied diagnostics, and headless reports. Diagnostics replace device serials and OTP public IDs with `[REDACTED]`, shorten probable OTPs to a public-prefix-shaped marker ending in `[REDACTED]`, and remove Windows usernames and serial-bearing USB path components. PIN fields and cryptographic secrets are never exported.

The application displays a connected device serial locally because destructive and persistent operations require the user to type that displayed value. It does not persist the serial in the repository.

## Public and local storage

- **PUBLIC / SANITIZED DATA:** repository source, documentation, synthetic fixtures, and copied sanitized diagnostics.
- **LOCAL PRIVATE DEVICE DATA:** `%LOCALAPPDATA%\ZukeyLab\private\`.

Raw logging is not implemented. If it is added later, it must default off, show a **PRIVATE / UNSANITIZED** warning, write only below that local private directory, and never upload automatically.

## Synthetic fixtures

`tests/fixtures/synthetic.py` generates deterministic format-valid serial, public-ID, and 44-character Modhex values. They are labeled `SYNTHETIC TEST DATA — NOT FROM A REAL DEVICE` and preserve parser behavior without publishing captures.

## Commit and CI controls

The local pre-commit configuration runs the project scanner and gitleaks. `scripts/check-sensitive-data.py` reports only file, line number, and rule; it deliberately avoids echoing a matched value. CI repeats unit tests, the project scanner, and gitleaks for pushes and pull requests and uploads no diagnostic artifacts.

To contribute diagnostics safely, use **Copy sanitized diagnostics**, inspect the text for context-specific identifiers, and paste only the minimum necessary excerpt. Never attach raw captures.
