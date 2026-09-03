# ZUKEY 2 reverse-engineering timeline

## 2026-09-02 — passive identification

Enumerated Windows HID/PnP and raw USB descriptors. Found CTAPHID plus a standard boot keyboard only; no feature, CCID, WebUSB, DFU, BOS, or vendor collection.

## 2026-09-02 — protocol fingerprint

Documented read-only CTAPHID/CTAP2 probes and direct attestation. Minimal CTAP2.0 GetInfo and ClientPIN responses match 2022-era CanoKey; attestation identifies Amazon codename Fathom 1.

## 2026-09-02 — transport elimination

Compared public forks and historical source, audited matching code offline for memory disclosure, and reviewed Windows driver metadata. No public OEM fork, usable disclosure, OEM driver, or documented management interface found; safe software-only paths exhausted.

## 2026-09-02 — attestation recovery and pause

Recovered public attestation metadata from Windows WebAuthn event trace, compared root identity with official FIDO MDS, and ran final health/sanitization checks. Device remains connected and CTAP2-responsive. Paused pending non-destructive hardware identification and a sacrificial spare.
