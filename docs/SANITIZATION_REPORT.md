# Pre-publication sanitization report

> Date: 2026-09-02
>
> Scope: owner-authorized local repository and all refs intended for publication
>
> Report flavor: null (defensive source audit; no malware/APT overlay)

## Executive summary

The original one-commit repository contained a physical device serial, an OTP public-ID prefix, a personal Windows path, and a tracked private research/evidence directory. The application also serialized raw device structures for diagnostics. The publication tree now uses runtime device selection, centralized default redaction, deterministic synthetic fixtures, and layered local/CI scanning. A new parentless sanitized commit replaces the original root; no push was performed. Hardware checks, unit tests, packaging, and visible-window launch continue to work, with elevated FIDO access left for user-approved manual verification.

This is an evidence-based technical sanitization result, not a legal guarantee.

## Scope and authorization

The repository owner explicitly authorized local inspection, defensive modification, backup creation, and history rewrite. Network activity was limited to installing declared dependencies and retrieving public scanner tooling. No remote push, device reset, PIN change, legacy write, or credential operation occurred. The private operational case record was moved outside the repository before publication.

## Evidence

| ID | Source | Reproduction | Hash |
|---|---|---|---|
| E-001 | Verified external Git bundle | `git bundle verify ..\zukeylab-pre-sanitize-backup.bundle` | SHA-256 recorded outside publication docs |
| E-002 | Baseline and regression tests | `.\.venv\Scripts\python.exe -m unittest discover -s tests -v` | n/a |
| E-003 | Sanitized real-device headless output | `.\.venv\Scripts\python.exe .\main.py --headless-check --output <outside-repo.json>` | private artifact removed after verification |
| E-004 | Project scanner | `.\.venv\Scripts\python.exe scripts\check-sensitive-data.py` | n/a |
| E-005 | Reachable Git object scan | `git rev-list --objects --all` plus known-value and pattern scans | n/a |
| E-006 | Build and UI launch | `.\build.ps1`, then visible window-handle/title check | n/a |

## Findings

### F-001 — Device-specific data in original publication

- severity: HIGH
- status: validated
- evidence_ids: E-001, E-005
- confidence: high
- location: original root and tracked private research tree
- impact: public history exposed a unit identifier, OTP public-ID prefix, machine identity/path, and captured diagnostics.
- remediation: replace the root with a sanitized parentless commit and remove all refs to the original graph.

### F-002 — Diagnostic export lacked a complete redaction boundary

- severity: HIGH
- status: validated
- evidence_ids: E-002, E-003
- confidence: high
- location: former `main.py` and `app/ui.py` serialization paths
- impact: copied or saved reports could disclose serials, instance paths, and OTP identifiers.
- remediation: route logs and every diagnostic serialization path through `app/sanitize.py`; test against synthetic and connected-device data.

### F-003 — Preventive controls were insufficient

- severity: MEDIUM
- status: validated
- evidence_ids: E-004, E-005
- confidence: high
- location: repository contribution workflow
- impact: captured hardware identifiers or credentials could be recommitted.
- remediation: ignore private artifact classes, install a staged project scanner and gitleaks hook, repeat both in CI, and document synthetic fixture rules.

## Sanitization path

### P-001 — Unsafe publication graph to clean publication graph

- path_type: callflow
- start: original published root and raw serialization paths
- goal: parentless sanitized root with guarded diagnostics and no reachable known sensitive values
- steps:
  1. Create and verify an external bundle — evidence E-001 — finding F-001.
  2. Establish baseline hardware/application behavior — evidence E-002/E-006.
  3. Remove private captures and replace device-specific constants/fixtures — finding F-001.
  4. Centralize redaction and validate real-device output — evidence E-002/E-003 — finding F-002.
  5. Add scanner, pre-commit, CI, and contributor controls — evidence E-004 — finding F-003.
  6. Write a new parentless root, remove stale refs, and rescan reachable objects — evidence E-005.
- residual_risks: external GitHub copies/caches and manual elevated hardware verification.

## Timeline

1. External bundle backup created and verified.
2. Baseline tests, headless device discovery, packaging, and UI launch completed.
3. Sensitive values inventoried without echoing matched contents.
4. Runtime serial authorization, redaction, synthetic fixtures, and guardrails implemented.
5. Regression build/tests and negative scanner checks completed.
6. Clean root created and every reachable publication ref rescanned.

## Manual review

- A fresh elevated FIDO GetInfo run requires user-approved UAC.
- A live OTP touch was not repeated; parser behavior is covered with deterministic synthetic data.
- Third-party notices cover direct dependencies; binary distributors should review transitive `imgui-bundle` license files.
- Previously published copies may persist outside the rewritten Git graph.
