#!/usr/bin/env python3
"""Reject likely private device data and credentials without printing them."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
PRIVATE_PARTS = {"captures", "diagnostics-private", "dumps", "logs"}
SYNTHETIC_MARKER = "SYNTHETIC TEST DATA — NOT FROM A REAL DEVICE"
KNOWN_FORBIDDEN_HASHES = {
    "248429c2cb82000c450190338af6c304476981fba1ea2866841700cb3e89daf3",
    "88107b178366ae66278dd8e3499215d97eb6cccd2077ef959e4b13201d75a35e",
    "6d2e585067d4d17bff0445e3438f86655acea5be54158cf676ab9126ae2c5d05",
}
RULES = {
    "modhex-otp-44": re.compile(r"(?i)\b[cbdefghijklnrtuv]{44}\b"),
    "personal-windows-path": re.compile(
        r"(?i)\b[A-Z]:\\Users\\(?!ExampleUser(?:\\|$))[^\\\s]+"
    ),
    "internal-url": re.compile(
        r"(?i)https?://[^\s/]*(?:\.internal\b|\.corp\b|internal\.|corp\.|amazon-internal)"
    ),
    "usb-instance-serial": re.compile(
        r"(?i)(?:USB|HID)\\VID_[0-9A-F]{4}&PID_[0-9A-F]{4}[^\r\n]*(?:[#\\])[A-Z0-9-]{8,}"
    ),
    "private-key": re.compile("-----" + r"BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    "aws-access-key": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "bearer-token": re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]{16,}={0,2}"),
    "credential-assignment": re.compile(
        r"(?i)\b(?:password|passwd|pwd|pin|api[_-]?key|access[_-]?key|secret|token|cookie)"
        r"\s*[:=]\s*[\"']?[A-Za-z0-9._~+/-]{8,}"
    ),
    "specific-device-serial": re.compile(
        r"\b(?=[A-Z0-9-]{14,20}\b)(?=[A-Z0-9-]*\d[A-Z0-9-]*\d[A-Z0-9-]*\d)"
        r"(?=[A-Z0-9-]*[A-Z][A-Z0-9-]*[A-Z][A-Z0-9-]*[A-Z])[A-Z0-9-]+\b"
    ),
}
CANDIDATE_WORD = re.compile(r"[A-Za-z0-9_-]{5,64}")


def staged_files() -> list[tuple[str, str]]:
    names = subprocess.check_output(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z"], cwd=ROOT
    ).decode("utf-8", "surrogateescape").split("\0")
    result = []
    for name in filter(None, names):
        try:
            content = subprocess.check_output(["git", "show", f":{name}"], cwd=ROOT).decode(
                "utf-8", "replace"
            )
        except subprocess.CalledProcessError:
            continue
        result.append((name, content))
    return result


def working_files() -> list[tuple[str, str]]:
    ignored = {".git", ".venv", "build", "dist", "__pycache__", "work"}
    result = []
    for path in ROOT.rglob("*"):
        relative = path.relative_to(ROOT)
        if not path.is_file() or any(part in ignored for part in relative.parts):
            continue
        try:
            result.append((relative.as_posix(), path.read_text(encoding="utf-8")))
        except (UnicodeDecodeError, OSError):
            continue
    return result


def scan(files: list[tuple[str, str]]) -> list[tuple[str, int, str]]:
    findings = []
    for name, content in files:
        parts = set(Path(name).parts)
        if parts & PRIVATE_PARTS:
            findings.append((name, 0, "private-capture-path"))
            continue
        synthetic = name.startswith("tests/fixtures/") and SYNTHETIC_MARKER in "\n".join(
            content.splitlines()[:5]
        )
        for line_number, line in enumerate(content.splitlines(), 1):
            for rule, pattern in RULES.items():
                if pattern.search(line) and not synthetic:
                    findings.append((name, line_number, rule))
            if not synthetic and any(
                hashlib.sha256(token.encode()).hexdigest() in KNOWN_FORBIDDEN_HASHES
                for token in CANDIDATE_WORD.findall(line)
            ):
                findings.append((name, line_number, "known-forbidden-value"))
    return sorted(set(findings))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--staged", action="store_true", help="scan the staged Git snapshot")
    args = parser.parse_args()
    findings = scan(staged_files() if args.staged else working_files())
    for filename, line, rule in findings:
        print(f"{filename}:{line}: {rule}", file=sys.stderr)
    if findings:
        print(f"Sensitive-data scan failed with {len(findings)} finding(s); values suppressed.", file=sys.stderr)
        return 1
    print("Sensitive-data scan passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
