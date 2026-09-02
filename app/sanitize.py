from __future__ import annotations

import re
from typing import Any


REDACTED = "[REDACTED]"
MODHEX_OTP = re.compile(r"(?i)\b[cbdefghijklnrtuv]{44}\b")
WINDOWS_USER_PATH = re.compile(r"(?i)\b[A-Z]:\\Users\\[^\\\s]+")
USB_INSTANCE_SERIAL = re.compile(
    r"(?i)((?:USB|HID)\\VID_[0-9A-F]{4}&PID_[0-9A-F]{4}[^\r\n]*?[#\\])([A-Z0-9-]{8,})(?=[#\\\s]|$)"
)


def redact_serial(value: object) -> str:
    return REDACTED if value else ""


def redact_otp(value: str) -> str:
    stripped = value.rstrip("\r\n")
    return f"{stripped[:12]}...{REDACTED}" if len(stripped) >= 12 else REDACTED


def redact_windows_user_path(value: str) -> str:
    return WINDOWS_USER_PATH.sub(r"C:\\Users\\ExampleUser", value)


def sanitize_log_message(message: object) -> str:
    text = redact_windows_user_path(str(message))
    text = MODHEX_OTP.sub(lambda match: redact_otp(match.group(0)), text)
    return USB_INSTANCE_SERIAL.sub(r"\1[REDACTED]", text)


def sanitize_diagnostics(value: Any) -> Any:
    sensitive_keys = {"serial", "public_id", "pin", "old_pin", "new_pin", "secret", "credential"}

    def clean(item: Any, key: str = "", serial: str = "") -> Any:
        lowered = key.casefold()
        if lowered in sensitive_keys or lowered.endswith(("_serial", "_secret", "_credential")):
            return redact_serial(item)
        if isinstance(item, dict):
            detected_serial = serial or str(item.get("serial") or "")
            return {str(k): clean(v, str(k), detected_serial) for k, v in item.items()}
        if isinstance(item, list):
            return [clean(child, key, serial) for child in item]
        if isinstance(item, tuple):
            return [clean(child, key, serial) for child in item]
        if isinstance(item, str):
            text = sanitize_log_message(item)
            return text.replace(serial, REDACTED) if serial else text
        return item

    return clean(value)
