from __future__ import annotations

from dataclasses import dataclass

from .sanitize import redact_otp


MODHEX_ALPHABET = "cbdefghijklnrtuv"
HEX_ALPHABET = "0123456789abcdef"
MODHEX_TO_HEX = str.maketrans(MODHEX_ALPHABET, HEX_ALPHABET)
HEX_TO_MODHEX = str.maketrans(HEX_ALPHABET, MODHEX_ALPHABET)


@dataclass(frozen=True, slots=True)
class OtpAnalysis:
    redacted: str
    total_length: int
    alphabet: str
    valid_modhex: bool
    public_id: str
    encrypted_length: int
    enter_appended: bool
    prefix_matches_previous: bool | None
    intended_touch: str
    elapsed_seconds: float | None


def modhex_encode(data: bytes) -> str:
    return data.hex().translate(HEX_TO_MODHEX)


def modhex_decode(value: str) -> bytes:
    normalized = value.lower()
    if not normalized or any(char not in MODHEX_ALPHABET for char in normalized):
        raise ValueError("invalid Modhex")
    return bytes.fromhex(normalized.translate(MODHEX_TO_HEX))


def analyze_otp(
    value: str,
    previous_public_id: str | None = None,
    intended_touch: str = "Unspecified",
    elapsed_seconds: float | None = None,
) -> OtpAnalysis:
    enter_appended = value.endswith(("\n", "\r"))
    stripped = value.rstrip("\r\n")
    lowered = stripped.lower()
    valid_modhex = bool(lowered) and all(char in MODHEX_ALPHABET for char in lowered)
    public_id = lowered[:12] if len(lowered) >= 12 and valid_modhex else ""
    encrypted_length = max(0, len(lowered) - 12) if public_id else 0
    prefix_matches = None if not previous_public_id or not public_id else public_id == previous_public_id
    return OtpAnalysis(
        redacted=redact_otp(stripped),
        total_length=len(stripped),
        alphabet="".join(sorted(set(lowered))),
        valid_modhex=valid_modhex,
        public_id=public_id,
        encrypted_length=encrypted_length,
        enter_appended=enter_appended,
        prefix_matches_previous=prefix_matches,
        intended_touch=intended_touch,
        elapsed_seconds=elapsed_seconds,
    )

