from __future__ import annotations

import ctypes
from ctypes import wintypes

from .device import get_hid_caps
from .models import CommandMetadata, Confidence, DeviceSnapshot, LegacyProbeResult, OperationClass


STATUS_COMMAND = CommandMetadata(
    name="YubiKey legacy status feature report",
    opcode_or_report_id="GetFeature report 0, 9-byte buffer",
    known_purpose="Read firmware, programming sequence, touch/slot status bits",
    operation_class=OperationClass.READ_ONLY,
    confidence=Confidence.CONFIRMED,
    source="Yubico yubikey-personalization ykcore/ykcore_windows.c and ykdef.h",
)

UNKNOWN_WRITE_COMMAND = CommandMetadata(
    name="ZUKEY legacy slot write",
    opcode_or_report_id="unknown",
    known_purpose="Potential Slot 1 programming",
    operation_class=OperationClass.UNKNOWN,
    confidence=Confidence.UNKNOWN,
    source="No ZUKEY 2 protocol documentation found",
    targets_slot=1,
    requires_developer_mode=True,
)


def build_status_feature_buffer() -> bytes:
    return bytes(9)


def parse_yubikey_status(raw: bytes) -> LegacyProbeResult:
    if len(raw) != 9:
        raise ValueError("legacy status response must be 9 bytes including report ID")
    payload = raw[1:]
    touch_level = int.from_bytes(payload[4:6], "little")
    return LegacyProbeResult(
        protocol_status="Compatible",
        protocol_confidence=Confidence.CONFIRMED,
        slot1_status="Configured" if touch_level & 0x01 else "Empty",
        slot1_confidence=Confidence.CONFIRMED,
        slot2_status="Configured" if touch_level & 0x02 else "Empty",
        slot2_confidence=Confidence.CONFIRMED,
        firmware=f"{payload[0]}.{payload[1]}.{payload[2]}",
        programming_sequence=payload[3],
        touch_level=touch_level,
        raw_response=raw.hex(),
        evidence=["9-byte YubiKey-compatible status report returned"],
    )


def _get_feature(path: str, length: int) -> bytes:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    hid_dll = ctypes.WinDLL("hid", use_last_error=True)
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    hid_dll.HidD_GetFeature.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.ULONG]
    hid_dll.HidD_GetFeature.restype = wintypes.BOOLEAN
    handle = kernel32.CreateFileW(path, 0x40000000, 3, None, 3, 0, None)
    if handle == wintypes.HANDLE(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        buffer = (ctypes.c_ubyte * length).from_buffer_copy(build_status_feature_buffer())
        if not hid_dll.HidD_GetFeature(handle, buffer, length):
            raise ctypes.WinError(ctypes.get_last_error())
        return bytes(buffer)
    finally:
        kernel32.CloseHandle(handle)


def probe_legacy_status(device: DeviceSnapshot) -> LegacyProbeResult:
    result = LegacyProbeResult()
    keyboard = next(
        (
            interface
            for interface in device.hid_interfaces
            if interface.interface_number == 1 and interface.usage_page == 0x01 and interface.usage == 0x06
        ),
        None,
    )
    if keyboard is None:
        result.protocol_status = "Not detected"
        result.protocol_confidence = Confidence.CONFIRMED
        result.evidence.append("No expected MI_01 keyboard HID collection found")
        return result
    try:
        _, _, feature_size = get_hid_caps(keyboard.path)
        result.evidence.append(f"MI_01 HID feature report length: {feature_size} bytes")
        if feature_size == 0:
            result.protocol_status = "Not detected"
            result.protocol_confidence = Confidence.CONFIRMED
            result.evidence.extend(
                [
                    "Yubico OTP protocol requires 9-byte HID feature reports; descriptor advertises none",
                    "Slot 1 remains unknown; no safe response establishes presence or writability",
                    "Slot 2 configured is inferred only from observed long-touch OTP output",
                ]
            )
            return result
        if feature_size < 9:
            result.protocol_status = "Partially compatible"
            result.protocol_confidence = Confidence.CONFIRMED
            result.evidence.append("Feature report exists but is shorter than Yubico 9-byte status transport")
            return result
        return parse_yubikey_status(_get_feature(keyboard.path, 9))
    except Exception as exc:
        result.error = str(exc)
        result.evidence.append(f"Read-only status probe failed: {exc}")
        return result

