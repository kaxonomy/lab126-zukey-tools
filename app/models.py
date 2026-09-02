from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


EXPECTED_VID = 0x1949
EXPECTED_PID = 0x0429


class Confidence(StrEnum):
    CONFIRMED = "CONFIRMED"
    INFERRED = "INFERRED"
    UNKNOWN = "UNKNOWN"


class OperationClass(StrEnum):
    READ_ONLY = "read-only"
    PERSISTENT = "persistent"
    DESTRUCTIVE = "destructive"
    UNKNOWN = "unknown"


@dataclass(slots=True)
class HidInterface:
    path: str
    interface_number: int
    usage_page: int
    usage: int
    product: str
    manufacturer: str
    serial: str
    input_report_bytes: int | None = None
    output_report_bytes: int | None = None
    feature_report_bytes: int | None = None


@dataclass(slots=True)
class PnpDescriptor:
    status: str
    device_class: str
    friendly_name: str
    instance_id: str


@dataclass(slots=True)
class DeviceSnapshot:
    connected: bool = False
    product: str = "ZUKEY 2 HID"
    manufacturer: str = "Amazon / Lab126"
    serial: str = ""
    vid: int = EXPECTED_VID
    pid: int = EXPECTED_PID
    hid_interfaces: list[HidInterface] = field(default_factory=list)
    pnp_descriptors: list[PnpDescriptor] = field(default_factory=list)
    fido_paths: list[str] = field(default_factory=list)
    other_fido_devices: list[str] = field(default_factory=list)
    admin: bool = False
    error: str = ""


@dataclass(slots=True)
class FidoSnapshot:
    available: bool = False
    selected_path: str = ""
    properties: dict[str, Any] = field(default_factory=dict)
    raw_properties: dict[str, Any] = field(default_factory=dict)
    error: str = ""


@dataclass(frozen=True, slots=True)
class CommandMetadata:
    name: str
    opcode_or_report_id: str
    known_purpose: str
    operation_class: OperationClass
    confidence: Confidence
    source: str
    targets_slot: int | None = None
    requires_developer_mode: bool = False


@dataclass(slots=True)
class LegacyProbeResult:
    protocol_status: str = "Unknown"
    protocol_confidence: Confidence = Confidence.UNKNOWN
    slot1_status: str = "Unknown"
    slot1_confidence: Confidence = Confidence.UNKNOWN
    slot2_status: str = "Configured"
    slot2_confidence: Confidence = Confidence.INFERRED
    firmware: str = ""
    programming_sequence: int | None = None
    touch_level: int | None = None
    raw_response: str = ""
    evidence: list[str] = field(default_factory=list)
    error: str = ""


def model_dict(value: Any) -> dict[str, Any]:
    return asdict(value)

