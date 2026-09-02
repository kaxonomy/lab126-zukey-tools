from __future__ import annotations

import ctypes
from ctypes import wintypes
import json
import subprocess

import hid

from .models import DeviceSnapshot, EXPECTED_PID, EXPECTED_VID, HidInterface, PnpDescriptor


class HidpCaps(ctypes.Structure):
    _fields_ = [
        ("usage", ctypes.c_ushort),
        ("usage_page", ctypes.c_ushort),
        ("input_report_bytes", ctypes.c_ushort),
        ("output_report_bytes", ctypes.c_ushort),
        ("feature_report_bytes", ctypes.c_ushort),
        ("reserved", ctypes.c_ushort * 17),
        ("number_link_collection_nodes", ctypes.c_ushort),
        ("number_input_button_caps", ctypes.c_ushort),
        ("number_input_value_caps", ctypes.c_ushort),
        ("number_input_data_indices", ctypes.c_ushort),
        ("number_output_button_caps", ctypes.c_ushort),
        ("number_output_value_caps", ctypes.c_ushort),
        ("number_output_data_indices", ctypes.c_ushort),
        ("number_feature_button_caps", ctypes.c_ushort),
        ("number_feature_value_caps", ctypes.c_ushort),
        ("number_feature_data_indices", ctypes.c_ushort),
    ]


def _path_text(path: bytes | str) -> str:
    return path.decode(errors="replace") if isinstance(path, bytes) else path


def is_admin() -> bool:
    return bool(ctypes.windll.shell32.IsUserAnAdmin())


def get_hid_caps(path: str) -> tuple[int, int, int]:
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
    hid_dll.HidD_GetPreparsedData.argtypes = [wintypes.HANDLE, ctypes.POINTER(ctypes.c_void_p)]
    hid_dll.HidD_GetPreparsedData.restype = wintypes.BOOLEAN
    hid_dll.HidD_FreePreparsedData.argtypes = [ctypes.c_void_p]
    hid_dll.HidP_GetCaps.argtypes = [ctypes.c_void_p, ctypes.POINTER(HidpCaps)]
    hid_dll.HidP_GetCaps.restype = ctypes.c_long
    handle = kernel32.CreateFileW(path, 0, 3, None, 3, 0, None)
    if handle == wintypes.HANDLE(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    preparsed = ctypes.c_void_p()
    try:
        if not hid_dll.HidD_GetPreparsedData(handle, ctypes.byref(preparsed)):
            raise ctypes.WinError(ctypes.get_last_error())
        caps = HidpCaps()
        status = hid_dll.HidP_GetCaps(preparsed, ctypes.byref(caps))
        if status < 0:
            raise OSError(f"HidP_GetCaps failed: 0x{status & 0xFFFFFFFF:08x}")
        return caps.input_report_bytes, caps.output_report_bytes, caps.feature_report_bytes
    finally:
        if preparsed:
            hid_dll.HidD_FreePreparsedData(preparsed)
        kernel32.CloseHandle(handle)


def _pnp_descriptors() -> list[PnpDescriptor]:
    script = r"""
$items = Get-PnpDevice -PresentOnly | Where-Object { $_.InstanceId -match 'VID_1949&PID_0429' } |
  Select-Object Status,Class,FriendlyName,InstanceId
$items | ConvertTo-Json -Compress
"""
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", script],
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    )
    if not result.stdout.strip():
        return []
    raw = json.loads(result.stdout)
    rows = raw if isinstance(raw, list) else [raw]
    return [
        PnpDescriptor(
            status=row.get("Status", ""),
            device_class=row.get("Class", ""),
            friendly_name=row.get("FriendlyName", ""),
            instance_id=row.get("InstanceId", ""),
        )
        for row in rows
    ]


def discover_device() -> DeviceSnapshot:
    snapshot = DeviceSnapshot(admin=is_admin())
    try:
        snapshot.pnp_descriptors = _pnp_descriptors()
        for item in hid.enumerate(EXPECTED_VID, EXPECTED_PID):
            path = _path_text(item["path"])
            try:
                input_size, output_size, feature_size = get_hid_caps(path)
            except OSError:
                input_size = output_size = feature_size = None
            interface = HidInterface(
                path=path,
                interface_number=item.get("interface_number", -1),
                usage_page=item.get("usage_page", 0),
                usage=item.get("usage", 0),
                product=item.get("product_string") or "",
                manufacturer=item.get("manufacturer_string") or "",
                serial=item.get("serial_number") or "",
                input_report_bytes=input_size,
                output_report_bytes=output_size,
                feature_report_bytes=feature_size,
            )
            snapshot.hid_interfaces.append(interface)
            snapshot.product = interface.product or snapshot.product
            snapshot.manufacturer = interface.manufacturer or snapshot.manufacturer
            snapshot.serial = snapshot.serial or interface.serial
        snapshot.connected = bool(snapshot.pnp_descriptors or snapshot.hid_interfaces)
    except Exception as exc:
        snapshot.error = str(exc)
    return snapshot

