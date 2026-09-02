from __future__ import annotations

from dataclasses import fields
from typing import Any

import hid
from fido2.ctap2 import ClientPin, Ctap2
from fido2.ctap2.base import Info
from fido2.hid import CtapHidDevice

from .models import EXPECTED_PID, EXPECTED_VID, FidoSnapshot


def _safe_value(value: Any) -> Any:
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, dict):
        return {str(key): _safe_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_safe_value(item) for item in value]
    if hasattr(value, "hex") and callable(value.hex):
        try:
            return value.hex()
        except TypeError:
            pass
    return value


def _descriptor_path(device: CtapHidDevice) -> str:
    path = device.descriptor.path
    return path.decode(errors="replace") if isinstance(path, bytes) else str(path)


def _normalized_path(path: str) -> str:
    return path.casefold()


def _authorized_paths(serial: str) -> set[str]:
    if not serial:
        return set()
    return {
        _normalized_path(
            item["path"].decode(errors="replace") if isinstance(item["path"], bytes) else item["path"]
        )
        for item in hid.enumerate(EXPECTED_VID, EXPECTED_PID)
        if item.get("serial_number") == serial and item.get("interface_number") == 0
    }


def _info_properties(info: Info) -> dict[str, Any]:
    return {field.name: _safe_value(getattr(info, field.name)) for field in fields(Info)}


class FidoBackend:
    def list_devices(self, serial: str) -> tuple[list[str], list[str]]:
        target_paths: list[str] = []
        others: list[str] = []
        authorized_paths = _authorized_paths(serial)
        for device in CtapHidDevice.list_devices():
            try:
                descriptor = device.descriptor
                text = f"{descriptor.vid:04x}:{descriptor.pid:04x} {_descriptor_path(device)}"
                if (
                    descriptor.vid == EXPECTED_VID
                    and descriptor.pid == EXPECTED_PID
                    and _normalized_path(_descriptor_path(device)) in authorized_paths
                ):
                    target_paths.append(_descriptor_path(device))
                else:
                    others.append(text)
            finally:
                device.close()
        return target_paths, others

    def _open_target(self, serial: str, selected_path: str = "") -> CtapHidDevice:
        matches: list[CtapHidDevice] = []
        authorized_paths = _authorized_paths(serial)
        if not authorized_paths:
            raise RuntimeError("selected device serial not present on FIDO MI_00")
        for device in CtapHidDevice.list_devices():
            descriptor = device.descriptor
            path = _descriptor_path(device)
            if (
                descriptor.vid == EXPECTED_VID
                and descriptor.pid == EXPECTED_PID
                and _normalized_path(path) in authorized_paths
            ):
                matches.append(device)
            else:
                device.close()
        if not matches:
            raise RuntimeError("authorized FIDO interface not accessible; launch elevated and reconnect token")
        selected = next(
            (
                device
                for device in matches
                if not selected_path or _normalized_path(_descriptor_path(device)) == _normalized_path(selected_path)
            ),
            None,
        )
        if selected is None:
            for device in matches:
                device.close()
            raise RuntimeError("selected authorized FIDO path disappeared")
        for device in matches:
            if device is not selected:
                device.close()
        return selected

    def refresh(self, serial: str, selected_path: str = "") -> FidoSnapshot:
        snapshot = FidoSnapshot()
        try:
            device = self._open_target(serial, selected_path)
            try:
                info = Ctap2(device).get_info()
                snapshot.available = True
                snapshot.selected_path = _descriptor_path(device)
                snapshot.properties = _info_properties(info)
                snapshot.raw_properties = _safe_value(dict(info))
            finally:
                device.close()
        except Exception as exc:
            snapshot.error = str(exc)
        return snapshot

    def set_fido_pin(self, serial: str, pin: str, selected_path: str = "") -> None:
        device = self._open_target(serial, selected_path)
        try:
            ClientPin(Ctap2(device)).set_pin(pin)
        finally:
            device.close()

    def change_fido_pin(self, serial: str, old_pin: str, new_pin: str, selected_path: str = "") -> None:
        device = self._open_target(serial, selected_path)
        try:
            ClientPin(Ctap2(device)).change_pin(old_pin, new_pin)
        finally:
            device.close()

    def reset_fido(self, serial: str, selected_path: str = "") -> None:
        device = self._open_target(serial, selected_path)
        try:
            Ctap2(device).reset()
        finally:
            device.close()
