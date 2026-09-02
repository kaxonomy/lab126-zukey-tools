from __future__ import annotations

from dataclasses import asdict
import json
import time

from imgui_bundle import imgui, immapp

from .audit_log import AuditLog
from .device import discover_device
from .fido_backend import FidoBackend
from .legacy import STATUS_COMMAND, UNKNOWN_WRITE_COMMAND, probe_legacy_status
from .models import Confidence, DeviceSnapshot, EXPECTED_PID, EXPECTED_VID, FidoSnapshot, LegacyProbeResult
from .otp import OtpAnalysis, analyze_otp
from .sanitize import sanitize_diagnostics
from .safety import SafetyGate


def _value_text(value: object) -> str:
    if isinstance(value, (dict, list)):
        return json.dumps(value, indent=2, sort_keys=True)
    return str(value)


class ZukeyLabApp:
    def __init__(self) -> None:
        self.log = AuditLog()
        self.fido_backend = FidoBackend()
        self.device = DeviceSnapshot()
        self.fido = FidoSnapshot()
        self.legacy = LegacyProbeResult()
        self.safety = SafetyGate()
        self.otp_capture = ""
        self.otp_samples: list[OtpAnalysis] = []
        self.touch_label = "Unspecified"
        self.touch_started: float | None = None
        self.old_pin = ""
        self.new_pin = ""
        self.confirm_pin = ""
        self.pin_serial = ""
        self.reset_phrase = ""
        self.reset_serial = ""
        self.reset_timing_ack = False
        self.refresh_all()

    def refresh_all(self) -> None:
        self.device = discover_device()
        self.log.add("DEVICE", f"target {'connected' if self.device.connected else 'disconnected'} 1949:0429")
        try:
            paths, others = self.fido_backend.list_devices(self.device.serial)
            self.device.fido_paths = paths
            self.device.other_fido_devices = others
            if paths and self.fido.selected_path not in paths:
                self.fido.selected_path = paths[0]
        except Exception as exc:
            self.log.add("WARNING", f"FIDO enumeration unavailable: {exc}")
        self.refresh_fido()
        self.legacy = probe_legacy_status(self.device)
        self.log.add("RESEARCH", f"legacy protocol: {self.legacy.protocol_status}")

    def refresh_fido(self) -> None:
        self.fido = self.fido_backend.refresh(self.device.serial, self.fido.selected_path)
        if self.fido.available:
            self.log.add("FIDO", "CTAP2 getInfo succeeded")
        elif self.fido.error:
            self.log.add("WARNING", self.fido.error)

    def _kv(self, key: str, value: object) -> None:
        imgui.text(f"{key:<28} {_value_text(value)}")

    def _confidence(self, confidence: Confidence, text: str) -> None:
        colors = {
            Confidence.CONFIRMED: (0.3, 0.9, 0.45, 1.0),
            Confidence.INFERRED: (0.95, 0.75, 0.25, 1.0),
            Confidence.UNKNOWN: (0.75, 0.75, 0.75, 1.0),
        }
        imgui.text_colored(colors[confidence], f"{confidence}: {text}")

    def render(self) -> None:
        color = (0.3, 0.9, 0.45, 1.0) if self.device.connected else (1.0, 0.3, 0.3, 1.0)
        imgui.text_colored(
            color,
            f"ZUKEY 2 — {'Connected' if self.device.connected else 'Disconnected'} — 1949:0429 — {self.device.serial}",
        )
        if not self.device.admin:
            imgui.text_colored((1.0, 0.75, 0.2, 1.0), "Not elevated: Windows may hide FIDO HID. Use run.ps1.")
        if imgui.begin_tab_bar("MainTabs"):
            for label, renderer in (
                ("DEVICE", self._device_tab),
                ("FIDO2", self._fido_tab),
                ("FIDO MANAGEMENT", self._management_tab),
                ("OTP / TOUCH", self._otp_tab),
                ("LEGACY SLOT RESEARCH", self._legacy_tab),
            ):
                if imgui.begin_tab_item_simple(label):
                    renderer()
                    imgui.end_tab_item()
            imgui.end_tab_bar()
        imgui.separator_text("SANITIZED LOG")
        if imgui.button("Copy sanitized diagnostics"):
            imgui.set_clipboard_text(self.sanitized_diagnostics())
            self.log.add("INFO", "sanitized diagnostics copied")
        imgui.same_line()
        if imgui.button("Refresh all"):
            self.refresh_all()
        imgui.begin_child("log", (0, 150), imgui.ChildFlags_.borders)
        imgui.text_unformatted(self.log.text())
        imgui.end_child()

    def _device_tab(self) -> None:
        self._kv("Status", "Connected" if self.device.connected else "Disconnected")
        self._kv("Product", self.device.product)
        self._kv("Manufacturer", self.device.manufacturer)
        self._kv("Serial", self.device.serial)
        self._kv("VID/PID", f"{self.device.vid:04x}:{self.device.pid:04x}")
        self._kv("Expected model", f"{EXPECTED_VID:04x}:{EXPECTED_PID:04x}")
        self._kv("Elevated", self.device.admin)
        imgui.separator_text("HID interfaces")
        for interface in self.device.hid_interfaces:
            imgui.bullet_text(
                f"MI_{interface.interface_number:02d} usage {interface.usage_page:04x}:{interface.usage:04x} "
                f"reports IN={interface.input_report_bytes} OUT={interface.output_report_bytes} "
                f"FEATURE={interface.feature_report_bytes}"
            )
            imgui.text_wrapped(interface.path)
        imgui.separator_text("Windows PnP descriptors")
        for descriptor in self.device.pnp_descriptors:
            imgui.bullet_text(f"{descriptor.friendly_name} [{descriptor.device_class}] {descriptor.status}")
            imgui.text_wrapped(descriptor.instance_id)
        imgui.separator_text("FIDO selections")
        for path in self.device.fido_paths:
            imgui.bullet_text(f"AUTHORIZED TARGET: {path}")
        for item in self.device.other_fido_devices:
            imgui.bullet_text(f"OTHER KEY — never operated automatically: {item}")

    def _fido_tab(self) -> None:
        if len(self.device.fido_paths) > 1:
            current = self.device.fido_paths.index(self.fido.selected_path)
            changed, selected = imgui.combo("Authorized FIDO path", current, self.device.fido_paths)
            if changed:
                self.fido.selected_path = self.device.fido_paths[selected]
                self.refresh_fido()
        if imgui.button("Refresh CTAP2 getInfo"):
            self.refresh_fido()
        if not self.fido.available:
            imgui.text_colored((1.0, 0.45, 0.25, 1.0), self.fido.error or "FIDO unavailable")
            return
        options = self.fido.properties.get("options", {}) or {}
        extensions = self.fido.properties.get("extensions", []) or []
        for label, condition, yes, no in (
            ("Resident credentials", options.get("rk") is True, "Supported", "Not advertised"),
            ("FIDO PIN", options.get("clientPin") is True, "Configured", "Not configured / unavailable"),
            (
                "Biometric FIDO verification",
                options.get("bioEnroll") is True or options.get("uv") is True,
                "Supported",
                "Not supported",
            ),
            ("Credential management", options.get("credMgmt") is True, "Supported", "Not advertised"),
            ("hmac-secret", "hmac-secret" in extensions, "Supported", "Not advertised"),
        ):
            self._kv(label, yes if condition else no)
        imgui.separator_text("All GetInfo properties")
        for key, value in self.fido.properties.items():
            self._kv(key, value)
        if self.safety.developer_mode:
            imgui.separator_text("Raw CBOR map")
            imgui.text_wrapped(json.dumps(self.fido.raw_properties, indent=2, sort_keys=True))

    def _management_tab(self) -> None:
        imgui.text("STANDARD FIDO2 operations only. Legacy OTP configuration is separate.")
        if imgui.button("Test authenticator presence"):
            self.refresh_fido()
        imgui.same_line()
        imgui.text("Present" if self.fido.available else "Not accessible")
        options = self.fido.properties.get("options", {}) if self.fido.available else {}
        pin_configured = options.get("clientPin") is True
        flags = imgui.InputTextFlags_.password
        _, self.old_pin = imgui.input_text("Current PIN", self.old_pin, flags)
        _, self.new_pin = imgui.input_text("New PIN", self.new_pin, flags)
        _, self.confirm_pin = imgui.input_text("Confirm new PIN", self.confirm_pin, flags)
        _, self.pin_serial = imgui.input_text("Confirm target serial##pin", self.pin_serial)
        min_pin = int(self.fido.properties.get("min_pin_length") or 4)
        pin_ready = (
            self.fido.available
            and self.pin_serial == self.device.serial
            and self.new_pin == self.confirm_pin
            and len(self.new_pin) >= min_pin
        )
        imgui.begin_disabled(not pin_ready or pin_configured)
        if imgui.button("Set PIN"):
            try:
                self.fido_backend.set_fido_pin(self.device.serial, self.new_pin, self.fido.selected_path)
                self.log.add("FIDO", "PIN set on confirmed target")
                self.old_pin = self.new_pin = self.confirm_pin = ""
                self.refresh_fido()
            except Exception as exc:
                self.log.add("ERROR", f"Set PIN failed: {exc}")
        imgui.end_disabled()
        imgui.same_line()
        imgui.begin_disabled(not pin_ready or not pin_configured or not self.old_pin)
        if imgui.button("Change PIN"):
            try:
                self.fido_backend.change_fido_pin(
                    self.device.serial, self.old_pin, self.new_pin, self.fido.selected_path
                )
                self.log.add("FIDO", "PIN changed on confirmed target")
                self.old_pin = self.new_pin = self.confirm_pin = ""
                self.refresh_fido()
            except Exception as exc:
                self.log.add("ERROR", f"Change PIN failed: {exc}")
        imgui.end_disabled()
        imgui.separator_text("FIDO factory reset")
        if imgui.button("Reset FIDO"):
            self.reset_phrase = self.reset_serial = ""
            self.reset_timing_ack = False
            imgui.open_popup("Reset FIDO confirmation")
        opened, _ = imgui.begin_popup_modal(
            "Reset FIDO confirmation", None, imgui.WindowFlags_.always_auto_resize
        )
        if opened:
            imgui.text_colored((1.0, 0.35, 0.2, 1.0), "DESTRUCTIVE STANDARD FIDO2 RESET")
            imgui.bullet_text("Removes FIDO credentials")
            imgui.bullet_text("Removes FIDO PIN")
            imgui.bullet_text("May NOT affect separate legacy OTP configuration")
            imgui.text_wrapped(
                "Unplug/replug token, then issue reset promptly when authenticator accepts reset. "
                "No legacy OTP command is sent."
            )
            _, self.reset_phrase = imgui.input_text("Type RESET", self.reset_phrase)
            _, self.reset_serial = imgui.input_text("Confirm displayed serial", self.reset_serial)
            _, self.reset_timing_ack = imgui.checkbox(
                "I understand unplug/replug timing", self.reset_timing_ack
            )
            ready = (
                self.fido.available
                and self.reset_phrase == "RESET"
                and self.reset_serial == self.device.serial
                and self.reset_timing_ack
            )
            imgui.begin_disabled(not ready)
            if imgui.button("Issue authenticatorReset now"):
                try:
                    self.fido_backend.reset_fido(self.device.serial, self.fido.selected_path)
                    self.log.add("WARNING", "FIDO factory reset completed on confirmed target")
                    imgui.close_current_popup()
                    self.refresh_fido()
                except Exception as exc:
                    self.log.add("ERROR", f"FIDO reset failed: {exc}")
            imgui.end_disabled()
            imgui.same_line()
            if imgui.button("Cancel"):
                imgui.close_current_popup()
            imgui.end_popup()

    def _otp_tab(self) -> None:
        imgui.text("Focused capture only. No global keyboard hook. Full OTP never logged or saved.")
        imgui.bullet_text("Short tap: under ~2.5 seconds")
        imgui.bullet_text("1–2 second tap: observe whether anything appears")
        imgui.bullet_text("3–5 second hold: expected long-touch OTP")
        for label in ("Short tap", "1–2 second tap", "3–5 second hold"):
            if imgui.button(f"Arm {label}"):
                self.touch_label = label
                self.touch_started = time.monotonic()
                self.otp_capture = ""
            imgui.same_line()
        imgui.new_line()
        submitted, self.otp_capture = imgui.input_text(
            "Touch capture##otp", self.otp_capture, imgui.InputTextFlags_.enter_returns_true
        )
        imgui.same_line()
        analyze_clicked = imgui.button("Analyze capture")
        if (submitted or analyze_clicked) and self.otp_capture:
            previous = next((sample.public_id for sample in self.otp_samples if sample.public_id), None)
            elapsed = time.monotonic() - self.touch_started if self.touch_started is not None else None
            analysis = analyze_otp(
                self.otp_capture + ("\n" if submitted else ""),
                previous_public_id=previous,
                intended_touch=self.touch_label,
                elapsed_seconds=elapsed,
            )
            self.otp_samples.append(analysis)
            self.log.add(
                "OTP",
                f"captured {analysis.redacted} length={analysis.total_length} touch={analysis.intended_touch}",
            )
            self.otp_capture = ""
            self.touch_started = None
        if self.otp_samples:
            imgui.separator_text("Samples (memory only, redacted)")
            for index, sample in enumerate(self.otp_samples, 1):
                imgui.text(f"#{index} {sample.intended_touch} {sample.redacted}")
                self._kv("  total length", sample.total_length)
                self._kv("  alphabet", sample.alphabet)
                self._kv("  valid Modhex", sample.valid_modhex)
                self._kv("  first 12 / public ID", sample.public_id or "n/a")
                self._kv("  encrypted portion", sample.encrypted_length)
                self._kv("  Enter appended", sample.enter_appended)
                self._kv("  prefix matches prior", sample.prefix_matches_previous)
                elapsed = f"{sample.elapsed_seconds:.2f}s" if sample.elapsed_seconds is not None else "n/a"
                self._kv("  elapsed", elapsed)
        if imgui.button("Clear samples"):
            self.otp_samples.clear()

    def _legacy_tab(self) -> None:
        imgui.text("EXPERIMENTAL RESEARCH — write controls default OFF every launch")
        changed, self.safety.developer_mode = imgui.checkbox(
            "Developer / Experimental Mode", self.safety.developer_mode
        )
        if changed and not self.safety.developer_mode:
            self.safety.experimental_writes = False
            self.safety.allow_slot2 = False
        imgui.begin_disabled(not self.safety.developer_mode)
        _, self.safety.experimental_writes = imgui.checkbox(
            "Experimental writes", self.safety.experimental_writes
        )
        _, self.safety.allow_slot2 = imgui.checkbox(
            "Allow modifying long-touch Slot 2", self.safety.allow_slot2
        )
        imgui.end_disabled()
        if imgui.button("Run safe read-only compatibility probe"):
            allowed, reason = self.safety.authorize(STATUS_COMMAND)
            if allowed:
                self.legacy = probe_legacy_status(self.device)
                self.log.add("RESEARCH", f"legacy read-only probe: {self.legacy.protocol_status}")
            else:
                self.log.add("ERROR", reason)
        self._confidence(
            self.legacy.protocol_confidence,
            f"Legacy YubiKey protocol: {self.legacy.protocol_status}",
        )
        self._confidence(
            self.legacy.slot1_confidence,
            f"Slot 1 / short touch: {self.legacy.slot1_status}",
        )
        self._confidence(
            self.legacy.slot2_confidence,
            f"Slot 2 / long touch: {self.legacy.slot2_status}",
        )
        for evidence in self.legacy.evidence:
            imgui.bullet_text(evidence)
        if self.legacy.raw_response and self.safety.developer_mode:
            self._kv("Raw response", self.legacy.raw_response)
        imgui.separator_text("Program Short-Touch Slot")
        _, reason = self.safety.authorize(UNKNOWN_WRITE_COMMAND, confirmed=False)
        imgui.text_colored((1.0, 0.45, 0.25, 1.0), f"Blocked: {reason}")
        imgui.text_wrapped(
            "No write offered. MI_01 advertises zero feature-report bytes, so Yubico personalization "
            "transport is not detected. No safe response proves Slot 1 exists, is writable, or maps "
            "independently from provisioned long-touch behavior."
        )

    def sanitized_diagnostics(self) -> str:
        data = {
            "device": asdict(self.device),
            "fido": asdict(self.fido),
            "legacy": asdict(self.legacy),
            "otp_samples": [
                {
                    "redacted": sample.redacted,
                    "length": sample.total_length,
                    "public_id": sample.public_id,
                    "valid_modhex": sample.valid_modhex,
                    "touch": sample.intended_touch,
                    "elapsed_seconds": sample.elapsed_seconds,
                }
                for sample in self.otp_samples
            ],
            "log": self.log.text(),
        }
        return json.dumps(sanitize_diagnostics(data), indent=2, default=str)


def run() -> None:
    app = ZukeyLabApp()
    immapp.run(app.render, window_title="ZukeyLab", window_size=(1100, 820))
