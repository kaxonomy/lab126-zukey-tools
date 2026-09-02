from __future__ import annotations

import unittest
from unittest.mock import patch

from app.fido_backend import _authorized_paths
from app.legacy import UNKNOWN_WRITE_COMMAND, build_status_feature_buffer, parse_yubikey_status
from app.models import CommandMetadata, Confidence, OperationClass
from app.otp import analyze_otp, modhex_decode, modhex_encode
from app.sanitize import REDACTED, redact_otp, sanitize_diagnostics, sanitize_log_message
from app.safety import SafetyGate
from tests.fixtures.synthetic import make_fake_modhex_public_id, make_fake_otp, make_fake_serial


class OtpTests(unittest.TestCase):
    def test_modhex_round_trip(self) -> None:
        data = bytes(range(16))
        self.assertEqual(modhex_decode(modhex_encode(data)), data)

    def test_parse_44_character_otp(self) -> None:
        otp = make_fake_otp()
        public_id = make_fake_modhex_public_id()
        result = analyze_otp(otp + "\n", previous_public_id=public_id)
        self.assertEqual(result.total_length, 44)
        self.assertTrue(result.valid_modhex)
        self.assertEqual(result.public_id, public_id)
        self.assertEqual(result.encrypted_length, 32)
        self.assertTrue(result.enter_appended)
        self.assertTrue(result.prefix_matches_previous)

    def test_redaction(self) -> None:
        self.assertEqual(redact_otp(make_fake_otp()), f"{make_fake_modhex_public_id()}...{REDACTED}")

    def test_shared_diagnostics_redaction(self) -> None:
        serial = make_fake_serial()
        data = sanitize_diagnostics(
            {
                "serial": serial,
                "path": rf"USB\VID_1949&PID_0429\{serial}",
                "otp": make_fake_otp(),
                "public_id": make_fake_modhex_public_id(),
                "min_pin_length": 4,
            }
        )
        rendered = str(data)
        self.assertNotIn(serial, rendered)
        self.assertNotIn(make_fake_otp(), rendered)
        self.assertNotIn(make_fake_modhex_public_id(), data["public_id"])
        self.assertEqual(data["min_pin_length"], 4)

    def test_log_redaction(self) -> None:
        self.assertNotIn(make_fake_otp(), sanitize_log_message(make_fake_otp()))
        private_path = r"C:\Users" + r"\RealUser\capture.log"
        self.assertNotIn("RealUser", sanitize_log_message(private_path))


class SafetyTests(unittest.TestCase):
    def test_unknown_command_never_defaults_safe(self) -> None:
        allowed, _ = SafetyGate(True, True, False).authorize(UNKNOWN_WRITE_COMMAND, confirmed=True)
        self.assertFalse(allowed)

    def test_slot2_requires_explicit_launch_local_switch(self) -> None:
        command = CommandMetadata(
            "slot2 write",
            "0x03",
            "test",
            OperationClass.PERSISTENT,
            Confidence.CONFIRMED,
            "test",
            2,
            True,
        )
        allowed, _ = SafetyGate(True, True, False).authorize(command, confirmed=True)
        self.assertFalse(allowed)
        allowed, _ = SafetyGate(True, True, True).authorize(command, confirmed=True)
        self.assertTrue(allowed)


class ProtocolTests(unittest.TestCase):
    def test_fido_paths_are_bound_to_runtime_serial(self) -> None:
        serial = make_fake_serial()
        path = b"synthetic-fido-path"
        with patch(
            "app.fido_backend.hid.enumerate",
            return_value=[{"path": path, "serial_number": serial, "interface_number": 0}],
        ):
            self.assertEqual(_authorized_paths(serial), {path.decode()})
            self.assertEqual(_authorized_paths("different-synthetic-device"), set())

    def test_status_feature_request_buffer(self) -> None:
        self.assertEqual(build_status_feature_buffer(), bytes(9))

    def test_status_response_parser(self) -> None:
        raw = bytes([0, 4, 3, 1, 7, 3, 0, 0, 0])
        result = parse_yubikey_status(raw)
        self.assertEqual(result.firmware, "4.3.1")
        self.assertEqual(result.programming_sequence, 7)
        self.assertEqual(result.slot1_status, "Configured")
        self.assertEqual(result.slot2_status, "Configured")


if __name__ == "__main__":
    unittest.main()

