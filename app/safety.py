from __future__ import annotations

from dataclasses import dataclass

from .models import CommandMetadata, OperationClass


@dataclass(slots=True)
class SafetyGate:
    developer_mode: bool = False
    experimental_writes: bool = False
    allow_slot2: bool = False

    def authorize(self, command: CommandMetadata, confirmed: bool = False) -> tuple[bool, str]:
        if command.operation_class == OperationClass.READ_ONLY:
            return True, "read-only command"
        if command.operation_class == OperationClass.UNKNOWN:
            return False, "unknown commands never default safe"
        if command.requires_developer_mode and not self.developer_mode:
            return False, "Developer / Experimental Mode is off"
        if command.targets_slot == 2 and not self.allow_slot2:
            return False, "long-touch Slot 2 writes disabled"
        if command.requires_developer_mode and not self.experimental_writes:
            return False, "Experimental writes is off"
        if not confirmed:
            return False, "individual confirmation required"
        return True, "confirmed"

