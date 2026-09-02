from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from .sanitize import sanitize_log_message


@dataclass(frozen=True, slots=True)
class LogEntry:
    timestamp: str
    level: str
    message: str


class AuditLog:
    def __init__(self) -> None:
        self.entries: list[LogEntry] = []

    def add(self, level: str, message: str) -> None:
        safe = sanitize_log_message(message)
        self.entries.append(LogEntry(datetime.now().strftime("%H:%M:%S"), level, safe))

    def text(self) -> str:
        return "\n".join(f"[{entry.timestamp}] {entry.level}: {entry.message}" for entry in self.entries)

