"""Minimal connector base types used by the standalone JXMIS client."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Literal

ConnectorStatus = Literal["disconnected", "starting", "qr_pending", "scanned", "active", "expired", "failed"]
QrCallback = Callable[[str], Awaitable[None]]
StatusCallback = Callable[[str, dict[str, Any]], Awaitable[None]]


@dataclass(slots=True)
class ConnectorLoginResult:
    ok: bool
    credentials: dict[str, Any] = field(default_factory=dict)
    qr_url: str = ""
    final_url: str = ""
    error_message: str = ""


class Connector:
    name = ""
    display_name = ""

    def __init__(self, config: Any) -> None:
        self.config = config
