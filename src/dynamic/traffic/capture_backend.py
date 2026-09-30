"""Traffic capture backend protocol and interface definition."""

from __future__ import annotations

from typing import Any, Callable, Protocol, runtime_checkable

from src.dynamic.traffic.models import TrafficTransaction


@runtime_checkable
class TrafficCaptureBackend(Protocol):
    """Protocol defining standard lifecycle and capabilities of a traffic capture engine."""

    def check_available(self) -> bool:
        """Returns True if the backend binary/dependencies are present and operational."""
        ...

    def start(
        self,
        listen_host: str,
        listen_port: int,
        on_transaction_captured: Callable[[TrafficTransaction], None] | None = None,
    ) -> None:
        """Starts the capture backend listening on the specified host and port."""
        ...

    def stop(self, timeout_seconds: float = 5.0) -> None:
        """Gracefully stops the capture backend and terminates child processes."""
        ...

    def is_alive(self) -> bool:
        """Checks if the underlying capture process or engine is actively running."""
        ...

    def get_captured_transactions(self) -> list[TrafficTransaction]:
        """Returns transactions accumulated during capture."""
        ...
