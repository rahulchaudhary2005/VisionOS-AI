from __future__ import annotations

from dataclasses import dataclass
from threading import Lock


@dataclass
class MetricsSnapshot:
    total_requests: int
    active_requests: int
    total_errors: int
    slow_requests: int
    average_response_time_ms: float


class MetricsCollector:
    """
    Thread-safe in-memory metrics collector.
    """

    def __init__(self) -> None:
        self._lock = Lock()

        self.total_requests = 0
        self.active_requests = 0
        self.total_errors = 0
        self.slow_requests = 0
        self.total_response_time = 0.0

    def request_started(self) -> None:
        with self._lock:
            self.total_requests += 1
            self.active_requests += 1

    def request_finished(
        self,
        duration_ms: float,
        status_code: int,
        slow_threshold_ms: float = 500,
    ) -> None:
        with self._lock:
            self.active_requests -= 1
            self.total_response_time += duration_ms

            if status_code >= 400:
                self.total_errors += 1

            if duration_ms >= slow_threshold_ms:
                self.slow_requests += 1

    def snapshot(self) -> MetricsSnapshot:
        with self._lock:
            average = (
                self.total_response_time / self.total_requests
                if self.total_requests
                else 0.0
            )

            return MetricsSnapshot(
                total_requests=self.total_requests,
                active_requests=self.active_requests,
                total_errors=self.total_errors,
                slow_requests=self.slow_requests,
                average_response_time_ms=round(average, 2),
            )


metrics = MetricsCollector()
