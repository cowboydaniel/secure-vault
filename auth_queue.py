"""Authentication request queue backed by a semaphore.

This module centralises throttling for memory-hard authentication operations
such as Argon2 derivations.  Expensive calls are funneled through the
``AuthQueue`` which enforces an upper bound on concurrent work while emitting
diagnostic metrics that help detect abuse.
"""

from __future__ import annotations

import logging
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterator


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class QueueSnapshot:
    """Immutable view of the queue metrics for observability."""

    total_requests: int
    total_wait_time: float
    max_wait_time: float
    max_queue_depth: int
    current_waiters: int


class AuthQueue:
    """Semaphore backed queue limiting concurrent Argon2 operations."""

    def __init__(
        self,
        max_concurrent: int = 2,
        *,
        wait_warning_threshold: float = 1.0,
        metrics_log_interval: int = 50,
    ) -> None:
        if max_concurrent < 1:
            raise ValueError("max_concurrent must be at least 1")
        if metrics_log_interval < 1:
            raise ValueError("metrics_log_interval must be at least 1")

        self._max_concurrent = max_concurrent
        self._wait_warning_threshold = wait_warning_threshold
        self._metrics_log_interval = metrics_log_interval
        self._semaphore = threading.BoundedSemaphore(max_concurrent)
        self._lock = threading.Lock()

        # Metrics
        self._total_requests = 0
        self._total_wait_time = 0.0
        self._max_wait_time = 0.0
        self._max_queue_depth = 0
        self._current_waiters = 0

    @property
    def max_concurrent(self) -> int:
        """Return the configured concurrency limit."""

        return self._max_concurrent

    def snapshot(self) -> QueueSnapshot:
        """Return a snapshot of current metrics."""

        with self._lock:
            return QueueSnapshot(
                total_requests=self._total_requests,
                total_wait_time=self._total_wait_time,
                max_wait_time=self._max_wait_time,
                max_queue_depth=self._max_queue_depth,
                current_waiters=self._current_waiters,
            )

    @contextmanager
    def acquire(self, operation: str = "argon2") -> Iterator[None]:
        """Acquire the queue for the duration of an expensive operation."""

        wait_time = 0.0
        queue_depth = 0

        if self._semaphore.acquire(blocking=False):
            # Immediate acquisition
            pass
        else:
            start = time.monotonic()
            with self._lock:
                self._current_waiters += 1
                queue_depth = self._current_waiters
                if queue_depth > self._max_queue_depth:
                    self._max_queue_depth = queue_depth

            self._semaphore.acquire()
            wait_time = time.monotonic() - start

            with self._lock:
                self._current_waiters -= 1

        total_requests, avg_wait = self._record_metrics(wait_time, queue_depth)

        if wait_time > 0:
            level = logging.WARNING if wait_time >= self._wait_warning_threshold else logging.INFO
            snapshot = self.snapshot()
            logger.log(
                level,
                "AuthQueue contention for %s: wait=%.3fs queue_depth=%d current_waiters=%d "
                "limit=%d total=%d avg_wait=%.3fs",
                operation,
                wait_time,
                queue_depth,
                snapshot.current_waiters,
                self._max_concurrent,
                snapshot.total_requests,
                avg_wait,
            )

        if total_requests % self._metrics_log_interval == 0:
            snapshot = self.snapshot()
            average_wait = 0.0
            if snapshot.total_requests:
                average_wait = snapshot.total_wait_time / snapshot.total_requests
            logger.info(
                "AuthQueue metrics: total=%d avg_wait=%.3fs max_wait=%.3fs max_depth=%d current_waiters=%d limit=%d",
                snapshot.total_requests,
                average_wait,
                snapshot.max_wait_time,
                snapshot.max_queue_depth,
                snapshot.current_waiters,
                self._max_concurrent,
            )

        try:
            yield
        finally:
            self._semaphore.release()

    def _record_metrics(self, wait_time: float, queue_depth: int) -> tuple[int, float]:
        with self._lock:
            self._total_requests += 1
            self._total_wait_time += wait_time
            if wait_time > self._max_wait_time:
                self._max_wait_time = wait_time
            if queue_depth > self._max_queue_depth:
                self._max_queue_depth = queue_depth

            total_requests = self._total_requests
            average_wait = (
                self._total_wait_time / total_requests if total_requests else 0.0
            )

        return total_requests, average_wait

