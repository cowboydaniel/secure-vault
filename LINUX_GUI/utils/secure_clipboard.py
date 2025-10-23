"""Secure clipboard helper for the SecureVault GUI."""

from __future__ import annotations

import threading
import time
from typing import Optional

from PyQt6.QtCore import QObject, Qt, pyqtSignal, pyqtSlot
from PyQt6.QtGui import QClipboard
from PyQt6.QtWidgets import QApplication


class SecureClipboard(QObject):
    """Copy text to the clipboard and clear it after a timeout."""

    cleared = pyqtSignal()
    _clear_requested = pyqtSignal(str, int)

    def __init__(
        self,
        timeout_seconds: float = 30.0,
        *,
        enabled: bool = True,
        parent: Optional[QObject] = None,
    ) -> None:
        super().__init__(parent)
        self._clipboard = QApplication.clipboard()
        self._timeout_seconds = max(0.0, float(timeout_seconds))
        self._enabled = bool(enabled)
        self._lock = threading.Lock()
        self._generation = 0

        self._clear_requested.connect(
            self._perform_clear,
            Qt.ConnectionType.QueuedConnection,
        )

    def copy(self, text: Optional[str], timeout_seconds: Optional[float] = None) -> None:
        """Copy *text* to the clipboard and clear it after ``timeout_seconds``."""

        normalized = "" if text is None else str(text)

        with self._lock:
            self._generation += 1
            generation = self._generation
            enabled = self._enabled
            default_timeout = self._timeout_seconds

        self._clipboard.setText(normalized)

        if not enabled:
            return

        if timeout_seconds is None:
            effective_timeout = default_timeout
        else:
            effective_timeout = max(0.0, float(timeout_seconds))

        thread = threading.Thread(
            target=self._delayed_clear,
            args=(normalized, effective_timeout, generation),
            daemon=True,
        )
        thread.start()

    def clear(self) -> None:
        """Immediately clear the clipboard contents."""

        with self._lock:
            self._generation += 1
            generation = self._generation
            text = self._clipboard.text(mode=QClipboard.Mode.Clipboard)

        self._perform_clear(text, generation)

    def set_timeout(self, timeout_seconds: float) -> None:
        """Update the default timeout for subsequent copies."""

        with self._lock:
            self._timeout_seconds = max(0.0, float(timeout_seconds))
            self._generation += 1

    def set_enabled(self, enabled: bool) -> None:
        """Enable or disable automatic clearing."""

        with self._lock:
            self._enabled = bool(enabled)
            self._generation += 1

    def is_enabled(self) -> bool:
        """Return ``True`` if automatic clearing is enabled."""

        with self._lock:
            return self._enabled

    def _delayed_clear(self, text: str, timeout: float, generation: int) -> None:
        if timeout > 0:
            time.sleep(timeout)

        self._clear_requested.emit(text, generation)

    @pyqtSlot(str, int)
    def _perform_clear(self, expected_text: str, generation: int) -> None:
        with self._lock:
            if generation != self._generation:
                return

        current_text = self._clipboard.text(mode=QClipboard.Mode.Clipboard)
        if current_text != expected_text:
            return

        self._clipboard.clear(mode=QClipboard.Mode.Clipboard)

        try:
            self._clipboard.clear(mode=QClipboard.Mode.Selection)
        except AttributeError:
            pass

        self.cleared.emit()

