"""Backward-compatible wrapper around :class:`SecureClipboard`."""

from __future__ import annotations

from typing import Optional

from PyQt6.QtCore import QObject, pyqtSignal

from .secure_clipboard import SecureClipboard


class ClipboardSecurityManager(QObject):
    """Compatibility wrapper that exposes the legacy manager API."""

    clipboard_cleared = pyqtSignal()

    def __init__(self, timeout_ms: int = 30000, parent: Optional[QObject] = None) -> None:
        super().__init__(parent)
        self._secure_clipboard = SecureClipboard(
            timeout_seconds=timeout_ms / 1000.0,
            parent=self,
        )
        self._secure_clipboard.cleared.connect(self.clipboard_cleared.emit)

    def copy_secure(self, text: Optional[str], timeout_ms: Optional[int] = None) -> None:
        """Copy ``text`` to the clipboard and schedule automatic clearing."""

        timeout_seconds = None if timeout_ms is None else timeout_ms / 1000.0
        self._secure_clipboard.copy(text, timeout_seconds=timeout_seconds)

    def clear_clipboard(self) -> None:
        """Immediately clear the clipboard."""

        self._secure_clipboard.clear()

    def set_timeout(self, timeout_ms: int) -> None:
        """Update the default auto-clear timeout."""

        self._secure_clipboard.set_timeout(timeout_ms / 1000.0)

    def disable_auto_clear(self) -> None:
        """Disable automatic clipboard clearing."""

        self._secure_clipboard.set_enabled(False)

    def enable_auto_clear(self) -> None:
        """Enable automatic clipboard clearing."""

        self._secure_clipboard.set_enabled(True)

    @property
    def secure_clipboard(self) -> SecureClipboard:
        """Expose the underlying :class:`SecureClipboard` instance."""

        return self._secure_clipboard
