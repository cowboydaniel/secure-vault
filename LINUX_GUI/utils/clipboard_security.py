"""
Clipboard security manager for SecureVault.
Automatically clears clipboard after a specified timeout.
"""
from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import QTimer, QObject, pyqtSignal


class ClipboardSecurityManager(QObject):
    """Manager for secure clipboard operations."""

    clipboard_cleared = pyqtSignal()

    def __init__(self, timeout_ms=30000, parent=None):
        """Initialize the clipboard security manager.

        Args:
            timeout_ms: Time in milliseconds before clearing clipboard (default: 30000ms = 30s)
            parent: Parent QObject
        """
        super().__init__(parent)
        self.timeout_ms = timeout_ms
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.clear_clipboard)
        self.clipboard = QApplication.clipboard()
        self.last_text = ""

        # Monitor clipboard changes
        self.clipboard.dataChanged.connect(self.on_clipboard_changed)

    def on_clipboard_changed(self):
        """Handle clipboard content changes."""
        # Restart timer when clipboard changes
        if self.timer.isActive():
            self.timer.stop()

        # Only start timer if clipboard has text
        if self.clipboard.text():
            self.last_text = self.clipboard.text()
            self.timer.start(self.timeout_ms)

    def clear_clipboard(self):
        """Clear the clipboard."""
        self.clipboard.clear()
        self.timer.stop()
        self.last_text = ""
        self.clipboard_cleared.emit()

    def copy_secure(self, text):
        """Copy text to clipboard with auto-clear enabled.

        Args:
            text: Text to copy to clipboard
        """
        self.clipboard.setText(text)
        # Timer will start automatically via on_clipboard_changed

    def set_timeout(self, timeout_ms):
        """Set the auto-clear timeout.

        Args:
            timeout_ms: Timeout in milliseconds
        """
        self.timeout_ms = timeout_ms

        # Restart timer with new timeout if currently active
        if self.timer.isActive():
            self.timer.stop()
            self.timer.start(self.timeout_ms)

    def disable_auto_clear(self):
        """Disable automatic clipboard clearing."""
        if self.timer.isActive():
            self.timer.stop()

    def enable_auto_clear(self):
        """Enable automatic clipboard clearing."""
        if self.clipboard.text() and not self.timer.isActive():
            self.timer.start(self.timeout_ms)
