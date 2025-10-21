"""
Settings dialog for the SecureVault application.
"""
from PyQt6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel,
                           QPushButton, QTabWidget, QWidget, QFormLayout,
                           QComboBox, QCheckBox, QDialogButtonBox)
from PyQt6.QtCore import Qt, pyqtSignal


class SettingsDialog(QDialog):
    """Settings dialog with theme and security options."""

    theme_changed = pyqtSignal(str)  # Emits theme name ('dark' or 'light')

    def __init__(self, current_theme='dark', parent=None):
        super().__init__(parent)
        self.current_theme = current_theme
        self.setWindowTitle("Settings")
        self.setMinimumSize(600, 400)

        # Create tab widget
        tabs = QTabWidget()

        # General tab
        general_tab = QWidget()
        general_layout = QFormLayout(general_tab)

        # Theme selection
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["Dark", "Light"])
        self.theme_combo.setCurrentText(current_theme.capitalize())
        general_layout.addRow("Theme:", self.theme_combo)

        # Auto-update
        self.auto_update = QCheckBox("Check for updates automatically")
        self.auto_update.setChecked(True)
        general_layout.addRow(self.auto_update)

        # System tray
        self.system_tray = QCheckBox("Enable system tray icon")
        self.system_tray.setChecked(True)
        general_layout.addRow(self.system_tray)

        # Security tab
        security_tab = QWidget()
        security_layout = QFormLayout(security_tab)

        # Auto-lock settings
        self.auto_lock = QComboBox()
        self.auto_lock.addItems(["Never", "1 minute", "5 minutes", "15 minutes", "30 minutes"])
        self.auto_lock.setCurrentIndex(3)  # Default to 15 minutes
        security_layout.addRow("Auto-lock after:", self.auto_lock)

        # Clear clipboard
        self.clear_clipboard = QCheckBox("Clear clipboard automatically")
        self.clear_clipboard.setChecked(True)
        security_layout.addRow(self.clear_clipboard)

        self.clipboard_timeout = QComboBox()
        self.clipboard_timeout.addItems(["10 seconds", "30 seconds", "1 minute", "5 minutes"])
        self.clipboard_timeout.setCurrentIndex(1)  # Default to 30 seconds
        security_layout.addRow("Clipboard timeout:", self.clipboard_timeout)

        # Add tabs
        tabs.addTab(general_tab, "General")
        tabs.addTab(security_tab, "Security")

        # Buttons
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok |
            QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.on_accept)
        buttons.rejected.connect(self.reject)

        # Main layout
        layout = QVBoxLayout(self)
        layout.addWidget(tabs)
        layout.addWidget(buttons)

    def on_accept(self):
        """Handle accept button click."""
        # Check if theme changed
        new_theme = self.theme_combo.currentText().lower()
        if new_theme != self.current_theme:
            self.theme_changed.emit(new_theme)

        self.accept()

    def get_settings(self):
        """Get the current settings as a dictionary."""
        return {
            'theme': self.theme_combo.currentText().lower(),
            'auto_update': self.auto_update.isChecked(),
            'system_tray': self.system_tray.isChecked(),
            'auto_lock': self.auto_lock.currentText(),
            'clear_clipboard': self.clear_clipboard.isChecked(),
            'clipboard_timeout': self.clipboard_timeout.currentText(),
        }
