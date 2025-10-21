"""
System tray integration for SecureVault (Linux/cross-platform).
"""
from PyQt6.QtWidgets import QSystemTrayIcon, QMenu
from PyQt6.QtGui import QIcon, QAction
from PyQt6.QtCore import QObject, pyqtSignal


class SystemTrayManager(QObject):
    """Manager for system tray icon and menu."""

    show_window = pyqtSignal()
    quit_app = pyqtSignal()
    encrypt_requested = pyqtSignal()
    decrypt_requested = pyqtSignal()
    key_manager_requested = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.tray_icon = None
        self.menu = None
        self.setup_tray()

    def setup_tray(self):
        """Set up the system tray icon and menu."""
        # Create system tray icon
        self.tray_icon = QSystemTrayIcon(self.parent())

        # Set icon (use a simple built-in icon for now)
        icon = QIcon.fromTheme("security-high", QIcon.fromTheme("dialog-password"))
        self.tray_icon.setIcon(icon)

        # Create context menu
        self.menu = QMenu()

        # Add actions
        show_action = QAction("Show SecureVault", self.parent())
        show_action.triggered.connect(self.show_window.emit)

        encrypt_action = QAction("Encrypt File...", self.parent())
        encrypt_action.triggered.connect(self.encrypt_requested.emit)

        decrypt_action = QAction("Decrypt File...", self.parent())
        decrypt_action.triggered.connect(self.decrypt_requested.emit)

        key_manager_action = QAction("Key Manager", self.parent())
        key_manager_action.triggered.connect(self.key_manager_requested.emit)

        quit_action = QAction("Quit", self.parent())
        quit_action.triggered.connect(self.quit_app.emit)

        # Add actions to menu
        self.menu.addAction(show_action)
        self.menu.addSeparator()
        self.menu.addAction(encrypt_action)
        self.menu.addAction(decrypt_action)
        self.menu.addAction(key_manager_action)
        self.menu.addSeparator()
        self.menu.addAction(quit_action)

        # Set menu to tray icon
        self.tray_icon.setContextMenu(self.menu)

        # Connect double-click to show window
        self.tray_icon.activated.connect(self.on_activated)

        # Set tooltip
        self.tray_icon.setToolTip("SecureVault - Secure File Encryption")

    def on_activated(self, reason):
        """Handle tray icon activation."""
        if reason == QSystemTrayIcon.ActivationReason.DoubleClick:
            self.show_window.emit()

    def show(self):
        """Show the tray icon."""
        if self.tray_icon:
            self.tray_icon.show()

    def hide(self):
        """Hide the tray icon."""
        if self.tray_icon:
            self.tray_icon.hide()

    def is_visible(self):
        """Check if tray icon is visible."""
        return self.tray_icon.isVisible() if self.tray_icon else False

    def show_message(self, title, message, icon=QSystemTrayIcon.MessageIcon.Information, duration=3000):
        """Show a notification message.

        Args:
            title: Message title
            message: Message text
            icon: Message icon type
            duration: Display duration in milliseconds
        """
        if self.tray_icon and self.tray_icon.isVisible():
            self.tray_icon.showMessage(title, message, icon, duration)

    @staticmethod
    def is_system_tray_available():
        """Check if system tray is available on this system."""
        return QSystemTrayIcon.isSystemTrayAvailable()
