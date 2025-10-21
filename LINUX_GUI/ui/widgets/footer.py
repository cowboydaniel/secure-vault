"""
Footer widget for the SecureVault application.
"""
from PyQt6.QtWidgets import QWidget, QHBoxLayout, QLabel
from PyQt6.QtCore import Qt

from LINUX_GUI.config import styles


class Footer(QWidget):
    """Application footer with status and version information."""
    
    def __init__(self, parent=None):
        """Initialize the footer widget."""
        super().__init__(parent)
        self.setObjectName("footer")
        
        self.setup_ui()
    
    def setup_ui(self):
        """Initialize the UI components."""
        layout = QHBoxLayout(self)
        layout.setContentsMargins(20, 10, 20, 10)
        
        # Status label
        self.status_label = QLabel("Ready")
        self.status_label.setObjectName("statusLabel")
        
        # Version info
        self.version_label = QLabel("SecureVault v1.0.0")
        self.version_label.setObjectName("versionLabel")
        
        # Add widgets to layout
        layout.addWidget(self.status_label)
        layout.addStretch()
        layout.addWidget(self.version_label)
        
        # Apply styles
        self.setStyleSheet(styles.BASE_STYLE)
    
    def set_status(self, message, timeout=0):
        """Set the status message.
        
        Args:
            message (str): The status message to display
            timeout (int, optional): Time in milliseconds before clearing the message.
                                   If 0, the message remains until changed.
        """
        self.status_label.setText(message)
        if timeout > 0:
            # Clear the message after the timeout
            from PyQt6.QtCore import QTimer
            QTimer.singleShot(timeout, lambda: self.clear_status())
    
    def clear_status(self):
        """Clear the status message."""
        self.status_label.clear()
    
    def set_version(self, version):
        """Set the version information.
        
        Args:
            version (str): The version string to display
        """
        self.version_label.setText(f"SecureVault {version}")
