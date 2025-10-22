"""About dialog for the SecureVault application."""

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QDialog, QVBoxLayout, QLabel, QDialogButtonBox

class AboutDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("About SecureVault")
        self.setMinimumSize(400, 300)
        
        layout = QVBoxLayout(self)
        
        # Title
        title = QLabel("<h1>SecureVault</h1>")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # Version
        version = QLabel("Version 1.0.0")
        version.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # Description
        description = QLabel(
            "A secure file encryption and management tool\n\n"
            "© 2025 SecureVault. All rights reserved.\n"
            "Licensed under the MIT License"
        )
        description.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # Close button
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        
        # Add widgets to layout
        layout.addStretch()
        layout.addWidget(title)
        layout.addWidget(version)
        layout.addSpacing(20)
        layout.addWidget(description)
        layout.addStretch()
        layout.addWidget(buttons)
