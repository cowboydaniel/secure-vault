"""
Settings dialog for the SecureVault application.
"""
from PyQt6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, 
                           QPushButton, QTabWidget, QWidget, QFormLayout,
                           QComboBox, QCheckBox, QDialogButtonBox)
from PyQt6.QtCore import Qt

class SettingsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Settings")
        self.setMinimumSize(600, 400)
        
        # Create tab widget
        tabs = QTabWidget()
        
        # General tab
        general_tab = QWidget()
        general_layout = QFormLayout(general_tab)
        
        # Theme selection
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["Dark", "Light", "System"])
        general_layout.addRow("Theme:", self.theme_combo)
        
        # Auto-update
        self.auto_update = QCheckBox("Check for updates automatically")
        self.auto_update.setChecked(True)
        general_layout.addRow(self.auto_update)
        
        # Security tab
        security_tab = QWidget()
        security_layout = QFormLayout(security_tab)
        
        # Auto-lock settings
        self.auto_lock = QComboBox()
        self.auto_lock.addItems(["Never", "1 minute", "5 minutes", "15 minutes", "30 minutes"])
        security_layout.addRow("Auto-lock after:", self.auto_lock)
        
        # Clear clipboard
        self.clear_clipboard = QCheckBox("Clear clipboard after 30 seconds")
        self.clear_clipboard.setChecked(True)
        security_layout.addRow(self.clear_clipboard)
        
        # Add tabs
        tabs.addTab(general_tab, "General")
        tabs.addTab(security_tab, "Security")
        
        # Buttons
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | 
            QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        
        # Main layout
        layout = QVBoxLayout(self)
        layout.addWidget(tabs)
        layout.addWidget(buttons)
