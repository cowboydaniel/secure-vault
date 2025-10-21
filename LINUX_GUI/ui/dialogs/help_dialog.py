"""
Help dialog for the SecureVault application.
"""
from PyQt6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, 
                           QTextEdit, QDialogButtonBox, QTabWidget, QWidget)
from PyQt6.QtCore import Qt

class HelpDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Help")
        self.setMinimumSize(600, 400)
        
        # Create tab widget
        tabs = QTabWidget()
        
        # Help tab
        help_tab = QWidget()
        help_layout = QVBoxLayout(help_tab)
        
        help_text = QTextEdit()
        help_text.setReadOnly(True)
        help_text.setHtml("""
        <h2>SecureVault Help</h2>
        <h3>Getting Started</h3>
        <p>Welcome to SecureVault! Here's how to get started:</p>
        <ul>
            <li><b>Encrypt Files</b>: Click 'Encrypt File' to secure your files with strong encryption.</li>
            <li><b>Decrypt Files</b>: Use 'Decrypt File' to access your encrypted files.</li>
            <li><b>Manage Keys</b>: Use the Key Manager to handle your encryption keys.</li>
        </ul>
        <h3>Keyboard Shortcuts</h3>
        <ul>
            <li><b>Ctrl+E</b>: Encrypt file</li>
            <li><b>Ctrl+D</b>: Decrypt file</li>
            <li><b>Ctrl+K</b>: Key Manager</li>
            <li><b>Ctrl+Q</b>: Quit application</li>
        </ul>
        """)
        help_layout.addWidget(help_text)
        
        # Add tabs
        tabs.addTab(help_tab, "Help")
        
        # Close button
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        
        # Main layout
        layout = QVBoxLayout(self)
        layout.addWidget(tabs)
        layout.addWidget(buttons)
