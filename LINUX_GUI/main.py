#!/usr/bin/env python3
"""
SecureVault - Linux GUI Application
"""
import sys
import os
from pathlib import Path

from PyQt6.QtWidgets import QApplication, QDialog, QVBoxLayout, QTextEdit, QDialogButtonBox, QTabWidget, QWidget
from PyQt6.QtCore import Qt

# Import MainWindow from the ui module
from ui.main_window import MainWindow

# Add the parent directory to the path to import secure_vault modules
sys.path.insert(0, str(Path(__file__).parent.parent))

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


class AccountDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Account")
        self.setMinimumSize(400, 300)
        
        layout = QVBoxLayout(self)
        
        # User info
        user_info = QLabel("<h2>User Account</h2>")
        user_info.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # User avatar (placeholder)
        avatar = QLabel()
        avatar.setFixedSize(80, 80)
        
        # Create a circular avatar
        pixmap = QPixmap(80, 80)
        pixmap.fill(Qt.GlobalColor.transparent)
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setBrush(QColor("#4a36b4"))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawEllipse(0, 0, 80, 80)
        
        # Add user initial
        font = QFont()
        font.setPointSize(32)
        font.setBold(True)
        painter.setFont(font)
        painter.setPen(QColor("#ffffff"))
        painter.drawText(QRect(0, 0, 80, 80), Qt.AlignmentFlag.AlignCenter, "U")
        painter.end()
        
        avatar.setPixmap(pixmap)
        avatar.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # User details
        user_name = QLabel("User Name")
        user_name.setAlignment(Qt.AlignmentFlag.AlignCenter)
        user_email = QLabel("user@example.com")
        user_email.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # Buttons
        btn_change_pw = QPushButton("Change Password")
        btn_sign_out = QPushButton("Sign Out")
        
        # Layout
        layout.addWidget(user_info)
        layout.addSpacing(10)
        layout.addWidget(avatar)
        layout.addSpacing(10)
        layout.addWidget(user_name)
        layout.addWidget(user_email)
        layout.addSpacing(20)
        layout.addWidget(btn_change_pw)
        layout.addWidget(btn_sign_out)
        layout.addStretch()


class HelpDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Help & About")
        self.setMinimumSize(600, 400)
        
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
        
        # About tab
        about_tab = QWidget()
        about_layout = QVBoxLayout(about_tab)
        
        about_text = QTextEdit()
        about_text.setReadOnly(True)
        about_text.setHtml("""
        <div style='text-align: center;'>
            <h1>SecureVault</h1>
            <p>Version 1.0.0</p>
            <p>A secure file encryption and management tool</p>
            <p>© 2025 SecureVault. All rights reserved.</p>
            <p>Licensed under the MIT License</p>
            <p><a href='https://github.com/yourusername/securevault'>GitHub Repository</a></p>
        </div>
        """)
        about_layout.addWidget(about_text)
        
        # Add tabs
        tabs.addTab(help_tab, "Help")
        tabs.addTab(about_tab, "About")
        
        # Close button
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        
        # Main layout
        layout = QVBoxLayout(self)
        layout.addWidget(tabs)
        layout.addWidget(buttons)
    
    def create_header(self):
        """Create the application header with account info"""
        header = QWidget()
        header.setObjectName("header")
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(20, 10, 20, 10)
        
        # App logo and title
        title_layout = QHBoxLayout()
        title_layout.setSpacing(10)
        
        # Logo placeholder (can be replaced with an actual image)
        logo = QLabel("SV")
        logo.setObjectName("logo")
        logo.setFixedSize(32, 32)
        
        title = QLabel("SecureVault")
        title.setObjectName("app_title")
        
        title_layout.addWidget(logo)
        title_layout.addWidget(title)
        title_layout.addStretch()
        
        # Account section
        account_layout = QHBoxLayout()
        account_layout.setSpacing(10)
        
        # User info
        user_btn = QToolButton()
        user_btn.setText("User")
        user_btn.setIcon(QIcon.fromTheme("avatar-default"))
        user_btn.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        user_btn.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        user_btn.setObjectName("accountButton")
    def show_key_manager(self):
        self.statusBar().showMessage("Opening Key Manager...")
        QMessageBox.information(self, "Info", "Key manager will be implemented here")
        self.statusBar().showMessage("Ready", 3000)
    
    def show_settings(self):
        """Show settings dialog"""
        dialog = SettingsDialog(self)
        if dialog.exec():
            # Save settings here
            self.statusBar().showMessage("Settings saved", 3000)
    
    def show_account(self):
        """Show account dialog"""
        dialog = AccountDialog(self)
        dialog.exec()
    
    def show_help(self):
        """Show help dialog"""
        dialog = HelpDialog(self)
        dialog.exec()
    
    def show_about(self):
        """Show about dialog"""
        QMessageBox.about(self, "About SecureVault",
            "<h2>SecureVault</h2>"
            "<p>Version 1.0.0</p>"
            "<p>A secure file encryption and management tool</p>"
            "<p>© 2025 SecureVault. All rights reserved.</p>"
        )
    
    def sign_out(self):
        """Handle sign out"""
        reply = QMessageBox.question(
            self, 'Sign Out',
            'Are you sure you want to sign out?',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            # Handle sign out logic here
            self.statusBar().showMessage("Signed out successfully", 3000)

def main():
    """Main entry point for the application."""
    # Enable high DPI scaling
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    
    # Create application instance
    app = QApplication(sys.argv)
    
    # Set application metadata
    app.setStyle('Fusion')  # Use Fusion style for a modern look
    app.setApplicationName("SecureVault")
    app.setApplicationVersion("1.0.0")
    app.setOrganizationName("SecureVault")
    app.setOrganizationDomain("securevault.example.com")
    
    # Set window icon if available
    icon_path = os.path.join(os.path.dirname(__file__), 'assets', 'icon.png')
    if os.path.exists(icon_path):
        app.setWindowIcon(QIcon(icon_path))
    
    try:
        # Create and show main window
        window = MainWindow()
        window.show()
        
        # Start the event loop
        return app.exec()
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    main()
