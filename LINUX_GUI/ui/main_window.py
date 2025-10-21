"""
Main window for the SecureVault application.
"""
import os
import sys
from pathlib import Path

# Add the project root to the Python path
project_root = str(Path(__file__).parent.parent.parent)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from PyQt6.QtWidgets import (
    QMainWindow, QVBoxLayout, QWidget, QStackedWidget, QMessageBox
)
from PyQt6.QtGui import QIcon, QAction
from PyQt6.QtCore import Qt, QSize

# Import from config and local modules
from LINUX_GUI.config import styles, settings as app_settings
from .dialogs import SettingsDialog, AccountDialog, HelpDialog, AboutDialog
from .widgets import Header, Footer


class MainWindow(QMainWindow):
    """Main application window for SecureVault."""
    
    def __init__(self):
        """Initialize the main window."""
        super().__init__()
        self.setWindowTitle("SecureVault")
        self.setMinimumSize(1000, 700)
        
        # Load settings
        self.settings = app_settings.get_settings()
        
        # Set up the UI
        self.setup_ui()
        
        # Apply styles
        self.apply_styles()
    
    def setup_ui(self):
        """Initialize the UI components."""
        # Create menu bar
        self.create_menu_bar()
        
        # Create main widget and layout
        self.main_widget = QWidget()
        self.main_layout = QVBoxLayout(self.main_widget)
        self.main_layout.setContentsMargins(0, 0, 0, 0)
        self.main_layout.setSpacing(0)
        self.setCentralWidget(self.main_widget)
        
        # Create header
        self.header = Header()
        self.main_layout.addWidget(self.header, 0)  # 0 for no stretch
        
        # Connect header signals
        self.header.show_account.connect(self.show_account)
        self.header.show_settings.connect(self.show_settings)
        self.header.sign_out.connect(self.sign_out)
        
        # Create content area
        self.content_widget = QWidget()
        self.content_layout = QVBoxLayout(self.content_widget)
        self.content_layout.setContentsMargins(40, 20, 40, 20)
        self.content_layout.setSpacing(0)
        
        # Stacked widget for different views
        self.stacked_widget = QStackedWidget()
        self.content_layout.addWidget(self.stacked_widget)
        
        # Add content to main layout
        self.main_layout.addWidget(self.content_widget, 1)  # 1 is stretch factor
        
        # Create footer
        self.footer = Footer()
        self.main_layout.addWidget(self.footer, 0)  # 0 for no stretch
        
        # Set window icon if available
        if os.path.exists(app_settings.ICON_PATH):
            self.setWindowIcon(QIcon(app_settings.ICON_PATH))
        
        # Create and add main menu
        self.create_main_menu()
    
    def create_menu_bar(self):
        """Create the main menu bar."""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu("&File")
        
        new_action = QAction("&New...", self)
        new_action.setShortcut("Ctrl+N")
        file_menu.addAction(new_action)
        
        open_action = QAction("&Open...", self)
        open_action.setShortcut("Ctrl+O")
        file_menu.addAction(open_action)
        
        file_menu.addSeparator()
        
        settings_action = QAction("&Settings...", self)
        settings_action.triggered.connect(self.show_settings)
        settings_action.setShortcut("Ctrl+,")
        file_menu.addAction(settings_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction("E&xit", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Edit menu
        edit_menu = menubar.addMenu("&Edit")
        
        cut_action = QAction("Cu&t", self)
        cut_action.setShortcut("Ctrl+X")
        edit_menu.addAction(cut_action)
        
        copy_action = QAction("&Copy", self)
        copy_action.setShortcut("Ctrl+C")
        edit_menu.addAction(copy_action)
        
        paste_action = QAction("&Paste", self)
        paste_action.setShortcut("Ctrl+V")
        edit_menu.addAction(paste_action)
        
        # View menu
        view_menu = menubar.addMenu("&View")
        
        zoom_in = QAction("Zoom &In", self)
        zoom_in.setShortcut("Ctrl++")
        view_menu.addAction(zoom_in)
        
        zoom_out = QAction("Zoom &Out", self)
        zoom_out.setShortcut("Ctrl+-")
        view_menu.addAction(zoom_out)
        
        view_menu.addSeparator()
        
        fullscreen = QAction("&Full Screen", self)
        fullscreen.setShortcut("F11")
        fullscreen.setCheckable(True)
        fullscreen.triggered.connect(self.toggle_fullscreen)
        view_menu.addAction(fullscreen)
        
        # Help menu
        help_menu = menubar.addMenu("&Help")
        
        help_action = QAction("&Help", self)
        help_action.setShortcut("F1")
        help_action.triggered.connect(self.show_help)
        help_menu.addAction(help_action)
        
        about_action = QAction("&About", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
    
    def create_main_menu(self):
        """Create the main menu widget."""
        from PyQt6.QtWidgets import QVBoxLayout, QLabel, QPushButton
        
        menu_widget = QWidget()
        layout = QVBoxLayout(menu_widget)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setContentsMargins(0, 40, 0, 40)
        
        # Title with modern styling
        title = QLabel("Welcome to SecureVault")
        title.setObjectName("title")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # Subtitle
        subtitle = QLabel("Secure File Encryption & Management")
        subtitle.setObjectName("subtitle")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # Buttons
        btn_encrypt = QPushButton("Encrypt File")
        btn_encrypt.clicked.connect(self.show_encrypt_view)
        btn_encrypt.setMinimumSize(240, 48)
        
        btn_decrypt = QPushButton("Decrypt File")
        btn_decrypt.clicked.connect(self.show_decrypt_view)
        btn_decrypt.setMinimumSize(240, 48)
        
        btn_key_manager = QPushButton("Key Manager")
        btn_key_manager.clicked.connect(self.show_key_manager)
        btn_key_manager.setMinimumSize(240, 48)
        
        # Button layout
        button_layout = QVBoxLayout()
        button_layout.setSpacing(12)
        button_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        button_layout.addWidget(btn_encrypt)
        button_layout.addWidget(btn_decrypt)
        button_layout.addWidget(btn_key_manager)
        
        # Add widgets to layout with proper spacing
        layout.addStretch()
        layout.addWidget(title)
        layout.addWidget(subtitle)
        layout.addSpacing(40)
        layout.addLayout(button_layout)
        layout.addStretch()
        
        # Add to stacked widget
        self.stacked_widget.addWidget(menu_widget)
    
    def apply_styles(self):
        """Apply styles to the window and its children."""
        self.setStyleSheet(styles.BASE_STYLE)
    
    def toggle_fullscreen(self, checked):
        """Toggle fullscreen mode."""
        if checked:
            self.showFullScreen()
        else:
            self.showNormal()
    
    # Slots for actions
    def show_encrypt_view(self):
        """Show the encrypt file view."""
        self.footer.set_status("Preparing to encrypt file...")
        QMessageBox.information(self, "Info", "Encrypt view will be implemented here")
        self.footer.set_status("Ready", 3000)
    
    def show_decrypt_view(self):
        """Show the decrypt file view."""
        self.footer.set_status("Preparing to decrypt file...")
        QMessageBox.information(self, "Info", "Decrypt view will be implemented here")
        self.footer.set_status("Ready", 3000)
    
    def show_key_manager(self):
        """Show the key manager."""
        self.footer.set_status("Opening Key Manager...")
        QMessageBox.information(self, "Info", "Key manager will be implemented here")
        self.footer.set_status("Ready", 3000)
    
    def show_settings(self):
        """Show the settings dialog."""
        dialog = SettingsDialog(self)
        if dialog.exec():
            self.footer.set_status("Settings saved", 3000)
    
    def show_account(self):
        """Show the account dialog."""
        dialog = AccountDialog(self)
        dialog.exec()
    
    def show_help(self):
        """Show the help dialog."""
        dialog = HelpDialog(self)
        dialog.exec()
    
    def show_about(self):
        """Show the about dialog."""
        dialog = AboutDialog(self)
        dialog.exec()
    
    def sign_out(self):
        """Handle sign out action."""
        reply = QMessageBox.question(
            self,
            'Sign Out',
            'Are you sure you want to sign out?',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            self.footer.set_status("Signed out successfully", 3000)
            # TODO: Implement sign out logic
            print("User signed out")
