"""
Header widget for the SecureVault application.
"""
from PyQt6.QtWidgets import (
    QWidget, QHBoxLayout, QLabel, QToolButton, QMenu
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QIcon, QAction

from LINUX_GUI.config import styles


class Header(QWidget):
    """Application header with title and user controls."""
    
    # Signals
    show_account = pyqtSignal()
    show_settings = pyqtSignal()
    sign_out = pyqtSignal()
    
    def __init__(self, parent=None):
        """Initialize the header widget."""
        super().__init__(parent)
        self.setObjectName("header")
        
        self.setup_ui()
    
    def setup_ui(self):
        """Initialize the UI components."""
        layout = QHBoxLayout(self)
        layout.setContentsMargins(20, 10, 20, 10)
        
        # App logo and title
        title_layout = QHBoxLayout()
        title_layout.setSpacing(10)
        
        # Logo
        self.logo = QLabel("SV")
        self.logo.setObjectName("logo")
        self.logo.setFixedSize(32, 32)
        
        # App title
        self.title = QLabel("SecureVault")
        self.title.setObjectName("app_title")
        
        title_layout.addWidget(self.logo)
        title_layout.addWidget(self.title)
        title_layout.addStretch()
        
        # Account section
        self.account_layout = QHBoxLayout()
        self.account_layout.setSpacing(10)
        
        # User button
        self.user_btn = QToolButton()
        self.user_btn.setText("User")
        self.user_btn.setIcon(QIcon.fromTheme("avatar-default"))
        self.user_btn.setToolButtonStyle(
            Qt.ToolButtonStyle.ToolButtonTextBesideIcon
        )
        self.user_btn.setPopupMode(
            QToolButton.ToolButtonPopupMode.InstantPopup
        )
        self.user_btn.setObjectName("accountButton")
        
        # Create account menu
        self.setup_account_menu()
        
        # Add to layout
        self.account_layout.addWidget(self.user_btn)
        
        # Add layouts to header
        layout.addLayout(title_layout)
        layout.addStretch()
        layout.addLayout(self.account_layout)
        
        # Apply styles
        self.setStyleSheet(styles.BASE_STYLE)
    
    def setup_account_menu(self):
        """Set up the account dropdown menu."""
        menu = QMenu(self)
        
        # Menu actions
        account_action = QAction("My Account", self)
        settings_action = QAction("Settings", self)
        signout_action = QAction("Sign Out", self)
        
        # Connect actions
        account_action.triggered.connect(self.show_account)
        settings_action.triggered.connect(self.show_settings)
        signout_action.triggered.connect(self.sign_out)
        
        # Add actions to menu
        menu.addAction(account_action)
        menu.addAction(settings_action)
        menu.addSeparator()
        menu.addAction(signout_action)
        
        # Set menu to button
        self.user_btn.setMenu(menu)
    
    def set_user_info(self, name, email=None):
        """Set the user information in the header.
        
        Args:
            name (str): The user's name
            email (str, optional): The user's email address
        """
        self.user_btn.setText(name)
        # Store email for later use if needed
        self._user_email = email
