"""
Header widget for the SecureVault application.
"""
from PyQt6.QtWidgets import (
    QWidget, QHBoxLayout, QLabel, QToolButton, QMenu
)
from PyQt6.QtCore import Qt, pyqtSignal, QTimer
from PyQt6.QtGui import QIcon, QAction

from LINUX_GUI.config import styles


class Header(QWidget):
    """Application header with title and user controls."""

    # Signals
    show_account = pyqtSignal()
    show_settings = pyqtSignal()
    sign_out = pyqtSignal()
    lock_screen = pyqtSignal()
    
    def __init__(self, parent=None):
        """Initialize the header widget."""
        super().__init__(parent)
        self.setObjectName("header")

        self._session_expires_at = None
        self._session_timer = QTimer(self)
        self._session_timer.timeout.connect(self._update_session_timeout)
        self._session_timer.setInterval(1000)  # Update every second

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

        # Session timeout indicator
        self.session_timeout_label = QLabel()
        self.session_timeout_label.setObjectName("sessionTimeout")
        self.session_timeout_label.setStyleSheet("color: #a0a0a0; font-size: 11px;")
        self.session_timeout_label.setVisible(False)
        self.account_layout.addWidget(self.session_timeout_label)

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
        lock_action = QAction("Lock Screen", self)
        lock_action.setShortcut("Ctrl+L")
        signout_action = QAction("Sign Out", self)

        # Connect actions
        account_action.triggered.connect(self.show_account)
        settings_action.triggered.connect(self.show_settings)
        lock_action.triggered.connect(self.lock_screen)
        signout_action.triggered.connect(self.sign_out)

        # Add actions to menu
        menu.addAction(account_action)
        menu.addAction(settings_action)
        menu.addSeparator()
        menu.addAction(lock_action)
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

    def set_session_expiration(self, expires_at):
        """Set the session expiration time and start the countdown.

        Args:
            expires_at: datetime object or timestamp when the session expires
        """
        from datetime import datetime

        if isinstance(expires_at, (int, float)):
            self._session_expires_at = datetime.fromtimestamp(expires_at)
        else:
            self._session_expires_at = expires_at

        self.session_timeout_label.setVisible(True)
        self._session_timer.start()
        self._update_session_timeout()

    def clear_session_timeout(self):
        """Clear the session timeout indicator."""
        self._session_timer.stop()
        self.session_timeout_label.setVisible(False)
        self._session_expires_at = None

    def _update_session_timeout(self):
        """Update the session timeout indicator."""
        if not self._session_expires_at:
            return

        from datetime import datetime

        now = datetime.now()
        remaining = self._session_expires_at - now

        if remaining.total_seconds() <= 0:
            self.session_timeout_label.setText("Session expired")
            self.session_timeout_label.setStyleSheet("color: #ff4444; font-size: 11px;")
            self._session_timer.stop()
            return

        # Format the remaining time
        total_seconds = int(remaining.total_seconds())
        minutes = total_seconds // 60
        seconds = total_seconds % 60

        if minutes > 5:
            # Show in minutes only if more than 5 minutes
            self.session_timeout_label.setText(f"Session expires in {minutes}m")
            self.session_timeout_label.setStyleSheet("color: #a0a0a0; font-size: 11px;")
        elif minutes > 2:
            # Show warning color when less than 5 minutes
            self.session_timeout_label.setText(f"Session expires in {minutes}m {seconds}s")
            self.session_timeout_label.setStyleSheet("color: #FFC107; font-size: 11px;")
        else:
            # Show critical color when less than 2 minutes
            self.session_timeout_label.setText(f"Session expires in {minutes}m {seconds}s")
            self.session_timeout_label.setStyleSheet("color: #ff4444; font-size: 11px;")
