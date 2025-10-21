"""
Custom button widgets for SecureVault Linux GUI
"""
from PyQt6.QtWidgets import QPushButton, QSizePolicy
from PyQt6.QtCore import Qt, QSize
from PyQt6.QtGui import QIcon

class PrimaryButton(QPushButton):
    """Primary action button with custom styling"""
    def __init__(self, text="", parent=None, icon=None):
        super().__init__(text, parent)
        self.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)
        self.setMinimumHeight(40)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        
        if icon:
            self.setIcon(icon)
            self.setIconSize(QSize(20, 20))
        
        self.setStyleSheet("""
            QPushButton {
                background-color: #4a86e8;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: 500;
                min-width: 120px;
            }
            QPushButton:hover {
                background-color: #3a76d8;
            }
            QPushButton:pressed {
                background-color: #2a66c8;
            }
            QPushButton:disabled {
                background-color: #a0a0a0;
                color: #e0e0e0;
            }
        """)

class SecondaryButton(QPushButton):
    """Secondary action button with custom styling"""
    def __init__(self, text="", parent=None, icon=None):
        super().__init__(text, parent)
        self.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)
        self.setMinimumHeight(40)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        
        if icon:
            self.setIcon(icon)
            self.setIconSize(QSize(20, 20))
        
        self.setStyleSheet("""
            QPushButton {
                background-color: #f0f0f0;
                color: #333333;
                border: 1px solid #cccccc;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: 500;
                min-width: 120px;
            }
            QPushButton:hover {
                background-color: #e0e0e0;
                border-color: #bbbbbb;
            }
            QPushButton:pressed {
                background-color: #d0d0d0;
            }
            QPushButton:disabled {
                background-color: #f5f5f5;
                color: #a0a0a0;
                border-color: #dddddd;
            }
        """)
