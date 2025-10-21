"""
Account dialog for the SecureVault application.
"""
from PyQt6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, 
                           QPushButton, QLineEdit, QFormLayout, QDialogButtonBox)
from PyQt6.QtGui import QPixmap, QPainter, QColor
from PyQt6.QtCore import Qt, QRect

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
        font = painter.font()
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
        
        # Button box for standard buttons
        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        button_box.rejected.connect(self.reject)
        
        # Layout
        layout.addWidget(user_info)
        layout.addSpacing(10)
        layout.addWidget(avatar, 0, Qt.AlignmentFlag.AlignCenter)
        layout.addSpacing(10)
        layout.addWidget(user_name)
        layout.addWidget(user_email)
        layout.addSpacing(20)
        
        # Add buttons with center alignment
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        button_layout.addWidget(btn_change_pw)
        button_layout.addWidget(btn_sign_out)
        button_layout.addStretch()
        
        layout.addLayout(button_layout)
        layout.addStretch()
        layout.addWidget(button_box)
