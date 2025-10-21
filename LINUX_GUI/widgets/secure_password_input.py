"""
Secure password input widget with strength meter.
"""
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLineEdit, QLabel, QProgressBar,
    QPushButton
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QIcon


class SecurePasswordInput(QWidget):
    """Password input widget with strength meter and show/hide toggle."""

    textChanged = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()

    def setup_ui(self):
        """Initialize the UI components."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)

        # Input row
        input_layout = QHBoxLayout()
        input_layout.setSpacing(4)

        self.input_field = QLineEdit()
        self.input_field.setEchoMode(QLineEdit.EchoMode.Password)
        self.input_field.setPlaceholderText("Enter password...")
        self.input_field.textChanged.connect(self.on_text_changed)

        self.btn_toggle = QPushButton("Show")
        self.btn_toggle.setMaximumWidth(60)
        self.btn_toggle.clicked.connect(self.toggle_visibility)

        input_layout.addWidget(self.input_field)
        input_layout.addWidget(self.btn_toggle)

        # Strength meter
        strength_layout = QHBoxLayout()
        strength_layout.setSpacing(4)

        self.strength_label = QLabel("Strength:")
        self.strength_label.setStyleSheet("font-size: 10px; color: #a0a0a0;")

        self.strength_bar = QProgressBar()
        self.strength_bar.setMaximumHeight(6)
        self.strength_bar.setTextVisible(False)
        self.strength_bar.setRange(0, 100)
        self.strength_bar.setValue(0)

        self.strength_text = QLabel("None")
        self.strength_text.setStyleSheet("font-size: 10px; color: #a0a0a0;")

        strength_layout.addWidget(self.strength_label)
        strength_layout.addWidget(self.strength_bar, 1)
        strength_layout.addWidget(self.strength_text)

        # Add to main layout
        layout.addLayout(input_layout)
        layout.addLayout(strength_layout)

    def toggle_visibility(self):
        """Toggle password visibility."""
        if self.input_field.echoMode() == QLineEdit.EchoMode.Password:
            self.input_field.setEchoMode(QLineEdit.EchoMode.Normal)
            self.btn_toggle.setText("Hide")
        else:
            self.input_field.setEchoMode(QLineEdit.EchoMode.Password)
            self.btn_toggle.setText("Show")

    def on_text_changed(self, text):
        """Handle text changes and update strength meter."""
        strength, label, color = self.calculate_password_strength(text)

        self.strength_bar.setValue(strength)
        self.strength_text.setText(label)

        # Update strength bar color
        self.strength_bar.setStyleSheet(f"""
            QProgressBar {{
                border: 1px solid #2a3a5c;
                border-radius: 3px;
                background-color: #1a1a2e;
            }}
            QProgressBar::chunk {{
                background-color: {color};
                border-radius: 2px;
            }}
        """)

        self.strength_text.setStyleSheet(f"font-size: 10px; color: {color};")

        # Emit signal
        self.textChanged.emit(text)

    def calculate_password_strength(self, password):
        """Calculate password strength.

        Returns:
            tuple: (strength_percent, label, color)
        """
        if not password:
            return 0, "None", "#a0a0a0"

        strength = 0
        length = len(password)

        # Length score (max 40 points)
        if length >= 12:
            strength += 40
        elif length >= 8:
            strength += 25
        elif length >= 6:
            strength += 15
        else:
            strength += 5

        # Character variety score (max 60 points)
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)

        variety_score = sum([has_lower, has_upper, has_digit, has_special]) * 15
        strength += variety_score

        # Determine label and color
        if strength < 30:
            return strength, "Weak", "#ff4444"
        elif strength < 60:
            return strength, "Fair", "#FFC107"
        elif strength < 85:
            return strength, "Good", "#4CAF50"
        else:
            return strength, "Strong", "#2196F3"

    def text(self):
        """Get the password text."""
        return self.input_field.text()

    def clear(self):
        """Clear the password input."""
        self.input_field.clear()

    def setEnabled(self, enabled):
        """Enable or disable the widget."""
        super().setEnabled(enabled)
        self.input_field.setEnabled(enabled)
        self.btn_toggle.setEnabled(enabled)
