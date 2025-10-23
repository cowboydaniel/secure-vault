"""Accessible PIN pad widget for SecureVault."""

from __future__ import annotations

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QKeyEvent
from PyQt6.QtWidgets import (
    QFrame,
    QGridLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
)


class AccessiblePinPad(QFrame):
    """Screen-reader and keyboard friendly PIN pad."""

    digit_pressed = pyqtSignal(str)
    backspace_pressed = pyqtSignal()
    clear_pressed = pyqtSignal()

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setFrameShape(QFrame.Shape.StyledPanel)
        self.setAccessibleName("Secure PIN pad")
        self.setAccessibleDescription(
            "On-screen keypad for entering PIN codes with keyboard shortcuts and screen reader guidance."
        )

        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        instruction = QLabel(
            "Use Tab to focus the keypad, arrow keys to move, or press digits on your keyboard."
        )
        instruction.setWordWrap(True)
        instruction.setAccessibleName("PIN pad instructions")
        layout.addWidget(instruction)

        grid = QGridLayout()
        grid.setSpacing(4)
        layout.addLayout(grid)

        self._buttons: dict[str, QPushButton] = {}
        digits = ["1", "2", "3", "4", "5", "6", "7", "8", "9", "", "0", "⌫"]
        positions = [(row, col) for row in range(4) for col in range(3)]

        for position, digit in zip(positions, digits, strict=True):
            row, col = position
            if digit == "":
                clear_button = QPushButton("Clear")
                clear_button.setAccessibleName("Clear PIN entry")
                clear_button.setAccessibleDescription(
                    "Clear all digits currently entered in the PIN field."
                )
                clear_button.clicked.connect(self.clear_pressed.emit)
                clear_button.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
                grid.addWidget(clear_button, row, col)
                self._buttons["clear"] = clear_button
                continue

            button = QPushButton(digit)
            button.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
            button.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
            button.setShortcut(digit)
            if digit == "⌫":
                button.setAccessibleName("Backspace")
                button.setAccessibleDescription("Remove the last digit from the PIN entry field.")
                button.clicked.connect(self.backspace_pressed.emit)
                button.setShortcut(Qt.Key.Key_Backspace)
            else:
                button.setAccessibleName(f"Digit {digit}")
                button.setAccessibleDescription(f"Enter digit {digit} into the PIN field.")
                button.clicked.connect(lambda checked=False, d=digit: self.digit_pressed.emit(d))
            grid.addWidget(button, row, col)
            key = "backspace" if digit == "⌫" else digit
            self._buttons[key] = button

    def focus_first_button(self) -> None:
        """Set focus on the first button for keyboard navigation."""

        if self._buttons:
            next(iter(self._buttons.values())).setFocus()

    def keyPressEvent(self, event: QKeyEvent) -> None:
        key = event.key()
        if Qt.Key.Key_0 <= key <= Qt.Key.Key_9:
            self.digit_pressed.emit(str(key - Qt.Key.Key_0))
            event.accept()
            return
        if key in (Qt.Key.Key_Backspace, Qt.Key.Key_Delete):
            self.backspace_pressed.emit()
            event.accept()
            return
        if key in (Qt.Key.Key_Escape,):
            self.clear_pressed.emit()
            event.accept()
            return
        super().keyPressEvent(event)


__all__ = ["AccessiblePinPad"]

