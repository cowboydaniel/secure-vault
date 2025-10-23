"""GUI regression automation for authentication flows."""

from __future__ import annotations

import os
import sys

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PyQt6.QtWidgets import QApplication
except ImportError as exc:  # pragma: no cover - environment-specific skip
    pytest.skip(f"PyQt6 unavailable: {exc}", allow_module_level=True)

from auth_manager import AuthManager, InvalidCredentialsError
from config import default_config
from LINUX_GUI.ui.dialogs.login_dialog import LoginDialog


class _StubPinManager:
    def hash_email_for_lookup(self, email: str) -> bytes:
        return email.encode("utf-8")


class _StubAuthManager:
    def __init__(self):
        self.pin_manager = _StubPinManager()

    def authenticate_with_pin(self, email: str, pin: str):  # pragma: no cover - invoked via GUI slot
        raise InvalidCredentialsError()


def _qt_app() -> QApplication:
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
    return app


@pytest.fixture
def qt_app(tmp_path) -> QApplication:
    original_dir = default_config.config_dir
    default_config.config_dir = str(tmp_path)
    app = _qt_app()
    yield app
    default_config.config_dir = original_dir


def test_login_dialog_pin_pad_accessibility(qt_app) -> None:
    dialog = LoginDialog(auth_manager=AuthManager())
    dialog.pin_pad.digit_pressed.emit("1")
    dialog.pin_pad.digit_pressed.emit("2")
    assert dialog.pin_edit.text() == "12"

    dialog.pin_pad.backspace_pressed.emit()
    assert dialog.pin_edit.text() == "1"

    dialog.pin_pad.clear_pressed.emit()
    assert dialog.pin_edit.text() == ""

    assert dialog.pin_edit.accessibleName() == "PIN entry"
    assert "keypad" in dialog.pin_pad.accessibleDescription().lower()


def test_login_dialog_invalid_credentials_shows_error(qt_app) -> None:
    dialog = LoginDialog(auth_manager=_StubAuthManager())
    dialog.email_edit.setText("user@example.com")
    dialog.pin_edit.setText("000000")

    dialog.accept()

    assert dialog.error_label.isVisible()
    assert "invalid email or pin" in dialog.error_label.text().lower()
