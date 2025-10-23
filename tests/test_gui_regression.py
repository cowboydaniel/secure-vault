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

from auth_manager import AuthManager
from config import default_config
from LINUX_GUI.ui.dialogs.login_dialog import LoginDialog


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
