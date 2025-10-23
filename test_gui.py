#!/usr/bin/env python3
"""Test script for SecureVault GUI.
Run this to verify the GUI is working correctly."""

import os
import sys
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

# Add project to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

try:
    from PyQt6.QtWidgets import QApplication, QLabel, QLineEdit
except ImportError as exc:  # pragma: no cover - environment-specific dependency
    pytest.skip(f"PyQt6 dependencies unavailable: {exc}", allow_module_level=True)

from LINUX_GUI.utils import safe_set_text
from LINUX_GUI.ui.dialogs.account_recovery_dialog import AccountRecoveryDialog
from LINUX_GUI.ui.dialogs.login_dialog import LoginDialog

REQUIRED_BUTTONS = {
    "Encrypt File",
    "Decrypt File",
    "Key Manager",
    "Secure Notes",
    "Activity Monitor",
    "Vault Health Check",
}


def main() -> int:
    """Smoke-test the SecureVault GUI without requiring a display server."""

    # Allow the GUI to run in CI/headless environments.
    try:
        from PyQt6.QtWidgets import QApplication, QPushButton
        from PyQt6.QtCore import Qt, QTimer

        from LINUX_GUI.ui.main_window import MainWindow
    except ImportError as exc:
        print(f"Error: Missing dependency - {exc}")
        if "libGL" in str(exc):
            print("The host system is missing libGL. Install mesa-libGL or an equivalent package.")
        else:
            print("Please install PyQt6: pip install PyQt6")
        return 1

    class DummyAuthManager:
        """Minimal stub used for GUI validation."""

        def logout(self, *_args, **_kwargs):  # pragma: no cover - defensive stub
            pass

    try:
        print("Starting SecureVault GUI test...")

        QApplication.setHighDpiScaleFactorRoundingPolicy(
            Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
        )

        app = QApplication(sys.argv)
        app.setStyle("Fusion")
        app.setApplicationName("SecureVault")
        app.setApplicationVersion("1.0.0")

        window = MainWindow(auth_manager=DummyAuthManager())
        window.show()

        def verify_buttons() -> None:
            discovered = {
                btn.text().strip()
                for btn in window.findChildren(QPushButton)
                if btn.isVisible()
            }

            print("Discovered main menu buttons:", ", ".join(sorted(discovered)))

            missing = REQUIRED_BUTTONS - discovered
            if missing:
                print("Missing buttons:", ", ".join(sorted(missing)))
                app.exit(1)
            else:
                print("All expected feature buttons are present.")
                app.exit(0)

        QTimer.singleShot(100, verify_buttons)

        return app.exec()

    except Exception as exc:  # pragma: no cover - diagnostic output for manual runs
        print(f"Error starting GUI: {exc}")
        import traceback

        traceback.print_exc()
        return 1


class _DummyAuditLogger:
    def log_event(self, *_args, **_kwargs):  # pragma: no cover - no-op stub
        pass


class _DummyPinManager:
    def hash_email_for_lookup(self, _email: str) -> bytes:  # pragma: no cover - stub
        return b"00"


class _DummyAuthManager:
    def __init__(self) -> None:
        self.pin_manager = _DummyPinManager()
        self.user_manager = None

    def authenticate_with_pin(self, *_args, **_kwargs):  # pragma: no cover - stub
        raise NotImplementedError


class _DummyRecoveryAuthManager(_DummyAuthManager):
    def __init__(self) -> None:
        super().__init__()

        class _DummyUserManager:
            pass

        self.user_manager = _DummyUserManager()


@pytest.fixture(scope="module")
def qapp():
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


def test_safe_set_text_label_escapes_html(qapp):
    label = QLabel()
    malicious = "<img src=x onerror=alert('xss')>"

    safe_set_text(label, malicious)

    assert "<img" not in label.text()
    assert "&lt;img" in label.text()


def test_safe_set_text_line_edit_preserves_literal_text(qapp):
    line_edit = QLineEdit()
    malicious = "<script>alert('boom')</script>"

    safe_set_text(line_edit, malicious)

    assert line_edit.text() == malicious


def test_login_dialog_error_label_escapes_html(qapp):
    dialog = LoginDialog(auth_manager=_DummyAuthManager(), audit_logger=_DummyAuditLogger())
    dialog._show_error("<b>attack</b>")

    assert "<b>" not in dialog.error_label.text()
    assert "&lt;b&gt;attack&lt;/b&gt;" == dialog.error_label.text()


def test_account_recovery_dialog_error_label_escapes_html(qapp):
    dialog = AccountRecoveryDialog(
        auth_manager=_DummyRecoveryAuthManager(),
        audit_logger=_DummyAuditLogger(),
    )
    dialog._show_error("<i>owned</i>")

    assert "<i>" not in dialog.error_label.text()
    assert "&lt;i&gt;owned&lt;/i&gt;" == dialog.error_label.text()


if __name__ == "__main__":
    sys.exit(main())
