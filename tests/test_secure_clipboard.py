"""Tests for the secure clipboard helper."""

from __future__ import annotations

import os
import sys
import time

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PyQt6.QtWidgets import QApplication
except ImportError as exc:  # pragma: no cover - environment-specific skip
    pytest.skip(f"PyQt6 unavailable: {exc}", allow_module_level=True)

from LINUX_GUI.utils.secure_clipboard import SecureClipboard


def _get_app() -> QApplication:
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
    return app


def test_secure_clipboard_clears_after_timeout() -> None:
    app = _get_app()

    clipboard_helper = SecureClipboard(timeout_seconds=0.1)
    clipboard_helper.copy("top-secret")

    assert app.clipboard().text() == "top-secret"

    deadline = time.time() + 2.0
    while app.clipboard().text() and time.time() < deadline:
        app.processEvents()
        time.sleep(0.05)

    assert app.clipboard().text() == ""
