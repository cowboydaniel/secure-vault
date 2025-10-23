"""Text handling utilities for the SecureVault Linux GUI."""

from __future__ import annotations

from html import escape
from typing import Any

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QTextEdit,
)


def safe_set_text(widget: Any, value: str | None) -> None:
    """Safely assign user-controlled strings to Qt widgets.

    This helper ensures that any widget capable of interpreting HTML receives
    an escaped representation of the supplied ``value``. Plain-text widgets
    continue to receive their raw value because they do not evaluate markup.

    Args:
        widget: The Qt widget whose textual content should be updated.
        value: The potentially user-controlled value to display.

    Raises:
        TypeError: If the widget does not expose a compatible text API.
    """

    raw_value = "" if value is None else str(value)
    escaped_value = escape(raw_value, quote=True)

    if isinstance(widget, QLabel):
        widget.setTextFormat(Qt.TextFormat.RichText)
        widget.setText(escaped_value)
        return

    if isinstance(widget, QTextEdit):
        widget.setHtml(escaped_value.replace("\n", "<br />"))
        return

    if isinstance(widget, QPlainTextEdit):
        widget.setPlainText(raw_value)
        return

    if isinstance(widget, QLineEdit):
        widget.setText(raw_value)
        return

    if hasattr(widget, "setText"):
        widget.setText(escaped_value)
        return

    raise TypeError(
        f"Widget of type {type(widget).__name__} is not supported by safe_set_text"
    )


__all__ = ["safe_set_text"]
