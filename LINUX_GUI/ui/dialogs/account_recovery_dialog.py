"""Account recovery dialog for PIN reset."""

from __future__ import annotations

import logging
from typing import Optional

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QVBoxLayout,
)

from audit_logger import AuditEventType, AuditLogger, AuditSeverity, get_audit_logger
from auth_manager import AuthManager
from pin_manager import PINValidationError
from secure_memory import secure_wipe
from user_manager import UserManager, ValidationError


logger = logging.getLogger(__name__)


class AccountRecoveryDialog(QDialog):
    """Dialog for resetting a forgotten PIN."""

    def __init__(
        self,
        auth_manager: AuthManager,
        audit_logger: Optional[AuditLogger] = None,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.auth_manager = auth_manager
        self.user_manager: UserManager = auth_manager.user_manager
        self.audit_logger = audit_logger or get_audit_logger()
        self._recovery_successful = False

        self.setWindowTitle("Account Recovery")
        self.setModal(True)

        layout = QVBoxLayout(self)

        # Header
        header = QLabel(
            "<h3>Reset Your PIN</h3>"
            "<p>If you've forgotten your PIN, you can reset it using your email and password. "
            "<strong>Warning:</strong> Resetting your PIN will generate a new master key, and "
            "you will lose access to files encrypted with the old key.</p>"
        )
        header.setWordWrap(True)
        header.setTextFormat(Qt.TextFormat.RichText)
        layout.addWidget(header)

        # Form
        form = QFormLayout()

        self.email_edit = QLineEdit()
        self.email_edit.setPlaceholderText("name@example.com")

        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_edit.setPlaceholderText("Your account password")

        self.new_pin_edit = QLineEdit()
        self.new_pin_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.new_pin_edit.setMaxLength(8)
        self.new_pin_edit.setPlaceholderText("6-8 digits")

        self.confirm_pin_edit = QLineEdit()
        self.confirm_pin_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirm_pin_edit.setMaxLength(8)
        self.confirm_pin_edit.setPlaceholderText("Re-enter new PIN")

        form.addRow("Email:", self.email_edit)
        form.addRow("Password:", self.password_edit)
        form.addRow("New PIN:", self.new_pin_edit)
        form.addRow("Confirm New PIN:", self.confirm_pin_edit)
        layout.addLayout(form)

        # Error label
        self.error_label = QLabel()
        self.error_label.setObjectName("errorLabel")
        self.error_label.setWordWrap(True)
        self.error_label.setStyleSheet("color: #d9534f;")
        self.error_label.setVisible(False)
        layout.addWidget(self.error_label)

        # Buttons
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self.resize(500, self.sizeHint().height())

    @property
    def recovery_successful(self) -> bool:
        """Return True if the recovery was successful."""
        return self._recovery_successful

    def accept(self) -> None:
        """Attempt PIN recovery and close dialog on success."""
        email = self.email_edit.text().strip()
        password = self.password_edit.text()
        new_pin = self.new_pin_edit.text().strip()
        confirm_pin = self.confirm_pin_edit.text().strip()

        if not email or not password or not new_pin or not confirm_pin:
            self._show_error("All fields are required.")
            return

        if new_pin != confirm_pin:
            self._show_error("PIN entries do not match.")
            return

        try:
            # Get user by email
            user = self.user_manager.get_user_by_email(email)
            if not user:
                # Don't reveal whether the email exists
                self._show_error("Invalid email or password.")
                self._log_failure(email, "user_not_found")
                return

            # Confirm the data loss warning
            confirm = QMessageBox.warning(
                self,
                "Confirm PIN Reset",
                "Resetting your PIN will generate a new master key. "
                "You will lose access to all files encrypted with your old PIN.\n\n"
                "Are you sure you want to continue?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )

            if confirm != QMessageBox.StandardButton.Yes:
                return

            # Reset PIN
            self.user_manager.reset_pin(
                user_id=user.user_id,
                password=password,
                new_pin=new_pin
            )

            self.audit_logger.log_event(
                AuditEventType.CONFIG_CHANGED,
                AuditSeverity.WARNING,
                "PIN reset via recovery",
                {"email_hash": user.email_hash.hex()},
                user_id=str(user.user_id),
            )

            self._recovery_successful = True

            QMessageBox.information(
                self,
                "PIN Reset Successful",
                "Your PIN has been reset successfully. You can now log in with your new PIN.",
            )

            self.error_label.setVisible(False)
            super().accept()

        except ValidationError as exc:
            self._show_error(str(exc))
            self._log_failure(email, "validation_error")
            logger.warning("PIN recovery validation error: %s", exc)
        except PINValidationError as exc:
            self._show_error(str(exc))
            self._log_failure(email, "invalid_pin")
            logger.warning("PIN recovery PIN validation error: %s", exc)
        except Exception as exc:
            logger.exception("Unexpected error during PIN recovery")
            QMessageBox.critical(
                self,
                "Unexpected Error",
                "An unexpected error occurred during recovery. Please try again.",
            )
        finally:
            # Wipe sensitive data
            for secret in (password, new_pin, confirm_pin):
                self._wipe_secret(secret)

    def _show_error(self, message: str) -> None:
        self.error_label.setText(message)
        self.error_label.setVisible(True)

    def _log_failure(self, email: str, reason: str) -> None:
        try:
            email_hash = self.auth_manager.pin_manager.hash_email(email).hex()
        except Exception:
            email_hash = "unknown"

        self.audit_logger.log_event(
            AuditEventType.AUTH_FAILURE,
            AuditSeverity.WARNING,
            "PIN recovery attempt failed",
            {"email_hash": email_hash, "reason": reason},
        )

    @staticmethod
    def _wipe_secret(value: Optional[str]) -> None:
        if not value:
            return
        try:
            secure_wipe(bytearray(value, "utf-8"))
        except Exception:
            pass
