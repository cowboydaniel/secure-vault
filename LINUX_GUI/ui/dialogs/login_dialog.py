"""PIN-based login dialog for the SecureVault GUI."""

from __future__ import annotations

import logging
from typing import Optional

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
)

from audit_logger import AuditEventType, AuditLogger, AuditSeverity, get_audit_logger
from auth_manager import AuthManager, AuthSession, InvalidCredentialsError
from rate_limiter import AccountLockedError, RateLimitError
from secure_memory import secure_wipe


logger = logging.getLogger(__name__)


class LoginDialog(QDialog):
    """Modal dialog that prompts for email and PIN."""

    def __init__(
        self,
        auth_manager: AuthManager,
        audit_logger: Optional[AuditLogger] = None,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.auth_manager = auth_manager
        self.audit_logger = audit_logger or get_audit_logger()
        self._session: Optional[AuthSession] = None
        self._email: Optional[str] = None

        self.setWindowTitle("SecureVault Login")
        self.setModal(True)

        layout = QVBoxLayout(self)

        intro = QLabel(
            "Enter the email used during onboarding and the associated PIN to unlock the vault."
        )
        intro.setWordWrap(True)
        layout.addWidget(intro)

        form = QFormLayout()
        self.email_edit = QLineEdit()
        self.email_edit.setPlaceholderText("name@example.com")

        self.pin_edit = QLineEdit()
        self.pin_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.pin_edit.setMaxLength(8)

        form.addRow("Email:", self.email_edit)
        form.addRow("PIN:", self.pin_edit)
        layout.addLayout(form)

        self.error_label = QLabel()
        self.error_label.setObjectName("authErrorLabel")
        self.error_label.setWordWrap(True)
        self.error_label.setStyleSheet("color: #d9534f;")
        self.error_label.setVisible(False)
        layout.addWidget(self.error_label)

        # Forgot PIN link
        forgot_layout = QHBoxLayout()
        forgot_layout.addStretch()
        self.forgot_pin_btn = QPushButton("Forgot PIN?")
        self.forgot_pin_btn.setFlat(True)
        self.forgot_pin_btn.setStyleSheet("QPushButton { color: #4a9eff; text-decoration: underline; border: none; }")
        self.forgot_pin_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.forgot_pin_btn.clicked.connect(self.on_forgot_pin)
        forgot_layout.addWidget(self.forgot_pin_btn)
        layout.addLayout(forgot_layout)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self.resize(420, self.sizeHint().height())

    @property
    def session(self) -> Optional[AuthSession]:
        """Return the authenticated session, if available."""

        return self._session

    @property
    def email(self) -> Optional[str]:
        """Return the email used for login."""

        return self._email

    def accept(self) -> None:  # noqa: D401
        """Attempt authentication and close dialog on success."""

        email = self.email_edit.text().strip()
        pin = self.pin_edit.text().strip()

        if not email or not pin:
            self._show_error("Email and PIN are required.")
            return

        try:
            session = self.auth_manager.authenticate_with_pin(email=email, pin=pin)
            self._session = session
            self._email = email

            self.audit_logger.log_event(
                AuditEventType.AUTH_SUCCESS,
                AuditSeverity.INFO,
                "GUI login successful",
                {"session_id": session.session_id},
                user_id=str(session.user_id),
            )

            self.error_label.setVisible(False)
            super().accept()

        except AccountLockedError as exc:
            self._log_failure(email, "account_locked", str(exc))
            QMessageBox.critical(self, "Account Locked", str(exc))
        except RateLimitError as exc:
            self._log_failure(email, "rate_limited", str(exc))
            self._show_error(str(exc))
        except InvalidCredentialsError:
            self._log_failure(email, "invalid_credentials", "Invalid email or PIN")
            self._show_error("Invalid email or PIN. Please try again.")
        except Exception as exc:  # pragma: no cover - defensive programming
            logger.exception("Unexpected error during GUI authentication")
            QMessageBox.critical(
                self,
                "Unexpected Error",
                "An unexpected error occurred during authentication. Please try again.",
            )
        finally:
            self._wipe_secret(pin)

    def _show_error(self, message: str) -> None:
        self.error_label.setText(message)
        self.error_label.setVisible(True)

    def _log_failure(self, email: str, reason: str, message: str) -> None:
        try:
            email_hash = self.auth_manager.pin_manager.hash_email_for_lookup(email).hex()
            email_hash = self.auth_manager.pin_manager.hash_email(email).hex()
        except Exception:
            email_hash = "unknown"

        self.audit_logger.log_event(
            AuditEventType.AUTH_FAILURE,
            AuditSeverity.WARNING,
            "GUI authentication failure",
            {"email_hash": email_hash, "reason": reason, "message": message},
        )

    def on_forgot_pin(self) -> None:
        """Handle the Forgot PIN button click."""
        from LINUX_GUI.ui.dialogs.account_recovery_dialog import AccountRecoveryDialog

        dialog = AccountRecoveryDialog(
            auth_manager=self.auth_manager,
            audit_logger=self.audit_logger,
            parent=self
        )

        result = dialog.exec()

        if result == QDialog.DialogCode.Accepted and dialog.recovery_successful:
            QMessageBox.information(
                self,
                "Recovery Complete",
                "Your PIN has been reset. Please log in with your new PIN.",
            )
            # Pre-fill email if it was entered
            if dialog.email_edit.text():
                self.email_edit.setText(dialog.email_edit.text())
            self.pin_edit.clear()
            self.pin_edit.setFocus()

    @staticmethod
    def _wipe_secret(pin: Optional[str]) -> None:
        if not pin:
            return
        try:
            secure_wipe(bytearray(pin, "utf-8"))
        except Exception:  # pragma: no cover - best effort cleanup
            pass
