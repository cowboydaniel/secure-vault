"""First-start onboarding wizard for the SecureVault GUI."""

from __future__ import annotations

import logging
from typing import Optional

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QFormLayout,
    QLineEdit,
    QLabel,
    QMessageBox,
    QVBoxLayout,
    QWizard,
    QWizardPage,
)

from audit_logger import AuditEventType, AuditLogger, AuditSeverity, get_audit_logger
from auth_manager import AuthManager
from pin_manager import PINValidationError
from secure_memory import secure_wipe
from user_manager import UserExistsError, UserManager, ValidationError


logger = logging.getLogger(__name__)


class _IntroPage(QWizardPage):
    """Welcome page describing the onboarding process."""

    def __init__(self) -> None:
        super().__init__()
        self.setTitle("Welcome to SecureVault")
        self.setSubTitle(
            "Let's set up your master account so that your vault stays protected from the very first launch."
        )

        layout = QVBoxLayout(self)
        intro = QLabel(
            """
            <p>The initial account controls access to the entire vault. During this wizard you will:</p>
            <ul>
              <li>Provide a recovery email and strong account password</li>
              <li>Choose a high-entropy 6–8 digit PIN used to unlock your vault key</li>
              <li>Generate a cryptographically secure master key that never leaves this device in plaintext</li>
            </ul>
            <p>None of your secrets are stored directly; only encrypted material is written to disk.</p>
            """
        )
        intro.setWordWrap(True)
        intro.setTextFormat(Qt.TextFormat.RichText)
        layout.addWidget(intro)


class _CredentialsPage(QWizardPage):
    """Collect email and password from the operator."""

    def __init__(self) -> None:
        super().__init__()
        self.setTitle("Account Credentials")
        self.setSubTitle("Use a valid email address and a strong password for recovery operations.")

        layout = QFormLayout(self)

        self.email_edit = QLineEdit()
        self.email_edit.setPlaceholderText("name@example.com")

        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)

        self.confirm_password_edit = QLineEdit()
        self.confirm_password_edit.setEchoMode(QLineEdit.EchoMode.Password)

        layout.addRow("Email:", self.email_edit)
        layout.addRow("Password:", self.password_edit)
        layout.addRow("Confirm Password:", self.confirm_password_edit)

        self.registerField("email*", self.email_edit)
        self.registerField("password*", self.password_edit)
        self.registerField("confirm_password*", self.confirm_password_edit)


class _PinPage(QWizardPage):
    """Collect the vault PIN."""

    def __init__(self) -> None:
        super().__init__()
        self.setTitle("Vault PIN")
        self.setSubTitle("Select a 6–8 digit PIN that avoids simple patterns.")

        layout = QFormLayout(self)

        instructions = QLabel(
            "PIN requirements: 6–8 digits, no simple sequences, no repeated digits, and not in common PIN lists."
        )
        instructions.setWordWrap(True)

        self.pin_edit = QLineEdit()
        self.pin_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.pin_edit.setMaxLength(8)

        self.confirm_pin_edit = QLineEdit()
        self.confirm_pin_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirm_pin_edit.setMaxLength(8)

        layout.addRow(instructions)
        layout.addRow("PIN:", self.pin_edit)
        layout.addRow("Confirm PIN:", self.confirm_pin_edit)

        self.registerField("pin*", self.pin_edit)
        self.registerField("confirm_pin*", self.confirm_pin_edit)


class FirstStartWizard(QWizard):
    """QWizard implementation for first-start enrollment."""

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

        self.setWindowTitle("SecureVault Setup Wizard")
        self.setOption(QWizard.WizardOption.NoBackButtonOnStartPage, True)
        self.setButtonText(QWizard.WizardButton.FinishButton, "Create Account")

        self._intro_page = _IntroPage()
        self._credentials_page = _CredentialsPage()
        self._pin_page = _PinPage()

        self.addPage(self._intro_page)
        self.addPage(self._credentials_page)
        self.addPage(self._pin_page)

    def accept(self) -> None:  # noqa: D401
        """Validate inputs and attempt to create the initial account."""

        email = self.field("email").strip()
        password = self.field("password")
        confirm_password = self.field("confirm_password")
        pin = self.field("pin")
        confirm_pin = self.field("confirm_pin")

        try:
            if password != confirm_password:
                QMessageBox.warning(self, "Password Mismatch", "Passwords do not match. Please try again.")
                return

            if pin != confirm_pin:
                QMessageBox.warning(self, "PIN Mismatch", "PIN entries do not match. Please re-enter them.")
                return

            user_id = self.user_manager.create_user(email=email, password=password, pin=pin)

            email_hash_hex = self.auth_manager.pin_manager.hash_email_for_lookup(email).hex()
            self.audit_logger.log_event(
                AuditEventType.CONFIG_CHANGED,
                AuditSeverity.INFO,
                "Initial GUI account created",
                {"email_hash": email_hash_hex, "user_id": user_id},
                user_id=str(user_id),
            )

            QMessageBox.information(
                self,
                "Setup Complete",
                "SecureVault is ready. Please authenticate with your new PIN to begin using the application.",
            )

            super().accept()

        except (ValidationError, PINValidationError, UserExistsError) as exc:
            QMessageBox.warning(self, "Unable to Create Account", str(exc))
            logger.warning("Failed to create initial GUI account: %s", exc)
        except Exception as exc:  # pragma: no cover - defensive programming
            logger.exception("Unexpected error during GUI onboarding")
            QMessageBox.critical(
                self,
                "Unexpected Error",
                "An unexpected error occurred while creating the account. Please review the logs for details.",
            )
        finally:
            for secret in (password, confirm_password, pin, confirm_pin):
                self._wipe_secret(secret)

    @staticmethod
    def _wipe_secret(value: Optional[str]) -> None:
        if not value:
            return
        try:
            secure_wipe(bytearray(value, "utf-8"))
        except Exception:  # pragma: no cover - best effort
            pass
