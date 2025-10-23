"""CLI Authentication Flow for SecureVault."""

from __future__ import annotations

import logging
import time
import unicodedata
from getpass import getpass
from typing import Optional, Callable

from audit_logger import AuditEventType, AuditLogger, AuditSeverity, get_audit_logger
from auth_manager import (
    AuthManager,
    AuthSession,
    InvalidCredentialsError,
    SystemLockdownError,
)
from rate_limiter import RateLimitError, AccountLockedError
from secure_memory import secure_wipe
from user_manager import UserManager, ValidationError, UserExistsError, validate_email
from pin_manager import PINValidationError


logger = logging.getLogger(__name__)


class AuthenticationFlowError(Exception):
    """Raised when the CLI authentication flow cannot continue."""


class CLIAuthenticator:
    """Interactive authentication helper for the CLI."""

    def __init__(
        self,
        auth_manager: Optional[AuthManager] = None,
        input_func: Callable[[str], str] = input,
        getpass_func: Callable[[str], str] = getpass,
        audit_logger: Optional[AuditLogger] = None,
    ) -> None:
        try:
            self.auth_manager = auth_manager or AuthManager()
        except SystemLockdownError as exc:
            raise AuthenticationFlowError(str(exc)) from exc
        self.auth_manager = auth_manager or AuthManager()
        self.user_manager: UserManager = self.auth_manager.user_manager
        self._input = input_func
        self._getpass = getpass_func
        self.audit_logger = audit_logger or get_audit_logger()

    def ensure_authenticated_session(self) -> AuthSession:
        """Ensure the CLI has an authenticated session."""

        if self.auth_manager.is_first_start():
            self._run_first_start()

        return self._prompt_for_login()

    def logout(self, session: Optional[AuthSession]) -> None:
        """Logout and clean up the provided session."""

        if session is None:
            return

        try:
            self.auth_manager.logout(session.session_id)
            self.audit_logger.log_event(
                AuditEventType.AUTH_SUCCESS,
                AuditSeverity.INFO,
                "CLI session terminated",
                {
                    "session_id": session.session_id,
                    "user_id": session.user_id,
                },
                user_id=str(session.user_id),
            )
        except Exception:  # pragma: no cover - defensive cleanup
            logger.exception("Failed to log out session cleanly")

    def _run_first_start(self) -> None:
        """Execute the first-start enrollment flow."""

        print("\n🔐 SecureVault Initial Setup")
        print("""This appears to be the first time SecureVault has been launched.""")
        print("You will create the master account before any vault operations are allowed.\n")

        while True:
            email = self._input("Email address: ").strip()
            password = self._prompt_secret("Create password: ")
            confirm_password = self._prompt_secret("Confirm password: ")

            pin = self._prompt_secret("Choose a PIN (min 8 chars, letters and digits allowed): ")
            confirm_pin = self._prompt_secret("Confirm PIN: ")

            try:
                normalized_email = validate_email(email)
                self._validate_matching_secret(password, confirm_password, "Passwords")
                self._validate_matching_secret(pin, confirm_pin, "PINs")

                user_id = self.user_manager.create_user(
                    email=normalized_email,
                    password=password,
                    pin=pin,
                )

                email_hash_hex = self.auth_manager.pin_manager.hash_email_for_lookup(
                    normalized_email
                ).hex()
                self.audit_logger.log_event(
                    AuditEventType.CONFIG_CHANGED,
                    AuditSeverity.INFO,
                    "Initial CLI account created",
                    {"email_hash": email_hash_hex, "user_id": user_id},
                    user_id=str(user_id),
                )

                print("\n✅ Account created successfully. Please log in with your new PIN.\n")
                return
            except (ValidationError, PINValidationError) as exc:
                print(f"\n❌ {exc}")
            except UserExistsError:
                print("\n❌ An account with this email already exists. Please use a different email.")
            except Exception as exc:  # pragma: no cover - unexpected errors
                logger.exception("Failed to create initial account")
                raise AuthenticationFlowError(str(exc)) from exc
            finally:
                self._wipe_secret(password)
                self._wipe_secret(confirm_password)
                self._wipe_secret(pin)
                self._wipe_secret(confirm_pin)

    def _prompt_for_login(self) -> AuthSession:
        """Prompt the operator for email and PIN until authenticated or aborted."""

        print("\n🔐 SecureVault Authentication Required")

        while True:
            email = self._input("Email address: ").strip()
            pin = self._prompt_secret("PIN: ")

            try:
                normalized_email = validate_email(email)
            except ValidationError as exc:
                self._log_failure(email, "invalid_email_format", str(exc))
                print(f"\n❌ {exc}\n")
                continue

            try:
                session = self.auth_manager.authenticate_with_pin(email=normalized_email, pin=pin)
                self.audit_logger.log_event(
                    AuditEventType.AUTH_SUCCESS,
                    AuditSeverity.INFO,
                    "CLI login successful",
                    {"session_id": session.session_id},
                    user_id=str(session.user_id),
                )

                print("\n✅ Authentication successful. Access to SecureVault granted.\n")
                return session
            except AccountLockedError as exc:
                self._log_failure(normalized_email, "account_locked", str(exc))
                print(f"\n🚫 {exc}")
                raise AuthenticationFlowError(str(exc)) from exc
            except RateLimitError as exc:
                self._log_failure(normalized_email, "rate_limited", str(exc))
                wait_time = max(0.0, exc.retry_after or 0.0)
                if wait_time:
                    print(f"\n⏳ {exc} Waiting {int(wait_time)} seconds...")
                    time.sleep(min(wait_time, 5))
                else:
                    print(f"\n⏳ {exc}")
            except InvalidCredentialsError:
                self._log_failure(normalized_email, "invalid_credentials", "Invalid email or PIN")
                print("\n❌ Invalid email or PIN. Please try again.\n")
            finally:
                self._wipe_secret(pin)

    def _prompt_secret(self, prompt: str) -> str:
        """Prompt for sensitive input using the configured getpass function."""

        value = self._getpass(prompt)
        return value.strip()

    def _validate_matching_secret(self, value: str, confirm: str, label: str) -> None:
        """Ensure that two secrets match before proceeding."""

        if value != confirm:
            raise ValidationError(f"{label} do not match")

    def _wipe_secret(self, secret: Optional[str]) -> None:
        """Best-effort wipe of sensitive string data."""

        if not secret:
            return

        try:
            secure_wipe(bytearray(secret, "utf-8"))
        except Exception:  # pragma: no cover - best effort cleanup
            pass

    def _log_failure(self, email: str, reason: str, message: str) -> None:
        """Log authentication failures without exposing secrets."""

        try:
            normalized_email = validate_email(email)
        except ValidationError:
            normalized_email = unicodedata.normalize("NFKC", email or "").strip()

        try:
            email_hash = self.auth_manager.pin_manager.hash_email_for_lookup(normalized_email).hex()
        except Exception:
            email_hash = "unknown"

        self.audit_logger.log_event(
            AuditEventType.AUTH_FAILURE,
            AuditSeverity.WARNING,
            "CLI authentication failure",
            {"email_hash": email_hash, "reason": reason, "message": message},
        )

        if hasattr(self.auth_manager, "auth_queue"):
            snapshot = self.auth_manager.auth_queue.snapshot()
            logger.info(
                "Auth queue snapshot after failure: total=%d max_wait=%.3fs max_depth=%d current_waiters=%d",
                snapshot.total_requests,
                snapshot.max_wait_time,
                snapshot.max_queue_depth,
                snapshot.current_waiters,
            )
