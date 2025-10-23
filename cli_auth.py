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
    SessionExpiredError,
    SessionLockedError,
    MFARequiredError,
)
from rate_limiter import RateLimitError, AccountLockedError
from secure_memory import secure_wipe
from user_manager import UserManager, ValidationError, UserExistsError, validate_email
from pin_manager import PINValidationError

from cli_session_store import EncryptedSessionStore, PersistentSession
from mfa_manager import MFAChallenge, MFAResponse


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
        self.user_manager: UserManager = self.auth_manager.user_manager
        self._input = input_func
        self._getpass = getpass_func
        self.audit_logger = audit_logger or get_audit_logger()
        self.session_store = EncryptedSessionStore()
        self._client_ip = "127.0.0.1"
        self._client_user_agent = "SecureVaultCLI/1.0"

    def ensure_authenticated_session(self) -> AuthSession:
        """Ensure the CLI has an authenticated session."""

        restored = self._restore_persisted_session()
        if restored is not None:
            return restored

        if self.auth_manager.is_first_start():
            self._run_first_start()

        return self._prompt_for_login()

    def logout(self, session: Optional[AuthSession]) -> None:
        """Logout and clean up the provided session."""

        if session is None:
            return

        try:
            self.auth_manager.logout(session.session_id)
            self.session_store.remove(session.session_id)
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

            mfa_response: Optional[MFAResponse] = None

            while True:
                try:
                    session = self.auth_manager.authenticate_with_pin(
                        email=normalized_email,
                        pin=pin,
                        ip_address=self._client_ip,
                        user_agent=self._client_user_agent,
                        mfa_response=mfa_response,
                    )
                    self.audit_logger.log_event(
                        AuditEventType.AUTH_SUCCESS,
                        AuditSeverity.INFO,
                        "CLI login successful",
                        {"session_id": session.session_id},
                        user_id=str(session.user_id),
                    )

                    print("\n✅ Authentication successful. Access to SecureVault granted.\n")
                    self._persist_session(session)
                    self._wipe_secret(pin)
                    return session
                except MFARequiredError as challenge_error:
                    mfa_response = self._collect_mfa_response(challenge_error.challenge)
                    continue
                except AccountLockedError as exc:
                    self._log_failure(normalized_email, "account_locked", str(exc))
                    print(f"\n🚫 {exc}")
                    self._wipe_secret(pin)
                    raise AuthenticationFlowError(str(exc)) from exc
                except RateLimitError as exc:
                    self._log_failure(normalized_email, "rate_limited", str(exc))
                    wait_time = max(0.0, exc.retry_after or 0.0)
                    if wait_time:
                        print(f"\n⏳ {exc} Waiting {int(wait_time)} seconds...")
                        time.sleep(min(wait_time, 5))
                    else:
                        print(f"\n⏳ {exc}")
                    self._wipe_secret(pin)
                    break
                except InvalidCredentialsError:
                    self._log_failure(normalized_email, "invalid_credentials", "Invalid email or PIN")
                    print("\n❌ Invalid email or PIN. Please try again.\n")
                    self._wipe_secret(pin)
                    break

    def _prompt_secret(self, prompt: str) -> str:
        """Prompt for sensitive input using the configured getpass function."""

        value = self._getpass(prompt)
        return value.strip()

    def _restore_persisted_session(self) -> Optional[AuthSession]:
        sessions = sorted(
            self.session_store.load_sessions(),
            key=lambda s: s.expires_at,
            reverse=True,
        )

        for persisted in sessions:
            buffer = bytearray(persisted.master_key)
            try:
                session = self.auth_manager.restore_session(
                    session_id=persisted.session_id,
                    user_id=persisted.user_id,
                    master_key=bytes(buffer),
                    created_at=persisted.created_at,
                    expires_at=persisted.expires_at,
                    ip_address=persisted.ip_address,
                    user_agent=persisted.user_agent,
                )
                try:
                    self.auth_manager.get_session(
                        session.session_id,
                        self._client_ip,
                        self._client_user_agent,
                    )
                except SessionLockedError:
                    unlocked = self._unlock_session(session.session_id)
                    if unlocked is not None:
                        return unlocked
                    continue
                self.audit_logger.log_event(
                    AuditEventType.AUTH_SUCCESS,
                    AuditSeverity.INFO,
                    "CLI session restored from secure cache",
                    {"session_id": session.session_id},
                    user_id=str(session.user_id),
                )
                return session
            except SessionExpiredError:
                self.session_store.remove(persisted.session_id)
            except Exception as exc:  # pragma: no cover - defensive restore path
                logger.warning("Failed to restore persisted CLI session: %s", exc)
                self.session_store.remove(persisted.session_id)
            finally:
                secure_wipe(buffer)

        return None

    def _persist_session(self, session: AuthSession) -> None:
        try:
            with session.master_key() as key_buffer:
                snapshot = PersistentSession(
                    session_id=session.session_id,
                    user_id=session.user_id,
                    created_at=session.created_at,
                    expires_at=session.expires_at,
                    ip_address=session.ip_address,
                    user_agent=session.user_agent,
                    master_key=bytes(key_buffer),
                )
        except SessionLockedError:
            return

        self.session_store.append(snapshot)

    def _collect_mfa_response(self, challenge: MFAChallenge) -> MFAResponse:
        print(f"\n🔑 Additional verification required: {challenge.prompt}")

        if challenge.challenge_type == "totp":
            code = self._prompt_secret("Enter TOTP code: ")
            return MFAResponse("totp", {"code": code})

        if challenge.challenge_type == "hardware_key":
            challenge_blob = challenge.metadata.get("challenge")
            if challenge_blob:
                print(f"Challenge (base64): {challenge_blob}")
            signature = self._input("Signature from security key (base64): ").strip()
            return MFAResponse("hardware_key", {"signature": signature})

        if challenge.challenge_type == "biometric":
            length = int(challenge.metadata.get("length", 0) or 0)
            sample_input = self._input(
                f"Provide biometric sample with {length} comma-separated values: "
            )
            parts = [value.strip() for value in sample_input.split(",") if value.strip()]
            sample = [float(part) for part in parts]
            return MFAResponse("biometric", {"sample": sample})

        raise AuthenticationFlowError(f"Unsupported MFA challenge: {challenge.challenge_type}")

    def _unlock_session(self, session_id: str) -> Optional[AuthSession]:
        print("\n🔒 Session locked due to inactivity. Please re-authenticate.")

        pin = self._prompt_secret("PIN: ")
        mfa_response: Optional[MFAResponse] = None

        while True:
            try:
                session = self.auth_manager.unlock_session_with_pin(
                    session_id=session_id,
                    pin=pin,
                    ip_address=self._client_ip,
                    user_agent=self._client_user_agent,
                    mfa_response=mfa_response,
                )
                print("\n🔓 Session unlocked.")
                self._persist_session(session)
                self._wipe_secret(pin)
                return session
            except MFARequiredError as challenge_error:
                mfa_response = self._collect_mfa_response(challenge_error.challenge)
                continue
            except (InvalidCredentialsError, AccountLockedError, RateLimitError) as exc:
                print(f"\n❌ Unable to unlock session: {exc}")
                self._wipe_secret(pin)
                return None

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
