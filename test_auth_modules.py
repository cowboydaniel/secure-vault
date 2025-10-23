"""Unit tests for SecureVault authentication components."""

import json
import os
import tempfile
import unittest
from pathlib import Path

from auth_database import AuthDatabase
from auth_manager import AuthManager, InvalidCredentialsError, SessionExpiredError
from auth_manager import (
    AuthManager,
    InvalidCredentialsError,
    SessionHijackingError,
)
from instance_guard import InstanceGuard, TamperDetectedError
from pin_manager import PINManager, PINValidationError, PINPolicy
from rate_limiter import AccountLockedError, RateLimitError
from user_manager import UserManager, UserExistsError


class AuthenticationTestCase(unittest.TestCase):
    """Test harness that provisions an isolated authentication database."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.state_dir = os.path.join(self.temp_dir.name, "state")
        self._prev_state_dir = os.environ.get("SECURE_VAULT_STATE_DIR")
        os.environ["SECURE_VAULT_STATE_DIR"] = self.state_dir
        self.db_path = os.path.join(self.temp_dir.name, "users.db")
        self.db = AuthDatabase(db_path=self.db_path)
        self.auth_manager = AuthManager(db=self.db)
        self.user_manager: UserManager = self.auth_manager.user_manager

    def tearDown(self) -> None:  # pragma: no cover - cleanup
        if self._prev_state_dir is not None:
            os.environ["SECURE_VAULT_STATE_DIR"] = self._prev_state_dir
        else:
            os.environ.pop("SECURE_VAULT_STATE_DIR", None)
        self.temp_dir.cleanup()

    def test_pin_manager_round_trip(self) -> None:
        """PIN manager should encrypt and verify master keys reliably."""

        manager = PINManager()
        pin = "75832164"
        salt = manager.generate_salt()
        derived = manager.derive_key_from_pin(pin, salt)
        master_key = manager.generate_master_key()
        associated_data = b"test@example.commaster_key"

        encrypted = manager.encrypt_master_key(master_key, derived, associated_data)
        decrypted = manager.decrypt_master_key(encrypted, derived, associated_data)
        verification_marker = manager.create_verification_marker(master_key, b"verification")

        self.assertEqual(master_key, decrypted)
        self.assertTrue(manager.verify_master_key(master_key, verification_marker, b"verification"))

        with self.assertRaises(PINValidationError):
            manager.validate_pin_format("1234567")

    def test_configurable_alphanumeric_pin_policy(self) -> None:
        """PIN policy can require alphanumeric PINs when configured."""

        policy = PINPolicy(min_length=10, require_letter=True)
        manager = PINManager(pin_policy=policy)

        # Valid: meets length, includes both letters and digits
        manager.validate_pin_format("VaultKey90")

        # Invalid: lacks alphabetic characters required by policy
        with self.assertRaises(PINValidationError):
            manager.validate_pin_format("1234567890")

    def test_end_to_end_auth_flow(self) -> None:
        """Creating a user should allow successful PIN authentication."""

        email = "alice@example.com"
        password = "Sup3rSecurePass!"
        pin = "83920174"

        user_id = self.user_manager.create_user(email=email, password=password, pin=pin)
        self.assertIsInstance(user_id, int)

        db_user = self.db.get_user_by_id(user_id)
        self.assertIsNotNone(db_user.email_lookup_hash)
        self.assertIsNotNone(db_user.email_salt)
        self.assertEqual(16, len(db_user.email_salt))
        self.assertEqual('argon2id', db_user.password_kdf)
        self.assertIn('time_cost', db_user.password_kdf_metadata)

        login_ip = " 198.51.100.5 "
        login_user_agent = " SecureVaultTest/1.0 "
        session = self.auth_manager.authenticate_with_pin(
            email=email,
            pin=pin,
            ip_address=login_ip,
            user_agent=login_user_agent,
        )
        self.assertIsNotNone(session)
        self.assertEqual(user_id, session.user_id)

        with session.master_key() as buffer:
            self.assertEqual(32, len(buffer))
            snapshot = bytes(buffer)

        self.assertEqual(32, len(snapshot))
        self.assertTrue(all(b == 0 for b in buffer))
        self.assertTrue(session.has_master_key())

        credentials = self.db.get_credentials(user_id)
        self.assertEqual('argon2id', credentials.kdf_algorithm)
        self.assertIn('memory_cost', credentials.kdf_metadata)

        # Session should remain retrievable until logout
        normalized_ip = "198.51.100.5"
        normalized_user_agent = "SecureVaultTest/1.0"
        retrieved = self.auth_manager.get_session(
            session.session_id,
            normalized_ip,
            normalized_user_agent,
        )
        self.assertIsNotNone(retrieved)

        stored_session = self.db.get_session(session.session_id)
        self.assertIsNotNone(stored_session)
        self.assertNotEqual(stored_session.session_id, session.session_id)
        self.assertEqual(64, len(stored_session.session_id))
        self.assertNotIn('-', stored_session.session_id)
        self.assertEqual(normalized_ip, stored_session.ip_address)
        self.assertEqual(normalized_user_agent, stored_session.user_agent)

        self.auth_manager.logout(session.session_id)
        self.assertIsNone(self.auth_manager.get_session(session.session_id))
        self.assertFalse(session.has_master_key())

    def test_session_secret_zeroized_after_logout(self) -> None:
        """Logging out should wipe the in-memory session secret."""

        email = "alice@example.com"
        password = "Sup3rSecurePass!"
        pin = "839201"

        self.user_manager.create_user(email=email, password=password, pin=pin)
        session = self.auth_manager.authenticate_with_pin(email=email, pin=pin)

        with session.master_key() as buffer:
            preview = bytes(buffer)

        self.assertEqual(32, len(preview))
        self.assertTrue(session.has_master_key())

        self.auth_manager.logout(session.session_id)

        self.assertFalse(session.has_master_key())
        with self.assertRaises(SessionExpiredError):
            with session.master_key():
                pass
        self.assertIsNone(
            self.auth_manager.get_session(
                session.session_id,
                normalized_ip,
                normalized_user_agent,
            )
        )

    def test_detects_session_client_metadata_mismatch(self) -> None:
        """Session retrieval should fail if client metadata changes."""

        email = "carol@example.com"
        password = "Sup3rSecurePass!"
        pin = "123789"
        ip_address = "203.0.113.9"
        user_agent = "SecureVaultTest/2.0"

        self.user_manager.create_user(email=email, password=password, pin=pin)
        session = self.auth_manager.authenticate_with_pin(
            email=email,
            pin=pin,
            ip_address=ip_address,
            user_agent=user_agent,
        )

        # Baseline retrieval succeeds with matching metadata
        self.assertIsNotNone(
            self.auth_manager.get_session(session.session_id, ip_address, user_agent)
        )

        # Mismatched metadata should trigger hijacking detection
        with self.assertRaises(SessionHijackingError):
            self.auth_manager.get_session(
                session.session_id,
                "198.51.100.23",
                user_agent,
            )

        # Session should no longer be retrievable after hijacking detection
        self.assertIsNone(
            self.auth_manager.get_session(
                session.session_id,
                ip_address,
                user_agent,
            )
        )

    def test_rate_limiter_enforces_lockout(self) -> None:
        """Repeated invalid attempts trigger an account lockout."""

        email = "bob@example.com"
        password = "AnotherStr0ngPass!"
        pin = "67584920"

        self.user_manager.create_user(email=email, password=password, pin=pin)

        # Speed up the lockout for testing purposes
        limiter = self.auth_manager.rate_limiter
        limiter.config.max_attempts = 3
        limiter.config.exponential_backoff = False

        for _ in range(limiter.config.max_attempts):
            with self.assertRaises(InvalidCredentialsError):
                self.auth_manager.authenticate_with_pin(email=email, pin="00000000")

        with self.assertRaises(AccountLockedError):
            self.auth_manager.authenticate_with_pin(email=email, pin="00000000")

    def test_prevents_multiple_accounts(self) -> None:
        """Only a single owner account may be provisioned."""

        email = "owner@example.com"
        password = "Secur3OwnerPass!"
        pin = "74629183"

        self.user_manager.create_user(email=email, password=password, pin=pin)

        with self.assertRaises(UserExistsError):
            self.user_manager.create_user(
                email="second@example.com",
                password="AnotherStrongPass1!",
                pin="83912057",
            )

    def test_global_rate_limit_blocks_unknown_email(self) -> None:
        """Repeated failures for the same email trigger a cooldown."""

        limiter = self.auth_manager.rate_limiter
        limiter.config.max_attempts = 50
        limiter.config.max_global_attempts = 10
        limiter.config.global_window_seconds = 600
        limiter.config.max_email_attempts = 2
        limiter.config.email_window_seconds = 3600

        target_email = "nobody@example.com"

        for _ in range(limiter.config.max_email_attempts):
            with self.assertRaises(InvalidCredentialsError):
                self.auth_manager.authenticate_with_pin(email=target_email, pin="00000000")

        with self.assertRaises(RateLimitError):
            self.auth_manager.authenticate_with_pin(email=target_email, pin="00000000")

    def test_aliases_share_device_limits(self) -> None:
        """Email aliases from the same device share throttling state."""

        email = "carol@example.com"
        alias = "carol+spam@example.com"
        password = "ComplexP@ss123!"
        pin = "482951"
        ip_address = "203.0.113.5"
        device_fingerprint = "device-test-001"
        user_agent = "SecureVaultTests/1.0"

        self.user_manager.create_user(email=email, password=password, pin=pin)

        limiter = self.auth_manager.rate_limiter
        limiter.config.max_email_attempts = 2
        limiter.config.email_window_seconds = 600

        for _ in range(limiter.config.max_email_attempts):
            with self.assertRaises(InvalidCredentialsError):
                self.auth_manager.authenticate_with_pin(
                    email=alias,
                    pin="000000",
                    ip_address=ip_address,
                    device_fingerprint=device_fingerprint,
                    user_agent=user_agent,
                )

        with self.assertRaises(RateLimitError):
            self.auth_manager.authenticate_with_pin(
                email=email,
                pin=pin,
                ip_address=ip_address,
                device_fingerprint=device_fingerprint,
                user_agent=user_agent,
            )

    def test_lockdown_when_database_missing(self) -> None:
        """Deleting the authentication database triggers tamper lockdown."""

        self.user_manager.create_user(
            email="alice@example.com",
            password="Sup3rSecurePass!",
            pin="83920174",
        )

        self.db.close()
        os.remove(self.db_path)

        with self.assertRaises(TamperDetectedError):
            AuthDatabase(db_path=self.db_path)

    def test_guard_state_reversion_detected(self) -> None:
        """Reverting the guard state to pending should be treated as tampering."""

        self.user_manager.create_user(
            email="owner@example.com",
            password="Secur3OwnerPass!",
            pin="74629183",
        )

        state_path = Path(self.state_dir) / InstanceGuard.STATE_FILENAME
        with state_path.open("r", encoding="utf-8") as handle:
            state_data = json.load(handle)

        state_data["status"] = "pending"
        state_data.pop("locked_at", None)
        state_data.pop("lock_reason", None)

        tmp_path = state_path.with_suffix(".tmp")
        with tmp_path.open("w", encoding="utf-8") as handle:
            json.dump(state_data, handle, indent=2, sort_keys=True)
        os.replace(tmp_path, state_path)
        os.chmod(state_path, 0o600)

        self.db.close()
        os.remove(self.db_path)

        with self.assertRaises(TamperDetectedError):
            AuthDatabase(db_path=self.db_path)



if __name__ == "__main__":  # pragma: no cover - convenience
    unittest.main()
