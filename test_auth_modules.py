"""Unit tests for SecureVault authentication components."""

import os
import tempfile
import unittest

from auth_database import AuthDatabase
from auth_manager import AuthManager, InvalidCredentialsError
from pin_manager import PINManager, PINValidationError
from rate_limiter import AccountLockedError
from user_manager import UserManager


class AuthenticationTestCase(unittest.TestCase):
    """Test harness that provisions an isolated authentication database."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        db_path = os.path.join(self.temp_dir.name, "users.db")
        self.db = AuthDatabase(db_path=db_path)
        self.auth_manager = AuthManager(db=self.db)
        self.user_manager: UserManager = self.auth_manager.user_manager

    def tearDown(self) -> None:  # pragma: no cover - cleanup
        self.temp_dir.cleanup()

    def test_pin_manager_round_trip(self) -> None:
        """PIN manager should encrypt and verify master keys reliably."""

        manager = PINManager()
        pin = "758321"
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
            manager.validate_pin_format("123456")

    def test_end_to_end_auth_flow(self) -> None:
        """Creating a user should allow successful PIN authentication."""

        email = "alice@example.com"
        password = "Sup3rSecurePass!"
        pin = "839201"

        user_id = self.user_manager.create_user(email=email, password=password, pin=pin)
        self.assertIsInstance(user_id, int)

        db_user = self.db.get_user_by_id(user_id)
        self.assertIsNotNone(db_user.email_lookup_hash)
        self.assertIsNotNone(db_user.email_salt)
        self.assertEqual(16, len(db_user.email_salt))
        self.assertEqual('argon2id', db_user.password_kdf)
        self.assertIn('time_cost', db_user.password_kdf_metadata)

        session = self.auth_manager.authenticate_with_pin(email=email, pin=pin)
        self.assertIsNotNone(session)
        self.assertEqual(user_id, session.user_id)
        self.assertEqual(32, len(session.get_master_key()))

        credentials = self.db.get_credentials(user_id)
        self.assertEqual('argon2id', credentials.kdf_algorithm)
        self.assertIn('memory_cost', credentials.kdf_metadata)

        # Session should remain retrievable until logout
        retrieved = self.auth_manager.get_session(session.session_id)
        self.assertIsNotNone(retrieved)

        stored_session = self.db.get_session(session.session_id)
        self.assertIsNotNone(stored_session)
        self.assertNotEqual(stored_session.session_id, session.session_id)
        self.assertEqual(64, len(stored_session.session_id))
        self.assertNotIn('-', stored_session.session_id)

        self.auth_manager.logout(session.session_id)
        self.assertIsNone(self.auth_manager.get_session(session.session_id))

    def test_rate_limiter_enforces_lockout(self) -> None:
        """Repeated invalid attempts trigger an account lockout."""

        email = "bob@example.com"
        password = "AnotherStr0ngPass!"
        pin = "675849"

        self.user_manager.create_user(email=email, password=password, pin=pin)

        # Speed up the lockout for testing purposes
        limiter = self.auth_manager.rate_limiter
        limiter.config.max_attempts = 3
        limiter.config.exponential_backoff = False

        for _ in range(limiter.config.max_attempts):
            with self.assertRaises(InvalidCredentialsError):
                self.auth_manager.authenticate_with_pin(email=email, pin="000000")

        with self.assertRaises(AccountLockedError):
            self.auth_manager.authenticate_with_pin(email=email, pin="000000")


if __name__ == "__main__":  # pragma: no cover - convenience
    unittest.main()
