"""
SecureVault User Manager Module

This module handles user account creation and management:
- User registration with email validation
- Password policy enforcement
- PIN setup and validation
- User credential storage
- Account recovery

Security Notes:
- Passwords are hashed with Argon2id before storage
- PINs are never stored (only used for key derivation)
- Master vault keys are encrypted with PIN-derived keys
- All sensitive data is wiped from memory after use
"""

import re
import logging
import hmac
from typing import Optional, Tuple, Dict
from dataclasses import dataclass

try:
    from argon2.low_level import hash_secret_raw, Type
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False
    logging.warning("argon2-cffi not available")

from auth_database import AuthDatabase, User
from pin_manager import PINManager, PINValidationError, Argon2Params
from secure_memory import secure_wipe

logger = logging.getLogger(__name__)


@dataclass
class PasswordPolicy:
    """Password complexity requirements"""
    min_length: int = 12
    max_length: int = 128
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_digit: bool = True
    require_special: bool = True
    special_chars: str = "!@#$%^&*()_+-=[]{}|;:,.<>?"


class ValidationError(Exception):
    """Raised when validation fails"""
    pass


class UserExistsError(Exception):
    """Raised when trying to create a user that already exists"""
    pass


class UserManager:
    """
    User account manager.

    Handles all user account operations including creation, validation,
    and credential management.
    """

    def __init__(
        self,
        db: AuthDatabase,
        password_policy: Optional[PasswordPolicy] = None
    ):
        """
        Initialize user manager.

        Args:
            db: Authentication database
            password_policy: Password policy (uses defaults if None)
        """
        self.db = db
        self.policy = password_policy or PasswordPolicy()
        self.pin_manager = PINManager()

    def create_user(
        self,
        email: str,
        password: str,
        pin: str
    ) -> int:
        """
        Create a new user account.

        This implements the complete first-start account creation flow:
        1. Validate email, password, and PIN
        2. Hash email for privacy
        3. Hash password with Argon2id
        4. Generate master vault key
        5. Derive key from PIN
        6. Encrypt master key with PIN-derived key
        7. Create verification marker
        8. Store all credentials in database

        Args:
            email: User's email address
            password: User's password
            pin: User's PIN (6-8 digits)

        Returns:
            user_id: New user's ID

        Raises:
            ValidationError: Invalid input
            UserExistsError: Email already registered
        """
        # Step 1: Validate all inputs
        self.validate_email(email)
        self.validate_password(password)
        self.pin_manager.validate_pin_format(pin)

        if self.db.has_users():
            raise UserExistsError(
                "This SecureVault installation already has a provisioned owner account."
            )

        # Step 2: Hash email for storage and lookup
        email_hash, email_salt = self.pin_manager.hash_email_for_storage(email)
        email_lookup_hash = self.pin_manager.hash_email_for_lookup(email)

        # Check if user already exists (peppered hash first, legacy fallback)
        existing_user = self.db.get_user_by_email_lookup_hash(email_lookup_hash)
        if not existing_user:
            legacy_hash = self.pin_manager.hash_email_legacy(email)
            existing_user = self.db.get_user_by_email_hash(legacy_hash)
        if existing_user:
            raise UserExistsError(f"An account with this email already exists")

        # Step 3: Hash password with Argon2id
        password_hash, password_salt, password_kdf, password_kdf_metadata = self._hash_password(password)

        # Step 4: Generate master vault key (256-bit random)
        master_key = self.pin_manager.generate_master_key()

        try:
            # Step 5: Generate PIN salt and derive key
            pin_salt = self.pin_manager.generate_salt()
            pin_kdf_metadata = self.pin_manager.export_kdf_metadata()
            pin_derived_key = self.pin_manager.derive_key_from_pin(
                pin,
                pin_salt,
                algorithm=pin_kdf_metadata.get("algorithm"),
                metadata=pin_kdf_metadata,
            )

            # Step 6: Encrypt master key with PIN-derived key
            associated_data = email_hash + b"master_key"
            encrypted_master_key = self.pin_manager.encrypt_master_key(
                master_key,
                pin_derived_key,
                associated_data
            )

            # Step 7: Create verification marker
            verification_ad = email_hash + b"verification"
            verification_marker = self.pin_manager.create_verification_marker(
                master_key,
                verification_ad
            )

            # Step 8: Store in database
            user_id = self.db.create_user(
                email_hash=email_hash,
                email_lookup_hash=email_lookup_hash,
                email_salt=email_salt,
                password_hash=password_hash,
                password_salt=password_salt,
                password_kdf=password_kdf,
                password_kdf_metadata=password_kdf_metadata,
                pin_salt=pin_salt,
                encrypted_master_key=encrypted_master_key,
                verification_marker=verification_marker,
                pin_kdf_algorithm=pin_kdf_metadata.get("algorithm", "argon2id"),
                pin_kdf_metadata=pin_kdf_metadata,
            )

            logger.info(f"Created new user account with ID {user_id}")
            return user_id

        finally:
            # Wipe sensitive data from memory
            secure_wipe(master_key)
            secure_wipe(pin_derived_key)
            secure_wipe(password.encode('utf-8'))
            secure_wipe(pin.encode('utf-8'))

    def validate_email(self, email: str) -> None:
        """
        Validate email address format.

        Args:
            email: Email address to validate

        Raises:
            ValidationError: Invalid email format
        """
        if not email or len(email) < 3:
            raise ValidationError("Email address is too short")

        if len(email) > 254:  # RFC 5321
            raise ValidationError("Email address is too long")

        # Basic email regex (not perfect but good enough)
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            raise ValidationError("Invalid email address format")

    def validate_password(self, password: str) -> None:
        """
        Validate password against security policy.

        Args:
            password: Password to validate

        Raises:
            ValidationError: Password doesn't meet policy requirements
        """
        # Check length
        if len(password) < self.policy.min_length:
            raise ValidationError(
                f"Password must be at least {self.policy.min_length} characters long"
            )

        if len(password) > self.policy.max_length:
            raise ValidationError(
                f"Password must be no more than {self.policy.max_length} characters long"
            )

        # Check complexity requirements
        has_uppercase = any(c.isupper() for c in password)
        has_lowercase = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in self.policy.special_chars for c in password)

        errors = []

        if self.policy.require_uppercase and not has_uppercase:
            errors.append("at least one uppercase letter")

        if self.policy.require_lowercase and not has_lowercase:
            errors.append("at least one lowercase letter")

        if self.policy.require_digit and not has_digit:
            errors.append("at least one digit")

        if self.policy.require_special and not has_special:
            errors.append(f"at least one special character ({self.policy.special_chars})")

        if errors:
            raise ValidationError(
                f"Password must contain: {', '.join(errors)}"
            )

    def calculate_password_strength(self, password: str) -> Tuple[int, str]:
        """
        Calculate password strength score.

        Returns:
            Tuple of (score, description)
            - score: 0-4 (0=very weak, 4=very strong)
            - description: Human-readable strength description
        """
        score = 0

        # Length scoring
        if len(password) >= 8:
            score += 1
        if len(password) >= 12:
            score += 1
        if len(password) >= 16:
            score += 1

        # Complexity scoring
        has_uppercase = any(c.isupper() for c in password)
        has_lowercase = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)

        complexity_count = sum([has_uppercase, has_lowercase, has_digit, has_special])

        if complexity_count >= 2:
            score += 1
        if complexity_count >= 4:
            score += 1

        # Cap at maximum
        score = min(score, 4)

        # Description
        descriptions = {
            0: "Very Weak",
            1: "Weak",
            2: "Fair",
            3: "Strong",
            4: "Very Strong"
        }

        return score, descriptions[score]

    def _hash_password(self, password: str) -> Tuple[bytes, bytes, str, Dict[str, int]]:
        """
        Hash password with Argon2id.

        Args:
            password: Plaintext password

        Returns:
            Tuple of (password_hash, salt, algorithm_name, metadata)
        """
        password_bytes = password.encode('utf-8')

        try:
            if ARGON2_AVAILABLE:
                # Generate salt
                import os
                salt = os.urandom(16)

                # Hash with Argon2id
                time_cost = 3
                memory_cost = 65536
                parallelism = 4
                hash_len = 32
                password_hash = hash_secret_raw(
                    secret=password_bytes,
                    salt=salt,
                    time_cost=time_cost,
                    memory_cost=memory_cost,
                    parallelism=parallelism,
                    hash_len=hash_len,
                    type=Type.ID
                )

                metadata = {
                    "algorithm": "argon2id",
                    "time_cost": time_cost,
                    "memory_cost": memory_cost,
                    "parallelism": parallelism,
                    "hash_length": hash_len,
                }

                return password_hash, salt, "argon2id", metadata
            else:
                # Fallback to PBKDF2
                from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
                from cryptography.hazmat.primitives import hashes
                import os

                salt = os.urandom(16)

                iterations = 600000
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=iterations,
                )

                password_hash = kdf.derive(password_bytes)
                metadata = {
                    "algorithm": "pbkdf2_sha256",
                    "iterations": iterations,
                    "length": 32,
                }
                return password_hash, salt, "pbkdf2_sha256", metadata

        finally:
            # Wipe password from memory
            secure_wipe(password_bytes)

    def verify_password(self, user_id: int, password: str) -> bool:
        """
        Verify password for user.

        Args:
            user_id: User ID
            password: Password to verify

        Returns:
            True if password is correct, False otherwise
        """
        user = self.db.get_user_by_id(user_id)
        if not user:
            return False

        password_bytes = password.encode('utf-8')

        try:
            algorithm = (user.password_kdf or 'argon2id').lower()
            metadata = user.password_kdf_metadata or {}

            if algorithm == 'argon2id':
                if not ARGON2_AVAILABLE:
                    logger.error("Argon2 not available to verify stored Argon2id password")
                    return False

                params = Argon2Params.from_metadata(metadata)
                attempted_hash = hash_secret_raw(
                    secret=password_bytes,
                    salt=user.password_salt,
                    time_cost=params.time_cost,
                    memory_cost=params.memory_cost,
                    parallelism=params.parallelism,
                    hash_len=params.hash_length,
                    type=Type.ID,
                    version=params.version,
                )
            elif algorithm == 'pbkdf2_sha256':
                from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
                from cryptography.hazmat.primitives import hashes

                iterations = int(metadata.get('iterations', 600000))
                length = int(metadata.get('length', 32))

                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=length,
                    salt=user.password_salt,
                    iterations=iterations,
                )
                attempted_hash = kdf.derive(password_bytes)
            else:
                logger.error("Unsupported password KDF '%s'", algorithm)
                return False

            # Constant-time comparison
            return hmac.compare_digest(attempted_hash, user.password_hash)

        finally:
            # Wipe password from memory
            secure_wipe(password_bytes)

    def update_password(
        self,
        user_id: int,
        old_password: str,
        new_password: str
    ) -> None:
        """
        Update user's password.

        Args:
            user_id: User ID
            old_password: Current password (for verification)
            new_password: New password

        Raises:
            ValidationError: Invalid password or verification failed
        """
        # Verify old password
        if not self.verify_password(user_id, old_password):
            raise ValidationError("Current password is incorrect")

        # Validate new password
        self.validate_password(new_password)

        # Hash new password
        new_hash, new_salt, kdf_name, kdf_metadata = self._hash_password(new_password)

        # Update in database
        self.db.update_password(
            user_id,
            new_hash,
            new_salt,
            password_kdf=kdf_name,
            password_kdf_metadata=kdf_metadata,
        )

        logger.info(f"Updated password for user {user_id}")

    def reset_pin(
        self,
        user_id: int,
        password: str,
        new_pin: str
    ) -> None:
        """
        Reset user's PIN.

        Requires password verification. This is the recovery path if user
        forgets their PIN.

        Process:
        1. Verify password
        2. Get current credentials (includes encrypted master key)
        3. Decrypt master key using password (TODO: implement password-based recovery)
        4. Generate new PIN salt
        5. Derive new PIN key
        6. Encrypt master key with new PIN key
        7. Create new verification marker
        8. Update database

        Args:
            user_id: User ID
            password: Current password (for verification)
            new_pin: New PIN to set

        Raises:
            ValidationError: Invalid password or PIN
        """
        # Verify password
        if not self.verify_password(user_id, password):
            raise ValidationError("Password is incorrect")

        # Validate new PIN
        self.pin_manager.validate_pin_format(new_pin)

        # Get user
        user = self.db.get_user_by_id(user_id)
        if not user:
            raise ValueError(f"User {user_id} not found")

        # NOTE: For now, we can't decrypt the master key without the old PIN
        # This would require implementing password-based master key recovery
        # For MVP, we'll generate a NEW master key (user loses access to old encrypted files)

        logger.warning(
            f"PIN reset for user {user_id} - generating new master key. "
            "Old encrypted files will be inaccessible!"
        )

        # Generate new master key
        master_key = self.pin_manager.generate_master_key()

        try:
            # Generate new PIN credentials
            pin_salt = self.pin_manager.generate_salt()
            pin_kdf_metadata = self.pin_manager.export_kdf_metadata()
            pin_derived_key = self.pin_manager.derive_key_from_pin(
                new_pin,
                pin_salt,
                algorithm=pin_kdf_metadata.get("algorithm"),
                metadata=pin_kdf_metadata,
            )

            # Encrypt new master key
            associated_data = user.email_hash + b"master_key"
            encrypted_master_key = self.pin_manager.encrypt_master_key(
                master_key,
                pin_derived_key,
                associated_data
            )

            # Create verification marker
            verification_ad = user.email_hash + b"verification"
            verification_marker = self.pin_manager.create_verification_marker(
                master_key,
                verification_ad
            )

            # Update database
            self.db.update_pin_credentials(
                user_id,
                pin_salt,
                encrypted_master_key,
                verification_marker,
                kdf_algorithm=pin_kdf_metadata.get("algorithm"),
                kdf_metadata=pin_kdf_metadata,
            )

            logger.info(f"Reset PIN for user {user_id}")

        finally:
            # Wipe sensitive data
            secure_wipe(master_key)
            secure_wipe(pin_derived_key)
            secure_wipe(new_pin.encode('utf-8'))

    def get_user_by_email(self, email: str) -> Optional[User]:
        """
        Get user by email address.

        Args:
            email: Email address

        Returns:
            User object or None if not found
        """
        email_lookup_hash = self.pin_manager.hash_email_for_lookup(email)
        user = self.db.get_user_by_email_lookup_hash(email_lookup_hash)
        if user:
            return user

        legacy_hash = self.pin_manager.hash_email_legacy(email)
        return self.db.get_user_by_email_hash(legacy_hash)

    def user_exists(self, email: str) -> bool:
        """
        Check if user with email exists.

        Args:
            email: Email address

        Returns:
            True if user exists, False otherwise
        """
        return self.get_user_by_email(email) is not None
