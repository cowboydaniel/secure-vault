"""
SecureVault PIN Manager Module

This module handles PIN-related cryptographic operations:
- PIN-to-key derivation using Argon2id (memory-hard KDF)
- Master key encryption/decryption with PIN-derived key
- PIN validation and strength checking
- Secure memory handling for sensitive data

CRITICAL SECURITY REQUIREMENT:
The PIN is NEVER stored. It's only used as input to Argon2id to derive
an encryption key, which is then used to encrypt the master vault key.
Verification happens by attempting decryption - if successful, PIN is correct.
"""

import os
import re
import logging
import hashlib
from typing import Tuple, Optional, Dict, Any, Union
from dataclasses import dataclass

# Argon2 for key derivation
try:
    from argon2 import PasswordHasher, Type
    from argon2.low_level import hash_secret_raw
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False
    logging.warning("argon2-cffi not available, using fallback PBKDF2")

# AES-GCM for encryption
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Secure memory wiping
from secure_memory import secure_wipe
from auth_secrets import get_email_pepper

logger = logging.getLogger(__name__)


# Common weak PINs to reject
WEAK_PINS = {
    '000000', '111111', '222222', '333333', '444444', '555555', '666666', '777777', '888888', '999999',
    '123456', '654321', '123123', '121212', '111222', '112233',
    '012345', '123450', '234567', '345678', '456789', '567890',
    '102030', '112233', '121314', '131415', '141516', '151617',
    '1234', '4321', '0000', '1111', '2222', '3333', '4444', '5555', '6666', '7777', '8888', '9999',
}


@dataclass
class Argon2Params:
    """Argon2id parameters for PIN derivation"""
    time_cost: int = 3            # Number of iterations
    memory_cost: int = 65536      # Memory in KiB (64 MB)
    parallelism: int = 4          # Number of threads
    hash_length: int = 32         # Output length in bytes (256-bit)
    salt_length: int = 16         # Salt length in bytes (128-bit)
    type: str = "argon2id"        # Hybrid mode (recommended)
    version: int = 0x13           # Argon2 version 1.3

    def to_metadata(self) -> Dict[str, Any]:
        return {
            "algorithm": "argon2id",
            "time_cost": self.time_cost,
            "memory_cost": self.memory_cost,
            "parallelism": self.parallelism,
            "hash_length": self.hash_length,
            "salt_length": self.salt_length,
            "version": self.version,
        }

    @classmethod
    def from_metadata(cls, metadata: Optional[Dict[str, Any]]) -> "Argon2Params":
        if not metadata:
            return cls()
        return cls(
            time_cost=metadata.get("time_cost", cls.time_cost),
            memory_cost=metadata.get("memory_cost", cls.memory_cost),
            parallelism=metadata.get("parallelism", cls.parallelism),
            hash_length=metadata.get("hash_length", cls.hash_length),
            salt_length=metadata.get("salt_length", cls.salt_length),
            type=metadata.get("algorithm", "argon2id"),
            version=metadata.get("version", cls.version),
        )


class PINValidationError(Exception):
    """Raised when PIN validation fails"""
    pass


class PINManager:
    """
    Manages PIN-based cryptographic operations.

    This class provides secure PIN handling without ever storing the PIN.
    Instead, the PIN is used to derive an encryption key via Argon2id,
    which is then used to encrypt the master vault key.

    Security Features:
    - Argon2id memory-hard KDF (resistant to GPU/ASIC attacks)
    - AES-256-GCM authenticated encryption
    - Secure memory wiping of sensitive data
    - PIN strength validation
    """

    def __init__(self, argon2_params: Optional[Argon2Params] = None):
        """
        Initialize PIN manager.

        Args:
            argon2_params: Argon2 parameters (uses defaults if None)
        """
        self.params = argon2_params or Argon2Params()

        if not ARGON2_AVAILABLE:
            logger.warning("Argon2 not available - using PBKDF2 fallback (less secure!)")

    def validate_pin_format(self, pin: str) -> None:
        """
        Validate PIN format and strength.

        Requirements:
        - 6-8 digits only
        - No repeating digits (e.g., 111111)
        - No sequential digits (e.g., 123456)
        - Not in common weak PIN list

        Args:
            pin: PIN to validate

        Raises:
            PINValidationError: If PIN doesn't meet requirements
        """
        # Check length
        if len(pin) < 6 or len(pin) > 8:
            raise PINValidationError("PIN must be 6-8 digits")

        # Check if digits only
        if not pin.isdigit():
            raise PINValidationError("PIN must contain only digits")

        # Check for repeating digits (e.g., 111111)
        if len(set(pin)) == 1:
            raise PINValidationError("PIN cannot have all repeating digits")

        # Check for sequential digits (ascending or descending)
        if self._is_sequential(pin):
            raise PINValidationError("PIN cannot be sequential (e.g., 123456)")

        # Check against weak PIN list
        if pin in WEAK_PINS:
            raise PINValidationError("PIN is too common - please choose a stronger PIN")

        # Check for patterns like 121212
        if self._has_pattern(pin):
            raise PINValidationError("PIN has a repeating pattern - please choose a more random PIN")

    def _is_sequential(self, pin: str) -> bool:
        """Check if PIN has sequential digits"""
        # Check ascending
        ascending = all(
            int(pin[i+1]) == int(pin[i]) + 1
            for i in range(len(pin) - 1)
        )

        # Check descending
        descending = all(
            int(pin[i+1]) == int(pin[i]) - 1
            for i in range(len(pin) - 1)
        )

        return ascending or descending

    def _has_pattern(self, pin: str) -> bool:
        """Check if PIN has repeating patterns like 121212"""
        # Check for 2-digit patterns
        if len(pin) >= 4:
            pattern = pin[:2]
            if pattern * (len(pin) // 2) == pin[:len(pin) - len(pin) % 2]:
                return True

        # Check for 3-digit patterns
        if len(pin) >= 6:
            pattern = pin[:3]
            if pattern * (len(pin) // 3) == pin[:len(pin) - len(pin) % 3]:
                return True

        return False

    def derive_key_from_pin(
        self,
        pin: str,
        salt: bytes,
        *,
        algorithm: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> bytes:
        """
        Derive encryption key from PIN using Argon2id.

        This is the core of the PIN authentication system. The PIN is used
        as input to a memory-hard key derivation function (Argon2id), which
        produces a cryptographically strong encryption key.

        Args:
            pin: User's PIN (6-8 digits)
            salt: Random salt (16 bytes)

        Returns:
            32-byte derived key (256-bit)

        Security Notes:
            - Argon2id is memory-hard (resistant to GPU attacks)
            - Salt ensures different keys for same PIN across users
            - PIN is wiped from memory after derivation
        """
        pin_bytes = bytearray(pin, 'utf-8')

        try:
            alg = (algorithm or ("argon2id" if ARGON2_AVAILABLE else "pbkdf2_sha256")).lower()
            if alg == "argon2id" and ARGON2_AVAILABLE:
                params = Argon2Params.from_metadata(metadata) if metadata else self.params
                derived_key = hash_secret_raw(
                    secret=bytes(pin_bytes),
                    salt=salt,
                    time_cost=params.time_cost,
                    memory_cost=params.memory_cost,
                    parallelism=params.parallelism,
                    hash_len=params.hash_length,
                    type=Type.ID,
                    version=params.version,
                )
            else:
                params = metadata or {}
                iterations = int(params.get("iterations", 600_000))
                length = int(params.get("length", self.params.hash_length))
                logger.warning("Using PBKDF2 for PIN derivation - ensure rate limiting is enforced")
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=length,
                    salt=salt,
                    iterations=iterations,
                )
                derived_key = kdf.derive(bytes(pin_bytes))

            return bytearray(derived_key)

        finally:
            # Wipe PIN from memory
            secure_wipe(pin_bytes)

    def generate_salt(self) -> bytes:
        """Generate cryptographically secure random salt"""
        return os.urandom(self.params.salt_length)

    def encrypt_master_key(
        self,
        master_key: Union[bytes, bytearray],
        pin_derived_key: Union[bytes, bytearray],
        associated_data: bytes
    ) -> bytes:
        """
        Encrypt master vault key with PIN-derived key using AES-256-GCM.

        AES-GCM provides authenticated encryption (AEAD), which means:
        - Confidentiality: Master key is encrypted
        - Authenticity: Any tampering will be detected
        - Associated data: Additional context is authenticated (email hash)

        Args:
            master_key: Master vault key to encrypt (32 bytes)
            pin_derived_key: Key derived from PIN (32 bytes)
            associated_data: Additional authenticated data (e.g., email hash)

        Returns:
            Encrypted data (nonce || ciphertext || tag)
                - nonce: 12 bytes (96-bit, GCM standard)
                - ciphertext: same length as master_key
                - tag: 16 bytes (128-bit authentication tag)

        Raises:
            ValueError: If key length is invalid
        """
        if len(pin_derived_key) != 32:
            raise ValueError("PIN-derived key must be 32 bytes")

        if len(master_key) != 32:
            raise ValueError("Master key must be 32 bytes")

        # Generate random nonce (never reuse!)
        nonce = os.urandom(12)  # 96-bit nonce (GCM standard)

        # Create AES-GCM cipher
        aesgcm = AESGCM(bytes(pin_derived_key))

        # Encrypt with authenticated encryption
        ciphertext = aesgcm.encrypt(
            nonce=nonce,
            data=bytes(master_key),
            associated_data=associated_data
        )

        # Return nonce || ciphertext || tag (all in one blob)
        # Note: aesgcm.encrypt() already returns ciphertext || tag
        return nonce + ciphertext

    def decrypt_master_key(
        self,
        encrypted_data: bytes,
        pin_derived_key: Union[bytes, bytearray],
        associated_data: bytes
    ) -> bytes:
        """
        Decrypt master vault key with PIN-derived key.

        This is used for PIN verification. If decryption succeeds, the PIN
        was correct. If decryption fails, the PIN was wrong.

        Args:
            encrypted_data: Encrypted master key (nonce || ciphertext || tag)
            pin_derived_key: Key derived from PIN attempt (32 bytes)
            associated_data: Additional authenticated data (must match encryption)

        Returns:
            Decrypted master key (32 bytes)

        Raises:
            cryptography.exceptions.InvalidTag: Wrong PIN or tampered data
            ValueError: Invalid encrypted data format
        """
        if len(pin_derived_key) != 32:
            raise ValueError("PIN-derived key must be 32 bytes")

        if len(encrypted_data) < 12 + 16:  # nonce + tag minimum
            raise ValueError("Invalid encrypted data format")

        # Extract nonce and ciphertext
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]  # Includes authentication tag

        # Create AES-GCM cipher
        aesgcm = AESGCM(bytes(pin_derived_key))

        # Decrypt and verify
        # If PIN is wrong, this will raise InvalidTag exception
        try:
            plaintext = aesgcm.decrypt(
                nonce=nonce,
                data=ciphertext,
                associated_data=associated_data
            )
            return plaintext
        except Exception as e:
            # Don't leak information about the error
            raise ValueError("Decryption failed - invalid PIN") from e

    def create_verification_marker(
        self,
        master_key: Union[bytes, bytearray],
        associated_data: bytes
    ) -> bytes:
        """
        Create verification marker to validate master key.

        The verification marker is a known string encrypted with the master key.
        After decrypting the master key with the PIN, we can verify it's correct
        by trying to decrypt this marker.

        Args:
            master_key: Master vault key (32 bytes)
            associated_data: Additional authenticated data

        Returns:
            Encrypted verification marker
        """
        # Use a known plaintext string
        verification_plaintext = b"SECURE_VAULT_AUTH_v1"

        # Generate nonce
        nonce = os.urandom(12)

        # Encrypt with master key
        aesgcm = AESGCM(bytes(master_key))
        ciphertext = aesgcm.encrypt(
            nonce=nonce,
            data=verification_plaintext,
            associated_data=associated_data
        )

        return nonce + ciphertext

    def verify_master_key(
        self,
        master_key: Union[bytes, bytearray],
        encrypted_verification_marker: bytes,
        associated_data: bytes
    ) -> bool:
        """
        Verify master key is correct by decrypting verification marker.

        Args:
            master_key: Master key to verify
            encrypted_verification_marker: Encrypted verification string
            associated_data: Additional authenticated data

        Returns:
            True if master key is valid, False otherwise
        """
        try:
            # Extract nonce and ciphertext
            nonce = encrypted_verification_marker[:12]
            ciphertext = encrypted_verification_marker[12:]

            # Decrypt verification marker
            aesgcm = AESGCM(bytes(master_key))
            plaintext = aesgcm.decrypt(
                nonce=nonce,
                data=ciphertext,
                associated_data=associated_data
            )

            # Check if it matches expected value
            return plaintext == b"SECURE_VAULT_AUTH_v1"

        except Exception:
            return False

    def generate_master_key(self) -> bytearray:
        """
        Generate new master vault encryption key.

        Returns:
            32-byte (256-bit) cryptographically secure random key
        """
        return bytearray(os.urandom(32))

    def hash_email_for_lookup(self, email: str) -> bytes:
        """Return a peppered hash for consistent email lookups."""
        email_normalized = email.lower().strip().encode("utf-8")
        pepper = get_email_pepper()
        return hashlib.blake2b(email_normalized, key=pepper, digest_size=32).digest()

    def hash_email_for_storage(self, email: str, *, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """Return a salted & peppered hash along with the salt used."""
        email_normalized = email.lower().strip().encode("utf-8")
        pepper = get_email_pepper()
        salt = salt or os.urandom(16)
        digest = hashlib.blake2b(
            email_normalized,
            key=pepper,
            salt=salt,
            digest_size=32,
        ).digest()
        return digest, salt

    def hash_email_legacy(self, email: str) -> bytes:
        """Return the legacy unsalted hash for backward compatibility."""
        email_normalized = email.lower().strip().encode("utf-8")
        return hashlib.blake2b(email_normalized).digest()

    def export_kdf_metadata(self, *, algorithm: Optional[str] = None) -> Dict[str, Any]:
        alg = (algorithm or ("argon2id" if ARGON2_AVAILABLE else "pbkdf2_sha256")).lower()
        if alg == "argon2id" and ARGON2_AVAILABLE:
            return self.params.to_metadata()
        if alg == "argon2id":
            # Argon2 requested but unavailable; fall back metadata should reflect PBKDF2 usage
            alg = "pbkdf2_sha256"
        return {
            "algorithm": alg,
            "iterations": 600_000,
            "length": self.params.hash_length,
        }


# Convenience functions for common operations

def validate_pin(pin: str) -> None:
    """Validate PIN format (convenience wrapper)"""
    manager = PINManager()
    manager.validate_pin_format(pin)


def derive_key(pin: str, salt: bytes) -> bytes:
    """Derive key from PIN (convenience wrapper)"""
    manager = PINManager()
    return manager.derive_key_from_pin(pin, salt)


def encrypt_key(master_key: bytes, pin_derived_key: bytes, email_hash: bytes) -> bytes:
    """Encrypt master key (convenience wrapper)"""
    manager = PINManager()
    associated_data = email_hash + b"master_key"
    return manager.encrypt_master_key(master_key, pin_derived_key, associated_data)


def decrypt_key(encrypted_data: bytes, pin_derived_key: bytes, email_hash: bytes) -> bytes:
    """Decrypt master key (convenience wrapper)"""
    manager = PINManager()
    associated_data = email_hash + b"master_key"
    return manager.decrypt_master_key(encrypted_data, pin_derived_key, associated_data)
