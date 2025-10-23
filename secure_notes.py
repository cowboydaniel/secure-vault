"""Secure Notes storage and encryption utilities for SecureVault."""
from __future__ import annotations

import base64
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


FALLBACK_ASSOCIATED_DATA = b"SecureNotesVaultFallback"
FALLBACK_ENVELOPE_VERSION = 1
FALLBACK_WRAP_INFO = b"SecureNotesFallbackWrap"


class SecureNotesLockedError(RuntimeError):
    """Raised when secure notes access requires re-authentication."""


@dataclass
class SecureNote:
    """Dataclass representing a secure note entry."""

    note_id: str
    title: str
    body: str
    created_at: float
    updated_at: float


class SecureNotesVault:
    """Manages encrypted storage of secure notes."""

    def __init__(
        self,
        storage_path: Optional[Path] = None,
        key_fallback_path: Optional[Path] = None,
        session_provider: Optional[Callable[[], Optional[object]]] = None,
        device_secret_provider: Optional[Callable[[], Optional[bytes]]] = None,
    ) -> None:
        self.base_dir = Path.home() / ".securevault"
        self.base_dir.mkdir(mode=0o700, exist_ok=True)

        self.storage_path = storage_path or (self.base_dir / "secure_notes.vault")
        self.key_fallback_path = key_fallback_path or (self.base_dir / "secure_notes.key")
        self.salt_path = self.base_dir / "secure_notes.salt"
        self.session_provider = session_provider
        self.device_secret_provider = device_secret_provider
        self._cached_key: Optional[bytes] = None

    def load_notes(self) -> List[SecureNote]:
        """Load notes from encrypted storage."""
        if not self.storage_path.exists():
            return []

        payload = json.loads(self.storage_path.read_text(encoding="utf-8"))

        nonce = base64.b64decode(payload["nonce"])
        ciphertext = base64.b64decode(payload["ciphertext"])
        associated = payload.get("associated", "").encode("utf-8") or None

        key = self._get_encryption_key()
        aesgcm = AESGCM(key)
        data = aesgcm.decrypt(nonce, ciphertext, associated)
        raw_notes = json.loads(data.decode("utf-8"))

        return [SecureNote(**note) for note in raw_notes]

    def save_notes(self, notes: List[SecureNote]) -> None:
        """Persist the provided notes list to encrypted storage."""
        key = self._get_encryption_key()
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        associated = b"secure-notes-v1"

        data = json.dumps([note.__dict__ for note in notes], ensure_ascii=False).encode("utf-8")
        ciphertext = aesgcm.encrypt(nonce, data, associated)

        payload = {
            "version": 1,
            "nonce": base64.b64encode(nonce).decode("utf-8"),
            "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
            "associated": associated.decode("utf-8"),
        }
        self.storage_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        os.chmod(self.storage_path, stat.S_IRUSR | stat.S_IWUSR)

    # Internal helpers -------------------------------------------------
    def _get_encryption_key(self) -> bytes:
        if self._cached_key is not None:
            return self._cached_key

        session = self.session_provider() if self.session_provider else None
        if session is None:
            raise SecureNotesLockedError(
                "Secure notes are locked. Please re-authenticate to continue."
            )

        try:
            with session.master_key() as master_key_buffer:  # type: ignore[attr-defined]
                master_key = bytes(master_key_buffer)
        except Exception as exc:  # pragma: no cover - defensive
            raise SecureNotesLockedError(
                "Secure notes are locked. Please re-authenticate to continue."
            ) from exc

        salt = self._load_or_create_salt()
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b"SecureNotesVault",
        )
        key = hkdf.derive(master_key)
        self._persist_fallback_key(master_key, key)
        del master_key

        self._cached_key = key
        return key

    def _load_or_create_salt(self) -> bytes:
        if self.salt_path.exists():
            return self.salt_path.read_bytes()

        salt = os.urandom(16)
        self.salt_path.write_bytes(salt)
        os.chmod(self.salt_path, stat.S_IRUSR | stat.S_IWUSR)
        return salt

    def _persist_fallback_key(self, master_key: bytes, key: bytes) -> None:
        """Persist the derived key encrypted with a device-bound secret."""

        device_secret = self._get_device_secret()
        if device_secret is None:
            # Remove legacy plaintext fallback keys when we cannot secure them.
            try:
                if self.key_fallback_path.exists():
                    self.key_fallback_path.unlink()
            except OSError:  # pragma: no cover - defensive cleanup
                pass
            return

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=device_secret,
            info=FALLBACK_WRAP_INFO,
        )
        wrap_key = hkdf.derive(master_key)
        aesgcm = AESGCM(wrap_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, key, FALLBACK_ASSOCIATED_DATA)

        payload = {
            "version": FALLBACK_ENVELOPE_VERSION,
            "nonce": base64.b64encode(nonce).decode("utf-8"),
            "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
        }
        self.key_fallback_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        os.chmod(self.key_fallback_path, stat.S_IRUSR | stat.S_IWUSR)

    def _get_device_secret(self) -> Optional[bytes]:
        if self.device_secret_provider is not None:
            return self.device_secret_provider()

        state_dir = Path(
            os.environ.get("SECURE_VAULT_STATE_DIR", Path.home() / ".config" / "secure_vault")
        )
        state_path = state_dir / "instance_state.json"
        try:
            data = json.loads(state_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None
        except (OSError, json.JSONDecodeError):  # pragma: no cover - defensive
            return None

        secret_b64 = data.get("secret")
        if not isinstance(secret_b64, str):
            return None

        try:
            return base64.b64decode(secret_b64.encode("utf-8"))
        except (TypeError, ValueError):  # pragma: no cover - defensive
            return None


__all__ = ["SecureNote", "SecureNotesVault", "SecureNotesLockedError"]
