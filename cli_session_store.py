"""Encrypted CLI session persistence for SecureVault."""

from __future__ import annotations

import base64
import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from auth_secrets import get_session_pepper
from config import default_config

logger = logging.getLogger(__name__)


KEY_TTL = timedelta(days=1)


@dataclass
class PersistentSession:
    """Serializable representation of a CLI session."""

    session_id: str
    user_id: int
    created_at: datetime
    expires_at: datetime
    ip_address: Optional[str]
    user_agent: Optional[str]
    master_key: bytes


class EncryptedSessionStore:
    """Encrypt and persist CLI sessions for restart resilience."""

    def __init__(self, store_path: Optional[Path] = None) -> None:
        config_dir = Path(default_config.config_dir)
        self._store_path = store_path or config_dir / "cli_sessions.enc"
        self._key_info_path = self._store_path.with_suffix(".keyinfo")
        self._encryption_key = self._load_or_rotate_key()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def persist(self, sessions: Iterable[PersistentSession]) -> None:
        payload = [self._serialize_session(session) for session in sessions]
        self._write_encrypted(payload)

    def append(self, session: PersistentSession) -> None:
        sessions = {item.session_id: item for item in self.load_sessions()}
        sessions[session.session_id] = session
        self.persist(sessions.values())

    def remove(self, session_id: str) -> None:
        sessions = [s for s in self.load_sessions() if s.session_id != session_id]
        self.persist(sessions)

    def load_sessions(self) -> List[PersistentSession]:
        if not self._store_path.exists():
            return []

        try:
            data = self._read_encrypted()
        except Exception as exc:  # noqa: BLE001 - defensive decrypt handling
            logger.error("Failed to decrypt CLI session store: %s", exc)
            return []

        sessions: List[PersistentSession] = []
        for entry in data:
            try:
                sessions.append(self._deserialize_session(entry))
            except Exception as exc:  # noqa: BLE001
                logger.warning("Skipping invalid persisted session: %s", exc)
        return sessions

    def clear(self) -> None:
        if self._store_path.exists():
            try:
                self._store_path.unlink()
            except OSError:
                logger.debug("Failed to remove session store", exc_info=True)

    # ------------------------------------------------------------------
    # Encryption helpers
    # ------------------------------------------------------------------
    def _load_or_rotate_key(self) -> bytes:
        now = datetime.utcnow()
        if self._key_info_path.exists():
            try:
                key_info = json.loads(self._key_info_path.read_text(encoding="utf-8"))
                raw_key = base64.b64decode(key_info["key"])
                created = datetime.fromisoformat(key_info["created_at"])
                if now - created < KEY_TTL:
                    return self._derive_application_key(raw_key)
            except Exception:  # noqa: BLE001 - fallback to fresh key
                logger.warning("Unable to reuse CLI session key; rotating.")

        raw_key = os.urandom(32)
        key_info_payload = {
            "key": base64.b64encode(raw_key).decode("ascii"),
            "created_at": now.isoformat(),
        }
        self._key_info_path.parent.mkdir(parents=True, exist_ok=True)
        self._key_info_path.write_text(json.dumps(key_info_payload), encoding="utf-8")
        os.chmod(self._key_info_path, 0o600)
        return self._derive_application_key(raw_key)

    def _derive_application_key(self, raw_key: bytes) -> bytes:
        pepper = get_session_pepper()
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=pepper,
            info=b"secure-vault-cli-session",
        )
        return hkdf.derive(raw_key)

    def _cipher(self) -> AESGCM:
        return AESGCM(self._encryption_key)

    def _write_encrypted(self, payload: List[Dict[str, object]]) -> None:
        cipher = self._cipher()
        nonce = os.urandom(12)
        data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        ciphertext = cipher.encrypt(nonce, data, None)
        blob = base64.b64encode(nonce + ciphertext)
        self._store_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = self._store_path.with_suffix(".tmp")
        tmp_path.write_bytes(blob)
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, self._store_path)

    def _read_encrypted(self) -> List[Dict[str, object]]:
        blob = base64.b64decode(self._store_path.read_bytes())
        nonce, ciphertext = blob[:12], blob[12:]
        plaintext = self._cipher().decrypt(nonce, ciphertext, None)
        return json.loads(plaintext.decode("utf-8"))

    # ------------------------------------------------------------------
    # Serialization helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _serialize_session(session: PersistentSession) -> Dict[str, object]:
        return {
            "session_id": session.session_id,
            "user_id": session.user_id,
            "created_at": session.created_at.isoformat(),
            "expires_at": session.expires_at.isoformat(),
            "ip_address": session.ip_address,
            "user_agent": session.user_agent,
            "master_key": base64.b64encode(session.master_key).decode("ascii"),
        }

    @staticmethod
    def _deserialize_session(payload: Dict[str, object]) -> PersistentSession:
        return PersistentSession(
            session_id=str(payload["session_id"]),
            user_id=int(payload["user_id"]),
            created_at=datetime.fromisoformat(str(payload["created_at"])),
            expires_at=datetime.fromisoformat(str(payload["expires_at"])),
            ip_address=payload.get("ip_address"),
            user_agent=payload.get("user_agent"),
            master_key=base64.b64decode(payload["master_key"]),
        )


__all__ = ["EncryptedSessionStore", "PersistentSession"]

