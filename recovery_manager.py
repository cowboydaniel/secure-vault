"""Account recovery workflow helpers."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional

from config import default_config

logger = logging.getLogger(__name__)


@dataclass
class RecoveryChallenge:
    email: str
    code_hash: str
    issued_at: float
    expires_in: int = 600

    def is_expired(self) -> bool:
        return time.time() > self.issued_at + self.expires_in


class RecoveryManager:
    """Issue and validate recovery verification codes."""

    STORE_FILENAME = "recovery_codes.json"
    HMAC_KEY_NAME = "recovery_hmac"

    def __init__(self, store_path: Optional[Path] = None) -> None:
        config_dir = Path(default_config.config_dir)
        self._store_path = store_path or config_dir / self.STORE_FILENAME
        self._hmac_key_path = config_dir / f"{self.HMAC_KEY_NAME}.key"
        self._load_state()

    def issue_code(self, email: str) -> str:
        """Generate a one-time recovery code for *email*."""

        code = f"{secrets.randbelow(10**6):06d}"
        normalized_email = email.strip().lower()
        code_hash = self._hash_code(normalized_email, code)
        self._challenges[normalized_email] = RecoveryChallenge(
            email=normalized_email,
            code_hash=code_hash,
            issued_at=time.time(),
        )
        self._write_state()
        return code

    def verify_code(self, email: str, code: str) -> bool:
        normalized_email = email.strip().lower()
        challenge = self._challenges.get(normalized_email)
        if not challenge:
            return False

        if challenge.is_expired():
            logger.info("Recovery code for %s expired", normalized_email)
            self._challenges.pop(normalized_email, None)
            self._write_state()
            return False

        expected_hash = self._hash_code(normalized_email, code)
        if not hmac.compare_digest(expected_hash, challenge.code_hash):
            return False

        self._challenges.pop(normalized_email, None)
        self._write_state()
        return True

    def clear_code(self, email: str) -> None:
        normalized_email = email.strip().lower()
        if normalized_email in self._challenges:
            self._challenges.pop(normalized_email, None)
            self._write_state()

    def _load_state(self) -> None:
        self._challenges: Dict[str, RecoveryChallenge] = {}
        if not self._store_path.exists():
            return
        try:
            raw = self._store_path.read_text(encoding="utf-8")
            payload = json.loads(raw)
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("Failed to load recovery store: %s", exc)
            return

        for email, entry in payload.items():
            try:
                self._challenges[email] = RecoveryChallenge(
                    email=email,
                    code_hash=entry["code_hash"],
                    issued_at=float(entry["issued_at"]),
                    expires_in=int(entry.get("expires_in", 600)),
                )
            except KeyError:
                logger.debug("Skipping malformed recovery record for %s", email)

    def _write_state(self) -> None:
        data = {
            email: {
                "code_hash": challenge.code_hash,
                "issued_at": challenge.issued_at,
                "expires_in": challenge.expires_in,
            }
            for email, challenge in self._challenges.items()
        }
        self._store_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._store_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        os.replace(tmp, self._store_path)

    def _hash_code(self, email: str, code: str) -> str:
        key = self._load_or_create_hmac_key()
        digest = hmac.new(key, f"{email}|{code}".encode("utf-8"), hashlib.sha256)
        return base64.b64encode(digest.digest()).decode("ascii")

    def _load_or_create_hmac_key(self) -> bytes:
        if self._hmac_key_path.exists():
            data = self._hmac_key_path.read_bytes()
            if len(data) == 32:
                return data
        key = os.urandom(32)
        self._hmac_key_path.write_bytes(key)
        os.chmod(self._hmac_key_path, 0o600)
        return key


__all__ = ["RecoveryManager", "RecoveryChallenge"]

