"""Secure account delegation workflows."""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from access_control import PermissionLevel
from auth_secrets import get_session_pepper
from config import default_config

logger = logging.getLogger(__name__)


@dataclass
class DelegationRecord:
    delegation_id: str
    grantor_id: int
    grantee_email: str
    permission: PermissionLevel
    created_at: datetime
    expires_at: Optional[datetime]
    encrypted_share: str


class DelegationManager:
    """Manage encrypted delegation invitations for shared access."""

    STORE_FILENAME = "delegations.json"

    def __init__(self, store_path: Optional[Path] = None) -> None:
        config_dir = Path(default_config.config_dir)
        self._store_path = store_path or config_dir / self.STORE_FILENAME
        self._encryption_key = get_session_pepper()
        self._records: Dict[str, DelegationRecord] = {}
        self._load()

    def create_delegation(
        self,
        *,
        delegation_id: str,
        grantor_id: int,
        grantee_email: str,
        permission: PermissionLevel,
        payload: bytes,
        ttl_hours: int = 72,
    ) -> DelegationRecord:
        aes = AESGCM(self._derive_key())
        nonce = os.urandom(12)
        encrypted = aes.encrypt(nonce, payload, None)
        expires_at = datetime.utcnow() + timedelta(hours=ttl_hours)
        record = DelegationRecord(
            delegation_id=delegation_id,
            grantor_id=grantor_id,
            grantee_email=grantee_email,
            permission=permission,
            created_at=datetime.utcnow(),
            expires_at=expires_at,
            encrypted_share=(nonce + encrypted).hex(),
        )
        self._records[delegation_id] = record
        self._persist()
        return record

    def list_active(self) -> List[DelegationRecord]:
        now = datetime.utcnow()
        return [
            record
            for record in self._records.values()
            if record.expires_at is None or record.expires_at > now
        ]

    def revoke(self, delegation_id: str) -> None:
        if delegation_id in self._records:
            self._records.pop(delegation_id)
            self._persist()

    def retrieve_payload(self, delegation_id: str) -> Optional[bytes]:
        record = self._records.get(delegation_id)
        if not record:
            return None
        if record.expires_at and record.expires_at <= datetime.utcnow():
            self._records.pop(delegation_id, None)
            self._persist()
            return None
        blob = bytes.fromhex(record.encrypted_share)
        nonce, ciphertext = blob[:12], blob[12:]
        aes = AESGCM(self._derive_key())
        try:
            return aes.decrypt(nonce, ciphertext, None)
        except Exception as exc:  # noqa: BLE001 - defensive decrypt
            logger.error("Failed to decrypt delegation payload: %s", exc)
            return None

    def _derive_key(self) -> bytes:
        return self._encryption_key

    def _load(self) -> None:
        if not self._store_path.exists():
            return
        try:
            payload = json.loads(self._store_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("Failed to load delegation store: %s", exc)
            return
        for entry in payload:
            try:
                record = DelegationRecord(
                    delegation_id=entry["delegation_id"],
                    grantor_id=int(entry["grantor_id"]),
                    grantee_email=entry["grantee_email"],
                    permission=PermissionLevel(entry["permission"]),
                    created_at=datetime.fromisoformat(entry["created_at"]),
                    expires_at=(
                        datetime.fromisoformat(entry["expires_at"])
                        if entry.get("expires_at")
                        else None
                    ),
                    encrypted_share=entry["encrypted_share"],
                )
                self._records[record.delegation_id] = record
            except Exception as exc:  # noqa: BLE001
                logger.debug("Skipping invalid delegation entry: %s", exc)

    def _persist(self) -> None:
        data = []
        for record in self._records.values():
            payload = asdict(record)
            payload["permission"] = record.permission.value
            payload["created_at"] = record.created_at.isoformat()
            payload["expires_at"] = (
                record.expires_at.isoformat() if record.expires_at else None
            )
            data.append(payload)
        self._store_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._store_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        os.replace(tmp, self._store_path)


__all__ = ["DelegationManager", "DelegationRecord"]

