"""Utilities for binding an authentication database to a specific device."""

from __future__ import annotations

import base64
import json
import logging
import os
import secrets
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional, TYPE_CHECKING

logger = logging.getLogger(__name__)


class InstanceStateError(Exception):
    """Raised when the persisted instance metadata cannot be processed."""


class TamperDetectedError(Exception):
    """Raised when tamper detection determines the environment is unsafe."""


if TYPE_CHECKING:  # pragma: no cover - used for type checking only
    from auth_database import AuthDatabase


class InstanceGuard:
    """Persisted state helper that detects authentication tampering."""

    STATE_FILENAME = "instance_state.json"

    def __init__(self, db_path: str, state_dir: Optional[str] = None) -> None:
        env_dir = os.environ.get("SECURE_VAULT_STATE_DIR")
        base_dir = state_dir or env_dir or os.path.expanduser("~/.config/secure_vault")
        self.state_dir = Path(base_dir)
        self.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.state_path = self.state_dir / self.STATE_FILENAME
        self.db_path = Path(db_path)
        self._state: Dict[str, Any] = {}
        self._fresh_state = False
        self._state = self._load_or_initialize_state()

    # ------------------------------------------------------------------
    # State handling
    # ------------------------------------------------------------------
    def _load_or_initialize_state(self) -> Dict[str, Any]:
        if self.state_path.exists():
            try:
                with self.state_path.open("r", encoding="utf-8") as handle:
                    data = json.load(handle)
            except (OSError, json.JSONDecodeError) as exc:  # pragma: no cover - defensive
                raise InstanceStateError("Unable to read instance guard state") from exc

            if "secret" not in data:
                raise InstanceStateError("Instance guard state missing secret")

            if data.get("status") not in {"pending", "provisioned", "locked"}:
                raise InstanceStateError("Instance guard state status is invalid")

            self._fresh_state = False
            return data

        secret_bytes = secrets.token_bytes(32)
        state = {
            "instance_id": secrets.token_hex(16),
            "secret": base64.b64encode(secret_bytes).decode("utf-8"),
            "status": "pending",
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat(),
        }
        self._write_state(state)
        self._fresh_state = True
        return state

    def _write_state(self, state: Dict[str, Any]) -> None:
        tmp_path = self.state_path.with_suffix(".tmp")
        with tmp_path.open("w", encoding="utf-8") as handle:
            json.dump(state, handle, sort_keys=True, indent=2)
        os.replace(tmp_path, self.state_path)
        os.chmod(self.state_path, 0o600)

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------
    @property
    def status(self) -> str:
        return str(self._state.get("status", "pending"))

    def is_locked(self) -> bool:
        return self.status == "locked"

    def get_secret(self) -> bytes:
        secret = self._state.get("secret")
        if not isinstance(secret, str):
            raise InstanceStateError("Instance guard secret is invalid")
        return base64.b64decode(secret.encode("utf-8"))

    def allows_initial_binding(self) -> bool:
        """Return True when the guard may legitimately initialize bindings."""

        return self._fresh_state and self.status == "pending"

    def verify_environment(self, db: "AuthDatabase") -> None:
        """Confirm that the authentication database matches the guard state."""

        if self.is_locked():
            raise TamperDetectedError(
                "SecureVault authentication has been locked due to prior tamper detection."
            )

        stored_hash = db.get_instance_secret()
        status = self.status

        if stored_hash is None:
            if self._fresh_state and not db.has_users():
                return

            self.lockdown("missing_instance_secret")
            raise TamperDetectedError(
                "Authentication store integrity verification failed; manual recovery required."
            )
            if status == "provisioned" or db.has_users():
                self.lockdown("missing_instance_secret")
                raise TamperDetectedError(
                    "Authentication store integrity verification failed; manual recovery required."
                )
            return

        expected_hash = db.hash_instance_secret(self.get_secret())
        if stored_hash != expected_hash:
            self.lockdown("binding_mismatch")
            raise TamperDetectedError(
                "Authentication store integrity verification failed; manual recovery required."
            )

        if status != "provisioned":
            self.mark_provisioned()

    def mark_provisioned(self) -> None:
        if self.status == "provisioned":
            return
        self._state["status"] = "provisioned"
        self._state["updated_at"] = datetime.utcnow().isoformat()
        self._write_state(self._state)

    def lockdown(self, reason: str) -> None:
        self._state["status"] = "locked"
        self._state["locked_at"] = datetime.utcnow().isoformat()
        self._state["lock_reason"] = reason
        self._write_state(self._state)
        logger.error("Instance guard entered lockdown due to %s", reason)

