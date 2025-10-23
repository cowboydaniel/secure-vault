"""Utilities for binding an authentication database to a specific device."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import logging
import os
import platform
import secrets
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional, TYPE_CHECKING

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from crypto_utils import derive_key_hkdf_sha3_512

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
    MARKER_FILENAME = "instance_marker.json"
    SECRET_PAYLOAD_VERSION = 2
    SECRET_WRAP_SALT = hashlib.sha256(b"InstanceGuard::secret_wrap").digest()
    SECRET_WRAP_INFO = b"instance-guard-secret"
    SECRET_WRAP_ENV = "SECURE_VAULT_GUARD_WRAP_SECRET"

    def __init__(self, db_path: str, state_dir: Optional[str] = None) -> None:
        env_dir = os.environ.get("SECURE_VAULT_STATE_DIR")
        base_dir = state_dir or env_dir or os.path.expanduser("~/.config/secure_vault")
        self.state_dir = Path(base_dir)
        self.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.state_path = self.state_dir / self.STATE_FILENAME
        self.marker_path = self.state_dir / self.MARKER_FILENAME
        self.db_path = Path(db_path)
        self._state: Dict[str, Any] = {}
        self._fresh_state = False
        self._wrap_key: Optional[bytes] = None
        self._secret_cache: Optional[bytes] = None
        self._marker: Optional[Dict[str, Any]] = self._load_marker()
        self._state = self._load_or_initialize_state()
        self._secret_cache = self._load_secret_from_state(self._state)

    # ------------------------------------------------------------------
    # State handling
    # ------------------------------------------------------------------
    def _load_marker(self) -> Optional[Dict[str, Any]]:
        if not self.marker_path.exists():
            return None

        try:
            with self.marker_path.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:  # pragma: no cover - defensive
            raise InstanceStateError("Unable to read instance guard marker") from exc

        if not isinstance(data, dict):
            raise InstanceStateError("Instance guard marker is invalid")

        return data

    def _write_marker(self, marker: Dict[str, Any]) -> None:
        tmp_path = self.marker_path.with_suffix(".tmp")
        with tmp_path.open("w", encoding="utf-8") as handle:
            json.dump(marker, handle, sort_keys=True, indent=2)
        os.replace(tmp_path, self.marker_path)
        os.chmod(self.marker_path, 0o600)
        self._marker = marker

    def _marker_indicates_provisioned(self) -> bool:
        marker = self._marker
        if not marker:
            return False

        binding_hash = marker.get("binding_hash")
        if isinstance(binding_hash, str) and binding_hash:
            return True

        provisioned = marker.get("provisioned")
        return bool(provisioned)

    def _load_or_initialize_state(self) -> Dict[str, Any]:
        if self.state_path.exists():
            try:
                with self.state_path.open("r", encoding="utf-8") as handle:
                    data = json.load(handle)
            except (OSError, json.JSONDecodeError) as exc:  # pragma: no cover - defensive
                raise InstanceStateError("Unable to read instance guard state") from exc

            if "secret" not in data and "secret_wrapped" not in data:
                raise InstanceStateError("Instance guard state missing secret")

            if data.get("status") not in {"pending", "provisioned", "locked"}:
                raise InstanceStateError("Instance guard state status is invalid")

            if data.get("status") in {"provisioned", "locked"} and not self._marker_indicates_provisioned():
                logger.error(
                    "Instance guard marker missing while state indicates provisioning"
                )
                raise TamperDetectedError(
                    "Authentication guard marker missing; manual recovery required."
                )

            if data.get("status") == "pending" and self._marker_indicates_provisioned():
                logger.error(
                    "Instance guard marker indicates prior provisioning but state reverted"
                )
                raise TamperDetectedError(
                    "Authentication guard state reverted unexpectedly; manual recovery required."
                )

            self._fresh_state = False
            return data

        if self._database_has_prior_state():
            logger.error(
                "Instance guard state missing while authentication database %s persists",
                self.db_path,
            )
            raise TamperDetectedError(
                "Authentication guard state missing; manual recovery is required."
            )

        secret_bytes = secrets.token_bytes(32)
        state = {
            "instance_id": secrets.token_hex(16),
            "status": "pending",
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat(),
        }
        state["secret_wrapped"] = self._wrap_secret(secret_bytes)
        self._write_state(state)
        self._fresh_state = True
        self._secret_cache = secret_bytes
        return state

    def _database_has_prior_state(self) -> bool:
        """Return ``True`` when the database indicates a previous installation."""

        try:
            if self._marker_indicates_provisioned():
                return True
            if not self.db_path.exists():
                return False

            # An empty file may appear during initial provisioning. Treat non-empty
            # databases as an indication of prior state to avoid silent resets.
            return self.db_path.stat().st_size > 0
        except OSError:  # pragma: no cover - defensive
            # Err on the side of caution by assuming prior state when the database
            # cannot be inspected.
            return True

    def _write_state(self, state: Dict[str, Any]) -> None:
        tmp_path = self.state_path.with_suffix(".tmp")
        sanitized = dict(state)
        sanitized.pop("secret", None)
        with tmp_path.open("w", encoding="utf-8") as handle:
            json.dump(sanitized, handle, sort_keys=True, indent=2)
        os.replace(tmp_path, self.state_path)
        os.chmod(self.state_path, 0o600)

    def _derive_secret_wrap_key(self) -> bytes:
        if self._wrap_key is not None:
            return self._wrap_key

        entropy_components: list[bytes] = []

        env_secret = os.environ.get(self.SECRET_WRAP_ENV)
        if env_secret:
            entropy_components.append(env_secret.encode("utf-8"))

        machine_id = ""
        for path in (Path("/etc/machine-id"), Path("/var/lib/dbus/machine-id")):
            try:
                machine_id = path.read_text(encoding="utf-8").strip()
            except OSError:
                continue
            if machine_id:
                entropy_components.append(machine_id.encode("utf-8"))
                break

        device_hint = os.environ.get("SECURE_VAULT_DEVICE_ID")
        if device_hint:
            entropy_components.append(device_hint.encode("utf-8"))

        node_identifier = uuid.getnode()
        if node_identifier:
            entropy_components.append(f"node:{node_identifier:012x}".encode("ascii"))

        hostname = platform.node()
        if hostname:
            entropy_components.append(hostname.encode("utf-8"))

        if not entropy_components:
            raise InstanceStateError(
                "Unable to derive device binding entropy for instance guard secret"
            )

        seed = hashlib.sha3_512(b"\x00".join(entropy_components)).digest()
        self._wrap_key = derive_key_hkdf_sha3_512(
            seed,
            length=32,
            salt=self.SECRET_WRAP_SALT,
            info=self.SECRET_WRAP_INFO,
        )
        return self._wrap_key

    def _wrap_secret(self, secret: bytes) -> Dict[str, str]:
        if not isinstance(secret, (bytes, bytearray)):
            raise InstanceStateError("Instance guard secret must be bytes")

        key = self._derive_secret_wrap_key()
        nonce = os.urandom(12)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, bytes(secret), self.SECRET_WRAP_INFO)
        return {
            "version": self.SECRET_PAYLOAD_VERSION,
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        }

    def _unwrap_secret(self, payload: Dict[str, Any]) -> bytes:
        if payload.get("version") != self.SECRET_PAYLOAD_VERSION:
            raise InstanceStateError("Unsupported instance guard secret format")

        try:
            nonce = base64.b64decode(payload["nonce"])
            ciphertext = base64.b64decode(payload["ciphertext"])
        except (KeyError, ValueError, binascii.Error) as exc:
            raise InstanceStateError("Instance guard secret payload is invalid") from exc

        key = self._derive_secret_wrap_key()
        aesgcm = AESGCM(key)
        try:
            return aesgcm.decrypt(nonce, ciphertext, self.SECRET_WRAP_INFO)
        except Exception as exc:  # pragma: no cover - integrity protection
            raise TamperDetectedError(
                "Instance guard secret failed authentication; manual recovery required."
            ) from exc

    def _load_secret_from_state(self, state: Dict[str, Any]) -> bytes:
        payload = state.get("secret_wrapped")
        if isinstance(payload, dict):
            return self._unwrap_secret(payload)

        legacy = state.get("secret")
        if not isinstance(legacy, str):
            raise InstanceStateError("Instance guard secret is missing")

        try:
            secret = base64.b64decode(legacy.encode("utf-8"))
        except (ValueError, binascii.Error) as exc:  # pragma: no cover - defensive
            raise InstanceStateError("Instance guard legacy secret is invalid") from exc

        state["secret_wrapped"] = self._wrap_secret(secret)
        state.pop("secret", None)
        self._write_state(state)
        return secret

    def ensure_binding_marker(self, binding_hash: str, *, allow_create: bool = False) -> None:
        """Validate or initialize the tamper-evident binding marker."""

        if not isinstance(binding_hash, str) or not binding_hash:
            raise InstanceStateError("Instance guard binding hash is invalid")

        marker = self._marker

        if marker is None:
            if not allow_create:
                logger.error("Instance guard marker missing when binding expected")
                self.lockdown("missing_marker")
                raise TamperDetectedError(
                    "Authentication guard marker missing; manual recovery required."
                )

            marker = {
                "binding_hash": binding_hash,
                "provisioned": True,
                "created_at": datetime.utcnow().isoformat(),
                "updated_at": datetime.utcnow().isoformat(),
            }
            self._write_marker(marker)
            return

        existing_hash = marker.get("binding_hash")

        if existing_hash is None:
            if allow_create:
                marker["binding_hash"] = binding_hash
                marker["provisioned"] = True
            else:
                logger.error("Instance guard marker missing binding hash")
                self.lockdown("missing_marker")
                raise TamperDetectedError(
                    "Authentication guard marker missing; manual recovery required."
                )
        elif existing_hash != binding_hash:
            self.lockdown("binding_marker_mismatch")
            raise TamperDetectedError(
                "Authentication guard tamper marker mismatch; manual recovery required."
            )

        marker["updated_at"] = datetime.utcnow().isoformat()
        self._write_marker(marker)

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------
    @property
    def status(self) -> str:
        return str(self._state.get("status", "pending"))

    def is_locked(self) -> bool:
        return self.status == "locked"

    def get_secret(self) -> bytes:
        if self._secret_cache is None:
            self._secret_cache = self._load_secret_from_state(self._state)
        return bytes(self._secret_cache)

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
        if stored_hash is not None:
            self.ensure_binding_marker(expected_hash, allow_create=False)

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

