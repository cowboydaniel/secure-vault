"""Multi-factor authentication manager for SecureVault."""

from __future__ import annotations

import base64
import json
import logging
import math
import os
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_public_key,
)

from config import default_config

logger = logging.getLogger(__name__)


@dataclass
class MFAChallenge:
    """Represents an MFA challenge that must be satisfied."""

    challenge_type: str
    prompt: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MFAResponse:
    """Response payload for an MFA challenge."""

    challenge_type: str
    payload: Dict[str, Any]


@dataclass
class _MFAEnrollment:
    """Stored enrollment information."""

    totp_secret: Optional[str] = None
    totp_digits: int = 6
    totp_step: int = 30
    hardware_public_key: Optional[str] = None
    hardware_label: Optional[str] = None
    biometric_template: Optional[list[float]] = None
    biometric_threshold: float = 0.25


class MFAConfigurationError(RuntimeError):
    """Raised when MFA is misconfigured."""


class MFAChallengeError(RuntimeError):
    """Raised when an MFA challenge cannot be completed."""


class MFAManager:
    """Manage multi-factor authentication enrollments and challenges."""

    STORE_FILENAME = "mfa_enrollments.json"

    def __init__(self, store_path: Optional[Path] = None) -> None:
        config_dir = Path(default_config.config_dir)
        self._store_path = store_path or config_dir / self.STORE_FILENAME
        self._pending_hardware: Dict[int, Dict[str, Any]] = {}
        self._load_enrollments()

    # ------------------------------------------------------------------
    # Persistence helpers
    # ------------------------------------------------------------------
    def _load_enrollments(self) -> None:
        self._enrollments: Dict[int, _MFAEnrollment] = {}
        if not self._store_path.exists():
            return

        try:
            raw = self._store_path.read_text(encoding="utf-8")
            payload = json.loads(raw)
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("Failed to load MFA enrollment store: %s", exc)
            return

        for key, value in payload.items():
            try:
                user_id = int(key)
            except ValueError:
                logger.debug("Skipping malformed MFA enrollment key: %s", key)
                continue

            enrollment = _MFAEnrollment(
                totp_secret=value.get("totp_secret"),
                totp_digits=int(value.get("totp_digits", 6)),
                totp_step=int(value.get("totp_step", 30)),
                hardware_public_key=value.get("hardware_public_key"),
                hardware_label=value.get("hardware_label"),
                biometric_template=value.get("biometric_template"),
                biometric_threshold=float(value.get("biometric_threshold", 0.25)),
            )
            self._enrollments[user_id] = enrollment

    def _write_enrollments(self) -> None:
        data = {}
        for user_id, enrollment in self._enrollments.items():
            data[str(user_id)] = {
                "totp_secret": enrollment.totp_secret,
                "totp_digits": enrollment.totp_digits,
                "totp_step": enrollment.totp_step,
                "hardware_public_key": enrollment.hardware_public_key,
                "hardware_label": enrollment.hardware_label,
                "biometric_template": enrollment.biometric_template,
                "biometric_threshold": enrollment.biometric_threshold,
            }

        try:
            self._store_path.parent.mkdir(parents=True, exist_ok=True)
            tmp_path = self._store_path.with_suffix(".tmp")
            tmp_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
            os.replace(tmp_path, self._store_path)
        except OSError as exc:
            logger.error("Failed to persist MFA enrollment store: %s", exc)
            raise MFAConfigurationError(str(exc)) from exc

    # ------------------------------------------------------------------
    # Enrollment management
    # ------------------------------------------------------------------
    def clear_enrollment(self, user_id: int) -> None:
        self._enrollments.pop(user_id, None)
        self._pending_hardware.pop(user_id, None)
        self._write_enrollments()

    def enroll_totp(
        self,
        user_id: int,
        secret: str,
        *,
        digits: int = 6,
        step: int = 30,
    ) -> None:
        """Register TOTP for the given user."""

        normalized = secret.replace(" ", "").upper()
        try:
            base64.b32decode(normalized)
        except Exception as exc:  # noqa: BLE001 - broad for invalid data
            raise MFAConfigurationError("Invalid TOTP secret") from exc

        enrollment = self._enrollments.get(user_id, _MFAEnrollment())
        enrollment.totp_secret = normalized
        enrollment.totp_digits = digits
        enrollment.totp_step = step
        self._enrollments[user_id] = enrollment
        self._write_enrollments()

    def enroll_hardware_key(
        self,
        user_id: int,
        public_key_pem: bytes,
        *,
        label: Optional[str] = None,
    ) -> None:
        """Register a hardware security key for the user."""

        try:
            public_key = load_pem_public_key(public_key_pem)
        except ValueError as exc:
            raise MFAConfigurationError("Invalid hardware key data") from exc

        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            raise MFAConfigurationError("Hardware keys must use EC public keys")

        serialized = public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        enrollment = self._enrollments.get(user_id, _MFAEnrollment())
        enrollment.hardware_public_key = serialized.decode("utf-8")
        enrollment.hardware_label = label
        self._enrollments[user_id] = enrollment
        self._write_enrollments()

    def enroll_biometric(
        self,
        user_id: int,
        template: Iterable[float],
        *,
        threshold: float = 0.25,
    ) -> None:
        """Register a biometric template for the user."""

        vector = [float(value) for value in template]
        if not vector:
            raise MFAConfigurationError("Biometric template cannot be empty")

        enrollment = self._enrollments.get(user_id, _MFAEnrollment())
        enrollment.biometric_template = vector
        enrollment.biometric_threshold = max(0.05, float(threshold))
        self._enrollments[user_id] = enrollment
        self._write_enrollments()

    # ------------------------------------------------------------------
    # Challenge lifecycle
    # ------------------------------------------------------------------
    def has_mfa(self, user_id: int) -> bool:
        enrollment = self._enrollments.get(user_id)
        if not enrollment:
            return False
        return any(
            (
                enrollment.totp_secret,
                enrollment.hardware_public_key,
                enrollment.biometric_template,
            )
        )

    def build_challenge(self, user_id: int) -> MFAChallenge:
        enrollment = self._enrollments.get(user_id)
        if not enrollment:
            raise MFAChallengeError("No MFA enrollment for user")

        # Prioritise hardware keys -> biometric -> TOTP to support strongest method first
        if enrollment.hardware_public_key:
            challenge = secrets.token_bytes(32)
            metadata = {
                "challenge": base64.b64encode(challenge).decode("ascii"),
                "label": enrollment.hardware_label or "Security key",
            }
            self._pending_hardware[user_id] = {
                "challenge": challenge,
                "timestamp": time.time(),
            }
            return MFAChallenge(
                challenge_type="hardware_key",
                prompt="Touch your registered security key to sign the challenge.",
                metadata=metadata,
            )

        if enrollment.biometric_template:
            return MFAChallenge(
                challenge_type="biometric",
                prompt="Provide a biometric sample to unlock the vault.",
                metadata={
                    "length": len(enrollment.biometric_template),
                    "threshold": enrollment.biometric_threshold,
                },
            )

        if enrollment.totp_secret:
            return MFAChallenge(
                challenge_type="totp",
                prompt="Enter the verification code from your authenticator app.",
                metadata={
                    "digits": enrollment.totp_digits,
                    "step": enrollment.totp_step,
                },
            )

        raise MFAChallengeError("No MFA methods enabled")

    def verify_response(self, user_id: int, response: MFAResponse) -> bool:
        enrollment = self._enrollments.get(user_id)
        if not enrollment:
            raise MFAChallengeError("No MFA enrollment for user")

        if response.challenge_type == "hardware_key":
            return self._verify_hardware(user_id, enrollment, response.payload)

        if response.challenge_type == "biometric":
            return self._verify_biometric(enrollment, response.payload)

        if response.challenge_type == "totp":
            return self._verify_totp(enrollment, response.payload)

        raise MFAChallengeError(f"Unsupported challenge type: {response.challenge_type}")

    # ------------------------------------------------------------------
    # Specific verifiers
    # ------------------------------------------------------------------
    def _verify_totp(self, enrollment: _MFAEnrollment, payload: Dict[str, Any]) -> bool:
        if not enrollment.totp_secret:
            raise MFAChallengeError("TOTP is not configured")

        try:
            code = str(payload["code"]).strip()
        except KeyError as exc:  # noqa: PERF203 - explicit for clarity
            raise MFAChallengeError("Missing TOTP code") from exc

        if not code.isdigit():
            raise MFAChallengeError("TOTP codes must be numeric")

        digits = enrollment.totp_digits
        step = enrollment.totp_step
        secret = enrollment.totp_secret

        counter = int(time.time() // step)
        for offset in (-1, 0, 1):
            expected = self._generate_totp(secret, counter + offset, digits)
            if expected == code:
                return True

        raise MFAChallengeError("Invalid verification code")

    def _verify_hardware(
        self,
        user_id: int,
        enrollment: _MFAEnrollment,
        payload: Dict[str, Any],
    ) -> bool:
        if not enrollment.hardware_public_key:
            raise MFAChallengeError("Hardware key not configured")

        pending = self._pending_hardware.get(user_id)
        if not pending:
            raise MFAChallengeError("No pending hardware challenge")

        if time.time() - pending["timestamp"] > 90:
            self._pending_hardware.pop(user_id, None)
            raise MFAChallengeError("Hardware key challenge expired")

        try:
            signature_bytes = base64.b64decode(payload["signature"])
        except (KeyError, ValueError) as exc:
            raise MFAChallengeError("Invalid hardware key response") from exc

        public_key = load_pem_public_key(
            enrollment.hardware_public_key.encode("utf-8")
        )
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            raise MFAChallengeError("Unsupported hardware key algorithm")

        challenge = pending["challenge"]
        self._pending_hardware.pop(user_id, None)

        try:
            r, s = decode_dss_signature(signature_bytes)
            der_signature = encode_dss_signature(r, s)
            public_key.verify(der_signature, challenge, ec.ECDSA(hashes.SHA256()))
            return True
        except (InvalidSignature, ValueError) as exc:
            raise MFAChallengeError("Hardware key verification failed") from exc

    def _verify_biometric(
        self,
        enrollment: _MFAEnrollment,
        payload: Dict[str, Any],
    ) -> bool:
        template = enrollment.biometric_template
        if not template:
            raise MFAChallengeError("Biometric template not configured")

        sample = payload.get("sample")
        if sample is None:
            raise MFAChallengeError("Biometric sample missing")

        vector = [float(value) for value in sample]
        if len(vector) != len(template):
            raise MFAChallengeError("Biometric sample has incorrect dimensions")

        distance = math.sqrt(
            sum((a - b) ** 2 for a, b in zip(template, vector))
        )
        normalized = distance / math.sqrt(len(template))
        return normalized <= enrollment.biometric_threshold

    # ------------------------------------------------------------------
    # Helper utilities
    # ------------------------------------------------------------------
    @staticmethod
    def _generate_totp(secret: str, counter: int, digits: int) -> str:
        key = base64.b32decode(secret)
        msg = counter.to_bytes(8, "big")
        h = hmac.HMAC(key, hashes.SHA1())
        h.update(msg)
        digest = h.finalize()
        offset = digest[-1] & 0x0F
        binary = int.from_bytes(digest[offset : offset + 4], "big") & 0x7FFFFFFF
        code = binary % (10 ** digits)
        return str(code).zfill(digits)


__all__ = [
    "MFAManager",
    "MFAChallenge",
    "MFAResponse",
    "MFAChallengeError",
    "MFAConfigurationError",
]

