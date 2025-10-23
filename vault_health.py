"""Vault health assessment helpers for SecureVault."""
from __future__ import annotations

import math
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Tuple

from audit_logger import DEFAULT_AUDIT_LOG_DIR


@dataclass
class HealthCheckResult:
    """Represents a single health check outcome."""

    name: str
    status: str
    details: str
    remediation: str = ""


class VaultHealthEvaluator:
    """Runs a suite of lightweight health checks on the local vault."""

    def __init__(self, base_dir: Path | None = None) -> None:
        self.base_dir = base_dir or (Path.home() / ".securevault")
        self.base_dir.mkdir(mode=0o700, exist_ok=True)

    def run_checks(self) -> Tuple[str, List[HealthCheckResult]]:
        results = [
            self._entropy_check(),
            self._secure_storage_check(),
            self._audit_log_check(),
        ]

        status_order = {"Healthy": 0, "Warning": 1, "Critical": 2}
        worst = max(results, key=lambda r: status_order.get(r.status, 2))
        overall = worst.status
        return overall, results

    # Individual checks -------------------------------------------------
    def _entropy_check(self) -> HealthCheckResult:
        sample = os.urandom(2048)
        counts = [0] * 256
        for byte in sample:
            counts[byte] += 1

        probs = [c / len(sample) for c in counts if c]
        shannon = -sum(p * math.log2(p) for p in probs)
        min_entropy = -math.log2(max(probs)) if probs else 0.0

        if shannon >= 7.8 and min_entropy >= 4.0:
            status = "Healthy"
        elif shannon >= 7.2 and min_entropy >= 3.0:
            status = "Warning"
        else:
            status = "Critical"

        details = f"Shannon entropy {shannon:.2f} bits/byte, min-entropy {min_entropy:.2f} bits"
        remediation = "Investigate entropy sources and ensure hardware RNG is functioning."
        return HealthCheckResult("Entropy Quality", status, details, remediation)

    def _secure_storage_check(self) -> HealthCheckResult:
        notes_file = self.base_dir / "secure_notes.vault"
        key_file = self.base_dir / "secure_notes.key"
        salt_file = self.base_dir / "secure_notes.salt"

        files = [f for f in [notes_file, key_file, salt_file] if f.exists()]
        if not files:
            details = "Secure notes storage has not been initialised yet."
            remediation = "Create at least one secure note to provision encrypted storage."
            return HealthCheckResult("Secure Notes Storage", "Warning", details, remediation)

        insecure = [
            f
            for f in files
            if (f.stat().st_mode & 0o077) != 0
        ]

        if insecure:
            status = "Critical"
            details = ", ".join(f.name for f in insecure) + " require owner-only permissions"
            remediation = "Run chmod 600 on the reported files."
            return HealthCheckResult("Secure Notes Storage", status, details, remediation)

        newest = max(f.stat().st_mtime for f in files)
        age_minutes = (time.time() - newest) / 60
        if age_minutes > 60 * 24 * 30:
            status = "Warning"
            details = "Secure notes have not been modified in over 30 days."
            remediation = "Review the secure notes vault or rotate the encryption key."
        else:
            status = "Healthy"
            details = "Secure notes vault permissions and freshness look good."
            remediation = ""

        return HealthCheckResult("Secure Notes Storage", status, details, remediation)

    def _audit_log_check(self) -> HealthCheckResult:
        log_dir = Path(DEFAULT_AUDIT_LOG_DIR)
        log_file = log_dir / "security_audit.log"

        if not log_file.exists():
            details = "No audit log has been created yet."
            remediation = "Trigger a vault action (e.g. encrypt a file) to ensure logging works."
            return HealthCheckResult("Audit Logging", "Warning", details, remediation)

        try:
            lines = log_file.read_text(encoding="utf-8").strip().splitlines()
        except OSError as exc:
            return HealthCheckResult(
                "Audit Logging",
                "Critical",
                f"Failed to read audit log: {exc}",
                "Verify filesystem permissions and free space.",
            )

        entry_count = len(lines)
        if entry_count == 0:
            details = "Audit log is empty."
            remediation = "Initiate vault operations to validate logging."
            status = "Warning"
        else:
            status = "Healthy"
            newest_ts = self._parse_latest_timestamp(lines[-50:])
            if newest_ts is None:
                details = f"{entry_count} entries found (timestamps unavailable)."
                remediation = "Ensure audit logger writes JSON with timestamps."
            else:
                age_minutes = (time.time() - newest_ts) / 60
                details = f"{entry_count} entries, most recent {age_minutes:.1f} minutes ago."
                remediation = ""
                if age_minutes > 60 * 24:
                    status = "Warning"
                    remediation = "Verify scheduled tasks are still producing audit events."

        return HealthCheckResult("Audit Logging", status, details, remediation)

    # Helpers ------------------------------------------------------------
    @staticmethod
    def _parse_latest_timestamp(lines: List[str]) -> float | None:
        for line in reversed(lines):
            line = line.strip()
            if not line:
                continue
            try:
                import json

                payload = json.loads(line)
            except Exception:
                continue
            ts = payload.get("timestamp")
            if isinstance(ts, (int, float)):
                return float(ts)
        return None


__all__ = ["HealthCheckResult", "VaultHealthEvaluator"]
