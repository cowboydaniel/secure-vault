"""
Security Audit Logger for SecureVault

This module provides comprehensive security event logging and auditing
capabilities for tracking all security-relevant operations.
"""

import logging
import json
import time
import hashlib
import os
from datetime import datetime
from typing import Dict, Any, Optional, List
from pathlib import Path
from dataclasses import dataclass, asdict
from enum import Enum


class AuditEventType(Enum):
    """Types of security audit events"""
    # Authentication events
    AUTH_SUCCESS = "auth_success"
    AUTH_FAILURE = "auth_failure"

    # Key management events
    KEY_GENERATED = "key_generated"
    KEY_ACCESSED = "key_accessed"
    KEY_ROTATED = "key_rotated"
    KEY_DELETED = "key_deleted"
    KEY_BACKUP = "key_backup"
    KEY_RESTORE = "key_restore"

    # Encryption/Decryption events
    ENCRYPTION_START = "encryption_start"
    ENCRYPTION_SUCCESS = "encryption_success"
    ENCRYPTION_FAILURE = "encryption_failure"
    DECRYPTION_START = "decryption_start"
    DECRYPTION_SUCCESS = "decryption_success"
    DECRYPTION_FAILURE = "decryption_failure"

    # Share management events
    SHARES_CREATED = "shares_created"
    SHARES_RECONSTRUCTED = "shares_reconstructed"

    # System events
    SYSTEM_START = "system_start"
    SYSTEM_SHUTDOWN = "system_shutdown"
    CONFIG_CHANGED = "config_changed"

    # Security events
    INTEGRITY_CHECK_PASS = "integrity_check_pass"
    INTEGRITY_CHECK_FAIL = "integrity_check_fail"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"

    # Entropy events
    ENTROPY_LOW = "entropy_low"
    ENTROPY_CRITICAL = "entropy_critical"
    RNG_HEALTH_CHECK = "rng_health_check"


class AuditSeverity(Enum):
    """Severity levels for audit events"""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class AuditEvent:
    """Represents a security audit event"""
    timestamp: float
    event_type: AuditEventType
    severity: AuditSeverity
    message: str
    details: Dict[str, Any]
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    source_ip: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'timestamp': self.timestamp,
            'datetime': datetime.fromtimestamp(self.timestamp).isoformat(),
            'event_type': self.event_type.value,
            'severity': self.severity.value,
            'message': self.message,
            'details': self.details,
            'user_id': self.user_id,
            'session_id': self.session_id,
            'source_ip': self.source_ip
        }

    def to_json(self) -> str:
        """Convert to JSON string"""
        return json.dumps(self.to_dict(), indent=2)


class AuditLogger:
    """
    Security audit logger for tracking all security-relevant operations

    Features:
    - Structured logging of security events
    - Tamper-evident logging with checksums
    - Log rotation and archival
    - Multiple output formats (JSON, syslog, etc.)
    - Configurable log retention
    """

    def __init__(self,
                 log_dir: str = "audit_logs",
                 log_file: str = "security_audit.log",
                 max_log_size: int = 10 * 1024 * 1024,  # 10 MB
                 max_backups: int = 10,
                 enable_tamper_detection: bool = True):
        """
        Initialize audit logger

        Args:
            log_dir: Directory for log files
            log_file: Name of log file
            max_log_size: Maximum size before rotation
            max_backups: Number of backup logs to keep
            enable_tamper_detection: Enable tamper detection features
        """
        self.log_dir = Path(log_dir)
        self.log_file = self.log_dir / log_file
        self.max_log_size = max_log_size
        self.max_backups = max_backups
        self.enable_tamper_detection = enable_tamper_detection

        # Create log directory if it doesn't exist
        self.log_dir.mkdir(parents=True, exist_ok=True)

        # Initialize logging
        self._setup_logging()

        # Chain hash for tamper detection
        self._last_hash = b'\x00' * 32

        # Event counters
        self._event_counters = {severity: 0 for severity in AuditSeverity}

        # Session tracking
        self._session_id = self._generate_session_id()

        self.log_event(
            AuditEventType.SYSTEM_START,
            AuditSeverity.INFO,
            "Audit logger initialized",
            {'session_id': self._session_id}
        )

    def _setup_logging(self):
        """Setup Python logging framework"""
        self.logger = logging.getLogger('SecureVault.Audit')
        self.logger.setLevel(logging.DEBUG)

        # File handler
        file_handler = logging.FileHandler(self.log_file)
        file_handler.setLevel(logging.DEBUG)

        # Console handler for critical events
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.WARNING)

        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)

        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)

    def _generate_session_id(self) -> str:
        """Generate unique session ID"""
        return hashlib.sha256(
            str(time.time()).encode() + os.urandom(16)
        ).hexdigest()[:16]

    def _compute_event_hash(self, event: AuditEvent) -> bytes:
        """Compute tamper-evident hash for event"""
        event_data = event.to_json().encode()
        hash_input = self._last_hash + event_data
        return hashlib.sha3_512(hash_input).digest()

    def log_event(self,
                  event_type: AuditEventType,
                  severity: AuditSeverity,
                  message: str,
                  details: Optional[Dict[str, Any]] = None,
                  user_id: Optional[str] = None,
                  source_ip: Optional[str] = None):
        """
        Log a security audit event

        Args:
            event_type: Type of event
            severity: Severity level
            message: Human-readable message
            details: Additional event details
            user_id: User identifier
            source_ip: Source IP address
        """
        event = AuditEvent(
            timestamp=time.time(),
            event_type=event_type,
            severity=severity,
            message=message,
            details=details or {},
            user_id=user_id,
            session_id=self._session_id,
            source_ip=source_ip
        )

        # Update event counters
        self._event_counters[severity] += 1

        # Compute tamper-evident hash
        if self.enable_tamper_detection:
            event_hash = self._compute_event_hash(event)
            event.details['event_hash'] = event_hash.hex()[:16]
            self._last_hash = event_hash[:32]

        # Write to log file (JSON format)
        try:
            with open(self.log_file, 'a') as f:
                f.write(event.to_json() + '\n')
        except IOError as e:
            self.logger.error(f"Failed to write audit log: {e}")

        # Also log to Python logger
        log_level = {
            AuditSeverity.DEBUG: logging.DEBUG,
            AuditSeverity.INFO: logging.INFO,
            AuditSeverity.WARNING: logging.WARNING,
            AuditSeverity.ERROR: logging.ERROR,
            AuditSeverity.CRITICAL: logging.CRITICAL
        }[severity]

        self.logger.log(
            log_level,
            f"[{event_type.value}] {message}"
        )

        # Check if rotation needed
        self._check_rotation()

    def _check_rotation(self):
        """Check if log rotation is needed"""
        if self.log_file.exists():
            size = self.log_file.stat().st_size
            if size >= self.max_log_size:
                self._rotate_logs()

    def _rotate_logs(self):
        """Rotate log files"""
        # Rename existing backups
        for i in range(self.max_backups - 1, 0, -1):
            old_file = self.log_dir / f"{self.log_file.name}.{i}"
            new_file = self.log_dir / f"{self.log_file.name}.{i+1}"

            if old_file.exists():
                if new_file.exists():
                    new_file.unlink()
                old_file.rename(new_file)

        # Rename current log to .1
        if self.log_file.exists():
            backup_file = self.log_dir / f"{self.log_file.name}.1"
            if backup_file.exists():
                backup_file.unlink()
            self.log_file.rename(backup_file)

        self.log_event(
            AuditEventType.SYSTEM_START,
            AuditSeverity.INFO,
            "Log rotation completed",
            {'backups_kept': self.max_backups}
        )

    def log_encryption(self, success: bool, file_size: int, details: Dict[str, Any]):
        """Log encryption event"""
        if success:
            self.log_event(
                AuditEventType.ENCRYPTION_SUCCESS,
                AuditSeverity.INFO,
                f"Successfully encrypted {file_size} bytes",
                details
            )
        else:
            self.log_event(
                AuditEventType.ENCRYPTION_FAILURE,
                AuditSeverity.ERROR,
                f"Encryption failed for {file_size} bytes",
                details
            )

    def log_decryption(self, success: bool, file_size: int, details: Dict[str, Any]):
        """Log decryption event"""
        if success:
            self.log_event(
                AuditEventType.DECRYPTION_SUCCESS,
                AuditSeverity.INFO,
                f"Successfully decrypted {file_size} bytes",
                details
            )
        else:
            self.log_event(
                AuditEventType.DECRYPTION_FAILURE,
                AuditSeverity.ERROR,
                f"Decryption failed for {file_size} bytes",
                details
            )

    def log_key_operation(self, operation: str, key_id: str, details: Dict[str, Any]):
        """Log key management operation"""
        event_types = {
            'generate': AuditEventType.KEY_GENERATED,
            'access': AuditEventType.KEY_ACCESSED,
            'rotate': AuditEventType.KEY_ROTATED,
            'delete': AuditEventType.KEY_DELETED,
            'backup': AuditEventType.KEY_BACKUP,
            'restore': AuditEventType.KEY_RESTORE
        }

        event_type = event_types.get(operation, AuditEventType.KEY_ACCESSED)

        self.log_event(
            event_type,
            AuditSeverity.INFO,
            f"Key {operation}: {key_id}",
            details
        )

    def log_integrity_check(self, passed: bool, file_path: str, details: Dict[str, Any]):
        """Log integrity check result"""
        if passed:
            self.log_event(
                AuditEventType.INTEGRITY_CHECK_PASS,
                AuditSeverity.INFO,
                f"Integrity check passed: {file_path}",
                details
            )
        else:
            self.log_event(
                AuditEventType.INTEGRITY_CHECK_FAIL,
                AuditSeverity.CRITICAL,
                f"Integrity check FAILED: {file_path}",
                details
            )

    def log_suspicious_activity(self, description: str, details: Dict[str, Any]):
        """Log suspicious activity"""
        self.log_event(
            AuditEventType.SUSPICIOUS_ACTIVITY,
            AuditSeverity.WARNING,
            f"Suspicious activity detected: {description}",
            details
        )

    def log_entropy_warning(self, level: str, details: Dict[str, Any]):
        """Log entropy warning"""
        event_type = (AuditEventType.ENTROPY_CRITICAL
                     if level == 'critical'
                     else AuditEventType.ENTROPY_LOW)

        self.log_event(
            event_type,
            AuditSeverity.CRITICAL if level == 'critical' else AuditSeverity.WARNING,
            f"Entropy {level}: {details.get('message', 'Low entropy detected')}",
            details
        )

    def get_event_summary(self) -> Dict[str, int]:
        """Get summary of logged events by severity"""
        return {
            severity.value: count
            for severity, count in self._event_counters.items()
        }

    def query_events(self,
                    start_time: Optional[float] = None,
                    end_time: Optional[float] = None,
                    event_type: Optional[AuditEventType] = None,
                    severity: Optional[AuditSeverity] = None,
                    limit: int = 100) -> List[Dict[str, Any]]:
        """
        Query audit events with filters

        Args:
            start_time: Start timestamp
            end_time: End timestamp
            event_type: Filter by event type
            severity: Filter by severity
            limit: Maximum number of events to return

        Returns:
            List of matching events
        """
        events = []

        try:
            with open(self.log_file, 'r') as f:
                for line in f:
                    try:
                        event = json.loads(line)

                        # Apply filters
                        if start_time and event['timestamp'] < start_time:
                            continue
                        if end_time and event['timestamp'] > end_time:
                            continue
                        if event_type and event['event_type'] != event_type.value:
                            continue
                        if severity and event['severity'] != severity.value:
                            continue

                        events.append(event)

                        if len(events) >= limit:
                            break
                    except json.JSONDecodeError:
                        continue
        except IOError:
            pass

        return events

    def close(self):
        """Close audit logger"""
        self.log_event(
            AuditEventType.SYSTEM_SHUTDOWN,
            AuditSeverity.INFO,
            "Audit logger shutting down",
            self.get_event_summary()
        )


# Global audit logger instance
_audit_logger: Optional[AuditLogger] = None


def get_audit_logger() -> AuditLogger:
    """Get or create global audit logger instance"""
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger()
    return _audit_logger


def log_audit_event(event_type: AuditEventType,
                   severity: AuditSeverity,
                   message: str,
                   details: Optional[Dict[str, Any]] = None):
    """Convenience function to log audit event"""
    logger = get_audit_logger()
    logger.log_event(event_type, severity, message, details)
