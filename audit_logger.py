"""
Security Audit Logger for SecureVault

This module provides comprehensive security event logging and auditing
capabilities for tracking all security-relevant operations.
"""

import base64
import binascii
import hashlib
import hmac
import json
import logging
import os
import time
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Dict, Any, Optional, List, Union
from dataclasses import dataclass
from enum import Enum


_SENSITIVE_DETAIL_KEYWORDS = {
    'key',
    'secret',
    'token',
    'password',
    'passphrase',
    'checksum',
    'digest',
    'hash',
    'salt',
    'iv',
    'path',
    'data',
    'blob',
    'bytes',
    'credential'
}

_SENSITIVE_ALLOWLIST_KEYS = {'event_hash', 'metadata'}


def _summarize_sensitive_value(value: Any) -> Any:
    """Produce a safe summary for sensitive values."""
    if isinstance(value, (bytes, bytearray)):
        return f"<{len(value)} bytes>"
    if isinstance(value, dict):
        return f"<{len(value)} fields>"
    if isinstance(value, (list, tuple, set)):
        return f"<{len(list(value))} items>"
    if value is None:
        return None
    return "<redacted>"


def sanitize_audit_details(details: Any) -> Any:
    """
    Sanitize audit event details to avoid leaking sensitive data.

    Args:
        details: Arbitrary event details structure.

    Returns:
        Sanitized structure safe for logging.
    """
    if isinstance(details, dict):
        sanitized: Dict[str, Any] = {}
        for key, value in details.items():
            if key is None:
                continue
            key_lower = str(key).lower()
            if key_lower in _SENSITIVE_ALLOWLIST_KEYS:
                sanitized[key] = sanitize_audit_details(value)
                continue
            if any(token in key_lower for token in _SENSITIVE_DETAIL_KEYWORDS):
                sanitized[key] = _summarize_sensitive_value(value)
            else:
                sanitized[key] = sanitize_audit_details(value)
        return sanitized

    if isinstance(details, (list, tuple, set)):
        return [sanitize_audit_details(item) for item in list(details)]

    if isinstance(details, (bytes, bytearray)):
        return f"<{len(details)} bytes>"

    return details


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


REDACTED_PLACEHOLDER = "***REDACTED***"
SENSITIVE_KEYWORDS = (
    "pin",
    "pass",
    "secret",
    "key",
    "token",
    "identifier",
)


class LogEncryptor:
    """Simple stream-based encryptor for audit logs."""

    NONCE_SIZE = 16
    MAC_SIZE = 32

    def __init__(self, key: bytes):
        if len(key) < 32:
            raise ValueError("Encryption key must be at least 32 bytes")
        self._key_material = hashlib.sha3_512(key).digest()

    def _derive_keystream(self, nonce: bytes, length: int) -> bytes:
        keystream = bytearray()
        counter = 0
        while len(keystream) < length:
            counter_bytes = counter.to_bytes(4, 'big')
            block = hashlib.sha3_512(self._key_material + nonce + counter_bytes).digest()
            keystream.extend(block)
            counter += 1
        return bytes(keystream[:length])

    def encrypt(self, message: str) -> str:
        plaintext = message.encode('utf-8')
        nonce = os.urandom(self.NONCE_SIZE)
        keystream = self._derive_keystream(nonce, len(plaintext))
        ciphertext = bytes(p ^ k for p, k in zip(plaintext, keystream))
        mac = hashlib.sha3_256(self._key_material + nonce + ciphertext).digest()
        payload = nonce + mac + ciphertext
        return base64.b64encode(payload).decode('ascii')

    def decrypt(self, payload: str) -> Optional[str]:
        try:
            data = base64.b64decode(payload)
        except (binascii.Error, ValueError):
            return None

        if len(data) < self.NONCE_SIZE + self.MAC_SIZE:
            return None

        nonce = data[:self.NONCE_SIZE]
        mac = data[self.NONCE_SIZE:self.NONCE_SIZE + self.MAC_SIZE]
        ciphertext = data[self.NONCE_SIZE + self.MAC_SIZE:]

        expected_mac = hashlib.sha3_256(self._key_material + nonce + ciphertext).digest()
        if not hmac.compare_digest(mac, expected_mac):
            return None

        keystream = self._derive_keystream(nonce, len(ciphertext))
        plaintext = bytes(c ^ k for c, k in zip(ciphertext, keystream))
        try:
            return plaintext.decode('utf-8')
        except UnicodeDecodeError:
            return None


class EncryptedRotatingFileHandler(RotatingFileHandler):
    """Rotating handler that encrypts log records before persistence."""

    def __init__(self,
                 filename: Union[str, os.PathLike],
                 max_bytes: int,
                 backup_count: int,
                 encryptor: LogEncryptor):
        super().__init__(
            filename,
            mode='a',
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding='utf-8',
            delay=True
        )
        self._encryptor = encryptor
        self.setFormatter(logging.Formatter('%(message)s'))

    def emit(self, record: logging.LogRecord) -> None:
        message = self.format(record)
        encrypted_message = self._encryptor.encrypt(message)
        record = logging.LogRecord(
            name=record.name,
            level=record.levelno,
            pathname=record.pathname,
            lineno=record.lineno,
            msg=encrypted_message,
            args=None,
            exc_info=None
        )
        super().emit(record)

    def _open(self):
        stream = super()._open()
        try:
            if os.name == 'posix':
                os.chmod(self.baseFilename, 0o600)
        except PermissionError:
            pass
        return stream


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

        # Create log directory if it doesn't exist and restrict permissions
        self.log_dir.mkdir(parents=True, exist_ok=True)
        try:
            if os.name == 'posix':
                os.chmod(self.log_dir, 0o700)
        except PermissionError:
            pass

        # Load encryption material
        self._log_key, self._log_iv = self._load_encryption_material()
        derived_key = hashlib.sha3_512(self._log_key + self._log_iv).digest()
        self._encryptor = LogEncryptor(derived_key)

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
        self.logger.propagate = False
        self.logger.handlers.clear()

        # Console handler for critical events
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.WARNING)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)

        # Storage logger for encrypted audit entries
        self.storage_logger = logging.getLogger('SecureVault.Audit.Storage')
        self.storage_logger.setLevel(logging.INFO)
        self.storage_logger.propagate = False
        self.storage_logger.handlers.clear()

        encrypted_handler = EncryptedRotatingFileHandler(
            self.log_file,
            max_bytes=self.max_log_size,
            backup_count=self.max_backups,
            encryptor=self._encryptor
        )
        self.storage_logger.addHandler(encrypted_handler)

    def _generate_session_id(self) -> str:
        """Generate unique session ID"""
        return hashlib.sha256(
            str(time.time()).encode() + os.urandom(16)
        ).hexdigest()[:16]

    def _compute_event_hash(self, payload: Dict[str, Any]) -> bytes:
        """Compute tamper-evident hash for sanitized payload"""
        event_data = json.dumps(payload, sort_keys=True).encode()
        hash_input = self._last_hash + event_data
        return hashlib.sha3_512(hash_input).digest()

    def _load_encryption_material(self) -> (bytes, bytes):
        """Load or create encryption material for log storage."""
        key_file = self.log_dir / '.audit_log.key'
        if key_file.exists():
            data = key_file.read_bytes()
            if len(data) != 128:
                raise ValueError("Invalid audit log key file length")
            key = data[:64]
            iv = data[64:]
        else:
            key = os.urandom(64)
            iv = os.urandom(64)
            key_file.write_bytes(key + iv)
            try:
                if os.name == 'posix':
                    os.chmod(key_file, 0o600)
            except PermissionError:
                pass
        return key, iv

    def _sanitize_identifier(self, value: Optional[str]) -> Optional[str]:
        """Return a hashed representation of identifiers."""
        if value is None:
            return None
        digest = hashlib.sha256(str(value).encode()).hexdigest()
        return digest[:12]

    def _sanitize_payload(self, payload: Any) -> Any:
        """Recursively sanitize payload data to remove sensitive fields."""
        if isinstance(payload, dict):
            sanitized: Dict[str, Any] = {}
            for key, value in payload.items():
                lower_key = key.lower()
                if any(keyword in lower_key for keyword in SENSITIVE_KEYWORDS):
                    sanitized[key] = REDACTED_PLACEHOLDER
                    continue
                if lower_key.endswith('_id') or lower_key in {'session', 'user'}:
                    sanitized[key] = self._sanitize_identifier(value)
                    continue
                if lower_key in {'source_ip', 'ip_address'}:
                    sanitized[key] = self._sanitize_identifier(value)
                    continue
                sanitized[key] = self._sanitize_payload(value)
            return sanitized
        if isinstance(payload, list):
            return [self._sanitize_payload(item) for item in payload]
        if isinstance(payload, (bytes, bytearray)):
            return REDACTED_PLACEHOLDER
        return payload

    def _decrypt_log_line(self, encoded_line: str) -> Optional[str]:
        """Decrypt a single encoded log line."""
        encoded_line = encoded_line.strip()
        if not encoded_line:
            return None
        return self._encryptor.decrypt(encoded_line)

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
        sanitized_details = sanitize_audit_details(details or {})

        event = AuditEvent(
            timestamp=time.time(),
            event_type=event_type,
            severity=severity,
            message=message,
            details=sanitized_details,
            user_id=user_id,
            session_id=self._session_id,
            source_ip=source_ip
        )

        # Update event counters
        self._event_counters[severity] += 1

        sanitized_details = self._sanitize_payload(event.details)
        sanitized_event = {
            'timestamp': event.timestamp,
            'datetime': datetime.fromtimestamp(event.timestamp).isoformat(),
            'event_type': event.event_type.value,
            'severity': event.severity.value,
            'message': event.message,
            'details': sanitized_details,
            'user_id': self._sanitize_identifier(event.user_id),
            'session_id': self._sanitize_identifier(event.session_id),
            'source_ip': self._sanitize_identifier(event.source_ip),
        }

        # Compute tamper-evident hash
        if self.enable_tamper_detection:
            event_hash = self._compute_event_hash(sanitized_event)
            sanitized_event['details']['event_hash'] = event_hash.hex()[:32]
            self._last_hash = event_hash[:32]

        try:
            json_payload = json.dumps(sanitized_event, separators=(',', ':'))
            record = logging.LogRecord(
                name='SecureVault.Audit.Storage',
                level=logging.INFO,
                pathname=__file__,
                lineno=0,
                msg=json_payload,
                args=None,
                exc_info=None
            )
            self.storage_logger.handle(record)
        except Exception as exc:
            self.logger.error(f"Failed to persist audit event: {exc}")

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
                    decoded = self._decrypt_log_line(line)
                    if not decoded:
                        continue
                    try:
                        event = json.loads(decoded)

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
