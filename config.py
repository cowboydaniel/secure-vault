"""
Streamlined 512-bit Multi-Layer Encryption System
Configuration and Constants

This module defines all system-wide configuration parameters,
ensuring consistent 512-bit security standards throughout.
"""

import os
from enum import Enum
from dataclasses import dataclass
from typing import Any, Iterable, List, Mapping, Optional

# 512-bit Security Standards
SECURITY_LEVEL_BITS = 512
SECURITY_LEVEL_BYTES = SECURITY_LEVEL_BITS // 8  # 64 bytes

# Cryptographic Constants
FIELD_SIZE_BITS = 512  # GF(2^512) for Information Dispersal
KEY_SIZE_BYTES = 64    # 512-bit keys throughout
IV_SIZE_BYTES = 64     # 512-bit initialization vectors
SALT_SIZE_BYTES = 64   # 512-bit salts
NONCE_SIZE_BYTES = 64  # 512-bit nonces
CHECKSUM_SIZE_BYTES = 64  # 512-bit checksums (SHA3-512)

# Information Dispersal Algorithm Settings
class IDAConfig:
    """Information Dispersal Algorithm configuration"""
    DEFAULT_TOTAL_SHARES = 5      # N total shares
    DEFAULT_THRESHOLD = 3         # K shares needed for reconstruction
    MIN_SHARES = 2
    MAX_SHARES = 255
    FIELD_POLYNOMIAL_BITS = 512   # Irreducible polynomial for GF(2^512)
    BLOCK_SIZE_BYTES = 1024       # Process files in 1KB blocks

# One-Time Pad Configuration
class OTPConfig:
    """One-Time Pad configuration for perfect secrecy"""
    ENTROPY_POOL_SIZE = 1048576   # 1MB entropy pool
    MIN_ENTROPY_BITS = 7.9        # Minimum entropy per byte
    KEY_REFRESH_INTERVAL = 3600   # Refresh keys every hour
    MAX_KEY_AGE_SECONDS = 7200    # Maximum key lifetime
    BLOCK_SIZE_BYTES = 64         # 512-bit aligned processing
    
# ML-KEM-1024 Post-Quantum Configuration
class MLKEMConfig:
    """ML-KEM-1024 post-quantum cryptography settings"""
    ALGORITHM_NAME = "Kyber1024"
    PUBLIC_KEY_BYTES = 1568
    CIPHERTEXT_BYTES = 1568
    SHARED_SECRET_BYTES = 32      # Expanded to 64 bytes via HKDF
    EXPANDED_SECRET_BYTES = 64    # 512-bit expanded shared secret

# Custom 512-bit Cipher Configuration
class CustomCipherConfig:
    """Custom 512-bit algorithm configuration"""
    BLOCK_SIZE_BYTES = 64         # 512-bit blocks
    KEY_SIZE_BYTES = 64           # 512-bit keys
    ROUNDS = 32                   # 32 rounds for 512-bit security
    SBOX_SIZE = 256               # S-box dimensions
    ROUND_KEYS = 33               # Master key + 32 round keys

# File System and Storage
class StorageConfig:
    """Storage layer configuration"""
    ENCRYPTED_EXTENSION = ".sec512"
    SHARE_EXTENSION = ".share"
    METADATA_EXTENSION = ".meta"
    DEFAULT_STORAGE_DIR = os.path.expanduser("~/secure_vault")
    SAFE_STORAGE_DIRECTORIES = [
        DEFAULT_STORAGE_DIR,
        os.path.expanduser("~/.secure_vault"),
    ]
    EXTRA_SAFE_DIRECTORIES: List[str] = []
    EXTRA_SAFE_DIRECTORIES_ENV = "SECURE_VAULT_EXTRA_SAFE_DIRS"
    MAX_FILE_SIZE_GB = 100        # Maximum file size for processing
    COMPRESSION_ENABLED = True    # Pre-encryption compression
    SCHEMA_CONFIG_FILE = "storage_schema.json"  # Optional schema validation configuration

    @classmethod
    def get_allowlisted_directories(cls) -> List[str]:
        """Return all configured storage directories considered safe."""
        allowlist: List[str] = []
        for path in cls.SAFE_STORAGE_DIRECTORIES + cls.EXTRA_SAFE_DIRECTORIES:
            expanded = os.path.abspath(os.path.expanduser(path))
            if expanded not in allowlist:
                allowlist.append(expanded)

        env_paths = os.environ.get(cls.EXTRA_SAFE_DIRECTORIES_ENV, "")
        if env_paths:
            for raw_path in env_paths.split(os.pathsep):
                cleaned = raw_path.strip()
                if not cleaned:
                    continue
                expanded = os.path.abspath(os.path.expanduser(cleaned))
                if expanded not in allowlist:
                    allowlist.append(expanded)

        return allowlist

# Security and OPSEC
class SecurityConfig:
    """Operational security configuration"""
    RAM_ONLY_KEYS = True          # Never write keys to disk
    SECURE_MEMORY_ALIGNMENT = 64  # 512-bit memory alignment
    AUTO_LOCK_TIMEOUT = 1800      # Auto-lock after 30 minutes
    MAX_LOGIN_ATTEMPTS = 3        # Fail2Ban trigger
    SALT_ROTATION_INTERVAL = 300  # New salt every 5 minutes
    AUDIT_LOG_ENABLED = True      # Security event logging

# Backup and Recovery Configuration
BACKUP_CONFIG = {
    'backup_enabled': True,
    'backup_dir': os.path.expanduser('~/.secure_vault/backups'),
    'backup_retention': 5,           # Number of backups to keep
    'backup_schedule': 24,           # Backup interval in hours (0 to disable)
    'metadata_backup_enabled': True,
    'auto_recovery': True,           # Attempt recovery on startup if metadata is corrupted
}

# Performance Optimization
class PerformanceConfig:
    """Performance tuning parameters"""
    USE_AVX512 = True             # Use AVX-512 instructions if available
    THREAD_POOL_SIZE = os.cpu_count()  # Use all CPU cores
    MEMORY_CHUNK_SIZE = 16 * 1024 * 1024  # 16MB chunks for large files
    ENABLE_NUMA_OPTIMIZATION = True
    CACHE_LINE_SIZE = 64          # CPU cache line optimization

# Classification Levels
class ClassificationLevel(Enum):
    """File classification levels"""
    UNCLASSIFIED = 0
    OFFICIAL = 1
    PROTECTED = 2
    SECRET = 3
    TOP_SECRET = 4

@dataclass
class SystemConfig:
    """Main system configuration"""
    # Directory paths
    config_dir: str = os.path.expanduser("~/.secure_vault")
    log_dir: str = os.path.expanduser("~/.secure_vault/logs")
    temp_dir: str = "/tmp/secure_vault"
    
    # Hardware capabilities
    has_avx512: Optional[bool] = None
    has_hardware_rng: Optional[bool] = None
    has_tpm: Optional[bool] = None
    
    # Debug and development
    debug_mode: bool = False
    verbose_logging: bool = False
    development_mode: bool = False
    
    def __post_init__(self):
        """Initialize configuration directories"""
        os.makedirs(self.config_dir, exist_ok=True)
        os.makedirs(self.log_dir, exist_ok=True)
        os.makedirs(self.temp_dir, mode=0o700, exist_ok=True)

# File type definitions
SUPPORTED_FILE_TYPES = {
    '.txt', '.doc', '.docx', '.pdf', '.xlsx', '.ppt', '.pptx',
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff',
    '.mp4', '.avi', '.mkv', '.mov', '.wmv',
    '.mp3', '.wav', '.flac', '.ogg',
    '.zip', '.rar', '.7z', '.tar', '.gz',
    '.py', '.cpp', '.c', '.h', '.java', '.js', '.html', '.css'
}

# Cryptographic algorithm identifiers
ALGORITHM_IDS = {
    'IDA': 0x01,           # Information Dispersal Algorithm
    'OTP': 0x02,           # One-Time Pad
    'MLKEM': 0x03,         # ML-KEM-1024
    'CUSTOM512': 0x04,     # Custom 512-bit cipher
    'STORAGE': 0x05        # Storage layer encryption
}

# Error codes
class ErrorCodes(Enum):
    """System error codes"""
    SUCCESS = 0
    INVALID_INPUT = 1
    INSUFFICIENT_ENTROPY = 2
    KEY_GENERATION_FAILED = 3
    ENCRYPTION_FAILED = 4
    DECRYPTION_FAILED = 5
    SHARE_RECONSTRUCTION_FAILED = 6
    HARDWARE_NOT_AVAILABLE = 7
    MEMORY_ALLOCATION_FAILED = 8
    FILE_NOT_FOUND = 9
    PERMISSION_DENIED = 10
    INTEGRITY_CHECK_FAILED = 11
    INVALID_SHARE = 12
    INSUFFICIENT_SHARES = 13

# Version information
VERSION = "1.0.0-alpha"
BUILD_DATE = "2025-08-22"
PROTOCOL_VERSION = 1

# Default configuration instance
default_config = SystemConfig()

def get_config() -> SystemConfig:
    """Get the default system configuration."""
    return default_config


def apply_configuration_overrides(overrides: Mapping[str, Any]) -> List[str]:
    """Apply configuration overrides loaded from an external source.

    The function accepts a mapping containing optional "system", "storage",
    and "security" sections. Recognised values are applied to the global
    configuration objects and missing sections are ignored. Unknown fields are
    skipped to keep forward compatibility.

    Args:
        overrides: Structured overrides loaded from a configuration file.

    Returns:
        List of dot-separated keys that were applied. The caller can surface
        this to the user for diagnostics and audit trails.
    """

    if not overrides:
        return []

    applied: List[str] = []

    system_overrides = overrides.get("system", {}) if isinstance(overrides, Mapping) else {}
    if isinstance(system_overrides, Mapping):
        for key in ("config_dir", "log_dir", "temp_dir", "debug_mode", "verbose_logging", "development_mode"):
            if key in system_overrides:
                setattr(default_config, key, system_overrides[key])
                applied.append(f"system.{key}")

        # Ensure updated directories exist
        default_config.__post_init__()

    storage_overrides = overrides.get("storage", {}) if isinstance(overrides, Mapping) else {}
    if isinstance(storage_overrides, Mapping):
        extra_dirs = storage_overrides.get("extra_safe_directories")
        if isinstance(extra_dirs, Iterable) and not isinstance(extra_dirs, (str, bytes)):
            StorageConfig.EXTRA_SAFE_DIRECTORIES = [str(path) for path in extra_dirs]
            applied.append("storage.extra_safe_directories")

        compression = storage_overrides.get("compression_enabled")
        if isinstance(compression, bool):
            StorageConfig.COMPRESSION_ENABLED = compression
            applied.append("storage.compression_enabled")

    security_overrides = overrides.get("security", {}) if isinstance(overrides, Mapping) else {}
    if isinstance(security_overrides, Mapping):
        for key in ("auto_lock_timeout", "max_login_attempts"):
            if key in security_overrides and hasattr(SecurityConfig, key.upper()):
                setattr(SecurityConfig, key.upper(), security_overrides[key])
                applied.append(f"security.{key}")

    return applied

def validate_512bit_alignment(size: int) -> bool:
    """Validate that size is properly aligned to 512-bit boundaries"""
    return size % SECURITY_LEVEL_BYTES == 0

def align_to_512bit(size: int) -> int:
    """Align size to 512-bit boundary"""
    remainder = size % SECURITY_LEVEL_BYTES
    if remainder == 0:
        return size
    return size + (SECURITY_LEVEL_BYTES - remainder)

def get_hardware_info() -> dict:
    """Get hardware capability information"""
    info = {
        'cpu_count': os.cpu_count(),
        'avx512_available': False,  # Will be detected by system_info.py
        'hardware_rng_available': False,
        'tpm_available': False,
        'total_memory': 0,
        'cache_line_size': 64
    }
    return info

# Security constants for mathematical operations
IRREDUCIBLE_POLYNOMIAL_512 = (
    # This is a placeholder - actual 512-bit irreducible polynomial
    # would be computed and verified during initialization
    b'\x01' + b'\x00' * 62 + b'\x87'  # 512-bit polynomial
)

# Predefined secure parameters
SECURE_PRIMES_512BIT = [
    # Placeholder for 512-bit secure prime numbers
    # These would be properly generated and verified
]

# Magic numbers for file format identification
MAGIC_NUMBERS = {
    'ENCRYPTED_FILE': b'SEC512\x00\x01',
    'IDA_SHARE': b'SHARE512',
    'KEY_MATERIAL': b'KEY512\x00',
    'METADATA': b'META512\x00'
}

# Logging configuration
LOGGING_CONFIG = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'detailed': {
            'format': '%(asctime)s [%(levelname)s] %(name)s:%(lineno)d - %(message)s'
        },
        'simple': {
            'format': '%(levelname)s - %(message)s'
        }
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'level': 'INFO',
            'formatter': 'simple'
        },
        'file': {
            'class': 'logging.FileHandler',
            'filename': os.path.join(default_config.log_dir, 'secure_vault.log'),
            'level': 'DEBUG',
            'formatter': 'detailed'
        }
    },
    'loggers': {
        'secure_vault': {
            'level': 'DEBUG',
            'handlers': ['console', 'file'],
            'propagate': False
        }
    }
}

if __name__ == "__main__":
    print(f"Secure Vault Configuration v{VERSION}")
    print(f"512-bit Security Level: {SECURITY_LEVEL_BITS} bits")
    print(f"Key Size: {KEY_SIZE_BYTES} bytes")
    print(f"Field Size: {FIELD_SIZE_BITS} bits")
    print(f"Config Directory: {default_config.config_dir}")