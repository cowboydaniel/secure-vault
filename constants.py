"""
Streamlined 512-bit Multi-Layer Encryption System
Mathematical Constants and Data Structures

This module contains all mathematical constants, data structures,
and type definitions used throughout the 512-bit encryption system.
"""

from dataclasses import dataclass
from typing import List, Optional, Union, Dict, Any
from enum import Enum, IntEnum
import struct
from config import SECURITY_LEVEL_BYTES, KEY_SIZE_BYTES, IV_SIZE_BYTES

# =====================================================
# 512-bit Mathematical Constants
# =====================================================

# 512-bit irreducible polynomial for GF(2^512)
# This is the foundation for all Galois Field operations
# Using x^512 + x^8 + x^5 + x^2 + 1 (a common irreducible polynomial for GF(2^512))
GF512_IRREDUCIBLE_POLYNOMIAL = (
    (1 << 512) | (1 << 8) | (1 << 5) | (1 << 2) | 1
)

# 512-bit primitive element for field operations
GF512_PRIMITIVE_ELEMENT = (
    0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002
)

# Maximum value for 512-bit operations
MAX_512BIT = (1 << 512) - 1

# 512-bit modulus for modular arithmetic
MODULUS_512BIT = (
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
)

# =====================================================
# Data Structures for Multi-Layer Encryption
# =====================================================

@dataclass
class GF512Element:
    """Represents a 512-bit Galois Field element"""
    value: int  # 512-bit integer value
    
    def __post_init__(self):
        if self.value < 0 or self.value > MAX_512BIT:
            raise ValueError("Value must be within 512-bit range")
    
    def to_bytes(self) -> bytes:
        """Convert to 64-byte representation"""
        return self.value.to_bytes(64, 'big')
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'GF512Element':
        """Create from 64-byte representation"""
        if len(data) != 64:
            raise ValueError("Data must be exactly 64 bytes")
        return cls(int.from_bytes(data, 'big'))

@dataclass
class Key512:
    """512-bit cryptographic key"""
    key_data: bytes  # 64 bytes of key material
    key_id: bytes    # 32-byte key identifier
    created_time: float
    expires_time: Optional[float] = None
    key_type: str = "unknown"
    
    def __post_init__(self):
        if len(self.key_data) != 64:
            raise ValueError("Key must be exactly 512 bits (64 bytes)")
        if len(self.key_id) != 32:
            raise ValueError("Key ID must be 32 bytes")
    
    def is_expired(self, current_time: float) -> bool:
        """Check if key has expired"""
        return self.expires_time is not None and current_time > self.expires_time

@dataclass
class IDAShare:
    """Information Dispersal Algorithm share"""
    share_id: int           # Share identifier (1 to N)
    total_shares: int       # Total number of shares (N)
    threshold: int          # Minimum shares needed (K)
    share_data: bytes       # Actual share data
    checksum: bytes         # 512-bit SHA3-512 checksum
    field_polynomial: int   # GF(2^512) polynomial used
    original_size: int      # Original file size
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if len(self.checksum) != 64:
            raise ValueError("Checksum must be 512 bits (64 bytes)")
        if self.share_id < 1 or self.share_id > self.total_shares:
            raise ValueError("Invalid share ID")
        if self.threshold > self.total_shares:
            raise ValueError("Threshold cannot exceed total shares")

@dataclass
class OTPKeyMaterial:
    """One-Time Pad key material"""
    key_data: bytes         # Random key material
    entropy_estimate: float # Estimated entropy per byte
    source_info: str        # RNG source information
    generation_time: float  # When this key was generated
    used_bytes: int = 0     # How many bytes have been used
    
    def __post_init__(self):
        if self.entropy_estimate < 7.0:
            raise ValueError("Insufficient entropy for OTP keys")
    
    def remaining_bytes(self) -> int:
        """Get number of unused key bytes"""
        return len(self.key_data) - self.used_bytes
    
    def consume_bytes(self, count: int) -> bytes:
        """Consume and return key bytes"""
        if self.used_bytes + count > len(self.key_data):
            raise ValueError("Insufficient key material remaining")
        
        result = self.key_data[self.used_bytes:self.used_bytes + count]
        self.used_bytes += count
        return result

@dataclass
class MLKEMContext:
    """ML-KEM-1024 cryptographic context"""
    public_key: bytes       # 1568-byte public key
    private_key: bytes      # Private key material
    ciphertext: bytes       # Encapsulated key
    shared_secret: bytes    # 32-byte shared secret
    expanded_secret: bytes  # 64-byte expanded secret (512-bit)
    salt: bytes            # 512-bit salt for key derivation
    
    def __post_init__(self):
        if len(self.expanded_secret) != 64:
            raise ValueError("Expanded secret must be 512 bits")
        if len(self.salt) != 64:
            raise ValueError("Salt must be 512 bits")

@dataclass
class CustomCipherContext:
    """Custom 512-bit cipher context"""
    master_key: bytes       # 512-bit master key
    round_keys: List[bytes] # 33 round keys (512 bits each)
    iv: bytes              # 512-bit initialization vector
    sbox: List[List[int]]  # Dynamic S-box tables
    rounds: int = 32       # Number of rounds
    
    def __post_init__(self):
        if len(self.master_key) != 64:
            raise ValueError("Master key must be 512 bits")
        if len(self.iv) != 64:
            raise ValueError("IV must be 512 bits")
        if len(self.round_keys) != 33:
            raise ValueError("Must have 33 round keys")
        for key in self.round_keys:
            if len(key) != 64:
                raise ValueError("Each round key must be 512 bits")

@dataclass
class EncryptionMetadata:
    """Metadata for encrypted files"""
    version: int            # Protocol version
    algorithm_layers: List[int]  # Algorithm IDs used
    file_size: int         # Original file size
    classification: int    # Security classification level
    creation_time: float   # When file was encrypted
    key_derivation_info: Dict[str, Any]  # Key derivation parameters
    integrity_hash: bytes  # 512-bit file integrity hash
    
    def to_bytes(self) -> bytes:
        """Serialize metadata to bytes"""
        # Simple serialization - in practice would use more robust format
        data = struct.pack('>I', self.version)  # Version
        data += struct.pack('>I', len(self.algorithm_layers))  # Layer count
        for layer in self.algorithm_layers:
            data += struct.pack('>I', layer)
        data += struct.pack('>Q', self.file_size)  # File size
        data += struct.pack('>I', self.classification)  # Classification
        data += struct.pack('>d', self.creation_time)  # Creation time
        data += self.integrity_hash  # 512-bit hash
        return data

# =====================================================
# Enumerations for System Operations
# =====================================================

class OperationMode(IntEnum):
    """Encryption/Decryption operation modes"""
    ENCRYPT = 1
    DECRYPT = 2
    SHARE_GENERATE = 3
    SHARE_RECONSTRUCT = 4
    KEY_GENERATE = 5
    KEY_DERIVE = 6

class LayerType(IntEnum):
    """Multi-layer encryption layer types"""
    INFORMATION_DISPERSAL = 1
    ONE_TIME_PAD = 2
    POST_QUANTUM = 3
    CUSTOM_CIPHER = 4
    STORAGE_ENCRYPTION = 5

class EntropySource(Enum):
    """Random number generation sources"""
    HARDWARE_RNG = "hardware"
    THERMAL_NOISE = "thermal"
    QUANTUM_NOISE = "quantum"
    PSEUDORANDOM = "prng"
    MIXED_SOURCES = "mixed"

class SecurityLevel(IntEnum):
    """Security strength levels"""
    BITS_128 = 128
    BITS_256 = 256
    BITS_384 = 384
    BITS_512 = 512  # Our standard level

# =====================================================
# Mathematical Operation Constants
# =====================================================

# Precomputed logarithm tables for GF(2^512) operations
GF512_LOG_TABLE = None  # Will be computed during initialization
GF512_ANTILOG_TABLE = None  # Will be computed during initialization

# S-box generation constants for custom cipher
SBOX_GENERATION_CONSTANTS = {
    'initial_seed': 0x123456789ABCDEF0,
    'mixing_constant': 0x9E3779B97F4A7C15,
    'rounds': 16
}

# Performance optimization constants
SIMD_ALIGNMENT = 64  # AVX-512 alignment
CACHE_LINE_SIZE = 64
PREFETCH_DISTANCE = 8

# Error correction constants for IDA
REED_SOLOMON_PRIMITIVE = 0x11D  # Primitive polynomial for RS codes
MAX_ERROR_CORRECTION_SYMBOLS = 255

# =====================================================
# File Format Constants
# =====================================================

# File headers and magic numbers
ENCRYPTED_FILE_HEADER = b'SEC512\x00\x01'
IDA_SHARE_HEADER = b'SHARE512'
METADATA_HEADER = b'META512\x00'

# File format versions
CURRENT_FORMAT_VERSION = 1
MINIMUM_SUPPORTED_VERSION = 1

# Compression constants
COMPRESSION_LEVEL = 6  # zlib compression level
COMPRESSION_THRESHOLD = 1024  # Minimum size to compress

# =====================================================
# Security and Validation Constants
# =====================================================

# Entropy requirements
MINIMUM_ENTROPY_BITS_PER_BYTE = 7.9
ENTROPY_TEST_BLOCK_SIZE = 4096
ENTROPY_ESTIMATION_SAMPLES = 1000000

# Key lifetime limits
DEFAULT_KEY_LIFETIME_SECONDS = 3600  # 1 hour
MAXIMUM_KEY_LIFETIME_SECONDS = 86400  # 24 hours
MINIMUM_KEY_LIFETIME_SECONDS = 60     # 1 minute

# Memory security constants
SECURE_MEMORY_PAGE_SIZE = 4096
MEMORY_CLEAR_PATTERN = 0x00  # Pattern for secure memory clearing
MEMORY_CLEAR_PASSES = 3      # Number of clearing passes

# Timing attack protection
CONSTANT_TIME_COMPARISON_BLOCK = 64  # Block size for constant-time ops

# =====================================================
# Hardware-Specific Constants
# =====================================================

# CPU instruction sets
AVX512_AVAILABLE = False  # Will be detected at runtime
AES_NI_AVAILABLE = False  # Will be detected at runtime
RDRAND_AVAILABLE = False  # Will be detected at runtime

# Hardware RNG device paths (Linux)
HARDWARE_RNG_DEVICES = [
    '/dev/hwrng',
    '/dev/truerng',
    '/dev/ttyUSB0',  # Common for USB RNG devices
]

# TPM device paths
TPM_DEVICE_PATHS = [
    '/dev/tpm0',
    '/dev/tpmrm0'
]

# =====================================================
# Testing and Validation Constants
# =====================================================

# Statistical test parameters
CHI_SQUARE_THRESHOLD = 3.84  # 95% confidence level
RUNS_TEST_THRESHOLD = 2.576  # 99% confidence level
AUTOCORRELATION_THRESHOLD = 0.01

# Performance test parameters
BENCHMARK_ITERATIONS = 1000
BENCHMARK_DATA_SIZE = 1024 * 1024  # 1MB test data
PERFORMANCE_TOLERANCE = 0.1  # 10% performance variance allowed

# Fuzzing parameters
FUZZ_TEST_ITERATIONS = 10000
FUZZ_MAX_INPUT_SIZE = 1024 * 1024
FUZZ_RANDOM_SEED = 42

if __name__ == "__main__":
    print("512-bit Encryption System Constants")
    print(f"Security level: {SecurityLevel.BITS_512} bits")
    print(f"GF(2^512) polynomial: 0x{GF512_IRREDUCIBLE_POLYNOMIAL:x}")
    print(f"Maximum 512-bit value: 0x{MAX_512BIT:x}")
    print(f"Key size: {KEY_SIZE_BYTES} bytes")
    print(f"IV size: {IV_SIZE_BYTES} bytes")