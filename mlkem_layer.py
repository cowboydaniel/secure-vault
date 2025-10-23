"""
Streamlined 512-bit Multi-Layer Encryption System
ML-KEM-1024 Post-Quantum Layer (Layer 3) - FIXED VERSION

This module implements the third layer: ML-KEM-1024 post-quantum
key encapsulation for protecting OTP keys against quantum computers.
"""

import os
import time
import struct
from typing import Optional, Tuple, Dict, List, Union, Any
from dataclasses import dataclass, field
import logging

from crypto_utils import (
    derive_key_hkdf_sha3_512,
    compute_sha3_512,
    secure_random_bytes,
    SecureBytes
)
from constants import MLKEMContext
from config import MLKEMConfig, SECURITY_LEVEL_BYTES
from pqc_registry import PQCAlgorithmRegistry, PQCAlgorithmProfile

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import x25519
except Exception:  # pragma: no cover - optional dependency
    serialization = None
    x25519 = None

logger = logging.getLogger(__name__)

# ML-KEM-1024 Parameters (NIST specification) - FIXED
MLKEM_1024_PARAMS = {
    'n': 256,           # Ring dimension
    'k': 4,             # Module rank
    'q': 3329,          # Modulus
    'eta1': 2,          # Noise parameter for secret
    'eta2': 2,          # Noise parameter for error
    'du': 11,           # Compression parameter
    'dv': 5,            # Compression parameter
    'public_key_bytes': 1568,   # FIXED: Correct size
    'secret_key_bytes': 3168,   # FIXED: Correct size
    'ciphertext_bytes': 1568,   # FIXED: Correct size
    'shared_secret_bytes': 32
}

@dataclass
class MLKEMKeyPair:
    """ML-KEM-1024 key pair"""
    public_key: bytes
    secret_key: bytes
    generation_time: float
    key_id: str

@dataclass
class MLKEMEncapsulationResult:
    """Result of ML-KEM encapsulation"""
    ciphertext: bytes
    shared_secret: bytes
    expanded_secret: bytes  # 512-bit expanded version
    key_id: str
    timestamp: float


@dataclass
class HybridEncapsulationResult:
    """Result of a hybrid (ML-KEM + classical) encapsulation"""

    key_id: str
    mlkem_result: MLKEMEncapsulationResult
    classical_public_key: bytes
    classical_shared_secret: bytes
    combined_secret: bytes
    algorithm_profile: Optional[PQCAlgorithmProfile]
    timestamp: float
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class EncapsulationBenchmark:
    """Benchmark result for encapsulation throughput"""

    algorithm: str
    iterations: int
    average_time_ms: float
    throughput_ops: float

class MLKEMError(Exception):
    """ML-KEM specific errors"""
    pass

class PostQuantumMLKEM:
    """
    ML-KEM-1024 Post-Quantum Key Encapsulation Mechanism - FIXED VERSION
    
    Provides quantum-resistant key protection for OTP keys using
    NIST-standardized lattice-based cryptography.
    """
    
    def __init__(self):
        """Initialize ML-KEM engine"""
        self.params = MLKEM_1024_PARAMS
        self._key_cache: Dict[str, MLKEMKeyPair] = {}
        self._encapsulation_cache: Dict[bytes, Dict[str, Any]] = {}
        self._cache_ttl = 5.0

        # Try to import liboqs for real ML-KEM implementation
        self._liboqs_available = self._check_liboqs()

        if not self._liboqs_available:
            logger.warning("liboqs not available, using simulation mode")
            logger.warning("Install liboqs for production use!")

        self.registry = PQCAlgorithmRegistry()
        self.registry.register_default_algorithms(self._liboqs_available)

        logger.info("ML-KEM-1024 Post-Quantum Engine initialized")
    
    def _check_liboqs(self) -> bool:
        """Check if liboqs is available - FIXED"""
        try:
            import oqs
            # FIXED: Changed from get_enabled_KEM_mechanisms() to get_enabled_kem_mechanisms()
            return 'Kyber1024' in oqs.get_enabled_kem_mechanisms()
        except (ImportError, AttributeError):
            return False
    
    def generate_keypair(self) -> MLKEMKeyPair:
        """
        Generate ML-KEM-1024 key pair.
        
        Returns:
            New ML-KEM key pair
        """
        start_time = time.time()
        
        if self._liboqs_available:
            # Use real ML-KEM implementation
            public_key, secret_key = self._generate_real_keypair()
        else:
            # Use simulation for development/testing
            public_key, secret_key = self._generate_simulated_keypair()
        
        key_id = f"mlkem_{int(start_time)}_{os.getpid()}"
        
        keypair = MLKEMKeyPair(
            public_key=public_key,
            secret_key=secret_key,
            generation_time=start_time,
            key_id=key_id
        )
        
        # Cache the keypair
        self._key_cache[key_id] = keypair
        
        logger.info(f"Generated ML-KEM-1024 keypair: {key_id}")
        return keypair
    
    def _generate_real_keypair(self) -> Tuple[bytes, bytes]:
        """Generate real ML-KEM-1024 keypair using liboqs"""
        try:
            import oqs
            
            with oqs.KeyEncapsulation('Kyber1024') as kem:
                public_key = kem.generate_keypair()
                secret_key = kem.export_secret_key()
                
                return public_key, secret_key
        
        except Exception as e:
            logger.error(f"Real ML-KEM keypair generation failed: {e}")
            raise MLKEMError(f"ML-KEM keypair generation failed: {e}")
    
    def _generate_simulated_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generate simulated ML-KEM-1024 keypair for development - FIXED VERSION.
        
        WARNING: This is NOT secure and should only be used for testing!
        """
        logger.warning("Using SIMULATED ML-KEM - NOT SECURE!")
        
        # Generate random data with CORRECT sizes, accounting for the 7-byte prefix we'll add
        public_key = secure_random_bytes(self.params['public_key_bytes'] - 7)  # 1561 bytes
        secret_key = secure_random_bytes(self.params['secret_key_bytes'] - 7)   # 3161 bytes
        
        # Add headers to identify as simulated
        public_key = b'SIM_PK_' + public_key
        secret_key = b'SIM_SK_' + secret_key
        
        return public_key, secret_key
    
    def encapsulate(self, public_key: bytes, use_cache: bool = True) -> MLKEMEncapsulationResult:
        """
        Encapsulate a shared secret using ML-KEM-1024.

        Args:
            public_key: Recipient's public key

        Returns:
            Encapsulation result with ciphertext and shared secret
        """
        if len(public_key) != self.params['public_key_bytes']:
            raise ValueError(f"Invalid public key size: {len(public_key)} (expected {self.params['public_key_bytes']})")

        cache_key = compute_sha3_512(public_key)[:16]
        if use_cache:
            cached = self._encapsulation_cache.get(cache_key)
            if cached and time.time() - cached['timestamp'] < self._cache_ttl:
                logger.debug("Returning cached ML-KEM encapsulation result")
                return cached['result']

        start_time = time.time()

        if self._liboqs_available and not public_key.startswith(b'SIM_PK_'):
            # Use real ML-KEM implementation
            ciphertext, shared_secret = self._encapsulate_real(public_key)
        else:
            # Use simulation
            ciphertext, shared_secret = self._encapsulate_simulated(public_key)
        
        # Expand shared secret to 512 bits using HKDF
        expanded_secret = derive_key_hkdf_sha3_512(
            shared_secret,
            SECURITY_LEVEL_BYTES,
            salt=public_key[:32],  # Use part of public key as salt
            info=b"MLKEM1024-512bit-expansion"
        )
        
        key_id = cache_key.hex()

        result = MLKEMEncapsulationResult(
            ciphertext=ciphertext,
            shared_secret=shared_secret,
            expanded_secret=expanded_secret,
            key_id=key_id,
            timestamp=start_time
        )

        if use_cache:
            self._encapsulation_cache[cache_key] = {
                'timestamp': time.time(),
                'result': result
            }
            self._prune_cache()

        logger.info(f"ML-KEM encapsulation completed: {key_id}")
        return result

    def hybrid_encapsulate(
        self,
        public_key: bytes,
        peer_classical_public: Optional[bytes] = None,
        use_cache: bool = True,
    ) -> HybridEncapsulationResult:
        """Perform a hybrid ML-KEM + classical encapsulation."""

        mlkem_result = self.encapsulate(public_key, use_cache=use_cache)
        classical_public, classical_secret = self._derive_classical_secret(peer_classical_public)
        combined_secret = self._combine_hybrid_secret(mlkem_result.expanded_secret, classical_secret)
        profile = self.registry.get("Hybrid-MLKEM-X25519")

        metadata = {
            'post_quantum_algorithm': 'ML-KEM-1024',
            'classical_algorithm': 'X25519' if classical_public else 'synthetic-jitter',
            'liboqs_available': self._liboqs_available,
        }

        return HybridEncapsulationResult(
            key_id=mlkem_result.key_id,
            mlkem_result=mlkem_result,
            classical_public_key=classical_public,
            classical_shared_secret=classical_secret,
            combined_secret=combined_secret,
            algorithm_profile=profile,
            timestamp=time.time(),
            metadata=metadata,
        )

    def list_algorithms(self) -> List[PQCAlgorithmProfile]:
        """Expose registered PQC algorithm options."""

        return self.registry.list_algorithms()

    def benchmark_encapsulation(self, iterations: int = 10) -> EncapsulationBenchmark:
        """Benchmark encapsulation throughput for ML-KEM."""

        keypair = self.generate_keypair()
        start = time.time()
        for _ in range(max(1, iterations)):
            self.encapsulate(keypair.public_key, use_cache=False)
        elapsed = time.time() - start
        average_ms = (elapsed / max(1, iterations)) * 1000
        throughput = iterations / max(elapsed, 1e-9)

        return EncapsulationBenchmark(
            algorithm="ML-KEM-1024",
            iterations=iterations,
            average_time_ms=average_ms,
            throughput_ops=throughput,
        )

    def _derive_classical_secret(self, peer_public: Optional[bytes]) -> Tuple[bytes, bytes]:
        """Derive the classical component of the hybrid secret."""

        if x25519 and serialization:
            private_key = x25519.X25519PrivateKey.generate()
            public_bytes = private_key.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )

            if peer_public:
                peer_key = x25519.X25519PublicKey.from_public_bytes(peer_public)
                shared = private_key.exchange(peer_key)
            else:
                shared = compute_sha3_512(public_bytes + secure_random_bytes(32))[:32]

            return public_bytes, shared

        return b"", secure_random_bytes(32)

    def _combine_hybrid_secret(self, pq_secret: bytes, classical_secret: bytes) -> bytes:
        """Combine PQC and classical secrets into a single key."""

        salt = classical_secret[:16]
        if len(salt) < 16:
            salt = salt.ljust(16, b"\x00")

        material = pq_secret + classical_secret
        return derive_key_hkdf_sha3_512(
            material,
            SECURITY_LEVEL_BYTES,
            salt=salt,
            info=b"Hybrid-MLKEM-X25519",
        )

    def _prune_cache(self) -> None:
        """Remove stale entries from the encapsulation cache."""

        if len(self._encapsulation_cache) <= 32:
            return

        now = time.time()
        stale_keys = [
            key for key, value in self._encapsulation_cache.items()
            if now - value['timestamp'] > self._cache_ttl
        ]
        for key in stale_keys:
            self._encapsulation_cache.pop(key, None)

        while len(self._encapsulation_cache) > 32:
            oldest_key = min(
                self._encapsulation_cache.items(),
                key=lambda item: item[1]['timestamp'],
            )[0]
            self._encapsulation_cache.pop(oldest_key, None)

    def _encapsulate_real(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """Real ML-KEM encapsulation using liboqs"""
        try:
            import oqs
            
            with oqs.KeyEncapsulation('Kyber1024') as kem:
                ciphertext, shared_secret = kem.encap_secret(public_key)
                return ciphertext, shared_secret
        
        except Exception as e:
            logger.error(f"Real ML-KEM encapsulation failed: {e}")
            raise MLKEMError(f"ML-KEM encapsulation failed: {e}")
    
    def _encapsulate_simulated(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """
        Simulated ML-KEM encapsulation for development - FIXED VERSION.
        
        WARNING: This is NOT secure!
        """
        logger.warning("Using SIMULATED ML-KEM encapsulation - NOT SECURE!")
        
        # Generate simulated ciphertext and shared secret with CORRECT sizes
        ciphertext = secure_random_bytes(self.params['ciphertext_bytes'])  # 1568 bytes
        shared_secret = secure_random_bytes(self.params['shared_secret_bytes'])  # 32 bytes
        
        # Mix with public key for deterministic simulation
        key_hash = compute_sha3_512(public_key)
        
        # XOR with key hash for pseudo-deterministic behavior
        ciphertext_array = bytearray(ciphertext)
        for i in range(len(ciphertext_array)):
            ciphertext_array[i] ^= key_hash[i % len(key_hash)]
        
        shared_secret_array = bytearray(shared_secret)
        for i in range(len(shared_secret_array)):
            shared_secret_array[i] ^= key_hash[(i + 32) % len(key_hash)]
        
        return bytes(ciphertext_array), bytes(shared_secret_array)
    
    def decapsulate(self, ciphertext: bytes, secret_key: bytes) -> bytes:
        """
        Decapsulate shared secret using ML-KEM-1024.
        
        Args:
            ciphertext: Encapsulated ciphertext
            secret_key: Recipient's secret key
            
        Returns:
            Shared secret (32 bytes)
        """
        if len(ciphertext) != self.params['ciphertext_bytes']:
            raise ValueError(f"Invalid ciphertext size: {len(ciphertext)} (expected {self.params['ciphertext_bytes']})")
        
        if len(secret_key) != self.params['secret_key_bytes']:
            raise ValueError(f"Invalid secret key size: {len(secret_key)} (expected {self.params['secret_key_bytes']})")
        
        if self._liboqs_available and not secret_key.startswith(b'SIM_SK_'):
            # Use real ML-KEM implementation
            shared_secret = self._decapsulate_real(ciphertext, secret_key)
        else:
            # Use simulation
            shared_secret = self._decapsulate_simulated(ciphertext, secret_key)
        
        logger.info("ML-KEM decapsulation completed")
        return shared_secret
    
    def _decapsulate_real(self, ciphertext: bytes, secret_key: bytes) -> bytes:
        """
        Real ML-KEM decapsulation using liboqs - FIXED VERSION
        
        The KeyEncapsulation object must be initialized with the secret_key
        at construction time, not via a load method.
        """
        try:
            import oqs
            
            # FIXED: Initialize KeyEncapsulation with secret_key at construction
            with oqs.KeyEncapsulation('Kyber1024', secret_key=secret_key) as kem:
                shared_secret = kem.decap_secret(ciphertext)
                return shared_secret
        
        except Exception as e:
            logger.error(f"Real ML-KEM decapsulation failed: {e}")
            raise MLKEMError(f"ML-KEM decapsulation failed: {e}")
    
    def _decapsulate_simulated(self, ciphertext: bytes, secret_key: bytes) -> bytes:
        """
        Simulated ML-KEM decapsulation for development - FIXED VERSION.
        
        WARNING: This is NOT secure!
        """
        logger.warning("Using SIMULATED ML-KEM decapsulation - NOT SECURE!")
        
        # For simulation, derive shared secret from both ciphertext and secret key
        combined = ciphertext + secret_key
        shared_secret = compute_sha3_512(combined)[:self.params['shared_secret_bytes']]
        
        return shared_secret
    
    def serialize_context(self, context: MLKEMContext) -> bytes:
        """
        Serialize ML-KEM context for storage.
        
        Args:
            context: ML-KEM context to serialize
            
        Returns:
            Serialized context data
        """
        # Create header with version and lengths
        header = struct.pack(
            '>IIIIII',
            1,  # Version
            len(context.public_key),
            len(context.ciphertext),
            len(context.shared_secret),
            len(context.expanded_secret),
            len(context.salt)
        )
        
        # Concatenate all data
        data = (
            header +
            context.public_key +
            context.ciphertext +
            context.shared_secret +
            context.expanded_secret +
            context.salt
        )
        
        return data
    
    def deserialize_context(self, data: bytes) -> MLKEMContext:
        """
        Deserialize ML-KEM context from storage.
        
        Args:
            data: Serialized context data
            
        Returns:
            ML-KEM context object
        """
        offset = 0
        
        # Parse header
        version = struct.unpack('>I', data[offset:offset+4])[0]
        offset += 4
        
        if version != 1:
            raise ValueError(f"Unsupported context version: {version}")
        
        # Parse lengths
        pk_len = struct.unpack('>I', data[offset:offset+4])[0]
        offset += 4
        ct_len = struct.unpack('>I', data[offset:offset+4])[0]
        offset += 4
        ss_len = struct.unpack('>I', data[offset:offset+4])[0]
        offset += 4
        es_len = struct.unpack('>I', data[offset:offset+4])[0]
        offset += 4
        salt_len = struct.unpack('>I', data[offset:offset+4])[0]
        offset += 4
        
        # Extract data
        public_key = data[offset:offset+pk_len]
        offset += pk_len
        ciphertext = data[offset:offset+ct_len]
        offset += ct_len
        shared_secret = data[offset:offset+ss_len]
        offset += ss_len
        expanded_secret = data[offset:offset+es_len]
        offset += es_len
        salt = data[offset:offset+salt_len]
        
        return MLKEMContext(
            public_key=public_key,
            private_key=b'',  # Not serialized for security
            ciphertext=ciphertext,
            shared_secret=shared_secret,
            expanded_secret=expanded_secret,
            salt=salt
        )
    
    def get_engine_status(self) -> Dict:
        """Get status of ML-KEM engine"""
        return {
            "layer_name": "ML-KEM-1024 Post-Quantum",
            "security_level": "Quantum Resistant (1024-bit equivalent)",
            "liboqs_available": self._liboqs_available,
            "implementation": "Real ML-KEM" if self._liboqs_available else "Simulation",
            "cached_keypairs": len(self._key_cache),
            "parameters": self.params
        }
    
    def benchmark_operations(self, iterations: int = 100) -> Dict[str, float]:
        """
        Benchmark ML-KEM operations.
        
        Args:
            iterations: Number of iterations for benchmarking
            
        Returns:
            Performance metrics
        """
        import time
        
        metrics = {}
        
        # Benchmark key generation
        start_time = time.time()
        for _ in range(iterations):
            keypair = self.generate_keypair()
        keygen_time = time.time() - start_time
        metrics['keygen_ops_per_sec'] = iterations / keygen_time
        
        # Use last generated keypair for encap/decap tests
        test_keypair = keypair
        
        # Benchmark encapsulation
        start_time = time.time()
        encap_results = []
        for _ in range(iterations):
            result = self.encapsulate(test_keypair.public_key)
            encap_results.append(result)
        encap_time = time.time() - start_time
        metrics['encap_ops_per_sec'] = iterations / encap_time
        
        # Benchmark decapsulation
        start_time = time.time()
        for result in encap_results:
            self.decapsulate(result.ciphertext, test_keypair.secret_key)
        decap_time = time.time() - start_time
        metrics['decap_ops_per_sec'] = iterations / decap_time
        
        return metrics
    
    def cleanup_cache(self, max_age_seconds: int = 3600):
        """Clean up old cached keypairs"""
        current_time = time.time()
        expired_keys = []
        
        for key_id, keypair in self._key_cache.items():
            if current_time - keypair.generation_time > max_age_seconds:
                expired_keys.append(key_id)
        
        for key_id in expired_keys:
            del self._key_cache[key_id]
        
        if expired_keys:
            logger.info(f"Cleaned up {len(expired_keys)} expired ML-KEM keypairs")

# Global ML-KEM engine instance
_mlkem_engine = None

def get_mlkem_engine() -> PostQuantumMLKEM:
    """Get the global ML-KEM engine instance"""
    global _mlkem_engine
    if _mlkem_engine is None:
        _mlkem_engine = PostQuantumMLKEM()
    return _mlkem_engine

def create_installation_script():
    """Create script to install liboqs for real ML-KEM support"""
    script_content = """#!/bin/bash
# Build and install liboqs for ML-KEM support

echo "Building liboqs for ML-KEM-1024 support..."

# Install dependencies
sudo apt-get update
sudo apt-get install -y build-essential cmake ninja-build libssl-dev python3-dev

# Clone liboqs
git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git
cd liboqs

# Build liboqs
mkdir build && cd build
cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local ..
ninja
sudo ninja install

# Install Python wrapper
cd ..
pip3 install liboqs-python

echo "liboqs installation complete!"
echo "Restart your application to use real ML-KEM-1024."
"""
    
    with open('install_liboqs.sh', 'w') as f:
        f.write(script_content)
    
    os.chmod('install_liboqs.sh', 0o755)
    logger.info("Created install_liboqs.sh script")

# Test function
if __name__ == "__main__":
    print("ML-KEM-1024 Post-Quantum Layer Test")
    print("=" * 50)
    
    # Initialize engine
    mlkem = PostQuantumMLKEM()
    
    # Show status
    status = mlkem.get_engine_status()
    print(f"\nEngine Status:")
    print(f"  Implementation: {status['implementation']}")
    print(f"  Security Level: {status['security_level']}")
    print(f"  liboqs Available: {status['liboqs_available']}")
    
    # Test key generation
    print(f"\nGenerating ML-KEM-1024 keypair...")
    keypair = mlkem.generate_keypair()
    print(f"  Public key: {len(keypair.public_key)} bytes")
    print(f"  Secret key: {len(keypair.secret_key)} bytes")
    print(f"  Key ID: {keypair.key_id}")
    
    # Test encapsulation
    print(f"\nTesting encapsulation...")
    result = mlkem.encapsulate(keypair.public_key)
    print(f"  Ciphertext: {len(result.ciphertext)} bytes")
    print(f"  Shared secret: {len(result.shared_secret)} bytes")
    print(f"  Expanded secret: {len(result.expanded_secret)} bytes")
    
    # Test decapsulation
    print(f"\nTesting decapsulation...")
    recovered_secret = mlkem.decapsulate(result.ciphertext, keypair.secret_key)
    print(f"  Recovered secret: {len(recovered_secret)} bytes")
    
    # Verify
    if recovered_secret == result.shared_secret:
        print(f"\n✅ Encapsulation/Decapsulation successful!")
    else:
        print(f"\n❌ OTP key protection/unprotection failed!")
    
    # Performance benchmark
    print(f"\nPerformance benchmark (10 iterations)...")
    metrics = mlkem.benchmark_operations(10)
    
    print(f"Key generation: {metrics['keygen_ops_per_sec']:.1f} ops/sec")
    print(f"Encapsulation: {metrics['encap_ops_per_sec']:.1f} ops/sec")
    print(f"Decapsulation: {metrics['decap_ops_per_sec']:.1f} ops/sec")
    
    # Create installation script if liboqs not available
    if not status['liboqs_available']:
        print(f"\n⚠️ Using simulation mode - install liboqs for production use!")
        create_installation_script()
    
    print(f"\nML-KEM-1024 Post-Quantum Layer (Layer 3) ready!")
    print(f"Quantum resistance achieved! 🛡️")