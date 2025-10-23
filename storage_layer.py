"""
Streamlined 512-bit Multi-Layer Encryption System
Secure Storage Layer (Layer 5)

This module implements the fifth and final layer: Secure storage with
steganography, metadata protection, and distributed storage capabilities.
"""

import os
import time
import struct
import hashlib
from typing import Dict, List, Optional, Tuple, Union, Any
from dataclasses import dataclass
from enum import Enum
import logging
import json
import sqlite3
from pathlib import Path

from file_utils import safe_file_open

from crypto_utils import (
    secure_random_bytes,
    compute_sha3_512,
    derive_key_hkdf_sha3_512,
    secure_file_delete,
    constant_time_xor
)
from config import StorageConfig, SECURITY_LEVEL_BYTES, MAGIC_NUMBERS
from constants import EncryptionMetadata

logger = logging.getLogger(__name__)

class StorageFormat(Enum):
    """Storage format types"""
    ENCRYPTED_CONTAINER = "encrypted_container"
    STEGANOGRAPHIC = "steganographic"
    DISTRIBUTED_SHARES = "distributed_shares"
    CLOUD_FRAGMENTS = "cloud_fragments"

class CompressionType(Enum):
    """Compression algorithms"""
    NONE = "none"
    ZLIB = "zlib"
    LZMA = "lzma"
    ZSTD = "zstd"

@dataclass
class StorageMetadata:
    """Metadata for stored files"""
    file_id: str
    original_name: str
    storage_format: StorageFormat
    compression_type: CompressionType
    encryption_layers: List[str]
    total_size: int
    storage_paths: List[str]
    checksum: bytes
    timestamp: float
    classification_level: int
    access_count: int = 0
    last_accessed: Optional[float] = None

@dataclass
class StorageContainer:
    """Encrypted storage container"""
    container_id: str
    container_data: bytes
    metadata: StorageMetadata
    integrity_hash: bytes
    steganography_carrier: Optional[bytes] = None

class SecureStorageEngine:
    """
    Secure Storage Engine for Layer 5
    
    Features:
    - Encrypted containers with 512-bit keys
    - Optional steganography in image files
    - Distributed storage across multiple locations
    - Metadata protection and integrity verification
    - Anti-forensics and secure deletion
    """
    
    def __init__(self, storage_dir: str = None):
        """
        Initialize secure storage engine.
        
        Args:
            storage_dir: Base directory for storage (uses default if None)
        """
        if storage_dir is None:
            storage_dir = StorageConfig.DEFAULT_STORAGE_DIR
        
        self.storage_dir = Path(storage_dir)
        self.metadata_db_path = self.storage_dir / "metadata.db"
        
        # Create storage directory structure
        self._initialize_storage_structure()
        
        # Initialize metadata database
        self._initialize_metadata_db()
        
        logger.info(f"Secure Storage Engine initialized: {self.storage_dir}")
    
    def _initialize_storage_structure(self):
        """Create storage directory structure"""
        directories = [
            self.storage_dir,
            self.storage_dir / "containers",
            self.storage_dir / "fragments",
            self.storage_dir / "steganography",
            self.storage_dir / "temp",
            self.storage_dir / "backup"
        ]
        
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        
        # Create .secure_vault marker
        marker_file = self.storage_dir / ".secure_vault"
        if not marker_file.exists():
            with safe_file_open(marker_file, 'w') as f:
                f.write(f"Secure Vault Storage\nCreated: {time.time()}\n")
            marker_file.chmod(0o600)
    
    def _initialize_metadata_db(self):
        """Initialize SQLite database for metadata"""
        with sqlite3.connect(self.metadata_db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS file_metadata (
                    file_id TEXT PRIMARY KEY,
                    original_name TEXT NOT NULL,
                    storage_format TEXT NOT NULL,
                    compression_type TEXT NOT NULL,
                    encryption_layers TEXT NOT NULL,
                    total_size INTEGER NOT NULL,
                    storage_paths TEXT NOT NULL,
                    checksum BLOB NOT NULL,
                    timestamp REAL NOT NULL,
                    classification_level INTEGER NOT NULL,
                    access_count INTEGER DEFAULT 0,
                    last_accessed REAL
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS access_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_id TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    success BOOLEAN NOT NULL,
                    details TEXT
                )
            """)
            
            conn.commit()
    
    def store_encrypted_data(self, 
                           file_id: str,
                           encrypted_data: bytes,
                           original_name: str,
                           metadata: Dict[str, Any],
                           storage_format: StorageFormat = StorageFormat.ENCRYPTED_CONTAINER) -> StorageContainer:
        """
        Store encrypted data in secure container.
        
        Args:
            file_id: Unique file identifier
            encrypted_data: Data from Layer 4 (custom cipher)
            original_name: Original filename
            metadata: Additional metadata
            storage_format: Storage format to use
            
        Returns:
            Storage container with location info
        """
        logger.info(f"Storing encrypted data: {file_id}")
        
        # Generate storage key
        storage_key = self._derive_storage_key(file_id)
        
        # Compress data if beneficial
        compressed_data, compression_type = self._compress_data(encrypted_data)
        
        # Create storage container - now returns (container_data, checksum)
        container_data, container_checksum = self._create_storage_container(
            compressed_data, 
            storage_key, 
            metadata
        )
        
        # The integrity hash is now the checksum of the container before adding the checksum
        integrity_hash = container_checksum
        
        # Determine storage paths based on format
        storage_paths = self._determine_storage_paths(file_id, storage_format)
        
        # Store container (which now includes the checksum at the end)
        self._write_container_to_storage(container_data, storage_paths, storage_format)
        
        # Create metadata record
        storage_metadata = StorageMetadata(
            file_id=file_id,
            original_name=original_name,
            storage_format=storage_format,
            compression_type=compression_type,
            encryption_layers=metadata.get('encryption_layers', []),
            total_size=len(container_data),
            storage_paths=storage_paths,
            checksum=integrity_hash,
            timestamp=time.time(),
            classification_level=metadata.get('classification_level', 3)
        )
        
        # Save metadata to database
        self._save_metadata(storage_metadata)
        
        # Log access
        self._log_access(file_id, "STORE", True, f"Format: {storage_format.value}")
        
        container = StorageContainer(
            container_id=file_id,
            container_data=container_data,
            metadata=storage_metadata,
            integrity_hash=integrity_hash
        )
        
        logger.info(f"Data stored successfully: {len(storage_paths)} locations")
        return container
    
    def _derive_storage_key(self, file_id: str) -> bytes:
        """Derive 512-bit storage encryption key from file ID"""
        # Use file ID and system-specific salt
        system_salt = self._get_system_salt()
        
        # Generate enough key material in chunks if needed
        key_material = b''
        chunk_size = min(1024, SECURITY_LEVEL_BYTES)  # Process in chunks if needed
        
        for i in range(0, SECURITY_LEVEL_BYTES, chunk_size):
            current_size = min(chunk_size, SECURITY_LEVEL_BYTES - len(key_material))
            chunk = derive_key_hkdf_sha3_512(
                file_id.encode('utf-8') + i.to_bytes(8, 'big'),
                current_size,
                salt=system_salt + i.to_bytes(8, 'big'),
                info=b"SecureStorage-Layer5-512bit-Chunk" + i.to_bytes(4, 'big')
            )
            key_material += chunk
        
        return key_material[:SECURITY_LEVEL_BYTES]  # Ensure exact size
    
    def _get_system_salt(self) -> bytes:
        """Get or create system-specific salt"""
        salt_file = self.storage_dir / ".system_salt"
        
        if salt_file.exists():
            with safe_file_open(salt_file, 'rb') as f:
                return f.read()
        else:
            # Generate new system salt
            salt = secure_random_bytes(SECURITY_LEVEL_BYTES)
            with safe_file_open(salt_file, 'wb') as f:
                f.write(salt)
            salt_file.chmod(0o600)
            return salt
    
    def _compress_data(self, data: bytes) -> Tuple[bytes, CompressionType]:
        """Compress data if beneficial"""
        if len(data) < 1024:  # Don't compress small data
            return data, CompressionType.NONE
        
        # Try different compression algorithms
        best_compressed = data
        best_type = CompressionType.NONE
        
        # ZLIB compression
        try:
            import zlib
            zlib_compressed = zlib.compress(data, level=6)
            if len(zlib_compressed) < len(best_compressed):
                best_compressed = zlib_compressed
                best_type = CompressionType.ZLIB
        except ImportError:
            pass
        
        # ZSTD compression (if available)
        try:
            import zstandard as zstd
            cctx = zstd.ZstdCompressor(level=3)
            zstd_compressed = cctx.compress(data)
            if len(zstd_compressed) < len(best_compressed):
                best_compressed = zstd_compressed
                best_type = CompressionType.ZSTD
        except ImportError:
            pass
        
        compression_ratio = len(best_compressed) / len(data)
        logger.debug(f"Compression: {best_type.value}, ratio: {compression_ratio:.2f}")
        
        return best_compressed, best_type
    
    def _create_storage_container(self, data: bytes, storage_key: bytes, metadata: Dict) -> bytes:
        """Create encrypted storage container"""
        logger.debug(f"[CREATE_CONTAINER] Input data length: {len(data)} bytes")
        
        # Container header
        header = MAGIC_NUMBERS['ENCRYPTED_FILE']
        header += struct.pack('>I', 1)  # Version
        
        # Store original data length for verification
        original_length = len(data)
        header += struct.pack('>Q', original_length)  # Original data length
        
        # Add timestamp
        timestamp = int(time.time())
        header += struct.pack('>Q', timestamp)
        
        logger.debug(f"[CREATE_CONTAINER] Header size: {len(header)} bytes")
        
        # Serialize metadata
        metadata_json = json.dumps(metadata, default=str).encode('utf-8')
        header += struct.pack('>I', len(metadata_json))
        header += metadata_json
        
        # Generate random IV
        iv = secure_random_bytes(SECURITY_LEVEL_BYTES)
        header += iv
        
        # Encrypt data using XOR with derived key stream (chunked)
        chunk_size = 64 * 1024  # 64KB chunks
        encrypted_chunks = []
        logger.debug(f"[CREATE_CONTAINER] Encrypting {len(data)} bytes in chunks of {chunk_size}")
        
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i + chunk_size]
            logger.debug(f"[CREATE_CONTAINER] Processing chunk {i//chunk_size + 1}, size: {len(chunk)} bytes")
            
            # Ensure we generate enough key material for the chunk
            key_material_needed = len(chunk)
            
            # Derive key material for this chunk with unique info
            chunk_info = b"storage-keystream-chunk-" + i.to_bytes(8, 'big')
            key_chunk = derive_key_hkdf_sha3_512(
                storage_key + iv + i.to_bytes(8, 'big'),
                key_material_needed,  # Request exactly the number of bytes we need
                salt=storage_key[:16] + i.to_bytes(8, 'big'),
                info=chunk_info
            )
            
            # Ensure we have enough key material
            if len(key_chunk) < key_material_needed:
                # If we didn't get enough key material, pad with zeros
                key_chunk = key_chunk.ljust(key_material_needed, b'\x00')
            
            encrypted_chunk = constant_time_xor(chunk, key_chunk[:key_material_needed])
            logger.debug(f"[CREATE_CONTAINER] Chunk {i//chunk_size + 1} encrypted: {len(encrypted_chunk)} bytes")
            encrypted_chunks.append(encrypted_chunk)
        
        encrypted_data = b''.join(encrypted_chunks)
        
        # Create final container (header + encrypted data)
        container = header + encrypted_data
        
        # Calculate checksum of the container (before adding the checksum)
        checksum = compute_sha3_512(container)
        
        # Add integrity checksum to the container
        container += checksum
        
        # Return both the container and the checksum for storage in metadata
        return container, checksum
    
    def _determine_storage_paths(self, file_id: str, storage_format: StorageFormat) -> List[str]:
        """Determine where to store the container"""
        paths = []
        
        if storage_format == StorageFormat.ENCRYPTED_CONTAINER:
            # Single encrypted container
            container_path = self.storage_dir / "containers" / f"{file_id}.sec512"
            paths.append(str(container_path))
            
        elif storage_format == StorageFormat.DISTRIBUTED_SHARES:
            # Multiple distributed fragments
            for i in range(3):  # Create 3 fragments
                fragment_path = self.storage_dir / "fragments" / f"{file_id}_frag_{i:02d}.sec512"
                paths.append(str(fragment_path))
                
        elif storage_format == StorageFormat.STEGANOGRAPHIC:
            # Steganography in carrier files
            stego_path = self.storage_dir / "steganography" / f"{file_id}_hidden.png"
            paths.append(str(stego_path))
            
        elif storage_format == StorageFormat.CLOUD_FRAGMENTS:
            # Cloud storage paths (placeholder)
            for provider in ['aws', 'gcp', 'azure']:
                cloud_path = f"cloud://{provider}/{file_id}.fragment"
                paths.append(cloud_path)
        
        return paths
    
    def _write_container_to_storage(self, container_data: bytes, 
                                  storage_paths: List[str], 
                                  storage_format: StorageFormat):
        """Write container to storage locations"""
        if storage_format == StorageFormat.ENCRYPTED_CONTAINER:
            # Write single container
            with safe_file_open(storage_paths[0], 'wb') as f:
                f.write(container_data)
            os.chmod(storage_paths[0], 0o600)
            
        elif storage_format == StorageFormat.DISTRIBUTED_SHARES:
            # Split container into fragments
            fragment_size = len(container_data) // len(storage_paths)
            
            for i, path in enumerate(storage_paths):
                start_offset = i * fragment_size
                if i == len(storage_paths) - 1:
                    # Last fragment gets remainder
                    fragment = container_data[start_offset:]
                else:
                    fragment = container_data[start_offset:start_offset + fragment_size]
                
                with safe_file_open(path, 'wb') as f:
                    f.write(fragment)
                os.chmod(path, 0o600)
                
        elif storage_format == StorageFormat.STEGANOGRAPHIC:
            # Hide in steganographic carrier
            self._create_steganographic_container(container_data, storage_paths[0])
            
        # For cloud storage, we'd implement cloud provider APIs here
    
    def _create_steganographic_container(self, data: bytes, output_path: str):
        """Hide data in steganographic carrier (PNG image)"""
        try:
            from PIL import Image
            import numpy as np
            
            # Calculate required image size
            data_bits = len(data) * 8
            min_pixels = data_bits + 64  # Extra space for length header
            
            # Create square image
            side_length = int(np.sqrt(min_pixels / 3)) + 1  # 3 channels (RGB)
            
            # Generate random carrier image
            carrier = np.random.randint(0, 256, (side_length, side_length, 3), dtype=np.uint8)
            
            # Encode data length in first 64 bits
            data_length_bits = format(len(data), '064b')
            
            # Encode data as bits
            data_bits_str = ''.join(format(byte, '08b') for byte in data)
            all_bits = data_length_bits + data_bits_str
            
            # Hide bits in LSBs of image
            flat_carrier = carrier.flatten()
            for i, bit in enumerate(all_bits[:len(flat_carrier)]):
                if i < len(flat_carrier):
                    flat_carrier[i] = (flat_carrier[i] & 0xFE) | int(bit)
            
            # Reshape and save
            hidden_image = flat_carrier.reshape((side_length, side_length, 3))
            Image.fromarray(hidden_image).save(output_path, 'PNG')
            
            logger.info(f"Steganographic container created: {output_path}")
            
        except ImportError:
            logger.warning("PIL not available, using simple steganographic format")
            # Fallback: prepend data to random bytes
            carrier_size = len(data) * 10  # 10x expansion
            carrier = secure_random_bytes(carrier_size)
            
            # Simple XOR hiding
            hidden_data = bytearray(carrier)
            for i, byte in enumerate(data):
                if i < len(hidden_data):
                    hidden_data[i] ^= byte
            
            with safe_file_open(output_path, 'wb') as f:
                f.write(hidden_data)
    
    def retrieve_encrypted_data(self, file_id: str) -> Tuple[bytes, StorageMetadata]:
        """
        Retrieve encrypted data from storage.
        
        Args:
            file_id: File identifier
            
        Returns:
            Tuple of (decrypted_data, metadata)
        """
        logger.info(f"Retrieving encrypted data: {file_id}")
        
        # Load metadata from database
        metadata = self._load_metadata(file_id)
        if not metadata:
            raise FileNotFoundError(f"File not found: {file_id}")
        
        # Read container from storage
        container_data = self._read_container_from_storage(metadata)
        
        # Verify integrity
        if not self._verify_container_integrity(container_data, metadata.checksum):
            raise ValueError("Container integrity verification failed")
        
        # Decrypt container
        decrypted_data = self._decrypt_storage_container(container_data, file_id)
        
        # Decompress if needed
        final_data = self._decompress_data(decrypted_data, metadata.compression_type)
        
        # Update access statistics
        self._update_access_stats(file_id)
        
        # Log access
        self._log_access(file_id, "RETRIEVE", True, f"Size: {len(final_data)} bytes")
        
        logger.info(f"Data retrieved successfully: {len(final_data)} bytes")
        return final_data, metadata
    
    def _read_container_from_storage(self, metadata: StorageMetadata) -> bytes:
        """Read container from storage paths"""
        if metadata.storage_format == StorageFormat.ENCRYPTED_CONTAINER:
            # Read single container
            with safe_file_open(metadata.storage_paths[0], 'rb') as f:
                return f.read()
                
        elif metadata.storage_format == StorageFormat.DISTRIBUTED_SHARES:
            # Reconstruct from fragments
            fragments = []
            for path in metadata.storage_paths:
                with safe_file_open(path, 'rb') as f:
                    fragments.append(f.read())
            return b''.join(fragments)
            
        elif metadata.storage_format == StorageFormat.STEGANOGRAPHIC:
            # Extract from steganographic carrier
            return self._extract_from_steganographic_container(metadata.storage_paths[0])
            
        else:
            raise ValueError(f"Unsupported storage format: {metadata.storage_format}")
    
    def _extract_from_steganographic_container(self, container_path: str) -> bytes:
        """Extract data from steganographic container"""
        try:
            from PIL import Image
            import numpy as np
            
            # Load image
            with safe_file_open(container_path, 'rb') as image_file:
                image = Image.open(image_file)
                image.load()
            image_array = np.array(image)
            flat_array = image_array.flatten()
            
            # Extract length from first 64 bits
            length_bits = ''.join(str(pixel & 1) for pixel in flat_array[:64])
            data_length = int(length_bits, 2)
            
            # Extract data bits
            data_bits = ''.join(str(pixel & 1) for pixel in flat_array[64:64 + data_length * 8])
            
            # Convert bits to bytes
            data = bytearray()
            for i in range(0, len(data_bits), 8):
                byte_bits = data_bits[i:i+8]
                if len(byte_bits) == 8:
                    data.append(int(byte_bits, 2))
            
            return bytes(data)
            
        except ImportError:
            logger.warning("PIL not available, using simple steganographic extraction")
            # Fallback: simple XOR extraction
            with safe_file_open(container_path, 'rb') as f:
                hidden_data = f.read()
            
            # This is a simplified extraction - in practice you'd need
            # to know the original data length
            return hidden_data[:len(hidden_data) // 10]  # Assume 10x expansion
    
    def _verify_container_integrity(self, container_data: bytes, expected_checksum: bytes) -> bool:
        """Verify container integrity"""
        # Extract stored checksum (last 64 bytes)
        stored_checksum = container_data[-64:]
        container_without_checksum = container_data[:-64]
        
        # Calculate checksum
        calculated_checksum = compute_sha3_512(container_without_checksum)
        
        return calculated_checksum == expected_checksum
    
    def _decrypt_storage_container(self, container_data: bytes, file_id: str) -> bytes:
        """Decrypt storage container"""
        logger.debug(f"[DECRYPT_CONTAINER] Input container size: {len(container_data)} bytes")
        
        # Remove integrity checksum (last 64 bytes)
        container_data = container_data[:-64]
        logger.debug(f"[DECRYPT_CONTAINER] After removing checksum: {len(container_data)} bytes")
        
        # Parse header
        offset = 0
        magic = container_data[offset:offset+8]
        offset += 8
        
        if magic != MAGIC_NUMBERS['ENCRYPTED_FILE']:
            raise ValueError("Invalid container magic number")
        
        version = struct.unpack('>I', container_data[offset:offset+4])[0]
        offset += 4
        
        # Get the original data length from the header
        original_length = struct.unpack('>Q', container_data[offset:offset+8])[0]
        offset += 8
        
        timestamp = struct.unpack('>Q', container_data[offset:offset+8])[0]
        offset += 8
        
        metadata_length = struct.unpack('>I', container_data[offset:offset+4])[0]
        offset += 4
        
        metadata_json = container_data[offset:offset+metadata_length]
        offset += metadata_length
        
        iv = container_data[offset:offset+SECURITY_LEVEL_BYTES]
        offset += SECURITY_LEVEL_BYTES
        
        # The remaining data is the encrypted payload
        encrypted_data = container_data[offset:]
        
        logger.debug(f"[DECRYPT_CONTAINER] Original length from header: {original_length} bytes")
        logger.debug(f"[DECRYPT_CONTAINER] Header size: {offset} bytes")
        logger.debug(f"[DECRYPT_CONTAINER] Encrypted data size: {len(encrypted_data)} bytes")
        
        # Derive storage key
        storage_key = self._derive_storage_key(file_id)
        
        # Decrypt in chunks matching the encryption chunks
        chunk_size = 64 * 1024  # Must match the chunk size used in _create_storage_container
        logger.debug(f"[DECRYPT_CONTAINER] Decrypting in chunks of {chunk_size} bytes")
        
        decrypted_chunks = []
        total_decrypted = 0
        
        for i in range(0, len(encrypted_data), chunk_size):
            chunk = encrypted_data[i:i + chunk_size]
            logger.debug(f"[DECRYPT_CONTAINER] Processing chunk {i//chunk_size + 1}, size: {len(chunk)} bytes, offset: {i}")
            
            # Ensure we generate enough key material for the chunk
            key_material_needed = len(chunk)
            
            # Derive the same key material for this chunk
            chunk_info = b"storage-keystream-chunk-" + i.to_bytes(8, 'big')
            key_chunk = derive_key_hkdf_sha3_512(
                storage_key + iv + i.to_bytes(8, 'big'),
                key_material_needed,  # Request exactly the number of bytes we need
                salt=storage_key[:16] + i.to_bytes(8, 'big'),
                info=chunk_info
            )
            
            # Ensure we have enough key material
            if len(key_chunk) < key_material_needed:
                # If we didn't get enough key material, pad with zeros
                key_chunk = key_chunk.ljust(key_material_needed, b'\x00')
            
            logger.debug(f"[DECRYPT_CONTAINER] Derived key for chunk {i//chunk_size + 1}, length: {len(key_chunk)} bytes")
            
            decrypted_chunk = constant_time_xor(chunk, key_chunk[:key_material_needed])
            logger.debug(f"[DECRYPT_CONTAINER] Decrypted chunk {i//chunk_size + 1}, size: {len(decrypted_chunk)} bytes")
            
            # If this is the last chunk, truncate to the original length
            remaining_bytes = original_length - total_decrypted
            if len(decrypted_chunk) > remaining_bytes:
                logger.debug(f"[DECRYPT_CONTAINER] Truncating final chunk from {len(decrypted_chunk)} to {remaining_bytes} bytes")
                decrypted_chunk = decrypted_chunk[:remaining_bytes]
            
            decrypted_chunks.append(decrypted_chunk)
            total_decrypted += len(decrypted_chunk)
            logger.debug(f"[DECRYPT_CONTAINER] Total decrypted so far: {total_decrypted}/{original_length} bytes")
            
            if total_decrypted >= original_length:
                logger.debug("[DECRYPT_CONTAINER] Reached original data length, stopping decryption")
                break
        
        decrypted_data = b''.join(decrypted_chunks)
        
        # Verify we got the expected amount of data
        if len(decrypted_data) != original_length:
            raise ValueError(f"Decrypted data length ({len(decrypted_data)}) "
                           f"does not match expected length ({original_length})")
        
        return decrypted_data
    
    def _decompress_data(self, data: bytes, compression_type: CompressionType) -> bytes:
        """Decompress data"""
        if compression_type == CompressionType.NONE:
            return data
        elif compression_type == CompressionType.ZLIB:
            import zlib
            return zlib.decompress(data)
        elif compression_type == CompressionType.ZSTD:
            import zstandard as zstd
            dctx = zstd.ZstdDecompressor()
            return dctx.decompress(data)
        else:
            logger.warning(f"Unknown compression type: {compression_type}")
            return data
    
    def _save_metadata(self, metadata: StorageMetadata):
        """Save metadata to database"""
        with sqlite3.connect(self.metadata_db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO file_metadata
                (file_id, original_name, storage_format, compression_type, 
                 encryption_layers, total_size, storage_paths, checksum, 
                 timestamp, classification_level, access_count, last_accessed)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                metadata.file_id,
                metadata.original_name,
                metadata.storage_format.value,
                metadata.compression_type.value,
                json.dumps(metadata.encryption_layers),
                metadata.total_size,
                json.dumps(metadata.storage_paths),
                metadata.checksum,
                metadata.timestamp,
                metadata.classification_level,
                metadata.access_count,
                metadata.last_accessed
            ))
            conn.commit()
    
    def _load_metadata(self, file_id: str) -> Optional[StorageMetadata]:
        """Load metadata from database"""
        with sqlite3.connect(self.metadata_db_path) as conn:
            cursor = conn.execute("""
                SELECT * FROM file_metadata WHERE file_id = ?
            """, (file_id,))
            
            row = cursor.fetchone()
            if not row:
                return None
            
            return StorageMetadata(
                file_id=row[0],
                original_name=row[1],
                storage_format=StorageFormat(row[2]),
                compression_type=CompressionType(row[3]),
                encryption_layers=json.loads(row[4]),
                total_size=row[5],
                storage_paths=json.loads(row[6]),
                checksum=row[7],
                timestamp=row[8],
                classification_level=row[9],
                access_count=row[10],
                last_accessed=row[11]
            )
    
    def _update_access_stats(self, file_id: str):
        """Update file access statistics"""
        with sqlite3.connect(self.metadata_db_path) as conn:
            conn.execute("""
                UPDATE file_metadata 
                SET access_count = access_count + 1, last_accessed = ?
                WHERE file_id = ?
            """, (time.time(), file_id))
            conn.commit()
    
    def _log_access(self, file_id: str, operation: str, success: bool, details: str = ""):
        """Log access attempt"""
        with sqlite3.connect(self.metadata_db_path) as conn:
            conn.execute("""
                INSERT INTO access_log (file_id, operation, timestamp, success, details)
                VALUES (?, ?, ?, ?, ?)
            """, (file_id, operation, time.time(), success, details))
            conn.commit()
    
    def list_stored_files(self) -> List[StorageMetadata]:
        """List all stored files"""
        with sqlite3.connect(self.metadata_db_path) as conn:
            cursor = conn.execute("SELECT * FROM file_metadata ORDER BY timestamp DESC")
            
            files = []
            for row in cursor.fetchall():
                metadata = StorageMetadata(
                    file_id=row[0],
                    original_name=row[1],
                    storage_format=StorageFormat(row[2]),
                    compression_type=CompressionType(row[3]),
                    encryption_layers=json.loads(row[4]),
                    total_size=row[5],
                    storage_paths=json.loads(row[6]),
                    checksum=row[7],
                    timestamp=row[8],
                    classification_level=row[9],
                    access_count=row[10],
                    last_accessed=row[11]
                )
                files.append(metadata)
            
            return files
    
    def secure_delete_file(self, file_id: str) -> bool:
        """Securely delete file and all traces"""
        logger.info(f"Securely deleting file: {file_id}")
        
        try:
            # Load metadata
            metadata = self._load_metadata(file_id)
            if not metadata:
                logger.warning(f"File not found for deletion: {file_id}")
                return False
            
            # Securely delete storage files
            for path in metadata.storage_paths:
                if os.path.exists(path):
                    secure_file_delete(path)
                    logger.debug(f"Securely deleted: {path}")
            
            # Remove from database
            with sqlite3.connect(self.metadata_db_path) as conn:
                conn.execute("DELETE FROM file_metadata WHERE file_id = ?", (file_id,))
                conn.execute("DELETE FROM access_log WHERE file_id = ?", (file_id,))
                conn.commit()
            
            # Log deletion
            self._log_access(file_id, "DELETE", True, "Secure deletion completed")
            
            logger.info(f"File securely deleted: {file_id}")
            return True
            
        except Exception as e:
            logger.error(f"Secure deletion failed: {e}")
            self._log_access(file_id, "DELETE", False, str(e))
            return False
    
    def get_storage_statistics(self) -> Dict[str, Any]:
        """Get storage engine statistics"""
        with sqlite3.connect(self.metadata_db_path) as conn:
            # Count files by format
            cursor = conn.execute("""
                SELECT storage_format, COUNT(*), SUM(total_size)
                FROM file_metadata
                GROUP BY storage_format
            """)
            
            format_stats = {}
            total_files = 0
            total_size = 0
            
            for row in cursor.fetchall():
                format_stats[row[0]] = {
                    'count': row[1],
                    'total_size': row[2] or 0
                }
                total_files += row[1]
                total_size += row[2] or 0
            
            # Recent activity
            cursor = conn.execute("""
                SELECT COUNT(*) FROM access_log 
                WHERE timestamp > ?
            """, (time.time() - 86400,))  # Last 24 hours
            
            recent_activity = cursor.fetchone()[0]
            
            return {
                'total_files': total_files,
                'total_size_bytes': total_size,
                'total_size_mb': total_size / (1024 * 1024),
                'format_statistics': format_stats,
                'recent_activity_24h': recent_activity,
                'storage_directory': str(self.storage_dir),
                'database_size_bytes': os.path.getsize(self.metadata_db_path)
            }

# Global storage engine instance
_storage_engine = None

def get_storage_engine(storage_dir: str = None) -> SecureStorageEngine:
    """Get the global storage engine instance"""
    global _storage_engine
    if _storage_engine is None:
        _storage_engine = SecureStorageEngine(storage_dir)
    return _storage_engine

if __name__ == "__main__":
    # Demonstrate secure storage
    print("Secure Storage Layer (Layer 5) Demo")
    print("=" * 40)
    
    # Initialize storage engine
    storage = SecureStorageEngine("/tmp/test_secure_storage")
    
    # Create test data (simulating output from Layer 4)
    test_data = b"This is encrypted data from Layer 4 (Custom Cipher) that needs secure storage!"
    file_id = "TEST_FILE_001"
    original_name = "secret_document.pdf"
    
    metadata = {
        'encryption_layers': ['IDA', 'OTP', 'ML-KEM', 'CustomCipher'],
        'classification_level': 3,
        'created_by': 'test_user'
    }
    
    print(f"Test data: {len(test_data)} bytes")
    print(f"File ID: {file_id}")
    
    # Test different storage formats
    storage_formats = [
        StorageFormat.ENCRYPTED_CONTAINER,
        StorageFormat.DISTRIBUTED_SHARES,
        StorageFormat.STEGANOGRAPHIC
    ]
    
    for i, storage_format in enumerate(storage_formats):
        test_file_id = f"{file_id}_{i+1}"
        
        print(f"\nTesting {storage_format.value}...")
        
        # Store data
        container = storage.store_encrypted_data(
            test_file_id,
            test_data,
            f"{original_name}_{i+1}",
            metadata,
            storage_format
        )
        
        print(f"  ✓ Stored: {len(container.storage_paths)} locations")
        print(f"  ✓ Container size: {len(container.container_data):,} bytes")
        print(f"  ✓ Integrity hash: {container.integrity_hash[:16].hex()}...")
        
        # Retrieve data
        retrieved_data, retrieved_metadata = storage.retrieve_encrypted_data(test_file_id)
        
        if retrieved_data == test_data:
            print(f"  ✓ Retrieval successful")
        else:
            print(f"  ✗ Retrieval failed")
        
        print(f"  ✓ Access count: {retrieved_metadata.access_count}")
    
    # Show storage statistics
    print(f"\nStorage Statistics:")
    stats = storage.get_storage_statistics()
    print(f"  Total files: {stats['total_files']}")
    print(f"  Total size: {stats['total_size_mb']:.2f} MB")
    print(f"  Recent activity: {stats['recent_activity_24h']} operations")
    
    print(f"  Format breakdown:")
    for format_name, format_stats in stats['format_statistics'].items():
        print(f"    {format_name}: {format_stats['count']} files, "
              f"{format_stats['total_size'] / 1024:.1f} KB")
    
    # List all stored files
    print(f"\nStored Files:")
    stored_files = storage.list_stored_files()
    for file_meta in stored_files:
        print(f"  {file_meta.file_id}: {file_meta.original_name}")
        print(f"    Format: {file_meta.storage_format.value}")
        print(f"    Size: {file_meta.total_size:,} bytes")
        print(f"    Locations: {len(file_meta.storage_paths)}")
    
    # Test secure deletion
    print(f"\nTesting secure deletion...")
    for i in range(len(storage_formats)):
        test_file_id = f"{file_id}_{i+1}"
        success = storage.secure_delete_file(test_file_id)
        if success:
            print(f"  ✓ {test_file_id} securely deleted")
        else:
            print(f"  ✗ {test_file_id} deletion failed")
    
    # Final statistics
    final_stats = storage.get_storage_statistics()
    print(f"\nFinal Statistics:")
    print(f"  Remaining files: {final_stats['total_files']}")
    print(f"  Total operations: {final_stats['recent_activity_24h']}")
    
    print(f"\n🗄️ Secure Storage Layer (Layer 5) ready!")
    print(f"Anti-forensics and steganography achieved!")