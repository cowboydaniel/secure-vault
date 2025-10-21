"""
Data Integrity Verification Module

Provides comprehensive integrity checking using cryptographic hashes
and authenticated encryption for detecting tampering and corruption.
"""

import hashlib
import hmac
import os
from typing import Dict, Any, Optional, Tuple
from pathlib import Path
from dataclasses import dataclass
import json
import time


@dataclass
class IntegrityInfo:
    """Information about file integrity"""
    file_path: str
    file_size: int
    hash_sha3_512: str
    hash_blake2b: str
    hmac_sha3: str
    timestamp: float
    chunk_hashes: Optional[Dict[int, str]] = None  # For chunked verification


class IntegrityChecker:
    """
    Integrity checker using multiple hash algorithms

    Features:
    - Multiple hash algorithms for redundancy
    - HMAC for authenticated integrity
    - Chunked hashing for large files
    - Integrity manifest management
    """

    def __init__(self, hmac_key: Optional[bytes] = None):
        """
        Initialize integrity checker

        Args:
            hmac_key: Key for HMAC (generated if not provided)
        """
        self.hmac_key = hmac_key or os.urandom(64)
        self.chunk_size = 1024 * 1024  # 1 MB chunks

    def compute_file_hash_sha3(self, file_path: Path) -> str:
        """
        Compute SHA3-512 hash of file

        Args:
            file_path: Path to file

        Returns:
            Hex-encoded hash
        """
        hasher = hashlib.sha3_512()

        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(self.chunk_size)
                if not chunk:
                    break
                hasher.update(chunk)

        return hasher.hexdigest()

    def compute_file_hash_blake2b(self, file_path: Path) -> str:
        """
        Compute BLAKE2b hash of file

        Args:
            file_path: Path to file

        Returns:
            Hex-encoded hash
        """
        hasher = hashlib.blake2b(digest_size=64)

        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(self.chunk_size)
                if not chunk:
                    break
                hasher.update(chunk)

        return hasher.hexdigest()

    def compute_file_hmac(self, file_path: Path) -> str:
        """
        Compute HMAC-SHA3-512 of file

        Args:
            file_path: Path to file

        Returns:
            Hex-encoded HMAC
        """
        h = hmac.new(self.hmac_key, digestmod=hashlib.sha3_512)

        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(self.chunk_size)
                if not chunk:
                    break
                h.update(chunk)

        return h.hexdigest()

    def compute_chunk_hashes(self, file_path: Path) -> Dict[int, str]:
        """
        Compute hash for each chunk of file

        Allows detection of which part of file is corrupted.

        Args:
            file_path: Path to file

        Returns:
            Dictionary mapping chunk number to hash
        """
        chunk_hashes = {}
        chunk_num = 0

        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(self.chunk_size)
                if not chunk:
                    break

                hasher = hashlib.sha3_512()
                hasher.update(chunk)
                chunk_hashes[chunk_num] = hasher.hexdigest()

                chunk_num += 1

        return chunk_hashes

    def generate_integrity_info(self,
                               file_path: Path,
                               include_chunks: bool = False) -> IntegrityInfo:
        """
        Generate comprehensive integrity information for file

        Args:
            file_path: Path to file
            include_chunks: Include per-chunk hashes

        Returns:
            IntegrityInfo object
        """
        file_path = Path(file_path)

        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        # Compute hashes
        sha3_hash = self.compute_file_hash_sha3(file_path)
        blake2_hash = self.compute_file_hash_blake2b(file_path)
        hmac_hash = self.compute_file_hmac(file_path)

        # Optional chunk hashes
        chunk_hashes = None
        if include_chunks:
            chunk_hashes = self.compute_chunk_hashes(file_path)

        info = IntegrityInfo(
            file_path=str(file_path),
            file_size=file_path.stat().st_size,
            hash_sha3_512=sha3_hash,
            hash_blake2b=blake2_hash,
            hmac_sha3=hmac_hash,
            timestamp=time.time(),
            chunk_hashes=chunk_hashes
        )

        return info

    def verify_integrity(self,
                        file_path: Path,
                        integrity_info: IntegrityInfo,
                        verify_chunks: bool = False) -> Tuple[bool, Optional[str]]:
        """
        Verify file integrity against stored information

        Args:
            file_path: Path to file
            integrity_info: Previously generated integrity info
            verify_chunks: Also verify chunk hashes if available

        Returns:
            (is_valid, error_message)
        """
        file_path = Path(file_path)

        if not file_path.exists():
            return False, "File not found"

        # Check file size
        if file_path.stat().st_size != integrity_info.file_size:
            return False, "File size mismatch"

        # Verify SHA3-512 hash
        current_sha3 = self.compute_file_hash_sha3(file_path)
        if current_sha3 != integrity_info.hash_sha3_512:
            return False, "SHA3-512 hash mismatch"

        # Verify BLAKE2b hash
        current_blake2 = self.compute_file_hash_blake2b(file_path)
        if current_blake2 != integrity_info.hash_blake2b:
            return False, "BLAKE2b hash mismatch"

        # Verify HMAC
        current_hmac = self.compute_file_hmac(file_path)
        if current_hmac != integrity_info.hmac_sha3:
            return False, "HMAC verification failed"

        # Verify chunks if requested and available
        if verify_chunks and integrity_info.chunk_hashes:
            current_chunks = self.compute_chunk_hashes(file_path)

            for chunk_num, expected_hash in integrity_info.chunk_hashes.items():
                if chunk_num not in current_chunks:
                    return False, f"Missing chunk {chunk_num}"

                if current_chunks[chunk_num] != expected_hash:
                    return False, f"Chunk {chunk_num} corrupted"

        return True, None

    def save_integrity_manifest(self,
                               integrity_infos: list[IntegrityInfo],
                               manifest_path: Path):
        """
        Save integrity information to manifest file

        Args:
            integrity_infos: List of integrity information
            manifest_path: Path to save manifest
        """
        manifest = {
            'version': '1.0',
            'timestamp': time.time(),
            'hmac_key_fingerprint': hashlib.sha256(self.hmac_key).hexdigest()[:16],
            'files': []
        }

        for info in integrity_infos:
            file_info = {
                'path': info.file_path,
                'size': info.file_size,
                'sha3_512': info.hash_sha3_512,
                'blake2b': info.hash_blake2b,
                'hmac': info.hmac_sha3,
                'timestamp': info.timestamp
            }

            if info.chunk_hashes:
                file_info['chunks'] = info.chunk_hashes

            manifest['files'].append(file_info)

        with open(manifest_path, 'w') as f:
            json.dump(manifest, f, indent=2)

    def load_integrity_manifest(self, manifest_path: Path) -> list[IntegrityInfo]:
        """
        Load integrity information from manifest file

        Args:
            manifest_path: Path to manifest file

        Returns:
            List of IntegrityInfo objects
        """
        with open(manifest_path, 'r') as f:
            manifest = json.load(f)

        integrity_infos = []

        for file_info in manifest['files']:
            info = IntegrityInfo(
                file_path=file_info['path'],
                file_size=file_info['size'],
                hash_sha3_512=file_info['sha3_512'],
                hash_blake2b=file_info['blake2b'],
                hmac_sha3=file_info['hmac'],
                timestamp=file_info['timestamp'],
                chunk_hashes=file_info.get('chunks')
            )
            integrity_infos.append(info)

        return integrity_infos

    def verify_manifest(self,
                       manifest_path: Path,
                       verify_chunks: bool = False) -> Dict[str, Any]:
        """
        Verify all files in manifest

        Args:
            manifest_path: Path to manifest
            verify_chunks: Verify chunk hashes

        Returns:
            Dictionary with verification results
        """
        integrity_infos = self.load_integrity_manifest(manifest_path)

        results = {
            'total_files': len(integrity_infos),
            'verified': 0,
            'failed': 0,
            'missing': 0,
            'failures': []
        }

        for info in integrity_infos:
            file_path = Path(info.file_path)

            if not file_path.exists():
                results['missing'] += 1
                results['failures'].append({
                    'file': str(file_path),
                    'error': 'File not found'
                })
                continue

            is_valid, error = self.verify_integrity(file_path, info, verify_chunks)

            if is_valid:
                results['verified'] += 1
            else:
                results['failed'] += 1
                results['failures'].append({
                    'file': str(file_path),
                    'error': error
                })

        results['all_valid'] = results['failed'] == 0 and results['missing'] == 0

        return results


def compute_data_hash(data: bytes, algorithm: str = 'sha3-512') -> str:
    """
    Compute hash of data

    Args:
        data: Data to hash
        algorithm: Hash algorithm ('sha3-512', 'blake2b', 'sha256')

    Returns:
        Hex-encoded hash
    """
    if algorithm == 'sha3-512':
        return hashlib.sha3_512(data).hexdigest()
    elif algorithm == 'blake2b':
        return hashlib.blake2b(data, digest_size=64).hexdigest()
    elif algorithm == 'sha256':
        return hashlib.sha256(data).hexdigest()
    else:
        raise ValueError(f"Unknown algorithm: {algorithm}")


def compute_data_hmac(data: bytes, key: bytes, algorithm: str = 'sha3-512') -> str:
    """
    Compute HMAC of data

    Args:
        data: Data to authenticate
        key: HMAC key
        algorithm: Hash algorithm

    Returns:
        Hex-encoded HMAC
    """
    if algorithm == 'sha3-512':
        return hmac.new(key, data, hashlib.sha3_512).hexdigest()
    elif algorithm == 'sha256':
        return hmac.new(key, data, hashlib.sha256).hexdigest()
    else:
        raise ValueError(f"Unknown algorithm: {algorithm}")


def verify_data_integrity(data: bytes,
                         expected_hash: str,
                         algorithm: str = 'sha3-512') -> bool:
    """
    Verify data integrity against expected hash

    Args:
        data: Data to verify
        expected_hash: Expected hash value
        algorithm: Hash algorithm

    Returns:
        True if data integrity verified
    """
    actual_hash = compute_data_hash(data, algorithm)
    return actual_hash == expected_hash


def verify_data_hmac(data: bytes,
                    expected_hmac: str,
                    key: bytes,
                    algorithm: str = 'sha3-512') -> bool:
    """
    Verify data HMAC

    Args:
        data: Data to verify
        expected_hmac: Expected HMAC value
        key: HMAC key
        algorithm: Hash algorithm

    Returns:
        True if HMAC verified
    """
    actual_hmac = compute_data_hmac(data, key, algorithm)
    # Constant-time comparison to prevent timing attacks
    return hmac.compare_digest(actual_hmac, expected_hmac)
