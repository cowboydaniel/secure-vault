"""
Data Compression Module

Provides compression and decompression functionality using multiple algorithms
optimized for security and performance.
"""

import lz4.frame
import zstandard as zstd
import zlib
from typing import Tuple, Optional
from enum import Enum


class CompressionAlgorithm(Enum):
    """Supported compression algorithms"""
    NONE = "none"
    LZ4 = "lz4"
    ZSTD = "zstd"
    ZLIB = "zlib"


class CompressionEngine:
    """
    Multi-algorithm compression engine

    Features:
    - Multiple compression algorithms (LZ4, Zstandard, zlib)
    - Configurable compression levels
    - Automatic algorithm selection based on data characteristics
    - Compression ratio reporting
    """

    def __init__(self, default_algorithm: CompressionAlgorithm = CompressionAlgorithm.ZSTD):
        """
        Initialize compression engine

        Args:
            default_algorithm: Default compression algorithm
        """
        self.default_algorithm = default_algorithm

    def compress(self,
                data: bytes,
                algorithm: Optional[CompressionAlgorithm] = None,
                level: int = 3) -> Tuple[bytes, CompressionAlgorithm, float]:
        """
        Compress data using specified algorithm

        Args:
            data: Data to compress
            algorithm: Compression algorithm (uses default if None)
            level: Compression level (1-9 for most algorithms)

        Returns:
            (compressed_data, algorithm_used, compression_ratio)
        """
        if not data:
            return b'', CompressionAlgorithm.NONE, 1.0

        if algorithm is None:
            algorithm = self.default_algorithm

        original_size = len(data)
        compressed = None

        if algorithm == CompressionAlgorithm.LZ4:
            compressed = self._compress_lz4(data, level)

        elif algorithm == CompressionAlgorithm.ZSTD:
            compressed = self._compress_zstd(data, level)

        elif algorithm == CompressionAlgorithm.ZLIB:
            compressed = self._compress_zlib(data, level)

        elif algorithm == CompressionAlgorithm.NONE:
            compressed = data

        else:
            raise ValueError(f"Unknown compression algorithm: {algorithm}")

        compressed_size = len(compressed)
        ratio = original_size / compressed_size if compressed_size > 0 else 1.0

        # If compression doesn't help (ratio < 1.05), return uncompressed
        if ratio < 1.05 and algorithm != CompressionAlgorithm.NONE:
            return data, CompressionAlgorithm.NONE, 1.0

        return compressed, algorithm, ratio

    def decompress(self,
                  data: bytes,
                  algorithm: CompressionAlgorithm) -> bytes:
        """
        Decompress data using specified algorithm

        Args:
            data: Compressed data
            algorithm: Algorithm used for compression

        Returns:
            Decompressed data
        """
        if not data or algorithm == CompressionAlgorithm.NONE:
            return data

        if algorithm == CompressionAlgorithm.LZ4:
            return self._decompress_lz4(data)

        elif algorithm == CompressionAlgorithm.ZSTD:
            return self._decompress_zstd(data)

        elif algorithm == CompressionAlgorithm.ZLIB:
            return self._decompress_zlib(data)

        else:
            raise ValueError(f"Unknown compression algorithm: {algorithm}")

    def _compress_lz4(self, data: bytes, level: int) -> bytes:
        """
        Compress using LZ4 (fast, good for real-time)

        Args:
            data: Data to compress
            level: Compression level (0-16)

        Returns:
            Compressed data
        """
        # LZ4 level: 0 = fast, 16 = maximum compression
        return lz4.frame.compress(data, compression_level=min(level, 16))

    def _decompress_lz4(self, data: bytes) -> bytes:
        """Decompress LZ4 data"""
        return lz4.frame.decompress(data)

    def _compress_zstd(self, data: bytes, level: int) -> bytes:
        """
        Compress using Zstandard (balanced speed/ratio)

        Args:
            data: Data to compress
            level: Compression level (1-22)

        Returns:
            Compressed data
        """
        # Zstandard level: 1 = fast, 22 = maximum compression
        cctx = zstd.ZstdCompressor(level=min(level, 22))
        return cctx.compress(data)

    def _decompress_zstd(self, data: bytes) -> bytes:
        """Decompress Zstandard data"""
        dctx = zstd.ZstdDecompressor()
        return dctx.decompress(data)

    def _compress_zlib(self, data: bytes, level: int) -> bytes:
        """
        Compress using zlib (good compatibility)

        Args:
            data: Data to compress
            level: Compression level (1-9)

        Returns:
            Compressed data
        """
        # zlib level: 1 = fast, 9 = maximum compression
        return zlib.compress(data, level=min(level, 9))

    def _decompress_zlib(self, data: bytes) -> bytes:
        """Decompress zlib data"""
        return zlib.decompress(data)

    def auto_select_algorithm(self, data: bytes, sample_size: int = 10000) -> CompressionAlgorithm:
        """
        Automatically select best compression algorithm based on data

        Args:
            data: Data to analyze
            sample_size: Size of sample to test (for large files)

        Returns:
            Recommended compression algorithm
        """
        if len(data) == 0:
            return CompressionAlgorithm.NONE

        # Use sample for large files
        sample = data[:sample_size] if len(data) > sample_size else data

        # Estimate entropy (simple heuristic)
        unique_bytes = len(set(sample))
        entropy_ratio = unique_bytes / 256.0

        # High entropy (random-like data) - use LZ4 for speed
        if entropy_ratio > 0.9:
            return CompressionAlgorithm.LZ4

        # Medium entropy - use Zstandard for balance
        elif entropy_ratio > 0.5:
            return CompressionAlgorithm.ZSTD

        # Low entropy (highly compressible) - use Zstandard with higher compression
        else:
            return CompressionAlgorithm.ZSTD

    def benchmark_algorithms(self, data: bytes) -> dict:
        """
        Benchmark all algorithms on given data

        Args:
            data: Data to benchmark

        Returns:
            Dictionary with benchmark results
        """
        import time

        results = {}

        for algorithm in [CompressionAlgorithm.LZ4, CompressionAlgorithm.ZSTD, CompressionAlgorithm.ZLIB]:
            try:
                # Compression benchmark
                start = time.perf_counter()
                compressed, _, ratio = self.compress(data, algorithm)
                compress_time = time.perf_counter() - start

                # Decompression benchmark
                start = time.perf_counter()
                decompressed = self.decompress(compressed, algorithm)
                decompress_time = time.perf_counter() - start

                # Verify correctness
                assert decompressed == data

                results[algorithm.value] = {
                    'compression_ratio': ratio,
                    'compress_time': compress_time,
                    'decompress_time': decompress_time,
                    'compress_throughput': len(data) / compress_time / 1024 / 1024,  # MB/s
                    'decompress_throughput': len(data) / decompress_time / 1024 / 1024,  # MB/s
                    'compressed_size': len(compressed),
                    'original_size': len(data)
                }

            except Exception as e:
                results[algorithm.value] = {'error': str(e)}

        return results


def compress_data(data: bytes,
                 algorithm: CompressionAlgorithm = CompressionAlgorithm.ZSTD,
                 level: int = 3) -> Tuple[bytes, float]:
    """
    Convenience function to compress data

    Args:
        data: Data to compress
        algorithm: Compression algorithm
        level: Compression level

    Returns:
        (compressed_data, compression_ratio)
    """
    engine = CompressionEngine()
    compressed, _, ratio = engine.compress(data, algorithm, level)
    return compressed, ratio


def decompress_data(data: bytes,
                   algorithm: CompressionAlgorithm) -> bytes:
    """
    Convenience function to decompress data

    Args:
        data: Compressed data
        algorithm: Algorithm used for compression

    Returns:
        Decompressed data
    """
    engine = CompressionEngine()
    return engine.decompress(data, algorithm)


def estimate_compression_benefit(data: bytes, sample_size: int = 10000) -> float:
    """
    Estimate compression benefit without full compression

    Args:
        data: Data to analyze
        sample_size: Size of sample to test

    Returns:
        Estimated compression ratio
    """
    if len(data) == 0:
        return 1.0

    # Use sample for large files
    sample = data[:sample_size] if len(data) > sample_size else data

    # Quick compression test
    engine = CompressionEngine()
    compressed, _, ratio = engine.compress(sample, CompressionAlgorithm.LZ4, level=1)

    return ratio


def should_compress(data: bytes,
                   min_size: int = 1024,
                   min_ratio: float = 1.1) -> bool:
    """
    Determine if data should be compressed

    Args:
        data: Data to check
        min_size: Minimum size to consider compression
        min_ratio: Minimum compression ratio to be worthwhile

    Returns:
        True if compression is recommended
    """
    if len(data) < min_size:
        return False

    estimated_ratio = estimate_compression_benefit(data)

    return estimated_ratio >= min_ratio
