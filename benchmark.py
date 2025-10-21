"""
Performance Benchmarking Suite for SecureVault

Comprehensive benchmarking of all encryption layers and operations.
"""

import time
import os
import statistics
from typing import Dict, List, Callable, Any, Optional
from dataclasses import dataclass
import json


@dataclass
class BenchmarkResult:
    """Results from a benchmark run"""
    name: str
    iterations: int
    total_time: float
    mean_time: float
    median_time: float
    std_dev: float
    min_time: float
    max_time: float
    throughput_mbps: Optional[float] = None  # MB/s
    operations_per_second: Optional[float] = None


class BenchmarkSuite:
    """
    Comprehensive benchmark suite for SecureVault

    Features:
    - Layer-by-layer performance testing
    - End-to-end encryption/decryption benchmarks
    - Statistical analysis of results
    - Comparison against baseline performance
    """

    def __init__(self):
        """Initialize benchmark suite"""
        self.results = []

    def benchmark_function(self,
                          name: str,
                          func: Callable,
                          iterations: int = 100,
                          data_size: Optional[int] = None) -> BenchmarkResult:
        """
        Benchmark a function

        Args:
            name: Benchmark name
            func: Function to benchmark (should take no arguments)
            iterations: Number of iterations
            data_size: Size of data processed (for throughput calculation)

        Returns:
            BenchmarkResult
        """
        times = []

        # Warmup run
        func()

        # Benchmark runs
        for _ in range(iterations):
            start = time.perf_counter()
            func()
            end = time.perf_counter()
            times.append(end - start)

        # Calculate statistics
        total_time = sum(times)
        mean_time = statistics.mean(times)
        median_time = statistics.median(times)
        std_dev = statistics.stdev(times) if len(times) > 1 else 0
        min_time = min(times)
        max_time = max(times)

        # Calculate throughput if data size provided
        throughput = None
        if data_size:
            throughput = (data_size / mean_time) / (1024 * 1024)  # MB/s

        ops_per_second = 1.0 / mean_time if mean_time > 0 else 0

        result = BenchmarkResult(
            name=name,
            iterations=iterations,
            total_time=total_time,
            mean_time=mean_time,
            median_time=median_time,
            std_dev=std_dev,
            min_time=min_time,
            max_time=max_time,
            throughput_mbps=throughput,
            operations_per_second=ops_per_second
        )

        self.results.append(result)
        return result

    def benchmark_ida_layer(self) -> List[BenchmarkResult]:
        """Benchmark Information Dispersal Algorithm layer"""
        from ida_layer import InformationDispersalEngine, IDAConfiguration
        from constants import GF512_IRREDUCIBLE_POLYNOMIAL

        results = []

        # Test configurations
        configs = [
            (3, 5, "3-of-5"),
            (4, 7, "4-of-7"),
            (5, 10, "5-of-10"),
        ]

        for threshold, total, desc in configs:
            config = IDAConfiguration(
                total_shares=total,
                threshold=threshold,
                field_polynomial=GF512_IRREDUCIBLE_POLYNOMIAL
            )
            ida = InformationDispersalEngine(config)

            # Test data sizes
            for size in [1024, 10*1024, 100*1024]:
                data = os.urandom(size)

                # Share creation
                result = self.benchmark_function(
                    f"IDA {desc} - Create shares ({size//1024}KB)",
                    lambda: ida.create_shares(data),
                    iterations=10,
                    data_size=size
                )
                results.append(result)

                # Share reconstruction
                shares = ida.create_shares(data)
                result = self.benchmark_function(
                    f"IDA {desc} - Reconstruct ({size//1024}KB)",
                    lambda: ida.reconstruct_data(shares),
                    iterations=10,
                    data_size=size
                )
                results.append(result)

        return results

    def benchmark_otp_layer(self) -> List[BenchmarkResult]:
        """Benchmark One-Time Pad layer"""
        from otp_layer import OneTimePadEngine

        results = []
        otp = OneTimePadEngine()

        # Test data sizes
        for size in [1024, 10*1024, 100*1024, 1024*1024]:
            data = os.urandom(size)

            # Encryption
            result = self.benchmark_function(
                f"OTP - Encrypt ({size//1024}KB)",
                lambda: otp.encrypt(data),
                iterations=20,
                data_size=size
            )
            results.append(result)

            # Decryption
            encrypted = otp.encrypt(data)
            result = self.benchmark_function(
                f"OTP - Decrypt ({size//1024}KB)",
                lambda: otp.decrypt(encrypted.ciphertext, encrypted.key_id),
                iterations=20,
                data_size=size
            )
            results.append(result)

        return results

    def benchmark_custom_cipher(self) -> List[BenchmarkResult]:
        """Benchmark custom 512-bit cipher"""
        from custom_cipher import Cipher512

        results = []
        cipher = Cipher512()

        # Single block operations
        key = os.urandom(64)
        context = cipher.create_context(key)
        block = os.urandom(64)

        result = self.benchmark_function(
            "Custom Cipher - Single block encrypt",
            lambda: cipher.encrypt_block(block, context),
            iterations=1000,
            data_size=64
        )
        results.append(result)

        ciphertext = cipher.encrypt_block(block, context)
        result = self.benchmark_function(
            "Custom Cipher - Single block decrypt",
            lambda: cipher.decrypt_block(ciphertext, context),
            iterations=1000,
            data_size=64
        )
        results.append(result)

        # Multi-block operations
        for size in [1024, 10*1024, 100*1024]:
            data = os.urandom(size)

            result = self.benchmark_function(
                f"Custom Cipher - Encrypt ({size//1024}KB)",
                lambda: cipher.encrypt(data, context),
                iterations=10,
                data_size=size
            )
            results.append(result)

            encrypted = cipher.encrypt(data, context)
            result = self.benchmark_function(
                f"Custom Cipher - Decrypt ({size//1024}KB)",
                lambda: cipher.decrypt(encrypted, context),
                iterations=10,
                data_size=size
            )
            results.append(result)

        return results

    def benchmark_compression(self) -> List[BenchmarkResult]:
        """Benchmark compression algorithms"""
        from compression import CompressionEngine, CompressionAlgorithm

        results = []
        engine = CompressionEngine()

        # Test different data types
        test_data = {
            'random': os.urandom(100*1024),
            'text': b'The quick brown fox jumps over the lazy dog. ' * 2000,
            'zeros': b'\x00' * 100*1024,
        }

        algorithms = [
            CompressionAlgorithm.LZ4,
            CompressionAlgorithm.ZSTD,
            CompressionAlgorithm.ZLIB
        ]

        for data_type, data in test_data.items():
            for algo in algorithms:
                # Compression
                result = self.benchmark_function(
                    f"Compression - {algo.value} ({data_type})",
                    lambda: engine.compress(data, algo),
                    iterations=20,
                    data_size=len(data)
                )
                results.append(result)

                # Decompression
                compressed, _, _ = engine.compress(data, algo)
                result = self.benchmark_function(
                    f"Decompression - {algo.value} ({data_type})",
                    lambda: engine.decompress(compressed, algo),
                    iterations=20,
                    data_size=len(data)
                )
                results.append(result)

        return results

    def benchmark_hashing(self) -> List[BenchmarkResult]:
        """Benchmark hash functions"""
        import hashlib

        results = []

        hash_functions = {
            'SHA3-512': hashlib.sha3_512,
            'BLAKE2b': lambda: hashlib.blake2b(digest_size=64),
            'SHA256': hashlib.sha256,
        }

        for size in [1024, 10*1024, 100*1024, 1024*1024]:
            data = os.urandom(size)

            for name, hash_func in hash_functions.items():
                def hash_data():
                    h = hash_func()
                    h.update(data)
                    return h.digest()

                result = self.benchmark_function(
                    f"Hash - {name} ({size//1024}KB)",
                    hash_data,
                    iterations=50,
                    data_size=size
                )
                results.append(result)

        return results

    def benchmark_rng(self) -> List[BenchmarkResult]:
        """Benchmark random number generation"""
        results = []

        # os.urandom
        for size in [64, 1024, 10*1024]:
            result = self.benchmark_function(
                f"RNG - os.urandom ({size} bytes)",
                lambda: os.urandom(size),
                iterations=100,
                data_size=size
            )
            results.append(result)

        # Hardware RNG if available
        try:
            from hardware_rng import HardwareRNGManager
            hwrng = HardwareRNGManager()

            for size in [64, 1024]:
                result = self.benchmark_function(
                    f"RNG - Hardware ({size} bytes)",
                    lambda: hwrng.get_random_bytes(size),
                    iterations=100,
                    data_size=size
                )
                results.append(result)
        except Exception:
            pass

        return results

    def run_all_benchmarks(self) -> Dict[str, List[BenchmarkResult]]:
        """Run all benchmarks"""
        all_results = {}

        print("Running IDA Layer benchmarks...")
        all_results['ida'] = self.benchmark_ida_layer()

        print("Running OTP Layer benchmarks...")
        all_results['otp'] = self.benchmark_otp_layer()

        print("Running Custom Cipher benchmarks...")
        all_results['cipher'] = self.benchmark_custom_cipher()

        print("Running Compression benchmarks...")
        all_results['compression'] = self.benchmark_compression()

        print("Running Hashing benchmarks...")
        all_results['hashing'] = self.benchmark_hashing()

        print("Running RNG benchmarks...")
        all_results['rng'] = self.benchmark_rng()

        return all_results

    def print_results(self, results: Optional[List[BenchmarkResult]] = None):
        """Print benchmark results in a formatted table"""
        if results is None:
            results = self.results

        print("\n" + "="*100)
        print(f"{'Benchmark Name':<50} {'Mean Time':<15} {'Throughput':<15} {'Ops/sec':<15}")
        print("="*100)

        for result in results:
            throughput_str = f"{result.throughput_mbps:.2f} MB/s" if result.throughput_mbps else "N/A"
            ops_str = f"{result.operations_per_second:.2f}" if result.operations_per_second else "N/A"

            print(f"{result.name:<50} {result.mean_time*1000:.3f} ms      {throughput_str:<15} {ops_str:<15}")

        print("="*100)

    def export_results(self, filename: str):
        """Export results to JSON file"""
        data = {
            'timestamp': time.time(),
            'results': []
        }

        for result in self.results:
            data['results'].append({
                'name': result.name,
                'iterations': result.iterations,
                'total_time': result.total_time,
                'mean_time': result.mean_time,
                'median_time': result.median_time,
                'std_dev': result.std_dev,
                'min_time': result.min_time,
                'max_time': result.max_time,
                'throughput_mbps': result.throughput_mbps,
                'operations_per_second': result.operations_per_second
            })

        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)


def main():
    """Run benchmark suite"""
    print("SecureVault Performance Benchmark Suite")
    print("="*100)

    suite = BenchmarkSuite()

    # Run all benchmarks
    all_results = suite.run_all_benchmarks()

    # Print results by category
    for category, results in all_results.items():
        print(f"\n{category.upper()} Benchmarks:")
        suite.print_results(results)

    # Export results
    suite.export_results('benchmark_results.json')
    print("\nResults exported to benchmark_results.json")


if __name__ == "__main__":
    main()
