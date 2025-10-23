"""
Entropy Quality Monitoring System

This module provides continuous monitoring of entropy sources and quality metrics
to ensure cryptographically secure random number generation.
"""

import os
import time
import math
import ctypes
import hashlib
import numpy as np
from typing import Dict, List, Tuple, Optional, Callable, Any
from dataclasses import dataclass, field
from enum import Enum, auto
import threading
import logging
from collections import deque
from pathlib import Path
import platform
import sys

# Import secure memory for handling sensitive data
from secure_memory import SecureBytes, secure_alloc, secure_free
from entropy_pool import entropy_accumulator, start_accumulator, stop_accumulator
from hardware_rng import get_hardware_rng, get_hardware_random_bytes, HWRNGType

logger = logging.getLogger(__name__)

class EntropySource(Enum):
    """Available entropy sources"""
    SYSTEM_RANDOM = auto()
    OS_URANDOM = auto()
    HARDWARE_RNG = auto()
    TIMING = auto()
    USER_INPUT = auto()
    INTERRUPT = auto()
    DISK_ACTIVITY = auto()
    NETWORK_ACTIVITY = auto()

class EntropyHealthStatus(Enum):
    """Health status of entropy source"""
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    CRITICAL = "CRITICAL"
    FAILED = "FAILED"

@dataclass
class EntropyMetrics:
    """Metrics for entropy quality assessment
    
    Attributes:
        min_entropy: Minimum entropy in bits per byte (0-8)
        shannon_entropy: Shannon entropy in bits per byte (0-8)
        entropy_rate: Entropy rate in bits per second
        compression_ratio: Compression ratio (lower is better, range 0-1)
        autocorrelation: Autocorrelation at lag 1 (range -1 to 1)
        predictive_entropy: Predictive entropy ratio (0-1)
        chi_square: Chi-square test p-value
        runs_test: Runs test p-value
        spectral_test: Spectral test p-value
        cumulative_sums_forward: Cumulative sums (forward) test p-value
        cumulative_sums_reverse: Cumulative sums (reverse) test p-value
        health_score: Composite health score (0-100)
        source: Source of the entropy sample
        timestamp: When the sample was taken
        sample_size: Size of the sample in bytes
        chi_square: Chi-square test statistic
        mean: Mean byte value (0-255)
        variance: Variance of byte values
        monte_carlo_pi: Estimated value of π using Monte Carlo method
        longest_run: Length of longest run of identical bits
        runs_test: P-value from the runs test for randomness
        spectral_test: Spectral test result
        autocorrelation: Autocorrelation at lag 1 (-1 to 1)
        entropy_rate: Estimated entropy rate in bits per second
        compression_ratio: Ratio of compressed to original size (lower is better)
        predictive_entropy: Entropy after accounting for simple patterns
        health_score: Composite health score (0-100)
        timestamp: When these metrics were calculated
    """
    # Basic statistical metrics
    min_entropy: float = 0.0
    shannon_entropy: float = 0.0
    chi_square: float = 0.0
    mean: float = 0.0
    variance: float = 0.0
    
    # Statistical test results
    monte_carlo_pi: float = 0.0
    longest_run: int = 0
    runs_test: float = 0.0
    spectral_test: float = 0.0
    autocorrelation: float = 0.0
    cumulative_sums_forward: float = 0.0
    cumulative_sums_reverse: float = 0.0
    
    # Advanced metrics
    entropy_rate: float = 0.0
    compression_ratio: float = 1.0
    predictive_entropy: float = 0.0
    health_score: float = 100.0
    timestamp: float = field(default_factory=time.time)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to a dictionary"""
        return {
            'min_entropy': self.min_entropy,
            'shannon_entropy': self.shannon_entropy,
            'chi_square': self.chi_square,
            'mean': self.mean,
            'variance': self.variance,
            'monte_carlo_pi': self.monte_carlo_pi,
            'longest_run': self.longest_run,
            'runs_test': self.runs_test,
            'spectral_test': self.spectral_test,
            'autocorrelation': self.autocorrelation,
            'cumulative_sums_forward': self.cumulative_sums_forward,
            'cumulative_sums_reverse': self.cumulative_sums_reverse,
            'entropy_rate': self.entropy_rate,
            'compression_ratio': self.compression_ratio,
            'predictive_entropy': self.predictive_entropy,
            'health_score': self.health_score,
            'timestamp': self.timestamp
        }

@dataclass
class EntropySample:
    """A sample of entropy data with metadata"""
    source: EntropySource
    data: bytes
    timestamp: float = field(default_factory=time.time)
    metrics: EntropyMetrics = field(default_factory=EntropyMetrics)

class AlertManager:
    """Manages alerts for entropy monitoring"""
    
    def __init__(self, rate_limit: float = 60.0):
        """
        Initialize the alert manager.
        
        Args:
            rate_limit: Minimum seconds between alerts of the same type
        """
        self.rate_limit = rate_limit
        self.last_alert: Dict[Tuple[EntropySource, str], float] = {}
        self.lock = threading.RLock()
    
    def should_alert(self, source: EntropySource, alert_type: str) -> bool:
        """Check if an alert should be raised based on rate limiting"""
        with self.lock:
            key = (source, alert_type)
            now = time.time()
            last_time = self.last_alert.get(key, 0)
            
            if now - last_time >= self.rate_limit:
                self.last_alert[key] = now
                return True
            return False


class EntropyMonitor:
    """Continuous entropy quality monitoring system"""
    
    def __init__(self, sample_interval: float = 1.0, window_size: int = 1000):
        """
        Initialize the entropy monitor.
        
        Args:
            sample_interval: Time between samples in seconds
            window_size: Number of samples to keep in memory for analysis
        """
        self.sample_interval = sample_interval
        self.window_size = window_size
        self.samples: Dict[EntropySource, deque[EntropySample]] = {
            source: deque(maxlen=window_size) for source in EntropySource
        }
        self.running = False
        self.monitor_thread: Optional[threading.Thread] = None
        self.lock = threading.RLock()
        self.callbacks: List[Callable[[EntropySource, EntropyHealthStatus, Dict[str, Any]], None]] = []
        
        # Initialize alert manager
        self.alert_manager = AlertManager(rate_limit=300)  # 5 minutes between alerts
        
        # Health thresholds (configurable)
        self.health_thresholds = {
            # Basic entropy thresholds
            'min_entropy': 0.8,  # Minimum acceptable min-entropy per bit (0-1)
            'shannon_entropy': 7.0,  # Minimum Shannon entropy (0-8)
            
            # Statistical test thresholds
            'chi_square': (0.01, 0.99),  # Acceptable chi-square p-value range
            'runs_test': 0.01,  # Minimum p-value for runs test
            'spectral_test': 0.01,  # Minimum p-value for spectral test
            'cumulative_sums': 0.01,  # Minimum p-value for cumulative sums tests
            
            # Advanced metrics
            'autocorrelation': (-0.1, 0.1),  # Acceptable autocorrelation range at lag 1
            'compression_ratio': 0.9,  # Minimum compression ratio (lower is better)
            'predictive_entropy': 0.7,  # Minimum predictive entropy ratio (0-1)
            
            # Source-specific adjustments
            'source_adjustments': {
                'HARDWARE_RNG': {
                    'min_entropy': 0.9,  # Higher standard for hardware RNG
                    'compression_ratio': 0.85
                },
                'TIMING': {
                    'min_entropy': 0.6,  # More lenient for timing sources
                    'runs_test': 0.001
                },
                'INTERRUPT': {
                    'min_entropy': 0.65,
                    'entropy_rate': 0.05
                },
                'DISK_ACTIVITY': {
                    'min_entropy': 0.7,
                    'compression_ratio': 0.88
                },
                'NETWORK_ACTIVITY': {
                    'min_entropy': 0.7,
                    'runs_test': 0.005
                }
            },
            
            # Trend analysis
            'trend_window': 60,  # Window size for trend analysis (samples)
            'max_entropy_drop': 0.2,  # Maximum allowed drop in entropy over trend window
            'min_entropy_rate': 0.1,  # Minimum entropy rate (bits/second)
            
            # Alert thresholds
            'critical_threshold': 40.0,  # Health score below this is CRITICAL
            'degraded_threshold': 70.0,  # Health score below this is DEGRADED
            'alert_cooldown': 300  # Seconds between alerts for the same issue
        }
        
        # Start the entropy accumulator
        start_accumulator()
    
    def start(self) -> None:
        """Start the entropy monitoring thread"""
        if self.running:
            return
            
        self.running = True
        self.monitor_thread = threading.Thread(
            target=self._monitor_loop,
            daemon=True,
            name="EntropyMonitor"
        )
        self.monitor_thread.start()
        logger.info("Entropy monitoring started")
    
    def stop(self) -> None:
        """Stop the entropy monitoring thread"""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2.0)
        logger.info("Entropy monitoring stopped")
    
    def _monitor_loop(self) -> None:
        """Main monitoring loop"""
        # Initialize hardware RNG
        hw_rng = get_hardware_rng()
        hw_status = hw_rng.get_status()
        logger.info(f"Available hardware RNG sources: {hw_status['available_sources']}")
        
        while self.running:
            try:
                # Collect from all sources
                self.collect_sample(EntropySource.SYSTEM_RANDOM, self._collect_system_random())
                self.collect_sample(EntropySource.OS_URANDOM, self._collect_os_urandom())

                # Only collect from hardware RNG if available
                if hw_status['available_sources']:
                    hw_data = self._collect_hardware_rng()
                    self.collect_sample(EntropySource.HARDWARE_RNG, hw_data)

                self.collect_sample(EntropySource.TIMING, self._collect_timing_entropy())
                self.collect_sample(EntropySource.INTERRUPT, self._collect_interrupt_entropy())
                self.collect_sample(EntropySource.DISK_ACTIVITY, self._collect_disk_entropy())
                self.collect_sample(EntropySource.NETWORK_ACTIVITY, self._collect_network_entropy())

                user_entropy = self._collect_user_input_entropy()
                if user_entropy:
                    self.collect_sample(EntropySource.USER_INPUT, user_entropy)

                # Log hardware RNG status periodically
                if self.running and len(self.samples[EntropySource.HARDWARE_RNG]) % 10 == 0:
                    hw_status = hw_rng.get_status()
                    logger.debug(f"Hardware RNG status: {hw_status}")
                
                # Sleep for the sample interval
                time.sleep(self.sample_interval)
                
            except Exception as e:
                logger.error(f"Error in monitor loop: {e}", exc_info=True)
                time.sleep(1)  # Prevent tight loop on error
                
    def collect_sample(self, source: EntropySource, data: bytes) -> EntropySample:
        """
        Collect and analyze a sample from an entropy source.
        
        Args:
            source: The entropy source
            data: Raw entropy data
            
        Returns:
            Analyzed entropy sample
        """
        # Convert to secure bytes to prevent swapping
        secure_data = SecureBytes(data)
        try:
            # Calculate metrics
            metrics = self._calculate_metrics(secure_data)
            
            # Create and store sample
            sample = EntropySample(
                source=source,
                data=bytes(secure_data),  # Create a copy for storage
                metrics=metrics
            )
            
            with self.lock:
                self.samples[source].append(sample)
                
                # Add entropy to the accumulator
                estimated_bits = metrics.min_entropy * len(data) * 8  # Convert to bits
                entropy_accumulator.add_entropy(data, source.value, estimated_bits)
                
                logger.debug(f"Added {len(data)} bytes to entropy pool from {source.name} "
                           f"(est. {estimated_bits:.2f} bits)")
            
            # Check if health status changed and notify
            health_status = self.assess_health(source)
            if len(self.samples[source]) > 1:
                prev_health = self.assess_health(source, lookback=2)
                if health_status != prev_health:
                    self._notify_health_change(source, health_status)
            
            return sample
            
        finally:
            # Securely erase the temporary secure data
            secure_data.zero()
    
    def _calculate_autocorrelation(self, arr: np.ndarray, lag: int = 1) -> float:
        """Calculate autocorrelation at given lag"""
        if len(arr) <= lag:
            return 0.0
        x = arr[lag:] - np.mean(arr)
        y = arr[:-lag] - np.mean(arr)
        return float(np.sum(x * y) / (np.sum(x**2) * np.sum(y**2))**0.5)

    def _cumulative_sums_test(self, bits: np.ndarray) -> Tuple[float, float]:
        """Perform the NIST cumulative sums test in forward and reverse directions."""

        def _direction_test(bit_sequence: np.ndarray) -> float:
            if bit_sequence.size == 0:
                return 0.0

            converted = 2 * bit_sequence.astype(np.int32) - 1
            partial_sums = np.cumsum(converted)
            z = float(np.max(np.abs(partial_sums)))

            if z == 0.0:
                return 1.0

            n = bit_sequence.size
            sqrt_n = math.sqrt(n)
            denominator = sqrt_n * math.sqrt(2.0)

            def _summation(start: float, end: float, offset: int) -> float:
                first = int(math.ceil(start))
                last = int(math.floor(end))
                if last < first:
                    return 0.0
                total = 0.0
                for k in range(first, last + 1):
                    total += math.erfc((4 * k + offset) * z / denominator)
                return total

            start1 = (-n / z + 1.0) / 4.0
            end1 = (n / z - 1.0) / 4.0
            sum1 = _summation(start1, end1, 1)

            start2 = (-n / z - 3.0) / 4.0
            end2 = (n / z - 1.0) / 4.0
            sum2 = _summation(start2, end2, 3)

            p_value = 1.0 - sum1 + sum2
            return max(0.0, min(1.0, p_value))

        forward = _direction_test(bits)
        reverse = _direction_test(bits[::-1])
        return forward, reverse
    
    def _estimate_compression_ratio(self, data: bytes) -> float:
        """Estimate compression ratio using zlib"""
        try:
            import zlib
            compressed = zlib.compress(data, level=zlib.Z_BEST_COMPRESSION)
            return len(compressed) / len(data) if data else 1.0
        except Exception:
            return 1.0
    
    def _calculate_predictive_entropy(self, data: bytes, context_size: int = 4) -> float:
        """Calculate predictive entropy with context modeling"""
        if len(data) <= context_size + 1:
            return 0.0
            
        # Count n-gram frequencies
        counts = {}
        total = 0
        
        for i in range(len(data) - context_size):
            context = tuple(data[i:i+context_size])
            next_byte = data[i+context_size]
            
            if context not in counts:
                counts[context] = [0] * 256
            counts[context][next_byte] += 1
            total += 1
        
        # Calculate conditional entropy
        conditional_entropy = 0.0
        
        for context in counts:
            context_count = sum(counts[context])
            context_prob = context_count / total
            
            # Calculate entropy of next byte given context
            h = 0.0
            for count in counts[context]:
                if count > 0:
                    p = count / context_count
                    h -= p * math.log2(p)
            
            conditional_entropy += context_prob * h
        
        return conditional_entropy
    
    def _calculate_entropy_rate(self, source: EntropySource, new_entropy: float) -> float:
        """Calculate entropy rate in bits per second"""
        with self.lock:
            samples = list(self.samples[source])
        
        if not samples:
            return 0.0
            
        # Get timestamps of recent samples
        timestamps = [s.timestamp for s in samples[-self.health_thresholds['trend_window']:]]
        timestamps.append(time.time())
        
        # Calculate time differences in seconds
        time_diffs = np.diff(timestamps)
        if np.any(time_diffs <= 0):
            return 0.0
            
        # Calculate entropy per second
        entropy_per_second = new_entropy / np.mean(time_diffs)
        return float(entropy_per_second)
    
    def _calculate_metrics(self, data: bytes) -> EntropyMetrics:
        """
        Calculate comprehensive entropy quality metrics for the given data.
        
        Args:
            data: Raw entropy data to analyze
            
        Returns:
            EntropyMetrics object containing calculated metrics
        """
        if not data:
            return EntropyMetrics()
            
        # Convert to numpy array of bytes for analysis
        arr = np.frombuffer(data, dtype=np.uint8)
        n = len(arr)
        
        if n == 0:
            return EntropyMetrics()
        
        # Initialize metrics
        metrics = EntropyMetrics()
        
        # Basic statistics
        metrics.mean = float(np.mean(arr))
        metrics.variance = float(np.var(arr))
        
        # Calculate min-entropy
        value_counts = np.bincount(arr, minlength=256)
        max_prob = np.max(value_counts) / n
        metrics.min_entropy = -math.log2(max_prob) if max_prob > 0 else 0
        
        # Calculate Shannon entropy
        probs = value_counts / n
        shannon = -np.sum(p * math.log2(p) for p in probs if p > 0)
        metrics.shannon_entropy = float(shannon)
        
        # Chi-square test
        expected = n / 256
        chi_square = np.sum((value_counts - expected) ** 2 / expected)
        metrics.chi_square = float(chi_square)
        
        bits = np.unpackbits(arr) if n > 0 else np.array([], dtype=np.uint8)

        # Runs test (Wald-Wolfowitz)
        if n > 1:
            diffs = np.diff(arr)
            runs = np.sum(diffs != 0) + 1
            expected_runs = (2 * n - 1) / 3
            var_runs = (16 * n - 29) / 90
            z = (runs - expected_runs) / math.sqrt(var_runs)
            metrics.runs_test = float(2 * (1 - 0.5 * (1 + math.erf(abs(z) / math.sqrt(2.0)))))

            # Calculate longest run of identical bits
            if len(bits) > 0:
                diffs = np.diff(bits, prepend=1-bits[0])
                run_starts = np.where(diffs != 0)[0]
                run_lengths = np.diff(np.append(run_starts, len(bits)))
                metrics.longest_run = int(np.max(run_lengths) if len(run_lengths) > 0 else 0)

        # Spectral test (simplified)
        if n > 1:
            fft = np.fft.fft(arr - metrics.mean)
            spectral = np.mean(np.abs(fft[1:n//2]) ** 2)
            metrics.spectral_test = float(spectral)

        if bits.size > 0:
            forward_p, reverse_p = self._cumulative_sums_test(bits)
            metrics.cumulative_sums_forward = forward_p
            metrics.cumulative_sums_reverse = reverse_p
        
        # Autocorrelation at lag 1
        if n > 1:
            metrics.autocorrelation = self._calculate_autocorrelation(arr, lag=1)
        
        # Compression ratio
        metrics.compression_ratio = self._estimate_compression_ratio(data)
        
        # Predictive entropy (context-based)
        if n >= 8:  # Need enough data for meaningful context
            metrics.predictive_entropy = self._calculate_predictive_entropy(data)
        
        # Calculate health score (0-100)
        metrics.health_score = self._calculate_health_score(metrics)
        
        return metrics
    
    def _calculate_health_score(self, metrics: EntropyMetrics) -> float:
        """Calculate a composite health score (0-100) based on multiple metrics"""
        score = 100.0
        
        # Penalize low min-entropy
        min_entropy_penalty = max(0, 0.8 - metrics.min_entropy) * 50
        score -= min_entropy_penalty
        
        # Penalize high autocorrelation
        autocorr_penalty = min(20, abs(metrics.autocorrelation) * 200)
        score -= autocorr_penalty
        
        # Penalize high compression ratio
        if metrics.compression_ratio > 0.9:
            compression_penalty = (metrics.compression_ratio - 0.9) * 100
            score -= compression_penalty
        
        # Penalize low predictive entropy ratio
        if metrics.shannon_entropy > 0:
            predictive_penalty = (1 - metrics.predictive_entropy) * 20
            score -= predictive_penalty

        cumulative_threshold = self.health_thresholds.get('cumulative_sums', 0.01)
        if metrics.cumulative_sums_forward < cumulative_threshold:
            score -= (cumulative_threshold - metrics.cumulative_sums_forward) * 200
        if metrics.cumulative_sums_reverse < cumulative_threshold:
            score -= (cumulative_threshold - metrics.cumulative_sums_reverse) * 200

        # Ensure score is within bounds
        score = max(0, min(100, score))
        return score
        
    def add_health_callback(self, callback: Callable[[EntropySource, EntropyHealthStatus, Dict[str, Any]], None]) -> None:
        """Add a callback for health status changes"""
        with self.lock:
            self.callbacks.append(callback)
    
    def _notify_health_change(self, source: EntropySource, status: EntropyHealthStatus) -> None:
        """Notify all registered callbacks of a health status change"""
        with self.lock:
            for callback in self.callbacks:
                try:
                    callback(source, status)
                except Exception as e:
                    logger.error(f"Error in health callback: {e}", exc_info=True)
    
    # Entropy collection methods
    def _collect_os_urandom(self, size: int = 1024) -> bytes:
        """Collect entropy from os.urandom()"""
        try:
            return os.urandom(size)
        except Exception as e:
            logger.error(f"Failed to collect entropy from os.urandom: {e}")
            return b''
    
    def _collect_system_random(self, size: int = 1024) -> bytes:
        """Collect entropy from system random source"""
        try:
            import random
            return bytes(random.SystemRandom().randrange(256) for _ in range(size))
        except Exception as e:
            logger.error(f"Failed to collect entropy from system random: {e}")
            return b''

    def _collect_timing_entropy(self, samples: int = 1000) -> bytes:
        """Collect entropy from timing variations

        Args:
            samples: Number of timing samples to collect
            
        Returns:
            Bytes containing timing-based entropy
        """
        timings = bytearray()
        for _ in range(samples):
            try:
                start = time.perf_counter()
                # Perform some work that might have variable timing
                _ = [i * i for i in range(1000)]
                end = time.perf_counter()
                # Use nanosecond precision, take LSB
                timing = int((end - start) * 1e9) & 0xFF
                timings.append(timing)
            except Exception as e:
                logger.warning(f"Error collecting timing entropy: {e}")
                continue
                
        if not timings:
            logger.warning("No timing entropy collected")
            return b'\x00'  # Return minimal entropy if collection failed

        return bytes(timings)

    def _collect_hardware_rng(self, size: int = 1024) -> bytes:
        """
        Collect entropy from hardware RNG if available
        
        Args:
            size: Number of bytes to collect
                
        Returns:
            Bytes from hardware RNG or fallback to os.urandom()
        """
        try:
            # Get hardware RNG data
            hw_data = get_hardware_random_bytes(size)
            if hw_data is not None and len(hw_data) == size:
                # Add to entropy accumulator
                entropy_accumulator.add_entropy(
                    hw_data, 
                    source=EntropySource.HARDWARE_RNG.value,
                    estimated_bits=size * 8 * 0.9  # Assume high quality entropy
                )
                return hw_data
            
            # Fallback to os.urandom() if hardware RNG fails
            fallback = os.urandom(size)
            logger.warning("Hardware RNG unavailable, falling back to os.urandom")
            return fallback
            
        except Exception as e:
            logger.error(f"Error reading from hardware RNG: {e}")
            return os.urandom(size)

    def _collect_interrupt_entropy(self, size: int = 512) -> bytes:
        """Collect entropy from kernel interrupt statistics"""
        path = Path('/proc/interrupts')
        if not path.exists():
            logger.debug("/proc/interrupts not available, synthesizing interrupt entropy")
            return self._synthesize_entropy_marker('interrupts', size)

        try:
            snapshot = path.read_bytes()
            timestamp = time.time_ns().to_bytes(8, 'little', signed=False)
            mixed = hashlib.sha512(snapshot + timestamp).digest()
            entropy_accumulator.add_entropy(
                mixed,
                source=EntropySource.INTERRUPT.value,
                estimated_bits=len(mixed) * 6.5,
            )
            return (mixed * ((size // len(mixed)) + 1))[:size]
        except Exception as exc:
            logger.warning(f"Failed to collect interrupt entropy: {exc}")
            return self._synthesize_entropy_marker('interrupts', size)

    def _collect_disk_entropy(self, size: int = 512) -> bytes:
        """Collect entropy from disk statistics and jitter"""
        path = Path('/proc/diskstats')
        if not path.exists():
            return self._synthesize_entropy_marker('disk', size)

        try:
            snapshot = path.read_bytes()
            jitter = time.perf_counter_ns().to_bytes(8, 'little', signed=False)
            pid_bytes = os.getpid().to_bytes(4, 'little', signed=False)
            mixed = hashlib.blake2b(snapshot + jitter + pid_bytes, digest_size=64).digest()
            entropy_accumulator.add_entropy(
                mixed,
                source=EntropySource.DISK_ACTIVITY.value,
                estimated_bits=len(mixed) * 6.0,
            )
            return (mixed * ((size // len(mixed)) + 1))[:size]
        except Exception as exc:
            logger.warning(f"Failed to collect disk entropy: {exc}")
            return self._synthesize_entropy_marker('disk', size)

    def _collect_network_entropy(self, size: int = 512) -> bytes:
        """Collect entropy from network device counters"""
        path = Path('/proc/net/dev')
        if not path.exists():
            return self._synthesize_entropy_marker('network', size)

        try:
            snapshot = path.read_bytes()
            monotonic = time.monotonic_ns().to_bytes(8, 'little', signed=False)
            tid = threading.get_ident().to_bytes(8, 'little', signed=False)
            mixed = hashlib.sha3_512(snapshot + monotonic + tid).digest()
            entropy_accumulator.add_entropy(
                mixed,
                source=EntropySource.NETWORK_ACTIVITY.value,
                estimated_bits=len(mixed) * 5.8,
            )
            return (mixed * ((size // len(mixed)) + 1))[:size]
        except Exception as exc:
            logger.warning(f"Failed to collect network entropy: {exc}")
            return self._synthesize_entropy_marker('network', size)

    def _collect_user_input_entropy(self, size: int = 256) -> bytes:
        """Collect entropy from cached user input timing artifacts"""
        cache_path = Path.home() / '.secure_vault' / 'user_input_entropy.bin'
        try:
            if cache_path.exists():
                data = cache_path.read_bytes()
                trimmed = data[-size:]
            else:
                trimmed = b''

            if not trimmed:
                # Derive entropy from recent timing jitter as a fallback
                jitter = time.perf_counter_ns()
                trimmed = jitter.to_bytes(16, 'little', signed=False) + os.urandom(size - 16)

            salt = hashlib.sha3_256(os.urandom(32)).digest()
            hashed = hashlib.pbkdf2_hmac('sha256', trimmed, salt, 1000, dklen=size)
            entropy_accumulator.add_entropy(
                hashed,
                source=EntropySource.USER_INPUT.value,
                estimated_bits=len(hashed) * 5.5,
            )
            return hashed
        except Exception as exc:
            logger.debug(f"User input entropy fallback engaged: {exc}")
            return self._synthesize_entropy_marker('user', size)

    def _synthesize_entropy_marker(self, label: str, size: int) -> bytes:
        """Synthesize entropy when the real source is unavailable"""
        seed_material = (
            f"{label}:{time.time_ns()}:{os.getpid()}:{threading.get_ident()}".encode('utf-8')
        )
        digest = hashlib.blake2b(seed_material, digest_size=64).digest()
        expanded = digest * ((size // len(digest)) + 1)
        return expanded[:size]

    def _collect_user_input(self, prompt: str = "Random input: ") -> bytes:
        """Collect entropy from user input

        Args:
            prompt: Prompt to show the user
                
        Returns:
            Bytes containing user input
        """
        try:
            # Only import getpass if needed
            import getpass
                
            # Get input without echo
            user_input = getpass.getpass(prompt)
                
            # Hash the input to ensure consistent output size
            import hashlib
            return hashlib.sha256(user_input.encode()).digest()
                
        except Exception as e:
            logger.error(f"Error collecting user input: {e}")
            return b''

# Global instance for easy access
entropy_monitor = EntropyMonitor()

def start_monitoring() -> None:
    """Start the global entropy monitor"""
    entropy_monitor.start()

def stop_monitoring() -> None:
    """Stop the global entropy monitor and accumulator"""
    entropy_monitor.stop()
    stop_accumulator()

def get_entropy_metrics(source: EntropySource) -> Optional[EntropyMetrics]:
    """Get the latest metrics for an entropy source"""
    if not entropy_monitor.samples[source]:
        return None
    return entropy_monitor.samples[source][-1].metrics

def get_health_status(source: EntropySource) -> EntropyHealthStatus:
    """Get the current health status of an entropy source"""
    return entropy_monitor.assess_health(source)


def benchmark_entropy_sources(samples: int = 32, sample_size: int = 256) -> Dict[str, Dict[str, float]]:
    """Benchmark all entropy sources and return aggregated metrics."""

    results: Dict[str, Dict[str, float]] = {}

    def _collect_for_source(source: EntropySource) -> bytes:
        if source == EntropySource.SYSTEM_RANDOM:
            return entropy_monitor._collect_system_random(sample_size)
        if source == EntropySource.OS_URANDOM:
            return entropy_monitor._collect_os_urandom(sample_size)
        if source == EntropySource.HARDWARE_RNG:
            return entropy_monitor._collect_hardware_rng(sample_size)
        if source == EntropySource.TIMING:
            return entropy_monitor._collect_timing_entropy(min(sample_size * 2, 4096))
        if source == EntropySource.USER_INPUT:
            return entropy_monitor._collect_user_input_entropy(sample_size)
        if source == EntropySource.INTERRUPT:
            return entropy_monitor._collect_interrupt_entropy(sample_size)
        if source == EntropySource.DISK_ACTIVITY:
            return entropy_monitor._collect_disk_entropy(sample_size)
        if source == EntropySource.NETWORK_ACTIVITY:
            return entropy_monitor._collect_network_entropy(sample_size)
        raise ValueError(f"Unsupported entropy source: {source}")

    for source in EntropySource:
        metrics: List[EntropyMetrics] = []
        durations: List[float] = []

        for _ in range(samples):
            start = time.perf_counter()
            raw = _collect_for_source(source)
            durations.append(time.perf_counter() - start)

            secure_sample = SecureBytes(raw)
            try:
                metric = entropy_monitor._calculate_metrics(bytes(secure_sample))
                metrics.append(metric)
            finally:
                secure_free(secure_sample)

        if not metrics:
            continue

        avg_min_entropy = sum(m.min_entropy for m in metrics) / len(metrics)
        avg_shannon_entropy = sum(m.shannon_entropy for m in metrics) / len(metrics)
        avg_health = sum(m.health_score for m in metrics) / len(metrics)
        avg_rate = sum(m.entropy_rate for m in metrics) / len(metrics)
        total_time = sum(durations) or 1e-9
        throughput = (len(metrics) * sample_size) / total_time

        results[source.name] = {
            'average_min_entropy': avg_min_entropy,
            'average_shannon_entropy': avg_shannon_entropy,
            'average_health_score': avg_health,
            'average_entropy_rate': avg_rate,
            'throughput_bytes_per_second': throughput,
            'samples': float(len(metrics)),
        }

    return results

# Register cleanup on exit
import atexit
atexit.register(stop_monitoring)
