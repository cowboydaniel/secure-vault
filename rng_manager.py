"""
Streamlined 512-bit Multi-Layer Encryption System
Hardware Random Number Generator Management

This module manages hardware entropy sources for the One-Time Pad layer,
ensuring maximum entropy quality for information-theoretic security.
"""

import os
import time
import threading
import struct
from typing import Optional, List, Dict, Tuple, Union
from dataclasses import dataclass
from enum import Enum
import logging
import statistics

from crypto_utils import validate_entropy_quality, compute_sha3_512
from config import SECURITY_LEVEL_BYTES

logger = logging.getLogger(__name__)

class EntropySourceType(Enum):
    """Types of entropy sources"""
    HARDWARE_RNG = "hardware_rng"      # Dedicated hardware RNG
    THERMAL_NOISE = "thermal_noise"    # CPU thermal noise
    TIMING_JITTER = "timing_jitter"    # System timing variations
    DISK_SEEK = "disk_seek"           # Hard disk seek timing
    NETWORK_TIMING = "network_timing"  # Network packet timing
    MOUSE_MOVEMENT = "mouse_movement"  # Mouse movement entropy
    KEYBOARD_TIMING = "keyboard_timing" # Keystroke timing
    MIXED_SOURCES = "mixed_sources"    # Combined entropy

@dataclass
class EntropySource:
    """Information about an entropy source"""
    name: str
    source_type: EntropySourceType
    device_path: Optional[str]
    available: bool
    quality_score: float  # 0.0 to 10.0
    read_speed_bps: int   # Bytes per second
    last_test_time: float
    total_bytes_read: int = 0
    failure_count: int = 0

class HardwareRNGManager:
    """
    Manager for hardware random number generators and entropy sources.
    
    Detects, tests, and manages multiple entropy sources to ensure
    maximum entropy quality for One-Time Pad operations.
    """
    
    def __init__(self):
        self.entropy_sources: List[EntropySource] = []
        self.primary_source: Optional[EntropySource] = None
        self.backup_sources: List[EntropySource] = []
        
        # Thread safety
        self._lock = threading.RLock()
        
        # Quality monitoring
        self._quality_history: Dict[str, List[float]] = {}
        self._monitoring_active = False
        self._monitor_thread: Optional[threading.Thread] = None
        
        # Initialize sources
        self._detect_entropy_sources()
        self._select_best_sources()
        self._start_quality_monitoring()
        
        logger.info(f"Hardware RNG Manager initialized with {len(self.entropy_sources)} sources")
    
    def _detect_entropy_sources(self):
        """Detect all available entropy sources"""
        logger.info("Detecting hardware entropy sources...")
        
        # Hardware RNG devices
        self._detect_hardware_rngs()
        
        # System entropy sources
        self._detect_system_sources()
        
        # Test all detected sources
        self._test_all_sources()
    
    def _detect_hardware_rngs(self):
        """Detect dedicated hardware RNG devices"""
        hardware_devices = [
            ("/dev/hwrng", "Hardware RNG"),
            ("/dev/truerng", "TrueRNG Device"),
            ("/dev/ttyUSB0", "USB RNG Device"),
            ("/dev/ttyACM0", "Arduino RNG"),
            ("/dev/random", "System Hardware RNG"),
        ]
        
        for device_path, name in hardware_devices:
            if os.path.exists(device_path):
                try:
                    # Test read access
                    with open(device_path, 'rb') as f:
                        test_data = f.read(64)
                        if len(test_data) > 0:
                            source = EntropySource(
                                name=name,
                                source_type=EntropySourceType.HARDWARE_RNG,
                                device_path=device_path,
                                available=True,
                                quality_score=0.0,  # Will be tested
                                read_speed_bps=0,   # Will be measured
                                last_test_time=0.0
                            )
                            self.entropy_sources.append(source)
                            logger.info(f"Detected hardware RNG: {name} at {device_path}")
                
                except (PermissionError, OSError) as e:
                    logger.warning(f"Cannot access {device_path}: {e}")
    
    def _detect_system_sources(self):
        """Detect system-based entropy sources"""
        # System urandom (always available)
        urandom_source = EntropySource(
            name="System urandom",
            source_type=EntropySourceType.MIXED_SOURCES,
            device_path="/dev/urandom",
            available=True,
            quality_score=7.0,  # Good baseline
            read_speed_bps=100000000,  # Very fast
            last_test_time=time.time()
        )
        self.entropy_sources.append(urandom_source)
        
        # CPU thermal noise (if available)
        if self._can_read_cpu_thermal():
            thermal_source = EntropySource(
                name="CPU Thermal Noise",
                source_type=EntropySourceType.THERMAL_NOISE,
                device_path=None,
                available=True,
                quality_score=0.0,  # Will be tested
                read_speed_bps=1000,  # Slower
                last_test_time=0.0
            )
            self.entropy_sources.append(thermal_source)
    
    def _can_read_cpu_thermal(self) -> bool:
        """Check if CPU thermal sensors are accessible"""
        thermal_paths = [
            "/sys/class/thermal/thermal_zone0/temp",
            "/sys/class/hwmon/hwmon0/temp1_input",
        ]
        
        for path in thermal_paths:
            if os.path.exists(path):
                try:
                    with open(path, 'r') as f:
                        f.read().strip()
                        return True
                except Exception:
                    continue
        
        return False
    
    def _test_all_sources(self):
        """Test quality and performance of all detected sources"""
        logger.info("Testing entropy source quality...")
        
        for source in self.entropy_sources:
            self._test_entropy_source(source)
    
    def _test_entropy_source(self, source: EntropySource):
        """Test a single entropy source"""
        try:
            # Measure read speed
            start_time = time.time()
            test_data = self._read_from_source(source, 4096)  # 4KB test
            read_time = time.time() - start_time
            
            if len(test_data) > 0:
                source.read_speed_bps = int(len(test_data) / max(read_time, 0.001))
                
                # Test entropy quality
                is_valid, metrics = validate_entropy_quality(test_data)
                entropy_score = metrics.get('entropy_per_byte', 0.0)
                
                # Calculate quality score (0-10)
                quality_score = min(10.0, entropy_score * 1.25)  # Scale 8.0 entropy to 10.0 quality
                
                # Bonus points for hardware sources
                if source.source_type == EntropySourceType.HARDWARE_RNG:
                    quality_score += 1.0
                
                source.quality_score = min(10.0, quality_score)
                source.last_test_time = time.time()
                source.available = True
                
                logger.info(f"Source '{source.name}': Quality={source.quality_score:.1f}/10, "
                           f"Speed={source.read_speed_bps:,} B/s, Entropy={entropy_score:.2f}")
            
            else:
                source.available = False
                source.failure_count += 1
                logger.warning(f"Source '{source.name}' failed to provide data")
        
        except Exception as e:
            source.available = False
            source.failure_count += 1
            logger.error(f"Error testing source '{source.name}': {e}")
    
    def _read_from_source(self, source: EntropySource, length: int) -> bytes:
        """Read entropy from a specific source"""
        if source.source_type == EntropySourceType.HARDWARE_RNG:
            return self._read_hardware_rng(source, length)
        elif source.source_type == EntropySourceType.THERMAL_NOISE:
            return self._read_thermal_noise(length)
        elif source.source_type == EntropySourceType.MIXED_SOURCES:
            return self._read_system_urandom(length)
        else:
            raise ValueError(f"Unsupported source type: {source.source_type}")
    
    def _read_hardware_rng(self, source: EntropySource, length: int) -> bytes:
        """Read from hardware RNG device"""
        if not source.device_path:
            raise ValueError("No device path for hardware RNG")
        
        with open(source.device_path, 'rb') as f:
            data = f.read(length)
            source.total_bytes_read += len(data)
            return data
    
    def _read_thermal_noise(self, length: int) -> bytes:
        """Read CPU thermal noise for entropy"""
        entropy_data = bytearray()
        
        thermal_paths = [
            "/sys/class/thermal/thermal_zone0/temp",
            "/sys/class/hwmon/hwmon0/temp1_input",
        ]
        
        # Collect thermal readings over time
        readings = []
        for _ in range(length * 2):  # Need more readings than output bytes
            for path in thermal_paths:
                try:
                    with open(path, 'r') as f:
                        temp = int(f.read().strip())
                        readings.append(temp)
                        time.sleep(0.001)  # 1ms delay
                except Exception:
                    continue
        
        # Convert thermal readings to entropy
        for i in range(0, len(readings) - 1, 2):
            if i + 1 < len(readings):
                # Use LSBs of temperature differences
                diff = readings[i] ^ readings[i + 1]
                entropy_data.append(diff & 0xFF)
                
                if len(entropy_data) >= length:
                    break
        
        return bytes(entropy_data[:length])
    
    def _read_system_urandom(self, length: int) -> bytes:
        """Read from system urandom"""
        return os.urandom(length)
    
    def _select_best_sources(self):
        """Select primary and backup entropy sources"""
        with self._lock:
            # Sort sources by quality score
            available_sources = [s for s in self.entropy_sources if s.available]
            available_sources.sort(key=lambda s: s.quality_score, reverse=True)
            
            if available_sources:
                self.primary_source = available_sources[0]
                self.backup_sources = available_sources[1:3]  # Top 2 backups
                
                logger.info(f"Primary entropy source: {self.primary_source.name} "
                           f"(Quality: {self.primary_source.quality_score:.1f}/10)")
                
                for i, backup in enumerate(self.backup_sources):
                    logger.info(f"Backup source {i+1}: {backup.name} "
                               f"(Quality: {backup.quality_score:.1f}/10)")
            else:
                logger.error("No available entropy sources!")
    
    def _start_quality_monitoring(self):
        """Start background quality monitoring"""
        self._monitoring_active = True
        self._monitor_thread = threading.Thread(
            target=self._quality_monitor_loop,
            daemon=True
        )
        self._monitor_thread.start()
        logger.info("Entropy quality monitoring started")
    
    def _quality_monitor_loop(self):
        """Background loop to monitor entropy quality"""
        while self._monitoring_active:
            try:
                # Test primary source
                if self.primary_source and self.primary_source.available:
                    test_data = self._read_from_source(self.primary_source, 1024)
                    is_valid, metrics = validate_entropy_quality(test_data)
                    
                    entropy_score = metrics.get('entropy_per_byte', 0.0)
                    
                    # Update quality history
                    source_name = self.primary_source.name
                    if source_name not in self._quality_history:
                        self._quality_history[source_name] = []
                    
                    self._quality_history[source_name].append(entropy_score)
                    
                    # Keep only recent history
                    if len(self._quality_history[source_name]) > 100:
                        self._quality_history[source_name] = self._quality_history[source_name][-100:]
                    
                    # Check for quality degradation
                    if len(self._quality_history[source_name]) >= 10:
                        recent_avg = statistics.mean(self._quality_history[source_name][-10:])
                        if recent_avg < 6.0:  # Below acceptable threshold
                            logger.warning(f"Entropy quality degradation detected: {recent_avg:.2f}")
                            self._select_best_sources()  # Reselect sources
                
                time.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                logger.error(f"Quality monitoring error: {e}")
                time.sleep(60)  # Wait longer on error
    
    def get_entropy(self, length: int, min_quality: float = 7.0) -> bytes:
        """
        Get high-quality entropy for cryptographic use.
        
        Args:
            length: Number of bytes needed
            min_quality: Minimum quality score required
            
        Returns:
            High-quality random bytes
        """
        if length <= 0:
            raise ValueError("Length must be positive")
        
        with self._lock:
            # Try primary source first
            if (self.primary_source and 
                self.primary_source.available and 
                self.primary_source.quality_score >= min_quality):
                
                try:
                    data = self._read_from_source(self.primary_source, length)
                    if len(data) == length:
                        return data
                except Exception as e:
                    logger.warning(f"Primary source failed: {e}")
                    self.primary_source.failure_count += 1
            
            # Try backup sources
            for backup in self.backup_sources:
                if (backup.available and 
                    backup.quality_score >= min_quality):
                    
                    try:
                        data = self._read_from_source(backup, length)
                        if len(data) == length:
                            logger.info(f"Using backup source: {backup.name}")
                            return data
                    except Exception as e:
                        logger.warning(f"Backup source {backup.name} failed: {e}")
                        backup.failure_count += 1
            
            # Last resort: use system urandom with entropy mixing
            logger.warning("All high-quality sources failed, using enhanced system entropy")
            return self._generate_mixed_entropy(length)
    
    def _generate_mixed_entropy(self, length: int) -> bytes:
        """Generate entropy by mixing multiple sources"""
        entropy_chunks = []
        
        # System urandom
        entropy_chunks.append(os.urandom(length))
        
        # High-resolution timing
        timing_entropy = bytearray()
        for _ in range(length):
            start = time.perf_counter_ns()
            time.sleep(0.00001)  # 10 microseconds
            end = time.perf_counter_ns()
            timing_entropy.append((end - start) & 0xFF)
        entropy_chunks.append(bytes(timing_entropy))
        
        # Process and system state
        state_data = struct.pack('>QII', 
                                time.time_ns(), 
                                os.getpid(), 
                                hash(threading.current_thread()) & 0xFFFFFFFF)
        entropy_chunks.append(state_data * (length // len(state_data) + 1))
        
        # Mix all entropy sources
        mixed = bytearray(length)
        for chunk in entropy_chunks:
            for i in range(length):
                mixed[i] ^= chunk[i % len(chunk)]
        
        # Final hash for uniform distribution
        final_entropy = compute_sha3_512(bytes(mixed))
        
        # Expand if needed
        if length <= 64:
            return final_entropy[:length]
        else:
            # Use HKDF-like expansion
            from crypto_utils import expand_key_material
            return expand_key_material(final_entropy, length)
    
    def get_source_status(self) -> Dict:
        """Get status of all entropy sources"""
        with self._lock:
            return {
                "primary_source": {
                    "name": self.primary_source.name if self.primary_source else None,
                    "quality": self.primary_source.quality_score if self.primary_source else 0,
                    "speed_bps": self.primary_source.read_speed_bps if self.primary_source else 0,
                    "total_read": self.primary_source.total_bytes_read if self.primary_source else 0,
                    "failures": self.primary_source.failure_count if self.primary_source else 0
                },
                "backup_sources": [
                    {
                        "name": source.name,
                        "quality": source.quality_score,
                        "speed_bps": source.read_speed_bps,
                        "available": source.available
                    }
                    for source in self.backup_sources
                ],
                "total_sources": len(self.entropy_sources),
                "available_sources": len([s for s in self.entropy_sources if s.available]),
                "quality_history_length": sum(len(h) for h in self._quality_history.values())
            }
    
    def shutdown(self):
        """Shutdown the RNG manager"""
        self._monitoring_active = False
        
        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=5)
        
        logger.info("Hardware RNG Manager shutdown complete")

# Global RNG manager instance
_rng_manager = None

def get_rng_manager() -> HardwareRNGManager:
    """Get the global RNG manager instance"""
    global _rng_manager
    if _rng_manager is None:
        _rng_manager = HardwareRNGManager()
    return _rng_manager

def get_high_quality_entropy(length: int) -> bytes:
    """Convenience function to get high-quality entropy"""
    return get_rng_manager().get_entropy(length)

if __name__ == "__main__":
    # Demonstrate RNG manager
    print("Hardware RNG Manager Demo")
    print("=" * 30)
    
    # Initialize manager
    rng_mgr = HardwareRNGManager()
    
    # Show source status
    status = rng_mgr.get_source_status()
    print(f"Primary source: {status['primary_source']['name']}")
    print(f"Quality: {status['primary_source']['quality']:.1f}/10")
    print(f"Speed: {status['primary_source']['speed_bps']:,} B/s")
    print(f"Available sources: {status['available_sources']}/{status['total_sources']}")
    
    # Generate test entropy
    print(f"\nGenerating 512-bit entropy...")
    entropy = rng_mgr.get_entropy(64)  # 512 bits
    print(f"Entropy: {entropy[:16].hex()}...")
    
    # Test entropy quality
    from crypto_utils import validate_entropy_quality
    is_valid, metrics = validate_entropy_quality(entropy)
    print(f"Entropy quality: {metrics['entropy_per_byte']:.2f} bits/byte")
    print(f"Valid for crypto: {is_valid}")
    
    # Performance test
    print(f"\nPerformance test...")
    start_time = time.time()
    total_bytes = 0
    
    for _ in range(100):
        test_entropy = rng_mgr.get_entropy(1024)  # 1KB per iteration
        total_bytes += len(test_entropy)
    
    elapsed = time.time() - start_time
    throughput = (total_bytes / 1024) / elapsed
    
    print(f"Generated {total_bytes:,} bytes in {elapsed:.3f}s ({throughput:.1f} KB/s)")
    
    # Cleanup
    rng_mgr.shutdown()
    print(f"\nHardware RNG Manager ready for One-Time Pad operations!")