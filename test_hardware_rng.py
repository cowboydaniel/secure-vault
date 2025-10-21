#!/usr/bin/env python3
"""
Test script for hardware RNG integration
"""

import time
import logging
import numpy as np
from typing import List, Dict, Any
from entropy_monitor import EntropySource, start_monitoring, stop_monitoring, entropy_monitor
from hardware_rng import get_hardware_rng, get_hardware_random_bytes

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def test_hardware_rng_detection():
    """Test if hardware RNG is detected correctly"""
    print("\n=== Testing Hardware RNG Detection ===")
    hw_rng = get_hardware_rng()
    status = hw_rng.get_status()
    
    print("Available hardware RNG sources:")
    for source in status['available_sources']:
        print(f"- {source}")
    
    print("\nDetailed status:")
    for name, src_status in status['sources'].items():
        print(f"\n{name}:")
        for k, v in src_status.items():
            print(f"  {k}: {v}")
    
    if status['available_sources']:
        print("\n✅ Hardware RNG detection test passed")
        return True
    else:
        print("\n⚠️  No hardware RNG sources found")
        return False

def test_hardware_rng_quality(sample_size: int = 1_000_000):
    """Test the quality of hardware RNG output"""
    print("\n=== Testing Hardware RNG Quality ===")
    
    # Collect samples
    print(f"Collecting {sample_size} bytes from hardware RNG...")
    start_time = time.time()
    data = get_hardware_random_bytes(sample_size)
    elapsed = time.time() - start_time
    
    if data is None or len(data) != sample_size:
        print("❌ Failed to collect hardware RNG data")
        return False
    
    print(f"Collected {len(data)} bytes in {elapsed:.3f} seconds "
          f"({len(data)/elapsed/1e6:.2f} MB/s)")
    
    # Basic statistics
    values = np.frombuffer(data, dtype=np.uint8)
    unique, counts = np.unique(values, return_counts=True)
    byte_dist = counts / len(values)
    
    print("\nBasic Statistics:")
    print(f"- Unique bytes: {len(unique)}/256")
    print(f"- Mean: {np.mean(values):.2f} (expected: ~127.5)")
    print(f"- StdDev: {np.std(values):.2f} (expected: ~73.9)")
    
    # Check for bias
    bias = np.abs(np.mean(byte_dist) - 1/256) * 256
    print(f"- Bias: {bias:.6f} (closer to 0 is better)")
    
    # Simple randomness test
    randomness = min(byte_dist) / max(byte_dist)
    print(f"- Randomness: {randomness:.6f} (closer to 1.0 is better)")
    
    # Check if the distribution is uniform enough
    chi_square = np.sum((counts - len(values)/256)**2 / (len(values)/256))
    print(f"- Chi-square: {chi_square:.2f} (lower is better, < 293 for p=0.05)")
    
    # Check min-entropy (should be close to 8 bits per byte for good RNG)
    min_entropy = -np.log2(np.max(byte_dist))
    print(f"- Min-entropy: {min_entropy:.2f} bits/byte (higher is better, max 8)")
    
    # Pass if we have reasonable statistics
    if min_entropy > 7.5 and chi_square < 300 and bias < 0.1:
        print("\n✅ Hardware RNG quality test passed")
        return True
    else:
        print("\n⚠️  Hardware RNG quality test shows potential issues")
        return False

def test_integration():
    """Test integration with entropy monitoring system"""
    print("\n=== Testing Entropy Monitor Integration ===")
    
    try:
        # Start monitoring
        start_monitoring()
        
        # Give it some time to collect samples
        print("Monitoring entropy sources for 5 seconds...")
        time.sleep(5)
        
        # Check if hardware RNG is being used
        hw_samples = list(entropy_monitor.samples[EntropySource.HARDWARE_RNG])
        if not hw_samples:
            print("❌ No hardware RNG samples collected")
            return False
        
        print(f"Collected {len(hw_samples)} hardware RNG samples")
        
        # Check health status
        health = entropy_monitor.assess_health(EntropySource.HARDWARE_RNG)
        print(f"Hardware RNG health status: {health.value}")
        
        if health == entropy_monitor.EntropyHealthStatus.HEALTHY:
            print("\n✅ Entropy monitor integration test passed")
            return True
        else:
            print(f"\n⚠️  Hardware RNG health check: {health.value}")
            return False
            
    finally:
        stop_monitoring()

def main():
    """Run all hardware RNG tests"""
    print("=== Secure Vault Hardware RNG Test Suite ===\n")
    
    results = {
        'detection': test_hardware_rng_detection(),
        'quality': test_hardware_rng_quality(),
        'integration': test_integration()
    }
    
    # Print summary
    print("\n=== Test Summary ===")
    for test, passed in results.items():
        status = "✅ PASSED" if passed else "⚠️  WARNING"
        print(f"{test:15} {status}")
    
    # Final status
    if all(results.values()):
        print("\n✅ All tests passed successfully!")
        return 0
    else:
        print("\n⚠️  Some tests had issues. See above for details.")
        return 1

if __name__ == "__main__":
    import sys
    sys.exit(main())
