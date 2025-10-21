#!/usr/bin/env python3
"""
Test script for the Entropy Accumulator
"""

import os
import time
import logging
from typing import List, Tuple
import numpy as np
from entropy_monitor import EntropySource, start_monitoring, stop_monitoring
from entropy_pool import entropy_accumulator, get_random_bytes, start_accumulator, stop_accumulator

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def test_entropy_accumulation():
    """Test basic entropy accumulation and random number generation"""
    print("\n=== Testing Entropy Accumulation ===")
    
    # Add some test entropy
    test_data = os.urandom(64)  # 512 bits
    entropy_accumulator.add_entropy(test_data, 1, 256)  # Estimate 256 bits of entropy
    
    # Get some random bytes
    random_data = get_random_bytes(32)
    print(f"Generated {len(random_data)} random bytes")
    print(f"First 16 bytes: {random_data[:16].hex()}")
    
    # Check uniqueness of multiple samples
    samples = [get_random_bytes(16).hex() for _ in range(5)]
    unique_samples = len(set(samples))
    print(f"\nGenerated {unique_samples}/5 unique samples")
    
    if unique_samples == 5:
        print("✅ Entropy accumulation test passed")
    else:
        print("❌ Entropy accumulation test failed")

def test_entropy_quality():
    """Test the quality of generated random numbers"""
    print("\n=== Testing Entropy Quality ===")
    
    # Generate a large sample of random data
    sample_size = 1_000_000  # 1MB
    random_data = get_random_bytes(sample_size)
    
    # Calculate basic statistics
    values = np.frombuffer(random_data, dtype=np.uint8)
    
    # Check byte distribution
    unique, counts = np.unique(values, return_counts=True)
    byte_dist = counts / len(values)
    
    print(f"Sample size: {len(values):,} bytes")
    print(f"Unique bytes: {len(unique)}/256")
    print(f"Mean: {np.mean(values):.2f} (expected: ~127.5)")
    print(f"StdDev: {np.std(values):.2f} (expected: ~73.9)")
    
    # Check for bias (should be close to 0.5)
    bias = np.abs(np.mean(byte_dist) - 1/256) * 256
    print(f"Bias: {bias:.6f} (closer to 0 is better)")
    
    # Simple randomness test (should be close to 1.0)
    randomness = min(byte_dist) / max(byte_dist)
    print(f"Randomness: {randomness:.6f} (closer to 1.0 is better)")
    
    if bias < 0.1 and randomness > 0.8:
        print("✅ Entropy quality test passed")
    else:
        print("⚠️  Entropy quality test shows potential issues")

def test_concurrent_access():
    """Test concurrent access to the entropy accumulator"""
    print("\n=== Testing Concurrent Access ===")
    import threading
    
    results = []
    
    def worker():
        try:
            data = get_random_bytes(16)
            results.append((threading.get_ident(), data.hex()))
        except Exception as e:
            results.append((threading.get_ident(), f"Error: {e}"))
    
    # Start multiple threads
    threads = []
    for _ in range(5):
        t = threading.Thread(target=worker)
        threads.append(t)
        t.start()
    
    # Wait for all threads to complete
    for t in threads:
        t.join()
    
    # Check results
    print(f"Generated {len(results)} samples from {len(set(r[0] for r in results))} threads")
    print("Sample results:")
    for tid, data in results[:3]:
        print(f"  Thread {tid}: {data[:16]}...")
    
    # Check for uniqueness
    unique_samples = len(set(r[1] for r in results))
    if unique_samples == len(results):
        print("✅ All samples are unique")
    else:
        print(f"⚠️  Found {len(results) - unique_samples} duplicate samples")

def main():
    """Run all tests"""
    print("=== Secure Vault Entropy Accumulator Tests ===\n")
    
    try:
        # Start the entropy monitoring and accumulator
        start_monitoring()
        start_accumulator()
        
        # Run tests
        test_entropy_accumulation()
        test_entropy_quality()
        test_concurrent_access()
        
    except Exception as e:
        logger.error(f"Test failed: {e}", exc_info=True)
        return 1
    finally:
        # Clean up
        stop_monitoring()
        stop_accumulator()
    
    print("\n=== Tests Complete ===")
    return 0

if __name__ == "__main__":
    import sys
    sys.exit(main())
