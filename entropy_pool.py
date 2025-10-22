"""
Fortuna-like Entropy Accumulator

This module implements a Fortuna-inspired entropy accumulator with multiple pools
and secure memory handling for cryptographically secure random number generation.
"""

import os
import time
import hashlib
import threading
import logging
from typing import Dict, List, Optional, Union, Tuple
from dataclasses import dataclass, field
from enum import Enum, auto
from collections import deque

# Import secure memory for handling sensitive data
from secure_memory import SecureBytes, secure_alloc, secure_free, secure_wipe

logger = logging.getLogger(__name__)

# Constants
NUM_POOLS = 32  # Number of entropy pools
MIN_POOL_SIZE = 64  # Minimum bytes before a pool can be used for reseeding
RESEED_INTERVAL = 100  # ms between automatic reseed checks

class PoolState(Enum):
    """State of an entropy pool"""
    EMPTY = auto()
    FILLING = auto()
    READY = auto()
    DRAINING = auto()

@dataclass
class EntropyPool:
    """Individual entropy pool with secure memory management"""
    data: SecureBytes
    size: int = 0
    state: PoolState = PoolState.EMPTY
    last_updated: float = field(default_factory=time.time)
    
    def add_entropy(self, data: bytes, estimated_bits: float) -> None:
        """Add entropy to the pool"""
        with self.data.lock():
            # Append the new data
            self.data.extend(data)
            self.size = len(self.data)
            self.last_updated = time.time()

            # Update state based on size
            if self.size >= MIN_POOL_SIZE:
                self.state = PoolState.READY
            else:
                self.state = PoolState.FILLING
    
    def get_entropy(self, num_bytes: int) -> Optional[bytes]:
        """Extract entropy from the pool"""
        if self.state != PoolState.READY or self.size < num_bytes:
            return None
            
        self.state = PoolState.DRAINING
        try:
            with self.data.lock():
                if len(self.data) < num_bytes:
                    return None

                # Extract the requested bytes
                result = self.data.consume(num_bytes)
                self.size = len(self.data)

                # Update state
                if self.size == 0:
                    self.state = PoolState.EMPTY
                elif self.size < MIN_POOL_SIZE:
                    self.state = PoolState.FILLING
                
                return result
        finally:
            if self.state == PoolState.DRAINING:
                self.state = PoolState.READY if self.size >= MIN_POOL_SIZE else PoolState.FILLING

class EntropyAccumulator:
    """
    Fortuna-like entropy accumulator with multiple pools and secure memory handling.
    
    This class implements a cryptographically secure entropy accumulator that:
    1. Collects entropy from multiple sources
    2. Distributes entropy across multiple pools
    3. Provides secure random data generation
    4. Implements automatic reseeding
    """
    
    def __init__(self):
        """Initialize the entropy accumulator"""
        self.pools = [self._create_pool() for _ in range(NUM_POOLS)]
        self.counter = 0
        self.last_reseed = 0
        self.lock = threading.RLock()
        self.running = False
        self.worker_thread: Optional[threading.Thread] = None
        
        # Initialize the key and cipher
        self.key = SecureBytes(64)  # 512-bit key
        self.counter = 0
        
    def _create_pool(self) -> EntropyPool:
        """Create a new secure entropy pool"""
        return EntropyPool(SecureBytes(b''))
    
    def add_entropy(self, data: bytes, source: int, estimated_bits: float) -> None:
        """
        Add entropy to the appropriate pools
        
        Args:
            data: The entropy data to add
            source: The source identifier (0-255)
            estimated_bits: Estimated number of bits of entropy in the data
        """
        if not data or estimated_bits <= 0:
            return
            
        with self.lock:
            # Distribute data to pools based on source and counter
            pool_num = source % NUM_POOLS
            self.pools[pool_num].add_entropy(data, estimated_bits)
            
            # Also add to pool 0 which is used more frequently
            if pool_num != 0:
                self.pools[0].add_entropy(data, estimated_bits)
            
            logger.debug(f"Added {len(data)} bytes of entropy (est. {estimated_bits:.2f} bits) to pool {pool_num}")
    
    def _reseed(self) -> bool:
        """Reseed the generator from the pools"""
        with self.lock:
            # Only reseed if enough time has passed
            current_time = time.time()
            if current_time - self.last_reseed < 0.1:  # 100ms minimum between reseeds
                return False
                
            # Find all ready pools
            ready_pools = [i for i, pool in enumerate(self.pools) 
                          if pool.state == PoolState.READY]
            
            if not ready_pools:
                return False
            
            # Combine data from ready pools
            combined = bytearray()
            for pool_num in ready_pools:
                pool = self.pools[pool_num]
                with pool.data.lock():
                    combined.extend(pool.data.read())
                    pool.data.clear()
                    pool.size = 0
                    pool.state = PoolState.EMPTY

            # Update the key using SHA-512
            with self.key.lock():
                hasher = hashlib.sha512()
                key_material = self.key.read()
                hasher.update(key_material)
                hasher.update(combined)
                new_key = hasher.digest()
                self.key.write(new_key)
                secure_wipe(bytearray(key_material))
            secure_wipe(combined)

            self.counter += 1
            self.last_reseed = current_time
            
            logger.debug(f"Reseeding completed (counter: {self.counter}, pools used: {len(ready_pools)})")
            return True
    
    def get_random_bytes(self, num_bytes: int) -> bytes:
        """
        Generate cryptographically secure random bytes
        
        Args:
            num_bytes: Number of bytes to generate
            
        Returns:
            bytes: The generated random bytes
        """
        if num_bytes <= 0:
            return b""
            
        with self.lock:
            # Try to reseed if needed
            self._reseed()
            
            # Generate random data using the current key and counter
            result = bytearray()
            remaining = num_bytes
            
            while remaining > 0:
                # Generate a block of random data
                with self.key.lock():
                    hasher = hashlib.sha512()
                    key_material = self.key.read()
                    hasher.update(key_material)
                    hasher.update(self.counter.to_bytes(8, 'big'))
                    block = hasher.digest()

                    # Update the key for the next iteration
                    hasher = hashlib.sha512()
                    hasher.update(key_material)
                    hasher.update(block)
                    self.key.write(hasher.digest())
                    secure_wipe(bytearray(key_material))

                    self.counter += 1

                # Add as much as we need from this block
                take = min(remaining, len(block))
                result.extend(block[:take])
                remaining -= take
                secure_wipe(bytearray(block))

            return bytes(result[:num_bytes])
    
    def start(self) -> None:
        """Start the background worker thread"""
        if self.running:
            return
            
        self.running = True
        self.worker_thread = threading.Thread(
            target=self._worker_loop,
            daemon=True,
            name="EntropyAccumulatorWorker"
        )
        self.worker_thread.start()
        logger.info("Entropy accumulator worker started")
    
    def stop(self) -> None:
        """Stop the background worker thread"""
        self.running = False
        if self.worker_thread:
            self.worker_thread.join(timeout=5.0)
            self.worker_thread = None
        logger.info("Entropy accumulator worker stopped")
    
    def _worker_loop(self) -> None:
        """Background worker loop for maintenance tasks"""
        while self.running:
            try:
                # Periodically try to reseed
                self._reseed()
                
                # Sleep for a short time
                time.sleep(RESEED_INTERVAL / 1000.0)
                
            except Exception as e:
                logger.error(f"Error in entropy accumulator worker: {e}", exc_info=True)
                time.sleep(1.0)  # Prevent tight loop on errors

# Global instance for easy access
entropy_accumulator = EntropyAccumulator()

def start_accumulator() -> None:
    """Start the global entropy accumulator"""
    entropy_accumulator.start()

def stop_accumulator() -> None:
    """Stop the global entropy accumulator"""
    entropy_accumulator.stop()

def get_random_bytes(num_bytes: int) -> bytes:
    """Get random bytes from the global entropy accumulator"""
    return entropy_accumulator.get_random_bytes(num_bytes)

# Register cleanup on exit
import atexit
atexit.register(stop_accumulator)
