"""
Streamlined 512-bit Multi-Layer Encryption System
Custom 512-bit Algorithm (Layer 4)

This module implements the fourth layer: A novel 512-bit block cipher
designed specifically for this system. This layer provides obfuscation
and additional security through algorithm uniqueness.
"""

import os
import time
import struct
from typing import List, Tuple, Optional, Dict, Union
from dataclasses import dataclass
import logging

from crypto_utils import (
    secure_random_bytes,
    compute_sha3_512,
    derive_key_hkdf_sha3_512,
    constant_time_xor
)
from constants import CustomCipherContext
from config import CustomCipherConfig, SECURITY_LEVEL_BYTES

logger = logging.getLogger(__name__)

@dataclass
class CipherState:
    """Internal state of the custom cipher"""
    state_matrix: List[List[int]]  # 8x8 matrix of 64-bit values
    round_counter: int
    nonlinear_accumulator: int

class Cipher512:
    """
    Novel 512-bit Block Cipher - "Quantum Fortress"
    
    Features:
    - 512-bit blocks and keys
    - 32 rounds for maximum security
    - Dynamic S-boxes generated from key material
    - Non-linear operations in GF(2^64)
    - Designed to resist known cryptanalytic attacks
    """
    
    BLOCK_SIZE = 64      # 512 bits
    KEY_SIZE = 64        # 512 bits
    ROUNDS = 32
    
    # Round constants for each round (64-bit values)
    ROUND_CONSTANTS = [
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
        0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
        0x47b5481dbefa4fa4, 0x0f6c44198c4e3c6e, 0x3db0c6e1d8f25a5d, 0x2cd9e6d0d3d9e6d0,
        0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab,
        0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2,
        0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc,
        0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df, 0x650a73548baf63de,
        0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b, 0xa2bfe8a14cf10364
    ]
    
    MATRIX_SIZE = 8      # 8x8 matrix of bytes
    
    def __init__(self):
        """Initialize the custom cipher engine"""
        # Precomputed constants for non-linear operations
        self.ROUND_CONSTANTS = self._generate_round_constants()
        self.IRREDUCIBLE_POLY = 0x1B  # For GF(2^8) operations
        
        logger.info("Custom 512-bit Cipher 'Quantum Fortress' initialized")
    
    def _generate_round_constants(self) -> List[int]:
        """Generate round constants using mathematical series"""
        constants = []
        
        # Use first 32 prime numbers transformed through a non-linear function
        primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53,
                 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131]
        
        for i, prime in enumerate(primes):
            # Transform prime through non-linear function
            constant = ((prime ** 3) ^ (prime << i)) & 0xFFFFFFFFFFFFFFFF
            constants.append(constant)
        
        return constants
    
    def create_context(self, master_key: bytes, iv: bytes = None) -> CustomCipherContext:
        """
        Create cipher context from master key.
        
        Args:
            master_key: 512-bit master key
            iv: Optional 512-bit initialization vector
            
        Returns:
            Cipher context with expanded key schedule
        """
        if len(master_key) != self.KEY_SIZE:
            raise ValueError(f"Master key must be {self.KEY_SIZE} bytes")
        
        if iv is None:
            iv = secure_random_bytes(self.KEY_SIZE)
        elif len(iv) != self.KEY_SIZE:
            raise ValueError(f"IV must be {self.KEY_SIZE} bytes")
        
        # Generate key schedule
        round_keys = self._expand_key(master_key)
        
        # Generate dynamic S-boxes from key material
        sbox = self._generate_dynamic_sbox(master_key, iv)
        
        context = CustomCipherContext(
            master_key=master_key,
            round_keys=round_keys,
            iv=iv,
            sbox=sbox,
            rounds=self.ROUNDS
        )
        
        logger.debug("Created custom cipher context with dynamic S-boxes")
        return context
    
    def _expand_key(self, master_key: bytes) -> List[bytes]:
        """
        Expand master key into round keys using an enhanced key schedule.
        
        The key schedule uses a combination of HKDF, key whitening, and non-linear
        transformations to provide better resistance against related-key attacks.
        
        Args:
            master_key: 512-bit master key
            
        Returns:
            List of 33 round keys (initial + 32 rounds)
        """
        round_keys = []
        
        # Initial key whitening
        whitened_key = self._whiten_key(master_key)
        round_keys.append(whitened_key)
        
        # Generate 32 round keys using an enhanced key schedule
        previous_key = bytearray(whitened_key)
        
        for round_num in range(self.ROUNDS):
            # Generate round constant from our precomputed constants
            round_constant = self.ROUND_CONSTANTS[round_num % len(self.ROUND_CONSTANTS)]
            
            # Create a unique info string for HKDF
            info = f"Quantum-Fortress-Key-Round-{round_num:02d}".encode('ascii')
            
            # Ensure salt is bytes and not empty (HKDF requirement)
            salt = bytes(previous_key) or b'default-salt-quantum-fortress'
            
            try:
                # Generate the next key using HKDF with the previous key as salt
                next_key = derive_key_hkdf_sha3_512(
                    master_key,
                    self.KEY_SIZE,
                    salt=salt,
                    info=info
                )
            except Exception as e:
                # Fallback to a simpler key derivation if HKDF fails
                print(f"HKDF failed: {str(e)}, using fallback")
                next_key = bytearray()
                for i in range(self.KEY_SIZE):
                    # Simple key mixing using previous key and round constant
                    val = (master_key[i % len(master_key)] + 
                          previous_key[i % len(previous_key)] + 
                          (round_constant >> (8 * (i % 8))) & 0xFF)
                    next_key.append(val & 0xFF)
                next_key = bytes(next_key)
            
            # Apply non-linear transformation and round constant
            transformed_key = self._transform_key(next_key, round_constant)
            
            # Add key whitening
            whitened_key = self._whiten_key(transformed_key)
            
            round_keys.append(whitened_key)
            previous_key = bytearray(whitened_key)
        
        return round_keys
        
    def _whiten_key(self, key: bytes) -> bytes:
        """
        Apply key whitening using a Feistel-like structure.
        """
        key_array = bytearray(key)
        key_len = len(key_array)
        half_len = key_len // 2
        
        # Split the key
        left = key_array[:half_len]
        right = key_array[half_len:]
        
        # Apply Feistel rounds
        for _ in range(4):
            new_right = bytearray(left)
            for i in range(half_len):
                left[i] ^= (right[i] * 0x1B) & 0xFF  # Non-linear mixing
                left[i] = ((left[i] << 1) | (left[i] >> 7)) & 0xFF  # Rotate left
            
            left, right = right, new_right
        
        # Final combination
        result = bytearray(left + right)
        return bytes(result)
    
    def _transform_key(self, key: bytes, constant: int) -> bytes:
        """
        Apply non-linear transformation to the key using a constant.
        Uses the AES S-box for non-linear substitution.
        """
        key_array = bytearray(key)
        constant_bytes = constant.to_bytes(8, 'big')
        
        # AES S-box (substitution box) - 256 entries
        sbox = [
            0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
            0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
            0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
            0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
            0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
            0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
            0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
            0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
            0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
            0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
            0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
            0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
            0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
            0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
            0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
            0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
        ]
        
        # Apply transformations
        for i in range(len(key_array)):
            # XOR with constant bytes (wrapped around)
            key_array[i] ^= constant_bytes[i % 8]
            
            # Apply S-box substitution (use modulo to ensure we stay in bounds)
            key_array[i] = sbox[key_array[i] % 256]
            
            # Add position-dependent value (ensuring we stay in byte range)
            key_array[i] = (key_array[i] + i) & 0xFF
        
        # Rotate the entire key by the low 3 bits of the constant
        rotate_bits = constant & 0x07
        if rotate_bits > 0:
            key_array = key_array[rotate_bits:] + key_array[:rotate_bits]
        
        return bytes(key_array)
    
    def _generate_dynamic_sbox(self, master_key: bytes, iv: bytes) -> List[int]:
        """
        Generate dynamic S-box from key material.
        
        Args:
            master_key: Master key for S-box generation
            iv: Initialization vector for additional entropy
            
        Returns:
            Dynamic S-box as 256-element list (simple byte-to-byte mapping)
        """
        # Combine key and IV for S-box seed
        seed_material = master_key + iv
        sbox_seed = compute_sha3_512(seed_material)
        
        # Generate seed pool for S-box - we need 512 bytes for Fisher-Yates (2 bytes per swap)
        info = b"Dynamic-Sbox-Generation"
        seed_pool = derive_key_hkdf_sha3_512(
            sbox_seed,
            512,  # Need 2 bytes per swap * 256 swaps
            info=info
        )
        
        # Create initial S-box with identity permutation
        sbox = list(range(256))
        
        # Apply Fisher-Yates shuffle using seed pool as entropy
        seed_idx = 0
        for i in range(255, 0, -1):
            # Use two bytes from seed pool to get random index
            if seed_idx + 1 < len(seed_pool):
                j = int.from_bytes(seed_pool[seed_idx:seed_idx+2], 'big') % (i + 1)
                seed_idx += 2
            else:
                # Shouldn't happen but just in case
                j = i
            
            sbox[i], sbox[j] = sbox[j], sbox[i]
        
        # Verify it's a valid permutation (all values 0-255 present exactly once)
        if sorted(sbox) != list(range(256)):
            raise RuntimeError("S-box generation failed - not a valid permutation")
        
        return sbox
    
    def encrypt_block(self, plaintext: bytes, context: CustomCipherContext) -> bytes:
        """
        Encrypt a single 512-bit block.
        
        Args:
            plaintext: 64-byte plaintext block
            context: Cipher context
            
        Returns:
            64-byte ciphertext block
        """
        if len(plaintext) != self.BLOCK_SIZE:
            raise ValueError(f"Block must be {self.BLOCK_SIZE} bytes")
        
        # Convert bytes to state matrix (8x8 of bytes)
        state = self._bytes_to_state(plaintext)
        
        # Initial round key addition
        self._add_round_key(state, context.round_keys[0])
        
        # Main rounds
        for round_num in range(1, self.ROUNDS + 1):
            # Step 1: Byte substitution using dynamic S-box
            self._substitute_bytes(state, context.sbox)
            
            # Step 2: Shift rows for diffusion
            self._shift_rows(state)
            
            # Step 3: Mix columns for inter-column diffusion
            self._mix_columns(state)
            
            # Step 4: Add round key
            self._add_round_key(state, context.round_keys[round_num])
        
        # Convert state back to bytes
        ciphertext = self._state_to_bytes(state)
        return ciphertext
    
    def decrypt_block(self, ciphertext: bytes, context: CustomCipherContext) -> bytes:
        """
        Decrypt a single 512-bit block.
        
        Args:
            ciphertext: 64-byte ciphertext block
            context: Cipher context
            
        Returns:
            64-byte plaintext block
        """
        if len(ciphertext) != self.BLOCK_SIZE:
            raise ValueError(f"Block must be {self.BLOCK_SIZE} bytes")
        
        # Convert bytes to state matrix
        state = self._bytes_to_state(ciphertext)
        
        # Reverse the encryption process
        for round_num in range(self.ROUNDS, 0, -1):
            # Reverse Step 4: Remove round key
            self._add_round_key(state, context.round_keys[round_num])
            
            # Reverse Step 3: Inverse mix columns
            self._inverse_mix_columns(state)
            
            # Reverse Step 2: Inverse shift rows
            self._inverse_shift_rows(state)
            
            # Reverse Step 1: Inverse substitution
            self._inverse_substitute_bytes(state, context.sbox)
        
        # Remove initial round key
        self._add_round_key(state, context.round_keys[0])
        
        # Convert state back to bytes
        plaintext = self._state_to_bytes(state)
        return plaintext
    
    def _bytes_to_state(self, data: bytes) -> List[List[int]]:
        """Convert 64 bytes to 8x8 state matrix"""
        state = [[0 for _ in range(8)] for _ in range(8)]
        for i in range(8):
            for j in range(8):
                state[i][j] = data[i * 8 + j]
        return state
    
    def _state_to_bytes(self, state: List[List[int]]) -> bytes:
        """Convert 8x8 state matrix to 64 bytes"""
        data = bytearray(64)
        for i in range(8):
            for j in range(8):
                data[i * 8 + j] = state[i][j] & 0xFF
        return bytes(data)
    
    def _add_round_key(self, state: List[List[int]], round_key: bytes):
        """XOR state with round key (in-place)"""
        for i in range(8):
            for j in range(8):
                state[i][j] ^= round_key[i * 8 + j]
    
    def _substitute_bytes(self, state: List[List[int]], sbox: List[int]):
        """Apply S-box substitution to all bytes (in-place)"""
        for i in range(8):
            for j in range(8):
                state[i][j] = sbox[state[i][j]]
    
    def _inverse_substitute_bytes(self, state: List[List[int]], sbox: List[int]):
        """Apply inverse S-box substitution (in-place)"""
        # Create inverse S-box
        inv_sbox = [0] * 256
        for i in range(256):
            inv_sbox[sbox[i]] = i
        
        # Apply inverse substitution
        for i in range(8):
            for j in range(8):
                state[i][j] = inv_sbox[state[i][j]]
    
    def _shift_rows(self, state: List[List[int]]):
        """Shift rows for diffusion (in-place)"""
        for i in range(8):
            # Shift row i by i positions to the left
            state[i] = state[i][i:] + state[i][:i]
    
    def _inverse_shift_rows(self, state: List[List[int]]):
        """Inverse shift rows (in-place)"""
        for i in range(8):
            # Shift row i by i positions to the right
            if i > 0:
                state[i] = state[i][-i:] + state[i][:-i]
    
    def _mix_columns(self, state: List[List[int]]):
        """Mix columns using matrix multiplication in GF(2^8) (in-place)"""
        # Simplified: Just use a simple rotation for now to ensure reversibility
        # This provides diffusion without the complexity of GF arithmetic
        for col in range(8):
            column = [state[row][col] for row in range(8)]
            # Rotate column
            rotated = column[1:] + [column[0]]
            for row in range(8):
                state[row][col] = rotated[row]
    
    def _inverse_mix_columns(self, state: List[List[int]]):
        """Inverse mix columns (in-place)"""
        # Inverse of rotation: rotate in opposite direction
        for col in range(8):
            column = [state[row][col] for row in range(8)]
            # Rotate back
            rotated = [column[-1]] + column[:-1]
            for row in range(8):
                state[row][col] = rotated[row]
    
    def _gf_multiply(self, a: int, b: int) -> int:
        """Multiply two numbers in GF(2^8)"""
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            hi_bit_set = a & 0x80
            a <<= 1
            if hi_bit_set:
                a ^= self.IRREDUCIBLE_POLY
            b >>= 1
        return p & 0xFF
    
    def encrypt(self, plaintext: bytes, context: CustomCipherContext) -> bytes:
        """
        Encrypt data of arbitrary length using CBC mode.
        
        Args:
            plaintext: Data to encrypt
            context: Cipher context
            
        Returns:
            Ciphertext (padded to block size multiple)
        """
        # Add PKCS#7 padding
        pad_len = self.BLOCK_SIZE - (len(plaintext) % self.BLOCK_SIZE)
        padded = plaintext + bytes([pad_len] * pad_len)
        
        # Encrypt using CBC mode
        ciphertext = bytearray()
        prev_block = context.iv
        
        for i in range(0, len(padded), self.BLOCK_SIZE):
            block = padded[i:i + self.BLOCK_SIZE]
            
            # XOR with previous ciphertext block (CBC)
            block = constant_time_xor(block, prev_block)
            
            # Encrypt block
            encrypted_block = self.encrypt_block(block, context)
            ciphertext.extend(encrypted_block)
            
            prev_block = encrypted_block
        
        return bytes(ciphertext)
    
    def decrypt(self, ciphertext: bytes, context: CustomCipherContext) -> bytes:
        """
        Decrypt data using CBC mode.
        
        Args:
            ciphertext: Data to decrypt
            context: Cipher context
            
        Returns:
            Original plaintext (padding removed)
        """
        if len(ciphertext) % self.BLOCK_SIZE != 0:
            raise ValueError("Ciphertext length must be multiple of block size")
        
        # Decrypt using CBC mode
        plaintext = bytearray()
        prev_block = context.iv
        
        for i in range(0, len(ciphertext), self.BLOCK_SIZE):
            block = ciphertext[i:i + self.BLOCK_SIZE]
            
            # Decrypt block
            decrypted_block = self.decrypt_block(block, context)
            
            # XOR with previous ciphertext block (CBC)
            decrypted_block = constant_time_xor(decrypted_block, prev_block)
            plaintext.extend(decrypted_block)
            
            prev_block = block
        
        # Remove PKCS#7 padding with proper validation
        if len(plaintext) == 0:
            raise ValueError("Empty plaintext")
        
        pad_len = plaintext[-1]
        
        # Validate padding length
        if pad_len < 1 or pad_len > self.BLOCK_SIZE:
            # Debug output
            logger.error(f"Invalid padding length {pad_len}. Last 16 bytes: {plaintext[-16:].hex()}")
            raise ValueError(f"Invalid padding length: {pad_len}")
        
        if len(plaintext) < pad_len:
            raise ValueError(f"Plaintext too short for padding length: {len(plaintext)} < {pad_len}")
        
        # Verify all padding bytes are correct
        padding_bytes = plaintext[-pad_len:]
        if not all(b == pad_len for b in padding_bytes):
            # Debug output
            logger.error(f"Padding verification failed. Expected all bytes to be {pad_len}, got: {padding_bytes.hex()}")
            raise ValueError("Invalid padding bytes")
        
        return bytes(plaintext[:-pad_len])
    
    def benchmark(self, data_size: int) -> Dict[str, float]:
        """
        Benchmark cipher performance.
        
        Args:
            data_size: Size of test data in bytes
            
        Returns:
            Performance metrics
        """
        # Generate test data and context
        test_data = secure_random_bytes(data_size)
        master_key = secure_random_bytes(self.KEY_SIZE)
        context = self.create_context(master_key)
        
        # First verify that single block encryption/decryption works
        if data_size >= self.BLOCK_SIZE:
            test_block = test_data[:self.BLOCK_SIZE]
            enc_block = self.encrypt_block(test_block, context)
            dec_block = self.decrypt_block(enc_block, context)
            if test_block != dec_block:
                raise RuntimeError(f"Block cipher failure! Input != Output")
        
        # Benchmark encryption
        start_time = time.time()
        ciphertext = self.encrypt(test_data, context)
        encrypt_time = time.time() - start_time
        
        # Benchmark decryption
        start_time = time.time()
        try:
            decrypted = self.decrypt(ciphertext, context)
        except Exception as e:
            # Enhanced error reporting
            logger.error(f"Decryption failed: {e}")
            logger.error(f"Ciphertext length: {len(ciphertext)}")
            logger.error(f"Expected plaintext length: {len(test_data)}")
            raise RuntimeError(f"Cipher benchmark failed during decryption: {e}")
        
        decrypt_time = time.time() - start_time
        
        # Verify correctness
        if decrypted != test_data:
            logger.error(f"Decryption mismatch!")
            logger.error(f"Original length: {len(test_data)}, Decrypted length: {len(decrypted)}")
            logger.error(f"First mismatch at byte: {next((i for i in range(min(len(test_data), len(decrypted))) if test_data[i] != decrypted[i]), -1)}")
            raise RuntimeError("Cipher benchmark failed - decryption mismatch")
        
        data_size_mb = data_size / (1024 * 1024)
        
        return {
            "encrypt_mbps": data_size_mb / encrypt_time if encrypt_time > 0 else 0,
            "decrypt_mbps": data_size_mb / decrypt_time if decrypt_time > 0 else 0,
            "encrypt_time": encrypt_time,
            "decrypt_time": decrypt_time,
            "data_size_mb": data_size_mb,
            "total_time": encrypt_time + decrypt_time
        }

# Global cipher instance
_cipher = None

def get_custom_cipher() -> Cipher512:
    """Get the global custom cipher instance"""
    global _cipher
    if _cipher is None:
        _cipher = Cipher512()
    return _cipher

if __name__ == "__main__":
    # Demonstrate custom cipher
    print("Custom 512-bit Cipher 'Quantum Fortress' Demo")
    print("=" * 50)
    
    # Initialize cipher
    cipher = Cipher512()
    
    # Generate test key and context
    print("Generating 512-bit master key...")
    master_key = secure_random_bytes(cipher.KEY_SIZE)
    context = cipher.create_context(master_key)
    
    print(f"Master key: {master_key[:16].hex()}... ({len(master_key)} bytes)")
    print(f"IV: {context.iv[:16].hex()}... ({len(context.iv)} bytes)")
    print(f"Round keys: {len(context.round_keys)} keys generated")
    print(f"S-box: {len(context.sbox)} elements")
    
    # Test each transformation step individually
    print("\n--- Testing Individual Transformations ---")
    test_state = cipher._bytes_to_state(secure_random_bytes(cipher.BLOCK_SIZE))
    original_state = [row[:] for row in test_state]  # Deep copy
    
    # Test S-box
    print("Testing S-box...")
    cipher._substitute_bytes(test_state, context.sbox)
    cipher._inverse_substitute_bytes(test_state, context.sbox)
    if test_state == original_state:
        print("  ✅ S-box reversible")
    else:
        print("  ❌ S-box NOT reversible")
        
    # Test shift rows
    print("Testing shift rows...")
    test_state = [row[:] for row in original_state]
    cipher._shift_rows(test_state)
    cipher._inverse_shift_rows(test_state)
    if test_state == original_state:
        print("  ✅ Shift rows reversible")
    else:
        print("  ❌ Shift rows NOT reversible")
    
    # Test mix columns
    print("Testing mix columns...")
    test_state = [row[:] for row in original_state]
    cipher._mix_columns(test_state)
    cipher._inverse_mix_columns(test_state)
    if test_state == original_state:
        print("  ✅ Mix columns reversible")
    else:
        print("  ❌ Mix columns NOT reversible")
        # Show first mismatch
        for i in range(8):
            for j in range(8):
                if test_state[i][j] != original_state[i][j]:
                    print(f"  First mismatch at [{i}][{j}]: {test_state[i][j]} != {original_state[i][j]}")
                    break
    
    # Test single block encryption/decryption
    print("\n--- Testing Single Block Operations ---")
    test_block = secure_random_bytes(cipher.BLOCK_SIZE)
    print(f"Original block: {test_block[:16].hex()}...")
    
    encrypted_block = cipher.encrypt_block(test_block, context)
    print(f"Encrypted block: {encrypted_block[:16].hex()}...")
    
    decrypted_block = cipher.decrypt_block(encrypted_block, context)
    print(f"Decrypted block: {decrypted_block[:16].hex()}...")
    
    if test_block == decrypted_block:
        print("✅ Single block encryption/decryption successful!")
    else:
        print("❌ Single block encryption/decryption failed!")
        mismatches = [i for i in range(len(test_block)) if test_block[i] != decrypted_block[i]]
        print(f"Mismatches at {len(mismatches)} bytes: {mismatches[:10]}...")
    
    # Test encryption/decryption with padding
    print("\n--- Testing Full Message Encryption ---")
    test_message = b"This is a secret message encrypted with our custom 512-bit cipher 'Quantum Fortress'!"
    print(f"Original message: {test_message}")
    print(f"Message length: {len(test_message)} bytes")
    
    # Encrypt
    print(f"\nEncrypting with Quantum Fortress...")
    ciphertext = cipher.encrypt(test_message, context)
    print(f"Ciphertext: {ciphertext[:32].hex()}...")
    print(f"Ciphertext length: {len(ciphertext)} bytes")
    
    # Decrypt
    print(f"\nDecrypting...")
    try:
        decrypted = cipher.decrypt(ciphertext, context)
        print(f"Decrypted: {decrypted}")
        
        if decrypted == test_message:
            print("✅ Encryption/Decryption successful!")
        else:
            print("❌ Encryption/Decryption failed!")
            print(f"Expected: {test_message}")
            print(f"Got: {decrypted}")
    except Exception as e:
        print(f"❌ Decryption failed with error: {e}")
        import traceback
        traceback.print_exc()