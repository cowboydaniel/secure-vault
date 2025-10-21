"""
Comprehensive Test Suite for Custom 512-bit Cipher
Tests for the Quantum Fortress cipher implementation
"""

import pytest
import os
from custom_cipher import Cipher512
from constants import CustomCipherContext


class TestCipher512Basic:
    """Basic functionality tests for the 512-bit cipher"""

    def test_cipher_initialization(self):
        """Test that cipher initializes correctly"""
        cipher = Cipher512()
        assert cipher.BLOCK_SIZE == 64
        assert cipher.KEY_SIZE == 64
        assert cipher.ROUNDS == 32
        assert len(cipher.ROUND_CONSTANTS) == 32

    def test_context_creation(self):
        """Test cipher context creation with valid key"""
        cipher = Cipher512()
        master_key = os.urandom(64)

        context = cipher.create_context(master_key)

        assert context is not None
        assert isinstance(context, CustomCipherContext)
        assert len(context.master_key) == 64
        assert len(context.round_keys) == 33  # Initial + 32 rounds
        assert len(context.iv) == 64
        assert len(context.sbox) == 256
        assert context.rounds == 32

    def test_context_creation_with_custom_iv(self):
        """Test cipher context creation with custom IV"""
        cipher = Cipher512()
        master_key = os.urandom(64)
        custom_iv = os.urandom(64)

        context = cipher.create_context(master_key, iv=custom_iv)

        assert context.iv == custom_iv

    def test_invalid_key_size(self):
        """Test that invalid key sizes are rejected"""
        cipher = Cipher512()

        with pytest.raises(ValueError, match="Master key must be 64 bytes"):
            cipher.create_context(b"short_key")

        with pytest.raises(ValueError, match="Master key must be 64 bytes"):
            cipher.create_context(os.urandom(32))

    def test_invalid_iv_size(self):
        """Test that invalid IV sizes are rejected"""
        cipher = Cipher512()
        master_key = os.urandom(64)

        with pytest.raises(ValueError, match="IV must be 64 bytes"):
            cipher.create_context(master_key, iv=b"short_iv")


class TestCipher512KeySchedule:
    """Tests for key expansion and key schedule"""

    def test_key_expansion_length(self):
        """Test that key expansion produces correct number of round keys"""
        cipher = Cipher512()
        master_key = os.urandom(64)

        context = cipher.create_context(master_key)

        assert len(context.round_keys) == 33  # Initial + 32 rounds
        for rk in context.round_keys:
            assert len(rk) == 64

    def test_key_expansion_uniqueness(self):
        """Test that all round keys are unique"""
        cipher = Cipher512()
        master_key = os.urandom(64)

        context = cipher.create_context(master_key)

        # All round keys should be different
        unique_keys = set(context.round_keys)
        assert len(unique_keys) == len(context.round_keys)

    def test_key_expansion_determinism(self):
        """Test that key expansion is deterministic"""
        cipher = Cipher512()
        master_key = os.urandom(64)
        iv = os.urandom(64)

        context1 = cipher.create_context(master_key, iv=iv)
        context2 = cipher.create_context(master_key, iv=iv)

        # Should produce identical contexts
        for i in range(len(context1.round_keys)):
            assert context1.round_keys[i] == context2.round_keys[i]
        assert context1.sbox == context2.sbox

    def test_different_keys_produce_different_schedules(self):
        """Test that different keys produce different round keys"""
        cipher = Cipher512()
        key1 = os.urandom(64)
        key2 = os.urandom(64)

        context1 = cipher.create_context(key1)
        context2 = cipher.create_context(key2)

        # Round keys should be different
        for i in range(len(context1.round_keys)):
            assert context1.round_keys[i] != context2.round_keys[i]


class TestCipher512SBox:
    """Tests for S-box generation"""

    def test_sbox_generation(self):
        """Test that S-box is properly generated"""
        cipher = Cipher512()
        master_key = os.urandom(64)

        context = cipher.create_context(master_key)

        assert len(context.sbox) == 256
        # S-box should be a permutation of 0-255
        assert set(context.sbox) == set(range(256))

    def test_sbox_is_permutation(self):
        """Test that S-box is a valid permutation"""
        cipher = Cipher512()
        master_key = os.urandom(64)

        context = cipher.create_context(master_key)

        # Every value 0-255 should appear exactly once
        sbox_values = list(context.sbox)
        assert len(sbox_values) == 256
        assert sorted(sbox_values) == list(range(256))

    def test_different_keys_produce_different_sboxes(self):
        """Test that different keys produce different S-boxes"""
        cipher = Cipher512()
        key1 = os.urandom(64)
        key2 = os.urandom(64)

        context1 = cipher.create_context(key1)
        context2 = cipher.create_context(key2)

        assert context1.sbox != context2.sbox

    def test_sbox_determinism(self):
        """Test that S-box generation is deterministic"""
        cipher = Cipher512()
        master_key = os.urandom(64)
        iv = os.urandom(64)

        context1 = cipher.create_context(master_key, iv=iv)
        context2 = cipher.create_context(master_key, iv=iv)

        assert context1.sbox == context2.sbox


class TestCipher512EncryptDecrypt:
    """Tests for encryption and decryption operations"""

    def test_encrypt_decrypt_single_block(self):
        """Test encryption and decryption of a single block"""
        cipher = Cipher512()
        master_key = os.urandom(64)
        context = cipher.create_context(master_key)

        plaintext = os.urandom(64)  # Single block

        # Encrypt
        ciphertext = cipher.encrypt_block(plaintext, context)
        assert len(ciphertext) == 64
        assert ciphertext != plaintext

        # Decrypt
        decrypted = cipher.decrypt_block(ciphertext, context)
        assert decrypted == plaintext

    def test_encrypt_decrypt_determinism(self):
        """Test that encryption is deterministic for same key and plaintext"""
        cipher = Cipher512()
        master_key = os.urandom(64)
        context = cipher.create_context(master_key)
        plaintext = os.urandom(64)

        ciphertext1 = cipher.encrypt_block(plaintext, context)
        ciphertext2 = cipher.encrypt_block(plaintext, context)

        assert ciphertext1 == ciphertext2

    def test_encrypt_all_zero_block(self):
        """Test encryption of all-zero block"""
        cipher = Cipher512()
        master_key = os.urandom(64)
        context = cipher.create_context(master_key)

        plaintext = b'\x00' * 64
        ciphertext = cipher.encrypt_block(plaintext, context)

        # Ciphertext should not be all zeros
        assert ciphertext != plaintext
        assert ciphertext != b'\x00' * 64

        # Should decrypt correctly
        decrypted = cipher.decrypt_block(ciphertext, context)
        assert decrypted == plaintext

    def test_encrypt_all_ones_block(self):
        """Test encryption of all-ones block"""
        cipher = Cipher512()
        master_key = os.urandom(64)
        context = cipher.create_context(master_key)

        plaintext = b'\xff' * 64
        ciphertext = cipher.encrypt_block(plaintext, context)

        assert ciphertext != plaintext

        decrypted = cipher.decrypt_block(ciphertext, context)
        assert decrypted == plaintext

    def test_different_keys_produce_different_ciphertext(self):
        """Test that different keys produce different ciphertexts"""
        cipher = Cipher512()
        plaintext = os.urandom(64)

        key1 = os.urandom(64)
        key2 = os.urandom(64)

        context1 = cipher.create_context(key1)
        context2 = cipher.create_context(key2)

        ciphertext1 = cipher.encrypt_block(plaintext, context1)
        ciphertext2 = cipher.encrypt_block(plaintext, context2)

        assert ciphertext1 != ciphertext2

    def test_avalanche_effect(self):
        """Test avalanche effect: small input change causes large output change"""
        cipher = Cipher512()
        master_key = os.urandom(64)
        context = cipher.create_context(master_key)

        plaintext1 = os.urandom(64)
        plaintext2 = bytearray(plaintext1)
        plaintext2[0] ^= 0x01  # Flip one bit
        plaintext2 = bytes(plaintext2)

        ciphertext1 = cipher.encrypt_block(plaintext1, context)
        ciphertext2 = cipher.encrypt_block(plaintext2, context)

        # Count different bits
        diff_bits = sum(bin(b1 ^ b2).count('1') for b1, b2 in zip(ciphertext1, ciphertext2))

        # Avalanche effect: ~50% of bits should change (256 ± 50 bits for 512-bit block)
        assert diff_bits > 200 and diff_bits < 312, f"Avalanche effect insufficient: {diff_bits} bits changed"


class TestCipher512CBC:
    """Tests for CBC mode encryption/decryption"""

    def test_cbc_encrypt_decrypt_single_block(self):
        """Test CBC mode with single block"""
        cipher = Cipher512()
        master_key = os.urandom(64)
        context = cipher.create_context(master_key)

        plaintext = os.urandom(64)

        ciphertext = cipher.encrypt(plaintext, context)
        decrypted = cipher.decrypt(ciphertext, context)

        assert decrypted == plaintext

    def test_cbc_encrypt_decrypt_multiple_blocks(self):
        """Test CBC mode with multiple blocks"""
        cipher = Cipher512()
        master_key = os.urandom(64)
        context = cipher.create_context(master_key)

        # 5 blocks
        plaintext = os.urandom(64 * 5)

        ciphertext = cipher.encrypt(plaintext, context)
        decrypted = cipher.decrypt(ciphertext, context)

        assert decrypted == plaintext

    def test_cbc_padding(self):
        """Test that padding is handled correctly"""
        cipher = Cipher512()
        master_key = os.urandom(64)
        context = cipher.create_context(master_key)

        # Non-block-aligned data
        plaintext = os.urandom(100)

        ciphertext = cipher.encrypt(plaintext, context)
        decrypted = cipher.decrypt(ciphertext, context)

        assert decrypted == plaintext

    def test_cbc_empty_input(self):
        """Test CBC mode with empty input"""
        cipher = Cipher512()
        master_key = os.urandom(64)
        context = cipher.create_context(master_key)

        plaintext = b""

        ciphertext = cipher.encrypt(plaintext, context)
        decrypted = cipher.decrypt(ciphertext, context)

        assert decrypted == plaintext


class TestCipher512EdgeCases:
    """Edge case tests"""

    def test_same_plaintext_different_contexts(self):
        """Test same plaintext with different contexts produces different ciphertext"""
        cipher = Cipher512()
        plaintext = os.urandom(64)
        key = os.urandom(64)

        # Different IVs
        iv1 = os.urandom(64)
        iv2 = os.urandom(64)

        context1 = cipher.create_context(key, iv=iv1)
        context2 = cipher.create_context(key, iv=iv2)

        ciphertext1 = cipher.encrypt_block(plaintext, context1)
        ciphertext2 = cipher.encrypt_block(plaintext, context2)

        # Different IVs should produce different S-boxes, thus different ciphertexts
        assert ciphertext1 != ciphertext2

    def test_large_data_encryption(self):
        """Test encryption of large data"""
        cipher = Cipher512()
        master_key = os.urandom(64)
        context = cipher.create_context(master_key)

        # 1 MB of data
        plaintext = os.urandom(1024 * 1024)

        ciphertext = cipher.encrypt(plaintext, context)
        decrypted = cipher.decrypt(ciphertext, context)

        assert decrypted == plaintext


class TestCipher512Properties:
    """Property-based and statistical tests"""

    def test_ciphertext_randomness(self):
        """Test that ciphertext appears random"""
        cipher = Cipher512()
        master_key = os.urandom(64)
        context = cipher.create_context(master_key)

        # Encrypt all-zero plaintext
        plaintext = b'\x00' * 64
        ciphertext = cipher.encrypt_block(plaintext, context)

        # Count byte frequency
        byte_counts = [0] * 256
        for byte in ciphertext:
            byte_counts[byte] += 1

        # No byte should appear too frequently (chi-square test approximation)
        # For 64 bytes, each byte value should appear ~0.25 times on average
        max_count = max(byte_counts)
        assert max_count <= 4, "Ciphertext lacks randomness"

    def test_round_constants_uniqueness(self):
        """Test that round constants are unique"""
        cipher = Cipher512()
        assert len(set(cipher.ROUND_CONSTANTS)) == len(cipher.ROUND_CONSTANTS)

    def test_encryption_invertibility(self):
        """Test that encryption is fully invertible for many random inputs"""
        cipher = Cipher512()
        master_key = os.urandom(64)
        context = cipher.create_context(master_key)

        for _ in range(10):
            plaintext = os.urandom(64)
            ciphertext = cipher.encrypt_block(plaintext, context)
            decrypted = cipher.decrypt_block(ciphertext, context)
            assert decrypted == plaintext


class TestCipher512KnownAnswers:
    """Known-answer tests (KAT) with predefined test vectors"""

    def test_known_vector_1(self):
        """Test with known test vector 1"""
        cipher = Cipher512()

        # Known key
        master_key = bytes([i & 0xFF for i in range(64)])
        iv = bytes([0x55] * 64)
        context = cipher.create_context(master_key, iv=iv)

        # Known plaintext
        plaintext = bytes([0xAA] * 64)

        # Encrypt
        ciphertext = cipher.encrypt_block(plaintext, context)

        # This should produce consistent results
        # (We don't have a reference implementation, so we just check invertibility)
        decrypted = cipher.decrypt_block(ciphertext, context)
        assert decrypted == plaintext

    def test_known_vector_2(self):
        """Test with known test vector 2"""
        cipher = Cipher512()

        # Known key (incremental pattern)
        master_key = bytes([(i * 3) & 0xFF for i in range(64)])
        iv = bytes([0x00] * 64)
        context = cipher.create_context(master_key, iv=iv)

        # Known plaintext (pattern)
        plaintext = bytes([i & 0xFF for i in range(64)])

        ciphertext = cipher.encrypt_block(plaintext, context)
        decrypted = cipher.decrypt_block(ciphertext, context)

        assert decrypted == plaintext


class TestCipher512Performance:
    """Performance-related tests"""

    def test_encryption_speed(self):
        """Basic encryption speed test"""
        import time

        cipher = Cipher512()
        master_key = os.urandom(64)
        context = cipher.create_context(master_key)
        plaintext = os.urandom(64 * 1000)  # 64KB

        start = time.time()
        ciphertext = cipher.encrypt(plaintext, context)
        end = time.time()

        elapsed = end - start
        throughput = len(plaintext) / elapsed / 1024  # KB/s

        # Should be reasonably fast (>10 KB/s even without optimization)
        assert throughput > 10, f"Encryption too slow: {throughput:.2f} KB/s"
        print(f"Encryption throughput: {throughput:.2f} KB/s")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
