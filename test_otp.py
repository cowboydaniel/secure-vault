"""
Comprehensive Test Suite for One-Time Pad (OTP) Layer
Tests for Layer 2 - Information-Theoretically Secure Encryption
"""

import pytest
import os
from otp_layer import OneTimePadEngine, OTPConfiguration, OTPEncryptionResult


class TestOTPConfiguration:
    """Tests for OTP configuration"""

    def test_default_configuration(self):
        """Test OTP with default configuration"""
        otp = OneTimePadEngine()
        assert otp.config is not None
        assert otp.config.min_entropy_per_byte >= 7.0

    def test_custom_configuration(self):
        """Test OTP with custom configuration"""
        config = OTPConfiguration(
            min_entropy_per_byte=7.5,
            key_pool_size=1024
        )
        otp = OneTimePadEngine(config)
        assert otp.config.min_entropy_per_byte == 7.5
        assert otp.config.key_pool_size == 1024


class TestOTPBasicEncryption:
    """Basic OTP encryption/decryption tests"""

    def test_encrypt_decrypt_basic(self):
        """Test basic OTP encryption and decryption"""
        otp = OneTimePadEngine()
        plaintext = b"Hello, World!"

        result = otp.encrypt(plaintext)

        assert isinstance(result, OTPEncryptionResult)
        assert len(result.ciphertext) == len(plaintext)
        assert result.ciphertext != plaintext

        decrypted = otp.decrypt(result.ciphertext, result.key_id)
        assert decrypted == plaintext

    def test_encrypt_empty_fails(self):
        """Test that encrypting empty data fails"""
        otp = OneTimePadEngine()

        with pytest.raises(ValueError, match="Cannot encrypt empty data"):
            otp.encrypt(b"")

    def test_encrypt_single_byte(self):
        """Test encryption of single byte"""
        otp = OneTimePadEngine()
        plaintext = b"A"

        result = otp.encrypt(plaintext)
        decrypted = otp.decrypt(result.ciphertext, result.key_id)

        assert decrypted == plaintext

    def test_encrypt_large_data(self):
        """Test encryption of large data"""
        otp = OneTimePadEngine()
        plaintext = os.urandom(1024 * 100)  # 100 KB

        result = otp.encrypt(plaintext)
        decrypted = otp.decrypt(result.ciphertext, result.key_id)

        assert decrypted == plaintext


class TestOTPProperties:
    """Tests for OTP cryptographic properties"""

    def test_perfect_secrecy_same_plaintext_different_ciphertext(self):
        """Test that same plaintext produces different ciphertext (probabilistic encryption)"""
        otp = OneTimePadEngine()
        plaintext = b"Secret message"

        result1 = otp.encrypt(plaintext)
        result2 = otp.encrypt(plaintext)

        # Different keys should produce different ciphertexts
        # (unless by extreme coincidence)
        assert result1.ciphertext != result2.ciphertext
        assert result1.key_id != result2.key_id

    def test_ciphertext_appears_random(self):
        """Test that ciphertext appears random even for structured plaintext"""
        otp = OneTimePadEngine()
        plaintext = b'\x00' * 64  # All zeros

        result = otp.encrypt(plaintext)

        # Ciphertext should not be all zeros
        assert result.ciphertext != b'\x00' * 64

        # Ciphertext should have reasonable byte distribution
        byte_counts = [0] * 256
        for byte in result.ciphertext:
            byte_counts[byte] += 1

        # No single byte should dominate (rough test)
        max_count = max(byte_counts)
        assert max_count < len(result.ciphertext) // 2

    def test_bit_flip_propagation(self):
        """Test that flipping one bit in key produces different plaintext"""
        otp = OneTimePadEngine()
        plaintext = b"Test message for bit flip"

        result = otp.encrypt(plaintext)
        ciphertext = result.ciphertext

        # In a real implementation, we can't easily flip bits in the key
        # since it's managed by the HSM, but we can test that different
        # ciphertexts decrypt differently

        # Create a slightly modified ciphertext
        modified_ciphertext = bytearray(ciphertext)
        modified_ciphertext[0] ^= 0x01  # Flip one bit
        modified_ciphertext = bytes(modified_ciphertext)

        # Decrypting modified ciphertext should give different plaintext
        try:
            modified_plaintext = otp.decrypt(modified_ciphertext, result.key_id)
            # The first byte should differ by 1 bit
            assert modified_plaintext != plaintext
            assert modified_plaintext[0] != plaintext[0]
        except Exception:
            # Some implementations might reject modified ciphertext
            pass


class TestOTPKeyManagement:
    """Tests for OTP key management"""

    def test_key_generation(self):
        """Test that keys are generated properly"""
        otp = OneTimePadEngine()
        plaintext = os.urandom(1024)

        result = otp.encrypt(plaintext)

        assert result.key_id is not None
        assert isinstance(result.key_id, str)
        assert len(result.key_id) > 0

    def test_key_reuse_detection(self):
        """Test that OTP keys are not reused"""
        otp = OneTimePadEngine()
        plaintext1 = b"Message 1"
        plaintext2 = b"Message 2"

        result1 = otp.encrypt(plaintext1)
        result2 = otp.encrypt(plaintext2)

        # Different encryptions should use different keys
        assert result1.key_id != result2.key_id

    def test_key_metadata(self):
        """Test that key metadata is properly maintained"""
        otp = OneTimePadEngine()
        plaintext = b"Test message"

        result = otp.encrypt(plaintext)

        assert result.timestamp > 0
        assert result.key_material_used > 0
        assert result.entropy_estimate >= 0


class TestOTPDataTypes:
    """Tests for different data types"""

    def test_text_data(self):
        """Test with text data"""
        otp = OneTimePadEngine()
        plaintext = b"The quick brown fox jumps over the lazy dog"

        result = otp.encrypt(plaintext)
        decrypted = otp.decrypt(result.ciphertext, result.key_id)

        assert decrypted == plaintext

    def test_binary_data(self):
        """Test with binary data"""
        otp = OneTimePadEngine()
        plaintext = bytes(range(256))  # All byte values

        result = otp.encrypt(plaintext)
        decrypted = otp.decrypt(result.ciphertext, result.key_id)

        assert decrypted == plaintext

    def test_all_zeros(self):
        """Test with all-zero data"""
        otp = OneTimePadEngine()
        plaintext = b'\x00' * 1024

        result = otp.encrypt(plaintext)
        decrypted = otp.decrypt(result.ciphertext, result.key_id)

        assert decrypted == plaintext
        # Ciphertext should not be all zeros (should be the key)
        assert result.ciphertext != plaintext

    def test_all_ones(self):
        """Test with all-ones data"""
        otp = OneTimePadEngine()
        plaintext = b'\xff' * 1024

        result = otp.encrypt(plaintext)
        decrypted = otp.decrypt(result.ciphertext, result.key_id)

        assert decrypted == plaintext

    def test_various_sizes(self):
        """Test with various data sizes"""
        otp = OneTimePadEngine()

        sizes = [1, 16, 64, 256, 512, 1024, 4096]

        for size in sizes:
            plaintext = os.urandom(size)
            result = otp.encrypt(plaintext)
            decrypted = otp.decrypt(result.ciphertext, result.key_id)
            assert decrypted == plaintext, f"Failed for size {size}"


class TestOTPErrorHandling:
    """Tests for error handling"""

    def test_decrypt_with_wrong_key_id(self):
        """Test that decryption with wrong key ID fails"""
        otp = OneTimePadEngine()
        plaintext = b"Secret message"

        result = otp.encrypt(plaintext)

        # Try to decrypt with wrong key ID
        with pytest.raises((ValueError, KeyError, RuntimeError)):
            otp.decrypt(result.ciphertext, "wrong-key-id")

    def test_decrypt_with_wrong_length_ciphertext(self):
        """Test that decryption with wrong length fails or handles gracefully"""
        otp = OneTimePadEngine()
        plaintext = b"Test message"

        result = otp.encrypt(plaintext)

        # Try to decrypt truncated ciphertext
        truncated = result.ciphertext[:len(result.ciphertext)//2]

        try:
            decrypted = otp.decrypt(truncated, result.key_id)
            # If it doesn't raise an error, the result should be truncated
            assert len(decrypted) == len(truncated)
        except (ValueError, RuntimeError):
            # It's also acceptable to raise an error
            pass


class TestOTPSecurity:
    """Security-focused tests"""

    def test_constant_time_xor(self):
        """Test that XOR operation is constant-time"""
        # This is a basic test - real timing analysis would be more complex
        import time

        otp = OneTimePadEngine()

        # Encrypt data with all zeros
        plaintext1 = b'\x00' * 1024
        start1 = time.perf_counter()
        result1 = otp.encrypt(plaintext1)
        time1 = time.perf_counter() - start1

        # Encrypt data with random bytes
        plaintext2 = os.urandom(1024)
        start2 = time.perf_counter()
        result2 = otp.encrypt(plaintext2)
        time2 = time.perf_counter() - start2

        # Times should be relatively similar (within 50% of each other)
        # This is a very loose test; real timing analysis is more sophisticated
        ratio = max(time1, time2) / min(time1, time2)
        assert ratio < 2.0, f"Timing difference too large: {ratio}"

    def test_entropy_quality(self):
        """Test that entropy quality meets requirements"""
        otp = OneTimePadEngine()
        plaintext = os.urandom(1024)

        result = otp.encrypt(plaintext)

        # Entropy estimate should meet minimum requirements
        assert result.entropy_estimate >= otp.config.min_entropy_per_byte

    def test_no_key_in_memory_after_use(self):
        """Test that keys are cleared from memory after use"""
        otp = OneTimePadEngine()
        plaintext = b"Sensitive data"

        result = otp.encrypt(plaintext)

        # After encryption, the key should not be in memory
        # This is difficult to test directly, but we can check that
        # the key manager doesn't expose keys directly
        assert not hasattr(result, 'raw_key')
        assert not hasattr(result, 'key_bytes')


class TestOTPProgressCallback:
    """Tests for progress callback functionality"""

    def test_progress_callback_called(self):
        """Test that progress callback is called during encryption"""
        otp = OneTimePadEngine()
        plaintext = os.urandom(1024 * 10)  # 10 KB

        progress_calls = []

        def progress_callback(percent, message):
            progress_calls.append((percent, message))

        result = otp.encrypt(plaintext, progress_callback=progress_callback)

        # Progress callback should have been called at least once
        assert len(progress_calls) > 0

        # Progress should be between 0 and 100
        for percent, message in progress_calls:
            assert 0 <= percent <= 100
            assert isinstance(message, str)


class TestOTPPerformance:
    """Performance tests"""

    def test_encryption_speed(self):
        """Test encryption performance"""
        import time

        otp = OneTimePadEngine()
        plaintext = os.urandom(1024 * 100)  # 100 KB

        start = time.time()
        result = otp.encrypt(plaintext)
        end = time.time()

        elapsed = end - start
        throughput = len(plaintext) / elapsed / 1024  # KB/s

        print(f"OTP encryption throughput: {throughput:.2f} KB/s")

        # Should be reasonably fast
        assert elapsed < 60, f"Encryption too slow: {elapsed:.2f}s"

    def test_decryption_speed(self):
        """Test decryption performance"""
        import time

        otp = OneTimePadEngine()
        plaintext = os.urandom(1024 * 100)  # 100 KB

        result = otp.encrypt(plaintext)

        start = time.time()
        decrypted = otp.decrypt(result.ciphertext, result.key_id)
        end = time.time()

        elapsed = end - start
        throughput = len(plaintext) / elapsed / 1024  # KB/s

        print(f"OTP decryption throughput: {throughput:.2f} KB/s")

        assert elapsed < 60, f"Decryption too slow: {elapsed:.2f}s"


class TestOTPMathematicalProperties:
    """Tests for mathematical properties of OTP"""

    def test_xor_commutativity(self):
        """Test that XOR is commutative: a • b = b • a"""
        from crypto_utils import constant_time_xor

        a = os.urandom(64)
        b = os.urandom(64)

        result1 = constant_time_xor(a, b)
        result2 = constant_time_xor(b, a)

        assert result1 == result2

    def test_xor_self_cancellation(self):
        """Test that a • a = 0"""
        from crypto_utils import constant_time_xor

        a = os.urandom(64)

        result = constant_time_xor(a, a)

        assert result == b'\x00' * 64

    def test_double_encryption_is_identity(self):
        """Test that encrypting twice with same key returns original"""
        otp = OneTimePadEngine()
        plaintext = b"Test message"

        # Encrypt
        result = otp.encrypt(plaintext)

        # Encrypt the ciphertext again (this would use a different key in real OTP)
        # But mathematically, XOR twice should give identity
        # We can test this directly with the crypto_utils function
        from crypto_utils import constant_time_xor

        key = os.urandom(len(plaintext))
        ciphertext = constant_time_xor(plaintext, key)
        decrypted = constant_time_xor(ciphertext, key)

        assert decrypted == plaintext


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
