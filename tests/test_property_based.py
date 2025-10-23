"""
Property-Based Testing Suite for All Cryptographic Layers
Uses hypothesis for property-based testing of cryptographic primitives
"""

import pytest
import os
from hypothesis import given, strategies as st, settings, assume

# Import all layer engines
from custom_cipher import Cipher512
from otp_layer import OneTimePadEngine, OTPConfiguration
from ida_layer import InformationDispersalEngine, IDAConfiguration
from mlkem_layer import PostQuantumMLKEM
from crypto_utils import compute_sha3_512, secure_random_bytes


# Custom strategies for cryptographic testing
@st.composite
def crypto_bytes(draw, min_size=1, max_size=1024):
    """Generate random byte strings for crypto testing"""
    size = draw(st.integers(min_value=min_size, max_value=max_size))
    return draw(st.binary(min_size=size, max_size=size))


@st.composite
def key_512bit(draw):
    """Generate 512-bit (64-byte) keys"""
    return draw(st.binary(min_size=64, max_size=64))


class TestCipher512Properties:
    """Property-based tests for Custom 512-bit Cipher"""

    @given(plaintext=crypto_bytes(min_size=1, max_size=1024))
    @settings(max_examples=50, deadline=None)
    def test_encrypt_decrypt_roundtrip(self, plaintext):
        """Property: Encrypt(Decrypt(x)) == x for all x"""
        cipher = Cipher512()
        master_key = os.urandom(64)
        context = cipher.create_context(master_key)

        # Encrypt and decrypt
        ciphertext = cipher.encrypt(plaintext, context)
        recovered = cipher.decrypt(ciphertext, context)

        assert recovered == plaintext

    @given(plaintext=crypto_bytes(min_size=1, max_size=512))
    @settings(max_examples=50, deadline=None)
    def test_ciphertext_differs_from_plaintext(self, plaintext):
        """Property: Ciphertext should differ from plaintext (except by extreme chance)"""
        cipher = Cipher512()
        master_key = os.urandom(64)
        context = cipher.create_context(master_key)

        ciphertext = cipher.encrypt(plaintext, context)

        # Ciphertext should be different from plaintext (with very high probability)
        # Allow for edge case where plaintext is very short
        if len(plaintext) > 10:
            assert ciphertext != plaintext

    @given(plaintext=crypto_bytes(min_size=1, max_size=512))
    @settings(max_examples=50, deadline=None)
    def test_different_keys_produce_different_ciphertexts(self, plaintext):
        """Property: Same plaintext with different keys produces different ciphertexts"""
        cipher = Cipher512()

        key1 = os.urandom(64)
        key2 = os.urandom(64)
        assume(key1 != key2)  # Ensure keys are different

        context1 = cipher.create_context(key1)
        context2 = cipher.create_context(key2)

        ciphertext1 = cipher.encrypt(plaintext, context1)
        ciphertext2 = cipher.encrypt(plaintext, context2)

        # Different keys should produce different ciphertexts
        assert ciphertext1 != ciphertext2

    @given(plaintext=crypto_bytes(min_size=1, max_size=512))
    @settings(max_examples=30, deadline=None)
    def test_avalanche_effect(self, plaintext):
        """Property: Small change in plaintext causes large change in ciphertext"""
        if len(plaintext) < 64:  # Need sufficient size for avalanche
            return

        cipher = Cipher512()
        master_key = os.urandom(64)
        context = cipher.create_context(master_key)

        # Original ciphertext
        ciphertext1 = cipher.encrypt(plaintext, context)

        # Flip one bit in plaintext
        modified_plaintext = bytearray(plaintext)
        modified_plaintext[0] ^= 0x01
        ciphertext2 = cipher.encrypt(bytes(modified_plaintext), context)

        # Count differing bits
        diff_bits = sum(bin(b1 ^ b2).count('1') for b1, b2 in zip(ciphertext1, ciphertext2))
        total_bits = len(ciphertext1) * 8

        # Avalanche effect: at least 25% of bits should differ
        assert diff_bits > total_bits * 0.25

    @given(key=key_512bit())
    @settings(max_examples=50, deadline=None)
    def test_key_schedule_deterministic(self, key):
        """Property: Key schedule is deterministic"""
        cipher = Cipher512()
        iv = os.urandom(64)

        context1 = cipher.create_context(key, iv=iv)
        context2 = cipher.create_context(key, iv=iv)

        # Same key and IV should produce same round keys
        assert context1.round_keys == context2.round_keys


class TestOTPProperties:
    """Property-based tests for One-Time Pad Layer"""

    @given(plaintext=crypto_bytes(min_size=1, max_size=1024))
    @settings(max_examples=50, deadline=None)
    def test_otp_encrypt_decrypt_roundtrip(self, plaintext):
        """Property: OTP decryption recovers original plaintext"""
        otp = OneTimePadEngine()

        result = otp.encrypt(plaintext)
        recovered = otp.decrypt(result.ciphertext, result.key_id, result.iv)

        assert recovered == plaintext

    @given(plaintext=crypto_bytes(min_size=1, max_size=512))
    @settings(max_examples=50, deadline=None)
    def test_otp_perfect_secrecy_randomness(self, plaintext):
        """Property: OTP ciphertext should appear random"""
        otp = OneTimePadEngine()

        result = otp.encrypt(plaintext)

        # Ciphertext should have high entropy
        assert result.entropy_estimate > 7.0  # High entropy per byte

    @given(plaintext=crypto_bytes(min_size=1, max_size=512))
    @settings(max_examples=30, deadline=None)
    def test_otp_same_plaintext_different_ciphertext(self, plaintext):
        """Property: Same plaintext produces different ciphertext each time"""
        otp = OneTimePadEngine()

        result1 = otp.encrypt(plaintext)
        result2 = otp.encrypt(plaintext)

        # Different encryptions should use different keys
        assert result1.key_id != result2.key_id
        # And produce different ciphertexts
        assert result1.ciphertext != result2.ciphertext

    @given(plaintext=crypto_bytes(min_size=1, max_size=512))
    @settings(max_examples=50, deadline=None)
    def test_otp_ciphertext_length_matches_plaintext(self, plaintext):
        """Property: OTP ciphertext length equals plaintext length"""
        otp = OneTimePadEngine()

        result = otp.encrypt(plaintext)

        # OTP should preserve length
        assert len(result.ciphertext) == len(plaintext)

    @given(plaintext=crypto_bytes(min_size=10, max_size=512))
    @settings(max_examples=30, deadline=None)
    def test_otp_uniform_distribution(self, plaintext):
        """Property: OTP ciphertext bytes should be uniformly distributed"""
        otp = OneTimePadEngine()

        result = otp.encrypt(plaintext)

        # Count byte frequencies
        frequencies = [0] * 256
        for byte in result.ciphertext:
            frequencies[byte] += 1

        # Check that bytes are reasonably distributed
        # (This is a weak test, but sufficient for property-based testing)
        non_zero_bytes = sum(1 for f in frequencies if f > 0)

        # Expect at least some variety in byte values
        if len(plaintext) > 100:
            assert non_zero_bytes > 50


class TestIDAProperties:
    """Property-based tests for Information Dispersal Algorithm"""

    @given(data=crypto_bytes(min_size=10, max_size=512),
           total_shares=st.integers(min_value=3, max_value=7),
           threshold=st.integers(min_value=2, max_value=5))
    @settings(max_examples=30, deadline=None)
    def test_ida_reconstruction_with_threshold_shares(self, data, total_shares, threshold):
        """Property: Any threshold shares can reconstruct the original data"""
        assume(threshold <= total_shares)
        assume(threshold >= 2)

        config = IDAConfiguration(total_shares=total_shares, threshold=threshold)
        ida = InformationDispersalEngine(config)

        # Create shares
        shares = ida.create_shares(data)
        assert len(shares) == total_shares

        # Reconstruct using exactly threshold shares
        selected_shares = shares[:threshold]
        reconstructed = ida.reconstruct(selected_shares)

        assert reconstructed == data

    @given(data=crypto_bytes(min_size=10, max_size=256))
    @settings(max_examples=30, deadline=None)
    def test_ida_any_threshold_subset_reconstructs(self, data):
        """Property: Any subset of threshold size can reconstruct data"""
        config = IDAConfiguration(total_shares=5, threshold=3)
        ida = InformationDispersalEngine(config)

        shares = ida.create_shares(data)

        # Test different combinations of 3 shares
        test_combinations = [
            [shares[0], shares[1], shares[2]],
            [shares[1], shares[2], shares[3]],
            [shares[2], shares[3], shares[4]],
            [shares[0], shares[2], shares[4]]
        ]

        for share_subset in test_combinations:
            reconstructed = ida.reconstruct(share_subset)
            assert reconstructed == data

    @given(data=crypto_bytes(min_size=10, max_size=256))
    @settings(max_examples=30, deadline=None)
    def test_ida_shares_are_unique(self, data):
        """Property: All shares should be unique"""
        config = IDAConfiguration(total_shares=5, threshold=3)
        ida = InformationDispersalEngine(config)

        shares = ida.create_shares(data)

        # All shares should be different
        share_data_list = [s.share_data for s in shares]
        unique_shares = set(share_data_list)

        assert len(unique_shares) == len(share_data_list)

    @given(data=crypto_bytes(min_size=10, max_size=256))
    @settings(max_examples=30, deadline=None)
    def test_ida_shares_contain_no_plaintext_leakage(self, data):
        """Property: Individual shares should not leak plaintext information"""
        config = IDAConfiguration(total_shares=5, threshold=3)
        ida = InformationDispersalEngine(config)

        shares = ida.create_shares(data)

        # Check that no single share contains the original data
        for share in shares:
            # Share data should not equal the original data
            assert share.share_data != data

            # Share should not contain large contiguous chunks of original data
            # (This is a heuristic test)
            if len(data) > 20:
                for i in range(len(data) - 10):
                    chunk = data[i:i+10]
                    assert chunk not in share.share_data


class TestMLKEMProperties:
    """Property-based tests for ML-KEM Post-Quantum Layer"""

    @settings(max_examples=20, deadline=None)
    @given(st.integers(min_value=0, max_value=100))
    def test_mlkem_keypair_generation_produces_valid_keys(self, seed):
        """Property: Generated keypairs have correct sizes"""
        mlkem = PostQuantumMLKEM()

        keypair = mlkem.generate_keypair()

        assert len(keypair.public_key) == 1568  # ML-KEM-1024 public key size
        assert len(keypair.secret_key) == 3168  # ML-KEM-1024 secret key size

    @settings(max_examples=20, deadline=None)
    @given(st.integers(min_value=0, max_value=100))
    def test_mlkem_encapsulation_produces_valid_sizes(self, seed):
        """Property: Encapsulation produces correct sizes"""
        mlkem = PostQuantumMLKEM()

        keypair = mlkem.generate_keypair()
        result = mlkem.encapsulate(keypair.public_key)

        assert len(result.ciphertext) == 1568  # ML-KEM-1024 ciphertext size
        assert len(result.shared_secret) == 32  # Shared secret size
        assert len(result.expanded_secret) == 64  # 512-bit expanded secret

    @settings(max_examples=15, deadline=None)
    @given(st.integers(min_value=0, max_value=100))
    def test_mlkem_encap_decap_consistency(self, seed):
        """Property: Decapsulation with correct key is consistent"""
        mlkem = PostQuantumMLKEM()

        keypair = mlkem.generate_keypair()
        encap_result = mlkem.encapsulate(keypair.public_key)

        # Decapsulate twice
        secret1 = mlkem.decapsulate(encap_result.ciphertext, keypair.secret_key)
        secret2 = mlkem.decapsulate(encap_result.ciphertext, keypair.secret_key)

        # Should get same result
        assert secret1 == secret2
        assert len(secret1) == 32

    @settings(max_examples=15, deadline=None)
    @given(st.integers(min_value=0, max_value=100))
    def test_mlkem_unique_keypairs(self, seed):
        """Property: Multiple keypair generations produce unique keys"""
        mlkem = PostQuantumMLKEM()

        keypairs = [mlkem.generate_keypair() for _ in range(3)]

        # All public keys should be unique
        public_keys = [kp.public_key for kp in keypairs]
        assert len(set(public_keys)) == len(public_keys)


class TestCryptoUtilsProperties:
    """Property-based tests for cryptographic utilities"""

    @given(data=crypto_bytes(min_size=1, max_size=1024))
    @settings(max_examples=50, deadline=None)
    def test_hash_deterministic(self, data):
        """Property: Hash function is deterministic"""
        hash1 = compute_sha3_512(data)
        hash2 = compute_sha3_512(data)

        assert hash1 == hash2

    @given(data=crypto_bytes(min_size=1, max_size=1024))
    @settings(max_examples=50, deadline=None)
    def test_hash_output_size(self, data):
        """Property: SHA3-512 produces 512-bit output"""
        hash_output = compute_sha3_512(data)

        assert len(hash_output) == 64  # 512 bits / 8 = 64 bytes

    @given(data1=crypto_bytes(min_size=1, max_size=512),
           data2=crypto_bytes(min_size=1, max_size=512))
    @settings(max_examples=50, deadline=None)
    def test_hash_collision_resistance(self, data1, data2):
        """Property: Different inputs produce different hashes (collision resistance)"""
        assume(data1 != data2)

        hash1 = compute_sha3_512(data1)
        hash2 = compute_sha3_512(data2)

        assert hash1 != hash2

    @given(size=st.integers(min_value=1, max_value=1024))
    @settings(max_examples=50, deadline=None)
    def test_secure_random_bytes_size(self, size):
        """Property: secure_random_bytes produces correct size"""
        random_bytes = secure_random_bytes(size)

        assert len(random_bytes) == size

    @given(size=st.integers(min_value=1, max_value=256))
    @settings(max_examples=50, deadline=None)
    def test_secure_random_bytes_uniqueness(self, size):
        """Property: Successive calls produce different random bytes"""
        bytes1 = secure_random_bytes(size)
        bytes2 = secure_random_bytes(size)

        # Should be different with extremely high probability
        if size > 4:
            assert bytes1 != bytes2


class TestCrossLayerProperties:
    """Property-based tests for interactions between layers"""

    @given(plaintext=crypto_bytes(min_size=10, max_size=256))
    @settings(max_examples=20, deadline=None)
    def test_cipher_then_otp_reversible(self, plaintext):
        """Property: Cipher then OTP is reversible"""
        # Layer 4: Custom Cipher
        cipher = Cipher512()
        cipher_key = os.urandom(64)
        cipher_ctx = cipher.create_context(cipher_key)
        ciphertext = cipher.encrypt(plaintext, cipher_ctx)

        # Layer 2: OTP
        otp = OneTimePadEngine()
        otp_result = otp.encrypt(ciphertext)

        # Reverse: OTP then Cipher
        recovered_from_otp = otp.decrypt(otp_result.ciphertext, otp_result.key_id, otp_result.iv)
        recovered_plaintext = cipher.decrypt(recovered_from_otp, cipher_ctx)

        assert recovered_plaintext == plaintext

    @given(data=crypto_bytes(min_size=20, max_size=256))
    @settings(max_examples=15, deadline=None)
    def test_ida_then_otp_reversible(self, data):
        """Property: IDA then OTP is reversible"""
        # Layer 1: IDA
        ida_config = IDAConfiguration(total_shares=5, threshold=3)
        ida = InformationDispersalEngine(ida_config)
        shares = ida.create_shares(data)

        # Layer 2: OTP on each share
        otp = OneTimePadEngine()
        encrypted_shares = []
        otp_results = []

        for share in shares:
            otp_result = otp.encrypt(share.share_data)
            encrypted_shares.append(share)
            otp_results.append(otp_result)

        # Reverse: OTP then IDA
        decrypted_shares = []
        for i, (share, otp_result) in enumerate(zip(shares, otp_results)):
            decrypted_data = otp.decrypt(otp_result.ciphertext, otp_result.key_id, otp_result.iv)
            # Create new share with decrypted data
            from ida_layer import IDAShare
            decrypted_share = IDAShare(
                share_data=decrypted_data,
                share_index=share.share_index,
                threshold=share.threshold
            )
            decrypted_shares.append(decrypted_share)

        # Use threshold shares to reconstruct
        reconstructed = ida.reconstruct(decrypted_shares[:3])

        assert reconstructed == data


class TestSecurityProperties:
    """Property-based tests for security guarantees"""

    @given(plaintext=crypto_bytes(min_size=10, max_size=256))
    @settings(max_examples=30, deadline=None)
    def test_encryption_hides_plaintext_patterns(self, plaintext):
        """Property: Encryption should hide patterns in plaintext"""
        cipher = Cipher512()
        key = os.urandom(64)
        ctx = cipher.create_context(key)

        ciphertext = cipher.encrypt(plaintext, ctx)

        # Ciphertext should not contain obvious plaintext patterns
        # Check that repeated bytes in plaintext don't appear repeated in ciphertext
        if len(plaintext) > 50:
            # Find repeated patterns in plaintext
            for i in range(len(plaintext) - 10):
                pattern = plaintext[i:i+5]
                if plaintext.count(pattern) > 1:
                    # Check that this pattern doesn't repeat in ciphertext
                    # (with high probability)
                    ct_pattern = ciphertext[i:i+5]
                    assert ciphertext.count(ct_pattern) <= 2  # Allow some coincidence

    @given(data=crypto_bytes(min_size=10, max_size=256))
    @settings(max_examples=30, deadline=None)
    def test_otp_provides_perfect_secrecy(self, data):
        """Property: OTP ciphertext reveals no information about plaintext"""
        otp = OneTimePadEngine()

        result = otp.encrypt(data)

        # High entropy indicates no information leakage
        assert result.entropy_estimate > 7.5  # Near maximum entropy

        # Ciphertext should not contain plaintext
        if len(data) > 10:
            assert data not in result.ciphertext


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
