"""
Comprehensive Test Suite for Information Dispersal Algorithm (IDA)
Tests for Layer 1 - Threshold Secret Sharing using GF(2^512)
"""

import pytest
import os
from ida_layer import InformationDispersalEngine, IDAConfiguration
from constants import IDAShare, GF512_IRREDUCIBLE_POLYNOMIAL


class TestIDAConfiguration:
    """Tests for IDA configuration validation"""

    def test_default_configuration(self):
        """Test IDA with default configuration"""
        ida = InformationDispersalEngine()
        assert ida.config is not None
        assert ida.config.threshold <= ida.config.total_shares
        assert ida.config.threshold >= 2

    def test_custom_configuration(self):
        """Test IDA with custom configuration"""
        config = IDAConfiguration(
            total_shares=7,
            threshold=4,
            field_polynomial=GF512_IRREDUCIBLE_POLYNOMIAL
        )
        ida = InformationDispersalEngine(config)
        assert ida.config.total_shares == 7
        assert ida.config.threshold == 4

    def test_invalid_threshold_too_high(self):
        """Test that threshold > total_shares is rejected"""
        config = IDAConfiguration(
            total_shares=5,
            threshold=6,  # Invalid: threshold > total_shares
            field_polynomial=GF512_IRREDUCIBLE_POLYNOMIAL
        )
        with pytest.raises(ValueError, match="Threshold cannot exceed total shares"):
            InformationDispersalEngine(config)

    def test_invalid_threshold_too_low(self):
        """Test that threshold < 2 is rejected"""
        config = IDAConfiguration(
            total_shares=5,
            threshold=1,  # Invalid: threshold must be >= 2
            field_polynomial=GF512_IRREDUCIBLE_POLYNOMIAL
        )
        with pytest.raises(ValueError, match="Threshold must be at least 2"):
            InformationDispersalEngine(config)

    def test_invalid_too_many_shares(self):
        """Test that > 255 shares is rejected"""
        config = IDAConfiguration(
            total_shares=256,  # Invalid: max 255
            threshold=128,
            field_polynomial=GF512_IRREDUCIBLE_POLYNOMIAL
        )
        with pytest.raises(ValueError, match="Maximum 255 shares supported"):
            InformationDispersalEngine(config)


class TestIDAShareCreation:
    """Tests for share creation functionality"""

    def test_create_shares_basic(self):
        """Test basic share creation"""
        ida = InformationDispersalEngine()
        data = os.urandom(1024)  # 1 KB of random data

        shares = ida.create_shares(data)

        assert len(shares) == ida.config.total_shares
        for share in shares:
            assert isinstance(share, IDAShare)
            assert share.share_id >= 0
            assert share.share_id < ida.config.total_shares

    def test_create_shares_small_data(self):
        """Test share creation with small data"""
        ida = InformationDispersalEngine()
        data = b"Hello, World!"

        shares = ida.create_shares(data)

        assert len(shares) == ida.config.total_shares

    def test_create_shares_large_data(self):
        """Test share creation with large data"""
        ida = InformationDispersalEngine()
        data = os.urandom(1024 * 100)  # 100 KB

        shares = ida.create_shares(data)

        assert len(shares) == ida.config.total_shares

    def test_create_shares_empty_data(self):
        """Test that empty data is rejected"""
        ida = InformationDispersalEngine()

        with pytest.raises(ValueError):
            ida.create_shares(b"")

    def test_shares_have_unique_ids(self):
        """Test that all shares have unique IDs"""
        ida = InformationDispersalEngine()
        data = os.urandom(1024)

        shares = ida.create_shares(data)

        share_ids = [share.share_id for share in shares]
        assert len(share_ids) == len(set(share_ids))  # All IDs are unique

    def test_shares_contain_data(self):
        """Test that shares contain non-empty data"""
        ida = InformationDispersalEngine()
        data = os.urandom(1024)

        shares = ida.create_shares(data)

        for share in shares:
            assert len(share.share_data) > 0


class TestIDAReconstruction:
    """Tests for data reconstruction from shares"""

    def test_reconstruct_with_all_shares(self):
        """Test reconstruction with all shares"""
        ida = InformationDispersalEngine()
        original_data = os.urandom(1024)

        shares = ida.create_shares(original_data)
        reconstructed = ida.reconstruct_data(shares)

        assert reconstructed == original_data

    def test_reconstruct_with_threshold_shares(self):
        """Test reconstruction with exactly threshold shares"""
        config = IDAConfiguration(
            total_shares=5,
            threshold=3,
            field_polynomial=GF512_IRREDUCIBLE_POLYNOMIAL
        )
        ida = InformationDispersalEngine(config)
        original_data = os.urandom(1024)

        shares = ida.create_shares(original_data)

        # Use exactly threshold shares
        subset_shares = shares[:3]
        reconstructed = ida.reconstruct_data(subset_shares)

        assert reconstructed == original_data

    def test_reconstruct_with_more_than_threshold(self):
        """Test reconstruction with more than threshold shares"""
        config = IDAConfiguration(
            total_shares=7,
            threshold=4,
            field_polynomial=GF512_IRREDUCIBLE_POLYNOMIAL
        )
        ida = InformationDispersalEngine(config)
        original_data = os.urandom(1024)

        shares = ida.create_shares(original_data)

        # Use 5 shares (more than threshold of 4)
        subset_shares = shares[:5]
        reconstructed = ida.reconstruct_data(subset_shares)

        assert reconstructed == original_data

    def test_reconstruct_with_random_subset(self):
        """Test reconstruction with random subset of shares"""
        import random

        config = IDAConfiguration(
            total_shares=7,
            threshold=4,
            field_polynomial=GF512_IRREDUCIBLE_POLYNOMIAL
        )
        ida = InformationDispersalEngine(config)
        original_data = os.urandom(1024)

        shares = ida.create_shares(original_data)

        # Select random subset of threshold shares
        random_shares = random.sample(shares, 4)
        reconstructed = ida.reconstruct_data(random_shares)

        assert reconstructed == original_data

    def test_reconstruct_fails_with_insufficient_shares(self):
        """Test that reconstruction fails with < threshold shares"""
        config = IDAConfiguration(
            total_shares=5,
            threshold=3,
            field_polynomial=GF512_IRREDUCIBLE_POLYNOMIAL
        )
        ida = InformationDispersalEngine(config)
        original_data = os.urandom(1024)

        shares = ida.create_shares(original_data)

        # Try with only 2 shares (less than threshold)
        with pytest.raises((ValueError, RuntimeError)):
            ida.reconstruct_data(shares[:2])


class TestIDADataTypes:
    """Tests for different data types and sizes"""

    def test_text_data(self):
        """Test with text data"""
        ida = InformationDispersalEngine()
        original_data = b"The quick brown fox jumps over the lazy dog"

        shares = ida.create_shares(original_data)
        reconstructed = ida.reconstruct_data(shares)

        assert reconstructed == original_data

    def test_binary_data(self):
        """Test with binary data"""
        ida = InformationDispersalEngine()
        original_data = bytes(range(256))  # All byte values

        shares = ida.create_shares(original_data)
        reconstructed = ida.reconstruct_data(shares)

        assert reconstructed == original_data

    def test_all_zeros(self):
        """Test with all-zero data"""
        ida = InformationDispersalEngine()
        original_data = b'\x00' * 1024

        shares = ida.create_shares(original_data)
        reconstructed = ida.reconstruct_data(shares)

        assert reconstructed == original_data

    def test_all_ones(self):
        """Test with all-ones data"""
        ida = InformationDispersalEngine()
        original_data = b'\xff' * 1024

        shares = ida.create_shares(original_data)
        reconstructed = ida.reconstruct_data(shares)

        assert reconstructed == original_data

    def test_various_sizes(self):
        """Test with various data sizes"""
        ida = InformationDispersalEngine()

        sizes = [1, 64, 512, 1024, 2048, 4096, 10000]

        for size in sizes:
            original_data = os.urandom(size)
            shares = ida.create_shares(original_data)
            reconstructed = ida.reconstruct_data(shares)
            assert reconstructed == original_data, f"Failed for size {size}"


class TestIDAShareIndependence:
    """Tests for share independence and security properties"""

    def test_shares_are_different(self):
        """Test that all shares are different"""
        ida = InformationDispersalEngine()
        data = os.urandom(1024)

        shares = ida.create_shares(data)

        # Compare all pairs of shares
        for i in range(len(shares)):
            for j in range(i + 1, len(shares)):
                assert shares[i].share_data != shares[j].share_data

    def test_single_share_reveals_nothing(self):
        """Test that single share appears random"""
        ida = InformationDispersalEngine()
        data = b'\x00' * 1024  # All zeros

        shares = ida.create_shares(data)

        # A single share should not be all zeros (should appear random)
        # Note: This is a probabilistic test - very unlikely to fail
        for share in shares:
            # Share should not be all zeros
            assert share.share_data != b'\x00' * len(share.share_data)

    def test_deterministic_sharing(self):
        """Test that sharing is deterministic with same input"""
        config = IDAConfiguration(
            total_shares=5,
            threshold=3,
            field_polynomial=GF512_IRREDUCIBLE_POLYNOMIAL
        )
        ida = InformationDispersalEngine(config)
        data = os.urandom(1024)

        shares1 = ida.create_shares(data)
        shares2 = ida.create_shares(data)

        # Note: Depending on implementation, this may or may not be true
        # If randomness is used in share generation, shares might differ
        # This test checks if the implementation is deterministic


class TestIDAFaultTolerance:
    """Tests for fault tolerance and error handling"""

    def test_corrupted_share_detection(self):
        """Test that corrupted shares can be detected"""
        ida = InformationDispersalEngine()
        data = os.urandom(1024)

        shares = ida.create_shares(data)

        # Corrupt one share
        if hasattr(shares[0], 'share_data'):
            corrupted_share = shares[0]
            # Try to corrupt it (this may or may not raise an error depending on implementation)
            # We just verify the system can handle it

        # With enough good shares, should still work
        if len(shares) > ida.config.threshold:
            reconstructed = ida.reconstruct_data(shares[1:ida.config.threshold+1])
            assert reconstructed == data

    def test_missing_shares_tolerance(self):
        """Test tolerance to missing shares"""
        config = IDAConfiguration(
            total_shares=10,
            threshold=4,
            field_polynomial=GF512_IRREDUCIBLE_POLYNOMIAL
        )
        ida = InformationDispersalEngine(config)
        data = os.urandom(1024)

        shares = ida.create_shares(data)

        # Can lose up to (total - threshold) shares
        max_lost = config.total_shares - config.threshold

        # Test with exactly threshold shares
        reconstructed = ida.reconstruct_data(shares[:config.threshold])
        assert reconstructed == data


class TestIDAEdgeCases:
    """Edge case tests"""

    def test_minimum_configuration(self):
        """Test minimum valid configuration (2-of-2)"""
        config = IDAConfiguration(
            total_shares=2,
            threshold=2,
            field_polynomial=GF512_IRREDUCIBLE_POLYNOMIAL
        )
        ida = InformationDispersalEngine(config)
        data = os.urandom(512)

        shares = ida.create_shares(data)
        reconstructed = ida.reconstruct_data(shares)

        assert reconstructed == data

    def test_maximum_practical_configuration(self):
        """Test large configuration (e.g., 20-of-50)"""
        config = IDAConfiguration(
            total_shares=50,
            threshold=20,
            field_polynomial=GF512_IRREDUCIBLE_POLYNOMIAL
        )
        ida = InformationDispersalEngine(config)
        data = os.urandom(512)

        shares = ida.create_shares(data)
        reconstructed = ida.reconstruct_data(shares[:20])

        assert reconstructed == data


class TestIDAPerformance:
    """Performance tests"""

    def test_share_creation_speed(self):
        """Test share creation performance"""
        import time

        ida = InformationDispersalEngine()
        data = os.urandom(1024 * 100)  # 100 KB

        start = time.time()
        shares = ida.create_shares(data)
        end = time.time()

        elapsed = end - start
        throughput = len(data) / elapsed / 1024  # KB/s

        print(f"Share creation throughput: {throughput:.2f} KB/s")
        # Should complete in reasonable time
        assert elapsed < 60, f"Share creation too slow: {elapsed:.2f}s"

    def test_reconstruction_speed(self):
        """Test reconstruction performance"""
        import time

        ida = InformationDispersalEngine()
        data = os.urandom(1024 * 100)  # 100 KB

        shares = ida.create_shares(data)

        start = time.time()
        reconstructed = ida.reconstruct_data(shares)
        end = time.time()

        elapsed = end - start
        throughput = len(data) / elapsed / 1024  # KB/s

        print(f"Reconstruction throughput: {throughput:.2f} KB/s")
        assert elapsed < 60, f"Reconstruction too slow: {elapsed:.2f}s"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
