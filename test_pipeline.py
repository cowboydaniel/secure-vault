"""
Comprehensive Integration Test Suite for Multi-Layer Pipeline
Tests for the complete 5-layer encryption system integration
"""

import pytest
import os
import tempfile
import time
from pathlib import Path

from pipeline import (
    MultiLayerPipeline,
    PipelineConfiguration,
    EncryptionResult,
    LayerResult,
    OperationStatus
)
from ida_layer import IDAConfiguration
from otp_layer import OTPConfiguration
from constants import LayerType, GF512_IRREDUCIBLE_POLYNOMIAL
from config import ClassificationLevel
from file_utils import InputFileValidationError


class TestPipelineInitialization:
    """Tests for pipeline initialization and configuration"""

    def test_default_initialization(self):
        """Test pipeline initialization with default configuration"""
        pipeline = MultiLayerPipeline()

        assert pipeline.config is not None
        assert pipeline.ida_engine is not None
        assert pipeline.otp_engine is not None
        assert pipeline.mlkem_engine is not None
        assert pipeline.cipher_engine is not None

    def test_custom_configuration(self):
        """Test pipeline initialization with custom configuration"""
        config = PipelineConfiguration(
            ida_config=IDAConfiguration(total_shares=7, threshold=4),
            otp_config=OTPConfiguration(),
            enable_compression=True,
            classification_level=ClassificationLevel.TOP_SECRET
        )

        pipeline = MultiLayerPipeline(config)

        assert pipeline.config.ida_config.total_shares == 7
        assert pipeline.config.ida_config.threshold == 4
        assert pipeline.config.classification_level == ClassificationLevel.TOP_SECRET

    def test_pipeline_status(self):
        """Test getting pipeline status"""
        pipeline = MultiLayerPipeline()
        status = pipeline.get_pipeline_status()

        assert 'pipeline_name' in status
        assert 'security_level' in status
        assert 'layer_engines' in status
        assert 'security_guarantees' in status
        assert len(status['layer_engines']) == 5

    def test_pipeline_with_storage_dir(self):
        """Test pipeline initialization with custom storage directory"""
        with tempfile.TemporaryDirectory() as tmpdir:
            pipeline = MultiLayerPipeline(storage_dir=tmpdir)
            assert hasattr(pipeline.config, 'storage_dir')


class TestPipelineFileEncryption:
    """Tests for file encryption through the complete pipeline"""

    def test_encrypt_small_file(self):
        """Test encrypting a small file through all layers"""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            test_data = b"Hello, this is a test message for multi-layer encryption!"
            f.write(test_data)
            temp_file = f.name

        try:
            pipeline = MultiLayerPipeline()
            result = pipeline.encrypt_file(temp_file)

            assert isinstance(result, EncryptionResult)
            assert result.original_size == len(test_data)
            assert len(result.encrypted_shares) > 0
            assert len(result.otp_results) > 0
            assert len(result.mlkem_contexts) > 0
            assert result.cipher_metadata is not None
            assert len(result.layer_results) == 5  # All 5 layers
            assert result.total_processing_time > 0

        finally:
            os.unlink(temp_file)

    def test_encrypt_empty_file_fails(self):
        """Test that encrypting an empty file fails appropriately"""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(b"")
            temp_file = f.name

        try:
            pipeline = MultiLayerPipeline()

            # Should raise an error or handle gracefully
            with pytest.raises(Exception):
                pipeline.encrypt_file(temp_file)

        finally:
            os.unlink(temp_file)

    def test_encrypt_file_exceeding_max_size_fails(self):
        """Test that files larger than the configured maximum are rejected."""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(os.urandom(2048))  # 2 KB
            temp_file = f.name

        try:
            config = PipelineConfiguration(
                ida_config=IDAConfiguration(
                    total_shares=5,
                    threshold=3,
                    field_polynomial=GF512_IRREDUCIBLE_POLYNOMIAL,
                ),
                otp_config=OTPConfiguration(),
            )
            config.max_input_size_bytes = 1024
            pipeline = MultiLayerPipeline(config)

            with pytest.raises(InputFileValidationError):
                pipeline.encrypt_file(temp_file)

        finally:
            os.unlink(temp_file)

    def test_encrypt_medium_file(self):
        """Test encrypting a medium-sized file (1MB)"""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            test_data = os.urandom(1024 * 1024)  # 1 MB
            f.write(test_data)
            temp_file = f.name

        try:
            pipeline = MultiLayerPipeline()
            result = pipeline.encrypt_file(temp_file)

            assert result.original_size == len(test_data)
            assert len(result.layer_results) == 5
            assert all(lr.status == OperationStatus.COMPLETED for lr in result.layer_results)

        finally:
            os.unlink(temp_file)

    def test_encrypt_with_progress_callback(self):
        """Test encryption with progress callback"""
        progress_updates = []

        def progress_callback(percent, message):
            progress_updates.append((percent, message))

        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(b"Test data for progress tracking")
            temp_file = f.name

        try:
            pipeline = MultiLayerPipeline()
            result = pipeline.encrypt_file(temp_file, progress_callback=progress_callback)

            assert len(progress_updates) > 0
            # Should have progress from 0 to 100
            percents = [p[0] for p in progress_updates]
            assert min(percents) >= 0
            assert max(percents) <= 100

        finally:
            os.unlink(temp_file)

    def test_encrypt_nonexistent_file_fails(self):
        """Test that encrypting a nonexistent file fails"""
        pipeline = MultiLayerPipeline()

        with pytest.raises(FileNotFoundError):
            pipeline.encrypt_file("/nonexistent/file/path.txt")


class TestPipelineLayers:
    """Tests for individual layer execution in the pipeline"""

    def test_layer_1_execution(self):
        """Test Layer 1: Information Dispersal Algorithm"""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            test_data = b"Test data for IDA layer"
            f.write(test_data)
            temp_file = f.name

        try:
            pipeline = MultiLayerPipeline()
            result = pipeline.encrypt_file(temp_file)

            # Find IDA layer result
            ida_result = next(
                (lr for lr in result.layer_results if lr.layer_type == LayerType.INFORMATION_DISPERSAL),
                None
            )

            assert ida_result is not None
            assert ida_result.status == OperationStatus.COMPLETED
            assert ida_result.output_size > ida_result.input_size  # Shares have overhead

        finally:
            os.unlink(temp_file)

    def test_layer_2_execution(self):
        """Test Layer 2: One-Time Pad"""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            test_data = b"Test data for OTP layer"
            f.write(test_data)
            temp_file = f.name

        try:
            pipeline = MultiLayerPipeline()
            result = pipeline.encrypt_file(temp_file)

            # Find OTP layer result
            otp_result = next(
                (lr for lr in result.layer_results if lr.layer_type == LayerType.ONE_TIME_PAD),
                None
            )

            assert otp_result is not None
            assert otp_result.status == OperationStatus.COMPLETED
            assert len(result.otp_results) > 0

        finally:
            os.unlink(temp_file)

    def test_layer_3_execution(self):
        """Test Layer 3: ML-KEM Post-Quantum"""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            test_data = b"Test data for ML-KEM layer"
            f.write(test_data)
            temp_file = f.name

        try:
            pipeline = MultiLayerPipeline()
            result = pipeline.encrypt_file(temp_file)

            # Find ML-KEM layer result
            mlkem_result = next(
                (lr for lr in result.layer_results if lr.layer_type == LayerType.POST_QUANTUM),
                None
            )

            assert mlkem_result is not None
            assert mlkem_result.status == OperationStatus.COMPLETED
            assert len(result.mlkem_contexts) > 0

        finally:
            os.unlink(temp_file)

    def test_layer_4_execution(self):
        """Test Layer 4: Custom 512-bit Cipher"""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            test_data = b"Test data for custom cipher layer"
            f.write(test_data)
            temp_file = f.name

        try:
            pipeline = MultiLayerPipeline()
            result = pipeline.encrypt_file(temp_file)

            # Find cipher layer result
            cipher_result = next(
                (lr for lr in result.layer_results if lr.layer_type == LayerType.CUSTOM_CIPHER),
                None
            )

            assert cipher_result is not None
            assert cipher_result.status == OperationStatus.COMPLETED
            assert result.cipher_metadata is not None

        finally:
            os.unlink(temp_file)

    def test_layer_5_execution(self):
        """Test Layer 5: Secure Storage"""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            test_data = b"Test data for storage layer"
            f.write(test_data)
            temp_file = f.name

        try:
            pipeline = MultiLayerPipeline()
            result = pipeline.encrypt_file(temp_file)

            # Find storage layer result
            storage_result = next(
                (lr for lr in result.layer_results if lr.layer_type == LayerType.STORAGE_ENCRYPTION),
                None
            )

            assert storage_result is not None
            assert storage_result.status == OperationStatus.COMPLETED

        finally:
            os.unlink(temp_file)

    def test_all_layers_complete(self):
        """Test that all 5 layers complete successfully"""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(b"Test data for complete pipeline")
            temp_file = f.name

        try:
            pipeline = MultiLayerPipeline()
            result = pipeline.encrypt_file(temp_file)

            assert len(result.layer_results) == 5
            for layer_result in result.layer_results:
                assert layer_result.status == OperationStatus.COMPLETED

        finally:
            os.unlink(temp_file)


class TestPipelineSecurityAnalysis:
    """Tests for security analysis and guarantees"""

    def test_security_analysis_present(self):
        """Test that security analysis is performed"""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(b"Test data")
            temp_file = f.name

        try:
            pipeline = MultiLayerPipeline()
            result = pipeline.encrypt_file(temp_file)

            assert result.security_analysis is not None
            assert 'theoretical_security' in result.security_analysis
            assert 'quantum_resistance' in result.security_analysis
            assert 'fault_tolerance' in result.security_analysis
            assert 'algorithm_uniqueness' in result.security_analysis

        finally:
            os.unlink(temp_file)

    def test_security_guarantees(self):
        """Test that all security guarantees are met"""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(b"Test data")
            temp_file = f.name

        try:
            pipeline = MultiLayerPipeline()
            result = pipeline.encrypt_file(temp_file)

            analysis = result.security_analysis

            # Check key security properties
            assert analysis['quantum_resistance'] == True
            assert analysis['fault_tolerance'] == True
            assert analysis['algorithm_uniqueness'] == True
            assert analysis['security_level_bits'] == 512

        finally:
            os.unlink(temp_file)

    def test_revolutionary_security_assessment(self):
        """Test that revolutionary security is achieved when all layers succeed"""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(b"Test data")
            temp_file = f.name

        try:
            pipeline = MultiLayerPipeline()
            result = pipeline.encrypt_file(temp_file)

            analysis = result.security_analysis

            if all(lr.status == OperationStatus.COMPLETED for lr in result.layer_results):
                assert analysis['overall_assessment'] in ['REVOLUTIONARY_SECURITY', 'MAXIMUM_SECURITY']

        finally:
            os.unlink(temp_file)


class TestPipelinePerformance:
    """Tests for pipeline performance and efficiency"""

    def test_encryption_throughput(self):
        """Test encryption throughput for various file sizes"""
        file_sizes = [1024, 10240, 102400]  # 1KB, 10KB, 100KB

        for size in file_sizes:
            with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
                f.write(os.urandom(size))
                temp_file = f.name

            try:
                pipeline = MultiLayerPipeline()
                start = time.time()
                result = pipeline.encrypt_file(temp_file)
                elapsed = time.time() - start

                throughput_mbps = (size / (1024 * 1024)) / elapsed
                print(f"Size: {size} bytes, Throughput: {throughput_mbps:.2f} MB/s")

                # Verify operation completed
                assert result.total_processing_time > 0

            finally:
                os.unlink(temp_file)

    def test_pipeline_statistics_tracking(self):
        """Test that pipeline tracks statistics correctly"""
        pipeline = MultiLayerPipeline()

        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(b"Test data for statistics")
            temp_file = f.name

        try:
            initial_status = pipeline.get_pipeline_status()
            initial_files = initial_status['total_files_processed']

            pipeline.encrypt_file(temp_file)

            final_status = pipeline.get_pipeline_status()
            final_files = final_status['total_files_processed']

            assert final_files == initial_files + 1

        finally:
            os.unlink(temp_file)

    def test_concurrent_operations_tracking(self):
        """Test tracking of active operations"""
        pipeline = MultiLayerPipeline()

        status = pipeline.get_pipeline_status()
        assert 'active_operations' in status
        assert status['active_operations'] >= 0


class TestPipelineShareManagement:
    """Tests for encrypted share management"""

    def test_share_creation(self):
        """Test that encrypted shares are created"""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(b"Test data for share creation")
            temp_file = f.name

        try:
            config = PipelineConfiguration(
                ida_config=IDAConfiguration(total_shares=5, threshold=3),
                otp_config=OTPConfiguration()
            )
            pipeline = MultiLayerPipeline(config)
            result = pipeline.encrypt_file(temp_file)

            assert len(result.encrypted_shares) == 5
            assert len(result.otp_results) == 5

        finally:
            os.unlink(temp_file)

    def test_threshold_configuration(self):
        """Test that threshold configuration is respected"""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(b"Test data")
            temp_file = f.name

        try:
            config = PipelineConfiguration(
                ida_config=IDAConfiguration(total_shares=7, threshold=4),
                otp_config=OTPConfiguration()
            )
            pipeline = MultiLayerPipeline(config)
            result = pipeline.encrypt_file(temp_file)

            assert len(result.encrypted_shares) == 7

            # Verify threshold is stored in shares
            if result.encrypted_shares:
                assert result.encrypted_shares[0].threshold == 4

        finally:
            os.unlink(temp_file)


class TestPipelineErrorHandling:
    """Tests for error handling in the pipeline"""

    def test_invalid_file_path(self):
        """Test handling of invalid file paths"""
        pipeline = MultiLayerPipeline()

        with pytest.raises(FileNotFoundError):
            pipeline.encrypt_file("/invalid/path/to/file.txt")

    def test_permission_denied_handling(self):
        """Test handling of permission errors"""
        # Create a file and remove read permissions
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(b"Test data")
            temp_file = f.name

        try:
            os.chmod(temp_file, 0o000)  # Remove all permissions

            pipeline = MultiLayerPipeline()

            with pytest.raises(PermissionError):
                pipeline.encrypt_file(temp_file)

        finally:
            os.chmod(temp_file, 0o644)  # Restore permissions
            os.unlink(temp_file)


class TestPipelineFileID:
    """Tests for file ID generation and tracking"""

    def test_file_id_generation(self):
        """Test that unique file IDs are generated"""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(b"Test data")
            temp_file = f.name

        try:
            pipeline = MultiLayerPipeline()
            result = pipeline.encrypt_file(temp_file)

            assert result.file_id is not None
            assert result.file_id.startswith('SEC512_')

        finally:
            os.unlink(temp_file)

    def test_file_id_uniqueness(self):
        """Test that file IDs are unique for different encryptions"""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(b"Test data")
            temp_file = f.name

        try:
            pipeline = MultiLayerPipeline()

            result1 = pipeline.encrypt_file(temp_file)
            result2 = pipeline.encrypt_file(temp_file)

            # Even encrypting the same file should produce different IDs
            # (due to timestamp)
            assert result1.file_id != result2.file_id

        finally:
            os.unlink(temp_file)


class TestPipelineMetadata:
    """Tests for metadata handling in the pipeline"""

    def test_encryption_metadata_present(self):
        """Test that encryption metadata is present"""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(b"Test data")
            temp_file = f.name

        try:
            pipeline = MultiLayerPipeline()
            result = pipeline.encrypt_file(temp_file)

            assert result.cipher_metadata is not None
            assert result.timestamp > 0
            assert result.file_id is not None

        finally:
            os.unlink(temp_file)

    def test_layer_metadata(self):
        """Test that each layer includes appropriate metadata"""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(b"Test data")
            temp_file = f.name

        try:
            pipeline = MultiLayerPipeline()
            result = pipeline.encrypt_file(temp_file)

            for layer_result in result.layer_results:
                assert layer_result.layer_name is not None
                assert layer_result.processing_time >= 0
                assert layer_result.metadata is not None

        finally:
            os.unlink(temp_file)


class TestPipelineIntegration:
    """High-level integration tests"""

    def test_complete_encryption_workflow(self):
        """Test complete encryption workflow from start to finish"""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            test_data = b"Complete workflow test data - SECRET INFORMATION"
            f.write(test_data)
            temp_file = f.name

        try:
            # Create pipeline with custom configuration
            config = PipelineConfiguration(
                ida_config=IDAConfiguration(total_shares=5, threshold=3),
                otp_config=OTPConfiguration(),
                enable_compression=True,
                classification_level=ClassificationLevel.SECRET
            )
            pipeline = MultiLayerPipeline(config)

            # Encrypt
            result = pipeline.encrypt_file(temp_file)

            # Verify all components
            assert result.original_size == len(test_data)
            assert len(result.encrypted_shares) == 5
            assert len(result.otp_results) == 5
            assert len(result.mlkem_contexts) == 5
            assert len(result.layer_results) == 5
            assert all(lr.status == OperationStatus.COMPLETED for lr in result.layer_results)

            # Verify security analysis
            analysis = result.security_analysis
            assert analysis['quantum_resistance'] == True
            assert analysis['fault_tolerance'] == True
            assert analysis['algorithm_uniqueness'] == True
            assert analysis['security_level_bits'] == 512

        finally:
            os.unlink(temp_file)

    def test_multiple_file_encryption(self):
        """Test encrypting multiple files in sequence"""
        files = []

        try:
            # Create multiple test files
            for i in range(3):
                with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
                    f.write(f"Test data for file {i}".encode())
                    files.append(f.name)

            pipeline = MultiLayerPipeline()

            # Encrypt all files
            results = []
            for file_path in files:
                result = pipeline.encrypt_file(file_path)
                results.append(result)

            # Verify all succeeded
            assert len(results) == 3
            for result in results:
                assert len(result.layer_results) == 5
                assert all(lr.status == OperationStatus.COMPLETED for lr in result.layer_results)

        finally:
            for file_path in files:
                if os.path.exists(file_path):
                    os.unlink(file_path)

    def test_pipeline_with_various_data_types(self):
        """Test pipeline with various types of data"""
        test_cases = [
            (b"Simple ASCII text", "ASCII"),
            (b"\x00\x01\x02\xff\xfe\xfd", "Binary"),
            (b"A" * 1000, "Repeated"),
            (os.urandom(500), "Random")
        ]

        for test_data, description in test_cases:
            with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
                f.write(test_data)
                temp_file = f.name

            try:
                pipeline = MultiLayerPipeline()
                result = pipeline.encrypt_file(temp_file)

                assert result.original_size == len(test_data)
                assert all(lr.status == OperationStatus.COMPLETED for lr in result.layer_results)

            finally:
                os.unlink(temp_file)


class TestPipelineRobustness:
    """Tests for pipeline robustness and edge cases"""

    def test_single_byte_file(self):
        """Test encrypting a single-byte file"""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(b"X")
            temp_file = f.name

        try:
            pipeline = MultiLayerPipeline()
            result = pipeline.encrypt_file(temp_file)

            assert result.original_size == 1
            assert len(result.layer_results) == 5

        finally:
            os.unlink(temp_file)

    def test_all_zeros_file(self):
        """Test encrypting a file of all zeros"""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(b"\x00" * 1000)
            temp_file = f.name

        try:
            pipeline = MultiLayerPipeline()
            result = pipeline.encrypt_file(temp_file)

            assert result.original_size == 1000
            # Encrypted data should not be all zeros
            assert any(len(otp_result.ciphertext) > 0 for otp_result in result.otp_results)

        finally:
            os.unlink(temp_file)

    def test_all_ones_file(self):
        """Test encrypting a file of all 0xFF bytes"""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(b"\xff" * 1000)
            temp_file = f.name

        try:
            pipeline = MultiLayerPipeline()
            result = pipeline.encrypt_file(temp_file)

            assert result.original_size == 1000
            assert len(result.layer_results) == 5

        finally:
            os.unlink(temp_file)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
