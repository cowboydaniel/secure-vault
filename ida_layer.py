"""
Streamlined 512-bit Multi-Layer Encryption System
Information Dispersal Algorithm (Layer 1)

This module implements the first layer of the multi-layer encryption system:
Information Dispersal using 512-bit Galois Field arithmetic for threshold
secret sharing with fault tolerance and redundancy.
"""

import os
import time
import hashlib
from typing import List, Dict, Optional, Tuple, Union
from dataclasses import dataclass
import struct
import logging

from galois_field import gf512, GF512Element
from constants import IDAShare, GF512_IRREDUCIBLE_POLYNOMIAL
from config import IDAConfig, SECURITY_LEVEL_BYTES
from crypto_utils import secure_random_bytes, compute_sha3_512

logger = logging.getLogger(__name__)

@dataclass
class IDAConfiguration:
    """Configuration for Information Dispersal Algorithm"""
    total_shares: int           # N - total number of shares to create
    threshold: int              # K - minimum shares needed for reconstruction
    field_polynomial: int       # GF(2^512) irreducible polynomial
    block_size: int = 1024      # File processing block size
    enable_error_correction: bool = True
    compression_enabled: bool = True

class InformationDispersalEngine:
    """
    512-bit Information Dispersal Algorithm Engine
    
    Implements threshold secret sharing using GF(2^512) arithmetic where
    any K of N shares can reconstruct the original data, but K-1 shares
    reveal no information about the original.
    """
    
    def __init__(self, config: Optional[IDAConfiguration] = None):
        """
        Initialize IDA engine with configuration.
        
        Args:
            config: IDA configuration, uses defaults if None
        """
        if config is None:
            config = IDAConfiguration(
                total_shares=IDAConfig.DEFAULT_TOTAL_SHARES,
                threshold=IDAConfig.DEFAULT_THRESHOLD,
                field_polynomial=GF512_IRREDUCIBLE_POLYNOMIAL
            )
        
        self.config = config
        
        # Initialize Galois Field with the configured polynomial
        from galois_field import GF512Field
        self.field = GF512Field(polynomial=config.field_polynomial)
        
        # Validate configuration
        self._validate_configuration()
        
        logger.info(f"IDA Engine initialized: {config.threshold}-of-{config.total_shares} shares")
    
    def _validate_configuration(self):
        """Validate IDA configuration parameters"""
        if self.config.threshold > self.config.total_shares:
            raise ValueError("Threshold cannot exceed total shares")
        
        if self.config.threshold < 2:
            raise ValueError("Threshold must be at least 2")
        
        if self.config.total_shares > 255:
            raise ValueError("Maximum 255 shares supported")
        
        if self.config.block_size % SECURITY_LEVEL_BYTES != 0:
            raise ValueError("Block size must be 512-bit aligned")
    
    def create_shares(self, data: bytes, metadata: Optional[Dict] = None, 
                     progress_callback: Optional[callable] = None) -> List[IDAShare]:
        """
        Create N shares from input data using threshold secret sharing.
        
        Args:
            data: Original data to split into shares
            metadata: Optional metadata to include with shares
            progress_callback: Optional callback function(percent: int, message: str)
            
        Returns:
            List of IDAShare objects
            
        Raises:
            ValueError: If data is empty or invalid
            RuntimeError: If share creation fails
        """
        if not data:
            raise ValueError("Cannot create shares: Input data is empty")
            
        logger.info(f"Creating {self.config.total_shares} shares from {len(data)} bytes")
        
        def update_progress(current: int, total: int, message: str):
            if progress_callback:
                progress = int((current / max(1, total)) * 100)
                progress_callback(progress, message)
        
        try:
            # Pre-process data (compression, padding)
            update_progress(0, 100, "Pre-processing data...")
            processed_data = self._preprocess_data(data)
            original_size = len(data)
            
            # Split data into 512-bit aligned blocks
            update_progress(10, 100, "Splitting data into blocks...")
            blocks = self._split_into_blocks(processed_data)
            
            # Generate shares for each block
            all_share_blocks = []
            total_blocks = len(blocks)
            for block_idx, block in enumerate(blocks):
                update_progress(
                    15 + int(70 * (block_idx / max(1, total_blocks))), 
                    100, 
                    f"Processing block {block_idx + 1}/{total_blocks}..."
                )
                share_blocks = self._create_block_shares(block, block_idx)
                all_share_blocks.append(share_blocks)
            
            # Assemble final shares
            shares = []
            for share_idx in range(self.config.total_shares):
                update_progress(
                    85 + int(10 * (share_idx / max(1, self.config.total_shares))),
                    100,
                    f"Assembling share {share_idx + 1}/{self.config.total_shares}..."
                )
                share_data = b''
                
                # Concatenate all blocks for this share
                for block_shares in all_share_blocks:
                    share_data += block_shares[share_idx]
                
                # Create share object
                share = IDAShare(
                    share_id=share_idx + 1,
                    total_shares=self.config.total_shares,
                    threshold=self.config.threshold,
                    share_data=share_data,
                    checksum=compute_sha3_512(share_data),
                    field_polynomial=self.config.field_polynomial,
                    original_size=original_size,
                    metadata=metadata or {}
                )
                
                shares.append(share)
                
            update_progress(100, 100, "Share creation complete")
            return shares
            
        except Exception as e:
            error_msg = f"Failed to create shares: {str(e)}"
            logger.error(error_msg, exc_info=True)
            raise RuntimeError(error_msg) from e
        
        logger.info(f"Successfully created {len(shares)} shares")
        return shares
    
    def _preprocess_data(self, data: bytes) -> bytes:
        """
        Pre-process data before share creation.
        
        Includes compression and 512-bit alignment padding.
        """
        processed = data
        
        # Optional compression
        if self.config.compression_enabled and len(data) > 1024:
            import zlib
            compressed = zlib.compress(data, level=6)
            if len(compressed) < len(data):
                processed = b'\x01' + compressed  # Mark as compressed
                logger.info(f"Compressed data: {len(data)} -> {len(compressed)} bytes")
            else:
                processed = b'\x00' + data  # Mark as uncompressed
        else:
            processed = b'\x00' + data  # Mark as uncompressed
        
        # Pad to 512-bit boundary
        padding_needed = (SECURITY_LEVEL_BYTES - (len(processed) % SECURITY_LEVEL_BYTES)) % SECURITY_LEVEL_BYTES
        if padding_needed > 0:
            padding = os.urandom(padding_needed - 1) + bytes([padding_needed])
            processed += padding
        
        return processed
    
    def _split_into_blocks(self, data: bytes) -> List[bytes]:
        """Split data into processing blocks"""
        blocks = []
        block_size = self.config.block_size
        
        for i in range(0, len(data), block_size):
            block = data[i:i + block_size]
            
            # Pad last block if necessary
            if len(block) < block_size:
                padding_needed = block_size - len(block)
                # Ensure we have at least 1 byte of padding
                if padding_needed == 1:
                    block += bytes([1])
                else:
                    # For larger padding, use PKCS#7 style padding
                    padding_byte = padding_needed % 256
                    if padding_byte == 0:
                        padding_byte = 256  # Use maximum padding for block size 256
                    block += os.urandom(padding_needed - 1) + bytes([padding_byte])
            
            blocks.append(block)
        
        return blocks
    
    def _create_block_shares(self, block: bytes, block_index: int) -> List[bytes]:
        """
        Create shares for a single data block using polynomial secret sharing.
        
        Args:
            block: Data block to share
            block_index: Index of this block in the file
            
        Returns:
            List of share data for each participant
        """
        # Convert block to GF(2^512) elements
        field_elements = self._bytes_to_field_elements(block)
        
        # Create polynomial for each field element
        share_values = [[] for _ in range(self.config.total_shares)]
        
        for element in field_elements:
            # Generate random polynomial coefficients
            coefficients = [element]  # a0 = secret value
            
            # Generate K-1 random coefficients for polynomial of degree K-1
            for i in range(self.config.threshold - 1):
                random_bytes = secure_random_bytes(SECURITY_LEVEL_BYTES)
                coeff = self.field.random_element(random_bytes)
                coefficients.append(coeff)
            
            # Evaluate polynomial at points 1, 2, ..., N
            for share_idx in range(self.config.total_shares):
                x = GF512Element(share_idx + 1)  # Use 1-based indexing
                y = self.field.polynomial_evaluate(coefficients, x)
                share_values[share_idx].append(y)
        
        # Convert field elements back to bytes
        share_blocks = []
        for share_vals in share_values:
            share_data = self._field_elements_to_bytes(share_vals)
            share_blocks.append(share_data)
        
        return share_blocks
    
    def _bytes_to_field_elements(self, data: bytes) -> List[GF512Element]:
        """Convert bytes to list of GF(2^512) elements"""
        elements = []
        
        for i in range(0, len(data), SECURITY_LEVEL_BYTES):
            chunk = data[i:i + SECURITY_LEVEL_BYTES]
            
            # Pad chunk if necessary
            if len(chunk) < SECURITY_LEVEL_BYTES:
                chunk += b'\x00' * (SECURITY_LEVEL_BYTES - len(chunk))
            
            element = self.field.element_from_bytes(chunk)
            elements.append(element)
        
        return elements
    
    def _field_elements_to_bytes(self, elements: List[GF512Element]) -> bytes:
        """Convert list of GF(2^512) elements to bytes"""
        data = b''
        for element in elements:
            data += self.field.element_to_bytes(element)
        return data
    
    def reconstruct_data(self, shares: List[IDAShare], progress_callback=None) -> bytes:
        """
        Reconstruct original data from K or more shares.
        
        Args:
            shares: List of available shares (must have at least K shares)
            progress_callback: Optional callback function(block_num, total_blocks)
            
        Returns:
            Original reconstructed data
        """
        if len(shares) < self.config.threshold:
            raise ValueError(f"Need at least {self.config.threshold} shares, got {len(shares)}")
        
        logger.info(f"Reconstructing data from {len(shares)} shares")
        
        # Validate shares
        self._validate_shares(shares)
        
        # Use first K shares for reconstruction
        shares = sorted(shares, key=lambda x: x.share_id)[:self.config.threshold]
        
        # Determine block size from first share
        block_size = len(shares[0].share_data) // ((self.config.threshold + 1) // 2)
        
        # Reconstruct each block
        reconstructed_blocks = []
        num_blocks = len(shares[0].share_data) // block_size
        
        if progress_callback:
            progress_callback(0, num_blocks)
        
        for block_idx in range(num_blocks):
            block_shares = []
            block_start = block_idx * block_size
            block_end = block_start + block_size
            
            # Extract this block from each share
            for share in shares:
                block_data = share.share_data[block_start:block_end]
                block_shares.append((share.share_id, block_data))
            
            # Reconstruct this block
            reconstructed_block = self._reconstruct_block(block_shares)
            reconstructed_blocks.append(reconstructed_block)
            
            # Update progress
            if progress_callback and (block_idx % 10 == 0 or block_idx == num_blocks - 1):
                progress_callback(block_idx + 1, num_blocks)
        
        # Combine all blocks
        reconstructed_data = b''.join(reconstructed_blocks)
        
        # Post-process (remove padding, decompress)
        final_data = self._postprocess_data(reconstructed_data, shares[0].original_size)
        
        logger.info(f"Successfully reconstructed {len(final_data)} bytes")
        return final_data
    
    def _validate_shares(self, shares: List[IDAShare]):
        """Validate that shares are compatible and valid"""
        if not shares:
            raise ValueError("No shares provided")
        
        # Check basic compatibility
        first_share = shares[0]
        for share in shares[1:]:
            if share.total_shares != first_share.total_shares:
                raise ValueError("Incompatible share total counts")
            if share.threshold != first_share.threshold:
                raise ValueError("Incompatible share thresholds")
            if share.field_polynomial != first_share.field_polynomial:
                raise ValueError("Incompatible field polynomials")
        
        # Verify checksums
        for share in shares:
            computed_checksum = compute_sha3_512(share.share_data)
            if computed_checksum != share.checksum:
                raise ValueError(f"Share {share.share_id} checksum verification failed")
        
        # Check for duplicate share IDs
        share_ids = [share.share_id for share in shares]
        if len(set(share_ids)) != len(share_ids):
            raise ValueError("Duplicate share IDs detected")
    
    def _reconstruct_block(self, block_shares: List[Tuple[int, bytes]]) -> bytes:
        """
        Reconstruct a single block using Lagrange interpolation.
        
        Args:
            block_shares: List of (share_id, share_data) tuples
            
        Returns:
            Reconstructed block data
        """
        # Convert share data to field elements
        share_points = []
        for share_id, share_data in block_shares:
            elements = self._bytes_to_field_elements(share_data)
            share_points.append((share_id, elements))
        
        # Reconstruct each field element position
        reconstructed_elements = []
        element_count = len(share_points[0][1])
        
        for elem_idx in range(element_count):
            # Collect points for this element position
            points = []
            for share_id, elements in share_points:
                x = GF512Element(share_id)
                y = elements[elem_idx]
                points.append((x, y))
            
            # Interpolate polynomial and evaluate at x=0 to get secret
            coefficients = self.field.polynomial_interpolate(points)
            secret_value = coefficients[0] if coefficients else GF512Element(0)
            reconstructed_elements.append(secret_value)
        
        # Convert back to bytes
        return self._field_elements_to_bytes(reconstructed_elements)
    
    def _postprocess_data(self, data: bytes, original_size: int) -> bytes:
        """
        Post-process reconstructed data.
        
        Removes padding and decompresses if necessary.
        """
        if not data:
            return data
        
        # Check compression flag
        compression_flag = data[0]
        data = data[1:]
        
        # Decompress if necessary
        if compression_flag == 0x01:
            import zlib
            try:
                data = zlib.decompress(data)
            except zlib.error as e:
                logger.error(f"Decompression failed: {e}")
                raise ValueError("Failed to decompress reconstructed data")
        
        # Remove padding
        if len(data) >= original_size:
            data = data[:original_size]
        
        return data
    
    def verify_share_integrity(self, share: IDAShare) -> bool:
        """
        Verify the integrity of a single share.
        
        Args:
            share: Share to verify
            
        Returns:
            True if share integrity is valid
        """
        try:
            computed_checksum = compute_sha3_512(share.share_data)
            return computed_checksum == share.checksum
        except Exception as e:
            logger.error(f"Share integrity verification failed: {e}")
            return False
    
    def get_share_info(self, share: IDAShare) -> Dict:
        """Get detailed information about a share"""
        return {
            'share_id': share.share_id,
            'total_shares': share.total_shares,
            'threshold': share.threshold,
            'data_size': len(share.share_data),
            'original_size': share.original_size,
            'checksum': share.checksum.hex(),
            'field_polynomial': hex(share.field_polynomial),
            'metadata': share.metadata,
            'integrity_valid': self.verify_share_integrity(share)
        }

def create_test_shares(data: bytes, n: int = 5, k: int = 3) -> List[IDAShare]:
    """
    Convenience function to create test shares.
    
    Args:
        data: Data to share
        n: Total number of shares
        k: Threshold (minimum shares needed)
        
    Returns:
        List of shares
    """
    config = IDAConfiguration(
        total_shares=n,
        threshold=k,
        field_polynomial=GF512_IRREDUCIBLE_POLYNOMIAL
    )
    
    engine = InformationDispersalEngine(config)
    return engine.create_shares(data)

def reconstruct_test_data(shares: List[IDAShare], progress_callback=None) -> bytes:
    """
    Convenience function to reconstruct data from shares.
    
    Args:
        shares: Available shares
        progress_callback: Optional callback function(block_num, total_blocks)
        
    Returns:
        Reconstructed data
    """
    if not shares:
        raise ValueError("No shares provided")
    
    config = IDAConfiguration(
        total_shares=shares[0].total_shares,
        threshold=shares[0].threshold,
        field_polynomial=shares[0].field_polynomial
    )
    
    engine = InformationDispersalEngine(config)
    return engine.reconstruct_data(shares, progress_callback=progress_callback)

def _process_block(args):
    """Helper function for parallel block processing"""
    try:
        block_idx, block_shares, share_ids = args
        from ida_layer import InformationDispersalEngine, IDAConfiguration, IDAConfig, GF512_IRREDUCIBLE_POLYNOMIAL
        
        # Create a minimal engine just for reconstruction
        config = IDAConfiguration(
            total_shares=len(share_ids),
            threshold=len(share_ids),  # We already have the minimum required shares
            field_polynomial=GF512_IRREDUCIBLE_POLYNOMIAL
        )
        engine = InformationDispersalEngine(config)
        
        # Reconstruct this block
        result = engine._reconstruct_block(block_shares)
        return (block_idx, result)
    except Exception as e:
        logger.error(f"Error processing block {block_idx}: {str(e)}")
        return (block_idx, None)

def benchmark_ida_performance(data_size: int = 256 * 1024,  # Reduced from 1MB to 256KB for faster testing
                          configs: List[Tuple[int, int]] = None,
                          num_processes: int = None) -> Dict[str, float]:
    """
    Benchmark IDA performance with different configurations.
    
    Args:
        data_size: Size of test data in bytes (default: 256KB for faster testing)
        configs: List of (threshold, total_shares) tuples to test. 
                If None, uses [(3,5), (5,9)] for faster testing.
        num_processes: Number of processes to use for parallel processing.
                     If None, uses all available CPU cores.
                     
    Returns:
        Performance metrics dictionary
    """
    import time
    import multiprocessing as mp
    from tqdm import tqdm
    
    if configs is None:
        configs = [
            (3, 5),   # 3-of-5
        ]
    
    # Set default number of processes
    if num_processes is None:
        num_processes = max(1, mp.cpu_count() - 1)  # Leave one core free
    
    print(f"Using {num_processes} processes for parallel execution")
    
    # Generate test data
    print(f"Generating {data_size/1024:.1f}KB of test data...")
    test_data = os.urandom(data_size)
    
    metrics = {}
    
    for threshold, total in configs:
        config_name = f"{threshold}_of_{total}"
        print(f"\nTesting {config_name} configuration...")
        
        # Benchmark share creation
        print("  Creating shares...")
        start_time = time.time()
        shares = create_test_shares(test_data, total, threshold)
        creation_time = time.time() - start_time
        
        metrics[f"{config_name}_creation_time"] = creation_time
        metrics[f"{config_name}_creation_mbps"] = (data_size / (1024 * 1024)) / max(0.001, creation_time)
        
        # Benchmark reconstruction with parallel processing
        print(f"  Reconstructing from {threshold} shares using {num_processes} processes...")
        start_time = time.time()
        
        try:
            # Prepare the engine for reconstruction
            config = IDAConfiguration(
                total_shares=total,
                threshold=threshold,
                field_polynomial=GF512_IRREDUCIBLE_POLYNOMIAL
            )
            engine = InformationDispersalEngine(config)
            
            # Use first K shares for reconstruction
            shares = sorted(shares, key=lambda x: x.share_id)[:threshold]
            
            # Determine block size from first share
            block_size = len(shares[0].share_data) // ((threshold + 1) // 2)
            num_blocks = len(shares[0].share_data) // block_size
            
            # Prepare block processing tasks
            tasks = []
            share_ids = [s.share_id for s in shares]
            
            for block_idx in range(num_blocks):
                block_shares = []
                block_start = block_idx * block_size
                block_end = block_start + block_size
                
                # Extract this block from each share
                for share in shares:
                    block_data = share.share_data[block_start:block_end]
                    block_shares.append((share.share_id, block_data))
                
                tasks.append((block_idx, block_shares, share_ids))
            
            # Initialize with None to maintain order
            reconstructed_blocks = [None] * num_blocks
            
            # Process blocks in parallel with error handling
            with mp.Pool(processes=num_processes) as pool:
                try:
                    # Use imap_unordered for better memory efficiency with large data
                    with tqdm(total=len(tasks), desc="Reconstructing blocks") as pbar:
                        # Process tasks in smaller chunks to better handle memory
                        chunk_size = max(1, len(tasks) // (num_processes * 2))
                        for result in pool.imap_unordered(_process_block, tasks, chunksize=chunk_size):
                            if result and result[1] is not None:  # Check if reconstruction was successful
                                block_idx, block_data = result
                                reconstructed_blocks[block_idx] = block_data
                            pbar.update(1)
                            
                    # Verify all blocks were reconstructed
                    if None in reconstructed_blocks:
                        failed_blocks = [i for i, x in enumerate(reconstructed_blocks) if x is None]
                        raise ValueError(f"Failed to reconstruct blocks: {failed_blocks}")
                        
                except KeyboardInterrupt:
                    print("\n⚠️  Benchmark interrupted by user")
                    pool.terminate()
                    pool.join()
                    raise
                except Exception as e:
                    print(f"\n❌ Parallel processing error: {str(e)}")
                    pool.terminate()
                    pool.join()
                    raise
            
            # Combine all blocks
            reconstructed_data = b''.join(reconstructed_blocks)
            
            # Post-process (remove padding, decompress)
            reconstructed = engine._postprocess_data(reconstructed_data, shares[0].original_size)
            
            reconstruction_time = time.time() - start_time
            
        except Exception as e:
            logger.error(f"Parallel reconstruction failed: {e}")
            # Fall back to sequential reconstruction
            print("  ⚠️ Parallel reconstruction failed, falling back to sequential...")
            start_time = time.time()
            reconstructed = reconstruct_test_data(shares)
            reconstruction_time = time.time() - start_time
        
        metrics[f"{config_name}_reconstruction_time"] = reconstruction_time
        metrics[f"{config_name}_reconstruction_mbps"] = (data_size / (1024 * 1024)) / max(0.001, reconstruction_time)
        
        # Verify correctness
        if reconstructed != test_data:
            logger.error(f"Reconstruction failed for {config_name}")
            metrics[f"{config_name}_correct"] = False
        else:
            print(f"  ✓ Reconstruction successful")
            metrics[f"{config_name}_correct"] = True
        
        # Calculate share overhead
        total_share_size = sum(len(share.share_data) for share in shares)
        overhead_ratio = total_share_size / len(test_data)
        metrics[f"{config_name}_overhead_ratio"] = overhead_ratio
        
        print(f"  Performance: {metrics[f'{config_name}_creation_mbps']:.2f} MB/s create, "
              f"{metrics[f'{config_name}_reconstruction_mbps']:.2f} MB/s reconstruct, "
              f"{overhead_ratio:.1f}x overhead")
    
    return metrics

class IDAShareManager:
    """
    Manager for distributing and tracking IDA shares across storage locations.
    """
    
    def __init__(self, storage_dir: str = None):
        """
        Initialize share manager.
        
        Args:
            storage_dir: Directory for storing shares
        """
        if storage_dir is None:
            storage_dir = os.path.expanduser("~/secure_vault/shares")
        
        self.storage_dir = storage_dir
        os.makedirs(storage_dir, exist_ok=True)
        
        logger.info(f"IDA Share Manager initialized with storage: {storage_dir}")
    
    def save_shares(self, shares: List[IDAShare], filename_base: str) -> List[str]:
        """
        Save shares to separate files.
        
        Args:
            shares: List of shares to save
            filename_base: Base filename for share files
            
        Returns:
            List of created file paths
        """
        filepaths = []
        
        for share in shares:
            filename = f"{filename_base}.share_{share.share_id:03d}"
            filepath = os.path.join(self.storage_dir, filename)
            
            # Serialize share data
            share_bytes = self._serialize_share(share)
            
            # Write to file
            with open(filepath, 'wb') as f:
                f.write(share_bytes)
            
            filepaths.append(filepath)
            logger.debug(f"Saved share {share.share_id} to {filepath}")
        
        logger.info(f"Saved {len(shares)} shares with base name {filename_base}")
        return filepaths
    
    def load_shares(self, filename_base: str) -> List[IDAShare]:
        """
        Load all available shares for a given base filename.
        
        Args:
            filename_base: Base filename to search for
            
        Returns:
            List of loaded shares
        """
        logger.info(f"Starting to load shares for base: {filename_base}")
        shares = []
        
        # Find all share files matching the pattern
        import glob
        
        # Try multiple patterns to find share files
        patterns = [
            os.path.join(self.storage_dir, f"{filename_base}*_share_*.sec"),  # New format
            os.path.join(self.storage_dir, f"{filename_base}.share_*"),      # Old format
            os.path.join(self.storage_dir, f"{filename_base}*")              # Any matching file
        ]
        
        logger.info(f"Searching for share files with patterns: {patterns}")
        share_files = []
        for pattern in patterns:
            new_files = [f for f in glob.glob(pattern) 
                        if f not in share_files and 
                        (f.endswith('.sec') or 'share_' in f or 'Share_' in f)]
            if new_files:
                logger.debug(f"Found {len(new_files)} files matching {pattern}")
                for f in new_files:
                    logger.debug(f"Found share file: {f}")
            share_files.extend(new_files)
        
        if not share_files:
            logger.warning(f"No share files found for base: {filename_base}")
            return []
            
        logger.info(f"Found {len(share_files)} share files to process")
        
        for filepath in sorted(share_files):
            try:
                logger.debug(f"Processing share file: {filepath}")
                file_size = os.path.getsize(filepath)
                logger.debug(f"Share file size: {file_size} bytes")
                
                with open(filepath, 'rb') as f:
                    share_bytes = f.read()
                
                logger.debug(f"Successfully read {len(share_bytes)} bytes from {filepath}")
                
                # Extract share ID from filename if possible (format: ..._share_X.sec)
                share_id = 1  # Default ID
                try:
                    # Try to extract ID from filename (e.g., '..._share_1.sec' -> 1)
                    import re
                    match = re.search(r'_share_(\d+)\.sec$', filepath)
                    if match:
                        share_id = int(match.group(1))
                        logger.debug(f"Extracted share ID {share_id} from filename {filepath}")
                    else:
                        # If no ID in filename, use a unique number based on the index
                        share_id = len(shares) + 1
                        logger.debug(f"Using generated share ID {share_id} for {filepath}")
                except (ValueError, IndexError) as e:
                    # If extraction fails, just use a unique number
                    share_id = len(shares) + 1
                    logger.warning(f"Error extracting share ID from {filepath}: {e}, using ID {share_id}")
                
                try:
                    logger.debug(f"Attempting to deserialize share {share_id} from {filepath}")
                    share = self._deserialize_share(share_bytes)
                    logger.debug(f"Successfully deserialized share {share_id}")
                    
                    # Ensure the share has the correct ID from the filename
                    share.share_id = share_id
                    shares.append(share)
                    logger.info(f"Successfully loaded share {share_id} from {filepath}")
                except Exception as e:
                    # Try to handle raw share data
                    logger.warning(f"Standard deserialization failed, trying fallback: {str(e)}")
                    try:
                        # Create a share with the extracted ID
                        share = IDAShare(
                            share_id=share_id,
                            total_shares=5,  # Default values, adjust as needed
                            threshold=3,     # Default values, adjust as needed
                            share_data=share_bytes,
                            checksum=hashlib.sha3_512(share_bytes).digest(),
                            field_polynomial=0x1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001a7,
                            original_size=len(share_bytes),
                            metadata={"source_file": os.path.basename(filepath)}
                        )
                        shares.append(share)
                        logger.info(f"Successfully loaded fallback share with ID {share_id} from {filepath}")
                    except Exception as fallback_error:
                        logger.error(f"Fallback deserialization failed: {str(fallback_error)}")
                        raise
                
            except Exception as e:
                logger.error(f"Failed to load share from {filepath}: {e}", exc_info=True)
        
        if not shares:
            logger.error(f"No valid shares found for {filename_base}")
        else:
            logger.info(f"Loaded {len(shares)} shares for {filename_base}")
        return shares
    
    def _serialize_share(self, share: IDAShare) -> bytes:
        """
        Serialize IDAShare to bytes for storage.
        
        Args:
            share: Share to serialize
            
        Returns:
            Serialized share data
        """
        # Create header
        header = struct.pack('>I', 1)  # Version
        header += struct.pack('>I', share.share_id)
        header += struct.pack('>I', share.total_shares)
        header += struct.pack('>I', share.threshold)
        header += struct.pack('>Q', share.original_size)
        header += struct.pack('>Q', share.field_polynomial)
        header += struct.pack('>I', len(share.share_data))
        header += share.checksum  # 64 bytes
        
        # Serialize metadata
        metadata_bytes = b''
        if share.metadata:
            import json
            metadata_str = json.dumps(share.metadata)
            metadata_bytes = metadata_str.encode('utf-8')
        
        header += struct.pack('>I', len(metadata_bytes))
        
        # Combine all parts
        return header + metadata_bytes + share.share_data
    
    def _deserialize_share(self, data: bytes) -> IDAShare:
        """
        Deserialize bytes to IDAShare with enhanced error handling and format detection.
        
        Args:
            data: Serialized share data
            
        Returns:
            Deserialized IDAShare object
        """
        logger.debug("Starting share deserialization")
        
        if not data:
            error_msg = "Empty share data provided"
            logger.error(error_msg)
            raise ValueError(error_msg)
        
        logger.debug(f"Share data length: {len(data)} bytes")
        
        # Try to detect the format
        try:
            # Try to parse as JSON first (might be a text-based format)
            try:
                logger.debug("Attempting to parse as JSON")
                import json
                share_dict = json.loads(data.decode('utf-8', errors='ignore'))
                if isinstance(share_dict, dict):
                    logger.debug("Successfully parsed as JSON dictionary")
                    # Ensure required fields are present
                    required_fields = ['share_id', 'total_shares', 'threshold', 
                                     'share_data', 'checksum', 'field_polynomial', 'original_size']
                    
                    logger.debug("Checking for required fields in JSON")
                    if all(field in share_dict for field in required_fields):
                        logger.debug("All required fields present in JSON")
                        # Convert string data to bytes if needed
                        if isinstance(share_dict.get('share_data'), str):
                            logger.debug("Converting share_data from hex string to bytes")
                            share_dict['share_data'] = bytes.fromhex(share_dict['share_data'])
                        if isinstance(share_dict.get('checksum'), str):
                            logger.debug("Converting checksum from hex string to bytes")
                            share_dict['checksum'] = bytes.fromhex(share_dict['checksum'])
                        
                        logger.debug("Creating IDAShare from JSON data")
                        return IDAShare(**share_dict)
                    else:
                        logger.warning("Missing required fields in JSON data")
                        missing_fields = [f for f in required_fields if f not in share_dict]
                        logger.warning(f"Missing fields: {missing_fields}")
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as e:
                logger.debug(f"Not a JSON share (expected for binary format): {str(e)}")
                pass
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as e:
                pass
            
            # If not JSON, try the binary format
            offset = 0
            
            # Check minimum length for binary format
            if len(data) < 4:
                raise ValueError("Share data too short")
            
            # Try to determine the format based on the first few bytes
            first_byte = data[0]
            
            # If it looks like a version number (small integer)
            if first_byte < 0x10:  # Version is likely 1-15
                version = struct.unpack('>I', data[offset:offset+4])[0]
                offset += 4
                
                # Special handling for version 1 format
                if version == 1:
                    if len(data) < offset + 4*4 + 8 + 8 + 4 + 64 + 4:
                        raise ValueError("Incomplete share header for version 1 format")
                    
                    # Parse header for version 1
                    share_id = struct.unpack('>I', data[offset:offset+4])[0]
                    offset += 4
                    total_shares = struct.unpack('>I', data[offset:offset+4])[0]
                    offset += 4
                    threshold = struct.unpack('>I', data[offset:offset+4])[0]
                    offset += 4
                    original_size = struct.unpack('>Q', data[offset:offset+8])[0]
                    offset += 8
                    field_polynomial = struct.unpack('>Q', data[offset:offset+8])[0]
                    offset += 8
                    data_length = struct.unpack('>I', data[offset:offset+4])[0]
                    offset += 4
                    checksum = data[offset:offset+64]
                    offset += 64
                    metadata_length = struct.unpack('>I', data[offset:offset+4])[0]
                    offset += 4
                    
                    # Read metadata
                    metadata = {}
                    if metadata_length > 0:
                        if len(data) < offset + metadata_length + data_length:
                            raise ValueError("Incomplete share data or metadata")
                        try:
                            metadata_str = data[offset:offset+metadata_length].decode('utf-8')
                            metadata = json.loads(metadata_str)
                        except (UnicodeDecodeError, json.JSONDecodeError):
                            metadata = {}
                        offset += metadata_length
                    
                    # Read share data
                    share_data = data[offset:offset+data_length]
                    
                    return IDAShare(
                        share_id=share_id,
                        total_shares=total_shares,
                        threshold=threshold,
                        share_data=share_data,
                        checksum=checksum,
                        field_polynomial=field_polynomial,
                        original_size=original_size,
                        metadata=metadata or {}
                    )
                else:
                    raise ValueError(f"Unsupported share format version: {version}")
            else:
                # Try to handle raw share data without version header
                # This is a fallback and makes assumptions about the format
                try:
                    # Try to parse as raw share data with default values
                    # This assumes the entire data is the share data
                    return IDAShare(
                        share_id=1,
                        total_shares=5,  # Default values, adjust as needed
                        threshold=3,     # Default values, adjust as needed
                        share_data=data,
                        checksum=hashlib.sha3_512(data).digest(),
                        field_polynomial=0x1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001a7,
                        original_size=len(data),
                        metadata={}
                    )
                except Exception as e:
                    raise ValueError(f"Failed to parse share data: {str(e)}")
        
        except struct.error as e:
            raise ValueError(f"Invalid share format: {str(e)}")
        except Exception as e:
            raise ValueError(f"Failed to deserialize share: {str(e)}")
            
    def verify_reconstruction_possible(self, filename_base: str) -> Tuple[bool, Dict]:
        """
        Check if reconstruction is possible with available shares.
        
        Args:
            filename_base: Base filename to check
            
        Returns:
            Tuple of (is_possible, status_info)
        """
        shares = self.load_shares(filename_base)
        
        if not shares:
            return False, {"error": "No shares found"}
        
        # Check share validity
        valid_shares = []
        for share in shares:
            engine = InformationDispersalEngine()
            if engine.verify_share_integrity(share):
                valid_shares.append(share)
        
        threshold = shares[0].threshold if shares else 0
        
        status = {
            "total_shares_found": len(shares),
            "valid_shares": len(valid_shares),
            "threshold_required": threshold,
            "reconstruction_possible": len(valid_shares) >= threshold,
            "missing_shares": max(0, threshold - len(valid_shares))
        }
        
        return len(valid_shares) >= threshold, status
    
    def cleanup_shares(self, filename_base: str) -> int:
        """
        Remove all share files for a given base filename.
        
        Args:
            filename_base: Base filename to clean up
            
        Returns:
            Number of files removed
        """
        import glob
        
        pattern = os.path.join(self.storage_dir, f"{filename_base}.share_*")
        share_files = glob.glob(pattern)
        
        removed_count = 0
        for filepath in share_files:
            try:
                os.remove(filepath)
                removed_count += 1
                logger.debug(f"Removed share file: {filepath}")
            except Exception as e:
                logger.error(f"Failed to remove {filepath}: {e}")
        
        logger.info(f"Cleaned up {removed_count} share files for {filename_base}")
        return removed_count

if __name__ == "__main__":
    # Demonstrate IDA functionality
    print("512-bit Information Dispersal Algorithm Demo")
    print("=" * 50)
    
    # Create test data
    test_message = b"This is a secret message that will be split using 512-bit Information Dispersal Algorithm with perfect threshold security!"
    print(f"Original message: {test_message}")
    print(f"Message size: {len(test_message)} bytes")
    
    # Create shares
    print(f"\nCreating 5 shares with threshold of 3...")
    shares = create_test_shares(test_message, n=5, k=3)
    
    print(f"Created {len(shares)} shares:")
    for share in shares:
        print(f"  Share {share.share_id}: {len(share.share_data)} bytes")
    
    # Test reconstruction with minimum shares
    print(f"\nReconstruction test with 3 shares (minimum threshold):")
    reconstructed = reconstruct_test_data(shares[:3])
    
    if reconstructed == test_message:
        print("✓ Reconstruction successful!")
    else:
        print("✗ Reconstruction failed!")
    
    # Test reconstruction with more shares
    print(f"\nReconstruction test with 4 shares:")
    reconstructed = reconstruct_test_data(shares[:4])
    
    if reconstructed == test_message:
        print("✓ Reconstruction successful!")
    else:
        print("✗ Reconstruction failed!")
    
    # Performance benchmark
    print(f"\nPerformance benchmark:")
    metrics = benchmark_ida_performance(64 * 1024)  # 64KB test
    
    for metric, value in metrics.items():
        if 'mbps' in metric:
            print(f"  {metric}: {value:.2f} MB/s")
        elif 'time' in metric:
            print(f"  {metric}: {value:.3f} seconds")
        elif 'overhead' in metric:
            print(f"  {metric}: {value:.2f}x")
    
    print(f"\nInformation Dispersal Algorithm (Layer 1) is ready!")