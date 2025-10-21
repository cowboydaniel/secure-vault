"""
Secure Key Backup and Recovery System

This module implements secure backup and recovery of encryption keys using
Shamir's Secret Sharing for secure key distribution.
"""

import os
import json
import hmac
import hashlib
import secrets
import struct
from typing import List, Dict, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from pathlib import Path

# Existing imports from your project
from crypto_utils import secure_random_bytes, secure_compare, secure_wipe
from secure_memory import SecureBuffer
from config import BACKUP_CONFIG

# Constants
DEFAULT_THRESHOLD = 3
DEFAULT_TOTAL_SHARES = 5
MAX_SECRET_SIZE = 4096  # 4KB maximum secret size

class KeyRecoveryError(Exception):
    """Base exception for key recovery operations"""
    pass

class InvalidShareError(KeyRecoveryError):
    """Raised when an invalid share is provided"""
    pass

class InsufficientSharesError(KeyRecoveryError):
    """Raised when insufficient shares are provided for recovery"""
    pass

@dataclass
class KeyShare:
    """Represents a single share of a split secret"""
    x: int  # Share index (1-255)
    y: bytes  # Share value
    version: str = "1.0"
    key_id: str = ""
    metadata: Dict[str, Any] = None
    hmac: bytes = None
    
    def to_dict(self) -> Dict:
        """Convert share to a serializable dictionary"""
        return {
            'x': self.x,
            'y': self.y.hex(),
            'version': self.version,
            'key_id': self.key_id,
            'metadata': self.metadata or {},
            'hmac': self.hmac.hex() if self.hmac else None
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'KeyShare':
        """Create a KeyShare from a dictionary"""
        return cls(
            x=data['x'],
            y=bytes.fromhex(data['y']),
            version=data.get('version', '1.0'),
            key_id=data.get('key_id', ''),
            metadata=data.get('metadata', {}),
            hmac=bytes.fromhex(data['hmac']) if 'hmac' in data and data['hmac'] else None
        )
    
    def validate_hmac(self, hmac_key: bytes) -> bool:
        """Validate the HMAC of this share"""
        if not self.hmac:
            return False
            
        # Create a copy of the share without the HMAC for validation
        temp = self.to_dict()
        temp.pop('hmac', None)
        serialized = json.dumps(temp, sort_keys=True).encode()
        
        expected_hmac = hmac.new(hmac_key, serialized, hashlib.sha256).digest()
        return hmac.compare_digest(self.hmac, expected_hmac)

class SecretSharer:
    """Implements Shamir's Secret Sharing for secure key distribution"""
    
    def __init__(self, threshold: int = DEFAULT_THRESHOLD, 
                 total_shares: int = DEFAULT_TOTAL_SHARES):
        """
        Initialize the secret sharer
        
        Args:
            threshold: Minimum number of shares required to reconstruct the secret (2-255)
            total_shares: Total number of shares to generate (1-255)
        """
        if not (2 <= threshold <= 255):
            raise ValueError("Threshold must be between 2 and 255")
        if not (1 <= total_shares <= 255):
            raise ValueError("Total shares must be between 1 and 255")
        if threshold > total_shares:
            raise ValueError("Threshold cannot be greater than total shares")
            
        self.threshold = threshold
        self.total_shares = total_shares
        
        # Use a 256-bit prime for the finite field
        # 2^256 - 189 (a safe prime)
        self.prime = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
    
    def _evaluate_polynomial(self, coefficients: List[int], x: int) -> int:
        """Evaluate a polynomial at point x"""
        result = 0
        for coefficient in reversed(coefficients):
            result = (result * x + coefficient) % self.prime
        return result
    
    def _generate_polynomial(self, secret: int, degree: int) -> List[int]:
        """Generate a random polynomial with the given secret as the constant term"""
        coefficients = [secret]  # The secret is the constant term
        
        # Generate random coefficients for the polynomial
        for _ in range(degree):
            coefficients.append(secrets.randbelow(self.prime - 1) + 1)
            
        return coefficients
    
    def _interpolate(self, x_s: List[int], y_s: List[int], x: int = 0) -> int:
        """
        Reconstruct the secret using Lagrange interpolation
        
        Args:
            x_s: List of x-coordinates of shares
            y_s: List of y-coordinates of shares
            x: The x-coordinate to evaluate the polynomial at (0 for the secret)
            
        Returns:
            The interpolated y-coordinate at point x
        """
        def modinv(a: int, m: int) -> int:
            """Modular multiplicative inverse using extended Euclidean algorithm"""
            g, x, y = self._extended_gcd(a, m)
            if g != 1:
                raise ValueError('No modular inverse exists')
            return x % m
            
        result = 0
        n = len(x_s)
        
        for i in range(n):
            # Calculate the Lagrange basis polynomial
            term = y_s[i] % self.prime
            
            for j in range(n):
                if i != j:
                    # (x - x_j) / (x_i - x_j)
                    numerator = (x - x_j) % self.prime
                    denominator = (x_s[i] - x_s[j]) % self.prime
                    
                    # Multiply by modular inverse instead of dividing
                    inv_denominator = modinv(denominator, self.prime)
                    term = (term * numerator * inv_denominator) % self.prime
            
            result = (result + term) % self.prime
            
        return result
    
    def _extended_gcd(self, a: int, b: int) -> Tuple[int, int, int]:
        """Extended Euclidean algorithm"""
        if a == 0:
            return (b, 0, 1)
        else:
            g, y, x = self._extended_gcd(b % a, a)
            return (g, x - (b // a) * y, y)
    
    def split_secret(self, secret: bytes) -> List[KeyShare]:
        """
        Split a secret into multiple shares using Shamir's Secret Sharing
        
        Args:
            secret: The secret to split (up to 4KB)
            
        Returns:
            List of KeyShare objects
            
        Raises:
            ValueError: If the secret is too large or invalid
        """
        if not secret:
            raise ValueError("Secret cannot be empty")
        if len(secret) > MAX_SECRET_SIZE:
            raise ValueError(f"Secret exceeds maximum size of {MAX_SECRET_SIZE} bytes")
        
        # Convert the secret to an integer
        secret_int = int.from_bytes(secret, byteorder='big')
        
        # Generate a random polynomial
        coefficients = self._generate_polynomial(secret_int, self.threshold - 1)
        
        # Generate shares
        shares = []
        for i in range(1, self.total_shares + 1):
            # Evaluate the polynomial at x = i
            y = self._evaluate_polynomial(coefficients, i)
            
            # Convert y to bytes (big-endian, fixed length)
            y_bytes = y.to_bytes((y.bit_length() + 7) // 8, 'big')
            
            # Create a new share
            share = KeyShare(x=i, y=y_bytes)
            shares.append(share)
        
        return shares
    
    def combine_shares(self, shares: List[KeyShare]) -> bytes:
        """
        Combine shares to reconstruct the original secret
        
        Args:
            shares: List of KeyShare objects
            
        Returns:
            The reconstructed secret as bytes
            
        Raises:
            InsufficientSharesError: If fewer than threshold shares are provided
            InvalidShareError: If any share is invalid
        """
        if len(shares) < self.threshold:
            raise InsufficientSharesError(
                f"At least {self.threshold} shares are required, but only {len(shares)} provided"
            )
        
        # Extract x and y values from shares
        x_s = []
        y_ints = []
        
        for share in shares:
            try:
                x = share.x
                y_int = int.from_bytes(share.y, byteorder='big')
                
                x_s.append(x)
                y_ints.append(y_int)
            except (AttributeError, ValueError) as e:
                raise InvalidShareError(f"Invalid share format: {e}")
        
        # Reconstruct the secret using Lagrange interpolation at x=0
        secret_int = self._interpolate(x_s, y_ints, 0)
        
        # Convert back to bytes
        # First, determine the minimum number of bytes needed
        byte_length = (secret_int.bit_length() + 7) // 8
        return secret_int.to_bytes(byte_length, byteorder='big')

class KeyBackupManager:
    """Manages secure backup and recovery of encryption keys"""
    
    def __init__(self, hsm_integration=None, config: Optional[Dict] = None):
        """
        Initialize the key backup manager
        
        Args:
            hsm_integration: Optional HSM integration for secure operations
            config: Configuration dictionary
        """
        self.hsm = hsm_integration
        self.config = config or {}
        self.backup_locations = self.config.get('backup_locations', [])
        
        # Initialize the secret sharer with configured or default values
        self.sharer = SecretSharer(
            threshold=self.config.get('threshold', DEFAULT_THRESHOLD),
            total_shares=self.config.get('total_shares', DEFAULT_TOTAL_SHARES)
        )
        
        # Generate or load HMAC key for share validation
        self._init_hmac_key()
    
    def _init_hmac_key(self):
        """Initialize or load the HMAC key for share validation"""
        # In a real implementation, this would load from secure storage
        # For now, we'll generate a new key each time
        self.hmac_key = secure_random_bytes(32)  # 256-bit HMAC key
    
    def create_backup(self, key_id: str, key_data: bytes, 
                     locations: Optional[List[str]] = None,
                     threshold: Optional[int] = None) -> Dict[str, Any]:
        """
        Create a secure backup of a key
        
        Args:
            key_id: ID of the key to back up
            key_data: The key data to back up
            locations: Optional list of backup locations (defaults to configured locations)
            threshold: Optional threshold for recovery (defaults to configured threshold)
            
        Returns:
            Dictionary with backup metadata
            
        Raises:
            ValueError: If key data is invalid or no backup locations are configured
        """
        if not key_data:
            raise ValueError("Key data cannot be empty")
            
        backup_locations = locations or self.backup_locations
        if not backup_locations:
            raise ValueError("No backup locations configured")
            
        # Split the key into shares
        shares = self.sharer.split_secret(key_data)
        
        # Add metadata to each share
        timestamp = int(time.time())
        for share in shares:
            share.key_id = key_id
            share.metadata = {
                'created_at': timestamp,
                'version': '1.0',
                'threshold': threshold or self.sharer.threshold,
                'total_shares': self.sharer.total_shares
            }
            
            # Add HMAC for integrity verification
            self._add_hmac(share)
        
        # Distribute shares to backup locations
        backup_metadata = {
            'key_id': key_id,
            'timestamp': timestamp,
            'threshold': threshold or self.sharer.threshold,
            'total_shares': self.sharer.total_shares,
            'locations': []
        }
        
        # Store each share in a different location
        for i, location in enumerate(backup_locations[:len(shares)]):
            share = shares[i]
            location_metadata = self._store_share(share, location)
            backup_metadata['locations'].append({
                'location': location,
                'share_index': share.x,
                'metadata': location_metadata
            })
        
        return backup_metadata
    
    def recover_key(self, key_id: str, shares_data: List[Dict] = None, 
                   share_locations: List[str] = None) -> bytes:
        """
        Recover a key from its shares
        
        Args:
            key_id: ID of the key to recover
            shares_data: Optional list of share data dictionaries
            share_locations: Optional list of share locations to load from
            
        Returns:
            The recovered key data
            
        Raises:
            KeyRecoveryError: If recovery fails
            ValueError: If insufficient parameters are provided
        """
        if not shares_data and not share_locations:
            raise ValueError("Either shares_data or share_locations must be provided")
            
        if not shares_data:
            shares_data = [{'location': loc} for loc in share_locations]
        """
        Recover a key from its shares
        
        Args:
            key_id: ID of the key to recover
            shares_data: List of share data dictionaries with 'location' and 'share_data'
            
        Returns:
            The recovered key data
            
        Raises:
            KeyRecoveryError: If recovery fails
        """
        if not shares_data:
            raise ValueError("No shares provided for recovery")
            
        shares = []
        
        # Load and validate each share
        for share_data in shares_data:
            try:
                # Support both direct share data and location-based loading
                if 'share_data' in share_data:
                    share = KeyShare.from_dict(share_data['share_data'])
                elif 'location' in share_data:
                    share = self._load_share(share_data['location'])
                else:
                    raise ValueError("Share data must include either 'share_data' or 'location'")
                
                # Verify the share belongs to the requested key
                if share.key_id != key_id:
                    raise InvalidShareError(f"Share does not belong to key {key_id}")
                    
                # Verify the HMAC if present
                if share.hmac and not share.validate_hmac(self.hmac_key):
                    raise InvalidShareError("Invalid HMAC for share")
                    
                shares.append(share)
                
            except (KeyError, ValueError, json.JSONDecodeError) as e:
                raise InvalidShareError(f"Invalid share data: {e}")
                
        # Check if we have enough shares
        if len(shares) < self.sharer.threshold:
            raise InsufficientSharesError(
                f"At least {self.sharer.threshold} shares are required, but only {len(shares)} provided"
            )
        
        # Combine the shares to recover the key
        try:
            return self.sharer.combine_shares(shares)
        except Exception as e:
            raise KeyRecoveryError(f"Failed to recover key: {e}")
    
    def _add_hmac(self, share: KeyShare) -> None:
        """Add an HMAC to a share for integrity verification"""
        # Create a copy of the share without the HMAC
        temp = share.to_dict()
        temp.pop('hmac', None)
        
        # Generate HMAC
        serialized = json.dumps(temp, sort_keys=True).encode()
        share.hmac = hmac.new(self.hmac_key, serialized, hashlib.sha256).digest()
    
    def _store_share(self, share: KeyShare, location: str) -> Dict:
        """
        Store a share at the specified location using HSM if available
        
        Args:
            share: The share to store
            location: The location identifier (can be a path or HSM key ID)
            
        Returns:
            Dictionary with storage metadata
            
        Raises:
            ValueError: If storage fails
        """
        try:
            # Convert share to bytes for storage
            share_data = json.dumps(share.to_dict()).encode('utf-8')
            
            if self.hsm and self.hsm.is_available():
                # Store in HSM if available
                key_id = f"{location}_share_{share.x}"
                if not self.hsm.store_key(key_id, share_data, 'SHARE'):
                    raise ValueError(f"Failed to store share {share.x} in HSM")
                
                return {
                    'stored_at': int(time.time()),
                    'location': f"hsm://{location}",
                    'share_index': share.x,
                    'storage_type': 'hsm',
                    'key_id': key_id
                }
            else:
                # Fall back to file-based storage
                location_path = Path(location)
                location_path.mkdir(parents=True, exist_ok=True)
                
                share_file = location_path / f"{share.key_id}_share_{share.x}.json"
                with open(share_file, 'wb') as f:
                    f.write(share_data)
                
                # Set secure permissions
                share_file.chmod(0o600)
                
                return {
                    'stored_at': int(time.time()),
                    'location': str(share_file.absolute()),
                    'share_index': share.x,
                    'storage_type': 'file'
                }
                
        except Exception as e:
            logger.error(f"Failed to store share: {e}")
            raise ValueError(f"Failed to store share: {e}")
    
    def _load_share(self, location: str, share_data: Optional[Dict] = None) -> KeyShare:
        """
        Load a share from the specified location or HSM
        
        Args:
            location: The location identifier or HSM key ID
            share_data: Optional share data (if already loaded)
            
        Returns:
            The loaded KeyShare
            
        Raises:
            InvalidShareError: If the share is invalid or cannot be loaded
        """
        try:
            if share_data is not None:
                # If share data is already provided, use it directly
                return KeyShare.from_dict(share_data)
                
            # Check if this is an HSM location
            if location.startswith('hsm://'):
                if not self.hsm or not self.hsm.is_available():
                    raise InvalidShareError("HSM is not available for share retrieval")
                    
                # Extract key ID from location (format: hsm://location_share_X)
                key_id = location[7:]  # Remove 'hsm://' prefix
                share_bytes = self.hsm.retrieve_key(key_id)
                if not share_bytes:
                    raise InvalidShareError(f"Failed to retrieve share from HSM with key ID: {key_id}")
                    
                try:
                    share_dict = json.loads(share_bytes.decode('utf-8'))
                    return KeyShare.from_dict(share_dict)
                except (json.JSONDecodeError, KeyError) as e:
                    raise InvalidShareError(f"Invalid share data from HSM: {e}")
                    
            else:
                # Load from file
                share_file = Path(location)
                if not share_file.exists():
                    raise InvalidShareError(f"Share file not found: {location}")
                    
                with open(share_file, 'rb') as f:
                    share_dict = json.loads(f.read().decode('utf-8'))
                    return KeyShare.from_dict(share_dict)
                    
        except Exception as e:
            logger.error(f"Error loading share from {location}: {e}", exc_info=True)
            raise InvalidShareError(f"Failed to load share: {e}")
    
    def _store_share_file(self, share: KeyShare, path: str) -> Dict:
        """Store a share in a file"""
        try:
            # Ensure the directory exists
            path_obj = Path(path)
            path_obj.parent.mkdir(parents=True, exist_ok=True)
            
            # Write the share to the file
            with open(path, 'w') as f:
                json.dump(share.to_dict(), f)
                
            # Set secure permissions
            path_obj.chmod(0o600)  # Owner read/write only
            
            return {
                'path': str(path_obj.absolute()),
                'size': path_obj.stat().st_size,
                'stored_at': int(time.time())
            }
            
        except (IOError, OSError) as e:
            raise ValueError(f"Failed to store share at {path}: {e}")
    
    def _load_share_file(self, path: str) -> KeyShare:
        """Load a share from a file"""
        try:
            with open(path, 'r') as f:
                share_data = json.load(f)
                
            return KeyShare.from_dict(share_data)
            
        except (IOError, OSError, json.JSONDecodeError) as e:
            raise ValueError(f"Failed to load share from {path}: {e}")
    
    def _store_share_hsm(self, share: KeyShare, key_id: str) -> Dict:
        """Store a share in the HSM"""
        if not self.hsm:
            raise ValueError("HSM integration not available")
            
        try:
            # Store the share in the HSM
            self.hsm.store_key(
                key_id=key_id,
                key_data=json.dumps(share.to_dict()).encode(),
                key_type='share',
                metadata={
                    'key_id': share.key_id,
                    'share_index': share.x,
                    'created_at': int(time.time())
                }
            )
            
            return {
                'hsm_key_id': key_id,
                'stored_at': int(time.time())
            }
            
        except Exception as e:
            raise ValueError(f"Failed to store share in HSM: {e}")
    
    def _load_share_hsm(self, key_id: str) -> KeyShare:
        """Load a share from the HSM"""
        if not self.hsm:
            raise ValueError("HSM integration not available")
            
        try:
            # Retrieve the share from the HSM
            share_data = self.hsm.retrieve_key(key_id)
            if not share_data:
                raise ValueError(f"Share not found in HSM: {key_id}")
                
            # Parse the share data
            share_dict = json.loads(share_data.decode())
            return KeyShare.from_dict(share_dict)
            
        except Exception as e:
            raise ValueError(f"Failed to load share from HSM: {e}")

# Example usage
if __name__ == "__main__":
    import time
    
    # Example configuration
    config = {
        'threshold': 3,
        'total_shares': 5,
        'backup_locations': [
            'file:/tmp/secure_vault/shares/share1.json',
            'file:/tmp/secure_vault/shares/share2.json',
            'file:/tmp/secure_vault/shares/share3.json',
            'file:/tmp/secure_vault/shares/share4.json',
            'file:/tmp/secure_vault/shares/share5.json'
        ]
    }
    
    # Create a key backup manager
    backup_manager = KeyBackupManager(config=config)
    
    # Example key to back up
    key_id = "example_key_" + str(int(time.time()))
    key_data = os.urandom(32)  # 256-bit key
    
    print(f"Creating backup for key: {key_id}")
    
    try:
        # Create a backup
        backup_metadata = backup_manager.create_backup(key_id, key_data)
        print(f"Backup created successfully. Metadata: {json.dumps(backup_metadata, indent=2)}")
        
        # Simulate recovery using the first 3 shares
        shares_to_recover = backup_metadata['locations'][:3]
        print(f"\nRecovering key from {len(shares_to_recover)} shares...")
        
        # Load the shares
        shares_data = []
        for loc in shares_to_recover:
            share = backup_manager._load_share(loc['location'])
            shares_data.append({
                'location': loc['location'],
                'share_data': share.to_dict()
            })
        
        # Recover the key
        recovered_key = backup_manager.recover_key(key_id, shares_data)
        
        # Verify the recovered key matches the original
        if secure_compare(key_data, recovered_key):
            print("\nSUCCESS: Key recovered successfully!")
            print(f"Original key: {key_data.hex()}")
            print(f"Recovered key: {recovered_key.hex()}")
        else:
            print("\nERROR: Recovered key does not match the original!")
            print(f"Original key: {key_data.hex()}")
            print(f"Recovered key: {recovered_key.hex()}")
        
    except Exception as e:
        print(f"\nERROR: {e}")
        import traceback
        traceback.print_exc()
