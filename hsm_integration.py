"""
HSM (Hardware Security Module) Integration Module

This module provides an abstraction layer for interacting with Hardware Security Modules.
It supports multiple HSM backends and provides a unified interface for cryptographic operations.
"""

import logging
from typing import Optional, Union, Tuple, List, Dict, Any
from dataclasses import dataclass
from enum import Enum, auto
import abc
import os
import json
import hashlib
import hmac
import struct
from pathlib import Path

# Import existing security utilities
from crypto_utils import secure_compare, secure_wipe
from secure_memory import SecureBytes

try:
    import pkcs11
    from pkcs11 import KeyType, Mechanism, ObjectClass, Attribute
    PKCS11_AVAILABLE = True
except ImportError:
    PKCS11_AVAILABLE = False

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class HSMType(Enum):
    """Supported HSM types"""
    PKCS11 = auto()
    PKCS11_SIMULATOR = auto()
    FILE_BASED = auto()
    AWS_KMS = auto()
    GOOGLE_CLOUD_KMS = auto()
    AZURE_KEY_VAULT = auto()
    YUBIKEY = auto()

@dataclass
class HSMKey:
    """Represents a key stored in the HSM"""
    key_id: str
    key_type: str
    public_data: Optional[bytes] = None
    attributes: Optional[Dict[str, Any]] = None

class HSMError(Exception):
    """Base exception for HSM-related errors"""
    pass

class HSMUnavailableError(HSMError):
    """Raised when the HSM is not available"""
    pass

class HSMOperationError(HSMError):
    """Raised when an HSM operation fails"""
    pass

class HSMSession(abc.ABC):
    """Abstract base class for HSM sessions"""
    
    @abc.abstractmethod
    def __init__(self, config: Dict[str, Any]):
        """Initialize the HSM session with the given configuration"""
        pass
    
    @abc.abstractmethod
    def is_available(self) -> bool:
        """Check if the HSM is available"""
        pass
    
    @abc.abstractmethod
    def generate_key(self, key_id: str, key_type: str = 'AES-256', 
                    extractable: bool = False) -> HSMKey:
        """Generate a new key in the HSM"""
        pass
    
    @abc.abstractmethod
    def get_key(self, key_id: str) -> Optional[HSMKey]:
        """Retrieve a key from the HSM"""
        pass
    
    @abc.abstractmethod
    def delete_key(self, key_id: str) -> bool:
        """Delete a key from the HSM"""
        pass
    
    @abc.abstractmethod
    def encrypt(self, key_id: str, plaintext: bytes, 
               aad: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """Encrypt data using a key in the HSM"""
        pass
    
    @abc.abstractmethod
    def decrypt(self, key_id: str, ciphertext: bytes, 
               iv: bytes, aad: Optional[bytes] = None) -> bytes:
        """Decrypt data using a key in the HSM"""
        pass
    
    @abc.abstractmethod
    def sign(self, key_id: str, data: bytes) -> bytes:
        """Sign data using a key in the HSM"""
        pass
    
    @abc.abstractmethod
    def verify(self, key_id: str, data: bytes, signature: bytes) -> bool:
        """Verify a signature using a key in the HSM"""
        pass
    
    @abc.abstractmethod
    def close(self):
        """Close the HSM session"""
        pass

class PKCS11HSMSession(HSMSession):
    """PKCS#11 HSM implementation"""
    
    def __init__(self, config: Dict[str, Any]):
        if not PKCS11_AVAILABLE:
            raise HSMUnavailableError("PKCS#11 library not available")
            
        self.config = config
        self.lib = config.get('pkcs11_library')
        self.slot = config.get('slot')
        self.pin = config.get('pin', '')
        self.session = None
        self._connect()
    
    def _connect(self):
        """Establish connection to the HSM"""
        try:
            lib = pkcs11.lib(self.lib)
            token = lib.get_token(token_spec=self.slot)
            self.session = token.open(user_pin=self.pin)
            logger.info("Successfully connected to PKCS#11 HSM")
        except Exception as e:
            logger.error(f"Failed to connect to PKCS#11 HSM: {e}")
            raise HSMUnavailableError(f"PKCS#11 HSM unavailable: {e}")
    
    def is_available(self) -> bool:
        return self.session is not None
    
    def generate_key(self, key_id: str, key_type: str = 'AES-256', 
                    extractable: bool = False) -> HSMKey:
        if not self.session:
            raise HSMUnavailableError("No active HSM session")
            
        try:
            # Convert key type to PKCS#11 key type
            if key_type.startswith('AES-'):
                key_size = int(key_type.split('-')[1])
                key_type = KeyType.AES
            else:
                raise ValueError(f"Unsupported key type: {key_type}")
            
            # Generate the key
            key = self.session.generate_key(
                key_type=key_type,
                key_size=key_size,
                template={
                    Attribute.ID: key_id.encode(),
                    Attribute.LABEL: key_id,
                    Attribute.TOKEN: True,
                    Attribute.EXTRACTABLE: extractable,
                    Attribute.SIGN: True,
                    Attribute.ENCRYPT: True,
                    Attribute.DECRYPT: True,
                    Attribute.WRAP: True,
                    Attribute.UNWRAP: True,
                }
            )
            
            return HSMKey(
                key_id=key_id,
                key_type=key_type,
                attributes={
                    'key_size': key_size,
                    'extractable': extractable
                }
            )
            
        except Exception as e:
            logger.error(f"Failed to generate key in HSM: {e}")
            raise HSMOperationError(f"Key generation failed: {e}")
    
    # Implement other required methods...
    
    def close(self):
        if self.session:
            self.session.close()
            self.session = None

class FileBasedHSMSession(HSMSession):
    """File-based HSM simulator for development and testing"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.keys_dir = Path(config.get('keys_dir', 'hsm_keys'))
        self.keys_dir.mkdir(exist_ok=True, mode=0o700)
        self.keys = {}
        self._load_keys()
    
    def _load_keys(self):
        """Load keys from the filesystem"""
        self.keys = {}
        for key_file in self.keys_dir.glob('*'):  
            try:
                with open(key_file, 'r') as f:
                    key_data = json.load(f)
                    self.keys[key_data['key_id']] = key_data
            except (json.JSONDecodeError, KeyError) as e:
                logger.warning(f"Failed to load key from {key_file}: {e}")
    
    def is_available(self) -> bool:
        return True  
    
    def generate_key(self, key_id: str, key_type: str = 'AES-256', 
                    extractable: bool = False) -> HSMKey:
        key_size = int(key_type.split('-')[-1]) // 8  
        key_data = os.urandom(key_size)
        
        key_path = self.keys_dir / f"{key_id}.json"
        key_info = {
            'key_id': key_id,
            'key_type': key_type,
            'key_data': key_data.hex(),
            'extractable': extractable,
            'created_at': int(time.time())
        }
        
        # Store the key (in a real HSM, the key would never leave the device)
        key_file = self.keys_dir / f"{key_id}.json"
        with open(key_file, 'w') as f:
            json.dump({
                'key_type': key_type,
                'public_data': key.public_data.hex() if key.public_data else '',
                'attributes': key.attributes
            }, f)
        os.chmod(key_file, 0o600)
        
        self.keys[key_id] = key
        return key
    
    def store_key(self, key_id: str, key_data: bytes, key_type: str = 'GENERIC', 
                 metadata: Optional[Dict] = None) -> bool:
        """
        Store arbitrary key data in the HSM
        
        Args:
            key_id: Unique identifier for the key
            key_data: The key data to store
            key_type: Type of the key (e.g., 'AES-256', 'RSA-2048', 'SHARE')
            metadata: Optional metadata to store with the key
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            key_path = self.keys_dir / f"{key_id}.json"
            key_info = {
                'key_id': key_id,
                'key_type': key_type,
                'key_data': key_data.hex(),
                'extractable': True,  # For stored data, we assume it's extractable
                'created_at': int(time.time()),
                'metadata': metadata or {}
            }
            
            with open(key_path, 'w') as f:
                json.dump(key_info, f)
                
            # Set secure permissions
            key_path.chmod(0o600)
            
            # Update in-memory cache
            self.keys[key_id] = key_info
            return True
            
        except Exception as e:
            logger.error(f"Failed to store key {key_id}: {e}")
            return False
            
    def retrieve_key(self, key_id: str) -> Optional[bytes]:
        """
        Retrieve key data from the HSM
        
        Args:
            key_id: The ID of the key to retrieve
            
        Returns:
            bytes: The key data, or None if not found
        """
        try:
            if key_id in self.keys:
                key_data = self.keys[key_id]
                if 'key_data' in key_data:
                    return bytes.fromhex(key_data['key_data'])
                    
            # Try to load from file if not in memory
            key_path = self.keys_dir / f"{key_id}.json"
            if key_path.exists():
                with open(key_path, 'r') as f:
                    key_data = json.load(f)
                    self.keys[key_id] = key_data  # Cache it
                    return bytes.fromhex(key_data['key_data'])
                    
            return None
            
        except Exception as e:
            logger.error(f"Failed to retrieve key {key_id}: {e}")
            return None

    def get_key(self, key_id: str) -> Optional[HSMKey]:
        """
        Retrieve a key from the HSM as an HSMKey object.

        Args:
            key_id: The ID of the key to retrieve

        Returns:
            HSMKey: The key object, or None if not found
        """
        try:
            if key_id in self.keys:
                key_data = self.keys[key_id]
            else:
                # Try to load from file if not in memory
                key_path = self.keys_dir / f"{key_id}.json"
                if not key_path.exists():
                    return None

                with open(key_path, 'r') as f:
                    key_data = json.load(f)
                    self.keys[key_id] = key_data  # Cache it

            # Convert to HSMKey object
            return HSMKey(
                key_id=key_data['key_id'],
                key_type=key_data.get('key_type', 'GENERIC'),
                public_data=bytes.fromhex(key_data.get('key_data', '')) if key_data.get('key_data') else None,
                attributes=key_data.get('metadata', {})
            )

        except Exception as e:
            logger.error(f"Failed to get key {key_id}: {e}")
            return None

    def delete_key(self, key_id: str) -> bool:
        """Delete a key from the HSM"""
        try:
            # Remove from memory
            if key_id in self.keys:
                del self.keys[key_id]
                
            # Remove from disk
            key_path = self.keys_dir / f"{key_id}.json"
            if key_path.exists():
                key_path.unlink()
                return True
                
            return False
            
        except Exception as e:
            logger.error(f"Failed to delete key {key_id}: {e}")
            return False
            
    def encrypt(self, key_id: str, plaintext: bytes, 
               aad: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """Encrypt data using a key in the HSM"""
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad
        from Crypto.Random import get_random_bytes
        
        # Get the key
        key = self.retrieve_key(key_id)
        if not key:
            raise HSMOperationError(f"Key {key_id} not found")
            
        # Generate a random IV
        iv = get_random_bytes(16)
        
        # Create cipher
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        
        # Add AAD if provided
        if aad:
            cipher.update(aad)
            
        # Encrypt the data
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
        
        # Get the authentication tag
        tag = cipher.digest()
        
        # Return IV + tag + ciphertext
        return (iv + tag, ciphertext)
        
    def decrypt(self, key_id: str, ciphertext: bytes, 
               iv: bytes, aad: Optional[bytes] = None) -> bytes:
        """Decrypt data using a key in the HSM"""
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad
        
        # Get the key
        key = self.retrieve_key(key_id)
        if not key:
            raise HSMOperationError(f"Key {key_id} not found")
            
        # Split IV and tag
        if len(iv) < 16 + 16:  # IV (16) + tag (16)
            raise HSMOperationError("Invalid IV/tag length")
            
        iv = iv[:16]
        tag = iv[16:32]
        
        try:
            # Create cipher
            cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
            
            # Add AAD if provided
            if aad:
                cipher.update(aad)
                
            # Decrypt the data
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            
            # Remove padding
            return unpad(plaintext, AES.block_size)
            
        except (ValueError, KeyError) as e:
            raise HSMOperationError(f"Decryption failed: {e}")
            
    def sign(self, key_id: str, data: bytes) -> bytes:
        """Sign data using a key in the HSM"""
        from Crypto.Hash import SHA256
        from Crypto.Signature import pkcs1_15
        from Crypto.PublicKey import RSA
        
        # Get the key
        key_data = self.retrieve_key(key_id)
        if not key_data:
            raise HSMOperationError(f"Key {key_id} not found")
            
        try:
            # In a real HSM, this would use the HSM's signing function
            key = RSA.import_key(key_data)
            h = SHA256.new(data)
            signature = pkcs1_15.new(key).sign(h)
            return signature
            
        except Exception as e:
            raise HSMOperationError(f"Signing failed: {e}")
            
    def verify(self, key_id: str, data: bytes, signature: bytes) -> bool:
        """Verify a signature using a key in the HSM"""
        from Crypto.Hash import SHA256
        from Crypto.Signature import pkcs1_15
        from Crypto.PublicKey import RSA
        
        # Get the key
        key_data = self.retrieve_key(key_id)
        if not key_data:
            raise HSMOperationError(f"Key {key_id} not found")
            
        try:
            # In a real HSM, this would use the HSM's verification function
            key = RSA.import_key(key_data)
            h = SHA256.new(data)
            pkcs1_15.new(key).verify(h, signature)
            return True
            
        except (ValueError, TypeError) as e:
            return False
            
    def close(self):
        """Close the HSM session and clean up"""
        # Clear sensitive data from memory
        for key_id in list(self.keys.keys()):
            if isinstance(self.keys[key_id], dict) and 'key_data' in self.keys[key_id]:
                self.keys[key_id]['key_data'] = 'REDACTED'
        self.keys.clear()

class HSMFactory:
    """Factory for creating HSM sessions"""
    
    @staticmethod
    def create_session(hsm_type: HSMType, config: Dict[str, Any]) -> HSMSession:
        """Create a new HSM session of the specified type"""
        if hsm_type == HSMType.PKCS11:
            return PKCS11HSMSession(config)
        elif hsm_type == HSMType.FILE_BASED:
            return FileBasedHSMSession(config)
        # Add other HSM types here
        else:
            raise ValueError(f"Unsupported HSM type: {hsm_type}")

# Example usage
if __name__ == "__main__":
    # Example configuration for file-based HSM (for testing)
    config = {
        'hsm_type': 'file',
        'keys_dir': 'hsm_test_keys'
    }
    
    try:
        # Create a file-based HSM session for testing
        hsm = HSMFactory.create_session(HSMType.FILE_BASED, config)
        
        # Generate a test key
        key = hsm.generate_key('test_key_1', 'AES-256')
        print(f"Generated key: {key.key_id} ({key.key_type})")
        
        # List available keys
        print(f"Available keys: {list(hsm.keys.keys())}")
        
        # Clean up
        hsm.close()
        
    except Exception as e:
        print(f"Error: {e}")
        if 'hsm' in locals():
            hsm.close()
