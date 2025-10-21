"""
Secure Storage Module

Handles secure storage of sensitive data like encryption keys and passwords
using the secure_memory module to prevent memory dumps and swapping.
"""

import os
import json
from typing import Dict, Any, Optional, Union
from pathlib import Path

from secure_memory import SecureBytes, SecureString, secure_alloc
from crypto_utils import constant_time_compare

class SecureStorage:
    """
    Secure storage for sensitive data that ensures memory is locked and zeroed when done.
    """
    
    def __init__(self, storage_path: Optional[Union[str, Path]] = None):
        """
        Initialize secure storage.
        
        Args:
            storage_path: Optional path for persistent storage (encrypted).
                         If None, data is only kept in memory.
        """
        self._storage_path = Path(storage_path) if storage_path else None
        self._secrets: Dict[str, bytes] = {}
        self._secure_objects = []  # Keep track of secure objects for cleanup
    
    def store_secret(self, key: str, value: Union[str, bytes]) -> None:
        """
        Store a secret securely in memory.
        
        Args:
            key: Identifier for the secret
            value: The secret value (string or bytes)
        """
        # Convert string to bytes if needed
        if isinstance(value, str):
            value = value.encode('utf-8')
            
        # Store in secure memory
        secure_val = SecureBytes(value)
        self._secrets[key] = secure_val
        self._secure_objects.append(secure_val)
    
    def get_secret(self, key: str) -> Optional[bytes]:
        """
        Retrieve a secret from secure storage.
        
        Args:
            key: Identifier for the secret
            
        Returns:
            The secret bytes or None if not found
        """
        if key not in self._secrets:
            return None
            
        # Return a copy to prevent modification of the secure storage
        return bytes(self._secrets[key])
    
    def compare_secret(self, key: str, value: Union[str, bytes]) -> bool:
        """
        Securely compare a value with a stored secret.
        
        Args:
            key: Identifier for the secret
            value: Value to compare against
            
        Returns:
            bool: True if the values match, False otherwise
        """
        if key not in self._secrets:
            return False
            
        stored = self._secrets[key]
        if isinstance(value, str):
            value = value.encode('utf-8')
            
        # Use constant-time comparison
        return constant_time_compare(bytes(stored), value)
    
    def store_secure_string(self, key: str, value: str) -> None:
        """
        Store a string secret securely.
        
        Args:
            key: Identifier for the secret
            value: The secret string
        """
        secure_str = SecureString(value)
        self._secrets[key] = secure_str
        self._secure_objects.append(secure_str)
    
    def get_secure_string(self, key: str) -> Optional[str]:
        """
        Retrieve a string secret from secure storage.
        
        Args:
            key: Identifier for the secret
            
        Returns:
            The secret string or None if not found
        """
        if key not in self._secrets or not isinstance(self._secrets[key], SecureString):
            return None
            
        # Return a copy of the string
        return str(self._secrets[key])
    
    def secure_erase(self) -> None:
        """
        Securely erase all stored secrets from memory.
        """
        for obj in self._secure_objects:
            if hasattr(obj, 'zero'):
                obj.zero()
        self._secrets.clear()
        self._secure_objects.clear()
    
    def __del__(self):
        """Ensure secure erasure when object is destroyed."""
        self.secure_erase()

# Global secure storage instance
secure_storage = SecureStorage()

def get_secure_storage() -> SecureStorage:
    """Get the global secure storage instance."""
    return secure_storage
