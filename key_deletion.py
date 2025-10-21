"""
Secure Key Deletion and Archival Module

This module provides secure key deletion and archival functionality, ensuring that
keys are properly destroyed or archived according to security best practices.
"""
import os
import logging
import hashlib
import hmac
import secrets
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum, auto
from datetime import datetime

# Import our audit logger for tracking deletion/archival events
from audit_logger import AuditLogger

logger = logging.getLogger(__name__)

class DeletionMethod(Enum):
    """Methods for secure key deletion"""
    ZEROIZE = auto()        # Overwrite with zeros
    RANDOMIZE = auto()      # Overwrite with random data
    CRYPTO_ERASE = auto()   # Cryptographically erase (e.g., by deleting the key-encrypting-key)
    PHYSICAL = auto()       # Physical destruction (for HSMs)

class ArchivalPolicy(Enum):
    """Archival retention policies"""
    RETAIN_30_DAYS = 30
    RETAIN_90_DAYS = 90
    RETAIN_1_YEAR = 365
    RETAIN_7_YEARS = 2555  # 7 * 365
    INDEFINITE = -1

@dataclass
class KeyDeletionRecord:
    """Record of a key deletion operation"""
    key_id: str
    deletion_time: float
    method: DeletionMethod
    verified: bool = False
    verification_time: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'key_id': self.key_id,
            'deletion_time': self.deletion_time,
            'method': self.method.name,
            'verified': self.verified,
            'verification_time': self.verification_time,
            'metadata': self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'KeyDeletionRecord':
        """Create from dictionary"""
        return cls(
            key_id=data['key_id'],
            deletion_time=data['deletion_time'],
            method=DeletionMethod[data['method']],
            verified=data.get('verified', False),
            verification_time=data.get('verification_time'),
            metadata=data.get('metadata', {})
        )

@dataclass
class ArchivedKey:
    """Represents an archived key"""
    key_id: str
    archived_at: float
    archived_by: str
    policy: ArchivalPolicy
    encrypted_data: bytes
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'key_id': self.key_id,
            'archived_at': self.archived_at,
            'archived_by': self.archived_by,
            'policy': self.policy.name,
            'encrypted_data': self.encrypted_data.hex(),
            'metadata': self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ArchivedKey':
        """Create from dictionary"""
        return cls(
            key_id=data['key_id'],
            archived_at=data['archived_at'],
            archived_by=data['archived_by'],
            policy=ArchivalPolicy[data['policy']],
            encrypted_data=bytes.fromhex(data['encrypted_data']),
            metadata=data.get('metadata', {})
        )

class KeyDeletionManager:
    """Manages secure key deletion and archival"""
    
    def __init__(
        self,
        key_manager,
        audit_logger: Optional[AuditLogger] = None,
        default_deletion_method: DeletionMethod = DeletionMethod.ZEROIZE,
        default_archival_policy: ArchivalPolicy = ArchivalPolicy.RETAIN_90_DAYS
    ):
        """Initialize with key manager and configuration"""
        self.key_manager = key_manager
        self.audit_logger = audit_logger or AuditLogger()
        self.default_deletion_method = default_deletion_method
        self.default_archival_policy = default_archival_policy
        
        # In-memory storage (replace with persistent storage in production)
        self.deletion_records: Dict[str, KeyDeletionRecord] = {}
        self.archived_keys: Dict[str, ArchivedKey] = {}
    
    def delete_key(
        self,
        key_id: str,
        method: Optional[DeletionMethod] = None,
        require_confirmation: bool = True,
        metadata: Optional[Dict[str, Any]] = None,
        requestor: Optional[str] = None
    ) -> bool:
        """Securely delete a key
        
        Args:
            key_id: ID of the key to delete
            method: Deletion method to use (defaults to instance default)
            require_confirmation: Whether to require confirmation before deletion
            metadata: Optional metadata to include with the deletion record
            requestor: Username or ID of the user requesting deletion
            
        Returns:
            bool: True if deletion was successful, False otherwise
        """
        if method is None:
            method = self.default_deletion_method
        
        # Log the deletion request
        self.audit_logger.log(
            action='key_deletion_requested',
            target=key_id,
            status='pending',
            details={
                'method': method.name,
                'requestor': requestor,
                'metadata': metadata or {}
            },
            user=requestor
        )
        
        try:
            # Get the key material (for secure erasure)
            key_data = self.key_manager.export_key(key_id)
            if not key_data:
                raise ValueError(f"Key {key_id} not found or cannot be exported")
            
            # Perform the secure deletion
            self._secure_erase(key_data, method)
            
            # Delete the key from the key manager
            if not self.key_manager.delete_key(key_id):
                raise RuntimeError(f"Failed to delete key {key_id} from key manager")
            
            # Create and store deletion record
            record = KeyDeletionRecord(
                key_id=key_id,
                deletion_time=time.time(),
                method=method,
                metadata=metadata or {}
            )
            self.deletion_records[key_id] = record
            
            # Log successful deletion
            self.audit_logger.log(
                action='key_deleted',
                target=key_id,
                status='success',
                details={
                    'method': method.name,
                    'requestor': requestor,
                    'metadata': metadata or {}
                },
                user=requestor
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to delete key {key_id}: {e}")
            self.audit_logger.log(
                action='key_deletion_failed',
                target=key_id,
                status='failed',
                details={
                    'error': str(e),
                    'method': method.name if method else None,
                    'requestor': requestor,
                    'metadata': metadata or {}
                },
                user=requestor
            )
            return False
    
    def archive_key(
        self,
        key_id: str,
        policy: Optional[ArchivalPolicy] = None,
        metadata: Optional[Dict[str, Any]] = None,
        requestor: Optional[str] = None
    ) -> bool:
        """Archive a key for long-term storage
        
        Args:
            key_id: ID of the key to archive
            policy: Archival retention policy (defaults to instance default)
            metadata: Optional metadata to include with the archive
            requestor: Username or ID of the user requesting archival
            
        Returns:
            bool: True if archival was successful, False otherwise
        """
        if policy is None:
            policy = self.default_archival_policy
        
        # Log the archival request
        self.audit_logger.log(
            action='key_archival_requested',
            target=key_id,
            status='pending',
            details={
                'policy': policy.name,
                'requestor': requestor,
                'metadata': metadata or {}
            },
            user=requestor
        )
        
        try:
            # Export the key material
            key_data = self.key_manager.export_key(key_id)
            if not key_data:
                raise ValueError(f"Key {key_id} not found or cannot be exported")
            
            # In a real implementation, we would encrypt the key data with a
            # dedicated archival key before storage
            encrypted_data = self._encrypt_for_archival(key_data)
            
            # Create and store the archive record
            archived_key = ArchivedKey(
                key_id=key_id,
                archived_at=time.time(),
                archived_by=requestor or 'system',
                policy=policy,
                encrypted_data=encrypted_data,
                metadata=metadata or {}
            )
            self.archived_keys[key_id] = archived_key
            
            # Log successful archival
            self.audit_logger.log(
                action='key_archived',
                target=key_id,
                status='success',
                details={
                    'policy': policy.name,
                    'requestor': requestor,
                    'metadata': metadata or {}
                },
                user=requestor
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to archive key {key_id}: {e}")
            self.audit_logger.log(
                action='key_archival_failed',
                target=key_id,
                status='failed',
                details={
                    'error': str(e),
                    'policy': policy.name if policy else None,
                    'requestor': requestor,
                    'metadata': metadata or {}
                },
                user=requestor
            )
            return False
    
    def verify_deletion(self, key_id: str) -> bool:
        """Verify that a key has been securely deleted
        
        Args:
            key_id: ID of the key to verify
            
        Returns:
            bool: True if deletion is verified, False otherwise
        """
        if key_id not in self.deletion_records:
            return False
            
        # In a real implementation, we would verify that the key material
        # has been securely erased according to the specified method
        # For this example, we'll just check that the key is no longer accessible
        try:
            if self.key_manager.get_key(key_id) is not None:
                return False
                
            # Mark as verified
            record = self.deletion_records[key_id]
            record.verified = True
            record.verification_time = time.time()
            
            # Log verification
            self.audit_logger.log(
                action='key_deletion_verified',
                target=key_id,
                status='success',
                details={'method': record.method.name}
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to verify deletion of key {key_id}: {e}")
            return False
    
    def _secure_erase(self, data: bytes, method: DeletionMethod) -> None:
        """Securely erase data in memory
        
        Args:
            data: The data to erase
            method: The erasure method to use
        """
        # This is a simplified implementation
        # In a real implementation, we would use platform-specific secure memory erasure
        if method == DeletionMethod.ZEROIZE:
            for i in range(len(data)):
                data[i] = 0
        elif method == DeletionMethod.RANDOMIZE:
            for i in range(len(data)):
                data[i] = secrets.randbits(8)
        elif method == DeletionMethod.CRYPTO_ERASE:
            # For crypto erase, we would delete the key-encrypting-key
            # which makes the data irrecoverable
            pass
        # PHYSICAL method would be handled by HSM-specific code
    
    def _encrypt_for_archival(self, data: bytes) -> bytes:
        """Encrypt data for archival storage
        
        Args:
            data: The data to encrypt
            
        Returns:
            Encrypted data
            
        Note: In a real implementation, this would use a dedicated archival key
        """
        # This is a placeholder - in a real implementation, we would use
        # a dedicated archival key stored in an HSM
        key = os.urandom(32)
        iv = os.urandom(16)
        # In a real implementation, we would use a proper AEAD cipher here
        return key + iv + data  # This is NOT secure - for illustration only
    
    def get_deletion_record(self, key_id: str) -> Optional[KeyDeletionRecord]:
        """Get the deletion record for a key, if it exists"""
        return self.deletion_records.get(key_id)
    
    def get_archived_key(self, key_id: str) -> Optional[ArchivedKey]:
        """Get an archived key, if it exists"""
        return self.archived_keys.get(key_id)
    
    def list_deleted_keys(self) -> List[str]:
        """Get a list of all deleted key IDs"""
        return list(self.deletion_records.keys())
    
    def list_archived_keys(self) -> List[str]:
        """Get a list of all archived key IDs"""
        return list(self.archived_keys.keys())
