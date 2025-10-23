"""
Key Management with HSM Integration

This module provides secure key management using Hardware Security Modules (HSM)
for storing and handling cryptographic keys. It serves as the central key management
interface for the Secure Vault application.
"""

import os
import logging
import time
from typing import Optional, Dict, Any, Tuple, List, Union
from dataclasses import dataclass
from enum import Enum
import json
from pathlib import Path

# Import HSM integration
from hsm_integration import (
    HSMType,
    HSMFactory,
    HSMKey,
    HSMError,
    HSMUnavailableError,
    HSMOperationError
)

# Import security utilities
from crypto_utils import (
    secure_random_bytes,
    secure_compare,
    secure_wipe,
    derive_key_hkdf_sha3_512
)
from secure_memory import SecureBytes

logger = logging.getLogger(__name__)

class KeyType(Enum):
    """Supported key types"""
    OTP = "otp"           # One-Time Pad keys
    MLKEM = "mlkem"       # Post-quantum ML-KEM keys
    SYMMETRIC = "sym"     # Symmetric encryption keys
    MASTER = "master"     # Master key for key derivation
    BACKUP = "backup"     # Backup/recovery keys

class RotationPolicy:
    """Defines when and how a key should be rotated"""
    
    def __init__(
        self,
        max_age_days: int = 90,
        max_usage_count: Optional[int] = None,
        auto_rotate: bool = False,
        rotation_interval_days: int = 30,
        next_rotation_time: Optional[float] = None
    ):
        """Initialize rotation policy
        
        Args:
            max_age_days: Maximum age in days before rotation is required
            max_usage_count: Maximum number of uses before rotation is required (None for no limit)
            auto_rotate: Whether to automatically rotate the key when conditions are met
            rotation_interval_days: How often to rotate the key (in days) if auto_rotate is True
            next_rotation_time: Timestamp for next rotation (auto-calculated if None)
        """
        self.max_age_days = max_age_days
        self.max_usage_count = max_usage_count
        self.auto_rotate = auto_rotate
        self.rotation_interval_days = rotation_interval_days
        self.next_rotation_time = next_rotation_time or (time.time() + (rotation_interval_days * 86400))
    
    def needs_rotation(self, key_metadata: 'KeyMetadata') -> bool:
        """Check if key needs rotation based on policy"""
        now = time.time()
        
        # Check max age
        if (now - key_metadata.created_at) > (self.max_age_days * 86400):
            return True
            
        # Check usage count
        if self.max_usage_count and key_metadata.usage_count >= self.max_usage_count:
            return True
            
        # Check scheduled rotation
        if self.auto_rotate and now >= self.next_rotation_time:
            return True
            
        return False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert policy to dictionary"""
        return {
            'max_age_days': self.max_age_days,
            'max_usage_count': self.max_usage_count,
            'auto_rotate': self.auto_rotate,
            'rotation_interval_days': self.rotation_interval_days,
            'next_rotation_time': self.next_rotation_time
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'RotationPolicy':
        """Create policy from dictionary"""
        return cls(
            max_age_days=data.get('max_age_days', 90),
            max_usage_count=data.get('max_usage_count'),
            auto_rotate=data.get('auto_rotate', False),
            rotation_interval_days=data.get('rotation_interval_days', 30),
            next_rotation_time=data.get('next_rotation_time')
        )

from key_states import KeyLifecycle, KeyState, KeyVersion
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List, Union

@dataclass
class KeyMetadata:
    """Metadata for managed keys with lifecycle management"""
    key_id: str
    key_type: KeyType
    description: str = ""
    created_at: float = 0.0
    last_used: float = 0.0
    usage_count: int = 0
    enabled: bool = True
    tags: List[str] = None
    custom_metadata: Dict[str, Any] = None
    rotation_policy: Optional[RotationPolicy] = None
    rotated_from: Optional[str] = None
    rotated_at: Optional[float] = None
    rotated_to: Optional[str] = None
    _lifecycle: Optional[KeyLifecycle] = None
    
    def __post_init__(self):
        """Initialize key lifecycle if not provided"""
        if self._lifecycle is None:
            valid_from = datetime.fromtimestamp(self.created_at) if self.created_at else None
            self._lifecycle = KeyLifecycle(
                state=KeyState.ACTIVE if self.enabled else KeyState.SUSPENDED,
                valid_from=valid_from
            )
    
    @property
    def lifecycle(self) -> KeyLifecycle:
        """Get the key lifecycle manager"""
        if self._lifecycle is None:
            self.__post_init__()
        return self._lifecycle
    
    @property
    def state(self) -> KeyState:
        """Get current key state"""
        return self.lifecycle.state
    
    @property
    def version(self) -> str:
        """Get current key version"""
        return str(self.lifecycle.version)
    
    def is_valid(self) -> bool:
        """Check if key is valid for use"""
        return self.lifecycle.is_valid()
    
    def activate(self, reason: str = "Manual activation", metadata: Optional[Dict] = None) -> bool:
        """Activate the key"""
        result = self.lifecycle.activate(reason, metadata)
        if result:
            self.enabled = True
        return result
    
    def suspend(self, reason: str, metadata: Optional[Dict] = None) -> bool:
        """Suspend the key"""
        result = self.lifecycle.suspend(reason, metadata)
        if result:
            self.enabled = False
        return result
    
    def revoke(self, reason: str, metadata: Optional[Dict] = None) -> bool:
        """Revoke the key"""
        result = self.lifecycle.revoke(reason, metadata)
        if result:
            self.enabled = False
        return result
    
    def expire(self, reason: str = "Key expired", metadata: Optional[Dict] = None) -> bool:
        """Mark key as expired"""
        result = self.lifecycle.expire(reason, metadata)
        if result:
            self.enabled = False
        return result
    
    def get_state_history(self) -> List[Dict[str, Any]]:
        """Get the complete state history"""
        return self.lifecycle.get_state_history()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metadata to dictionary"""
        data = {
            'key_id': self.key_id,
            'key_type': self.key_type.value,
            'description': self.description,
            'created_at': self.created_at,
            'last_used': self.last_used,
            'usage_count': self.usage_count,
            'enabled': self.enabled,
            'tags': self.tags or [],
            'custom_metadata': self.custom_metadata or {},
            'rotation_policy': self.rotation_policy.to_dict() if self.rotation_policy else None,
            'rotated_from': self.rotated_from,
            'rotated_at': self.rotated_at,
            'rotated_to': self.rotated_to,
            'lifecycle': self.lifecycle.to_dict() if hasattr(self, '_lifecycle') and self._lifecycle else None
        }
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'KeyMetadata':
        """Create metadata from dictionary"""
        rotation_policy_data = data.get('rotation_policy')
        rotation_policy = RotationPolicy.from_dict(rotation_policy_data) if rotation_policy_data else None
        
        # Create instance
        instance = cls(
            key_id=data['key_id'],
            key_type=KeyType(data['key_type']),
            description=data.get('description', ''),
            created_at=data.get('created_at', 0.0),
            last_used=data.get('last_used', 0.0),
            usage_count=data.get('usage_count', 0),
            enabled=data.get('enabled', True),
            tags=data.get('tags'),
            custom_metadata=data.get('custom_metadata'),
            rotation_policy=rotation_policy,
            rotated_from=data.get('rotated_from'),
            rotated_at=data.get('rotated_at'),
            rotated_to=data.get('rotated_to')
        )
        
        # Set lifecycle if available
        if 'lifecycle' in data and data['lifecycle']:
            instance._lifecycle = KeyLifecycle.from_dict(data['lifecycle'])
        
        return instance

class KeyManager:
    """
    Central key management with HSM integration
    
    This class provides a high-level interface for key management, with
    secure storage in an HSM when available, falling back to secure
    file-based storage when not available.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the KeyManager with optional configuration.
        
        Args:
            config: Configuration dictionary with HSM and backup settings
                backup_enabled: bool - Enable automatic backups (default: True)
                backup_dir: str - Directory to store backups (default: 'backups')
                backup_retention: int - Number of backups to keep (default: 5)
                backup_schedule: int - Backup interval in hours (0 for no scheduled backups, default: 24)
                backup_passphrase: Optional[str] - Passphrase for backups (if None, will prompt when needed)
                rotation_check_interval: int - Interval in minutes to check for key rotations (default: 60)
                default_rotation_policy: Dict[str, Any] - Default rotation policy for new keys
        """
        self.config = {
            'backup_enabled': True,
            'backup_dir': 'backups',
            'backup_retention': 5,
            'backup_schedule': 24,  # hours
            'backup_passphrase': None,
            'rotation_check_interval': 60,  # minutes
            'default_rotation_policy': {
                'max_age_days': 90,
                'max_usage_count': 1000,
                'auto_rotate': True,
                'rotation_interval_days': 30
            },
            **(config or {})
        }
        
        self._hsm = None
        self._hsm_available = False
        self._key_metadata: Dict[str, KeyMetadata] = {}
        self._metadata_file = Path(self.config.get('metadata_file', 'key_metadata.json'))
        self._backup_thread = None
        self._stop_event = None
        
        # Create backup directory if it doesn't exist
        if self.config['backup_enabled']:
            os.makedirs(self.config['backup_dir'], mode=0o700, exist_ok=True)
        
        try:
            # Initialize HSM if configured
            self._init_hsm()
            
            # Load key metadata
            self._load_metadata()
            
            # Start backup scheduler if enabled
            if self.config['backup_enabled'] and self.config['backup_schedule'] > 0:
                self._start_backup_scheduler()
                
            # Start rotation checker
            self._start_rotation_checker()
                
            logger.info(f"KeyManager initialized with HSM: {self._hsm_available}")
            
            # Verify and attempt recovery if needed
            self._verify_and_recover()
            
        except Exception as e:
            logger.error(f"Initialization failed: {e}")
            if self.config['backup_enabled']:
                logger.info("Attempting recovery from backup...")
                self._attempt_recovery()
            raise
    
    def _init_hsm(self) -> None:
        """Initialize HSM connection and backup manager"""
        try:
            hsm_type = self.config.get('hsm_type', 'file')
            
            if hsm_type == 'pkcs11':
                hsm_config = {
                    'pkcs11_library': self.config.get('pkcs11_library'),
                    'slot': self.config.get('pkcs11_slot'),
                    'pin': self.config.get('pkcs11_pin')
                }
                self._hsm = HSMFactory.create_session(HSMType.PKCS11, hsm_config)
            else:
                # Fall back to file-based HSM
                keys_dir = self.config.get('keys_dir', 'hsm_keys')
                self._hsm = HSMFactory.create_session(
                    HSMType.FILE_BASED, 
                    {'keys_dir': keys_dir}
                )
            
            self._hsm_available = self._hsm.is_available()
            
            # Initialize backup manager if HSM is available
            if self._hsm_available and self.config['backup_enabled']:
                from key_recovery import KeyBackupManager
                self._backup_manager = KeyBackupManager(
                    hsm_integration=self._hsm,
                    config={
                        'threshold': self.config.get('backup_threshold', 2),
                        'total_shares': self.config.get('backup_shares', 3)
                    }
                )
            
        except Exception as e:
            logger.warning(f"Failed to initialize HSM: {e}")
            self._hsm_available = False
    
    def _load_metadata(self) -> None:
        """Load key metadata from disk"""
        try:
            if self._metadata_file.exists():
                with open(self._metadata_file, 'r') as f:
                    data = json.load(f)
                    self._key_metadata = {
                        k: KeyMetadata.from_dict(v) 
                        for k, v in data.items()
                    }
        except Exception as e:
            logger.error(f"Failed to load key metadata: {e}")
            self._key_metadata = {}
    
    def _save_metadata(self) -> None:
        """Save key metadata to disk and create backup if enabled"""
        try:
            # Save primary metadata file
            with open(self._metadata_file, 'w') as f:
                json.dump(
                    {k: v.to_dict() for k, v in self._key_metadata.items()},
                    f,
                    indent=2
                )
            os.chmod(self._metadata_file, 0o600)  # Restrict permissions
            
            # Create automatic backup if enabled
            if self.config['backup_enabled']:
                try:
                    backup_file = Path(self.config['backup_dir']) / f"metadata_backup_{int(time.time())}.json"
                    with open(backup_file, 'w') as f:
                        json.dump(
                            {k: v.to_dict() for k, v in self._key_metadata.items()},
                            f,
                            indent=2
                        )
                    os.chmod(backup_file, 0o600)
                    
                    # Clean up old backups
                    self._cleanup_old_backups()
                    
                except Exception as e:
                    logger.warning(f"Failed to create metadata backup: {e}")
                    
        except Exception as e:
            logger.error(f"Failed to save key metadata: {e}")
            if self.config['backup_enabled']:
                logger.info("Attempting to recover from backup...")
                self._attempt_recovery()
    
    def _cleanup_old_backups(self) -> None:
        """Remove old backups based on retention policy"""
        try:
            backup_dir = Path(self.config['backup_dir'])
            backups = sorted(backup_dir.glob("metadata_backup_*.json"), key=os.path.getmtime)
            
            # Keep only the most recent N backups
            for backup in backups[:-(self.config['backup_retention'] - 1)]:
                try:
                    os.remove(backup)
                except Exception as e:
                    logger.warning(f"Failed to remove old backup {backup}: {e}")
                    
        except Exception as e:
            logger.warning(f"Failed to clean up old backups: {e}")
            
    # Key Lifecycle Management Methods
    
    def activate_key(self, key_id: str, reason: str = "Manual activation") -> bool:
        """Activate a key for use.
        
        Args:
            key_id: ID of the key to activate
            reason: Reason for activation (for audit logging)
            
        Returns:
            bool: True if key was activated, False otherwise
        """
        if key_id not in self._key_metadata:
            logger.warning(f"Key {key_id} not found")
            return False
            
        try:
            metadata = self._key_metadata[key_id]
            if metadata.activate(reason):
                self._save_metadata()
                self._audit_logger.log_key_operation(
                    'activate',
                    key_id,
                    {'reason': reason, 'key_type': metadata.key_type.value}
                )
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to activate key {key_id}: {e}")
            return False
            
    def suspend_key(self, key_id: str, reason: str, metadata: Optional[Dict] = None) -> bool:
        """Suspend a key to temporarily prevent its use.
        
        Args:
            key_id: ID of the key to suspend
            reason: Reason for suspension (for audit logging)
            metadata: Additional metadata about the suspension
            
        Returns:
            bool: True if key was suspended, False otherwise
        """
        if key_id not in self._key_metadata:
            logger.warning(f"Key {key_id} not found")
            return False
            
        try:
            key_metadata = self._key_metadata[key_id]
            if key_metadata.suspend(reason, metadata):
                self._save_metadata()
                self._audit_logger.log_key_operation(
                    'suspend',
                    key_id,
                    {
                        'reason': reason,
                        'key_type': key_metadata.key_type.value,
                        'metadata': metadata or {}
                    }
                )
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to suspend key {key_id}: {e}")
            return False
    
    def revoke_key(self, key_id: str, reason: str, metadata: Optional[Dict] = None) -> bool:
        """Revoke a key to permanently prevent its use.
        
        Args:
            key_id: ID of the key to revoke
            reason: Reason for revocation (for audit logging)
            metadata: Additional metadata about the revocation
            
        Returns:
            bool: True if key was revoked, False otherwise
        """
        if key_id not in self._key_metadata:
            logger.warning(f"Key {key_id} not found")
            return False
            
        try:
            key_metadata = self._key_metadata[key_id]
            if key_metadata.revoke(reason, metadata):
                self._save_metadata()
                self._audit_logger.log_key_operation(
                    'revoke',
                    key_id,
                    {
                        'reason': reason,
                        'key_type': key_metadata.key_type.value,
                        'metadata': metadata or {}
                    }
                )
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to revoke key {key_id}: {e}")
            return False
    
    def expire_key(self, key_id: str, reason: str = "Key expired", 
                  metadata: Optional[Dict] = None) -> bool:
        """Mark a key as expired.
        
        Args:
            key_id: ID of the key to expire
            reason: Reason for expiration (for audit logging)
            metadata: Additional metadata about the expiration
            
        Returns:
            bool: True if key was marked as expired, False otherwise
        """
        if key_id not in self._key_metadata:
            logger.warning(f"Key {key_id} not found")
            return False
            
        try:
            key_metadata = self._key_metadata[key_id]
            if key_metadata.expire(reason, metadata):
                self._save_metadata()
                self._audit_logger.log_key_operation(
                    'expire',
                    key_id,
                    {
                        'reason': reason,
                        'key_type': key_metadata.key_type.value,
                        'metadata': metadata or {}
                    }
                )
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to expire key {key_id}: {e}")
            return False
    
    def get_key_state(self, key_id: str) -> Optional[Dict[str, Any]]:
        """Get the current state of a key.
        
        Args:
            key_id: ID of the key
            
        Returns:
            Optional[Dict]: Key state information or None if key not found
        """
        if key_id not in self._key_metadata:
            return None
            
        metadata = self._key_metadata[key_id]
        return {
            'key_id': key_id,
            'state': metadata.state.name,
            'version': str(metadata.version),
            'is_valid': metadata.is_valid(),
            'created_at': metadata.created_at,
            'last_used': metadata.last_used,
            'usage_count': metadata.usage_count,
            'enabled': metadata.enabled
        }
    
    def get_key_state_history(self, key_id: str) -> Optional[List[Dict[str, Any]]]:
        """Get the state change history of a key.
        
        Args:
            key_id: ID of the key
            
        Returns:
            Optional[List[Dict]]: List of state changes or None if key not found
        """
        if key_id not in self._key_metadata:
            return None
            
        return self._key_metadata[key_id].get_state_history()
            
    def _start_backup_scheduler(self) -> None:
        """Start the periodic backup scheduler"""
        import threading

        def backup_worker():
            while not self._stop_event.is_set():
                try:
                    # Wait until the next scheduled backup time
                    next_run = datetime.now() + timedelta(hours=self.config['backup_schedule'])
                    while datetime.now() < next_run and not self._stop_event.is_set():
                        time.sleep(60)  # Check every minute
                    
                    if not self._stop_event.is_set():
                        logger.info("Starting scheduled backup...")
                        self.create_backup(
                            key_ids=list(self._key_metadata.keys()),
                            backup_passphrase=self._get_backup_passphrase(),
                            output_path=os.path.join(
                                self.config['backup_dir'],
                                f"scheduled_backup_{int(time.time())}.svb"
                            )
                        )
                        logger.info("Scheduled backup completed")
                        
                except Exception as e:
                    logger.error(f"Scheduled backup failed: {e}")
        
        self._stop_event = threading.Event()
        self._backup_thread = threading.Thread(target=backup_worker, daemon=True)
        self._backup_thread.start()
        
    def _start_rotation_checker(self) -> None:
        """Start the periodic rotation checker"""
        import threading

        def rotation_worker():
            while not self._rotation_stop_event.is_set():
                try:
                    # Check for keys needing rotation
                    self.check_and_rotate_keys()
                    
                    # Sleep for the configured interval
                    self._rotation_stop_event.wait(
                        self.config['rotation_check_interval'] * 60  # Convert minutes to seconds
                    )
                        
                except Exception as e:
                    logger.error(f"Rotation check failed: {e}")
                    # Don't exit on error, just wait and try again
                    self._rotation_stop_event.wait(60)  # Wait 1 minute before retrying on error
        
        self._rotation_stop_event = threading.Event()
        self._rotation_thread = threading.Thread(target=rotation_worker, daemon=True)
        self._rotation_thread.start()
    
    def _get_backup_passphrase(self) -> str:
        """Get backup passphrase from config or prompt user"""
        if self.config.get('backup_passphrase'):
            return self.config['backup_passphrase']
            
        # In a real application, you'd want to use a secure password prompt
        # This is a simplified version for demonstration
        import getpass
        passphrase = getpass.getpass("Enter backup passphrase: ")
        if not passphrase:
            raise ValueError("Backup passphrase cannot be empty")
        return passphrase
        
    def set_rotation_policy(
        self,
        key_id: str,
        max_age_days: Optional[int] = None,
        max_usage_count: Optional[int] = None,
        auto_rotate: Optional[bool] = None,
        rotation_interval_days: Optional[int] = None,
        next_rotation_time: Optional[float] = None
    ) -> bool:
        """Set or update rotation policy for a key
        
        Args:
            key_id: ID of the key to update
            max_age_days: Maximum age in days before rotation is required
            max_usage_count: Maximum number of uses before rotation is required
            auto_rotate: Whether to automatically rotate the key
            rotation_interval_days: How often to rotate the key if auto_rotate is True
            next_rotation_time: Timestamp for next rotation (None to calculate from now)
            
        Returns:
            bool: True if policy was updated, False otherwise
        """
        if key_id not in self._key_metadata:
            logger.warning(f"Key {key_id} not found")
            return False
            
        metadata = self._key_metadata[key_id]
        
        # Create new policy or update existing one
        if metadata.rotation_policy is None:
            # Create new policy with defaults from config
            policy_config = self.config['default_rotation_policy'].copy()
            metadata.rotation_policy = RotationPolicy(
                max_age_days=max_age_days or policy_config['max_age_days'],
                max_usage_count=max_usage_count or policy_config['max_usage_count'],
                auto_rotate=auto_rotate if auto_rotate is not None else policy_config['auto_rotate'],
                rotation_interval_days=rotation_interval_days or policy_config['rotation_interval_days']
            )
        else:
            # Update existing policy
            if max_age_days is not None:
                metadata.rotation_policy.max_age_days = max_age_days
            if max_usage_count is not None:
                metadata.rotation_policy.max_usage_count = max_usage_count
            if auto_rotate is not None:
                metadata.rotation_policy.auto_rotate = auto_rotate
            if rotation_interval_days is not None:
                metadata.rotation_policy.rotation_interval_days = rotation_interval_days
                
        # Update next rotation time if needed
        if next_rotation_time is not None:
            metadata.rotation_policy.next_rotation_time = next_rotation_time
        elif metadata.rotation_policy.auto_rotate and not metadata.rotation_policy.next_rotation_time:
            # Set initial next rotation time
            metadata.rotation_policy.next_rotation_time = (
                time.time() + (metadata.rotation_policy.rotation_interval_days * 86400)
            )
            
        self._save_metadata()
        logger.info(f"Updated rotation policy for key {key_id}")
        return True
        
    def rotate_key(self, key_id: str) -> Optional[str]:
        """Rotate a key by creating a new version and marking the old one as rotated
        
        Args:
            key_id: ID of the key to rotate
            
        Returns:
            str: ID of the new key, or None if rotation failed
        """
        if key_id not in self._key_metadata:
            logger.warning(f"Key {key_id} not found")
            return None
            
        old_metadata = self._key_metadata[key_id]
        
        # Create a new key with the same parameters
        try:
            new_key_id = f"{key_id}_v{int(time.time())}"
            
            # Generate new key with same parameters
            self._hsm.generate_key(
                key_id=new_key_id,
                key_type=old_metadata.key_type,
                **old_metadata.custom_metadata or {}
            )
            
            # Create metadata for new key
            new_metadata = KeyMetadata(
                key_id=new_key_id,
                key_type=old_metadata.key_type,
                description=f"Rotated from {key_id}",
                created_at=time.time(),
                custom_metadata=old_metadata.custom_metadata,
                rotation_policy=old_metadata.rotation_policy
            )
            
            # Update old key metadata
            old_metadata.rotated_at = time.time()
            old_metadata.rotated_to = new_key_id
            old_metadata.enabled = False  # Disable old key
            
            # Update new key metadata
            new_metadata.rotated_from = key_id
            
            # Save both metadata entries
            self._key_metadata[new_key_id] = new_metadata
            self._save_metadata()
            
            # Log the rotation
            self._audit_logger.log_key_operation(
                'rotate',
                key_id,
                {
                    'new_key_id': new_key_id,
                    'key_type': old_metadata.key_type.value,
                    'rotation_time': old_metadata.rotated_at
                }
            )
            
            logger.info(f"Rotated key {key_id} to {new_key_id}")
            return new_key_id
            
        except Exception as e:
            logger.error(f"Failed to rotate key {key_id}: {e}")
            return None
            
    def check_and_rotate_keys(self) -> Dict[str, str]:
        """Check all keys and rotate any that meet rotation criteria
        
        Returns:
            Dict[str, str]: Mapping of old key IDs to new key IDs for rotated keys
        """
        rotated = {}
        
        # Make a copy of keys to avoid modifying during iteration
        key_ids = list(self._key_metadata.keys())
        
        for key_id in key_ids:
            if key_id not in self._key_metadata:  # Skip if key was deleted during iteration
                continue
                
            metadata = self._key_metadata[key_id]
            
            # Skip if key is already rotated or has no rotation policy
            if not metadata.enabled or not metadata.rotation_policy:
                continue
                
            # Check if key needs rotation
            if metadata.rotation_policy.needs_rotation(metadata):
                logger.info(f"Rotating key {key_id} based on rotation policy")
                new_key_id = self.rotate_key(key_id)
                if new_key_id:
                    rotated[key_id] = new_key_id
                    
        return rotated
        
    def get_key_rotation_history(self, key_id: str) -> List[Dict[str, Any]]:
        """Get rotation history for a key
        
        Args:
            key_id: ID of the key to get history for
            
        Returns:
            List of rotation events in chronological order
        """
        history = []
        current_id = key_id
        
        # Follow the chain of rotated keys
        while current_id in self._key_metadata:
            metadata = self._key_metadata[current_id]
            
            if metadata.rotated_at:
                history.append({
                    'key_id': current_id,
                    'rotated_at': metadata.rotated_at,
                    'rotated_to': metadata.rotated_to,
                    'created_at': metadata.created_at,
                    'key_type': metadata.key_type.value
                })
                
            # Move to the next key in the chain
            current_id = metadata.rotated_from or ''
            
        # Sort by rotation time (oldest first)
        history.sort(key=lambda x: x.get('created_at', 0))
        return history
    
    def _verify_and_recover(self) -> None:
        """Verify metadata integrity and attempt recovery if needed"""
        try:
            # Check if metadata file exists
            if not self._metadata_file.exists():
                logger.info("No existing metadata file found - initializing new database")
                return

            # Simple verification - just try to load the metadata
            with open(self._metadata_file, 'r') as f:
                data = json.load(f)
                if not isinstance(data, dict):
                    raise ValueError("Invalid metadata format")

        except FileNotFoundError:
            # Normal on first run
            logger.info("Metadata file not found - will be created on first key operation")
        except Exception as e:
            logger.error(f"Metadata verification failed: {e}")
            if self.config['backup_enabled']:
                self._attempt_recovery()
    
    def _attempt_recovery(self) -> bool:
        """Attempt to recover from the most recent backup"""
        try:
            backup_dir = Path(self.config['backup_dir'])
            backups = sorted(backup_dir.glob("metadata_backup_*.json"), key=os.path.getmtime)
            
            if not backups:
                logger.warning("No backup files found for recovery")
                return False
                
            # Try the most recent backup first
            for backup in reversed(backups):
                try:
                    with open(backup, 'r') as f:
                        data = json.load(f)
                        if not isinstance(data, dict):
                            continue
                            
                        # If we got here, the backup is valid
                        logger.info(f"Recovering from backup: {backup}")
                        self._key_metadata = {
                            k: KeyMetadata.from_dict(v) for k, v in data.items()
                        }
                        self._save_metadata()
                        logger.info("Recovery successful")
                        return True
                        
                except Exception as e:
                    logger.warning(f"Failed to recover from {backup}: {e}")
                    continue
                    
            logger.error("All recovery attempts failed")
            return False
            
        except Exception as e:
            logger.error(f"Recovery process failed: {e}")
            return False
    
    def _update_key_metadata(self, key_id: str, **updates) -> None:
        """Update key metadata"""
        if key_id in self._key_metadata:
            metadata = self._key_metadata[key_id]
            for key, value in updates.items():
                if hasattr(metadata, key):
                    setattr(metadata, key, value)
            self._key_metadata[key_id] = metadata
            self._save_metadata()

    def update_key_metadata(self, key_id: str, **updates) -> None:
        """Public method to update key metadata and persist custom fields."""
        if key_id not in self._key_metadata:
            raise KeyError(f"Key {key_id} not found")

        metadata = self._key_metadata[key_id]
        custom_updates = updates.pop('custom_metadata', None)

        for key, value in updates.items():
            if hasattr(metadata, key):
                setattr(metadata, key, value)

        if custom_updates:
            merged_custom = dict(metadata.custom_metadata or {})
            merged_custom.update(custom_updates)
            metadata.custom_metadata = merged_custom

        self._key_metadata[key_id] = metadata
        self._save_metadata()
    
    def generate_key(self, key_type: KeyType, key_size: int = 32, 
                    key_id: Optional[str] = None, **metadata) -> Tuple[str, KeyMetadata]:
        """
        Generate a new cryptographic key.
        
        Args:
            key_type: Type of key to generate
            key_size: Size of the key in bytes
            key_id: Optional custom key ID
            **metadata: Additional metadata for the key
            
        Returns:
            Tuple of (key_id, KeyMetadata)
        """
        import time
        from uuid import uuid4
        
        # Generate a key ID if not provided
        if not key_id:
            key_id = f"{key_type.value}_{uuid4().hex[:8]}"
        
        try:
            # Generate the key in the HSM
            hsm_key_type = self._get_hsm_key_type(key_type, key_size)
            key = self._hsm.generate_key(
                key_id=key_id,
                key_type=hsm_key_type,
                extractable=False  # Never extract keys from HSM
            )
            
            # Create and store metadata
            metadata = KeyMetadata(
                key_id=key_id,
                key_type=key_type,
                created_at=time.time(),
                last_used=time.time(),
                usage_count=0,
                enabled=True,
                tags=metadata.get('tags', []),
                custom_metadata=metadata.get('custom_metadata', {})
            )
            
            self._key_metadata[key_id] = metadata
            self._save_metadata()
            
            logger.info(f"Generated new {key_type.value} key: {key_id}")
            return key_id, metadata
            
        except Exception as e:
            logger.error(f"Failed to generate key: {e}")
            raise HSMOperationError(f"Key generation failed: {e}")
    
    def get_key_metadata(self, key_id: str) -> Optional[KeyMetadata]:
        """Get metadata for a key"""
        return self._key_metadata.get(key_id)
    
    def list_keys(self, key_type: Optional[KeyType] = None) -> List[KeyMetadata]:
        """List all keys, optionally filtered by type"""
        if key_type is None:
            return list(self._key_metadata.values())
        return [m for m in self._key_metadata.values() if m.key_type == key_type]
    
    def delete_key(self, key_id: str) -> bool:
        """Delete a key and its metadata"""
        try:
            if self._hsm_available:
                self._hsm.delete_key(key_id)
            
            if key_id in self._key_metadata:
                del self._key_metadata[key_id]
                self._save_metadata()
                
            logger.info(f"Deleted key: {key_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to delete key {key_id}: {e}")
            return False
    
    def encrypt_with_key(self, key_id: str, plaintext: bytes, 
                        aad: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """
        Encrypt data using a key stored in the HSM.
        
        Args:
            key_id: ID of the key to use for encryption
            plaintext: Data to encrypt
            aad: Optional additional authenticated data
            
        Returns:
            Tuple of (ciphertext, iv)
        """
        try:
            if not self._hsm_available:
                raise HSMUnavailableError("HSM not available")
                
            # Update key usage stats
            metadata = self._key_metadata.get(key_id)
            if not metadata:
                raise KeyError(f"Key {key_id} not found")

            usage_count = metadata.usage_count + 1
            self.update_key_metadata(
                key_id,
                last_used=time.time(),
                usage_count=usage_count
            )
            
            return self._hsm.encrypt(key_id, plaintext, aad)
            
        except Exception as e:
            logger.error(f"Encryption with key {key_id} failed: {e}")
            raise HSMOperationError(f"Encryption failed: {e}")
    
    def decrypt_with_key(self, key_id: str, ciphertext: bytes, 
                        iv: bytes, aad: Optional[bytes] = None) -> bytes:
        """
        Decrypt data using a key stored in the HSM.
        
        Args:
            key_id: ID of the key to use for decryption
            ciphertext: Data to decrypt
            iv: Initialization vector
            aad: Optional additional authenticated data
            
        Returns:
            Decrypted plaintext
        """
        try:
            if not self._hsm_available:
                raise HSMUnavailableError("HSM not available")
                
            # Update key usage stats
            metadata = self._key_metadata.get(key_id)
            if not metadata:
                raise KeyError(f"Key {key_id} not found")

            usage_count = metadata.usage_count + 1
            self.update_key_metadata(
                key_id,
                last_used=time.time(),
                usage_count=usage_count
            )
            
            return self._hsm.decrypt(key_id, ciphertext, iv, aad)
            
        except Exception as e:
            logger.error(f"Decryption with key {key_id} failed: {e}")
            raise HSMOperationError(f"Decryption failed: {e}")
    
    def _get_hsm_key_type(self, key_type: KeyType, key_size: int) -> str:
        """Map key type to HSM key type"""
        if key_type == KeyType.OTP:
            return f"AES-{key_size * 8}"
        elif key_type == KeyType.MLKEM:
            return "ML-KEM-1024"
        elif key_type == KeyType.SYMMETRIC:
            return f"AES-{min(256, key_size * 8)}"  # Cap at 256 bits for AES
        elif key_type == KeyType.MASTER:
            return f"AES-{min(256, key_size * 8)}"
        elif key_type == KeyType.BACKUP:
            return f"AES-{min(256, key_size * 8)}"
        else:
            return f"AES-{min(256, key_size * 8)}"  # Default to AES
    
    def create_backup(self, key_ids: List[str], backup_passphrase: str, 
                      output_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Create a secure backup of specified keys.
        
        Args:
            key_ids: List of key IDs to include in the backup
            backup_passphrase: Strong passphrase to encrypt the backup
            output_path: Optional path to save the backup file. If None, returns the backup data.
            
        Returns:
            Dictionary containing backup data or status
            
        Raises:
            HSMOperationError: If backup creation fails
            ValueError: If no keys are provided or keys not found
        """
        if not key_ids:
            raise ValueError("At least one key ID must be provided")
            
        if not backup_passphrase or len(backup_passphrase) < 16:
            raise ValueError("Backup passphrase must be at least 16 characters long")
            
        # Verify all keys exist
        missing_keys = [key_id for key_id in key_ids if key_id not in self._key_metadata]
        if missing_keys:
            raise ValueError(f"Keys not found: {', '.join(missing_keys)}")
            
        try:
            # Generate a one-time backup key
            backup_key = secure_random_bytes(32)  # 256-bit key for AES-256
            
            # Create backup payload
            backup_time = time.time()
            backup_id = f"backup_{int(backup_time)}_{os.urandom(4).hex()}"
            
            # Prepare backup data
            backup_data = {
                'version': '1.0',
                'backup_id': backup_id,
                'timestamp': backup_time,
                'key_metadata': {},
                'keys': {}
            }
            
            # Export keys and metadata
            for key_id in key_ids:
                # Get key metadata
                metadata = self._key_metadata[key_id]
                backup_data['key_metadata'][key_id] = metadata.to_dict()
                
                # Export key from HSM (if supported)
                try:
                    key_data = self._hsm.export_key(key_id, wrap_key=backup_key)
                    backup_data['keys'][key_id] = key_data.hex()
                except Exception as e:
                    logger.warning(f"Could not export key {key_id}: {e}")
                    backup_data['keys'][key_id] = None
            
            # Encrypt backup data with the backup key
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            import base64
            
            # Derive encryption key from passphrase
            salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=600000,
            )
            encryption_key = kdf.derive(backup_passphrase.encode())
            
            # Encrypt the backup key with the derived key
            aesgcm = AESGCM(encryption_key)
            nonce = os.urandom(12)
            encrypted_backup_key = aesgcm.encrypt(nonce, backup_key, None)
            
            # Prepare final backup
            final_backup = {
                'format': 'secure_vault_backup',
                'version': '1.0',
                'backup_id': backup_id,
                'timestamp': backup_time,
                'salt': base64.b64encode(salt).decode(),
                'nonce': base64.b64encode(nonce).decode(),
                'encrypted_backup_key': base64.b64encode(encrypted_backup_key).decode(),
                'encrypted_data': base64.b64encode(
                    json.dumps(backup_data).encode()
                ).decode()
            }
            
            # Save to file if path provided
            if output_path:
                output_path = Path(output_path).with_suffix('.svb')
                with open(output_path, 'w') as f:
                    json.dump(final_backup, f, indent=2)
                os.chmod(output_path, 0o600)  # Restrict permissions
                logger.info(f"Backup saved to {output_path}")
                return {'status': 'success', 'backup_id': backup_id, 'path': str(output_path)}
            
            return {'status': 'success', 'backup_id': backup_id, 'data': final_backup}
            
        except Exception as e:
            logger.error(f"Backup creation failed: {e}")
            raise HSMOperationError(f"Backup creation failed: {e}")
    
    def restore_backup(self, backup_source: Union[str, Dict[str, Any]], 
                      backup_passphrase: str, 
                      key_ids: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Restore keys from a backup.
        
        Args:
            backup_source: Path to backup file or backup data dictionary
            backup_passphrase: Passphrase used to encrypt the backup
            key_ids: Optional list of key IDs to restore. If None, restores all keys.
            
        Returns:
            Dictionary with restoration status
            
        Raises:
            HSMOperationError: If restoration fails
            ValueError: If backup is invalid or passphrase is incorrect
        """
        try:
            # Load backup data
            if isinstance(backup_source, str):
                with open(backup_source, 'r') as f:
                    backup_data = json.load(f)
            else:
                backup_data = backup_source
                
            # Verify backup format
            if backup_data.get('format') != 'secure_vault_backup':
                raise ValueError("Invalid backup format")
                
            # Decode backup components
            import base64
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            from cryptography.exceptions import InvalidTag
            
            try:
                salt = base64.b64decode(backup_data['salt'])
                nonce = base64.b64decode(backup_data['nonce'])
                encrypted_backup_key = base64.b64decode(backup_data['encrypted_backup_key'])
                encrypted_data = base64.b64decode(backup_data['encrypted_data'])
            except (KeyError, base64.binascii.Error) as e:
                raise ValueError("Invalid backup data format") from e
            
            # Derive encryption key from passphrase
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=600000,
            )
            encryption_key = kdf.derive(backup_passphrase.encode())
            
            # Decrypt the backup key
            try:
                aesgcm = AESGCM(encryption_key)
                backup_key = aesgcm.decrypt(nonce, encrypted_backup_key, None)
            except InvalidTag:
                raise ValueError("Incorrect backup passphrase") from None
                
            # Decrypt the backup data
            backup_data = json.loads(encrypted_data)
            
            # Filter keys to restore
            if key_ids is None:
                key_ids = list(backup_data['key_metadata'].keys())
            else:
                key_ids = [k for k in key_ids if k in backup_data['key_metadata']]
                
            if not key_ids:
                raise ValueError("No valid keys found in backup")
                
            # Restore keys
            restored = []
            failed = []
            
            for key_id in key_ids:
                if key_id not in backup_data['keys'] or not backup_data['keys'][key_id]:
                    logger.warning(f"Key {key_id} not found in backup or could not be exported")
                    failed.append(key_id)
                    continue
                    
                try:
                    # Import key into HSM
                    key_data = bytes.fromhex(backup_data['keys'][key_id])
                    self._hsm.import_key(
                        key_id=key_id,
                        key_data=key_data,
                        key_type=backup_data['key_metadata'][key_id]['key_type'],
                        wrap_key=backup_key
                    )
                    
                    # Update metadata
                    metadata = KeyMetadata.from_dict(backup_data['key_metadata'][key_id])
                    self._key_metadata[key_id] = metadata
                    restored.append(key_id)
                    
                except Exception as e:
                    logger.error(f"Failed to restore key {key_id}: {e}")
                    failed.append(key_id)
            
            # Save updated metadata
            self._save_metadata()
            
            return {
                'status': 'partial' if failed else 'success',
                'restored': restored,
                'failed': failed,
                'backup_id': backup_data.get('backup_id', 'unknown')
            }
            
        except json.JSONDecodeError as e:
            raise ValueError("Invalid backup file format") from e
        except Exception as e:
            logger.error(f"Backup restoration failed: {e}")
            raise HSMOperationError(f"Backup restoration failed: {e}")
    
    def verify_backup(self, backup_source: Union[str, Dict[str, Any]], 
                     backup_passphrase: str) -> Dict[str, Any]:
        """
        Verify the integrity of a backup without restoring it.
        
        Args:
            backup_source: Path to backup file or backup data dictionary
            backup_passphrase: Passphrase to verify
            
        Returns:
            Dictionary with verification status and backup metadata
        """
        try:
            # Load backup data
            if isinstance(backup_source, str):
                with open(backup_source, 'r') as f:
                    backup_data = json.load(f)
            else:
                backup_data = backup_source
                
            # Just attempt to decrypt the backup key to verify the passphrase
            import base64
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            from cryptography.exceptions import InvalidTag
            
            try:
                salt = base64.b64decode(backup_data['salt'])
                nonce = base64.b64decode(backup_data['nonce'])
                encrypted_backup_key = base64.b64decode(backup_data['encrypted_backup_key'])
            except (KeyError, base64.binascii.Error) as e:
                return {'valid': False, 'error': 'Invalid backup format'}
            
            # Derive encryption key from passphrase
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=600000,
            )
            encryption_key = kdf.derive(backup_passphrase.encode())
            
            # Try to decrypt the backup key
            try:
                aesgcm = AESGCM(encryption_key)
                aesgcm.decrypt(nonce, encrypted_backup_key, None)
                
                # If we get here, the passphrase is correct
                return {
                    'valid': True,
                    'backup_id': backup_data.get('backup_id', 'unknown'),
                    'timestamp': backup_data.get('timestamp'),
                    'key_count': len(json.loads(base64.b64decode(backup_data['encrypted_data']))['key_metadata'])
                }
                
            except InvalidTag:
                return {'valid': False, 'error': 'Incorrect passphrase'}
                
        except Exception as e:
            logger.error(f"Backup verification failed: {e}")
            return {'valid': False, 'error': str(e)}
    
    def close(self) -> None:
        """Clean up resources"""
        # Stop the backup thread if running
        if self._stop_event:
            self._stop_event.set()
            if self._backup_thread and self._backup_thread.is_alive():
                self._backup_thread.join(timeout=30)
        
        # Stop the rotation thread if running
        if self._rotation_stop_event:
            self._rotation_stop_event.set()
            if self._rotation_thread and self._rotation_thread.is_alive():
                self._rotation_thread.join(timeout=30)
        
        # Close HSM connection
        if self._hsm:
            try:
                self._hsm.close()
            except Exception as e:
                logger.error(f"Error closing HSM: {e}")
        
        # Create one final backup before closing
        try:
            if self.config['backup_enabled'] and self._key_metadata:
                self.create_backup(
                    key_ids=list(self._key_metadata.keys()),
                    backup_passphrase=self._get_backup_passphrase(),
                    output_path=os.path.join(
                        self.config['backup_dir'],
                        f"shutdown_backup_{int(time.time())}.svb"
                    )
                )
        except Exception as e:
            logger.error(f"Failed to create final backup: {e}")
        
        # Clear sensitive data
        self._hsm = None
        self._hsm_available = False
        self._key_metadata.clear()
        self._save_metadata()

# Global key manager instance
_key_manager = None

def get_key_manager(config: Optional[Dict[str, Any]] = None) -> 'KeyManager':
    """Get the global key manager instance"""
    global _key_manager
    if _key_manager is None:
        _key_manager = KeyManager(config)
    return _key_manager

# Example usage
if __name__ == "__main__":
    import time
    
    # Initialize key manager with file-based HSM for testing
    config = {
        'hsm_type': 'file',
        'keys_dir': 'test_keys',
        'metadata_file': 'test_key_metadata.json'
    }
    
    km = get_key_manager(config)
    
    try:
        # Generate a test key
        key_id, metadata = km.generate_key(
            key_type=KeyType.SYMMETRIC,
            key_size=32,
            description="Test encryption key",
            tags=["test", "encryption"]
        )
        
        print(f"Generated key: {key_id}")
        
        # List all keys
        print("\nAll keys:")
        for key in km.list_keys():
            print(f"- {key.key_id} ({key.key_type.value}): {key.description}")
        
        # Encrypt some data
        plaintext = b"This is a test message for HSM encryption"
        print(f"\nEncrypting: {plaintext}")
        
        ciphertext, iv = km.encrypt_with_key(key_id, plaintext)
        print(f"Ciphertext: {ciphertext.hex()}")
        print(f"IV: {iv.hex()}")
        
        # Decrypt the data
        decrypted = km.decrypt_with_key(key_id, ciphertext, iv)
        print(f"\nDecrypted: {decrypted.decode()}")

        # Verify the decryption
        if plaintext == decrypted:
            print("\n✓ Encryption/decryption successful!")
        else:
            # Verify the decryption
            if decrypted == plaintext:
                print("Decryption successful!")

                # Test backup functionality
                print("\nTesting backup functionality...")
                backup_result = km.create_backup(
                    key_ids=[key_id],
                    backup_passphrase="test_backup_passphrase_123!@#",
                    output_path="test_backup.svb"
                )
                print(f"Backup created: {backup_result}")

                # Verify backup
                verify_result = km.verify_backup(
                    backup_source="test_backup.svb",
                    backup_passphrase="test_backup_passphrase_123!@#"
                )
                print(f"Backup verification: {verify_result}")

                # Restore backup to a new key manager
                print("\nTesting restore functionality...")
                restore_result = km.restore_backup(
                    backup_source="test_backup.svb",
                    backup_passphrase="test_backup_passphrase_123!@#",
                    key_ids=[key_id]
                )
                print(f"Restore result: {restore_result}")

                # Clean up test backup
                try:
                    os.remove("test_backup.svb")
                except:
                    pass

            else:
                print("Decryption failed!")

    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Clean up
        km.close()