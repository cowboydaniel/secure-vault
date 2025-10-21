"""Key state and version management for the Secure Vault system."""
from enum import Enum, auto
from datetime import datetime, timedelta
from typing import Dict, Any, Optional


class KeyState(Enum):
    """Possible states for a cryptographic key."""
    PENDING_ACTIVATION = auto()
    ACTIVE = auto()
    SUSPENDED = auto()
    REVOKED = auto()
    EXPIRED = auto()
    DESTROYED = auto()


class KeyVersion:
    """Manages versioning for cryptographic keys with major and minor versions."""
    
    def __init__(self, major: int = 1, minor: int = 0):
        """Initialize key version.
        
        Args:
            major: Major version number (incremented on key rotation)
            minor: Minor version number (incremented on metadata changes)
        """
        self.major = major
        self.minor = minor
    
    def increment_major(self) -> 'KeyVersion':
        """Increment major version and reset minor to 0."""
        return KeyVersion(self.major + 1, 0)
    
    def increment_minor(self) -> 'KeyVersion':
        """Increment minor version."""
        return KeyVersion(self.major, self.minor + 1)
    
    def __str__(self) -> str:
        """String representation of version (e.g., '1.0')."""
        return f"{self.major}.{self.minor}"
    
    def to_dict(self) -> Dict[str, int]:
        """Convert to dictionary for serialization."""
        return {'major': self.major, 'minor': self.minor}
    
    @classmethod
    def from_dict(cls, data: Dict[str, int]) -> 'KeyVersion':
        """Create from dictionary."""
        if not data:
            return cls()
        return cls(major=data.get('major', 1), minor=data.get('minor', 0))
    
    @classmethod
    def from_string(cls, version_str: str) -> 'KeyVersion':
        """Create from version string (e.g., '1.0')."""
        try:
            major, minor = map(int, version_str.split('.'))
            return cls(major, minor)
        except (ValueError, AttributeError):
            return cls(1, 0)


class KeyLifecycle:
    """Manages the lifecycle state of a cryptographic key."""
    
    def __init__(
        self,
        state: KeyState = KeyState.PENDING_ACTIVATION,
        version: Optional[KeyVersion] = None,
        valid_from: Optional[datetime] = None,
        valid_to: Optional[datetime] = None,
        state_history: Optional[list] = None
    ):
        """Initialize key lifecycle.
        
        Args:
            state: Current key state
            version: Key version
            valid_from: When the key becomes valid
            valid_to: When the key expires
            state_history: History of state changes
        """
        self.state = state
        self.version = version or KeyVersion()
        self.valid_from = valid_from or datetime.utcnow()
        self.valid_to = valid_to or (self.valid_from + timedelta(days=365))  # Default 1 year
        self.state_history: List[Dict[str, Any]] = state_history or []
        
        # Record initial state if no history exists
        if not self.state_history:
            self._record_state_change("Initial creation")
    
    def _record_state_change(
        self, 
        reason: str, 
        metadata: Optional[Dict[str, Any]] = None,
        timestamp: Optional[datetime] = None
    ) -> None:
        """Record a state change in the history.
        
        Args:
            reason: Reason for the state change
            metadata: Additional metadata about the state change
            timestamp: When the state change occurred (defaults to now)
        """
        timestamp = timestamp or datetime.utcnow()
        self.state_history.append({
            'timestamp': timestamp.isoformat(),
            'state': self.state.name,
            'version': str(self.version),
            'reason': reason,
            'metadata': metadata or {}
        })
    
    def activate(self, reason: str = "Manual activation", metadata: Optional[Dict] = None) -> bool:
        """Activate the key.
        
        Args:
            reason: Reason for activation
            metadata: Additional metadata
            
        Returns:
            bool: True if state was changed, False otherwise
        """
        if self.state != KeyState.PENDING_ACTIVATION:
            return False
            
        self.state = KeyState.ACTIVE
        self._record_state_change(reason, metadata)
        return True
    
    def suspend(self, reason: str, metadata: Optional[Dict] = None) -> bool:
        """Suspend the key.
        
        Args:
            reason: Reason for suspension
            metadata: Additional metadata
            
        Returns:
            bool: True if state was changed, False otherwise
        """
        if self.state not in (KeyState.ACTIVE, KeyState.PENDING_ACTIVATION):
            return False
            
        self.state = KeyState.SUSPENDED
        self._record_state_change(reason, metadata)
        return True
    
    def revoke(self, reason: str, metadata: Optional[Dict] = None) -> bool:
        """Revoke the key.
        
        Args:
            reason: Reason for revocation
            metadata: Additional metadata
            
        Returns:
            bool: True if state was changed, False otherwise
        """
        if self.state in (KeyState.REVOKED, KeyState.DESTROYED):
            return False
            
        self.state = KeyState.REVOKED
        self._record_state_change(reason, metadata)
        return True
    
    def expire(self, reason: str = "Key expired", metadata: Optional[Dict] = None) -> bool:
        """Mark key as expired.
        
        Args:
            reason: Reason for expiration
            metadata: Additional metadata
            
        Returns:
            bool: True if state was changed, False otherwise
        """
        if self.state in (KeyState.EXPIRED, KeyState.REVOKED, KeyState.DESTROYED):
            return False
            
        self.state = KeyState.EXPIRED
        self._record_state_change(reason, metadata)
        return True
    
    def destroy(self, reason: str, metadata: Optional[Dict] = None) -> bool:
        """Mark key as destroyed.
        
        Args:
            reason: Reason for destruction
            metadata: Additional metadata
            
        Returns:
            bool: True if state was changed, False otherwise
        """
        if self.state == KeyState.DESTROYED:
            return False
            
        self.state = KeyState.DESTROYED
        self._record_state_change(reason, metadata)
        return True
    
    def is_valid(self, reference_time: Optional[datetime] = None) -> bool:
        """Check if key is valid for use.
        
        Args:
            reference_time: Time to check validity against (defaults to now)
            
        Returns:
            bool: True if key is valid, False otherwise
        """
        now = reference_time or datetime.utcnow()
        return (self.state == KeyState.ACTIVE and 
                self.valid_from <= now <= self.valid_to)
    
    def get_state_history(self) -> list:
        """Get the complete state history.
        
        Returns:
            list: List of state change records
        """
        return self.state_history.copy()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization.
        
        Returns:
            dict: Dictionary representation
        """
        return {
            'state': self.state.name,
            'version': self.version.to_dict(),
            'valid_from': self.valid_from.isoformat(),
            'valid_to': self.valid_to.isoformat(),
            'state_history': self.state_history
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'KeyLifecycle':
        """Create from dictionary.
        
        Args:
            data: Dictionary representation
            
        Returns:
            KeyLifecycle: New instance
        """
        if not data:
            return cls()
            
        # Parse datetime strings
        valid_from = (
            datetime.fromisoformat(data['valid_from'])
            if 'valid_from' in data and data['valid_from']
            else None
        )
        valid_to = (
            datetime.fromisoformat(data['valid_to'])
            if 'valid_to' in data and data['valid_to']
            else None
        )
        
        # Parse version
        version = KeyVersion.from_dict(data.get('version', {}))
        
        # Get state
        state = KeyState[data.get('state', 'PENDING_ACTIVATION')]
        
        return cls(
            state=state,
            version=version,
            valid_from=valid_from,
            valid_to=valid_to,
            state_history=data.get('state_history', [])
        )
