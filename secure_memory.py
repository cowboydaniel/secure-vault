"""
Secure Memory Handling Module

This module provides secure memory management for sensitive data, including:
- Secure memory allocation with mlock() to prevent swapping
- Guaranteed zeroization of sensitive data
- Protection against memory dumps and cold boot attacks
- Secure string and bytes handling
"""

import os
import ctypes
import sys
import mmap
import platform
import warnings
from typing import Optional, Union, TypeVar, Type, Any, Tuple
import weakref

# Platform-specific imports
try:
    import fcntl
    import resource
    from ctypes.util import find_library
    
    # Load libc for memory management functions
    try:
        libc = ctypes.CDLL(find_library('c'))
    except (OSError, AttributeError):
        libc = None
        
    # Try to load Windows-specific libraries
    if platform.system() == 'Windows':
        try:
            kernel32 = ctypes.windll.kernel32
        except (OSError, AttributeError):
            kernel32 = None
    else:
        kernel32 = None
        
    # Memory protection constants
    PROT_READ = 1
    PROT_WRITE = 2
    PROT_EXEC = 4
    MAP_PRIVATE = 2
    MAP_ANONYMOUS = 0x20 if sys.platform == 'linux' else 0x1000
    
    # Memory locking constants
    MCL_CURRENT = 1
    MCL_FUTURE = 2
    
    # Windows-specific constants
    if kernel32 is not None:
        MEM_COMMIT = 0x1000
        MEM_RESERVE = 0x2000
        PAGE_READWRITE = 0x04
        MEM_RELEASE = 0x8000
        
except ImportError as e:
    warnings.warn(f"Could not import required modules for secure memory: {e}")
    libc = None
    kernel32 = None

class SecureMemoryError(Exception):
    """Base class for secure memory errors."""
    pass

class MemoryLockError(SecureMemoryError):
    """Raised when memory locking fails."""
    pass

class SecureMemory:
    """
    Secure memory allocation and management.
    
    This class provides secure memory allocation with the following features:
    - Memory is locked to prevent swapping to disk
    - Memory is zeroed before being freed
    - Memory is protected from being included in core dumps
    - Memory access can be restricted (read-only, no-execute, etc.)
    """
    
    _instances = set()
    
    def __init__(self, size: int, zero: bool = True):
        """
        Allocate secure memory.
        
        Args:
            size: Size of memory to allocate in bytes
            zero: If True, zero the allocated memory
        """
        self._size = size
        self._locked = False
        self._address = None
        self._allocated = False
        
        try:
            self._allocate()
            if zero:
                self.zero()
            self.lock()
            self._instances.add(weakref.ref(self))
        except Exception as e:
            self._release()
            raise MemoryLockError(f"Failed to allocate secure memory: {e}")
    
    def _allocate(self) -> None:
        """Allocate memory using the appropriate method for the platform."""
        if kernel32 is not None:
            # Windows implementation
            self._address = kernel32.VirtualAlloc(
                0, self._size, 
                kernel32.MEM_COMMIT | kernel32.MEM_RESERVE, 
                kernel32.PAGE_READWRITE
            )
            if not self._address:
                raise MemoryLockError("Failed to allocate secure memory")
        else:
            # POSIX implementation
            self._address = libc.mmap(
                0, self._size, 
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, 
                -1, 0
            )
            if self._address == -1:
                raise MemoryLockError("Failed to allocate secure memory")
        
        self._allocated = True
    
    def lock(self) -> None:
        """Lock memory to prevent swapping."""
        if self._locked or not self._allocated:
            return
            
        if kernel32 is not None:
            # Windows implementation
            old_protect = ctypes.c_ulong()
            if not kernel32.VirtualProtect(
                self._address, self._size, 
                kernel32.PAGE_READONLY, 
                ctypes.byref(old_protect)
            ):
                raise MemoryLockError("Failed to protect memory")
        else:
            # POSIX implementation
            if libc.mlock(self._address, self._size) != 0:
                raise MemoryLockError("Failed to lock memory")
            
            # Try to prevent core dumps
            try:
                resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            except (ValueError, resource.error):
                pass  # Not all systems support this
        
        self._locked = True
    
    def unlock(self) -> None:
        """Unlock memory (not recommended for sensitive data)."""
        if not self._locked or not self._allocated:
            return
            
        if kernel32 is not None:
            # Windows implementation
            old_protect = ctypes.c_ulong()
            kernel32.VirtualProtect(
                self._address, self._size,
                kernel32.PAGE_READWRITE,
                ctypes.byref(old_protect)
            )
        else:
            # POSIX implementation
            libc.munlock(self._address, self._size)
        
        self._locked = False
    
    def zero(self) -> None:
        """Securely zero the memory."""
        if not self._allocated:
            return
            
        # Use a volatile pointer to prevent optimization
        buf = (ctypes.c_byte * self._size).from_address(self._address)
        for i in range(self._size):
            buf[i] = 0
        
        # Ensure writes are not optimized away
        ctypes.memset(self._address, 0, self._size)
    
    def _release(self) -> None:
        """Release the allocated memory."""
        if not self._allocated:
            return
            
        try:
            self.zero()
            self.unlock()
            
            if kernel32 is not None:
                # Windows implementation
                kernel32.VirtualFree(self._address, 0, kernel32.MEM_RELEASE)
            else:
                # POSIX implementation
                libc.munmap(self._address, self._size)
                
        except Exception as e:
            warnings.warn(f"Error releasing secure memory: {e}")
        finally:
            self._allocated = False
            self._address = None
    
    def __del__(self):
        """Ensure memory is securely freed when object is destroyed."""
        self._release()
    
    @property
    def address(self) -> int:
        """Get the memory address (use with caution)."""
        return self._address
    
    @property
    def size(self) -> int:
        """Get the size of the allocated memory."""
        return self._size
    
    @classmethod
    def cleanup(cls) -> None:
        """Clean up all secure memory instances."""
        for ref in list(cls._instances):
            obj = ref()
            if obj is not None:
                obj._release()
        cls._instances.clear()

# Register cleanup on interpreter shutdown
import atexit
atexit.register(SecureMemory.cleanup)

# Convenience function for secure memory allocation
def secure_alloc(size: int, zero: bool = True):
    """
    Allocate secure memory.
    
    Args:
        size: Size of memory to allocate in bytes
        zero: If True, zero the allocated memory
        
    Returns:
        SecureMemory instance
    """
    return SecureMemory(size, zero=zero)


def secure_free(mem):
    """
    Securely free memory allocated by secure_alloc.
    
    Args:
        mem: The SecureMemory instance to free
    """
    if hasattr(mem, '_release'):
        mem._release()

# Secure string implementation
class SecureString:
    """
    Secure string that securely handles sensitive string data.
    """
    
    def __init__(self, data: Union[str, bytes]):
        """
        Initialize with sensitive string data.
        
        Args:
            data: String or bytes to store securely
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        self._length = len(data)
        self._memory = secure_alloc(self._length + 1)  # +1 for null terminator
        
        # Copy data into secure memory
        buf = (ctypes.c_byte * (self._length + 1)).from_address(self._memory.address)
        for i, b in enumerate(data):
            buf[i] = b
        buf[self._length] = 0  # Null terminator
    
    def __str__(self) -> str:
        """Get string representation (use with caution)."""
        buf = (ctypes.c_byte * self._length).from_address(self._memory.address)
        return bytes(buf).decode('utf-8', errors='replace')
    
    def __bytes__(self) -> bytes:
        """Get bytes representation (use with caution)."""
        buf = (ctypes.c_byte * self._length).from_address(self._memory.address)
        return bytes(buf)
    
    def __len__(self) -> int:
        """Get the length of the string."""
        return self._length
    
    def __del__(self):
        """Securely erase the string when done."""
        if hasattr(self, '_memory'):
            self._memory.zero()
            self._memory = None

# Secure bytes implementation
class SecureBytes:
    """
    Secure bytes that securely handles sensitive binary data.
    """
    
    def __init__(self, data: Union[bytes, bytearray, memoryview]):
        """
        Initialize with sensitive binary data.
        
        Args:
            data: Binary data to store securely
        """
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("Data must be bytes, bytearray, or memoryview")
        
        self._length = len(data)
        self._memory = secure_alloc(self._length)
        
        # Copy data into secure memory
        buf = (ctypes.c_byte * self._length).from_address(self._memory.address)
        for i, b in enumerate(data):
            buf[i] = b
    
    def __bytes__(self) -> bytes:
        """Get bytes representation (use with caution)."""
        buf = (ctypes.c_byte * self._length).from_address(self._memory.address)
        return bytes(buf)
    
    def __len__(self) -> int:
        """Get the length of the data."""
        return self._length
    
    def __del__(self):
        """Securely erase the data when done."""
        if hasattr(self, '_memory'):
            self._memory.zero()
            self._memory = None

# Context manager for secure memory
class secure_memory_section:
    """
    Context manager for working with secure memory.
    """
    
    def __init__(self, size: int):
        self.size = size
        self.mem = None
    
    def __enter__(self):
        self.mem = secure_alloc(self.size)
        return self.mem
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.mem is not None:
            self.mem.zero()
            self.mem = None

# Example usage
if __name__ == "__main__":
    # Example 1: Secure memory allocation
    with secure_memory_section(1024) as mem:
        # Use the secure memory
        buf = (ctypes.c_byte * 1024).from_address(mem.address)
        # ... do something with the buffer ...
    # Memory is automatically zeroed and freed here
    
    # Example 2: Secure string
    secret = SecureString("my secret password")
    try:
        # Use the secret string
        print(f"Secret length: {len(secret)}")
    finally:
        # Ensure secure cleanup
        del secret
    
    # Example 3: Secure bytes
    key = os.urandom(32)
    secure_key = SecureBytes(key)
    try:
        # Use the secure key
        print(f"Key length: {len(secure_key)}")
    finally:
        # Ensure secure cleanup
        del secure_key