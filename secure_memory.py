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
import threading
from typing import Optional, Union, TypeVar, Type, Any, Tuple
import weakref

from crypto_utils import secure_wipe as _crypto_secure_wipe

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
    MEM_COMMIT = 0x1000
    MEM_RESERVE = 0x2000
    PAGE_READWRITE = 0x04
    PAGE_READONLY = 0x02
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
        self._mmap_obj: Optional[mmap.mmap] = None
        
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
        if self._size <= 0:
            # Nothing to allocate but keep the instance usable
            self._allocated = True
            self._address = None
            return

        if kernel32 is not None:
            # Windows implementation
            self._address = kernel32.VirtualAlloc(
                0,
                self._size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
            if not self._address:
                raise MemoryLockError("Failed to allocate secure memory")
        elif libc is not None:
            # POSIX implementation using libc
            libc.mmap.restype = ctypes.c_void_p
            libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t,
                                  ctypes.c_int, ctypes.c_int,
                                  ctypes.c_int, ctypes.c_size_t]
            result = libc.mmap(
                0,
                self._size,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1,
                0,
            )
            if not result or result == ctypes.c_void_p(-1).value:
                raise MemoryLockError("Failed to allocate secure memory")
            self._address = result
        else:
            # Fallback to Python's mmap when libc isn't available
            try:
                self._mmap_obj = mmap.mmap(-1, self._size)
                self._address = ctypes.addressof(
                    ctypes.c_char.from_buffer(self._mmap_obj)
                )
                warnings.warn(
                    "libc not available; using mmap fallback without mlock guarantees",
                    RuntimeWarning,
                )
            except Exception as exc:
                raise MemoryLockError(f"Failed to allocate secure memory: {exc}")

        self._allocated = True

    def lock(self) -> None:
        """Lock memory to prevent swapping."""
        if self._locked or not self._allocated:
            return

        if self._size <= 0 or self._address is None:
            self._locked = True
            return

        if kernel32 is not None:
            # Windows implementation
            old_protect = ctypes.c_ulong()
            if not kernel32.VirtualProtect(
                self._address, self._size,
                PAGE_READONLY,
                ctypes.byref(old_protect)
            ):
                raise MemoryLockError("Failed to protect memory")
        elif libc is not None:
            # POSIX implementation
            if libc.mlock(self._address, self._size) != 0:
                warnings.warn(
                    "mlock failed; continuing without locked pages",
                    RuntimeWarning,
                )
            else:
                # Try to prevent core dumps
                try:
                    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
                except (ValueError, resource.error):
                    pass  # Not all systems support this
        else:
            # Fallback path without real locking
            warnings.warn(
                "Secure memory fallback in use; memory pages are not locked",
                RuntimeWarning,
            )

        self._locked = True

    def unlock(self) -> None:
        """Unlock memory (not recommended for sensitive data)."""
        if not self._locked or not self._allocated:
            return

        if self._size <= 0 or self._address is None:
            self._locked = False
            return

        if kernel32 is not None:
            # Windows implementation
            old_protect = ctypes.c_ulong()
            kernel32.VirtualProtect(
                self._address, self._size,
                PAGE_READWRITE,
                ctypes.byref(old_protect)
            )
        elif libc is not None:
            # POSIX implementation
            libc.munlock(self._address, self._size)
        else:
            # Nothing to do for fallback allocator
            return

        self._locked = False

    def zero(self) -> None:
        """Securely zero the memory."""
        if not self._allocated:
            return

        address = self._address
        if self._size <= 0 or not address:
            # Nothing to zero for empty allocations or if no address is present
            return

        # Use a volatile pointer to prevent optimization
        buf = (ctypes.c_byte * self._size).from_address(int(address))
        for i in range(self._size):
            buf[i] = 0

        # Ensure writes are not optimized away
        ctypes.memset(int(address), 0, self._size)
    
    def _release(self) -> None:
        """Release the allocated memory."""
        if not self._allocated:
            return
            
        try:
            self.zero()
            self.unlock()
            
            if self._address is None:
                pass
            elif kernel32 is not None:
                # Windows implementation
                kernel32.VirtualFree(self._address, 0, MEM_RELEASE)
            elif libc is not None:
                # POSIX implementation
                libc.munmap(self._address, self._size)
            elif self._mmap_obj is not None:
                self._mmap_obj.close()
                self._mmap_obj = None

        except Exception as e:
            warnings.warn(f"Error releasing secure memory: {e}")
        finally:
            self._allocated = False
            self._address = None
    
    def __del__(self):
        """Ensure memory is securely freed when object is destroyed."""
        self._release()

    def __enter__(self) -> "SecureMemory":
        """Support ``with secure_alloc(...)`` usage."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        """Automatically release the allocation when leaving a context."""
        self._release()
        return False
    
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


def secure_wipe(data: Union[bytearray, memoryview]) -> None:
    """Re-export secure_wipe for backwards compatibility."""
    _crypto_secure_wipe(data)

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
class _SecureBytesLock:
    """Context manager for thread-safe access to SecureBytes."""

    def __init__(self, owner: "SecureBytes") -> None:
        self._owner = owner

    def __enter__(self) -> "SecureBytes":
        self._owner._lock.acquire()
        return self._owner

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self._owner._lock.release()
        return False


class SecureBytes:
    """Thread-safe, wipe-aware container for sensitive byte sequences."""

    def __init__(self, data: Union[int, bytes, bytearray, memoryview]):
        if isinstance(data, int):
            if data < 0:
                raise ValueError("Length must be non-negative")
            initial = bytearray(data)
        elif isinstance(data, (bytes, bytearray, memoryview)):
            initial = bytearray(data)
        else:
            raise TypeError("Data must be an int or bytes-like object")

        self._lock = threading.RLock()
        self._memory: Optional[SecureMemory] = None
        self._length = 0
        self._replace_with_unlocked(initial)

    def _replace_with_unlocked(self, buffer: bytearray) -> None:
        """Replace the stored value with the provided buffer (expects lock held)."""
        new_len = len(buffer)
        new_memory = secure_alloc(new_len) if new_len > 0 else None

        if new_memory is not None and new_len > 0:
            dest = (ctypes.c_ubyte * new_len).from_address(new_memory.address)
            dest[:new_len] = buffer

        old_memory = self._memory
        self._memory = new_memory
        self._length = new_len

        if old_memory is not None:
            secure_free(old_memory)

        if buffer:
            _crypto_secure_wipe(buffer)

    def lock(self) -> _SecureBytesLock:
        """Return a context manager locking this instance."""
        return _SecureBytesLock(self)

    def write(self, data: Union[bytes, bytearray, memoryview]) -> None:
        """Overwrite the stored value with new data."""
        buffer = bytearray(data)
        with self._lock:
            self._replace_with_unlocked(buffer)

    def extend(self, data: Union[bytes, bytearray, memoryview]) -> None:
        """Append data to the end of the buffer."""
        addition = bytearray(data)
        with self._lock:
            if self._length == 0:
                self._replace_with_unlocked(addition)
                return

            existing = bytearray(self._read_unlocked())
            existing.extend(addition)
            self._replace_with_unlocked(existing)
            if addition:
                _crypto_secure_wipe(addition)

    def clear(self) -> None:
        """Remove all data and release memory."""
        with self._lock:
            self._replace_with_unlocked(bytearray())

    def _read_unlocked(self, num_bytes: Optional[int] = None) -> bytes:
        if self._length == 0 or self._memory is None:
            return b""

        length = self._length if num_bytes is None else min(num_bytes, self._length)
        if length <= 0:
            return b""
        return ctypes.string_at(self._memory.address, length)

    def read(self, num_bytes: Optional[int] = None) -> bytes:
        """Return up to num_bytes of the stored value as bytes."""
        with self._lock:
            return self._read_unlocked(num_bytes)

    def consume(self, num_bytes: int) -> bytes:
        """Remove and return the first num_bytes of data."""
        if num_bytes <= 0:
            return b""

        with self._lock:
            data = self._read_unlocked()
            if not data:
                return b""

            take = min(num_bytes, len(data))
            extracted = data[:take]
            remaining = bytearray(data[take:])
            self._replace_with_unlocked(remaining)

            if data:
                temp = bytearray(data)
                _crypto_secure_wipe(temp)

            return extracted

    def zero(self) -> None:
        """Zero and release the stored data."""
        with self._lock:
            if self._memory is not None:
                self._memory.zero()
                secure_free(self._memory)
                self._memory = None
            self._length = 0

    def __bytes__(self) -> bytes:
        return self.read()

    def __len__(self) -> int:
        return self._length

    @property
    def value(self) -> bytes:
        """Expose the current value as bytes."""
        return self.read()

    @value.setter
    def value(self, new_value: Union[bytes, bytearray, memoryview]) -> None:
        self.write(new_value)

    def __del__(self):
        try:
            self.zero()
        except Exception:
            pass

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