"""
Hardware Random Number Generator (RNG) Support

This module provides hardware-based random number generation capabilities,
with fallback to system RNG when hardware is not available.
"""

import os
import platform
import ctypes
import ctypes.util
import logging
import threading
import subprocess
import tempfile
from pathlib import Path
from typing import Optional, Tuple, List, Dict, Any
from enum import Enum, auto

# Import secure memory for handling sensitive data
from secure_memory import SecureBytes

logger = logging.getLogger(__name__)

_instruction_helper_lock = threading.RLock()
_instruction_helper: Optional[ctypes.CDLL] = None

INSTRUCTION_HELPER_CODE = r"""
#include <immintrin.h>
#include <stdint.h>
#include <string.h>
#include <cpuid.h>

static int has_rdrand_flag(void) {
    unsigned int eax, ebx, ecx, edx;
    if (__get_cpuid_max(0, NULL) < 1) {
        return 0;
    }
    __get_cpuid(1, &eax, &ebx, &ecx, &edx);
    return (ecx & bit_RDRND) != 0;
}

static int has_rdseed_flag(void) {
    unsigned int eax, ebx, ecx, edx;
    if (__get_cpuid_max(0, NULL) < 7) {
        return 0;
    }
    __cpuid_count(7, 0, &eax, &ebx, &ecx, &edx);
    return (ebx & bit_RDSEED) != 0;
}

int has_rdrand(void) {
    return has_rdrand_flag();
}

int has_rdseed(void) {
    return has_rdseed_flag();
}

int rdrand_bytes(unsigned char *buffer, unsigned long long length) {
#ifdef __RDRND__
    if (!has_rdrand_flag()) {
        return 0;
    }
    unsigned long long offset = 0;
    while (offset < length) {
        unsigned int value = 0;
        int retries = 10;
        while (retries-- > 0) {
            if (_rdrand32_step(&value)) {
                break;
            }
        }
        if (retries < 0) {
            return 0;
        }
        unsigned long long remaining = length - offset;
        unsigned long long copy = remaining < sizeof(value) ? remaining : sizeof(value);
        memcpy(buffer + offset, &value, copy);
        offset += copy;
    }
    return 1;
#else
    return 0;
#endif
}

int rdseed_bytes(unsigned char *buffer, unsigned long long length) {
#ifdef __RDSEED__
    if (!has_rdseed_flag()) {
        return 0;
    }
    unsigned long long offset = 0;
    while (offset < length) {
        unsigned int value = 0;
        int retries = 10;
        while (retries-- > 0) {
            if (_rdseed32_step(&value)) {
                break;
            }
        }
        if (retries < 0) {
            return 0;
        }
        unsigned long long remaining = length - offset;
        unsigned long long copy = remaining < sizeof(value) ? remaining : sizeof(value);
        memcpy(buffer + offset, &value, copy);
        offset += copy;
    }
    return 1;
#else
    return 0;
#endif
}
"""


def _cpu_has_feature(flag: str) -> bool:
    flag = flag.lower()
    try:
        system = platform.system().lower()
        if system == 'linux':
            cpuinfo = Path('/proc/cpuinfo')
            if cpuinfo.exists():
                return flag in cpuinfo.read_text().lower()
        elif system == 'darwin':
            output = subprocess.check_output(['sysctl', '-n', 'machdep.cpu.features'], stderr=subprocess.DEVNULL)
            return flag in output.decode().lower()
        elif system == 'windows':
            output = subprocess.check_output(['wmic', 'cpu', 'get', 'Name,ProcessorId'], stderr=subprocess.DEVNULL)
            return flag in output.decode().lower()
    except Exception:
        pass
    return False


def _compile_instruction_helper() -> Optional[Path]:
    try:
        workdir = Path(tempfile.mkdtemp(prefix='secure_vault_hw_rng_'))
        source_path = workdir / 'hw_rng_helper.c'
        source_path.write_text(INSTRUCTION_HELPER_CODE)
        output_path = workdir / 'hw_rng_helper.so'

        compiler = os.environ.get('CC', 'cc')
        cmd = [compiler, '-shared', '-fPIC', '-O2', str(source_path), '-o', str(output_path)]
        if platform.machine().lower() in ('x86_64', 'amd64', 'i386', 'i686'):
            cmd.extend(['-mrdrnd', '-mrdseed'])

        subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return output_path
    except Exception as exc:
        logger.debug(f"Failed to compile instruction helper: {exc}")
        return None


def _get_instruction_helper() -> Optional[ctypes.CDLL]:
    global _instruction_helper
    with _instruction_helper_lock:
        if _instruction_helper is not None:
            return _instruction_helper

        helper_path = _compile_instruction_helper()
        if not helper_path:
            return None

        try:
            helper = ctypes.CDLL(str(helper_path))
            helper.rdrand_bytes.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint64]
            helper.rdrand_bytes.restype = ctypes.c_int
            helper.rdseed_bytes.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint64]
            helper.rdseed_bytes.restype = ctypes.c_int
            helper.has_rdrand.restype = ctypes.c_int
            helper.has_rdseed.restype = ctypes.c_int
            _instruction_helper = helper
            return helper
        except Exception as exc:
            logger.debug(f"Failed to load instruction helper: {exc}")
            return None


class HWRNGType(Enum):
    """Types of hardware RNG sources"""
    RDRAND = auto()      # Intel RDRAND instruction
    RDSEED = auto()      # Intel RDSEED instruction
    DEV_RANDOM = auto()  # /dev/random (may use hardware RNG)
    DEV_HWRNG = auto()   # /dev/hwrng
    TPM = auto()         # Trusted Platform Module
    NONE = auto()        # No hardware RNG available

class HWRNGSource:
    """Base class for hardware RNG sources"""
    
    def __init__(self):
        self.type = HWRNGType.NONE
        self.available = False
        self.quality = 0.0  # 0.0 to 1.0, indicates quality of entropy
        self.initialized = False
        self.last_error = ""
    
    def initialize(self) -> bool:
        """Initialize the hardware RNG source"""
        self.initialized = True
        return True
    
    def read(self, size: int) -> Optional[bytes]:
        """Read random bytes from the hardware RNG"""
        raise NotImplementedError("Subclasses must implement read()")
    
    def get_status(self) -> Dict[str, Any]:
        """Get status information about the RNG source"""
        return {
            "type": self.type.name,
            "available": self.available,
            "initialized": self.initialized,
            "quality": self.quality,
            "last_error": self.last_error
        }

class RdRandSource(HWRNGSource):
    """Intel RDRAND instruction-based RNG"""
    
    def __init__(self):
        super().__init__()
        self.type = HWRNGType.RDRAND
        self.quality = 0.9  # High quality hardware RNG
        self._helper: Optional[ctypes.CDLL] = None

    def initialize(self) -> bool:
        """Check if RDRAND is available"""
        try:
            if not _cpu_has_feature('rdrand'):
                self.last_error = "RDRAND instruction not available on this CPU"
                return False

            helper = _get_instruction_helper()
            if not helper or helper.has_rdrand() == 0:
                self.last_error = "RDRAND helper not available"
                return False

            self._helper = helper
            self.available = True
            self.initialized = True
            return True

        except Exception as e:
            self.last_error = f"RDRAND initialization failed: {str(e)}"
            return False

    def read(self, size: int) -> Optional[bytes]:
        """Read random bytes using RDRAND instruction"""
        if not self.available or not self.initialized:
            return None

        try:
            if self._helper:
                buffer = (ctypes.c_ubyte * size)()
                if self._helper.rdrand_bytes(buffer, ctypes.c_uint64(size)) == 1:
                    return bytes(buffer)
                self.last_error = "RDRAND helper returned failure"
            # Fallback to os.urandom
            return os.urandom(size)
        except Exception as e:
            self.last_error = f"RDRAND read failed: {str(e)}"
            return None


class RdSeedSource(HWRNGSource):
    """Intel RDSEED instruction-based RNG"""

    def __init__(self):
        super().__init__()
        self.type = HWRNGType.RDSEED
        self.quality = 0.98
        self._helper: Optional[ctypes.CDLL] = None

    def initialize(self) -> bool:
        """Check if RDSEED is available"""
        try:
            if not _cpu_has_feature('rdseed'):
                self.last_error = "RDSEED instruction not available on this CPU"
                return False

            helper = _get_instruction_helper()
            if not helper or helper.has_rdseed() == 0:
                self.last_error = "RDSEED helper not available"
                return False

            self._helper = helper
            self.available = True
            self.initialized = True
            return True
        except Exception as exc:
            self.last_error = f"RDSEED initialization failed: {exc}"
            return False

    def read(self, size: int) -> Optional[bytes]:
        """Read random bytes using RDSEED instruction"""
        if not self.available or not self.initialized:
            return None

        try:
            if self._helper:
                buffer = (ctypes.c_ubyte * size)()
                if self._helper.rdseed_bytes(buffer, ctypes.c_uint64(size)) == 1:
                    return bytes(buffer)
                self.last_error = "RDSEED helper returned failure"
            return os.urandom(size)
        except Exception as exc:
            self.last_error = f"RDSEED read failed: {exc}"
            return None

class DevHWRNGSource(HWRNGSource):
    """Linux /dev/hwrng device"""
    
    def __init__(self, device_path: str = "/dev/hwrng"):
        super().__init__()
        self.type = HWRNGType.DEV_HWRNG
        self.device_path = device_path
        self.device = None
        self.quality = 0.8  # Typically high quality, but depends on hardware
    
    def initialize(self) -> bool:
        """Check if /dev/hwrng is available"""
        try:
            if not os.path.exists(self.device_path):
                self.last_error = f"Device {self.device_path} not found"
                return False
                
            self.available = True
            self.initialized = True
            return True
            
        except Exception as e:
            self.last_error = f"Failed to initialize {self.device_path}: {str(e)}"
            return False
    
    def read(self, size: int) -> Optional[bytes]:
        """Read random bytes from /dev/hwrng"""
        if not self.available or not self.initialized:
            return None
            
        try:
            with open(self.device_path, 'rb') as f:
                return f.read(size)
        except Exception as e:
            self.last_error = f"Failed to read from {self.device_path}: {str(e)}"
            return None

class HWRNGManager:
    """Manages multiple hardware RNG sources with prioritization and fallback"""
    
    def __init__(self):
        self.sources: List[HWRNGSource] = []
        self.available_sources: List[HWRNGSource] = []
        self._lock = threading.RLock()
        self.initialize_sources()
    
    def initialize_sources(self) -> None:
        """Initialize all available hardware RNG sources in order of preference"""
        with self._lock:
            # Clear existing sources
            self.sources.clear()
            self.available_sources.clear()
            
            # Detect platform-specific sources
            if platform.system().lower() == 'linux':
                # Linux-specific sources
                self._add_linux_sources()
            elif platform.system().lower() == 'windows':
                # Windows-specific sources
                self._add_windows_sources()
            elif platform.system().lower() == 'darwin':
                # macOS-specific sources
                self._add_darwin_sources()
            
            # Add platform-agnostic sources
            self._add_platform_agnostic_sources()
            
            # Initialize and collect available sources
            for source in self.sources:
                try:
                    if source.initialize() and source.available:
                        self.available_sources.append(source)
                        logger.info(f"Initialized {source.type.name} RNG source")
                except Exception as e:
                    logger.warning(f"Failed to initialize {source.type.name}: {str(e)}")
            
            if not self.available_sources:
                logger.warning("No hardware RNG sources available, falling back to system RNG")
    
    def _add_linux_sources(self) -> None:
        """Add Linux-specific RNG sources"""
        self.sources.append(RdSeedSource())
        self.sources.append(RdRandSource())

        # Try /dev/hwrng first if it exists
        if os.path.exists("/dev/hwrng"):
            self.sources.append(DevHWRNGSource("/dev/hwrng"))
        
        # Try TPM if available
        if os.path.exists("/dev/tpm0") or os.path.exists("/dev/tpmrm0"):
            self.sources.append(TpmRngSource())
    
    def _add_windows_sources(self) -> None:
        """Add Windows-specific RNG sources"""
        # Try RDRAND/RDSEED first
        self.sources.append(RdSeedSource())
        self.sources.append(RdRandSource())

        # Try Windows CNG (Cryptography API: Next Generation)
        try:
            import ctypes.wintypes
            self.sources.append(WindowsCngRngSource())
        except (ImportError, OSError):
            pass
    
    def _add_darwin_sources(self) -> None:
        """Add macOS-specific RNG sources"""
        # Try RDRAND/RDSEED first
        self.sources.append(RdSeedSource())
        self.sources.append(RdRandSource())
        
        # Try macOS Security.framework
        try:
            from Security import SecRandomCopyBytes
            self.sources.append(MacSecRandomSource())
        except ImportError:
            pass
    
    def _add_platform_agnostic_sources(self) -> None:
        """Add platform-agnostic RNG sources"""
        # Add RDRAND/RDSEED if not already added
        if not any(isinstance(s, RdSeedSource) for s in self.sources):
            self.sources.append(RdSeedSource())
        if not any(isinstance(s, RdRandSource) for s in self.sources):
            self.sources.append(RdRandSource())
        
        # Add /dev/random as fallback
        if platform.system().lower() != 'windows':
            self.sources.append(DevHWRNGSource("/dev/random"))
    
    def get_random_bytes(self, size: int) -> Optional[bytes]:
        """
        Get random bytes from the best available hardware RNG.
        
        Args:
            size: Number of random bytes to generate
            
        Returns:
            bytes: Random bytes if successful, None if no sources are available
        """
        if size <= 0:
            raise ValueError("Size must be a positive integer")
            
        with self._lock:
            if not self.available_sources:
                return None
                
            # Try sources in order until we get enough random data
            for source in self.available_sources:
                try:
                    data = source.read(size)
                    if data and len(data) == size:
                        # Verify the data isn't all zeros or a repeating pattern
                        if self._verify_randomness(data):
                            return data
                        else:
                            logger.warning(f"Suspicious RNG output from {source.type.name}")
                except Exception as e:
                    logger.warning(f"Failed to read from {source.type.name}: {str(e)}")
                    continue
            
            logger.error("All hardware RNG sources failed")
            return None
    
    def _verify_randomness(self, data: bytes) -> bool:
        """
        Perform basic sanity checks on random data
        
        Args:
            data: The random data to verify
            
        Returns:
            bool: True if the data appears random, False otherwise
        """
        if not data:
            return False
            
        # Check for all zeros
        if all(b == 0 for b in data):
            return False
            
        # Check for repeating patterns (simple check)
        if len(data) >= 8:
            # Check first 8 bytes against next 8 bytes
            if data[:8] == data[8:16] and len(data) >= 16:
                return False
                
            # Check for simple patterns
            if all(b == data[0] for b in data[1:4]):
                return False
        
        return True
    
    def get_status(self) -> Dict[str, Any]:
        """
        Get detailed status of all RNG sources
        
        Returns:
            dict: Status information including available sources and their states
        """
        with self._lock:
            return {
                "available_sources": [s.type.name for s in self.available_sources],
                "sources": {s.type.name: s.get_status() for s in self.sources},
                "system_info": {
                    "platform": platform.system(),
                    "machine": platform.machine(),
                    "python_version": platform.python_version(),
                }
            }
    
    def get_health_status(self) -> Dict[str, str]:
        """
        Get health status of the hardware RNG system
        
        Returns:
            dict: Health status information
        """
        status = {
            "status": "HEALTHY",
            "available_sources": len(self.available_sources),
            "sources": {}
        }
        
        with self._lock:
            for source in self.sources:
                source_status = {
                    "available": source.available,
                    "initialized": source.initialized,
                    "error": source.last_error or "None"
                }
                status["sources"][source.type.name] = source_status
                
                # Update overall status based on source status
                if not source.available and source.type != HWRNGType.NONE:
                    if status["status"] == "HEALTHY":
                        status["status"] = "DEGRADED"
                
                if source.available and not source.initialized:
                    status["status"] = "CRITICAL"
            
            if not self.available_sources:
                status["status"] = "CRITICAL"
                status["error"] = "No hardware RNG sources available"
        
        return status
    
    def reseed_from_entropy_pool(self) -> bool:
        """
        Reseed the entropy pools from high-quality entropy sources
        
        Returns:
            bool: True if reseeding was successful, False otherwise
        """
        # This would be called periodically to refresh entropy pools
        # Implementation depends on the specific RNG implementation
        success = False
        with self._lock:
            for source in self.available_sources:
                if hasattr(source, 'reseed'):
                    try:
                        if source.reseed():
                            success = True
                            logger.debug(f"Successfully reseeded {source.type.name}")
                    except Exception as e:
                        logger.warning(f"Failed to reseed {source.type.name}: {str(e)}")
        
        return success
    
class TpmRngSource(HWRNGSource):
    """Trusted Platform Module (TPM) RNG source"""
    
    def __init__(self, tpm_device: str = "/dev/tpm0"):
        super().__init__()
        self.type = HWRNGType.TPM
        self.device_path = tpm_device
        self.quality = 0.95  # Very high quality when available
        self._tpm = None
    
    def initialize(self) -> bool:
        """Initialize the TPM RNG source"""
        try:
            # Try to import the TPM library
            try:
                import tpm_random
                self._tpm = tpm_random.TPMRandom()
                self.available = True
            except ImportError:
                # Fall back to direct device access if library not available
                if not os.path.exists(self.device_path):
                    self.last_error = f"TPM device {self.device_path} not found"
                    return False
                self.available = True
            
            self.initialized = True
            return True
            
        except Exception as e:
            self.last_error = f"TPM initialization failed: {str(e)}"
            return False
    
    def read(self, size: int) -> Optional[bytes]:
        """Read random bytes from TPM"""
        if not self.available or not self.initialized:
            return None
            
        try:
            if self._tpm is not None:
                # Use the TPM library if available
                return self._tpm.get_random_bytes(size)
            else:
                # Fall back to direct device access
                with open(self.device_path, 'rb') as f:
                    # TPM devices typically require specific ioctls, this is simplified
                    return f.read(size)
        except Exception as e:
            self.last_error = f"TPM read failed: {str(e)}"
            return None


class WindowsCngRngSource(HWRNGSource):
    """Windows Cryptography API: Next Generation (CNG) RNG source"""
    
    def __init__(self):
        super().__init__()
        self.type = HWRNGType.DEV_RANDOM
        self.quality = 0.9
        self._provider = None
    
    def initialize(self) -> bool:
        """Initialize the Windows CNG RNG source"""
        try:
            import ctypes
            from ctypes import wintypes
            
            # Define necessary Windows types and constants
            BCRYPT_ALG_HANDLE = wintypes.HANDLE
            BCRYPT_RNG_ALGORITHM = "RNG"
            
            # Load bcrypt.dll
            bcrypt = ctypes.WinDLL('bcrypt.dll')
            
            # Define function prototypes
            bcrypt.BCryptOpenAlgorithmProvider.argtypes = [
                ctypes.POINTER(BCRYPT_ALG_HANDLE),
                wintypes.LPCWSTR,
                wintypes.LPCWSTR,
                wintypes.DWORD
            ]
            bcrypt.BCryptOpenAlgorithmProvider.restype = wintypes.NTSTATUS
            
            # Open the RNG algorithm provider
            alg_handle = BCRYPT_ALG_HANDLE()
            status = bcrypt.BCryptOpenAlgorithmProvider(
                ctypes.byref(alg_handle),
                BCRYPT_RNG_ALGORITHM,
                None,
                0
            )
            
            if status != 0:  # STATUS_SUCCESS = 0
                raise OSError(f"BCryptOpenAlgorithmProvider failed with status 0x{status:X}")
            
            self._provider = alg_handle
            self.available = True
            self.initialized = True
            return True
            
        except Exception as e:
            self.last_error = f"Windows CNG initialization failed: {str(e)}"
            return False
    
    def read(self, size: int) -> Optional[bytes]:
        """Read random bytes using Windows CNG"""
        if not self.available or not self.initialized or self._provider is None:
            return None
            
        try:
            import ctypes
            from ctypes import wintypes
            
            # Load bcrypt.dll
            bcrypt = ctypes.WinDLL('bcrypt.dll')
            
            # Define function prototypes
            bcrypt.BCryptGenRandom.argtypes = [
                wintypes.HANDLE,
                wintypes.LPBYTE,
                wintypes.ULONG,
                wintypes.ULONG
            ]
            bcrypt.BCryptGenRandom.restype = wintypes.NTSTATUS
            
            # Allocate buffer for random data
            buf = (ctypes.c_ubyte * size)()
            
            # Generate random bytes
            status = bcrypt.BCryptGenRandom(
                self._provider,
                buf,
                size,
                0  # No flags
            )
            
            if status != 0:  # STATUS_SUCCESS = 0
                raise OSError(f"BCryptGenRandom failed with status 0x{status:X}")
            
            return bytes(buf)
            
        except Exception as e:
            self.last_error = f"Windows CNG read failed: {str(e)}"
            return None


class MacSecRandomSource(HWRNGSource):
    """macOS Security.framework RNG source"""
    
    def __init__(self):
        super().__init__()
        self.type = HWRNGType.DEV_RANDOM
        self.quality = 0.9
        self._sec_random = None
    
    def initialize(self) -> bool:
        """Initialize the macOS Security.framework RNG source"""
        try:
            from Security import SecRandomCopyBytes
            self._sec_random = SecRandomCopyBytes
            self.available = True
            self.initialized = True
            return True
        except Exception as e:
            self.last_error = f"macOS Security.framework initialization failed: {str(e)}"
            return False
    
    def read(self, size: int) -> Optional[bytes]:
        """Read random bytes using macOS Security.framework"""
        if not self.available or not self.initialized or self._sec_random is None:
            return None
            
        try:
            buf = bytearray(size)
            self._sec_random(None, size, buf)
            return bytes(buf)
        except Exception as e:
            self.last_error = f"macOS Security.framework read failed: {str(e)}"
            return None


# Global instance for easy access
hw_rng_manager = HWRNGManager()

def get_hardware_rng() -> HWRNGManager:
    """
    Get the global hardware RNG manager
    
    Returns:
        HWRNGManager: The global hardware RNG manager instance
    """
    return hw_rng_manager

def get_hardware_random_bytes(size: int) -> Optional[bytes]:
    """
    Get random bytes from the best available hardware RNG source
    
    Args:
        size: Number of random bytes to generate
        
    Returns:
        bytes: Random bytes if successful, None if no sources are available
    """
    return hw_rng_manager.get_random_bytes(size)

def get_hardware_rng_status() -> Dict[str, Any]:
    """
    Get detailed status of all hardware RNG sources
    
    Returns:
        dict: Status information including available sources and their states
    """
    return hw_rng_manager.get_status()

def get_hardware_rng_health() -> Dict[str, Any]:
    """
    Get health status of the hardware RNG system
    
    Returns:
        dict: Health status information
    """
    return hw_rng_manager.get_health_status()


def reseed_hardware_rng() -> bool:
    """
    Reseed the hardware RNG from high-quality entropy sources
    
    Returns:
        bool: True if reseeding was successful, False otherwise
    """
    return hw_rng_manager.reseed_from_entropy_pool()

# Initialize on import
if __name__ == "__main__":
    # Simple test if run directly
    print("Hardware RNG Sources:")
    for source in hw_rng_manager.available_sources:
        print(f"- {source.type.name}")
    
    print("\nTesting random data (16 bytes):")
    data = get_hardware_random_bytes(16)
    if data:
        print(f"Got {len(data)} bytes: {data.hex()}")
    else:
        print("No hardware RNG available")