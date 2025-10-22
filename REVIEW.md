# Code Review Notes

## Critical Issues

### 1. `SecureMemory.zero` dereferences a null address for zero-length allocations
`SecureMemory.zero` assumes `self._address` is always valid. When a `SecureMemory`
instance is created with `size <= 0`, `_allocate` marks it as allocated but leaves
`_address` as `None`. Calling `zero()` on such an instance passes `None` to
`ctypes.from_address`, raising a `TypeError` and breaking callers like
`secure_free` that blindly invoke `zero()` during cleanup. This affects any code
path that attempts to "securely" free an empty buffer.

### 2. `hardware_rng` uses `threading` without importing it
`HWRNGManager` constructs a `threading.RLock`, but the module never imports the
`threading` package. Instantiating the manager therefore raises a `NameError`
and prevents all hardware RNG functionality from loading.

### 3. Entropy accumulator wipes temporary material incorrectly
`EntropyAccumulator` calls `secure_wipe(bytearray(key_material))` and
`secure_wipe(bytearray(block))`, which only zero temporary *copies* of the data.
The original immutable `bytes` objects remain untouched, leaving key material in
memory after reseed/output operations and defeating the expected security
properties.

### 4. `secure_alloc` is not a context manager
`main.py` uses `with secure_alloc(...) as secure_buffer:`, but `secure_alloc`
returns a `SecureMemory` instance that does not implement `__enter__`/`__exit__`.
This raises an `AttributeError` during the decrypt flow, aborting the operation.

### 5. `auth_database.py` does not compile
Running `python -m py_compile auth_database.py` fails with an unterminated string
literal error near `update_session_activity`. The module therefore cannot be
imported or executed.
