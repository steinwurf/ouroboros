# ouroboros-py

Pure-Python shared-memory log reader for Ouroboros.

This package provides a pure-Python implementation of the Ouroboros shared-memory log reader, allowing Python applications to read log entries from shared memory segments created by the C++ Ouroboros library.

## Requirements

- Python 3.8 or higher
- `multiprocessing.shared_memory` (available in Python 3.8+ on POSIX and Windows)

## Installation

```bash
cd python
pip install -e .
```

## Usage

```python
from ouroboros_py import Reader

# Attach to an existing shared memory segment
reader = Reader("/my_shm_segment")

# Read all entries
all_payloads = reader.read_all()

# Or iterate over entries
for payload in reader:
    print(f"Received: {payload}")

# Clean up
reader.close()

# Or use as context manager
with Reader("/my_shm_segment") as reader:
    for payload in reader:
        process(payload)
```

## API

### `Reader(name: str)`

Creates a reader that attaches to the shared memory segment with the given name.

**Parameters:**
- `name`: Name of the shared memory segment (must start with '/' on POSIX systems)

**Raises:**
- `ReaderError`: If shared memory cannot be attached or is invalid
- `InvalidMagicError`: If buffer magic value is invalid
- `UnsupportedVersionError`: If buffer version is unsupported
- `NoDataAvailableError`: If no data is available in the buffer

### Methods

#### `read_all() -> List[bytes]`

Read all available entries from the log.

**Returns:**
- List of payload bytes for all entries in order

#### `__iter__() -> Iterator[bytes]`

Iterate over all available entries.

**Yields:**
- Payload bytes for each entry in order

#### `close() -> None`

Close the shared memory connection and release resources.

### Properties

#### `total_entries_read: int`

Get the total number of entries read.

#### `chunk_count: int`

Get the number of chunks in the buffer.

## Testing

Tests require the `ouroboros_shm_generator` executable to be available. Set the `OUROBOROS_SHM_GENERATOR` environment variable to point to the executable, or it will be searched in common build paths.

```bash
# Install test dependencies
pip install -e ".[test]"

# Run tests
pytest
```

## Platform Support

- **POSIX (Linux, macOS)**: Uses `multiprocessing.shared_memory.SharedMemory` (Python 3.8+)
- **Windows**: Uses `multiprocessing.shared_memory.SharedMemory` (Python 3.8+)

The implementation matches the exact buffer format used by the C++ `shm_log_reader` and `shm_log_writer`, including:
- Buffer header with magic value and version
- Chunk table with offsets and tokens
- Entry framing with commit bits
- Wrap/overwrite semantics
- Atomic operations for thread-safe reading
