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
from ouroboros_py import Entry, Reader

# Attach to an existing shared memory segment
reader = Reader("/my_shm_segment")

# Read all entries (returns list of Entry objects)
all_entries = reader.read_all()
for entry in all_entries:
    if entry.is_valid():
        print(f"Received: {entry.data}")

# Or iterate over entries
for entry in reader:
    print(f"Chunk {entry.chunk_info.index}: {entry.data}")

# Clean up
reader.close()

# Or use as context manager
with Reader("/my_shm_segment") as reader:
for entry in reader:
    if entry.is_valid():
        process(entry.data)
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

### `Entry`

A log entry with payload data and chunk metadata. Mirrors the C++ `reader::entry`.

**Properties:**
- `data: bytes` - Payload bytes for this entry
- `chunk_info: ChunkInfo` - Chunk metadata (index, token, offset)
- `sequence_number: int` - Sequence number of this entry

**Methods:**
- `is_valid() -> bool` - Check if the entry is still valid (chunk has not been overwritten).

### `ChunkInfo`

Information about a chunk in the buffer. Mirrors the C++ `reader::chunk_info`.

**Properties:**
- `index: int` - Chunk index in the chunk table
- `token: int` - Chunk token (number of entries written before this chunk)
- `offset: int` - Byte offset of the chunk in the buffer
- `is_committed: bool` - Whether the chunk is committed

### Methods

#### `read_next_entry() -> Optional[Entry]`

Read the next available entry, if any. Returns an `Entry` with data and chunk
info, or `None` when no data is available yet (or when all data has been read).

**Returns:**
- `Entry` with data and chunk metadata, or `None` if no entry is available

#### `read_next() -> Optional[str]`

Read the next available entry as a UTF-8 string, if any. Validates the entry
with `is_valid()` before returning; returns `None` if the entry was overwritten.

**Returns:**
- Payload decoded as UTF-8 string, or `None` if no entry is available or if the entry was overwritten

#### `read_all() -> List[Entry]`

Read all available entries from the log.

**Returns:**
- List of `Entry` objects for all entries in order

#### `__iter__() -> Iterator[Entry]`

Iterate over all available entries.

**Yields:**
- `Entry` for each log entry in order

#### `close() -> None`

Close the shared memory connection and release resources.

### Properties

#### `total_entries_read: int`

Get the total number of entries read.

#### `chunk_count: int`

Get the number of chunks in the buffer.

## Testing

Tests require the `ouroboros_shm_generator` executable to be available. Either set the `OUROBOROS_SHM_GENERATOR` environment variable, or pass it via pytest:

```bash
# Install test dependencies
pip install -e ".[test]"

# Run tests (generator path via option; works on Windows and Unix)
pytest --ouroboros-shm-generator=/path/to/ouroboros_shm_generator

# Or use the env var
export OUROBOROS_SHM_GENERATOR=/path/to/ouroboros_shm_generator
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
