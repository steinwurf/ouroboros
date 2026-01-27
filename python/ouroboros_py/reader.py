"""Pure-Python implementation of Ouroboros shared-memory log reader."""

import logging
import struct
import sys
from typing import Iterator, List, Optional, Union

try:
    from multiprocessing import shared_memory
except ImportError:
    shared_memory = None  # type: ignore

log = logging.getLogger(__name__)

# Buffer format constants (matching C++ buffer_format.hpp)
MAGIC = 0x4F55524F424C4F47  # "OUROBLOG"
VERSION = 1
BUFFER_HEADER_SIZE = 16
CHUNK_ROW_SIZE = 16
ENTRY_HEADER_SIZE = 4
ENTRY_ALIGNMENT = 4


class ReaderError(Exception):
    """Base exception for Reader errors."""

    pass


class InvalidMagicError(ReaderError):
    """Raised when buffer magic value is invalid."""

    pass


class UnsupportedVersionError(ReaderError):
    """Raised when buffer version is unsupported."""

    pass


class InvalidChunkCountError(ReaderError):
    """Raised when chunk count is invalid."""

    pass


class BufferTooSmallError(ReaderError):
    """Raised when buffer is too small."""

    pass


class NoDataAvailableError(ReaderError):
    """Raised when no data is available to read."""

    pass


def _is_committed(value: int, bits: int = 64) -> bool:
    """Check if the commit bit (MSB) is set."""
    msb_mask = 1 << (bits - 1)
    return (value & msb_mask) != 0


def _clear_commit(value: int, bits: int = 64) -> int:
    """Clear the commit bit and return the value."""
    if not _is_committed(value, bits):
        raise ValueError(f"Value is not committed: {value}")
    msb_mask = 1 << (bits - 1)
    return value & ~msb_mask


def _align_up(size: int, align: int) -> int:
    """Align size up to the specified alignment boundary."""
    return (size + align - 1) & ~(align - 1)


def _load_acquire_u32(data: Union[bytes, memoryview], offset: int) -> int:
    """Load uint32_t with acquire semantics (read barrier)."""
    # On x86/x64, regular loads are naturally acquire-ordered
    # We use struct.unpack which should preserve ordering
    return struct.unpack("<I", data[offset : offset + 4])[0]


def _load_acquire_u64(data: Union[bytes, memoryview], offset: int) -> int:
    """Load uint64_t with acquire semantics (read barrier)."""
    # On x86/x64, regular loads are naturally acquire-ordered
    # We use struct.unpack which should preserve ordering
    return struct.unpack("<Q", data[offset : offset + 8])[0]


class Reader:
    """Pure-Python reader for Ouroboros shared-memory log buffers."""

    def __init__(self, name: str):
        """Initialize a reader for the given shared memory name.

        Args:
            name: Name of the shared memory segment (must start with '/' on POSIX)

        Raises:
            ReaderError: If shared memory cannot be attached or is invalid
        """
        if shared_memory is None:
            raise ReaderError(
                "multiprocessing.shared_memory is not available. "
                "Requires Python 3.8+ on POSIX or Windows."
            )

        self._name = name
        self._shm: Optional[shared_memory.SharedMemory] = None
        self._buffer: Optional[Union[bytes, memoryview]] = None
        self._chunk_count = 0
        self._current_chunk_index = 0
        self._current_chunk_token = 0
        self._offset = 0
        self._total_entries_read = 0
        self._entries_read_in_current_chunk = 0

        log.debug("Creating Reader for shared memory '%s'", self._name)
        self._attach()

    def _attach(self) -> None:
        """Attach to the shared memory segment and validate the buffer."""
        try:
            self._shm = shared_memory.SharedMemory(name=self._name, create=False)
            # Use live buffer (memoryview), not a snapshot; bytes() would copy once
            # and we would never see entries written by the generator after attach.
            self._buffer = self._shm.buf
        except FileNotFoundError:
            log.error(
                "Shared memory segment '%s' not found when attaching Reader",
                self._name,
            )
            raise ReaderError(
                f"Shared memory segment '{self._name}' not found. "
                "Make sure the writer has created it."
            )
        except Exception as e:
            log.exception(
                "Failed to attach Reader to shared memory '%s': %s",
                self._name,
                e,
            )
            raise ReaderError(f"Failed to attach to shared memory: {e}")

        if not self._is_ready():
            log.error(
                "Buffer for shared memory '%s' has invalid magic header", self._name
            )
            raise InvalidMagicError("Buffer magic value does not match")

        # Validate version
        version = _load_acquire_u32(self._buffer, 8)
        if version != VERSION:
            raise UnsupportedVersionError(
                f"Unsupported buffer version: {version} (expected {VERSION})"
            )

        # Read chunk count
        self._chunk_count = _load_acquire_u32(self._buffer, 12)
        if self._chunk_count == 0:
            raise InvalidChunkCountError("Chunk count is zero")

        # Validate buffer size
        min_buffer_size = BUFFER_HEADER_SIZE + (self._chunk_count * CHUNK_ROW_SIZE)
        if len(self._buffer) < min_buffer_size:
            raise BufferTooSmallError(
                f"Buffer too small: {len(self._buffer)} < {min_buffer_size}"
            )

        # Find starting chunk and initialize reading position
        starting_chunk = self._find_starting_chunk()
        if starting_chunk is None:
            raise NoDataAvailableError("No data available in buffer")

        if not self._jump_to_chunk(starting_chunk):
            raise NoDataAvailableError("Failed to jump to starting chunk")

        log.info(
            "Reader attached to shm '%s': size=%d bytes, chunks=%d, "
            "start_chunk=%d",
            self._name,
            len(self._buffer),
            self._chunk_count,
            starting_chunk,
        )

    def _is_ready(self) -> bool:
        """Check if the buffer is ready (magic bytes match)."""
        if len(self._buffer) < 8:
            return False
        magic_value = _load_acquire_u64(self._buffer, 0)
        return magic_value == MAGIC

    def _chunk_row_offset(self, chunk_index: int) -> int:
        """Get the byte offset of a chunk row in the buffer."""
        return BUFFER_HEADER_SIZE + (chunk_index * CHUNK_ROW_SIZE)

    def _get_chunk_offset(self, chunk_index: int) -> int:
        """Get the chunk offset, returning 0 if not committed."""
        offset = self._chunk_row_offset(chunk_index)
        offset_value = _load_acquire_u64(self._buffer, offset)
        if not _is_committed(offset_value):
            return 0
        return _clear_commit(offset_value)

    def _get_chunk_token(self, chunk_index: int) -> int:
        """Get the chunk token."""
        offset = self._chunk_row_offset(chunk_index) + 8
        return _load_acquire_u64(self._buffer, offset)

    def _is_chunk_committed(self, chunk_index: int) -> bool:
        """Check if a chunk is committed."""
        offset = self._chunk_row_offset(chunk_index)
        offset_value = _load_acquire_u64(self._buffer, offset)
        return _is_committed(offset_value)

    def _find_chunk_with_highest_token(self) -> Optional[int]:
        """Find the chunk with the highest token."""
        best_chunk: Optional[int] = None
        best_token = 0

        for i in range(self._chunk_count):
            if not self._is_chunk_committed(i):
                continue

            token = self._get_chunk_token(i)
            if token > best_token:
                best_token = token
                best_chunk = i

        return best_chunk

    def _find_chunk_with_lowest_token(self) -> Optional[int]:
        """Find the chunk with the lowest token."""
        best_chunk: Optional[int] = None
        best_token = sys.maxsize

        for i in range(self._chunk_count):
            if not self._is_chunk_committed(i):
                continue

            token = self._get_chunk_token(i)
            if token < best_token:
                best_token = token
                best_chunk = i

        return best_chunk

    def _find_starting_chunk(self) -> Optional[int]:
        """Find the starting chunk using auto-detect strategy."""
        # Auto-detect: if chunk 0 is committed with token 0, start there
        if self._is_chunk_committed(0) and self._get_chunk_token(0) == 0:
            return 0

        # Otherwise, find chunk with highest token (latest data)
        return self._find_chunk_with_highest_token()

    def _jump_to_chunk(self, chunk_index: int) -> bool:
        """Jump to a specific chunk and update reading position."""
        chunk_offset = self._get_chunk_offset(chunk_index)
        if chunk_offset == 0:
            return False

        if chunk_offset % ENTRY_ALIGNMENT != 0:
            raise ReaderError(
                f"Chunk offset {chunk_offset} is not aligned to {ENTRY_ALIGNMENT}"
            )

        chunk_token = self._get_chunk_token(chunk_index)
        if chunk_token < self._current_chunk_token:
            # Cannot jump to an older chunk
            return False

        self._current_chunk_token = chunk_token
        self._current_chunk_index = chunk_index
        self._offset = chunk_offset
        self._entries_read_in_current_chunk = 0
        return True

    def _read_next_entry(self) -> Optional[bytes]:
        """Read the next entry from the log, returning None if no data available."""
        if self._buffer is None:
            raise ReaderError("Reader not attached to buffer")

        # Retry loop: wrap / stale chunk / uncommitted entry all resolve by
        # either jumping and retrying, or returning None.
        while True:
            # Implicit wrap: no room for header
            if self._offset + ENTRY_HEADER_SIZE > len(self._buffer):
                log.debug(
                    "_read_next_entry: wrap at offset=%d (buf_len=%d), jump chunk 0",
                    self._offset,
                    len(self._buffer),
                )
                if not self._jump_to_chunk(0):
                    log.debug("_read_next_entry: jump_to_chunk(0) failed, returning None")
                    return None
                continue

            # Read entry header
            length_with_flag = _load_acquire_u32(self._buffer, self._offset)

            # Check if the read was valid by checking the chunk token
            if (
                not self._is_chunk_committed(self._current_chunk_index)
                or self._current_chunk_token
                != self._get_chunk_token(self._current_chunk_index)
            ):
                log.debug(
                    "_read_next_entry: chunk %d invalidated (token stale), jump latest",
                    self._current_chunk_index,
                )
                latest = self._find_chunk_with_highest_token()
                if latest is None:
                    log.debug("_read_next_entry: no chunk with highest token, None")
                    return None

                if not self._jump_to_chunk(latest):
                    log.debug("_read_next_entry: jump_to_chunk(%d) failed, None", latest)
                    return None
                continue

            # Check if the entry is committed
            if not _is_committed(length_with_flag, bits=32):
                log.debug(
                    "_read_next_entry: offset=%d length_with_flag=0x%x not committed",
                    self._offset,
                    length_with_flag,
                )
                return None

            # Clear the commit flag and get the length
            length = _clear_commit(length_with_flag, bits=32)

            # Check if the entry length is valid
            if length == 0:
                log.debug("_read_next_entry: offset=%d length=0 (not written yet)", self._offset)
                return None

            if length == 1:
                log.debug("_read_next_entry: offset=%d length=1 (writer wrap), jump chunk 0", self._offset)
                if not self._jump_to_chunk(0):
                    log.debug("_read_next_entry: jump_to_chunk(0) failed, None")
                    return None
                continue

            # Validate length
            if length < ENTRY_HEADER_SIZE:
                raise ReaderError(
                    f"Entry length {length} smaller than header size {ENTRY_HEADER_SIZE}"
                )

            # Check that the entry fits in the buffer
            if self._offset + length > len(self._buffer):
                raise ReaderError(
                    f"Entry exceeds buffer bounds: offset={self._offset}, "
                    f"length={length}, buffer_size={len(self._buffer)}"
                )

            # Check if we advanced to the next chunk
            next_chunk_index = self._current_chunk_index + 1
            if next_chunk_index < self._chunk_count:
                next_chunk_offset = self._get_chunk_offset(next_chunk_index)
                if next_chunk_offset != 0 and self._offset == next_chunk_offset:
                    log.debug(
                        "_read_next_entry: at chunk boundary, jump chunk %d",
                        next_chunk_index,
                    )
                    if not self._jump_to_chunk(next_chunk_index):
                        return None
                    continue

            # Extract payload
            payload_size = length - ENTRY_HEADER_SIZE
            payload_start = self._offset + ENTRY_HEADER_SIZE
            payload = bytes(
                self._buffer[payload_start : payload_start + payload_size]
            )

            # Advance offset
            self._offset += length
            self._offset = _align_up(self._offset, ENTRY_ALIGNMENT)
            self._total_entries_read += 1
            self._entries_read_in_current_chunk += 1

            log.debug(
                "_read_next_entry: read payload chunk=%d offset_was=%d len=%d "
                "payload_size=%d total_read=%d",
                self._current_chunk_index,
                payload_start - ENTRY_HEADER_SIZE,
                length,
                payload_size,
                self._total_entries_read,
            )
            return payload

    def read_next(self) -> Optional[bytes]:
        """Read the next available entry, if any.

        Returns one payload or None when no data is available yet (or when
        all data has been read). Use this for real-time reading: poll in a
        loop, collect payloads, and stop when you have enough or the writer
        has finished.

        Returns:
            Payload bytes for the next entry, or None if no entry is available.
        """
        return self._read_next_entry()

    def read_all(self) -> List[bytes]:
        """Read all available entries from the log.

        Returns:
            List of payload bytes for all entries in order

        Raises:
            ReaderError: If reading fails
        """
        log.debug("read_all() called on Reader for shm '%s'", self._name)
        entries = []
        while True:
            entry = self._read_next_entry()
            if entry is None:
                break
            entries.append(entry)
        log.info(
            "read_all() completed on shm '%s': %d entries",
            self._name,
            len(entries),
        )
        return entries

    def __iter__(self) -> Iterator[bytes]:
        """Iterate over all available entries.

        Yields:
            Payload bytes for each entry in order
        """
        while True:
            entry = self._read_next_entry()
            if entry is None:
                break
            yield entry

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - cleanup shared memory."""
        self.close()

    def close(self) -> None:
        """Close the shared memory connection."""
        if self._shm is not None:
            log.debug("Closing Reader for shm '%s'", self._name)
            self._shm.close()
            self._shm = None
            self._buffer = None

    @property
    def total_entries_read(self) -> int:
        """Get the total number of entries read."""
        return self._total_entries_read

    @property
    def chunk_count(self) -> int:
        """Get the number of chunks."""
        return self._chunk_count
