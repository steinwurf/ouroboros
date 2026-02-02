"""Pure-Python shared-memory log reader for Ouroboros."""

from .reader import ChunkInfo, Entry, Reader

__all__ = ["ChunkInfo", "Entry", "Reader"]
__version__ = "0.1.0"
