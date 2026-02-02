// Package ouroboros provides a pure-Go implementation of the Ouroboros
// shared-memory log reader.
package ouroboros

import (
	"encoding/binary"
	"errors"
	"os"
	"strings"
	"sync/atomic"
	"unsafe"

	"github.com/tmthrgd/go-shm"
	"golang.org/x/sys/unix"
)

// loadAcquireU32 loads a uint32 with acquire semantics (matching C++ atomic::load_acquire).
func loadAcquireU32(b []byte, offset uint64) uint32 {
	return atomic.LoadUint32((*uint32)(unsafe.Pointer(&b[offset])))
}

// loadAcquireU64 loads a uint64 with acquire semantics (matching C++ atomic::load_acquire).
func loadAcquireU64(b []byte, offset uint64) uint64 {
	return atomic.LoadUint64((*uint64)(unsafe.Pointer(&b[offset])))
}

// readValueU32 reads a uint32 with plain memcpy (matching C++ read_value).
func readValueU32(b []byte, offset uint64) uint32 {
	return binary.LittleEndian.Uint32(b[offset:])
}

// Buffer format constants (matching C++ buffer_format.hpp)
const (
	Magic             = 0x4F55524F424C4F47 // "OUROBLOG"
	Version           = 1
	BufferHeaderSize  = 16
	ChunkRowSize      = 16
	EntryHeaderSize = 4
	EntryAlignment  = 4
)

// Reader errors
var (
	ErrInvalidMagic       = errors.New("buffer magic value does not match")
	ErrUnsupportedVersion = errors.New("unsupported buffer version")
	ErrInvalidChunkCount  = errors.New("chunk count is zero")
	ErrBufferTooSmall     = errors.New("buffer too small")
	ErrNoDataAvailable    = errors.New("no data available in buffer")
	ErrReaderNotAttached  = errors.New("reader not attached to buffer")
)

// ChunkInfo holds information about a chunk in the buffer.
type ChunkInfo struct {
	Index       int
	Token       uint64
	Offset      uint64
	IsCommitted bool
}

// Entry represents a log entry with payload data and chunk metadata.
// IsValid() reads from the live buffer; do not call IsValid after Reader.Close().
type Entry struct {
	Data           []byte
	ChunkInfo      ChunkInfo
	SequenceNumber uint64
	chunkRowView   []byte // live view into buffer for IsValid; invalid after Reader.Close
}

// IsValid checks if the entry is still valid (chunk has not been overwritten).
// Must not be called after Reader.Close().
func (e *Entry) IsValid() bool {
	if e.chunkRowView == nil || len(e.chunkRowView) < 16 {
		return false
	}
	currentToken := loadAcquireU64(e.chunkRowView, 8)
	return e.ChunkInfo.Token == currentToken
}

// Reader reads from Ouroboros shared-memory log buffers.
type Reader struct {
	name               string
	file               *os.File
	buffer             []byte
	chunkCount         uint32
	currentChunk       ChunkInfo // cached; use for offset/token/index
	offset             uint64   // current read position
	totalEntriesRead   uint64
	entriesReadInChunk uint64
}

// NewReader creates a reader for the given shared memory name.
// On POSIX, the name may have a leading slash (e.g. "/ouro_test_xxx").
func NewReader(name string) (*Reader, error) {
	r := &Reader{name: name}
	if err := r.attach(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *Reader) attach() error {
	shmName := strings.TrimPrefix(r.name, "/")
	f, err := shm.Open(shmName, os.O_RDONLY, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return errors.New("shared memory segment " + r.name + " not found when attaching Reader")
		}
		return errors.New("failed to attach to shared memory: " + err.Error())
	}
	r.file = f

	info, err := f.Stat()
	if err != nil {
		f.Close()
		return errors.New("failed to stat shared memory: " + err.Error())
	}
	size := info.Size()
	if size <= 0 {
		f.Close()
		return ErrBufferTooSmall
	}

	data, err := unix.Mmap(int(f.Fd()), 0, int(size), unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		f.Close()
		return errors.New("failed to mmap shared memory: " + err.Error())
	}
	r.buffer = data

	if !r.isReady() {
		r.close()
		return ErrInvalidMagic
	}

	version := readValueU32(r.buffer, 8)
	if version != Version {
		r.close()
		return errors.Join(ErrUnsupportedVersion, errors.New("expected version 1"))
	}

	r.chunkCount = readValueU32(r.buffer, 12)
	if r.chunkCount == 0 {
		r.close()
		return ErrInvalidChunkCount
	}

	minSize := BufferHeaderSize + (r.chunkCount * ChunkRowSize)
	if uint64(len(r.buffer)) < uint64(minSize) {
		r.close()
		return ErrBufferTooSmall
	}

	startChunk := r.findStartingChunk()
	if !startChunk.IsCommitted || startChunk.Offset == 0 {
		r.close()
		return ErrNoDataAvailable
	}

	r.setCurrentChunk(startChunk)

	return nil
}

func (r *Reader) isReady() bool {
	if len(r.buffer) < 8 {
		return false
	}
	magic := loadAcquireU64(r.buffer, 0)
	return magic == Magic
}

func chunkRowOffset(chunkIndex int) uint64 {
	return BufferHeaderSize + uint64(chunkIndex)*ChunkRowSize
}

func isCommitted32(v uint32) bool {
	return (v & (1 << 31)) != 0
}

func clearCommit32(v uint32) uint32 {
	return v & ^uint32(1<<31)
}

func isCommitted64(v uint64) bool {
	return (v & (1 << 63)) != 0
}

func clearCommit64(v uint64) uint64 {
	return v & ^uint64(1<<63)
}

// getChunkInfo reads chunk row from buffer (2 atomic loads).
func getChunkInfo(buffer []byte, chunkIndex int) ChunkInfo {
	off := chunkRowOffset(chunkIndex)
	offsetVal := loadAcquireU64(buffer, off)
	tokenVal := loadAcquireU64(buffer, off+8)
	committed := isCommitted64(offsetVal)
	chunkOffset := uint64(0)
	if committed {
		chunkOffset = clearCommit64(offsetVal)
	}
	return ChunkInfo{
		Index:       chunkIndex,
		Token:       tokenVal,
		Offset:      chunkOffset,
		IsCommitted: committed,
	}
}

// chunkRow returns a view of the chunk row for IsValid. No buffer read.
func chunkRow(buffer []byte, chunkIndex int) []byte {
	off := chunkRowOffset(chunkIndex)
	return buffer[off : off+ChunkRowSize]
}

func (r *Reader) setCurrentChunk(info ChunkInfo) {
	// Check that the given chunk is committed and that
	// the new chunk token is greater than the current chunk token.
	if !info.IsCommitted {
		panic("chunk is not committed")
	}
	if r.currentChunk.IsCommitted && info.Token <= r.currentChunk.Token {
		panic("new chunk token is not greater than current chunk token")
	}
	r.currentChunk = info
	r.offset = info.Offset
	r.entriesReadInChunk = 0
}

func (r *Reader) findChunkWithHighestToken() ChunkInfo {
	var best ChunkInfo
	for i := 0; i < int(r.chunkCount); i++ {
		info := getChunkInfo(r.buffer, i)
		if !info.IsCommitted {
			continue
		}
		if !best.IsCommitted || info.Token > best.Token {
			best = info
		}
	}
	return best
}

func (r *Reader) findStartingChunk() ChunkInfo {
	info := getChunkInfo(r.buffer, 0)
	if info.IsCommitted && info.Token == 0 {
		return info
	}
	return r.findChunkWithHighestToken()
}

func alignUp(size, align uint64) uint64 {
	return (size + align - 1) & ^(align - 1)
}

func (r *Reader) jumpToChunk(chunkIndex int) bool {
	info := getChunkInfo(r.buffer, chunkIndex)
	if !info.IsCommitted || info.Offset == 0 {
		return false
	}
	if r.currentChunk.IsCommitted && info.Token <= r.currentChunk.Token {
		return false
	}
	r.setCurrentChunk(info)
	return true
}

// ReadNextEntry reads the next entry from the log. Returns nil if no data available.
func (r *Reader) ReadNextEntry() *Entry {
	if r.buffer == nil {
		panic(ErrReaderNotAttached)
	}

	for {
		// Implicit wrap: no room for header
		if r.offset+EntryHeaderSize > uint64(len(r.buffer)) {
			if !r.jumpToChunk(0) {
				return nil
			}
			continue
		}

		// Check if we advanced to the next chunk by reading into it
		nextIndex := r.currentChunk.Index + 1
		if nextIndex < int(r.chunkCount) {
			nextInfo := getChunkInfo(r.buffer, nextIndex)
			if nextInfo.IsCommitted && r.offset == nextInfo.Offset {
				if nextInfo.Token <= r.currentChunk.Token {
					return nil
				}
				r.setCurrentChunk(nextInfo)
				continue
			}
		}

		// Read entry header
		lengthWithFlag := loadAcquireU32(r.buffer, r.offset)

		// Validate current chunk (single read of chunk row)
		info := getChunkInfo(r.buffer, r.currentChunk.Index)
		if !info.IsCommitted || info.Token != r.currentChunk.Token {
			latest := r.findChunkWithHighestToken()
			if !latest.IsCommitted {
				return nil
			}
			if latest.Token <= r.currentChunk.Token {
				return nil
			}
			r.setCurrentChunk(latest)
			continue
		}

		if !isCommitted32(lengthWithFlag) {
			return nil
		}

		length := uint64(clearCommit32(lengthWithFlag))

		if length == 0 {
			return nil
		}

		if length == 1 {
			if !r.jumpToChunk(0) {
				return nil
			}
			continue
		}

		if length < EntryHeaderSize {
			panic("entry length smaller than header size")
		}

		if r.offset+length > uint64(len(r.buffer)) {
			panic("entry exceeds buffer bounds")
		}

		payloadSize := length - EntryHeaderSize
		payloadStart := r.offset + EntryHeaderSize
		payload := make([]byte, payloadSize)
		copy(payload, r.buffer[payloadStart:payloadStart+payloadSize])

		r.offset += length
		r.offset = alignUp(r.offset, EntryAlignment)
		r.totalEntriesRead++
		r.entriesReadInChunk++

		seqNum := r.currentChunk.Token + r.entriesReadInChunk
		chunkRowView := chunkRow(r.buffer, r.currentChunk.Index)

		return &Entry{
			Data:           payload,
			ChunkInfo:      r.currentChunk,
			SequenceNumber: seqNum,
			chunkRowView:   chunkRowView,
		}
	}
}

// ReadNext reads the next entry as a string (UTF-8). Returns empty string if none.
func (r *Reader) ReadNext() string {
	entry := r.ReadNextEntry()
	if entry == nil {
		return ""
	}
	if !entry.IsValid() {
		return ""
	}
	return string(entry.Data)
}

// ReadAll reads all available entries.
func (r *Reader) ReadAll() []*Entry {
	var entries []*Entry
	for {
		entry := r.ReadNextEntry()
		if entry == nil {
			break
		}
		entries = append(entries, entry)
	}
	return entries
}

// TotalEntriesRead returns the total number of entries read.
func (r *Reader) TotalEntriesRead() uint64 {
	return r.totalEntriesRead
}

// ChunkCount returns the number of chunks.
func (r *Reader) ChunkCount() uint32 {
	return r.chunkCount
}

func (r *Reader) close() {
	if r.buffer != nil {
		unix.Munmap(r.buffer)
		r.buffer = nil
	}
	if r.file != nil {
		r.file.Close()
		r.file = nil
	}
}

// Close releases the shared memory connection.
func (r *Reader) Close() error {
	r.close()
	return nil
}
