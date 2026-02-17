// Copyright (c) 2026 Steinwurf ApS
// SPDX-License-Identifier: MIT

#pragma once

#include <cstdint>
#include <cstring>
#include <verify/verify.hpp>

#include "../version.hpp"
#include "atomic.hpp"
#include "span.hpp"

namespace ouroboros
{
inline namespace STEINWURF_OUROBOROS_VERSION
{
namespace detail
{

/// Common buffer format constants and structures shared between reader and
/// writer.
namespace buffer_format
{

/// Magic value identifying a valid log buffer
constexpr static uint64_t magic = 0x4F55524F424C4F47ULL; // "OUROBLOG"

/// Current buffer format version
constexpr static uint32_t version = 2;

/// Size of the buffer header in bytes
constexpr static uint32_t buffer_header_size = 24;

/// Size of a chunk row in the chunk table (8 bytes offset + 8 bytes token)
constexpr static uint32_t chunk_row_size = 16;

/// Size of an entry header in bytes
constexpr static uint32_t entry_header_size = 4;

/// Alignment requirement for entries (must be 4-byte aligned for atomic
/// operations)
constexpr static uint32_t entry_alignment = 4;

template <typename Byte>
inline constexpr auto entry_header(std::span<Byte> buffer)
    -> std::conditional_t<std::is_const_v<Byte>, const uint32_t*, uint32_t*>
{
    static_assert(std::is_same_v<std::remove_const_t<Byte>, uint8_t>,
                  "entry_header expects a span of uint8_t");

    VERIFY(buffer.size() >= entry_header_size,
           "Buffer too small for entry header");

    VERIFY(reinterpret_cast<uintptr_t>(buffer.data()) % alignof(uint32_t) == 0,
           "Buffer not properly aligned for entry header");

    return reinterpret_cast<
        std::conditional_t<std::is_const_v<Byte>, const uint32_t*, uint32_t*>>(
        buffer.data());
}

template <typename Byte>
inline constexpr auto chunk_offset(std::span<Byte> buffer)
    -> std::conditional_t<std::is_const_v<Byte>, const uint64_t*, uint64_t*>
{
    static_assert(std::is_same_v<std::remove_const_t<Byte>, uint8_t>,
                  "chunk_offset expects a span of uint8_t");

    VERIFY(buffer.size() >= chunk_row_size, "Buffer too small for chunk row");

    VERIFY(reinterpret_cast<uintptr_t>(buffer.data()) % alignof(uint64_t) == 0,
           "Buffer not properly aligned for chunk offset");

    return reinterpret_cast<
        std::conditional_t<std::is_const_v<Byte>, const uint64_t*, uint64_t*>>(
        buffer.data());
}

template <typename Byte>
inline constexpr auto chunk_token(std::span<Byte> buffer)
    -> std::conditional_t<std::is_const_v<Byte>, const uint64_t*, uint64_t*>
{
    static_assert(std::is_same_v<std::remove_const_t<Byte>, uint8_t>,
                  "chunk_token expects a span of uint8_t");

    VERIFY(buffer.size() >= chunk_row_size, "Buffer too small for chunk row");

    VERIFY(reinterpret_cast<uintptr_t>(buffer.data()) % alignof(uint64_t) == 0,
           "Buffer not properly aligned for chunk token");

    return reinterpret_cast<
        std::conditional_t<std::is_const_v<Byte>, const uint64_t*, uint64_t*>>(
        buffer.data() + sizeof(uint64_t));
}

/// Calculate the size of the buffer header needed for a given chunk count
/// @param chunk_count The number of chunks
/// @return The size of the buffer header needed for the given chunk count
inline constexpr auto
compute_buffer_header_size(std::size_t chunk_count) -> std::size_t
{
    return buffer_header_size + (chunk_count * chunk_row_size);
}

/// Calculate the size of the buffer needed for a given chunk target size and
/// chunk count
/// @note This function is primarily used by the writer for buffer allocation.
///       The reader doesn't need chunk_target_size as it only uses chunk
///       offsets.
/// @param chunk_target_size The target size of each chunk
/// @param chunk_count The number of chunks
/// @return The size of the buffer needed for the given chunk target size and
/// chunk count
inline constexpr auto
compute_buffer_size(std::size_t chunk_target_size,
                    std::size_t chunk_count) -> std::size_t
{
    return compute_buffer_header_size(chunk_count) +
           (chunk_target_size * chunk_count);
}

/// Align a size up to the specified alignment boundary
/// @param size The size to align
/// @param align The alignment requirement (must be a power of 2)
/// @return The aligned size
inline constexpr auto align_up(std::size_t size,
                               std::size_t align) -> std::size_t
{
    return (size + align - 1) & ~(align - 1);
}

/// Offset of the buffer ID in the header (8 bytes, must be read/written
/// atomically)
constexpr static uint32_t buffer_id_offset = 16;

/// Get the offset of a chunk row in the buffer
/// @param chunk_index The index of the chunk
/// @return The byte offset of the chunk row from the start of the buffer
inline constexpr auto chunk_row_offset(std::size_t chunk_index) -> std::size_t
{
    return buffer_header_size + (chunk_index * chunk_row_size);
}

// ---- Small helpers for "commit bit" patterns ----

template <class T>
inline constexpr bool is_committed(T v) noexcept
{
    constexpr T msb_mask = static_cast<T>(1) << (sizeof(T) * 8 - 1);
    return (v & msb_mask) != 0;
}

template <class T>
inline constexpr T clear_commit(T v) noexcept
{
    VERIFY(is_committed(v), "Value is not committed", v);
    constexpr T msb_mask = static_cast<T>(1) << (sizeof(T) * 8 - 1);
    return (v & ~msb_mask);
}

template <class T>
inline constexpr T set_commit(T v) noexcept
{
    VERIFY(!is_committed(v), "Value is already committed", v);
    constexpr T msb_mask = static_cast<T>(1) << (sizeof(T) * 8 - 1);
    return (v | msb_mask);
}

// ---- Shared helper functions ----

/// Read a value from a buffer using memcpy (alignment-safe)
/// @tparam T The type of value to read
/// @param buffer Pointer to the buffer to read from
/// @return The value read from the buffer
template <typename T>
inline auto read_value(const uint8_t* buffer) -> T
{
    T value;
    std::memcpy(&value, buffer, sizeof(value));
    return value;
}

/// Write a value to a buffer using memcpy (alignment-safe)
/// @tparam T The type of value to write
/// @param buffer The buffer to write to (must be at least sizeof(T) bytes)
/// @param value The value to write
template <typename T>
inline void write_value(std::span<uint8_t> buffer, T value)
{
    VERIFY(buffer.size() >= sizeof(T), "Buffer too small for value", sizeof(T),
           buffer.size());
    std::memcpy(buffer.data(), &value, sizeof(value));
}

/// Get a span to a chunk row in the buffer (const version)
/// @param buffer The buffer containing the chunk table
/// @param chunk_index The index of the chunk
/// @return A span to the chunk row
inline auto chunk_row(std::span<const uint8_t> buffer,
                      std::size_t chunk_index) -> std::span<const uint8_t>
{
    return buffer.subspan(chunk_row_offset(chunk_index), chunk_row_size);
}

/// Get a span to a chunk row in the buffer (mutable version)
/// @param buffer The buffer containing the chunk table
/// @param chunk_index The index of the chunk
/// @return A span to the chunk row
inline auto chunk_row(std::span<uint8_t> buffer,
                      std::size_t chunk_index) -> std::span<uint8_t>
{
    return buffer.subspan(chunk_row_offset(chunk_index), chunk_row_size);
}

/// Check if a buffer has been initialized with valid magic bytes and version
/// @param buffer The buffer to check
/// @return True if the buffer has valid magic and version
inline auto is_initialized(std::span<const uint8_t> buffer) -> bool
{
    if (buffer.size() < buffer_header_size)
    {
        return false;
    }

    const uint64_t magic_value =
        atomic::load_acquire(reinterpret_cast<const uint64_t*>(buffer.data()));

    if (magic_value != magic)
    {
        return false;
    }

    const uint32_t buf_version = read_value<uint32_t>(buffer.data() + 8);
    if (buf_version != version)
    {
        return false;
    }

    return true;
}

/// Check if a chunk is committed
/// @param buffer The buffer containing the chunk table
/// @param chunk_index The index of the chunk
/// @return True if the chunk is committed
inline auto is_chunk_committed(std::span<const uint8_t> buffer,
                               std::size_t chunk_index) -> bool
{
    return is_committed(*chunk_offset(chunk_row(buffer, chunk_index)));
}

/// Get the offset of a chunk (with commit flag cleared if present)
/// @param buffer The buffer containing the chunk table
/// @param chunk_index The index of the chunk
/// @return The offset of the chunk
inline auto get_chunk_offset(std::span<const uint8_t> buffer,
                             std::size_t chunk_index) -> std::size_t
{
    auto offset_value = *chunk_offset(chunk_row(buffer, chunk_index));
    if (is_committed(offset_value))
    {
        return clear_commit(offset_value);
    }
    return offset_value;
}

} // namespace buffer_format
} // namespace detail
}
}
