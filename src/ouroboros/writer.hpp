// Copyright (c) 2026 Steinwurf ApS
// SPDX-License-Identifier: MIT

#pragma once

#include <tl/expected.hpp>
#include <verify/verify.hpp>

#include <cassert>
#include <cstdint>
#include <cstring>
#include <string_view>
#include <vector>

#include "detail/atomic.hpp"
#include "detail/buffer_format.hpp"
#include "detail/span.hpp"
#include "error_code.hpp"
#include "version.hpp"

namespace ouroboros
{
inline namespace STEINWURF_OUROBOROS_VERSION
{
/// A log writer that manages a circular buffer of variable-sized chunks.
///
/// The buffer is divided into a header followed by a table of chunks
/// descriptions. The chunks provide a stable synchronization point for readers
/// and allows safe detection of overwritten data that is not possible since
/// the entries have variable sizes.
///
/// The setup consists of the following components:
///
/// - Buffer: The entire memory area used consisting of buffer header, chunk
///           table, and entries.
///
/// - Chunk:  A logical division of the buffer used for synchronization. Each
///           chunk has a target size but it can be exceeded if an entry does
///           not fit in the remaining space of the chunk. In this case the next
///           chunk is offset and it's target size is reduced accordingly.
///
/// - Entry:  A slice of data written to the buffer with a header indicating
///           length and commit status.
///           To read an entry the reader must pick a chunk to start from and
///           read the chunk token. Then it can start reading the entries
///           sequentially from the chunk offset. After reading an entry the
///           reader must check the chunk token again to ensure it has not
///           changed. If it has changed the reader must discard the entry and
///           jump to the next chunk. Before reading an entry the reader must
///           also check if the commit flag of the entry is set. If not the
///           entry is not ready to be read and the reader must wait for the
///           writer to commit it. To ensure release–acquire synchronization the
///           entry header is atomic to guarantee that when a reader observes
///           the commit flag, all earlier payload writes are visible to it on
///           all CPU architectures. For this reason the entry header must be
///           aligned to a 4-byte boundary.
///
/// =================
/// Buffer header
/// =================
/// Offset | Size | Description
/// -------|------|-----------------------------------------------
/// 0      | 8    | Magic bytes "OUROBLOG"
/// 8      | 4    | Version
/// 12     | 4    | Chunk count N
/// 16     | 8    | Buffer ID (64-bit, configured by writer)
///  Chunk infos
/// 24     | 8    | Chunk 1 offset with MSB indicating commitment
/// 32     | 8    | Chunk 1 token
/// ...    | ...  | ...
/// 24+N*16| 8    | Chunk N offset
/// 24+N*16+8 | 8  | Chunk N token
/// -------|------|-----------------------------------------------
/// When writing the buffer the magic bytes are written last to ensure that
/// readers can detect a fully initialized buffer.
/// =================
/// Entry format
/// =================
/// Entries are written sequentially into the buffer.
///
/// Offset | Size | Description
/// -------|------|-----------------------------------------------
/// 0      | 4    | Entry length with MSB indicating commitment
/// 4      | N    | Entry payload
/// -------|------|-----------------------------------------------
/// Total entry header size: 4 bytes
///
/// The length of the entry covers the entire entry including the header.
/// This means that essentially the following values for the length
/// are invalid: 0, 1, 2, 3. This is useful as we can use them
/// to communicate special conditions.
/// - Length 0: Indicates that there are no more entries available.
/// - Length 1: Means that the writer has wrapped the buffer and that
///             the reader should jump to the first chunk.
/// - Length 2: Reserved.
/// - Length 3: Indicates that the writer has finished; no more data will be
///             written. The reader should unlink shared memory and return
///             writer_finished on all subsequent reads.
///
/// The commit flag is written last by the writer and is the sole indicator
/// of entry validity. Readers must never consume entries that are not
/// committed.
///
/// Entries must be aligned to a 4-byte boundary to ensure that the entry
/// header can be written atomically. This means that padding may be added
/// before the entry header if necessary.
///
/// =================
/// Padding and wrap behavior
/// =================
/// If an entry does not fit in the remaining space of the buffer it's pushed to
/// the next (first) chunk. And a special entry with length 1 is written to
/// indicate the wrap. This means that the reader when encountering an entry
/// with length 1 must jump to the first chunk and continue reading from there.
///
/// =================
/// Reader safety
/// =================
/// When the reader starts a session it will look at the first chunk in the
/// chunk table. If the chunk token is 0 the reader will start reading from
/// here. If the chunk token is non-zero the reader will instead look for the
/// chunk with the highest token and start reading from there. If the reader
/// reads an entry and detects that the chunk token was changed during the read
/// it will discard the entry and skip to the chunk with the highest token. The
/// reader only looks at the chunks with commited non-zero tokens.
class writer
{
public:
    /// Default constructor
    writer() = default;

    /// Information about where to resume writing
    struct resume_info
    {
        std::size_t offset;      ///< Byte offset where to continue writing
        std::size_t chunk_index; ///< Index of the current chunk
        uint64_t total_entries_written; ///< Number of entries written so far
    };

    /// Configure writer
    ///
    /// If the buffer is already initialized with matching parameters (magic,
    /// version, chunk_count, buffer_size, and buffer_id), the writer will
    /// attempt to resume from the previous writer and continue appending
    /// entries where it left off.
    ///
    /// @param buffer View of the buffer to write to (must be at least
    ///               buffer_header_size + (chunk_count * chunk_row_size) +
    ///               (chunk_count * chunk_target_size) bytes)
    /// @param chunk_target_size Target size of each chunk in bytes
    /// @param chunk_count Number of chunks (must be > 0)
    /// @param buffer_id 64-bit ID stored in the buffer header (e.g. for
    ///                  identifying the log instance)
    /// @param force_init If true, forces reinitialization of the buffer.
    ///          It will overwrite the values in the buffer header to the new
    ///          values and reset the current chunk index to 0.
    /// @return void on success, or an error_code indicating what failed.
    auto configure(std::span<uint8_t> buffer, std::size_t chunk_target_size,
                   std::size_t chunk_count, uint64_t buffer_id = 0,
                   bool force_init = false)
        -> tl::expected<void, configure_error>
    {
        VERIFY(buffer.data() != nullptr, "Buffer span must not be null!");
        VERIFY(buffer.size() > 0, "Buffer span must not be empty!");
        VERIFY(chunk_count > 0, "chunk_count must be greater than 0!");
        const auto chunk_table_size =
            (chunk_count * detail::buffer_format::chunk_row_size);
        const auto chunks_size = chunk_count * chunk_target_size;
        const auto expected_buffer_size =
            detail::buffer_format::buffer_header_size + chunk_table_size +
            chunks_size;
        VERIFY(buffer.size() >= expected_buffer_size,
               "Buffer span is too small for the given chunk_target_size and "
               "chunk_count");
        VERIFY(reinterpret_cast<uintptr_t>(buffer.data()) % 8 == 0,
               "Buffer must be 8-byte aligned!");

        // Check if buffer is previously initialized
        if (detail::buffer_format::is_initialized(buffer))
        {
            // Buffer is previously initialized

            // Check if we can resume writing where the previous writer
            // left off.
            auto result =
                try_resume(buffer, chunk_target_size, chunk_count, buffer_id);
            if (result.has_value())
            {
                const auto& info = result.value();
                m_current_chunk_index = info.chunk_index;
                m_offset = info.offset;
                m_total_entries_written = info.total_entries_written;
                m_finished = false;
                m_chunk_target_size = chunk_target_size;
                m_chunk_count = chunk_count;
                m_buffer_id = buffer_id;
                m_buffer = buffer;
                return {};
            }

            if (!force_init)
            {
                return tl::make_unexpected(result.error());
            }
        }

        // Buffer is not initialized, perform fresh initialization
        m_chunk_target_size = chunk_target_size;
        m_chunk_count = chunk_count;
        m_buffer_id = buffer_id;
        m_buffer = buffer;
        m_total_entries_written = 0;
        m_finished = false;

        // Zero initialize chunk table first
        std::memset(m_buffer.data() + detail::buffer_format::buffer_header_size,
                    0, chunk_table_size);

        // Write header (magic bytes written last to ensure fully initialized
        // buffer)
        write_header(
            m_buffer.subspan(0, detail::buffer_format::buffer_header_size),
            static_cast<uint32_t>(chunk_count), buffer_id);

        // Initialize first chunk
        m_current_chunk_index = 0;
        m_offset = detail::buffer_format::buffer_header_size + chunk_table_size;
        m_offset = detail::buffer_format::align_up(
            m_offset, detail::buffer_format::entry_alignment);
        initialize_chunk(
            detail::buffer_format::chunk_row(m_buffer, m_current_chunk_index),
            m_offset, m_total_entries_written);
        // Zero out the first entry header
        std::memset(m_buffer.data() + m_offset, 0,
                    detail::buffer_format::entry_header_size);
        commit_chunk(m_buffer, m_current_chunk_index);

        return {};
    }

    /// Write an entry to the log.
    /// @param entry The entry payload data to write
    void write(std::string_view entry)
    {
        VERIFY(!m_buffer.empty(), "Writer not configured");
        VERIFY(m_offset != 0, "Writer not properly configured - offset is 0");
        VERIFY(!m_finished, "Writer has already finished");
        VERIFY(entry.data() != nullptr, "Entry payload must not be null");
        VERIFY(entry.size() > 0, "Entry size must be greater than 0");

        auto payload_size = entry.size();
        uint32_t total_entry_size =
            detail::buffer_format::entry_header_size + payload_size;
        VERIFY(payload_size <= max_entry_size(),
               "Entry payload size exceeds maximum entry size");

        // Align offset to 4-byte boundary for entry header
        m_offset = detail::buffer_format::align_up(
            m_offset, detail::buffer_format::entry_alignment);

        // Check if entry fits in remaining buffer space (also handle the case
        // where offset is past the end of the buffer)
        const std::size_t remaining_space =
            (m_offset > m_buffer.size()) ? 0 : m_buffer.size() - m_offset;
        if (remaining_space < total_entry_size)
        {
            // It does not, we have to wrap the buffer

            // Check if we have enough space at the end of the buffer to write
            // the wrap entry (If not the wrap entry is implicit)
            if (remaining_space >= detail::buffer_format::entry_header_size)
            {
                auto header =
                    detail::buffer_format::entry_header(m_buffer.subspan(
                        m_offset, detail::buffer_format::entry_header_size));
                // Length 1 with commit flag set (MSB = 1)
                detail::atomic::store_release(header,
                                              detail::buffer_format::set_commit(
                                                  static_cast<uint32_t>(1)));
            }

            // Wrap the buffer
            m_current_chunk_index = 0;
            m_offset = detail::buffer_format::compute_buffer_header_size(
                m_chunk_count);
            // Verify that the offset is aligned to the entry alignment
            VERIFY(m_offset % detail::buffer_format::entry_alignment == 0,
                   "Offset is not aligned to entry alignment", m_offset,
                   detail::buffer_format::entry_alignment);
            initialize_chunk(detail::buffer_format::chunk_row(
                                 m_buffer, m_current_chunk_index),
                             m_offset, m_total_entries_written);
        }

        // Get current chunk offset
        auto chunk_offset = detail::buffer_format::get_chunk_offset(
            m_buffer, m_current_chunk_index);
        VERIFY(chunk_offset <= m_offset, "Chunk offset is greater than offset",
               chunk_offset, m_offset);
        auto written_in_chunk = m_offset - chunk_offset;
        if (written_in_chunk >= m_chunk_target_size)
        {
            // We have exceeded the target size of the current chunk, move to
            // the next chunk

            // But first check if the chunk we are leaving is committed
            if (!detail::buffer_format::is_chunk_committed(
                    m_buffer, m_current_chunk_index))
            {
                // Commit the chunk since we now have entries in the chunk
                commit_chunk(m_buffer, m_current_chunk_index);
            }

            m_current_chunk_index++;
            VERIFY(m_current_chunk_index < m_chunk_count,
                   "Current chunk index exceeds chunk count",
                   m_current_chunk_index, m_chunk_count);
            initialize_chunk(detail::buffer_format::chunk_row(
                                 m_buffer, m_current_chunk_index),
                             m_offset, m_total_entries_written);
            chunk_offset = detail::buffer_format::get_chunk_offset(
                m_buffer, m_current_chunk_index);
            m_offset = chunk_offset;
        }

        // Check if entry exceeds chunk target size
        // If so, we need to clear the chunk tokens of the overlapping chunks
        const std::size_t overlapping_chunks =
            (written_in_chunk + total_entry_size - 1) / m_chunk_target_size;
        // This should never happen as we just checked that the entry fits in
        // the buffer
        VERIFY(overlapping_chunks <= m_chunk_count - m_current_chunk_index,
               "Overlapping chunks exceed chunk count", overlapping_chunks,
               m_chunk_count - m_current_chunk_index);
        for (auto i = 1; i <= overlapping_chunks; i++)
        {
            auto chunk_index = m_current_chunk_index + i;
            if (!detail::buffer_format::is_chunk_committed(m_buffer,
                                                           chunk_index))
            {
                // Chunk is already uncommitted, nothing to do
                continue;
            }
            auto info = detail::buffer_format::chunk_row(m_buffer, chunk_index);
            detail::atomic::store_release(
                detail::buffer_format::chunk_token(info),
                static_cast<uint64_t>(0));
            detail::atomic::store_release(
                detail::buffer_format::chunk_offset(info),
                static_cast<uint64_t>(0));
        }

        auto header = detail::buffer_format::entry_header(
            m_buffer.subspan(m_offset, total_entry_size));
        VERIFY(!detail::buffer_format::is_committed(total_entry_size));
        // Write the total entry size without the commit flag
        detail::atomic::store_release(header, total_entry_size);

        // Write entry payload
        std::copy(
            entry.begin(), entry.end(),
            m_buffer
                .subspan(m_offset + detail::buffer_format::entry_header_size,
                         entry.size())
                .begin());

        // Update state
        m_total_entries_written++;
        m_offset += total_entry_size;
        m_offset = detail::buffer_format::align_up(
            m_offset, detail::buffer_format::entry_alignment);

        // Zero out the next entry header if there is space
        if (m_offset + detail::buffer_format::entry_header_size <=
            m_buffer.size())
        {
            auto next_header_span = m_buffer.subspan(
                m_offset, detail::buffer_format::entry_header_size);
            std::memset(next_header_span.data(), 0,
                        detail::buffer_format::entry_header_size);
        }

        // Commit the entry
        detail::atomic::store_release(
            header, detail::buffer_format::set_commit(total_entry_size));

        // check if the current chunk is committed
        if (!detail::buffer_format::is_chunk_committed(m_buffer,
                                                       m_current_chunk_index))
        {
            // Commit the chunk since we now have entries in the chunk
            commit_chunk(m_buffer, m_current_chunk_index);
        }
    }

    /// Signal that the writer has finished; no more data will be written.
    ///
    /// Writes a special entry (length 3) that tells readers the log is
    /// complete. Readers will return writer_finished and unlink shared memory
    /// upon receiving this signal.
    void finish()
    {
        VERIFY(!m_buffer.empty(), "Writer not configured");
        VERIFY(m_offset != 0, "Writer not properly configured - offset is 0");
        VERIFY(!m_finished, "Writer has already finished");

        // Align offset to 4-byte boundary for entry header
        m_offset = detail::buffer_format::align_up(
            m_offset, detail::buffer_format::entry_alignment);

        // Check if we have space for the finish entry (header only)
        const std::size_t remaining_space =
            (m_offset > m_buffer.size()) ? 0 : m_buffer.size() - m_offset;

        // Check if we have enough space for the finish entry
        if (remaining_space < detail::buffer_format::entry_header_size)
        {
            // We do not have enough space. Let's wrap
            m_current_chunk_index = 0;
            m_offset = detail::buffer_format::compute_buffer_header_size(
                m_chunk_count);
            // Verify that the offset is aligned to the entry alignment
            VERIFY(m_offset % detail::buffer_format::entry_alignment == 0,
                   "Offset is not aligned to entry alignment", m_offset,
                   detail::buffer_format::entry_alignment);
            initialize_chunk(detail::buffer_format::chunk_row(
                                 m_buffer, m_current_chunk_index),
                             m_offset, m_total_entries_written);
        }

        auto header = detail::buffer_format::entry_header(m_buffer.subspan(
            m_offset, detail::buffer_format::entry_header_size));

        constexpr uint32_t finish_entry_length = 3;
        detail::atomic::store_release(
            header, detail::buffer_format::set_commit(finish_entry_length));

        m_offset += detail::buffer_format::entry_header_size;

        if (!detail::buffer_format::is_chunk_committed(m_buffer,
                                                       m_current_chunk_index))
        {
            commit_chunk(m_buffer, m_current_chunk_index);
        }

        m_finished = true;
    }

    /// Get the maximum entry size that can be written.
    /// @return The maximum entry size in bytes
    auto max_entry_size() const -> std::size_t
    {
        VERIFY(!m_buffer.empty(), "Writer not configured");
        auto header_and_chunk_table = detail::buffer_format::align_up(
            detail::buffer_format::compute_buffer_header_size(m_chunk_count),
            detail::buffer_format::entry_alignment);
        auto usable_size = m_buffer.size() - header_and_chunk_table;
        return usable_size - detail::buffer_format::entry_header_size;
    }

    /// Get the chunk size.
    /// @return The chunk size in bytes
    auto chunk_target_size() const -> std::size_t
    {
        return m_chunk_target_size;
    }

    /// Get the chunk count.
    /// @return The number of chunks
    auto chunk_count() const -> std::size_t
    {
        return m_chunk_count;
    }

    auto total_entries_written() const -> std::size_t
    {
        return m_total_entries_written;
    }

    /// Get the buffer ID configured at setup.
    /// @return The 64-bit buffer ID
    auto buffer_id() const -> uint64_t
    {
        return m_buffer_id;
    }

private:
    /// Try to resume writing in an existing buffer where the previous writer
    /// left off. Validates that the buffer configuration matches, then finds
    /// the resume position.
    /// @param buffer The buffer to check
    /// @param chunk_target_size The target size of each chunk
    /// @param chunk_count The number of chunks
    /// @param buffer_id The buffer ID
    /// @return resume_info on success, or a configure_error indicating what
    ///         failed (includes the existing buffer_id for error context):
    ///         - resume_chunk_count_mismatch: Chunk count doesn't match
    ///         - resume_buffer_size_mismatch: Buffer size doesn't match
    ///         - resume_buffer_id_mismatch: Buffer ID doesn't match
    ///         - resume_buffer_overflow: Buffer overflow while scanning
    ///         - resume_unexpected_wrap: Unexpected wrap entry found
    ///         - resume_writer_finished: Previous writer finished
    static auto try_resume(std::span<const uint8_t> buffer,
                           std::size_t chunk_target_size,
                           std::size_t chunk_count,
                           uint64_t buffer_id)
        -> tl::expected<resume_info, configure_error>
    {
        VERIFY(detail::buffer_format::is_initialized(buffer),
               "Buffer is not initialized");

        // Read the existing buffer ID for error context
        const uint64_t existing_buffer_id =
            detail::atomic::load_acquire(reinterpret_cast<const uint64_t*>(
                buffer.data() + detail::buffer_format::buffer_id_offset));

        // Read and verify chunk count
        const uint32_t existing_chunk_count =
            detail::buffer_format::read_value<uint32_t>(buffer.data() + 12);
        if (existing_chunk_count != chunk_count)
        {
            return tl::make_unexpected(configure_error{
                make_error_code(ouroboros::error::resume_chunk_count_mismatch),
                existing_buffer_id});
        }

        // Verify buffer size matches expected size
        const auto chunk_table_size =
            (chunk_count * detail::buffer_format::chunk_row_size);
        const auto chunks_size = chunk_count * chunk_target_size;
        const auto expected_buffer_size =
            detail::buffer_format::buffer_header_size + chunk_table_size +
            chunks_size;
        if (buffer.size() < expected_buffer_size)
        {
            return tl::make_unexpected(configure_error{
                make_error_code(ouroboros::error::resume_buffer_size_mismatch),
                existing_buffer_id});
        }

        // Verify buffer ID
        if (existing_buffer_id != buffer_id)
        {
            return tl::make_unexpected(configure_error{
                make_error_code(ouroboros::error::resume_buffer_id_mismatch),
                existing_buffer_id});
        }

        // Find the chunk with the highest token
        std::size_t highest_token = 0;
        std::size_t highest_token_chunk_index = 0;
        for (std::size_t i = 0; i < chunk_count; i++)
        {
            if (!detail::buffer_format::is_chunk_committed(buffer, i))
            {
                continue;
            }
            auto token =
                detail::atomic::load_acquire(detail::buffer_format::chunk_token(
                    detail::buffer_format::chunk_row(buffer, i)));
            if (token > highest_token)
            {
                highest_token = token;
                highest_token_chunk_index = i;
            }
        }
        VERIFY(detail::buffer_format::is_chunk_committed(
                   buffer, highest_token_chunk_index),
               "Highest token chunk is not committed",
               highest_token_chunk_index);

        auto offset = detail::buffer_format::get_chunk_offset(
            buffer, highest_token_chunk_index);
        while (true)
        {
            if (offset >=
                buffer.size() - detail::buffer_format::entry_header_size)
            {
                // Buffer overflow
                return tl::make_unexpected(configure_error{
                    make_error_code(ouroboros::error::resume_buffer_overflow),
                    existing_buffer_id});
            }

            auto length_with_flag = detail::atomic::load_acquire(
                detail::buffer_format::entry_header(buffer.subspan(
                    offset, detail::buffer_format::entry_header_size)));
            if (detail::buffer_format::is_committed(length_with_flag))
            {
                auto length =
                    detail::buffer_format::clear_commit(length_with_flag);
                if (length == 0)
                {
                    // Entry is not written yet, we have found the resume
                    // position
                    break;
                }
                else if (length == 1)
                {
                    // Entry is a wrap - this is unexpected.
                    // The previous writer should have updated the chunk table
                    // such that the first chunk would have the highest token.
                    return tl::make_unexpected(configure_error{
                        make_error_code(
                            ouroboros::error::resume_unexpected_wrap),
                        existing_buffer_id});
                }
                else if (length == 3)
                {
                    return tl::make_unexpected(configure_error{
                        make_error_code(
                            ouroboros::error::resume_writer_finished),
                        existing_buffer_id});
                }
                else
                {
                    // Entry is committed, we need to find the next entry that
                    // is not committed
                    offset += length;
                    offset = detail::buffer_format::align_up(
                        offset, detail::buffer_format::entry_alignment);
                    // Increment the highest token since we have read an entry
                    highest_token += 1;
                }
            }
            else
            {
                // Entry is not committed, we have found the resume position
                break;
            }
        }
        return resume_info{offset, highest_token_chunk_index, highest_token};
    }

    static void initialize_chunk(std::span<uint8_t> info, uint64_t offset,
                                 uint64_t token)
    {
        VERIFY(offset % detail::buffer_format::entry_alignment == 0,
               "Chunk offset is not aligned to entry alignment", offset,
               detail::buffer_format::entry_alignment);

        // Store token first
        detail::atomic::store_release(detail::buffer_format::chunk_token(info),
                                      token);

        // Store offset with MSB cleared (uncommitted)
        VERIFY(!detail::buffer_format::is_committed(offset),
               "Chunk offset commit flag must be cleared on init", offset);
        detail::atomic::store_release(detail::buffer_format::chunk_offset(info),
                                      offset);
    }

    inline static void commit_chunk(std::span<uint8_t> buffer,
                                    std::size_t chunk_index)
    {
        auto offset = detail::buffer_format::chunk_offset(
            detail::buffer_format::chunk_row(buffer, chunk_index));
        VERIFY(!detail::buffer_format::is_committed(*offset),
               "Chunk already committed");

        detail::atomic::store_release(
            offset, detail::buffer_format::set_commit(*offset));
    }

    void write_header(std::span<uint8_t> buffer, uint32_t chunk_count,
                      uint64_t buffer_id)
    {
        VERIFY(buffer.size() >= detail::buffer_format::buffer_header_size,
               "Buffer size must be at least {}",
               detail::buffer_format::buffer_header_size);
        VERIFY(reinterpret_cast<uintptr_t>(buffer.data()) % alignof(uint64_t) ==
                   0,
               "Buffer must be 8-byte aligned");

        // Write header fields first (magic written last to ensure fully
        // initialized buffer)
        // Offset 8: Version (4 bytes)
        detail::buffer_format::write_value(buffer.subspan(8, 4),
                                           detail::buffer_format::version);

        // Offset 12: Chunk count (4 bytes)
        detail::buffer_format::write_value(buffer.subspan(12, 4), chunk_count);

        // Offset 16: Buffer ID (8 bytes) - written atomically for reader
        // restart detection
        detail::atomic::store_release(
            reinterpret_cast<uint64_t*>(
                buffer.data() + detail::buffer_format::buffer_id_offset),
            buffer_id);

        // Offset 0: Magic value (8 bytes) - written atomically with release
        // semantics
        detail::atomic::store_release(
            reinterpret_cast<uint64_t*>(buffer.data()),
            detail::buffer_format::magic);
    }

private:
    std::size_t m_chunk_target_size = 0;
    std::size_t m_chunk_count = 0;
    uint64_t m_buffer_id = 0;
    std::span<uint8_t> m_buffer;

    // Writer state
    std::size_t m_current_chunk_index = 0;
    uint64_t m_total_entries_written = 0;
    std::size_t m_offset = 0;
    bool m_finished = false;
};
}
}
