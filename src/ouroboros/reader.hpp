// Copyright (c) 2026 Steinwurf ApS
// SPDX-License-Identifier: MIT

#pragma once

#include <tl/expected.hpp>
#include <verify/verify.hpp>

#include <cassert>
#include <climits>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string_view>

#include "detail/atomic.hpp"
#include "detail/buffer_format.hpp"
#include "detail/span.hpp"
#include "error_code.hpp"
#include "version.hpp"

namespace ouroboros
{
inline namespace STEINWURF_OUROBOROS_VERSION
{
/// A log reader that safely reads from a circular buffer managed by a writer.
///
/// The reader uses chunk tokens as synchronization guards to detect when
/// entries have been overwritten during reading. See writer.hpp for the
/// complete buffer format documentation.
///
/// Reader safety protocol:
/// 1. Pick a chunk to start from (first chunk if token is 0, else chunk with
///    highest committed non-zero token)
/// 2. Read the chunk token before reading an entry
/// 3. Read and validate the entry (including commit flag)
/// 4. Read the chunk token again
/// 5. If tokens match and entry is committed, the entry is valid
/// 6. If tokens differ, the entry was overwritten and must be discarded
class reader
{
public:
    enum class read_strategy
    {
        auto_detect,
        from_latest,
        from_lowest
    };

    struct chunk_info
    {
        constexpr chunk_info() noexcept :
            m_token(0), m_offset(0), m_is_committed(false), m_index(0)
        {
        }

        constexpr chunk_info(std::size_t index, uint64_t token,
                             uint64_t offset_and_commit_flag) noexcept :
            m_token(token), m_is_committed(detail::buffer_format::is_committed(
                                offset_and_commit_flag)),
            m_offset(detail::buffer_format::is_committed(offset_and_commit_flag)
                         ? detail::buffer_format::clear_commit(
                               offset_and_commit_flag)
                         : 0),
            m_index(index)
        {
        }

        constexpr chunk_info& operator=(const chunk_info& other)
        {
            m_token = other.m_token;
            m_offset = other.m_offset;
            m_is_committed = other.m_is_committed;
            m_index = other.m_index;
            return *this;
        }

        constexpr bool is_committed() const
        {
            return m_is_committed;
        }

        constexpr uint64_t offset() const
        {
            VERIFY(is_committed(), "Chunk is uncommitted");
            return m_offset;
        }

        constexpr uint64_t token() const
        {
            VERIFY(is_committed(), "Chunk is uncommitted");
            return m_token;
        }

        constexpr std::size_t index() const
        {
            return m_index;
        }

    private:
        uint64_t m_token;
        uint64_t m_offset;
        std::size_t m_index;
        bool m_is_committed;
    };

    struct entry
    {
        entry(std::string_view data, std::span<const uint8_t> chunk_row,
              uint64_t chunk_token, uint64_t sequence_number) :
            data(data), chunk_row(chunk_row), chunk_token(chunk_token),
            sequence_number(sequence_number)
        {
        }

        const std::string_view data;
        const std::span<const uint8_t> chunk_row;
        const uint64_t chunk_token;
        const uint64_t sequence_number;

        bool is_valid() const
        {
            const uint64_t current_token = detail::atomic::load_acquire(
                detail::buffer_format::chunk_token(chunk_row));
            return chunk_token == current_token;
        }
    };

    reader() = default;

    static auto is_ready(std::span<const uint8_t> buffer) -> bool
    {
        VERIFY(buffer.size() >= detail::buffer_format::buffer_header_size);
        if (buffer.size() < 8)
        {
            return false;
        }

        // Load magic value atomically with acquire semantics
        // This ensures all previous writes (version, chunk_count) are visible
        const uint64_t magic_value = detail::atomic::load_acquire(
            reinterpret_cast<const uint64_t*>(buffer.data()));

        return magic_value == detail::buffer_format::magic;
    }

    auto configure(std::span<const uint8_t> buffer,
                   read_strategy strategy = read_strategy::auto_detect)
        -> tl::expected<void, std::error_code>
    {
        VERIFY(buffer.size() >= detail::buffer_format::buffer_header_size,
               "Buffer too small for header");

        if (!is_ready(buffer))
        {
            return tl::make_unexpected(
                make_error_code(ouroboros::error::invalid_magic));
        }

        const uint32_t version =
            detail::buffer_format::read_value<uint32_t>(buffer.data() + 8);
        if (version != detail::buffer_format::version)
        {
            return tl::make_unexpected(
                make_error_code(ouroboros::error::unsupported_version));
        }
        const std::size_t chunk_count =
            detail::buffer_format::read_value<uint32_t>(buffer.data() + 12);
        const uint64_t buffer_id =
            detail::atomic::load_acquire(reinterpret_cast<const uint64_t*>(
                buffer.data() + detail::buffer_format::buffer_id_offset));

        if (chunk_count == 0)
        {
            return tl::make_unexpected(
                make_error_code(ouroboros::error::invalid_chunk_count));
        }

        // Validate buffer is at least large enough for header and chunk table
        const std::size_t min_buffer_size =
            detail::buffer_format::compute_buffer_header_size(chunk_count);
        if (buffer.size() < min_buffer_size)
        {
            return tl::make_unexpected(
                make_error_code(ouroboros::error::buffer_too_small));
        }

        const auto start = find_chunk(buffer, chunk_count, strategy);
        if (!start.is_committed())
        {
            return tl::make_unexpected(
                make_error_code(ouroboros::error::no_data_available));
        }

        m_buffer = buffer;
        m_chunk_count = chunk_count;
        m_buffer_id = buffer_id;
        m_total_entries_read = 0;
        m_writer_finished = false;
        // Reset current chunk state before setting new chunk
        // This ensures reconfigure works correctly even if the new chunk has
        // the same token as the previous configuration
        m_current_chunk = chunk_info{};
        set_current_chunk(start);

        return {};
    }

    auto read_next_entry() -> tl::expected<entry, std::error_code>
    {
        VERIFY(!m_buffer.empty(), "Reader not configured");
        VERIFY(m_offset != 0, "Reader not properly configured - offset is 0");
        VERIFY(m_offset % detail::buffer_format::entry_alignment == 0,
               "Offset not aligned", m_offset,
               detail::buffer_format::entry_alignment);

        if (m_writer_finished)
        {
            return tl::make_unexpected(
                make_error_code(ouroboros::error::writer_finished));
        }

        // Retry loop: wrap / stale chunk / uncommitted entry all resolve by
        // either jumping and retrying, or returning no_data().
        for (;;)
        {
            // Check if buffer was restarted (ID changed); reader must
            // reconfigure
            const uint64_t current_id =
                detail::atomic::load_acquire(reinterpret_cast<const uint64_t*>(
                    m_buffer.data() + detail::buffer_format::buffer_id_offset));
            if (current_id != m_buffer_id)
            {
                return tl::make_unexpected(
                    make_error_code(ouroboros::error::buffer_restarted));
            }

            VERIFY(m_offset % detail::buffer_format::entry_alignment == 0,
                   "Offset not aligned", m_offset,
                   detail::buffer_format::entry_alignment);
            // Implicit wrap: no room for header.
            if (m_offset + detail::buffer_format::entry_header_size >
                m_buffer.size())
            {
                // Jump to the first chunk.
                if (!jump_to_chunk(0))
                {
                    // Failed to jump to the first chunk. No more data
                    // available.
                    return tl::make_unexpected(
                        make_error_code(ouroboros::error::no_data_available));
                }
            }

            // Check if we advanced to the next chunk by reading into it.
            const std::size_t next_chunk_index = m_current_chunk.index() + 1;
            // First we check if that's even possible by checking the chunk
            // count.
            if (next_chunk_index < m_chunk_count)
            {
                // Then we check if the next chunk is committed and if the
                // offset is the same as the current offset.
                const auto next_chunk_info =
                    get_chunk_info(m_buffer, next_chunk_index);
                if (next_chunk_info.is_committed() &&
                    m_offset == next_chunk_info.offset())
                {
                    // Check that the next chunk is newer than the current.
                    if (next_chunk_info.token() <= m_current_chunk.token())
                    {
                        // It wasn't which means that the must wait for the next
                        // chunk to be (re)written.
                        return tl::make_unexpected(make_error_code(
                            ouroboros::error::no_data_available));
                    }
                    set_current_chunk(next_chunk_info);
                }
            }

            // Get the entry header.
            const uint32_t* entry_header =
                detail::buffer_format::entry_header(m_buffer.subspan(
                    m_offset, detail::buffer_format::entry_header_size));

            // Read the entry header.
            const uint32_t length_with_flag =
                detail::atomic::load_acquire(entry_header);

            // Get the chunk info.
            const chunk_info chunk_info =
                get_chunk_info(m_buffer, m_current_chunk.index());

            // Check if the buffered chunk info is valid.
            if (!chunk_info.is_committed() ||
                chunk_info.token() != m_current_chunk.token())
            {
                // The chunk has changed, the entry is invalid.
                // This means the reader was too slow and entries have been
                // overwritten. We need to jump to the latest chunk and start
                // reading from there.
                const auto latest = find_chunk(m_buffer, m_chunk_count,
                                               read_strategy::from_latest);
                if (!latest.is_committed())
                {
                    // No more data available.
                    return tl::make_unexpected(
                        make_error_code(ouroboros::error::no_data_available));
                }

                if (latest.token() <= m_current_chunk.token())
                {
                    // The latest chunk is not newer than the current chunk.
                    // This means that the must wait for the next chunk to be
                    // (re)written.
                    return tl::make_unexpected(
                        make_error_code(ouroboros::error::no_data_available));
                }

                // Move to the latest chunk.
                set_current_chunk(latest);
                continue;
            }

            // Check if the entry is committed.
            if (!detail::buffer_format::is_committed(length_with_flag))
            {
                // The entry is not committed. No data available.
                return tl::make_unexpected(
                    make_error_code(ouroboros::error::no_data_available));
            }

            // Clear the commit flag and get the length of the entry.
            const std::size_t length =
                detail::buffer_format::clear_commit(length_with_flag);

            // Check the entry length
            if (length == 0)
            {
                // The entry length is 0 which means this entry is not yet
                // written.
                return tl::make_unexpected(
                    make_error_code(ouroboros::error::no_data_available));
            }

            if (length == 1)
            {
                // The entry length is 1 which means the writer has wrapped the
                // buffer. We need to jump to the first chunk and retry the
                // read.
                if (!jump_to_chunk(0))
                {
                    // Failed to jump to the first chunk. No more data
                    // available.
                    return tl::make_unexpected(
                        make_error_code(ouroboros::error::no_data_available));
                }

                continue;
            }

            if (length == 3)
            {
                // The entry length is 3 which means the writer has finished.
                // Advance past the entry header and mark as finished.
                m_offset += detail::buffer_format::entry_header_size;
                m_offset = detail::buffer_format::align_up(
                    m_offset, detail::buffer_format::entry_alignment);
                m_writer_finished = true;
                return tl::make_unexpected(
                    make_error_code(ouroboros::error::writer_finished));
            }

            // Check if the entry length is valid.
            // We already check the 0 and 1 cases above. So we can assume that
            // the length is greater than the header size.
            VERIFY(length >= detail::buffer_format::entry_header_size,
                   "Entry length smaller than header size", length,
                   detail::buffer_format::entry_header_size);
            // Check that the entry fits in the buffer.
            VERIFY(m_offset + length <= m_buffer.size(),
                   "Entry exceeds buffer bounds", m_offset, length,
                   m_buffer.size());

            // Extract payload
            const std::size_t payload_size =
                length - detail::buffer_format::entry_header_size;
            const char* payload_data = reinterpret_cast<const char*>(
                m_buffer.data() + m_offset +
                detail::buffer_format::entry_header_size);
            std::string_view payload_view(payload_data, payload_size);

            // Advance
            m_offset += length;
            m_offset = detail::buffer_format::align_up(
                m_offset, detail::buffer_format::entry_alignment);
            m_total_entries_read += 1;
            m_entries_read_in_current_chunk += 1;

            // Calculate sequence number: chunk_token is the number of entries
            // written before this chunk, so we add the entries read in this
            // chunk
            const uint64_t sequence_number =
                m_current_chunk.token() + m_entries_read_in_current_chunk;
            return entry(payload_view,
                         detail::buffer_format::chunk_row(
                             m_buffer, m_current_chunk.index()),
                         m_current_chunk.token(), sequence_number);
        }
    }

    auto read_next() -> tl::expected<std::string, std::error_code>
    {
        auto e = read_next_entry();
        if (!e)
        {
            return tl::make_unexpected(e.error());
        }

        std::string result(e->data);
        if (!e->is_valid())
        {
            return tl::make_unexpected(
                make_error_code(ouroboros::error::entry_not_valid));
        }
        return result;
    }

    auto chunk_count() const -> std::size_t
    {
        return m_chunk_count;
    }

    /// Get the buffer ID from the header.
    /// @return The 64-bit buffer ID configured by the writer
    auto buffer_id() const -> uint64_t
    {
        return m_buffer_id;
    }

    auto total_entries_read() const -> std::size_t
    {
        return m_total_entries_read;
    }

private:
    auto jump_to_chunk(std::size_t chunk_index) -> bool
    {
        const auto info = get_chunk_info(m_buffer, chunk_index);
        if (!info.is_committed() || info.token() <= m_current_chunk.token())
        {
            return false;
        }
        set_current_chunk(info);
        return true;
    }

    void set_current_chunk(const chunk_info& info)
    {
        VERIFY(info.is_committed(), "Chunk is not committed", info);
        // Check that if the current chunk is committed, the current chunk token
        // should be less that the new chunk token.
        if (m_current_chunk.is_committed())
        {
            VERIFY(m_current_chunk.token() < info.token(),
                   "Current chunk token is greater than new chunk token",
                   m_current_chunk.token(), info.token());
        }
        m_current_chunk = info;
        m_offset = m_current_chunk.offset();
        VERIFY(m_offset % detail::buffer_format::entry_alignment == 0,
               "Chunk offset is not aligned to entry alignment", m_offset,
               detail::buffer_format::entry_alignment);
        VERIFY(m_offset <= m_buffer.size(),
               "Chunk offset is greater than buffer size", m_offset,
               m_buffer.size());
        m_entries_read_in_current_chunk = 0;
    }

    static auto get_chunk_info(std::span<const uint8_t> buffer,
                               std::size_t chunk_index) -> chunk_info
    {
        const auto row = detail::buffer_format::chunk_row(buffer, chunk_index);
        return chunk_info(chunk_index,
                          detail::atomic::load_acquire(
                              detail::buffer_format::chunk_token(row)),
                          detail::atomic::load_acquire(
                              detail::buffer_format::chunk_offset(row)));
    }

    static auto find_chunk(std::span<const uint8_t> buffer,
                           std::size_t chunk_count, read_strategy strategy)
        -> chunk_info
    {
        switch (strategy)
        {
        case read_strategy::auto_detect:
        {
            const auto info = get_chunk_info(buffer, 0);
            if (info.is_committed() && info.token() == 0)
            {
                return info;
            }
            // The first chunk is not committed or has already been overwritten.
            // Let's find the most current chunk.
            [[fallthrough]];
        }
        case read_strategy::from_latest:
            return find_chunk_with_highest_token(buffer, chunk_count);
        case read_strategy::from_lowest:
            return find_chunk_with_lowest_token(buffer, chunk_count);
        default:
            VERIFY(false, "Invalid read strategy", strategy);
        }
        return {};
    }

    static auto find_chunk_with_highest_token(std::span<const uint8_t> buffer,
                                              std::size_t chunk_count)
        -> chunk_info
    {
        chunk_info best_chunk = get_chunk_info(buffer, 0);
        for (std::size_t i = 1; i < chunk_count; ++i)
        {
            const auto info = get_chunk_info(buffer, i);
            if (!info.is_committed())
            {
                continue;
            }
            if (!best_chunk.is_committed())
            {
                best_chunk = info;
                continue;
            }

            if (info.token() > best_chunk.token())
            {
                best_chunk = info;
            }
        }
        return best_chunk;
    }

    static auto find_chunk_with_lowest_token(std::span<const uint8_t> buffer,
                                             std::size_t chunk_count)
        -> chunk_info
    {
        chunk_info best_chunk = get_chunk_info(buffer, 0);
        for (std::size_t i = 1; i < chunk_count; ++i)
        {
            const auto info = get_chunk_info(buffer, i);
            if (!info.is_committed())
            {
                continue;
            }
            if (!best_chunk.is_committed())
            {
                best_chunk = info;
                continue;
            }
            if (info.token() < best_chunk.token())
            {
                best_chunk = info;
            }
        }
        return best_chunk;
    }

private:
    std::size_t m_chunk_count = 0;
    uint64_t m_buffer_id = 0;
    std::span<const uint8_t> m_buffer;

    chunk_info m_current_chunk;
    bool m_writer_finished = false;
    std::size_t m_offset = 0;
    std::size_t m_total_entries_read = 0;
    std::size_t m_entries_read_in_current_chunk = 0;
};
}
}
