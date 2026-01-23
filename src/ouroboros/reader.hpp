// Copyright (c) 2023 Steinwurf ApS
// All Rights Reserved
//
// THIS IS UNPUBLISHED PROPRIETARY SOURCE CODE OF STEINWURF
// The copyright notice above does not evidence any
// actual or intended publication of such source code.

#pragma once

#include <tl/expected.hpp>
#include <verify/verify.hpp>

#include <cassert>
#include <cstdint>
#include <cstring>
#include <string_view>
#include <vector>
#include <optional>

#include "error_code.hpp"
#include "version.hpp"
#include "buffer_format.hpp"
#include "portable_atomic.hpp"
#include "span.hpp"

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
        from_latest
    };

    struct entry
    {
        entry(std::string_view data, std::span<const uint8_t> chunk_row,
              uint64_t chunk_token, uint64_t sequence_number) :
            data(data), chunk_row(chunk_row), chunk_token(chunk_token),
            sequence_number(sequence_number)
        {
        }

        std::string_view data;
        std::span<const uint8_t> chunk_row;
        uint64_t chunk_token;
        uint64_t sequence_number;

        bool is_valid() const
        {
            const uint64_t current_token = portable_atomic::load_acquire(
                buffer_format::chunk_token(chunk_row));
            return chunk_token == current_token;
        }
    };

    reader() = default;

    static auto is_ready(std::span<const uint8_t> buffer) -> bool
    {
        VERIFY(buffer.size() >= buffer_format::buffer_header_size);
        if (buffer.size() < 8)
        {
            return false;
        }

        // Load magic value atomically with acquire semantics
        // This ensures all previous writes (version, chunk_count) are visible
        const uint64_t magic_value = portable_atomic::load_acquire(
            reinterpret_cast<const uint64_t*>(buffer.data()));

        return magic_value == buffer_format::magic;
    }

    auto configure(std::span<const uint8_t> buffer,
                   read_strategy strategy = read_strategy::auto_detect)
        -> tl::expected<void, std::error_code>
    {
        VERIFY(buffer.size() >= buffer_format::buffer_header_size,
               "Buffer too small for header");

        if (!is_ready(buffer))
        {
            return tl::make_unexpected(make_error_code(
                ouroboros::error::invalid_magic));
        }

        const uint32_t version = read_value<uint32_t>(buffer.data() + 8);
        if (version != buffer_format::version)
        {
            return tl::make_unexpected(
                make_error_code(ouroboros::error::unsupported_version));
        }
        const std::size_t chunk_count =
            read_value<uint32_t>(buffer.data() + 12);

        if (chunk_count == 0)
        {
            return tl::make_unexpected(
                make_error_code(ouroboros::error::invalid_chunk_count));
        }

        // Validate buffer is at least large enough for header and chunk table
        const std::size_t min_buffer_size =
            buffer_format::compute_buffer_header_size(chunk_count);
        if (buffer.size() < min_buffer_size)
        {
            return tl::make_unexpected(make_error_code(
                ouroboros::error::buffer_too_small));
        }

        const auto start = find_starting_chunk(buffer, chunk_count, strategy);
        if (!start)
        {
            return tl::make_unexpected(
                make_error_code(ouroboros::error::no_data_available));
        }

        m_buffer = buffer;
        m_chunk_count = chunk_count;

        if (!jump_to_chunk(start.value()))
        {
            return tl::make_unexpected(
                make_error_code(ouroboros::error::no_data_available));
        }

        return {};
    }

    auto read_next_entry() -> tl::expected<entry, std::error_code>
    {
        VERIFY(!m_buffer.empty(), "Reader not configured");
        VERIFY(m_offset != 0, "Reader not properly configured - offset is 0");
        VERIFY(m_offset % buffer_format::entry_alignment == 0,
               "Offset not aligned", m_offset, buffer_format::entry_alignment);
        // Retry loop: wrap / stale chunk / uncommitted entry all resolve by
        // either jumping and retrying, or returning no_data().
        for (;;)
        {
            VERIFY(m_offset % buffer_format::entry_alignment == 0,
                   "Offset not aligned", m_offset,
                   buffer_format::entry_alignment);
            // Implicit wrap: no room for header.
            if (m_offset + buffer_format::entry_header_size > m_buffer.size())
            {
                // Jump to the first chunk.
                if (!jump_to_chunk(0))
                {
                    // Failed to jump to the first chunk. No more data
                    // available.
                    return tl::make_unexpected(
                        make_error_code(ouroboros::error::no_data_available));
                }

                continue;
            }

            // We have room for the entry header, read it.
            const uint32_t* entry_header = buffer_format::entry_header(
                m_buffer.subspan(m_offset, buffer_format::entry_header_size));

            const uint32_t length_with_flag =
                portable_atomic::load_acquire(entry_header);

            // Check if the read was valid by checking the chunk token.
            if (!is_chunk_committed(m_buffer, m_current_chunk_index) ||
                m_current_chunk_token !=
                    get_chunk_token(m_buffer, m_current_chunk_index))
            {
                // If the chunk is not committed or the token is not the same,
                // we need to jump to the latest chunk and retry.
                auto latest = find_starting_chunk(m_buffer, m_chunk_count,
                                                  read_strategy::from_latest);
                if (!latest)
                {
                    // No more data available.
                    return tl::make_unexpected(
                        make_error_code(ouroboros::error::no_data_available));
                }

                // Jump to the latest chunk
                if (!jump_to_chunk(latest.value()))
                {
                    // Failed to jump to the latest chunk. No more data
                    // available.
                    return tl::make_unexpected(
                        make_error_code(ouroboros::error::no_data_available));
                }

                continue;
            }

            // Check if the entry is committed.
            if (!buffer_format::is_committed(length_with_flag))
            {
                // The entry is not committed. No data available.
                return tl::make_unexpected(
                    make_error_code(ouroboros::error::no_data_available));
            }

            // Clear the commit flag and get the length of the entry.
            const std::size_t length =
                buffer_format::clear_commit(length_with_flag);

            // Check if the entry length is valid.
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
                    // The first chunk is not yet available. No more data
                    // available.
                    return tl::make_unexpected(
                        make_error_code(ouroboros::error::no_data_available));
                }

                continue;
            }

            // Check if the entry length is valid.
            // We already check the 0 and 1 cases above. So we can assume that
            // the length is greater than the header size.
            VERIFY(length >= buffer_format::entry_header_size,
                   "Entry length smaller than header size", length,
                   buffer_format::entry_header_size);
            // Check that the entry fits in the buffer.
            VERIFY(m_offset + length <= m_buffer.size(),
                   "Entry exceeds buffer bounds", m_offset, length,
                   m_buffer.size());

            // Check if we advanced to the next chunk by reading into it.
            const std::size_t next_chunk_index = m_current_chunk_index + 1;
            if (next_chunk_index < m_chunk_count &&
                m_offset == get_chunk_offset(m_buffer, next_chunk_index))
            {
                VERIFY(is_chunk_committed(m_buffer, next_chunk_index),
                       "Next chunk is not committed", next_chunk_index);
                VERIFY(
                    get_chunk_token(m_buffer, next_chunk_index) >
                        m_current_chunk_token,
                    "Next chunk token is not greater than current chunk token",
                    get_chunk_token(m_buffer, next_chunk_index),
                    m_current_chunk_token);

                const auto offset_before_jump = m_offset;
                auto success = jump_to_chunk(next_chunk_index);

                VERIFY(success, "Failed to jump to next chunk");
                VERIFY(m_offset == offset_before_jump,
                       "Offset changed after jump", m_offset,
                       offset_before_jump);
            }

            // Extract payload
            const std::size_t payload_size =
                length - buffer_format::entry_header_size;
            const char* payload_data = reinterpret_cast<const char*>(
                m_buffer.data() + m_offset + buffer_format::entry_header_size);
            std::string_view payload_view(payload_data, payload_size);

            // Chunk row for validity checks
            const auto& info = chunk_row(m_buffer, m_current_chunk_index);

            // Advance
            m_offset += length;
            m_offset = buffer_format::align_up(m_offset,
                                               buffer_format::entry_alignment);
            m_total_entries_read += 1;
            m_entries_read_in_current_chunk += 1;

            // Calculate sequence number: chunk_token is the number of entries
            // written before this chunk, so we add the entries read in this
            // chunk
            const uint64_t sequence_number =
                m_current_chunk_token + m_entries_read_in_current_chunk;
            return entry(payload_view, info, m_current_chunk_token,
                         sequence_number);
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

    auto total_entries_read() const -> std::size_t
    {
        return m_total_entries_read;
    }

private:
    template <typename T>
    static T read_value(const uint8_t* buffer)
    {
        T value;
        std::memcpy(&value, buffer, sizeof(value));
        return value;
    }

    static auto chunk_row(std::span<const uint8_t> buffer,
                          std::size_t chunk_index) -> std::span<const uint8_t>
    {
        return buffer.subspan(buffer_format::chunk_row_offset(chunk_index),
                              buffer_format::chunk_row_size);
    }

    static auto get_chunk_offset(std::span<const uint8_t> buffer,
                                 std::size_t chunk_index) -> std::size_t
    {
        const auto& info = chunk_row(buffer, chunk_index);
        const uint64_t offset_value =
            portable_atomic::load_acquire(buffer_format::chunk_offset(info));
        if (!buffer_format::is_committed(offset_value))
        {
            return 0;
        }
        return buffer_format::clear_commit(offset_value);
    }

    static auto get_chunk_token(std::span<const uint8_t> buffer,
                                std::size_t chunk_index) -> uint64_t
    {
        const auto& info = chunk_row(buffer, chunk_index);
        return portable_atomic::load_acquire(buffer_format::chunk_token(info));
    }

    static auto is_chunk_committed(std::span<const uint8_t> buffer,
                                   std::size_t chunk_index) -> bool
    {
        const auto& info = chunk_row(buffer, chunk_index);
        const uint64_t offset_value =
            portable_atomic::load_acquire(buffer_format::chunk_offset(info));
        return buffer_format::is_committed(offset_value);
    }

    static auto
    find_starting_chunk(std::span<const uint8_t> buffer,
                        std::size_t chunk_count,
                        read_strategy strategy) -> std::optional<std::size_t>
    {
        switch (strategy)
        {
        case read_strategy::auto_detect:
            if (is_chunk_committed(buffer, 0) &&
                get_chunk_token(buffer, 0) == 0)
            {
                return 0;
            }
            [[fallthrough]];
        case read_strategy::from_latest:
            return find_chunk_with_highest_token(buffer, chunk_count);
        }
        return {};
    }

    static auto find_chunk_with_highest_token(std::span<const uint8_t> buffer,
                                              std::size_t chunk_count)
        -> std::optional<std::size_t>
    {
        std::optional<std::size_t> best_chunk = {};
        uint64_t best_token = 0;

        for (std::size_t i = 0; i < chunk_count; ++i)
        {
            if (!is_chunk_committed(buffer, i))
            {
                continue;
            }

            const uint64_t token = get_chunk_token(buffer, i);
            if (token > best_token)
            {
                best_token = token;
                best_chunk = i;
            }
        }

        return best_chunk;
    }

    // Extracted because it is used in 3+ places (configure + wrap cases).
    auto jump_to_chunk(std::size_t chunk_index) -> bool
    {
        const auto chunk_offset = get_chunk_offset(m_buffer, chunk_index);
        if (chunk_offset == 0)
        {
            return false;
        }

        VERIFY(chunk_offset % buffer_format::entry_alignment == 0,
               "Chunk offset is not aligned to entry alignment", chunk_offset,
               buffer_format::entry_alignment);
        const auto chunk_token = get_chunk_token(m_buffer, chunk_index);
        if (chunk_token < m_current_chunk_token)
        {
            // We cannot jump to an older chunk.
            return false;
        }

        m_current_chunk_token = chunk_token;
        m_current_chunk_index = chunk_index;
        m_offset = chunk_offset;
        m_entries_read_in_current_chunk = 0;
        return true;
    }

private:
    std::size_t m_chunk_count = 0;
    std::span<const uint8_t> m_buffer;

    std::size_t m_current_chunk_index = 0;
    uint64_t m_current_chunk_token = 0;
    std::size_t m_offset = 0;
    std::size_t m_total_entries_read = 0;
    std::size_t m_entries_read_in_current_chunk = 0;
};
}
}
