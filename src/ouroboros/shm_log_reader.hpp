// Copyright (c) 2026 Steinwurf ApS
// SPDX-License-Identifier: MIT

#pragma once

#include <tl/expected.hpp>
#include <verify/verify.hpp>

#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>

#include "reader.hpp"
#include "shm_platform.hpp"
#include "version.hpp"

namespace ouroboros
{
inline namespace STEINWURF_OUROBOROS_VERSION
{

/// A shared memory log reader that wraps the reader with shared memory
/// management.
///
/// This class opens and maps an existing POSIX shared memory segment created
/// by shm_log_writer and provides access to read log entries from it.
class shm_log_reader
{
public:
    shm_log_reader() = default;

    /// Destructor - unmaps the shared memory segment
    ~shm_log_reader()
    {
        cleanup();
    }

    /// Move constructor
    shm_log_reader(shm_log_reader&& other) noexcept :
        m_reader(std::move(other.m_reader)),
        m_shm_name(std::move(other.m_shm_name)),
        m_shm_handle(other.m_shm_handle), m_buffer_ptr(other.m_buffer_ptr),
        m_buffer_size(other.m_buffer_size)
    {
        other.m_shm_handle = shm_handle{};
        other.m_buffer_ptr = nullptr;
        other.m_buffer_size = 0;
    }

    /// Move assignment
    shm_log_reader& operator=(shm_log_reader&& other) noexcept
    {
        if (this != &other)
        {
            cleanup();
            m_reader = std::move(other.m_reader);
            m_shm_name = std::move(other.m_shm_name);
            m_shm_handle = other.m_shm_handle;
            m_buffer_ptr = other.m_buffer_ptr;
            m_buffer_size = other.m_buffer_size;

            other.m_shm_handle = shm_handle{};
            other.m_buffer_ptr = nullptr;
            other.m_buffer_size = 0;
        }
        return *this;
    }

    /// Delete copy constructor and assignment
    shm_log_reader(const shm_log_reader&) = delete;
    shm_log_reader& operator=(const shm_log_reader&) = delete;

    /// Configure the shared memory log reader
    ///
    /// @param shm_name Name of the shared memory segment (must start with '/'
    ///                 on POSIX systems)
    /// @param strategy Read strategy (default: auto_detect)
    /// @return Error if configuration fails
    auto configure(
        const std::string& shm_name,
        reader::read_strategy strategy = reader::read_strategy::auto_detect)
        -> tl::expected<void, std::error_code>
    {
        VERIFY(!shm_name.empty(), "shm_name must not be empty");

        // Open and map shared memory
        auto result = open_and_map_shm(shm_name);
        if (!result)
        {
            return tl::make_unexpected(result.error());
        }

        m_shm_name = shm_name;
        m_shm_handle = std::get<0>(result.value());
        m_buffer_ptr = std::get<1>(result.value());
        m_buffer_size = std::get<2>(result.value());

        // Configure the reader with the mapped buffer
        auto reader_result = m_reader.configure(
            std::span<const uint8_t>(static_cast<const uint8_t*>(m_buffer_ptr),
                                     m_buffer_size),
            strategy);
        if (!reader_result)
        {
            cleanup();
            return reader_result;
        }

        return {};
    }

    /// Read the next entry from the log
    /// @return The entry or an error
    auto read_next_entry() -> tl::expected<reader::entry, std::error_code>
    {
        return m_reader.read_next_entry();
    }

    /// Read the next entry and return as string
    /// @return The entry data as string or an error
    auto read_next() -> tl::expected<std::string, std::error_code>
    {
        return m_reader.read_next();
    }

    /// Get the chunk count
    /// @return The number of chunks
    auto chunk_count() const -> std::size_t
    {
        return m_reader.chunk_count();
    }

    /// Get the total number of entries read
    /// @return The total number of entries read
    auto total_entries_read() const -> std::size_t
    {
        return m_reader.total_entries_read();
    }

    /// Get the shared memory name
    /// @return The shared memory segment name
    auto shm_name() const -> const std::string&
    {
        return m_shm_name;
    }

    /// Get the buffer size
    /// @return The size of the shared memory buffer in bytes
    auto buffer_size() const -> std::size_t
    {
        return m_buffer_size;
    }

    /// Check if the shared memory buffer is ready (magic bytes match)
    /// @return True if the buffer is ready
    auto is_ready() const -> bool
    {
        if (m_buffer_ptr == nullptr || m_buffer_size == 0)
        {
            return false;
        }
        return reader::is_ready(std::span<const uint8_t>(
            static_cast<const uint8_t*>(m_buffer_ptr), m_buffer_size));
    }

private:
    void cleanup()
    {
        if (m_buffer_ptr != nullptr)
        {
            unmap_shm(m_shm_handle, m_buffer_ptr, m_buffer_size);
            m_buffer_ptr = nullptr;
            m_shm_handle = shm_handle{};
        }
    }

private:
    reader m_reader;
    std::string m_shm_name;
    shm_handle m_shm_handle;
    void* m_buffer_ptr = nullptr;
    std::size_t m_buffer_size = 0;
};
}
}
