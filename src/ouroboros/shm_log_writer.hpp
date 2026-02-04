// Copyright (c) 2026 Steinwurf ApS
// SPDX-License-Identifier: MIT

#pragma once

#include <tl/expected.hpp>
#include <verify/verify.hpp>

#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>

#include "shm_platform.hpp"
#include "version.hpp"
#include "writer.hpp"

namespace ouroboros
{
inline namespace STEINWURF_OUROBOROS_VERSION
{
/// A shared memory log writer that wraps the writer with shared memory
/// management.
///
/// This class creates and manages a POSIX shared memory segment that can be
/// accessed by multiple processes. The writer creates the shared memory segment
/// and initializes the log buffer.
class shm_log_writer
{
public:
    shm_log_writer() = default;

    /// Destructor - unmaps and optionally unlinks the shared memory segment
    ~shm_log_writer()
    {
        cleanup();
    }

    /// Move constructor
    shm_log_writer(shm_log_writer&& other) noexcept :
        m_writer(std::move(other.m_writer)),
        m_shm_name(std::move(other.m_shm_name)),
        m_shm_handle(other.m_shm_handle), m_buffer_ptr(other.m_buffer_ptr),
        m_buffer_size(other.m_buffer_size),
        m_should_unlink(other.m_should_unlink)
    {
        other.m_shm_handle = shm_handle{};
        other.m_buffer_ptr = nullptr;
        other.m_buffer_size = 0;
        other.m_should_unlink = false;
    }

    /// Move assignment
    shm_log_writer& operator=(shm_log_writer&& other) noexcept
    {
        if (this != &other)
        {
            cleanup();
            m_writer = std::move(other.m_writer);
            m_shm_name = std::move(other.m_shm_name);
            m_shm_handle = other.m_shm_handle;
            m_buffer_ptr = other.m_buffer_ptr;
            m_buffer_size = other.m_buffer_size;
            m_should_unlink = other.m_should_unlink;

            other.m_shm_handle = shm_handle{};
            other.m_buffer_ptr = nullptr;
            other.m_buffer_size = 0;
            other.m_should_unlink = false;
        }
        return *this;
    }

    /// Delete copy constructor and assignment
    shm_log_writer(const shm_log_writer&) = delete;
    shm_log_writer& operator=(const shm_log_writer&) = delete;

    /// Configure the shared memory log writer
    ///
    /// @param shm_name Name of the shared memory segment (must start with '/'
    ///                 on POSIX systems)
    /// @param chunk_target_size Target size of each chunk in bytes
    /// @param chunk_count Number of chunks (must be > 0)
    /// @param should_unlink If true, unlink the shared memory segment on
    ///                      destruction (default: true)
    /// @return Error if configuration fails
    auto configure(const std::string& shm_name, std::size_t chunk_target_size,
                   std::size_t chunk_count, bool should_unlink = true)
        -> tl::expected<void, std::error_code>
    {
        VERIFY(chunk_count > 0, "chunk_count must be greater than 0");
        VERIFY(!shm_name.empty(), "shm_name must not be empty");

        // Calculate required buffer size
        const std::size_t required_size =
            detail::buffer_format::compute_buffer_size(chunk_target_size,
                                                       chunk_count);

        // Create and map shared memory
        auto result = create_and_map_shm(shm_name, required_size);
        if (!result)
        {
            return tl::make_unexpected(result.error());
        }

        m_shm_name = shm_name;
        m_shm_handle = result->first;
        m_buffer_ptr = result->second;
        m_buffer_size = required_size;
        m_should_unlink = should_unlink;

        // Initialize the buffer to zero
        std::memset(m_buffer_ptr, 0, m_buffer_size);

        // Configure the writer with the mapped buffer
        m_writer.configure(
            std::span<uint8_t>(static_cast<uint8_t*>(m_buffer_ptr),
                               m_buffer_size),
            chunk_target_size, chunk_count);

        return {};
    }

    /// Write an entry to the log
    /// @param entry The entry payload data to write
    void write(std::string_view entry)
    {
        m_writer.write(entry);
    }

    /// Signal that the writer has finished; no more data will be written.
    ///
    /// Writes a special entry that tells readers the log is complete. Readers
    /// will return writer_finished and unlink shared memory upon receiving
    /// this.
    void finish()
    {
        m_writer.finish();
    }

    /// Get the maximum entry size that can be written
    /// @return The maximum entry size in bytes
    auto max_entry_size() const -> std::size_t
    {
        return m_writer.max_entry_size();
    }

    /// Get the chunk target size
    /// @return The chunk target size in bytes
    auto chunk_target_size() const -> std::size_t
    {
        return m_writer.chunk_target_size();
    }

    /// Get the chunk count
    /// @return The number of chunks
    auto chunk_count() const -> std::size_t
    {
        return m_writer.chunk_count();
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

private:
    void cleanup()
    {
        if (m_buffer_ptr != nullptr)
        {
            unmap_shm(m_shm_handle, m_buffer_ptr, m_buffer_size);
            if (m_should_unlink && !m_shm_name.empty())
            {
                unlink_shm(m_shm_name);
            }
            m_buffer_ptr = nullptr;
            m_shm_handle = shm_handle{};
        }
    }

private:
    writer m_writer;
    std::string m_shm_name;
    shm_handle m_shm_handle;
    void* m_buffer_ptr = nullptr;
    std::size_t m_buffer_size = 0;
    bool m_should_unlink = true;
};
}
}
