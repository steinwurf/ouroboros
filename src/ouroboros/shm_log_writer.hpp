// Copyright (c) 2026 Steinwurf ApS
// SPDX-License-Identifier: MIT

#pragma once

#include <tl/expected.hpp>
#include <verify/verify.hpp>

#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>

#include "ouroboros/detail/buffer_format.hpp"
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
    /// If the shared memory segment already exists, the writer will attempt
    /// to resume from the previous writer and continue appending entries
    /// where it left off. If the resume fails (e.g. due to a buffer ID
    /// mismatch), the returned configure_error will contain the existing
    /// buffer_id from the shared memory segment.
    ///
    /// @param shm_name Name of the shared memory segment (must start with '/'
    ///                 on POSIX systems)
    /// @param chunk_target_size Target size of each chunk in bytes
    /// @param chunk_count Number of chunks (must be > 0)
    /// @param buffer_id 64-bit ID stored in the buffer header (default: 0)
    /// @param force_init If true, forces reinitialization of an existing
    ///                   shared memory segment (default: false)
    /// @param should_unlink If true, unlink the shared memory segment on
    ///                      destruction (default: true)
    /// @return Error if configuration fails
    auto configure(const std::string& shm_name, std::size_t chunk_target_size,
                   std::size_t chunk_count, uint64_t buffer_id = 0,
                   bool force_init = false, bool should_unlink = true)
        -> tl::expected<void, configure_error>
    {
        VERIFY(chunk_count > 0, "chunk_count must be greater than 0");
        VERIFY(!shm_name.empty(), "shm_name must not be empty");

        // Calculate required buffer size
        const std::size_t required_size =
            detail::buffer_format::compute_buffer_size(chunk_target_size,
                                                       chunk_count);

        // Create or open the shared memory segment
        auto shm_result = create_or_open_and_map_shm(shm_name, required_size);
        if (!shm_result)
        {
            return tl::make_unexpected(configure_error{shm_result.error()});
        }

        // Only zero-initialize if we created a new segment
        if (shm_result->created)
        {
            // Zero out the buffer header and chunk table
            std::memset(
                shm_result->ptr, 0,
                detail::buffer_format::compute_buffer_header_size(chunk_count));
        }

        // Configure the writer with the mapped buffer.
        // If the segment already existed, the writer will try to resume.
        auto writer_result = m_writer.configure(
            std::span<uint8_t>(static_cast<uint8_t*>(shm_result->ptr),
                               shm_result->size),
            chunk_target_size, chunk_count, buffer_id, force_init);

        if (!writer_result)
        {
            // Just unmap, never unlink — we don't own the segment yet
            unmap_shm(shm_result->handle, shm_result->ptr, shm_result->size);
            return tl::make_unexpected(writer_result.error());
        }

        // Success — commit state
        m_shm_name = shm_name;
        m_shm_handle = shm_result->handle;
        m_buffer_ptr = shm_result->ptr;
        m_buffer_size = shm_result->size;
        m_should_unlink = should_unlink;

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

    /// Get the buffer ID from the header
    /// @return The 64-bit buffer ID
    auto buffer_id() const -> uint64_t
    {
        return m_writer.buffer_id();
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
