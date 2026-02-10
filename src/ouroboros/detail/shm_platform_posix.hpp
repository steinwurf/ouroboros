// Copyright (c) 2026 Steinwurf ApS
// SPDX-License-Identifier: MIT

#pragma once

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <tl/expected.hpp>
#include <verify/verify.hpp>

#include <cstdint>
#include <string>

#include "../error_code.hpp"

namespace ouroboros
{
inline namespace STEINWURF_OUROBOROS_VERSION
{
namespace detail
{

/// Platform-specific shared memory handle for POSIX systems
struct shm_handle
{
    int fd = -1;

    bool is_valid() const
    {
        return fd != -1;
    }
};

/// Result of a create-or-open shared memory operation
struct shm_mapping
{
    shm_handle handle;
    void* ptr = nullptr;
    std::size_t size = 0;
    bool created = false; ///< true if newly created, false if opened existing
};

/// Create or open and map a shared memory segment for writing (POSIX
/// implementation)
///
/// Tries to exclusively create the segment first. If it already exists,
/// opens the existing segment with read-write access instead.
///
/// @param name Name of the shared memory segment
/// @param size Size of the shared memory segment in bytes (used when creating)
/// @return An shm_mapping or an error
inline auto
create_or_open_and_map_shm(const std::string& name, std::size_t size)
    -> tl::expected<shm_mapping, std::error_code>
{
    // Try to exclusively create the shared memory object
    int fd = shm_open(name.c_str(), O_CREAT | O_RDWR | O_EXCL, 0666);
    if (fd != -1)
    {
        // Successfully created a new segment
        if (ftruncate(fd, static_cast<off_t>(size)) == -1)
        {
            close(fd);
            shm_unlink(name.c_str());
            return tl::make_unexpected(make_error_code(
                ouroboros::error::shared_memory_truncate_failed));
        }

        void* ptr =
            mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (ptr == MAP_FAILED)
        {
            close(fd);
            shm_unlink(name.c_str());
            return tl::make_unexpected(
                make_error_code(ouroboros::error::shared_memory_map_failed));
        }

        VERIFY(reinterpret_cast<uintptr_t>(ptr) % 8 == 0,
               "Mapped shared memory is not 8-byte aligned");

        shm_handle handle;
        handle.fd = fd;
        return shm_mapping{handle, ptr, size, true};
    }

    // Creation failed
    if (errno != EEXIST)
    {
        return tl::make_unexpected(
            make_error_code(ouroboros::error::shared_memory_create_failed));
    }

    // Segment already exists - open it for read-write
    fd = shm_open(name.c_str(), O_RDWR, 0666);
    if (fd == -1)
    {
        if (errno == ENOENT)
        {
            return tl::make_unexpected(
                make_error_code(ouroboros::error::shared_memory_not_found));
        }
        return tl::make_unexpected(
            make_error_code(ouroboros::error::shared_memory_open_failed));
    }

    struct stat st;
    if (fstat(fd, &st) == -1)
    {
        close(fd);
        return tl::make_unexpected(
            make_error_code(ouroboros::error::shared_memory_stat_failed));
    }

    const std::size_t existing_size = static_cast<std::size_t>(st.st_size);

    void* ptr = mmap(nullptr, existing_size, PROT_READ | PROT_WRITE,
                     MAP_SHARED, fd, 0);
    if (ptr == MAP_FAILED)
    {
        close(fd);
        return tl::make_unexpected(
            make_error_code(ouroboros::error::shared_memory_map_failed));
    }

    VERIFY(reinterpret_cast<uintptr_t>(ptr) % 8 == 0,
           "Mapped shared memory is not 8-byte aligned");

    shm_handle handle;
    handle.fd = fd;
    return shm_mapping{handle, ptr, existing_size, false};
}

/// Open and map an existing shared memory segment for reading (POSIX
/// implementation)
///
/// @param name Name of the shared memory segment
/// @return A tuple of (handle, mapped pointer, size) or an error
inline auto open_and_map_shm(const std::string& name)
    -> tl::expected<std::tuple<shm_handle, void*, std::size_t>, std::error_code>
{
    // Open existing shared memory object
    int fd = shm_open(name.c_str(), O_RDONLY, 0);
    if (fd == -1)
    {
        if (errno == ENOENT)
        {
            return tl::make_unexpected(
                make_error_code(ouroboros::error::shared_memory_not_found));
        }
        return tl::make_unexpected(
            make_error_code(ouroboros::error::shared_memory_open_failed));
    }

    // Get the size of the shared memory object
    struct stat st;
    if (fstat(fd, &st) == -1)
    {
        close(fd);
        return tl::make_unexpected(
            make_error_code(ouroboros::error::shared_memory_stat_failed));
    }

    const std::size_t size = static_cast<std::size_t>(st.st_size);

    // Map the shared memory object
    void* ptr = mmap(nullptr, size, PROT_READ, MAP_SHARED, fd, 0);
    if (ptr == MAP_FAILED)
    {
        close(fd);
        return tl::make_unexpected(
            make_error_code(ouroboros::error::shared_memory_map_failed));
    }

    shm_handle handle;
    handle.fd = fd;
    return std::make_tuple(handle, ptr, size);
}

/// Unmap shared memory (POSIX implementation)
///
/// @param handle The shared memory handle
/// @param ptr The mapped pointer
/// @param size The size of the mapped region
inline void unmap_shm(const shm_handle& handle, void* ptr, std::size_t size)
{
    if (ptr == nullptr)
    {
        return;
    }

    munmap(ptr, size);
    if (handle.is_valid())
    {
        close(handle.fd);
    }
}

/// Unlink (remove) a shared memory segment (POSIX implementation)
///
/// @param name Name of the shared memory segment
inline void unlink_shm(const std::string& name)
{
    shm_unlink(name.c_str());
}

} // namespace detail
}
}
