// Copyright (c) 2026 Steinwurf ApS
// SPDX-License-Identifier: MIT

#pragma once

#if !defined(_WIN32)
#error "shm_platform_windows.hpp included on non-Windows platform"
#endif

#include <tl/expected.hpp>

#include <cstdint>
#include <string>

#include "../error_code.hpp"

namespace ouroboros
{
inline namespace STEINWURF_OUROBOROS_VERSION
{
namespace detail
{

/// Platform-specific shared memory handle for Windows
struct shm_handle
{
    void* handle = nullptr;

    bool is_valid() const;
};

/// Result of a create-or-open shared memory operation
struct shm_mapping
{
    shm_handle handle;
    void* ptr = nullptr;
    std::size_t size = 0;
    bool created = false; ///< true if newly created, false if opened existing
};

/// Create or open and map a shared memory segment for writing (Windows
/// implementation)
///
/// Tries to exclusively create the segment first. If it already exists,
/// opens the existing segment with read-write access instead.
///
/// @param name Name of the shared memory segment
/// @param size Size of the shared memory segment in bytes (used when creating)
/// @return An shm_mapping or an error
auto create_or_open_and_map_shm(const std::string& name, std::size_t size)
    -> tl::expected<shm_mapping, std::error_code>;

/// Open and map an existing shared memory segment for reading (Windows
/// implementation)
///
/// @param name Name of the shared memory segment
/// @return A tuple of (handle, mapped pointer, size) or an error
auto open_and_map_shm(const std::string& name)
    -> tl::expected<std::tuple<shm_handle, void*, std::size_t>,
                    std::error_code>;

/// Unmap shared memory (Windows implementation)
///
/// @param handle The shared memory handle
/// @param ptr The mapped pointer
/// @param size The size of the mapped region
void unmap_shm(const shm_handle& handle, void* ptr, std::size_t size);

/// Unlink (remove) a shared memory segment (Windows implementation)
///
/// @param name Name of the shared memory segment
/// Note: Windows doesn't have unlink, but we can close the handle
/// This is a no-op here as unlinking is handled by closing the handle
void unlink_shm(const std::string& name);

} // namespace detail
}
}
