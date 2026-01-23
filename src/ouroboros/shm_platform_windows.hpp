// Copyright (c) 2023 Steinwurf ApS
// All Rights Reserved
//
// THIS IS UNPUBLISHED PROPRIETARY SOURCE CODE OF STEINWURF
// The copyright notice above does not evidence any
// actual or intended publication of such source code.

#pragma once

#if !defined(_WIN32)
#error "shm_platform_windows.hpp included on non-Windows platform"
#endif

#include <tl/expected.hpp>

#include <cstdint>
#include <string>

#include "error_code.hpp"

namespace ouroboros
{
inline namespace STEINWURF_OUROBOROS_VERSION
{

/// Platform-specific shared memory handle for Windows
struct shm_handle
{
    void* handle = nullptr;

    bool is_valid() const;
};

/// Create and map a shared memory segment for writing (Windows implementation)
///
/// @param name Name of the shared memory segment
/// @param size Size of the shared memory segment in bytes
/// @return A tuple of (handle, mapped pointer) or an error
auto create_and_map_shm(const std::string& name, std::size_t size)
    -> tl::expected<std::pair<shm_handle, void*>, std::error_code>;

/// Open and map an existing shared memory segment for reading (Windows
/// implementation)
///
/// @param name Name of the shared memory segment
/// @return A tuple of (handle, mapped pointer, size) or an error
auto open_and_map_shm(const std::string& name)
    -> tl::expected<std::tuple<shm_handle, void*, std::size_t>, std::error_code>;

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

}
}
