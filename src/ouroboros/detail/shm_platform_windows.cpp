// Copyright (c) 2023 Steinwurf ApS
// All Rights Reserved
//
// THIS IS UNPUBLISHED PROPRIETARY SOURCE CODE OF STEINWURF
// The copyright notice above does not evidence any
// actual or intended publication of such source code.

#include <platform/config.hpp>

#ifdef PLATFORM_WINDOWS

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#ifndef NOMINMAX
#define NOMINMAX
#endif

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <windows.h>

#include <tl/expected.hpp>
#include <verify/verify.hpp>

#include <cstdint>
#include <string>

#include "../error_code.hpp"
#include "shm_platform_windows.hpp"

namespace ouroboros
{
inline namespace STEINWURF_OUROBOROS_VERSION
{
namespace detail
{

bool shm_handle::is_valid() const
{
    return handle != nullptr;
}

auto create_and_map_shm(const std::string& name, std::size_t size)
    -> tl::expected<std::pair<shm_handle, void*>, std::error_code>
{
    // Windows uses CreateFileMapping
    HANDLE hMap =
        CreateFileMappingA(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0,
                           static_cast<DWORD>(size), name.c_str());
    if (hMap == nullptr)
    {
        return tl::make_unexpected(
            make_error_code(ouroboros::error::shared_memory_create_failed));
    }

    if (GetLastError() == ERROR_ALREADY_EXISTS)
    {
        CloseHandle(hMap);
        return tl::make_unexpected(
            make_error_code(ouroboros::error::shared_memory_exists));
    }

    void* ptr = MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0, size);
    if (ptr == nullptr)
    {
        CloseHandle(hMap);
        return tl::make_unexpected(
            make_error_code(ouroboros::error::shared_memory_map_failed));
    }

    VERIFY(reinterpret_cast<uintptr_t>(ptr) % 8 == 0,
           "Mapped shared memory is not 8-byte aligned");

    shm_handle handle;
    handle.handle = reinterpret_cast<void*>(hMap);
    return std::make_pair(handle, ptr);
}

auto open_and_map_shm(const std::string& name)
    -> tl::expected<std::tuple<shm_handle, void*, std::size_t>, std::error_code>
{
    // Windows uses OpenFileMapping
    HANDLE hMap = OpenFileMappingA(FILE_MAP_READ, FALSE, name.c_str());
    if (hMap == nullptr)
    {
        if (GetLastError() == ERROR_FILE_NOT_FOUND)
        {
            return tl::make_unexpected(
                make_error_code(ouroboros::error::shared_memory_not_found));
        }
        return tl::make_unexpected(
            make_error_code(ouroboros::error::shared_memory_open_failed));
    }

    // Map the view first (size 0 maps the entire object)
    void* ptr = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (ptr == nullptr)
    {
        CloseHandle(hMap);
        return tl::make_unexpected(
            make_error_code(ouroboros::error::shared_memory_map_failed));
    }

    // Query the mapped memory to get the size
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(ptr, &mbi, sizeof(mbi)) == 0)
    {
        UnmapViewOfFile(ptr);
        CloseHandle(hMap);
        return tl::make_unexpected(
            make_error_code(ouroboros::error::shared_memory_stat_failed));
    }

    const std::size_t size = static_cast<std::size_t>(mbi.RegionSize);

    shm_handle handle;
    handle.handle = reinterpret_cast<void*>(hMap);
    return std::make_tuple(handle, ptr, size);
}

void unmap_shm(const shm_handle& handle, void* ptr, std::size_t size)
{
    (void)size; // Unused on Windows
    if (ptr == nullptr)
    {
        return;
    }

    UnmapViewOfFile(ptr);
    if (handle.is_valid())
    {
        HANDLE hMap = reinterpret_cast<HANDLE>(handle.handle);
        CloseHandle(hMap);
    }
}

void unlink_shm(const std::string& name)
{
    (void)name; // Unused on Windows
}

} // namespace detail
}
}

#endif // PLATFORM_WINDOWS

