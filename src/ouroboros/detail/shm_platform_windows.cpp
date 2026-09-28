// Copyright (c) 2026 Steinwurf ApS
// SPDX-License-Identifier: MIT

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
#include <tuple>

#include "../error_code.hpp"
#include "shm_platform_windows.hpp"

namespace ouroboros
{
inline namespace STEINWURF_OUROBOROS_VERSION
{
namespace detail
{
namespace
{
auto file_size(HANDLE hFile) -> tl::expected<std::size_t, std::error_code>
{
    LARGE_INTEGER existing;
    if (!GetFileSizeEx(hFile, &existing))
    {
        return tl::make_unexpected(
            make_error_code(ouroboros::error::shared_memory_stat_failed));
    }
    return static_cast<std::size_t>(existing.QuadPart);
}

auto mapped_region_size(void* ptr) -> tl::expected<std::size_t, std::error_code>
{
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(ptr, &mbi, sizeof(mbi)) == 0)
    {
        return tl::make_unexpected(
            make_error_code(ouroboros::error::shared_memory_stat_failed));
    }
    return static_cast<std::size_t>(mbi.RegionSize);
}

auto open_existing_file(const std::string& path,
                        DWORD access) -> tl::expected<HANDLE, std::error_code>
{
    HANDLE hFile =
        CreateFileA(path.c_str(), access,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        if (GetLastError() == ERROR_FILE_NOT_FOUND)
        {
            return tl::make_unexpected(
                make_error_code(ouroboros::error::shared_memory_not_found));
        }
        return tl::make_unexpected(
            make_error_code(ouroboros::error::shared_memory_open_failed));
    }
    return hFile;
}

} // namespace

bool shm_handle::is_valid() const
{
    return handle != nullptr;
}

auto create_or_open_and_map_file(const std::string& path, std::size_t size)
    -> tl::expected<shm_mapping, std::error_code>
{
    HANDLE hFile =
        CreateFileA(path.c_str(), GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile != INVALID_HANDLE_VALUE)
    {
        LARGE_INTEGER truncate_size;
        truncate_size.QuadPart = static_cast<LONGLONG>(size);
        if (!SetFilePointerEx(hFile, truncate_size, nullptr, FILE_BEGIN) ||
            !SetEndOfFile(hFile))
        {
            CloseHandle(hFile);
            DeleteFileA(path.c_str());
            return tl::make_unexpected(make_error_code(
                ouroboros::error::shared_memory_truncate_failed));
        }

        HANDLE hMap = CreateFileMappingA(
            hFile, nullptr, PAGE_READWRITE,
            static_cast<DWORD>((static_cast<uint64_t>(size) >> 32) &
                               0xFFFFFFFF),
            static_cast<DWORD>(static_cast<uint64_t>(size) & 0xFFFFFFFF),
            nullptr);
        CloseHandle(hFile);
        if (hMap == nullptr)
        {
            DeleteFileA(path.c_str());
            return tl::make_unexpected(
                make_error_code(ouroboros::error::shared_memory_create_failed));
        }

        void* ptr = MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0, size);
        if (ptr == nullptr)
        {
            CloseHandle(hMap);
            DeleteFileA(path.c_str());
            return tl::make_unexpected(
                make_error_code(ouroboros::error::shared_memory_map_failed));
        }

        VERIFY(reinterpret_cast<uintptr_t>(ptr) % 8 == 0,
               "Mapped shared memory is not 8-byte aligned");

        shm_handle handle;
        handle.handle = reinterpret_cast<void*>(hMap);
        return shm_mapping{handle, ptr, size, true};
    }

    if (GetLastError() != ERROR_FILE_EXISTS)
    {
        return tl::make_unexpected(
            make_error_code(ouroboros::error::shared_memory_create_failed));
    }

    auto existing_file = open_existing_file(path, GENERIC_READ | GENERIC_WRITE);
    if (!existing_file)
    {
        return tl::make_unexpected(existing_file.error());
    }
    hFile = *existing_file;

    auto existing_size = file_size(hFile);
    if (!existing_size)
    {
        CloseHandle(hFile);
        return tl::make_unexpected(existing_size.error());
    }
    if (*existing_size != size)
    {
        CloseHandle(hFile);
        return tl::make_unexpected(
            make_error_code(ouroboros::error::shared_memory_size_mismatch));
    }

    HANDLE hMap =
        CreateFileMappingA(hFile, nullptr, PAGE_READWRITE, 0, 0, nullptr);
    CloseHandle(hFile);
    if (hMap == nullptr)
    {
        return tl::make_unexpected(
            make_error_code(ouroboros::error::shared_memory_open_failed));
    }

    void* ptr = MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0, *existing_size);
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
    return shm_mapping{handle, ptr, *existing_size, false};
}

auto open_and_map_file(const std::string& path)
    -> tl::expected<std::tuple<shm_handle, void*, std::size_t>, std::error_code>
{
    auto hFile = open_existing_file(path, GENERIC_READ);
    if (!hFile)
    {
        return tl::make_unexpected(hFile.error());
    }

    auto size = file_size(*hFile);
    if (!size)
    {
        CloseHandle(*hFile);
        return tl::make_unexpected(size.error());
    }

    HANDLE hMap =
        CreateFileMappingA(*hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
    CloseHandle(*hFile);
    if (hMap == nullptr)
    {
        return tl::make_unexpected(
            make_error_code(ouroboros::error::shared_memory_open_failed));
    }

    void* ptr = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, *size);
    if (ptr == nullptr)
    {
        CloseHandle(hMap);
        return tl::make_unexpected(
            make_error_code(ouroboros::error::shared_memory_map_failed));
    }

    shm_handle handle;
    handle.handle = reinterpret_cast<void*>(hMap);
    return std::make_tuple(handle, ptr, *size);
}

auto create_or_open_and_map_shm(shm_backing backing, const std::string& name,
                                std::size_t size)
    -> tl::expected<shm_mapping, std::error_code>
{
    if (backing == shm_backing::file)
    {
        return create_or_open_and_map_file(name, size);
    }

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
        // Segment already exists - close the handle from CreateFileMapping
        // and re-open with OpenFileMapping to get the existing size
        CloseHandle(hMap);

        hMap = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, name.c_str());
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

        void* ptr = MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0, 0);
        if (ptr == nullptr)
        {
            CloseHandle(hMap);
            return tl::make_unexpected(
                make_error_code(ouroboros::error::shared_memory_map_failed));
        }

        auto existing_size = mapped_region_size(ptr);
        if (!existing_size)
        {
            UnmapViewOfFile(ptr);
            CloseHandle(hMap);
            return tl::make_unexpected(existing_size.error());
        }

        VERIFY(reinterpret_cast<uintptr_t>(ptr) % 8 == 0,
               "Mapped shared memory is not 8-byte aligned");

        shm_handle handle;
        handle.handle = reinterpret_cast<void*>(hMap);
        return shm_mapping{handle, ptr, *existing_size, false};
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
    return shm_mapping{handle, ptr, size, true};
}

auto open_and_map_shm(shm_backing backing, const std::string& name)
    -> tl::expected<std::tuple<shm_handle, void*, std::size_t>, std::error_code>
{
    if (backing == shm_backing::file)
    {
        return open_and_map_file(name);
    }

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

    void* ptr = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (ptr == nullptr)
    {
        CloseHandle(hMap);
        return tl::make_unexpected(
            make_error_code(ouroboros::error::shared_memory_map_failed));
    }

    auto size = mapped_region_size(ptr);
    if (!size)
    {
        UnmapViewOfFile(ptr);
        CloseHandle(hMap);
        return tl::make_unexpected(size.error());
    }

    shm_handle handle;
    handle.handle = reinterpret_cast<void*>(hMap);
    return std::make_tuple(handle, ptr, *size);
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

void unlink_shm(shm_backing backing, const std::string& name)
{
    if (backing == shm_backing::file)
    {
        DeleteFileA(name.c_str());
        return;
    }
}

} // namespace detail
}
}

#endif // PLATFORM_WINDOWS
