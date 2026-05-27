// Copyright (c) 2026 Steinwurf ApS
// SPDX-License-Identifier: MIT

#pragma once

#include <tl/expected.hpp>

#include <string>
#include <type_traits>
#include <utility>

#include "shm_platform.hpp"
#include "version.hpp"

namespace ouroboros
{
inline namespace STEINWURF_OUROBOROS_VERSION
{

/// Access mode used to instantiate `shm_file`.
enum class shm_access
{
    /// Open/map shared memory as read-only.
    read_only,
    /// Create/open and map shared memory as read-write.
    read_write
};

/// RAII wrapper around a platform shared-memory mapping.
///
/// The access mode is selected at compile time through `Access`:
/// - `shm_access::read_only`: can call `open()` and `data() const`
/// - `shm_access::read_write`: can call `open_or_create()` and mutable `data()`
///
/// The object owns the mapping and unmaps it on destruction or reassignment.
/// Optionally, a read-write instance can also unlink the backing shared-memory
/// object on cleanup.
template <shm_access Access>
class shm_file
{
public:
    /// Construct an empty (unmapped) shared-memory file wrapper.
    shm_file() = default;

    /// Destroy the wrapper and release owned mapping resources.
    ~shm_file()
    {
        cleanup();
    }

    /// Move-construct from another wrapper, transferring ownership.
    shm_file(shm_file&& other) noexcept :
        m_name(std::move(other.m_name)), m_handle(other.m_handle),
        m_ptr(other.m_ptr), m_size(other.m_size),
        m_should_unlink(other.m_should_unlink)
    {
        other.m_handle = shm_handle{};
        other.m_ptr = nullptr;
        other.m_size = 0;
        other.m_should_unlink = false;
    }

    /// Move-assign from another wrapper, releasing current resources first.
    shm_file& operator=(shm_file&& other) noexcept
    {
        if (this != &other)
        {
            cleanup();
            m_name = std::move(other.m_name);
            m_handle = other.m_handle;
            m_ptr = other.m_ptr;
            m_size = other.m_size;
            m_should_unlink = other.m_should_unlink;

            other.m_handle = shm_handle{};
            other.m_ptr = nullptr;
            other.m_size = 0;
            other.m_should_unlink = false;
        }
        return *this;
    }

    shm_file(const shm_file&) = delete;
    shm_file& operator=(const shm_file&) = delete;

    /// Open and map an existing shared-memory object in read-only mode.
    ///
    /// Any existing mapping owned by this object is released first.
    ///
    /// @param name Shared-memory name
    /// @return Empty expected on success, or an error code on failure
    template <shm_access A = Access,
              typename std::enable_if_t<A == shm_access::read_only, int> = 0>
    auto open(const std::string& name) -> tl::expected<void, std::error_code>
    {
        cleanup();

        auto result = open_and_map_shm(name);
        if (!result)
        {
            return tl::make_unexpected(result.error());
        }

        m_name = name;
        m_handle = std::get<0>(result.value());
        m_ptr = std::get<1>(result.value());
        m_size = std::get<2>(result.value());
        m_should_unlink = false;
        return {};
    }

    /// Create or open and map a shared-memory object in read-write mode.
    ///
    /// Any existing mapping owned by this object is released first.
    ///
    /// @param name Shared-memory name
    /// @param size Requested size when creating a new object
    /// @param should_unlink If true, unlink on cleanup/destruction
    /// @return Empty expected on success, or an error code on failure
    template <shm_access A = Access,
              typename std::enable_if_t<A == shm_access::read_write, int> = 0>
    auto open_or_create(const std::string& name, std::size_t size,
                        bool should_unlink = true)
        -> tl::expected<void, std::error_code>
    {
        cleanup();

        auto result = create_or_open_and_map_shm(name, size);
        if (!result)
        {
            return tl::make_unexpected(result.error());
        }

        m_name = name;
        m_handle = result->handle;
        m_ptr = result->ptr;
        m_size = result->size;
        m_should_unlink = should_unlink;
        return {};
    }

    /// Check whether a mapping is currently held.
    ///
    /// @return True when mapped, otherwise false
    auto is_mapped() const -> bool
    {
        return m_ptr != nullptr;
    }

    /// Get the current shared-memory name.
    ///
    /// Returns an empty string when not mapped.
    auto name() const -> const std::string&
    {
        return m_name;
    }

    /// Get the mapped size in bytes.
    ///
    /// Returns 0 when not mapped.
    auto size() const -> std::size_t
    {
        return m_size;
    }

    /// Get a const pointer to mapped bytes.
    ///
    /// @return Pointer to mapping, or nullptr when not mapped
    auto data() const -> const uint8_t*
    {
        return static_cast<const uint8_t*>(m_ptr);
    }

    /// Get a mutable pointer to mapped bytes (read-write mode only).
    ///
    /// @return Pointer to mapping, or nullptr when not mapped
    template <shm_access A = Access,
              typename std::enable_if_t<A == shm_access::read_write, int> = 0>
    auto data() -> uint8_t*
    {
        return static_cast<uint8_t*>(m_ptr);
    }

    /// Unlink the shared-memory object by name and disable deferred unlink.
    ///
    /// This does not unmap the current view. On some platforms (for example
    /// Windows), unlinking is effectively a no-op and object lifetime is tied
    /// to open handles.
    void unlink()
    {
        if (!m_name.empty())
        {
            unlink_shm(m_name);
            m_should_unlink = false;
        }
    }

private:
    void cleanup()
    {
        if (m_ptr != nullptr)
        {
            unmap_shm(m_handle, m_ptr, m_size);
            m_ptr = nullptr;
            m_handle = shm_handle{};
        }
        if (m_should_unlink && !m_name.empty())
        {
            unlink_shm(m_name);
        }
        m_name.clear();
        m_size = 0;
        m_should_unlink = false;
    }

private:
    std::string m_name;
    shm_handle m_handle;
    void* m_ptr = nullptr;
    std::size_t m_size = 0;
    bool m_should_unlink = false;
};

} // namespace STEINWURF_OUROBOROS_VERSION
} // namespace ouroboros
