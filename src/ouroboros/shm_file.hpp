// Copyright (c) 2026 Steinwurf ApS
// SPDX-License-Identifier: MIT

#pragma once

#include <tl/expected.hpp>

#include <string>
#include <tuple>
#include <type_traits>
#include <utility>

#include "detail/span.hpp"
#include "shm_platform.hpp"
#include "version.hpp"

namespace ouroboros
{
inline namespace STEINWURF_OUROBOROS_VERSION
{

enum class shm_access
{
    read_only,
    read_write
};

template <shm_access Access>
class shm_file
{
public:
    shm_file() = default;

    ~shm_file()
    {
        cleanup();
    }

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

    auto is_mapped() const -> bool
    {
        return m_ptr != nullptr;
    }

    auto name() const -> const std::string&
    {
        return m_name;
    }

    auto size() const -> std::size_t
    {
        return m_size;
    }

    auto data() const -> const uint8_t*
    {
        return static_cast<const uint8_t*>(m_ptr);
    }

    template <shm_access A = Access,
              typename std::enable_if_t<A == shm_access::read_write, int> = 0>
    auto data() -> uint8_t*
    {
        return static_cast<uint8_t*>(m_ptr);
    }

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
