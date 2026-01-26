// Copyright (c) 2023 Steinwurf ApS
// All Rights Reserved
//
// THIS IS UNPUBLISHED PROPRIETARY SOURCE CODE OF STEINWURF
// The copyright notice above does not evidence any
// actual or intended publication of such source code.

#pragma once

#include <cstdint>
#include <type_traits>

#include <platform/config.hpp>

#include "../version.hpp"

namespace ouroboros
{
inline namespace STEINWURF_OUROBOROS_VERSION
{
namespace detail
{
namespace atomic
{
/// This code provides portable atomic load/store operations for uint32_t and
/// uint64_t types across different platforms.
/// Once std::atomic_ref from C++20 is widely available, this code can be
/// replaced with std::atomic_ref for better clarity and maintainability.

// Forward declarations for Windows implementation helpers
#if defined(PLATFORM_WINDOWS_64)
namespace detail
{
std::uint32_t load_relaxed_impl_u32(const std::uint32_t* p) noexcept;
std::uint64_t load_relaxed_impl_u64(const std::uint64_t* p) noexcept;
void store_relaxed_impl_u32(std::uint32_t* p, std::uint32_t v) noexcept;
void store_relaxed_impl_u64(std::uint64_t* p, std::uint64_t v) noexcept;
}

// Template functions for uint32_t and uint64_t
template <typename T>
inline T load_relaxed(const T* p) noexcept
{
    static_assert(std::is_same_v<T, std::uint32_t> ||
                      std::is_same_v<T, std::uint64_t>,
                  "atomic only supports uint32_t and uint64_t");

    if constexpr (std::is_same_v<T, std::uint32_t>)
    {
        return detail::load_relaxed_impl_u32(p);
    }
    else // T is uint64_t
    {
        return detail::load_relaxed_impl_u64(p);
    }
}

template <typename T>
inline T load_acquire(const T* p) noexcept
{
    static_assert(std::is_same_v<T, std::uint32_t> ||
                      std::is_same_v<T, std::uint64_t>,
                  "atomic only supports uint32_t and uint64_t");
    // Interlocked ops act as acquire+release (at least).
    return load_relaxed(p);
}

template <typename T>
inline void store_relaxed(T* p, T v) noexcept
{
    static_assert(std::is_same_v<T, std::uint32_t> ||
                      std::is_same_v<T, std::uint64_t>,
                  "atomic only supports uint32_t and uint64_t");

    if constexpr (std::is_same_v<T, std::uint32_t>)
    {
        detail::store_relaxed_impl_u32(p, v);
    }
    else // T is uint64_t
    {
        detail::store_relaxed_impl_u64(p, v);
    }
}

template <typename T>
inline void store_release(T* p, T v) noexcept
{
    static_assert(std::is_same_v<T, std::uint32_t> ||
                      std::is_same_v<T, std::uint64_t>,
                  "atomic only supports uint32_t and uint64_t");
    // InterlockedExchange is at least release (typically full barrier).
    store_relaxed(p, v);
}
#elif defined(PLATFORM_LINUX) || defined(PLATFORM_MAC)

static_assert(__atomic_always_lock_free(4, nullptr),
              "atomic requires lock-free 32-bit atomics on this target");
static_assert(__atomic_always_lock_free(8, nullptr),
              "atomic requires lock-free 64-bit atomics on this target");

// GCC/Clang path (including Apple Clang)
// Uses __atomic builtins (available in C++17).
template <typename T>
inline T load_relaxed(const T* p) noexcept
{
    static_assert(std::is_same_v<T, std::uint32_t> ||
                      std::is_same_v<T, std::uint64_t>,
                  "atomic only supports uint32_t and uint64_t");
    return __atomic_load_n(p, __ATOMIC_RELAXED);
}

template <typename T>
inline T load_acquire(const T* p) noexcept
{
    static_assert(std::is_same_v<T, std::uint32_t> ||
                      std::is_same_v<T, std::uint64_t>,
                  "atomic only supports uint32_t and uint64_t");
    return __atomic_load_n(p, __ATOMIC_ACQUIRE);
}

template <typename T>
inline void store_relaxed(T* p, T v) noexcept
{
    static_assert(std::is_same_v<T, std::uint32_t> ||
                      std::is_same_v<T, std::uint64_t>,
                  "atomic only supports uint32_t and uint64_t");
    __atomic_store_n(p, v, __ATOMIC_RELAXED);
}

template <typename T>
inline void store_release(T* p, T v) noexcept
{
    static_assert(std::is_same_v<T, std::uint32_t> ||
                      std::is_same_v<T, std::uint64_t>,
                  "atomic only supports uint32_t and uint64_t");
    __atomic_store_n(p, v, __ATOMIC_RELEASE);
}
#else
// Unsupported platform, just fall back to non-atomic operations with a warning.
#warning "atomic: Unsupported platform, falling back to non-atomic operations!"

template <typename T>
inline T load_relaxed(const T* p) noexcept
{
    return *p;
}

template <typename T>
inline T load_acquire(const T* p) noexcept
{
    return *p;
}

template <typename T>
inline void store_relaxed(T* p, T v) noexcept
{
    *p = v;
}

template <typename T>
inline void store_release(T* p, T v) noexcept
{
    *p = v;
}

#endif

} // namespace atomic
} // namespace detail
}
}
