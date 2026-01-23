// Copyright (c) 2023 Steinwurf ApS
// All Rights Reserved
//
// THIS IS UNPUBLISHED PROPRIETARY SOURCE CODE OF STEINWURF
// The copyright notice above does not evidence any
// actual or intended publication of such source code.

#include <platform/config.hpp>

#ifdef PLATFORM_WINDOWS_64

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <intrin.h>
#include <windows.h>

#include <cstdint>

#include "portable_atomic.hpp"

namespace ouroboros
{
inline namespace STEINWURF_OUROBOROS_VERSION
{
namespace detail
{
namespace portable_atomic
{
namespace detail
{

std::uint32_t load_relaxed_impl_u32(const std::uint32_t* p) noexcept
{
    // Atomic read via RMW with no change.
    return static_cast<std::uint32_t>(InterlockedCompareExchange(
        reinterpret_cast<volatile LONG*>(const_cast<std::uint32_t*>(p)), 0, 0));
}

std::uint64_t load_relaxed_impl_u64(const std::uint64_t* p) noexcept
{
    return static_cast<std::uint64_t>(InterlockedCompareExchange64(
        reinterpret_cast<volatile LONGLONG*>(const_cast<std::uint64_t*>(p)), 0,
        0));
}

void store_relaxed_impl_u32(std::uint32_t* p, std::uint32_t v) noexcept
{
    // Atomic write via exchange.
    InterlockedExchange(reinterpret_cast<volatile LONG*>(p),
                        static_cast<LONG>(v));
}

void store_relaxed_impl_u64(std::uint64_t* p, std::uint64_t v) noexcept
{
    InterlockedExchange64(reinterpret_cast<volatile LONGLONG*>(p),
                          static_cast<LONGLONG>(v));
}

} // namespace detail
} // namespace portable_atomic
} // namespace detail
} // namespace STEINWURF_OUROBOROS_VERSION
} // namespace ouroboros

#endif // PLATFORM_WINDOWS_64

