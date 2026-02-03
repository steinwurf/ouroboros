// Copyright (c) 2026 Steinwurf ApS
// SPDX-License-Identifier: MIT

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

#include "atomic.hpp"

namespace ouroboros
{
inline namespace STEINWURF_OUROBOROS_VERSION
{
namespace detail
{
namespace atomic
{
namespace impl
{

std::uint32_t load_acquire_impl_u32(const std::uint32_t* p) noexcept
{
    // On x86/x64, aligned reads of naturally aligned 32-bit values are atomic.
    // Use volatile read for atomicity without requiring write access to the
    // page. This works with read-only shared memory mappings (FILE_MAP_READ).
    // The volatile qualifier ensures the compiler doesn't optimize away or
    // reorder the read, and on x86/x64, aligned reads are naturally atomic.
    volatile const std::uint32_t* volatile_p = p;
    std::uint32_t value = *volatile_p;
    _ReadBarrier(); // Compiler barrier for acquire semantics - ensures
                    // subsequent operations don't happen before this load
                    // completes
    return value;
}

std::uint64_t load_acquire_impl_u64(const std::uint64_t* p) noexcept
{
    // On x86/x64, aligned reads of naturally aligned 64-bit values are atomic.
    // Use volatile read for atomicity without requiring write access to the
    // page. This works with read-only shared memory mappings (FILE_MAP_READ).
    // The volatile qualifier ensures the compiler doesn't optimize away or
    // reorder the read, and on x86/x64, aligned reads are naturally atomic.
    volatile const std::uint64_t* volatile_p = p;
    std::uint64_t value = *volatile_p;
    _ReadBarrier(); // Compiler barrier for acquire semantics - ensures
                    // subsequent operations don't happen before this load
                    // completes
    return value;
}

void store_release_impl_u32(std::uint32_t* p, std::uint32_t v) noexcept
{
    // Atomic write via exchange.
    InterlockedExchange(reinterpret_cast<volatile LONG*>(p),
                        static_cast<LONG>(v));
}

void store_release_impl_u64(std::uint64_t* p, std::uint64_t v) noexcept
{
    InterlockedExchange64(reinterpret_cast<volatile LONGLONG*>(p),
                          static_cast<LONGLONG>(v));
}

} // namespace detail
} // namespace atomic
} // namespace detail
} // namespace STEINWURF_OUROBOROS_VERSION
} // namespace ouroboros

#endif // PLATFORM_WINDOWS_64
