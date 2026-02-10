// Copyright (c) 2026 Steinwurf ApS
// SPDX-License-Identifier: MIT

#pragma once

#include <platform/config.hpp>

// Include platform-specific implementation
#if defined(PLATFORM_LINUX) || defined(PLATFORM_MAC)
#include "detail/shm_platform_posix.hpp"
#elif defined(PLATFORM_WINDOWS)
#include "detail/shm_platform_windows.hpp"
#else
#error "Unsupported platform for shared memory"
#endif

namespace ouroboros
{
inline namespace STEINWURF_OUROBOROS_VERSION
{

// Expose detail types and functions in the main namespace
using detail::create_or_open_and_map_shm;
using detail::open_and_map_shm;
using detail::shm_handle;
using detail::shm_mapping;
using detail::unlink_shm;
using detail::unmap_shm;

}
}
