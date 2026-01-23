// Copyright (c) 2023 Steinwurf ApS
// All Rights Reserved
//
// THIS IS UNPUBLISHED PROPRIETARY SOURCE CODE OF STEINWURF
// The copyright notice above does not evidence any
// actual or intended publication of such source code.

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
using detail::shm_handle;
using detail::create_and_map_shm;
using detail::open_and_map_shm;
using detail::unmap_shm;
using detail::unlink_shm;

}
}
