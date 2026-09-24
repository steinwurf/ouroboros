// Copyright (c) 2026 Steinwurf ApS
// SPDX-License-Identifier: MIT

#pragma once

#include "../version.hpp"

namespace ouroboros
{
inline namespace STEINWURF_OUROBOROS_VERSION
{
namespace detail
{

/// Where a shared-memory mapping is stored.
enum class shm_backing
{
    /// Named shared-memory object (`shm_open` / Windows file mapping).
    named,
    /// Regular filesystem file mapped into the process.
    file
};

} // namespace detail
}
}
