// Copyright (c) 2026 Steinwurf ApS
// SPDX-License-Identifier: MIT

#pragma once

#include <string>

namespace ouroboros
{
#define STEINWURF_OUROBOROS_VERSION v1_0_0

inline namespace STEINWURF_OUROBOROS_VERSION
{
/// @return The version of the app as a string
std::string version();
}
}
