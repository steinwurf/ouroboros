// Copyright (c) 2023 Steinwurf ApS
// All Rights Reserved
//
// THIS IS UNPUBLISHED PROPRIETARY SOURCE CODE OF STEINWURF
// The copyright notice above does not evidence any
// actual or intended publication of such source code.

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
