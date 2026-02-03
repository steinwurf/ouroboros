// Copyright (c) 2026 Steinwurf ApS
// SPDX-License-Identifier: MIT

#pragma once

#include <system_error>

#include "version.hpp"

namespace ouroboros
{
inline namespace STEINWURF_OUROBOROS_VERSION
{

enum class error
{

#define ERROR_TAG(id, msg) id,
#include "error_tags.hpp"
#undef ERROR_TAG
    undefined

};

auto make_error_code(error error) -> std::error_code;
auto make_error_condition(error error) -> std::error_condition;

}
}

/// Register for implicit conversion to error_code
/// This allows us to use the error enum class directly with
/// std::error_code and std::error_condition
///
/// See:
/// http://blog.think-async.com/2010/04/system-error-support-in-c0x-part-4.html
namespace std
{
template <>
struct is_error_code_enum<ouroboros::error> : true_type
{
};
}
