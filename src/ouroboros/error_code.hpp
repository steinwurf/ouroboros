// Copyright (c) 2026 Steinwurf ApS
// SPDX-License-Identifier: MIT

#pragma once

#include <cstdint>
#include <string>
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

/// Error information returned by writer configure operations.
///
/// Contains an error code and optionally the existing buffer_id
/// found in the buffer when configuration fails due to a buffer ID mismatch.
struct configure_error
{
    std::error_code code;
    uint64_t existing_buffer_id = 0;

    /// Convenience method for error message
    auto message() const -> std::string
    {
        return code.message();
    }

    /// Convenience method for error value
    auto value() const -> int
    {
        return code.value();
    }

    /// Compare with an error enum value
    friend auto operator==(const configure_error& lhs, error rhs) -> bool
    {
        return lhs.code == make_error_code(rhs);
    }

    friend auto operator!=(const configure_error& lhs, error rhs) -> bool
    {
        return !(lhs == rhs);
    }

    friend auto operator==(error lhs, const configure_error& rhs) -> bool
    {
        return rhs == lhs;
    }

    friend auto operator!=(error lhs, const configure_error& rhs) -> bool
    {
        return !(rhs == lhs);
    }
};

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
