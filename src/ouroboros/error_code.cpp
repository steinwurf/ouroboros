// Copyright (c) 2023 Steinwurf ApS
// All Rights Reserved
//
// THIS IS UNPUBLISHED PROPRIETARY SOURCE CODE OF STEINWURF
// The copyright notice above does not evidence any
// actual or intended publication of such source code.

#include "error_code.hpp"

#include <string>
#include <verify/verify.hpp>

namespace ouroboros
{
inline namespace STEINWURF_OUROBOROS_VERSION
{

class error_category : public std::error_category
{
    virtual const char* name() const noexcept override final
    {
        return "ouroboros::error";
    }

    virtual std::string message(int code) const override final
    {
        switch (static_cast<error>(code))
        {
#define ERROR_TAG(id, msg) \
    case error::id:        \
        return msg;
#include "error_tags.hpp"
#undef ERROR_TAG
        case error::undefined:
            VERIFY(false, "Invalid error code received!");
            return "";
        };
        VERIFY(false, "Invalid error code received!");
        return "";
    }
};

auto make_error_category() -> const error_category&
{
    static error_category category;
    return category;
}

auto make_error_code(error error) -> std::error_code
{
    return {static_cast<int>(error), make_error_category()};
}

auto make_error_condition(error error) -> std::error_condition
{
    return {static_cast<int>(error), make_error_category()};
}

}
}
