// Copyright (c) 2023 Steinwurf ApS
// All Rights Reserved
//
// THIS IS UNPUBLISHED PROPRIETARY SOURCE CODE OF STEINWURF
// The copyright notice above does not evidence any
// actual or intended publication of such source code.

#pragma once

/// If not using c++20, we need to define our own span
#if __cplusplus < 202002L

#include <cstddef>
#include <type_traits>
#include <verify/verify.hpp>

namespace std
{
template <typename T>
class span
{
public:
    // Type aliases
    using element_type = T;
    using value_type = std::remove_cv_t<T>;
    using size_type = std::size_t;
    using pointer = T*;
    using iterator = T*;
    using const_iterator = const T*;

    span() : m_ptr(nullptr), m_size(0)
    {
    }

    // Constructor
    span(T* ptr, size_type count) : m_ptr(ptr), m_size(count)
    {
        VERIFY(ptr != nullptr || count == 0,
               "Pointer must not be null if size > 0");
    }

    // Constructor from C-style array
    template <std::size_t N>
    span(T (&arr)[N]) : m_ptr(arr), m_size(N)
    {
    }

    // Constructor from const C-style array (allows conversion from non-const to
    // const)
    template <typename U, std::size_t N,
              typename = std::enable_if_t<
                  std::is_convertible<U (*)[], T (*)[]>::value>>
    span(const U (&arr)[N]) : m_ptr(arr), m_size(N)
    {
    }

    // Constructor from vector (only enabled for non-const T to avoid
    // std::vector<const T>)
    template <typename Allocator, typename U = T,
              typename = std::enable_if_t<!std::is_const_v<U>>>
    span(std::vector<U, Allocator>& vec) : m_ptr(vec.data()), m_size(vec.size())
    {
        VERIFY(m_ptr != nullptr, "Vector must not be empty");
    }

    template <typename U = T, typename = std::enable_if_t<!std::is_const_v<U>>>
    span(const std::vector<U>& vec) : m_ptr(vec.data()), m_size(vec.size())
    {
        VERIFY(m_ptr != nullptr, "Vector must not be empty");
    }

    // Allow conversion from non-const to const span
    template <typename U, typename = std::enable_if_t<
                              std::is_convertible<U (*)[], T (*)[]>::value>>
    span(const span<U>& other) : m_ptr(other.data()), m_size(other.size())
    {
        VERIFY(m_ptr != nullptr, "Other span must not be empty");
    }

    // Allow conversion from non-const vector to const span
    template <typename U, typename Allocator,
              typename = std::enable_if_t<
                  std::is_convertible<U (*)[], T (*)[]>::value>>
    span(const std::vector<U, Allocator>& vec) :
        m_ptr(vec.data()), m_size(vec.size())
    {
        VERIFY(m_ptr != nullptr, "Vector must not be empty");
    }

    // Constructor from other span
    template <typename U>
    span(span<U>& other) : m_ptr(other.data()), m_size(other.size())
    {
        VERIFY(m_ptr != nullptr, "Other span must not be empty");
    }

    // Size of the span
    size_type size() const
    {
        return m_size;
    }

    // Data pointer
    T* data() const
    {
        return m_ptr;
    }

    auto empty() const -> bool
    {
        return m_size == 0;
    }

    // Begin iterator
    iterator begin() const
    {
        VERIFY(!empty(), "Span is empty!");
        return m_ptr;
    }

    // End iterator
    iterator end() const
    {
        VERIFY(!empty(), "Span is empty!");
        return m_ptr + m_size;
    }

    // access operator
    T& operator[](size_type index) const
    {
        VERIFY(index < m_size, "Index out of bounds!");
        return m_ptr[index];
    }

    // subspan
    span<T> subspan(size_type offset, size_type count) const
    {
        VERIFY(offset + count <= m_size, "Subspan out of bounds!", offset, count, m_size);
        return span<T>(m_ptr + offset, count);
    }

private:
    T* m_ptr;
    size_type m_size;
};
}
#else
#include <span>
#endif
