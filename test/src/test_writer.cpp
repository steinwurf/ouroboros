// Copyright (c) 2026 Steinwurf ApS
// SPDX-License-Identifier: MIT

#include <ouroboros/reader.hpp>
#include <ouroboros/writer.hpp>

#include <cstring>
#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "test_helpers.hpp"

using test_helpers::create_aligned_buffer;

TEST(test_writer, size_calculations)
{
    constexpr std::size_t chunk_row_size = 16;
    constexpr std::size_t buffer_header_size = 24;

    /// Test cases: chunk_target_size, chunk_count, expected_size
    std::vector<std::tuple<std::size_t, std::size_t, std::size_t>> test_cases =
        {
            // header + chunk table + chunks = buffer size
            {1024, 4, buffer_header_size + 4 * chunk_row_size + 4 * 1024},
            {2048, 4, buffer_header_size + 4 * chunk_row_size + 4 * 2048},
            {4096, 4, buffer_header_size + 4 * chunk_row_size + 4 * 4096},
            {8192, 4, buffer_header_size + 4 * chunk_row_size + 4 * 8192},
            {16384, 4, buffer_header_size + 4 * chunk_row_size + 4 * 16384},
            {32768, 4, buffer_header_size + 4 * chunk_row_size + 4 * 32768},
            {65536, 4, buffer_header_size + 4 * chunk_row_size + 4 * 65536},
            {131072, 4, buffer_header_size + 4 * chunk_row_size + 4 * 131072},
            {262144, 4, buffer_header_size + 4 * chunk_row_size + 4 * 262144},
            {1024, 8, buffer_header_size + 8 * chunk_row_size + 8 * 1024},
            {2048, 8, buffer_header_size + 8 * chunk_row_size + 8 * 2048},
            {4096, 8, buffer_header_size + 8 * chunk_row_size + 8 * 4096},
            {8192, 8, buffer_header_size + 8 * chunk_row_size + 8 * 8192},
            {16384, 8, buffer_header_size + 8 * chunk_row_size + 8 * 16384},
            {32768, 8, buffer_header_size + 8 * chunk_row_size + 8 * 32768},
            {65536, 8, buffer_header_size + 8 * chunk_row_size + 8 * 65536},
            {131072, 8, buffer_header_size + 8 * chunk_row_size + 8 * 131072},
            {262144, 8, buffer_header_size + 8 * chunk_row_size + 8 * 262144},
        };

    for (const auto& [chunk_target_size, chunk_count, expected_size] :
         test_cases)
    {
        auto buffer_size =
            ouroboros::detail::buffer_format::compute_buffer_size(
                chunk_target_size, chunk_count);
        SCOPED_TRACE(
            ::testing::Message()
            << "chunk_target_size: " << chunk_target_size << " chunk_count: "
            << chunk_count << " expected_size: " << expected_size << std::endl
            << "If this test fails, it means that the header format has "
               "changed, consider incrementing the version number");
        EXPECT_EQ(buffer_size, expected_size);
    }
}

TEST(test_writer, buffer_readiness)
{
    constexpr std::size_t chunk_target_size = 1024;
    constexpr std::size_t chunk_count = 4;
    auto buffer_size = ouroboros::detail::buffer_format::compute_buffer_size(
        chunk_target_size, chunk_count);
    auto buffer = create_aligned_buffer(buffer_size);
    std::span<uint8_t> buffer_span(buffer);

    // Initially buffer should not be ready
    EXPECT_FALSE(
        ouroboros::reader::is_ready(std::span<const uint8_t>(buffer_span)));

    // Configure writer (this writes the header)
    ouroboros::writer writer;
    writer.configure(buffer_span, chunk_target_size, chunk_count);

    // Now buffer should be ready
    EXPECT_TRUE(
        ouroboros::reader::is_ready(std::span<const uint8_t>(buffer_span)));

    // Test with uninitialized buffer (must be at least buffer_header_size)
    std::vector<uint8_t> uninit_buffer(100);
    std::memset(uninit_buffer.data(), 0, uninit_buffer.size());
    EXPECT_FALSE(
        ouroboros::reader::is_ready(std::span<const uint8_t>(uninit_buffer)));
}

TEST(test_writer, configure)
{
    constexpr std::size_t chunk_target_size = 1024;
    constexpr std::size_t chunk_count = 4;
    auto buffer_size = ouroboros::detail::buffer_format::compute_buffer_size(
        chunk_target_size, chunk_count);
    auto buffer = create_aligned_buffer(buffer_size);
    std::span<uint8_t> buffer_span(buffer);

    ouroboros::writer writer;
    writer.configure(buffer_span, chunk_target_size, chunk_count);

    EXPECT_EQ(writer.chunk_target_size(), chunk_target_size);
    EXPECT_EQ(writer.chunk_count(), chunk_count);
    EXPECT_GT(writer.max_entry_size(), 0U);
    EXPECT_EQ(writer.buffer_id(), 0U);
}

TEST(test_writer, buffer_id)
{
    constexpr std::size_t chunk_target_size = 1024;
    constexpr std::size_t chunk_count = 4;
    constexpr uint64_t test_buffer_id = 0x123456789ABCDEF0ULL;
    auto buffer_size = ouroboros::detail::buffer_format::compute_buffer_size(
        chunk_target_size, chunk_count);
    auto buffer = create_aligned_buffer(buffer_size);
    std::span<uint8_t> buffer_span(buffer);

    ouroboros::writer writer;
    writer.configure(buffer_span, chunk_target_size, chunk_count,
                     test_buffer_id);

    EXPECT_EQ(writer.buffer_id(), test_buffer_id);

    writer.write("test");

    ouroboros::reader reader;
    auto result = reader.configure(std::span<const uint8_t>(buffer_span));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(reader.buffer_id(), test_buffer_id);
}

TEST(test_writer, write_single_entry)
{
    constexpr std::size_t chunk_target_size = 1024;
    constexpr std::size_t chunk_count = 4;
    auto buffer_size = ouroboros::detail::buffer_format::compute_buffer_size(
        chunk_target_size, chunk_count);
    auto buffer = create_aligned_buffer(buffer_size);
    std::span<uint8_t> buffer_span(buffer);

    ouroboros::writer writer;
    writer.configure(buffer_span, chunk_target_size, chunk_count);

    std::string test_entry = "Hello, World!";
    writer.write(test_entry);

    // Verify entry was written by reading it back
    ouroboros::reader reader;
    auto result = reader.configure(std::span<const uint8_t>(buffer_span));
    ASSERT_TRUE(result.has_value());

    auto entry_result = reader.read_next_entry();
    ASSERT_TRUE(entry_result.has_value());
    EXPECT_EQ(entry_result->data, test_entry);
    EXPECT_TRUE(entry_result->is_valid());

    // Should be no more entries
    auto no_more = reader.read_next_entry();
    EXPECT_FALSE(no_more.has_value());
}

TEST(test_writer, write_multiple_entries)
{
    constexpr std::size_t chunk_target_size = 1024;
    constexpr std::size_t chunk_count = 4;
    auto buffer_size = ouroboros::detail::buffer_format::compute_buffer_size(
        chunk_target_size, chunk_count);
    auto buffer = create_aligned_buffer(buffer_size);
    std::span<uint8_t> buffer_span(buffer);

    ouroboros::writer writer;
    writer.configure(buffer_span, chunk_target_size, chunk_count);

    std::vector<std::string> test_entries = {"First entry", "Second entry",
                                             "Third entry", "Fourth entry",
                                             "Fifth entry"};

    for (const auto& entry : test_entries)
    {
        writer.write(entry);
    }

    // Read back all entries
    ouroboros::reader reader;
    auto result = reader.configure(std::span<const uint8_t>(buffer_span));
    ASSERT_TRUE(result.has_value());

    for (const auto& expected_entry : test_entries)
    {
        auto entry_result = reader.read_next_entry();
        ASSERT_TRUE(entry_result.has_value());
        EXPECT_EQ(entry_result->data, expected_entry);
        EXPECT_TRUE(entry_result->is_valid());
    }

    // Should be no more entries
    auto no_more = reader.read_next_entry();
    EXPECT_FALSE(no_more.has_value());
}

TEST(test_writer, configure_returns_expected)
{
    // Verify that configure returns tl::expected and can be checked
    constexpr std::size_t chunk_target_size = 1024;
    constexpr std::size_t chunk_count = 4;
    auto buffer_size = ouroboros::detail::buffer_format::compute_buffer_size(
        chunk_target_size, chunk_count);
    auto buffer = create_aligned_buffer(buffer_size);
    std::span<uint8_t> buffer_span(buffer);

    ouroboros::writer writer;
    auto result = writer.configure(buffer_span, chunk_target_size, chunk_count);

    // Should succeed and be checkable
    EXPECT_TRUE(result.has_value());
    if (result.has_value())
    {
        writer.write("Test");
    }
}
