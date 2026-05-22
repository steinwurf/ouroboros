// Copyright (c) 2026 Steinwurf ApS
// SPDX-License-Identifier: MIT

#include <ouroboros/reader.hpp>
#include <ouroboros/writer.hpp>

#include <ouroboros/error_code.hpp>

#include <cstring>
#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "test_helpers.hpp"

using test_helpers::create_aligned_buffer;

TEST(test_reader, configure)
{
    constexpr std::size_t chunk_target_size = 1024;
    constexpr std::size_t chunk_count = 4;
    auto buffer_size = ouroboros::detail::buffer_format::compute_buffer_size(
        chunk_target_size, chunk_count);
    auto buffer = create_aligned_buffer(buffer_size);
    std::span<uint8_t> buffer_span(buffer);

    // Configure reader before writer - should fail
    ouroboros::reader reader;
    auto result = reader.configure(std::span<const uint8_t>(buffer_span));
    EXPECT_FALSE(result.has_value());

    // Configure writer first
    ouroboros::writer writer;
    writer.configure(buffer_span, chunk_target_size, chunk_count);

    // Configure reader again - should succeed
    result = reader.configure(std::span<const uint8_t>(buffer_span));
    ASSERT_TRUE(result.has_value());

    EXPECT_EQ(reader.chunk_count(), chunk_count);
}

TEST(test_reader, empty_buffer_handling)
{
    constexpr std::size_t chunk_target_size = 1024;
    constexpr std::size_t chunk_count = 4;
    auto buffer_size = ouroboros::detail::buffer_format::compute_buffer_size(
        chunk_target_size, chunk_count);
    auto buffer = create_aligned_buffer(buffer_size);
    std::span<uint8_t> buffer_span(buffer);

    ouroboros::writer writer;
    writer.configure(buffer_span, chunk_target_size, chunk_count);

    ouroboros::reader reader;
    auto result = reader.configure(std::span<const uint8_t>(buffer_span));
    ASSERT_TRUE(result.has_value());

    // Try to read from empty buffer - should fail
    auto entry_result = reader.read_next_entry();
    ASSERT_FALSE(entry_result.has_value());
    EXPECT_EQ(entry_result.error(),
              ouroboros::make_error_code(
                  ouroboros::error::no_data_entry_uncommitted));
}

TEST(test_reader, configure_invalid_magic)
{
    std::vector<uint8_t> buffer(1000);
    std::memset(buffer.data(), 0, buffer.size());

    buffer[0] = 0x0D; // Corrupt magic bytes
    buffer[1] = 0x0E;
    buffer[2] = 0x0A;
    buffer[3] = 0x0D;

    ouroboros::reader reader;
    auto result = reader.configure(std::span<const uint8_t>(buffer));
    EXPECT_FALSE(result.has_value());
}

TEST(test_reader, configure_invalid_version)
{
    constexpr std::size_t chunk_target_size = 1024;
    constexpr std::size_t chunk_count = 4;
    auto buffer_size = ouroboros::detail::buffer_format::compute_buffer_size(
        chunk_target_size, chunk_count);
    auto buffer = create_aligned_buffer(buffer_size);
    std::span<uint8_t> buffer_span(buffer);

    // Configure writer first
    ouroboros::writer writer;
    writer.configure(buffer_span, chunk_target_size, chunk_count);

    // Corrupt version
    buffer[4] = 0xFF;
    buffer[5] = 0xFF;
    buffer[6] = 0xFF;
    buffer[7] = 0xFF;

    ouroboros::reader reader;
    auto result = reader.configure(std::span<const uint8_t>(buffer_span));
    EXPECT_FALSE(result.has_value());
}

TEST(test_reader, token_validation)
{
    constexpr std::size_t chunk_target_size = 128;
    constexpr std::size_t chunk_count = 4;
    auto buffer_size = ouroboros::detail::buffer_format::compute_buffer_size(
        chunk_target_size, chunk_count);
    auto buffer = create_aligned_buffer(buffer_size);
    std::span<uint8_t> buffer_span(buffer);

    ouroboros::writer writer;
    writer.configure(buffer_span, chunk_target_size, chunk_count);

    writer.write("Test entry");

    ouroboros::reader reader;
    auto result = reader.configure(std::span<const uint8_t>(buffer_span));
    ASSERT_TRUE(result.has_value());

    auto entry_result = reader.read_next_entry();
    ASSERT_TRUE(entry_result.has_value());

    // Entry should be valid initially
    EXPECT_TRUE(entry_result->is_valid());

    // Write more entries (this may invalidate the previous entry if buffer
    // wraps)
    for (int i = 0; i < 100; ++i)
    {
        std::string entry = "Entry " + std::to_string(i);
        writer.write(entry);
    }

    EXPECT_FALSE(entry_result->is_valid());
}

TEST(test_reader, multiple_readers)
{
    constexpr std::size_t chunk_target_size = 128;
    constexpr std::size_t chunk_count = 4;
    auto buffer_size = ouroboros::detail::buffer_format::compute_buffer_size(
        chunk_target_size, chunk_count);
    auto buffer = create_aligned_buffer(buffer_size);
    std::span<uint8_t> buffer_span(buffer);

    ouroboros::writer writer;
    writer.configure(buffer_span, chunk_target_size, chunk_count);

    std::vector<std::string> test_entries = {"One", "Two", "Three"};

    for (const auto& entry : test_entries)
    {
        writer.write(entry);
    }

    // Create multiple readers
    ouroboros::reader reader1;
    auto result1 = reader1.configure(std::span<const uint8_t>(buffer_span));
    ASSERT_TRUE(result1.has_value());

    ouroboros::reader reader2;
    auto result2 = reader2.configure(std::span<const uint8_t>(buffer_span));
    ASSERT_TRUE(result2.has_value());

    // Both readers should be able to read the same entries
    for (const auto& expected_entry : test_entries)
    {
        auto entry1 = reader1.read_next_entry();
        auto entry2 = reader2.read_next_entry();

        ASSERT_TRUE(entry1.has_value());
        ASSERT_TRUE(entry2.has_value());

        EXPECT_EQ(entry1->data, expected_entry);
        EXPECT_EQ(entry2->data, expected_entry);
    }
}

TEST(test_reader, starting_chunk_selection)
{
    constexpr std::size_t chunk_target_size = 128;
    constexpr std::size_t chunk_count = 2;
    auto buffer_size = ouroboros::detail::buffer_format::compute_buffer_size(
        chunk_target_size, chunk_count);
    auto buffer = create_aligned_buffer(buffer_size);
    std::span<uint8_t> buffer_span(buffer);

    ouroboros::writer writer;
    writer.configure(buffer_span, chunk_target_size, chunk_count);

    // Write entries to advance through chunks
    for (int i = 0; i < 30; ++i)
    {
        std::string entry = std::string(i, 'A') + "Entry " + std::to_string(i);
        writer.write(entry);
    }

    ouroboros::reader reader;
    auto result = reader.configure(std::span<const uint8_t>(buffer_span));
    ASSERT_TRUE(result.has_value());

    // Reader should start from appropriate chunk
    // Should be able to read at least some entries
    int read_count = 0;
    while (read_count < 10)
    {
        auto entry_result = reader.read_next_entry();
        if (!entry_result.has_value())
        {
            break;
        }
        read_count++;
    }

    EXPECT_GT(read_count, 0);
    EXPECT_LT(read_count, 30); // Some entries may have been overwritten
}

TEST(test_reader, detects_overwritten_entry)
{
    constexpr std::size_t chunk_target_size = 64; // Small chunk to force wraps
    constexpr std::size_t chunk_count = 2;
    auto buffer_size = ouroboros::detail::buffer_format::compute_buffer_size(
        chunk_target_size, chunk_count);
    auto buffer = create_aligned_buffer(buffer_size);
    std::span<uint8_t> buffer_span(buffer);

    ouroboros::writer writer;
    writer.configure(buffer_span, chunk_target_size, chunk_count);

    ouroboros::reader reader;
    auto result = reader.configure(std::span<const uint8_t>(buffer_span));
    ASSERT_TRUE(result.has_value());

    // Writer writes first entry
    std::string first_entry = "First entry";
    writer.write(first_entry);

    // Reader reads the first entry
    auto entry_result1 = reader.read_next_entry();
    ASSERT_TRUE(entry_result1.has_value());
    EXPECT_EQ(entry_result1->data, first_entry);
    EXPECT_TRUE(entry_result1->is_valid());

    // Writer writes enough entries to overwrite the first entry
    // We need to write enough to cause a wrap and overwrite
    // Calculate approximate entries needed: buffer size / average entry size
    // Each entry is roughly: header (4) + payload + alignment padding
    std::size_t entries_to_write = 0;
    while (entries_to_write < 50) // Safety limit
    {
        std::string entry = "Entry " + std::to_string(entries_to_write);
        writer.write(entry);
        entries_to_write++;

        // Check if the first entry is now invalid
        if (!entry_result1->is_valid())
        {
            break;
        }
    }

    // The first entry should now be invalid (overwritten)
    EXPECT_FALSE(entry_result1->is_valid())
        << "First entry should be invalid after buffer wrap";

    // Reader will now skip to next valid chunk and continue reading from there
    int read_count = 0;
    for (int i = 0; i < entries_to_write; ++i)
    {
        auto entry_result = reader.read_next_entry();
        if (!entry_result.has_value())
        {
            break;
        }
        read_count++;
        EXPECT_NE(entry_result->data, first_entry);
    }

    EXPECT_GT(entries_to_write, 0) << "Should have written at least one entry";
    EXPECT_GT(read_count, 0) << "Should have read at least one entry";
}

TEST(test_reader, handles_rapid_writes)
{
    constexpr std::size_t chunk_target_size = 128;
    constexpr std::size_t chunk_count = 3;
    auto buffer_size = ouroboros::detail::buffer_format::compute_buffer_size(
        chunk_target_size, chunk_count);
    auto buffer = create_aligned_buffer(buffer_size);
    std::span<uint8_t> buffer_span(buffer);

    ouroboros::writer writer;
    writer.configure(buffer_span, chunk_target_size, chunk_count);

    ouroboros::reader reader;
    auto result = reader.configure(std::span<const uint8_t>(buffer_span));
    ASSERT_TRUE(result.has_value())
        << "Reader configuration failed: " << result.error().message();

    // Writer writes many entries rapidly
    constexpr int num_entries = 20;
    for (int i = 0; i < num_entries; ++i)
    {
        std::string entry = "Rapid entry " + std::to_string(i);
        writer.write(entry);
    }

    // Reader should be able to read entries (may not get all due to
    // overwrites)
    std::vector<std::string> read_entries;
    std::string error_message;
    while (read_entries.size() < num_entries)
    {
        auto entry_result = reader.read_next();
        if (entry_result)
        {
            read_entries.push_back(entry_result.value());
        }
        else
        {
            error_message = entry_result.error().message();
            break;
        }
    }

    SCOPED_TRACE(::testing::Message() << "Error message: " << error_message);

    // Should have read at least some entries
    EXPECT_GT(read_entries.size(), 0) << "Should read at least some entries";
    EXPECT_LE(read_entries.size(), num_entries)
        << "Should not read more entries than written";
}
