// Copyright (c) 2026 Steinwurf ApS
// SPDX-License-Identifier: MIT

#include <ouroboros/reader.hpp>
#include <ouroboros/writer.hpp>

#include <ouroboros/error_code.hpp>

#include <atomic>
#include <chrono>
#include <cstring>
#include <gtest/gtest.h>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

namespace
{

// Helper to create aligned buffer
// std::vector typically provides 8-byte aligned memory on most platforms
auto create_aligned_buffer(std::size_t size) -> std::vector<uint8_t>
{
    std::vector<uint8_t> buffer(size);
    // Verify alignment - most allocators provide 8-byte aligned memory
    // If this fails, the writer's VERIFY will catch it during configure()
    return buffer;
}
}

TEST(test_reader_writer, size_calculations)
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

TEST(test_reader_writer, buffer_readiness)
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

TEST(test_reader_writer, writer_configure)
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

TEST(test_reader_writer, buffer_id)
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

TEST(test_reader_writer, buffer_restarted_when_id_changes)
{
    constexpr std::size_t chunk_target_size = 1024;
    constexpr std::size_t chunk_count = 4;
    constexpr uint64_t initial_id = 1;
    constexpr uint64_t new_id = 2;
    auto buffer_size = ouroboros::detail::buffer_format::compute_buffer_size(
        chunk_target_size, chunk_count);
    auto buffer = create_aligned_buffer(buffer_size);
    std::span<uint8_t> buffer_span(buffer);

    ouroboros::writer writer;
    auto config_result = writer.configure(buffer_span, chunk_target_size,
                                          chunk_count, initial_id);
    ASSERT_TRUE(config_result.has_value());
    writer.write("first");

    ouroboros::reader reader;
    auto result = reader.configure(std::span<const uint8_t>(buffer_span));
    ASSERT_TRUE(result.has_value());

    auto entry = reader.read_next_entry();
    ASSERT_TRUE(entry.has_value());
    EXPECT_EQ(entry->data, "first");

    // Configure writer with new ID using force_takeover to reinitialize buffer
    // This simulates a new writer taking over with a different ID
    // Note: force_takeover reinitializes the buffer, so "first" will be lost
    auto force_result = writer.configure(buffer_span, chunk_target_size,
                                         chunk_count, new_id, true);
    ASSERT_TRUE(force_result.has_value()) << force_result.error().message();
    writer.write("second");

    // Next read should return buffer_restarted because the buffer ID changed
    auto restart_result = reader.read_next_entry();
    ASSERT_FALSE(restart_result.has_value());
    EXPECT_EQ(restart_result.error(),
              ouroboros::make_error_code(ouroboros::error::buffer_restarted));

    // Reconfigure reader - it should start from the beginning
    auto reconfig_result =
        reader.configure(std::span<const uint8_t>(buffer_span));
    ASSERT_TRUE(reconfig_result.has_value());
    EXPECT_EQ(reader.buffer_id(), new_id);

    // Read entries - only "second" exists since force_takeover reinitialized
    auto entry1 = reader.read_next_entry();
    ASSERT_TRUE(entry1.has_value());
    EXPECT_EQ(entry1->data, "second");

    // No more entries
    auto no_more = reader.read_next_entry();
    EXPECT_FALSE(no_more.has_value());
}

TEST(test_reader_writer, writer_write_single_entry)
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

TEST(test_reader_writer, writer_write_multiple_entries)
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

TEST(test_reader_writer, reader_configure)
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

TEST(test_reader_writer, reader_empty_buffer_handling)
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
              ouroboros::make_error_code(ouroboros::error::no_data_available));
}

TEST(test_reader_writer, reader_configure_invalid_magic)
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

TEST(test_reader_writer, reader_configure_invalid_version)
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

TEST(test_reader_writer, entry_alignment)
{
    constexpr std::size_t chunk_target_size = 1024;
    constexpr std::size_t chunk_count = 4;
    auto buffer_size = ouroboros::detail::buffer_format::compute_buffer_size(
        chunk_target_size, chunk_count);
    auto buffer = create_aligned_buffer(buffer_size);
    std::span<uint8_t> buffer_span(buffer);

    ouroboros::writer writer;
    writer.configure(buffer_span, chunk_target_size, chunk_count);

    // Write entries of different sizes to test alignment
    writer.write("A");    // Small entry
    writer.write("BB");   // Slightly larger
    writer.write("CCC");  // Even larger
    writer.write("DDDD"); // 4 bytes

    ouroboros::reader reader;
    auto result = reader.configure(std::span<const uint8_t>(buffer_span));
    ASSERT_TRUE(result.has_value());

    EXPECT_EQ(reader.read_next_entry()->data, "A");
    EXPECT_EQ(reader.read_next_entry()->data, "BB");
    EXPECT_EQ(reader.read_next_entry()->data, "CCC");
    EXPECT_EQ(reader.read_next_entry()->data, "DDDD");
}

TEST(test_reader_writer, wrap_behavior)
{
    constexpr std::size_t chunk_target_size = 64; // Small chunk size
    constexpr std::size_t chunk_count = 2;
    auto buffer_size = ouroboros::detail::buffer_format::compute_buffer_size(
        chunk_target_size, chunk_count);
    auto buffer = create_aligned_buffer(buffer_size);
    std::span<uint8_t> buffer_span(buffer);

    ouroboros::writer writer;
    writer.configure(buffer_span, chunk_target_size, chunk_count);

    // Write enough entries to cause a wrap
    for (int i = 0; i < 20; ++i)
    {
        std::string entry = "Entry " + std::to_string(i);
        writer.write(entry);
    }

    // Reader should handle wrap correctly
    ouroboros::reader reader;
    auto result = reader.configure(std::span<const uint8_t>(buffer_span));
    ASSERT_TRUE(result.has_value());

    // Should be able to read entries (may not get all due to overwrites)
    int read_count = 0;
    while (true)
    {
        auto entry_result = reader.read_next_entry();
        if (!entry_result.has_value())
        {
            break;
        }
        read_count++;
    }

    EXPECT_GT(read_count, 0);
    EXPECT_LT(read_count,
              20); // Make sure we actually wrapped and lost some entries
}

TEST(test_reader_writer, chunk_advancement)
{
    constexpr std::size_t chunk_target_size = 128;
    constexpr std::size_t chunk_count = 4;
    auto buffer_size = ouroboros::detail::buffer_format::compute_buffer_size(
        chunk_target_size, chunk_count);
    auto buffer = create_aligned_buffer(buffer_size);
    std::span<uint8_t> buffer_span(buffer);

    ouroboros::writer writer;
    writer.configure(buffer_span, chunk_target_size, chunk_count);

    // Entries per chunk: 4
    // Chunks: 4
    // Total entries: 16
    int total_entries = 16;
    // Write entries that will span multiple chunks
    for (int i = 0; i < (total_entries * 2) + 15;
         ++i) // 15 extra entries to force a wrap
    {

        std::string entry = std::string(
            28, 'A' + (i % 26)); // 28-byte entries + header = 32 bytes this
                                 // means 4 entries per chunk
        writer.write(entry);
    }

    ouroboros::reader reader;
    auto result = reader.configure(std::span<const uint8_t>(buffer_span));
    ASSERT_TRUE(result.has_value());

    // Should be able to read entries across chunks
    int read_count = 0;
    int chunks = 0;
    int largest_chunk_token = -1;
    while (read_count < 200)
    {
        auto entry_result = reader.read_next_entry();
        if (entry_result.has_value())
        {
            int token = entry_result.value().chunk_token;
            EXPECT_GE(token, largest_chunk_token)
                << "token: " << token
                << " largest_chunk_token: " << largest_chunk_token;
            if (token != largest_chunk_token)
            {
                largest_chunk_token = token;
                chunks++;
            }
        }
        else
        {
            break;
        }
        read_count++;
    }

    EXPECT_EQ(chunks, 1); // The reader skips to the latest chunk
    EXPECT_GT(read_count, 0);
}

TEST(test_reader_writer, minimal_entry)
{
    constexpr std::size_t chunk_target_size = 1024;
    constexpr std::size_t chunk_count = 4;
    auto buffer_size = ouroboros::detail::buffer_format::compute_buffer_size(
        chunk_target_size, chunk_count);
    auto buffer = create_aligned_buffer(buffer_size);
    std::span<uint8_t> buffer_span(buffer);

    ouroboros::writer writer;
    writer.configure(buffer_span, chunk_target_size, chunk_count);

    // Write an entry with minimal content
    writer.write("X");

    ouroboros::reader reader;
    auto result = reader.configure(std::span<const uint8_t>(buffer_span));
    ASSERT_TRUE(result.has_value());

    auto entry_result = reader.read_next_entry();
    ASSERT_TRUE(entry_result.has_value());
    EXPECT_EQ(entry_result->data, "X");
}

TEST(test_reader_writer, maximum_entry)
{
    constexpr std::size_t chunk_target_size = 128;
    constexpr std::size_t chunk_count = 4;
    auto buffer_size = ouroboros::detail::buffer_format::compute_buffer_size(
        chunk_target_size, chunk_count);
    auto buffer = create_aligned_buffer(buffer_size);
    std::span<uint8_t> buffer_span(buffer);

    ouroboros::writer writer;
    writer.configure(buffer_span, chunk_target_size, chunk_count);

    // Write a large entry (but within max_entry_size)
    std::string large_entry(writer.max_entry_size(), 'A');
    writer.write(large_entry);

    ouroboros::reader reader;
    auto result = reader.configure(std::span<const uint8_t>(buffer_span));
    ASSERT_TRUE(result.has_value());

    auto entry_result = reader.read_next_entry();
    ASSERT_TRUE(entry_result.has_value());
    EXPECT_EQ(entry_result->data.size(), writer.max_entry_size());
    EXPECT_EQ(entry_result->data, large_entry);
}

TEST(test_reader_writer, reader_token_validation)
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

TEST(test_reader_writer, multiple_readers)
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

TEST(test_reader_writer, reader_starting_chunk_selection)
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

// Helper to generate a string entry consiting of the entry_counter followed by
// a random number of characters to reach target size
auto generate_entry(std::size_t entry_counter,
                    std::size_t target_size) -> std::string
{
    std::string entry = std::to_string(entry_counter);
    while (entry.size() < target_size)
    {
        entry += 'A' + (entry_counter % 26); // Cycle through A-Z
    }

    return entry;
}

TEST(test_reader_writer, reader_detects_overwritten_entry)
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
    bool found_new_entry = false;
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

TEST(test_reader_writer, reader_writer_interleaved_operations)
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

    // Writer writes entry 1
    writer.write("Entry 1");

    // Reader reads entry 1
    auto entry1 = reader.read_next_entry();
    ASSERT_TRUE(entry1.has_value());
    EXPECT_EQ(entry1->data, "Entry 1");

    // Writer writes entry 2
    writer.write("Entry 2");

    // Reader reads entry 2
    auto entry2 = reader.read_next_entry();
    ASSERT_TRUE(entry2.has_value());
    EXPECT_EQ(entry2->data, "Entry 2");

    // Entry 1 should still be valid (no wrap yet)
    EXPECT_TRUE(entry1->is_valid());

    // Writer writes entry 3
    writer.write("Entry 3");

    // Reader reads entry 3
    auto entry3 = reader.read_next_entry();
    ASSERT_TRUE(entry3.has_value());
    EXPECT_EQ(entry3->data, "Entry 3");

    // All entries should still be valid
    EXPECT_TRUE(entry1->is_valid());
    EXPECT_TRUE(entry2->is_valid());
    EXPECT_TRUE(entry3->is_valid());

    // Reader tries to read again - should fail
    auto entry4 = reader.read_next_entry();
    ASSERT_FALSE(entry4.has_value());
    EXPECT_EQ(entry4.error(),
              ouroboros::make_error_code(ouroboros::error::no_data_available));
}

TEST(test_reader_writer, writer_finish_reader_returns_writer_finished)
{
    constexpr std::size_t chunk_target_size = 1024;
    constexpr std::size_t chunk_count = 4;
    auto buffer_size = ouroboros::detail::buffer_format::compute_buffer_size(
        chunk_target_size, chunk_count);
    auto buffer = create_aligned_buffer(buffer_size);
    std::span<uint8_t> buffer_span(buffer);

    ouroboros::writer writer;
    writer.configure(buffer_span, chunk_target_size, chunk_count);

    writer.write("First entry");
    writer.write("Second entry");
    writer.finish();

    ouroboros::reader reader;
    auto result = reader.configure(std::span<const uint8_t>(buffer_span));
    ASSERT_TRUE(result.has_value());

    auto entry1 = reader.read_next_entry();
    ASSERT_TRUE(entry1.has_value());
    EXPECT_EQ(entry1->data, "First entry");

    auto entry2 = reader.read_next_entry();
    ASSERT_TRUE(entry2.has_value());
    EXPECT_EQ(entry2->data, "Second entry");

    // After finish, reader should return writer_finished
    auto finish_result = reader.read_next_entry();
    ASSERT_FALSE(finish_result.has_value());
    EXPECT_EQ(finish_result.error(),
              ouroboros::make_error_code(ouroboros::error::writer_finished));

    // Subsequent reads should also return writer_finished
    auto subsequent_result = reader.read_next_entry();
    ASSERT_FALSE(subsequent_result.has_value());
    EXPECT_EQ(subsequent_result.error(),
              ouroboros::make_error_code(ouroboros::error::writer_finished));
}

TEST(test_reader_writer, reader_handles_rapid_writes)
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

TEST(test_reader_writer, chunk_invalidation_and_wrap_sequence)
{
    constexpr std::size_t chunk_target_size = 256;
    constexpr std::size_t chunk_count = 4;
    auto buffer_size = ouroboros::detail::buffer_format::compute_buffer_size(
        chunk_target_size, chunk_count);
    auto buffer = create_aligned_buffer(buffer_size);
    std::span<uint8_t> buffer_span(buffer);

    ouroboros::writer writer;
    writer.configure(buffer_span, chunk_target_size, chunk_count);

    // Calculate how many 4-byte entries fit exactly
    // Entry size: 4 bytes header + 4 bytes payload = 8 bytes total
    // Each entry is already 4-byte aligned
    constexpr std::size_t entry_payload_size = 4;
    constexpr std::size_t entry_total_size =
        ouroboros::detail::buffer_format::entry_header_size +
        entry_payload_size;
    ASSERT_EQ(entry_total_size, 8); // entry_total_size = 4 + 4 = 8 bytes

    // Calculate usable space: buffer_size - (header + chunk_table) - alignment
    constexpr std::size_t header_and_table =
        ouroboros::detail::buffer_format::buffer_header_size +
        (chunk_count * ouroboros::detail::buffer_format::chunk_row_size);
    ASSERT_EQ(header_and_table,
              88); // header_and_table = 24 + (4 * 16) = 88 bytes
    // First chunk starts at 88, which is already 4-byte aligned
    const std::size_t usable_space = buffer_size - header_and_table;
    ASSERT_EQ(usable_space,
              1024); // usable_space = (24 + 64 + 1024) - 88 = 1024 bytes

    // Calculate entries per chunk
    constexpr std::size_t entries_per_chunk =
        chunk_target_size / entry_total_size;
    ASSERT_EQ(entries_per_chunk,
              32); // entries_per_chunk = 256 / 8 = 32 entries

    // Total entries that fit exactly: 4 chunks * 32 entries = 128 entries
    constexpr std::size_t total_entries = chunk_count * entries_per_chunk;
    ASSERT_EQ(total_entries, 128); // total_entries = 4 * 32 = 128 entries

    // Step 1: Write exactly enough small 4-byte entries to fill the buffer
    for (std::size_t i = 0; i < total_entries; ++i)
    {
        std::string entry_data(entry_payload_size, 'A' + (i % 26));
        writer.write(entry_data);
    }

    ASSERT_EQ(writer.total_entries_written(), total_entries);

    // Step 2: Reader reads all entries and verifies they are all valid
    // Store entries in a map keyed by chunk token
    std::map<uint64_t, std::vector<ouroboros::reader::entry>> entries_by_token;
    ouroboros::reader reader;
    auto result = reader.configure(std::span<const uint8_t>(buffer_span));
    ASSERT_TRUE(result.has_value());

    auto read_and_add_entry =
        [&](std::size_t i) -> const ouroboros::reader::entry&
    {
        auto entry_result = reader.read_next_entry();
        SCOPED_TRACE(::testing::Message() << "Failed to read entry " << i);
        EXPECT_TRUE(entry_result.has_value());
        EXPECT_TRUE(entry_result->is_valid());
        entries_by_token[entry_result->chunk_token].push_back(
            entry_result.value());
        return entries_by_token[entry_result->chunk_token].back();
    };

    // Track the first entry to determine starting sequence number
    uint64_t first_sequence = 1;
    for (std::size_t i = 0; i < total_entries; ++i)
    {
        const auto& entry = read_and_add_entry(i);
        // Verify sequence numbers are sequential
        EXPECT_EQ(entry.sequence_number, first_sequence + i)
            << "Entry " << i << " should have sequence number "
            << (first_sequence + i) << " (starting from " << first_sequence
            << ")";
    }

    // Verify sequence numbers within each chunk
    // Chunk tokens should be: 0, 32, 64, 96 (entries_per_chunk = 32)
    for (const auto& [token, entries] : entries_by_token)
    {
        for (std::size_t i = 0; i < entries.size(); ++i)
        {
            const auto& entry = entries[i];
            uint64_t expected_sequence = token + i + 1;
            EXPECT_EQ(entry.sequence_number, expected_sequence)
                << "Entry at position " << i << " in chunk with token " << token
                << " should have sequence number " << expected_sequence;
        }
    }

    // Verify no more entries
    {
        auto no_more = reader.read_next_entry();
        EXPECT_FALSE(no_more.has_value())
            << "Should have no more entries but got entry with sequence number "
            << no_more.value().sequence_number;
    }

    // Step 3: Writer writes another small 4-byte entry
    // This should cause a wrap and invalidate entries from chunk 0
    writer.write("WRAP");

    // Find the minimum token (chunk 0 entries) - map is ordered by key
    ASSERT_FALSE(entries_by_token.empty()) << "Should have entries";

    // Verify that entries from chunk 0 are now invalid
    ASSERT_TRUE(entries_by_token.find(0) != entries_by_token.end());
    for (const auto& entry : entries_by_token[0])
    {
        EXPECT_FALSE(entry.is_valid()) << "Entry from chunk 0 (token " << 0
                                       << ") should be invalid after wrap";
    }

    // Entries from other chunks should still be valid (for now)
    for (auto& [token, entries] : entries_by_token)
    {
        if (token != 0)
        {
            for (const auto& entry : entries)
            {
                EXPECT_TRUE(entry.is_valid())
                    << "Entry from token " << token
                    << " should still be valid after first wrap";
            }
        }
    }

    // Step 4: Writer writes a large entry that spans remaining bytes of first
    // chunk and spills into second and third chunks
    // After "WRAP" entry, we're at: start_of_chunk_0 + 8 bytes
    // We want an entry that:
    // - Uses remaining space in chunk 0: chunk_target_size - 8 = 248 bytes
    // - Spills into all of chunk 1: chunk_target_size = 256 bytes
    // - Spills into all of chunk 2: chunk_target_size = 256 bytes
    // - Total space needed: 248 + 256 + 256 = 760 bytes
    // - Entry header is 4 bytes, so payload: 760 - 4 = 756 bytes
    constexpr std::size_t remaining_in_chunk_0 =
        chunk_target_size - entry_total_size;
    constexpr std::size_t large_entry_payload_size =
        remaining_in_chunk_0 + chunk_target_size + chunk_target_size -
        ouroboros::detail::buffer_format::entry_header_size;
    // large_entry_payload_size = (256 - 8) + 256 + 256 - 4 = 756 bytes

    std::string large_entry(large_entry_payload_size, 'L');
    writer.write(large_entry);

    // Now entries from chunks 0, 1, and 2 should be invalid
    // Only entries from chunk 3 should remain valid
    // Keys in the maps are sorted in ascending order. So the highest token is
    // the last key.
    uint64_t highest_token = entries_by_token.rbegin()->first;

    std::vector<uint64_t> invalid_tokens;
    for (const auto& [token, entries] : entries_by_token)
    {
        for (const auto& entry : entries)
        {
            ASSERT_GE(highest_token, token);
            if (token == highest_token)
            {
                // Entries from chunk 3 (highest token) should still be valid
                EXPECT_TRUE(entry.is_valid())
                    << "Entry from token " << token
                    << " (chunk 3) should still be valid after large entry";
            }
            else
            {
                // Entries from chunks 0, 1, and 2 should be invalid
                EXPECT_FALSE(entry.is_valid())
                    << "Entry from token " << token << " (chunk "
                    << std::distance(std::begin(entries_by_token),
                                     entries_by_token.find(token))
                    << ") should be invalid after large entry " << entry.data;
                invalid_tokens.push_back(token);
            }
        }
    }

    // Remove the invalid tokens from the map
    for (const auto& token : invalid_tokens)
    {
        entries_by_token.erase(token);
    }

    // Read the wrap entry
    auto wrap_entry = read_and_add_entry(total_entries + 1);
    EXPECT_EQ(wrap_entry.data, "WRAP");
    // Verify sequence number: should be total_entries + 1 = 129
    EXPECT_EQ(wrap_entry.sequence_number, total_entries + 1)
        << "WRAP entry should have sequence number " << (total_entries + 1);
    // Read the large entry
    auto read_large_entry = read_and_add_entry(total_entries + 2);
    EXPECT_EQ(read_large_entry.data, large_entry);
    // Verify sequence number: should be total_entries + 2 = 130
    EXPECT_EQ(read_large_entry.sequence_number, total_entries + 2)
        << "Large entry should have sequence number " << (total_entries + 2);

    // Verify no more entries
    {
        auto no_more = reader.read_next_entry();
        EXPECT_FALSE(no_more.has_value());
    }

    // Step 5: Write another large entry that causes a wrap and overwrites the
    // small wrap entry and the very large entry from the prior wrap event.
    // We need to calculate how much space remains after the large entry
    // The large entry ends somewhere in chunk 2, so we need an entry that:
    // - Fills remaining space to end of buffer plus some addtional data to
    //   trigger the wrap.
    // - Wraps and invalidates the "WRAP" entry and the large entry

    // Calculate remaining space after large entry
    std::size_t remaining_space = usable_space;

    // Subtract the WRAP entry
    remaining_space -= entry_total_size;

    // Subtract the large entry
    remaining_space -= large_entry_payload_size;

    // Calculate the size of the large entry that will cause the wrap
    std::size_t wrap_entry_size = remaining_space + 1;
    std::string large_wrap_entry =
        "WR" + std::string(wrap_entry_size - 3, 'A') + 'P';
    ASSERT_EQ(large_wrap_entry.size(), wrap_entry_size);
    writer.write(large_wrap_entry);

    // Read the large wrap entry
    auto read_large_wrap_entry = read_and_add_entry(total_entries + 3);
    EXPECT_EQ(read_large_wrap_entry.data, large_wrap_entry);
    // Verify sequence number: should be total_entries + 3 = 131
    EXPECT_EQ(read_large_wrap_entry.sequence_number, total_entries + 3)
        << "Large wrap entry should have sequence number "
        << (total_entries + 3);

    {
        auto no_more = reader.read_next_entry();
        EXPECT_FALSE(no_more.has_value());
    }

    // After this wrap, the "WRAP" entry and the large entry should be
    // overwritten and invalidated.
    EXPECT_FALSE(wrap_entry.is_valid());
    EXPECT_FALSE(read_large_entry.is_valid());

    // Verify we can read the new entries with a fresh reader
    ouroboros::reader reader2;
    auto result2 = reader2.configure(std::span<const uint8_t>(buffer_span));
    ASSERT_TRUE(result2.has_value());

    // Should be able to read just the large wrap entry
    auto read_large_wrap_entry2 = reader2.read_next_entry();
    ASSERT_TRUE(read_large_wrap_entry2.has_value());
    EXPECT_EQ(read_large_wrap_entry2.value().data, large_wrap_entry);
    // Verify sequence number: should be total_entries + 3 = 131
    EXPECT_EQ(read_large_wrap_entry2.value().sequence_number, total_entries + 3)
        << "Large wrap entry from fresh reader should have sequence number "
        << (total_entries + 3);

    // Verify no more entries
    {
        auto no_more = reader2.read_next_entry();
        EXPECT_FALSE(no_more.has_value());
    }
}

// ============================================================================
// Writer Takeover Tests
// ============================================================================

TEST(test_reader_writer, writer_takeover_succeeds_with_matching_params)
{
    constexpr std::size_t chunk_target_size = 1024;
    constexpr std::size_t chunk_count = 4;
    constexpr uint64_t buffer_id = 42;
    auto buffer_size = ouroboros::detail::buffer_format::compute_buffer_size(
        chunk_target_size, chunk_count);
    auto buffer = create_aligned_buffer(buffer_size);
    std::span<uint8_t> buffer_span(buffer);

    // First writer writes some entries
    {
        ouroboros::writer writer1;
        auto result = writer1.configure(buffer_span, chunk_target_size,
                                        chunk_count, buffer_id);
        ASSERT_TRUE(result.has_value()) << result.error().message();

        writer1.write("Entry 1");
        writer1.write("Entry 2");
        writer1.write("Entry 3");
        EXPECT_EQ(writer1.total_entries_written(), 3U);
    }

    // Second writer takes over with same parameters
    {
        ouroboros::writer writer2;
        auto result = writer2.configure(buffer_span, chunk_target_size,
                                        chunk_count, buffer_id);
        ASSERT_TRUE(result.has_value()) << result.error().message();

        // Should continue from where writer1 left off
        EXPECT_EQ(writer2.total_entries_written(), 3U);

        // Write more entries
        writer2.write("Entry 4");
        writer2.write("Entry 5");
        EXPECT_EQ(writer2.total_entries_written(), 5U);
    }

    // Reader should be able to read all entries
    ouroboros::reader reader;
    auto result = reader.configure(std::span<const uint8_t>(buffer_span));
    ASSERT_TRUE(result.has_value()) << result.error().message();

    std::vector<std::string> expected = {"Entry 1", "Entry 2", "Entry 3",
                                         "Entry 4", "Entry 5"};
    for (const auto& expected_entry : expected)
    {
        auto entry = reader.read_next_entry();
        ASSERT_TRUE(entry.has_value()) << entry.error().message();
        EXPECT_EQ(entry->data, expected_entry);
    }

    auto no_more = reader.read_next_entry();
    EXPECT_FALSE(no_more.has_value());
}

TEST(test_reader_writer, writer_reinitializes_on_version_mismatch)
{
    constexpr std::size_t chunk_target_size = 1024;
    constexpr std::size_t chunk_count = 4;
    auto buffer_size = ouroboros::detail::buffer_format::compute_buffer_size(
        chunk_target_size, chunk_count);
    auto buffer = create_aligned_buffer(buffer_size);
    std::span<uint8_t> buffer_span(buffer);

    // First writer initializes the buffer
    ouroboros::writer writer1;
    auto result1 =
        writer1.configure(buffer_span, chunk_target_size, chunk_count);
    ASSERT_TRUE(result1.has_value());
    writer1.write("Entry 1");

    // Corrupt the version in the buffer
    uint32_t bad_version = 0xDEADBEEF;
    std::memcpy(buffer.data() + 8, &bad_version, sizeof(bad_version));

    // Second writer should reinitialize (corrupted version = not initialized)
    ouroboros::writer writer2;
    auto result2 =
        writer2.configure(buffer_span, chunk_target_size, chunk_count);
    ASSERT_TRUE(result2.has_value());

    // Should start fresh since buffer was reinitialized
    EXPECT_EQ(writer2.total_entries_written(), 0U);

    writer2.write("Entry 2");
    EXPECT_EQ(writer2.total_entries_written(), 1U);

    // Reader should only see the new entry
    ouroboros::reader reader;
    auto result = reader.configure(std::span<const uint8_t>(buffer_span));
    ASSERT_TRUE(result.has_value());

    auto entry = reader.read_next_entry();
    ASSERT_TRUE(entry.has_value());
    EXPECT_EQ(entry->data, "Entry 2");
}

TEST(test_reader_writer, writer_takeover_fails_with_chunk_count_mismatch)
{
    constexpr std::size_t chunk_target_size = 1024;
    constexpr std::size_t chunk_count_initial = 4;
    constexpr std::size_t chunk_count_different = 3; // Different but smaller
    // Use the larger buffer size to accommodate both configurations
    auto buffer_size = ouroboros::detail::buffer_format::compute_buffer_size(
        chunk_target_size, chunk_count_initial);
    auto buffer = create_aligned_buffer(buffer_size);
    std::span<uint8_t> buffer_span(buffer);

    // First writer initializes with chunk_count = 4
    ouroboros::writer writer1;
    auto result1 =
        writer1.configure(buffer_span, chunk_target_size, chunk_count_initial);
    ASSERT_TRUE(result1.has_value());
    writer1.write("Entry 1");

    // Second writer tries to take over with different (smaller) chunk_count
    // The buffer is large enough, but the header says chunk_count = 4
    ouroboros::writer writer2;
    // Use a subspan that matches the smaller configuration size
    auto smaller_buffer_size =
        ouroboros::detail::buffer_format::compute_buffer_size(
            chunk_target_size, chunk_count_different);
    auto result2 =
        writer2.configure(buffer_span.subspan(0, smaller_buffer_size),
                          chunk_target_size, chunk_count_different);
    ASSERT_FALSE(result2.has_value());
    EXPECT_EQ(result2.error(),
              ouroboros::make_error_code(
                  ouroboros::error::takeover_chunk_count_mismatch));
}

// Note: writer_takeover_fails_with_buffer_size_mismatch test removed
// The buffer size mismatch error is unreachable because the initial VERIFY
// in configure() checks buffer.size() >= expected_buffer_size before the
// takeover logic runs. The takeover_buffer_size_mismatch error code exists
// for completeness but can't be triggered in practice.

TEST(test_reader_writer, writer_takeover_fails_with_buffer_id_mismatch)
{
    constexpr std::size_t chunk_target_size = 1024;
    constexpr std::size_t chunk_count = 4;
    constexpr uint64_t buffer_id_1 = 100;
    constexpr uint64_t buffer_id_2 = 200;
    auto buffer_size = ouroboros::detail::buffer_format::compute_buffer_size(
        chunk_target_size, chunk_count);
    auto buffer = create_aligned_buffer(buffer_size);
    std::span<uint8_t> buffer_span(buffer);

    // First writer initializes with buffer_id_1
    ouroboros::writer writer1;
    auto result1 = writer1.configure(buffer_span, chunk_target_size,
                                     chunk_count, buffer_id_1);
    ASSERT_TRUE(result1.has_value());
    writer1.write("Entry 1");

    // Second writer tries to take over with different buffer_id
    ouroboros::writer writer2;
    auto result2 = writer2.configure(buffer_span, chunk_target_size,
                                     chunk_count, buffer_id_2);
    ASSERT_FALSE(result2.has_value());
    EXPECT_EQ(result2.error(),
              ouroboros::make_error_code(
                  ouroboros::error::takeover_buffer_id_mismatch));
}

TEST(test_reader_writer, writer_force_takeover_reinitializes_with_different_id)
{
    constexpr std::size_t chunk_target_size = 1024;
    constexpr std::size_t chunk_count = 4;
    constexpr uint64_t buffer_id_1 = 100;
    constexpr uint64_t buffer_id_2 = 200;
    auto buffer_size = ouroboros::detail::buffer_format::compute_buffer_size(
        chunk_target_size, chunk_count);
    auto buffer = create_aligned_buffer(buffer_size);
    std::span<uint8_t> buffer_span(buffer);

    // First writer initializes with buffer_id_1
    {
        ouroboros::writer writer1;
        auto result1 = writer1.configure(buffer_span, chunk_target_size,
                                         chunk_count, buffer_id_1);
        ASSERT_TRUE(result1.has_value());
        writer1.write("Entry 1");
        writer1.write("Entry 2");
        EXPECT_EQ(writer1.buffer_id(), buffer_id_1);
    }

    // Second writer force takeover with different buffer_id
    // This reinitializes the buffer, losing old entries
    {
        ouroboros::writer writer2;
        auto result2 = writer2.configure(buffer_span, chunk_target_size,
                                         chunk_count, buffer_id_2,
                                         true); // force_takeover = true
        ASSERT_TRUE(result2.has_value()) << result2.error().message();

        // Buffer ID should be updated
        EXPECT_EQ(writer2.buffer_id(), buffer_id_2);

        // Should start fresh (force_takeover reinitializes)
        EXPECT_EQ(writer2.total_entries_written(), 0U);

        writer2.write("Entry 3");
        EXPECT_EQ(writer2.total_entries_written(), 1U);
    }

    // Reader should see the new buffer_id and only the new entry
    ouroboros::reader reader;
    auto result = reader.configure(std::span<const uint8_t>(buffer_span));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(reader.buffer_id(), buffer_id_2);

    auto entry = reader.read_next_entry();
    ASSERT_TRUE(entry.has_value());
    EXPECT_EQ(entry->data, "Entry 3");

    // No more entries
    auto no_more = reader.read_next_entry();
    EXPECT_FALSE(no_more.has_value());
}

TEST(test_reader_writer, writer_takeover_after_wrap)
{
    constexpr std::size_t chunk_target_size = 64; // Small chunks to force wraps
    constexpr std::size_t chunk_count = 2;
    constexpr uint64_t buffer_id = 42;
    auto buffer_size = ouroboros::detail::buffer_format::compute_buffer_size(
        chunk_target_size, chunk_count);
    auto buffer = create_aligned_buffer(buffer_size);
    std::span<uint8_t> buffer_span(buffer);

    // First writer writes entries causing wraps
    std::size_t entries_written_by_first = 0;
    {
        ouroboros::writer writer1;
        auto result = writer1.configure(buffer_span, chunk_target_size,
                                        chunk_count, buffer_id);
        ASSERT_TRUE(result.has_value());

        // Write enough entries to cause at least one wrap
        for (int i = 0; i < 15; ++i)
        {
            std::string entry = "Entry " + std::to_string(i);
            writer1.write(entry);
        }
        entries_written_by_first = writer1.total_entries_written();
    }

    // Second writer takes over
    {
        ouroboros::writer writer2;
        auto result = writer2.configure(buffer_span, chunk_target_size,
                                        chunk_count, buffer_id);
        ASSERT_TRUE(result.has_value()) << result.error().message();

        // Should have the same total entries written
        EXPECT_EQ(writer2.total_entries_written(), entries_written_by_first);

        // Write more entries
        writer2.write("New Entry A");
        writer2.write("New Entry B");
    }

    // Reader should be able to read entries (at least the latest ones)
    ouroboros::reader reader;
    auto result = reader.configure(std::span<const uint8_t>(buffer_span));
    ASSERT_TRUE(result.has_value());

    int read_count = 0;
    bool found_new_entries = false;
    while (read_count < 100)
    {
        auto entry = reader.read_next_entry();
        if (!entry.has_value())
        {
            break;
        }
        read_count++;
        if (entry->data == "New Entry A" || entry->data == "New Entry B")
        {
            found_new_entries = true;
        }
    }

    EXPECT_GT(read_count, 0);
    EXPECT_TRUE(found_new_entries)
        << "Should be able to read entries written by the second writer";
}

TEST(test_reader_writer, writer_takeover_fails_after_finish)
{
    constexpr std::size_t chunk_target_size = 1024;
    constexpr std::size_t chunk_count = 4;
    constexpr uint64_t buffer_id = 42;
    auto buffer_size = ouroboros::detail::buffer_format::compute_buffer_size(
        chunk_target_size, chunk_count);
    auto buffer = create_aligned_buffer(buffer_size);
    std::span<uint8_t> buffer_span(buffer);

    // First writer writes entries and finishes
    {
        ouroboros::writer writer1;
        auto result = writer1.configure(buffer_span, chunk_target_size,
                                        chunk_count, buffer_id);
        ASSERT_TRUE(result.has_value());
        writer1.write("Entry 1");
        writer1.write("Entry 2");
        writer1.finish();
    }

    // Second writer tries peaceful takeover - should fail because writer
    // finished
    {
        ouroboros::writer writer2;
        auto result = writer2.configure(buffer_span, chunk_target_size,
                                        chunk_count, buffer_id);
        ASSERT_FALSE(result.has_value());
        EXPECT_EQ(result.error(),
                  ouroboros::make_error_code(
                      ouroboros::error::takeover_writer_finished));
    }

    // With force_takeover, the buffer is reinitialized
    {
        ouroboros::writer writer3;
        auto result = writer3.configure(buffer_span, chunk_target_size,
                                        chunk_count, buffer_id, true);
        ASSERT_TRUE(result.has_value()) << result.error().message();

        // Should start fresh
        EXPECT_EQ(writer3.total_entries_written(), 0U);

        writer3.write("Entry 3");
        EXPECT_EQ(writer3.total_entries_written(), 1U);
    }

    // Fresh reader should only see the new entry
    ouroboros::reader reader;
    auto result = reader.configure(std::span<const uint8_t>(buffer_span));
    ASSERT_TRUE(result.has_value());

    auto entry = reader.read_next_entry();
    ASSERT_TRUE(entry.has_value());
    EXPECT_EQ(entry->data, "Entry 3");

    auto no_more = reader.read_next_entry();
    EXPECT_FALSE(no_more.has_value());
}

TEST(test_reader_writer, writer_takeover_fresh_buffer)
{
    // Test that configure on a fresh (uninitialized) buffer still works
    constexpr std::size_t chunk_target_size = 1024;
    constexpr std::size_t chunk_count = 4;
    auto buffer_size = ouroboros::detail::buffer_format::compute_buffer_size(
        chunk_target_size, chunk_count);
    auto buffer = create_aligned_buffer(buffer_size);
    std::span<uint8_t> buffer_span(buffer);

    // Buffer is zeroed, not initialized
    std::memset(buffer.data(), 0, buffer.size());

    ouroboros::writer writer;
    auto result =
        writer.configure(buffer_span, chunk_target_size, chunk_count, 123);
    ASSERT_TRUE(result.has_value()) << result.error().message();

    EXPECT_EQ(writer.total_entries_written(), 0U);
    EXPECT_EQ(writer.buffer_id(), 123U);

    writer.write("Test Entry");
    EXPECT_EQ(writer.total_entries_written(), 1U);

    ouroboros::reader reader;
    auto reader_result =
        reader.configure(std::span<const uint8_t>(buffer_span));
    ASSERT_TRUE(reader_result.has_value());

    auto entry = reader.read_next_entry();
    ASSERT_TRUE(entry.has_value());
    EXPECT_EQ(entry->data, "Test Entry");
}

TEST(test_reader_writer, writer_force_takeover_with_chunk_count_mismatch)
{
    constexpr std::size_t chunk_target_size = 1024;
    constexpr std::size_t chunk_count_initial = 4;
    constexpr std::size_t chunk_count_new = 3;
    // Use the larger buffer size to accommodate both configurations
    auto buffer_size = ouroboros::detail::buffer_format::compute_buffer_size(
        chunk_target_size, chunk_count_initial);
    auto buffer = create_aligned_buffer(buffer_size);
    std::span<uint8_t> buffer_span(buffer);

    // First writer initializes with chunk_count = 4
    {
        ouroboros::writer writer1;
        auto result = writer1.configure(buffer_span, chunk_target_size,
                                        chunk_count_initial);
        ASSERT_TRUE(result.has_value());
        writer1.write("Entry 1");
        writer1.write("Entry 2");
    }

    // Second writer force takeover with different chunk_count
    {
        ouroboros::writer writer2;
        auto result = writer2.configure(buffer_span, chunk_target_size,
                                        chunk_count_new, 0, true);
        ASSERT_TRUE(result.has_value()) << result.error().message();

        // Should start fresh (buffer reinitialized)
        EXPECT_EQ(writer2.total_entries_written(), 0U);
        EXPECT_EQ(writer2.chunk_count(), chunk_count_new);

        writer2.write("Entry 3");
        EXPECT_EQ(writer2.total_entries_written(), 1U);
    }

    // Reader should only see the new entry
    ouroboros::reader reader;
    auto result = reader.configure(std::span<const uint8_t>(buffer_span));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(reader.chunk_count(), chunk_count_new);

    auto entry = reader.read_next_entry();
    ASSERT_TRUE(entry.has_value());
    EXPECT_EQ(entry->data, "Entry 3");
}

// ============================================================================
// Parameterized Takeover Tests - Efficiently test all failure/recovery cases
// ============================================================================

struct TakeoverTestCase
{
    std::string name;
    ouroboros::error expected_error;
    // Setup function that creates the mismatch condition
    std::function<void(std::span<uint8_t>, std::size_t, std::size_t, uint64_t)>
        setup_mismatch;
    // Parameters for second writer (chunk_target_size, chunk_count, buffer_id)
    std::size_t second_chunk_target_size;
    std::size_t second_chunk_count;
    uint64_t second_buffer_id;
};

class WriterTakeoverTest : public ::testing::TestWithParam<TakeoverTestCase>
{
protected:
    static constexpr std::size_t kChunkTargetSize = 1024;
    static constexpr std::size_t kChunkCount = 4;
    static constexpr uint64_t kBufferId = 42;

    void SetUp() override
    {
        buffer_size_ =
            ouroboros::detail::buffer_format::compute_buffer_size(
                kChunkTargetSize, kChunkCount);
        buffer_ = create_aligned_buffer(buffer_size_);
        buffer_span_ = std::span<uint8_t>(buffer_);
    }

    std::size_t buffer_size_;
    std::vector<uint8_t> buffer_;
    std::span<uint8_t> buffer_span_;
};

TEST_P(WriterTakeoverTest, peaceful_takeover_fails_then_force_succeeds)
{
    const auto& test_case = GetParam();

    // First writer initializes the buffer
    {
        ouroboros::writer writer1;
        auto result = writer1.configure(buffer_span_, kChunkTargetSize,
                                        kChunkCount, kBufferId);
        ASSERT_TRUE(result.has_value()) << result.error().message();
        writer1.write("Original Entry");
    }

    // Apply the mismatch setup if provided
    if (test_case.setup_mismatch)
    {
        test_case.setup_mismatch(buffer_span_, kChunkTargetSize, kChunkCount,
                                 kBufferId);
    }

    // Peaceful takeover should fail with expected error
    {
        ouroboros::writer writer2;
        auto result = writer2.configure(
            buffer_span_, test_case.second_chunk_target_size,
            test_case.second_chunk_count, test_case.second_buffer_id, false);
        ASSERT_FALSE(result.has_value())
            << "Peaceful takeover should fail for: " << test_case.name;
        EXPECT_EQ(result.error(),
                  ouroboros::make_error_code(test_case.expected_error))
            << "Wrong error for: " << test_case.name;
    }

    // Force takeover should succeed
    {
        ouroboros::writer writer3;
        auto result = writer3.configure(
            buffer_span_, test_case.second_chunk_target_size,
            test_case.second_chunk_count, test_case.second_buffer_id, true);
        ASSERT_TRUE(result.has_value())
            << "Force takeover should succeed for: " << test_case.name
            << " error: " << result.error().message();

        // Should start fresh
        EXPECT_EQ(writer3.total_entries_written(), 0U);

        writer3.write("New Entry");
        EXPECT_EQ(writer3.total_entries_written(), 1U);
    }

    // Verify the new entry is readable
    ouroboros::reader reader;
    auto result = reader.configure(std::span<const uint8_t>(buffer_span_));
    ASSERT_TRUE(result.has_value());

    auto entry = reader.read_next_entry();
    ASSERT_TRUE(entry.has_value());
    EXPECT_EQ(entry->data, "New Entry");
}

INSTANTIATE_TEST_SUITE_P(
    TakeoverCases, WriterTakeoverTest,
    ::testing::Values(
        TakeoverTestCase{
            "chunk_count_mismatch",
            ouroboros::error::takeover_chunk_count_mismatch,
            nullptr, // No buffer modification needed
            1024,    // same chunk_target_size
            3,       // different chunk_count
            42       // same buffer_id
        },
        TakeoverTestCase{
            "buffer_id_mismatch",
            ouroboros::error::takeover_buffer_id_mismatch,
            nullptr, // No buffer modification needed
            1024,    // same chunk_target_size
            4,       // same chunk_count
            999      // different buffer_id
        },
        TakeoverTestCase{
            "writer_finished",
            ouroboros::error::takeover_writer_finished,
            [](std::span<uint8_t> buffer, std::size_t chunk_target_size,
               std::size_t chunk_count, uint64_t buffer_id) {
                // Call finish on the buffer
                ouroboros::writer finisher;
                auto result = finisher.configure(buffer, chunk_target_size,
                                                 chunk_count, buffer_id);
                if (result.has_value())
                {
                    finisher.finish();
                }
            },
            1024, // same chunk_target_size
            4,    // same chunk_count
            42    // same buffer_id
        }),
    [](const ::testing::TestParamInfo<TakeoverTestCase>& info) {
        return info.param.name;
    });

TEST(test_reader_writer, writer_configure_returns_expected)
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

TEST(test_reader_writer, multi_threaded_with_wraps)
{
    // Use a small buffer to force multiple wraps
    constexpr std::size_t chunk_target_size = 1024;
    constexpr std::size_t chunk_count = 42;
    auto buffer_size = ouroboros::detail::buffer_format::compute_buffer_size(
        chunk_target_size, chunk_count);
    auto buffer = create_aligned_buffer(buffer_size);
    std::span<uint8_t> buffer_span(buffer);

    ouroboros::writer writer;
    writer.configure(buffer_span, chunk_target_size, chunk_count);

    // Test parameters
    constexpr int num_reader_threads = 10;
    constexpr std::chrono::seconds test_duration(5);
    constexpr int entries_per_batch = 4;

    // Synchronization
    std::atomic<bool> writer_running{true};
    std::atomic<std::uint64_t> entries_written{0};
    std::atomic<std::uint64_t> total_reads{0};
    std::atomic<std::uint64_t> valid_reads{0};
    std::atomic<std::uint64_t> invalid_reads{0};
    std::mutex read_entries_mutex;
    std::vector<std::string> read_entries; // All reads (may have duplicates)
    std::set<std::string> unique_read_entries; // Unique entries read

    // Reader threads - continuously read entries
    std::vector<std::thread> reader_threads;
    for (int t = 0; t < num_reader_threads; ++t)
    {
        reader_threads.emplace_back(
            [&, t]()
            {
                ouroboros::reader reader;

                // Retry configuration until buffer is ready (writer may not
                // have started yet)
                auto result =
                    reader.configure(std::span<const uint8_t>(buffer_span));
                while (!result.has_value() && writer_running.load())
                {
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                    result =
                        reader.configure(std::span<const uint8_t>(buffer_span));
                }
                ASSERT_TRUE(result.has_value());

                int consecutive_failures = 0;
                constexpr int max_consecutive_failures = 1000;

                while (writer_running.load() ||
                       consecutive_failures < max_consecutive_failures)
                {
                    auto entry_result = reader.read_next();
                    if (entry_result.has_value())
                    {
                        consecutive_failures = 0;

                        // Store the entry string for verification
                        {
                            std::lock_guard<std::mutex> lock(
                                read_entries_mutex);
                            total_reads.fetch_add(1, std::memory_order_relaxed);
                            valid_reads.fetch_add(1, std::memory_order_relaxed);
                            read_entries.push_back(entry_result.value());
                            unique_read_entries.insert(entry_result.value());
                        }
                    }
                    else
                    {
                        consecutive_failures++;
                        // Small delay when no data available
                        // Increase delay as failures accumulate to avoid
                        // busy-waiting
                        std::this_thread::sleep_for(std::chrono::microseconds(
                            10 + consecutive_failures));
                    }
                }
            });
    }

    // Writer runs in main thread - continuously writes entries
    int entry_counter = 0;
    auto start_time = std::chrono::steady_clock::now();

    while (writer_running.load())
    {
        // Write a batch of entries
        for (int i = 0; i < entries_per_batch; ++i)
        {
            // Generate unique entry: include counter, timestamp, and unique
            // data
            std::string entry = "ENTRY_" + std::to_string(entry_counter) + "_" +
                                std::to_string(std::chrono::steady_clock::now()
                                                   .time_since_epoch()
                                                   .count()) +
                                "_";

            // Pad to target size with unique data
            std::size_t target_size = chunk_target_size * 1.5;
            while (entry.size() < target_size)
            {
                // Use entry_counter in a way that ensures uniqueness
                entry += std::to_string(entry_counter * 1000 + entry.size());
            }

            writer.write(entry);
            entry_counter++;
            entries_written.fetch_add(1, std::memory_order_relaxed);
        }

        // Check if we should stop
        auto elapsed = std::chrono::steady_clock::now() - start_time;
        if (elapsed >= test_duration)
        {
            writer_running.store(false);
            break;
        }

        // Small delay to allow readers to catch up
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    // Give readers a moment to finish reading remaining entries
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Wait for all reader threads
    for (auto& thread : reader_threads)
    {
        thread.join();
    }

    // Verify test results
    auto writes = entries_written.load();
    auto reads = total_reads.load();
    auto valid = valid_reads.load();
    auto invalid = invalid_reads.load();

    // Get unique entries count (thread-safe, all readers are joined)
    std::size_t unique_count = unique_read_entries.size();

    // We should have written many entries
    EXPECT_GT(writes, 0U) << "Writer should have written some entries";

    // We should have read many entries (can be more than writes due to multiple
    // readers)
    EXPECT_GT(reads, 0U) << "Readers should have read some entries";

    // Most reads should be valid (some may be invalid due to overwrites during
    // wraps)
    EXPECT_GT(valid, 0U) << "Should have at least some valid reads";

    EXPECT_EQ(unique_count, writes)
        << "Unique entries read should be equal to entries written";
}
