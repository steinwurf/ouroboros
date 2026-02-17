// Copyright (c) 2026 Steinwurf ApS
// SPDX-License-Identifier: MIT

#include <ouroboros/reader.hpp>
#include <ouroboros/writer.hpp>

#include <ouroboros/error_code.hpp>

#include <cstring>
#include <gtest/gtest.h>
#include <map>
#include <string>
#include <vector>

#include "test_helpers.hpp"

using test_helpers::create_aligned_buffer;

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

    // Configure writer with new ID using force_init to reinitialize buffer
    // This simulates a new writer taking over with a different ID
    // Note: force_init reinitializes the buffer, so "first" will be lost
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

    // Read entries - only "second" exists since force_init reinitialized
    auto entry1 = reader.read_next_entry();
    ASSERT_TRUE(entry1.has_value());
    EXPECT_EQ(entry1->data, "second");

    // No more entries
    auto no_more = reader.read_next_entry();
    EXPECT_FALSE(no_more.has_value());
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

TEST(test_reader_writer, interleaved_operations)
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
