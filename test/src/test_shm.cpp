// Copyright (c) 2026 Steinwurf ApS
// SPDX-License-Identifier: MIT

#include <ouroboros/shm_log_reader.hpp>
#include <ouroboros/shm_log_writer.hpp>

#include <ouroboros/error_code.hpp>

#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "test_helpers.hpp"

using test_helpers::generate_shm_name;

TEST(test_shm, writer_configure)
{
    constexpr std::size_t chunk_target_size = 1024;
    constexpr std::size_t chunk_count = 4;
    auto shm_name = generate_shm_name();

    ouroboros::shm_log_writer writer;
    auto result = writer.configure(shm_name, chunk_target_size, chunk_count);
    ASSERT_TRUE(result.has_value())
        << "Writer configuration failed: " << result.error().message();

    EXPECT_EQ(writer.chunk_target_size(), chunk_target_size);
    EXPECT_EQ(writer.chunk_count(), chunk_count);
    EXPECT_GT(writer.max_entry_size(), 0U);
    EXPECT_EQ(writer.shm_name(), shm_name);
    EXPECT_GT(writer.buffer_size(), 0U);
    EXPECT_EQ(writer.buffer_id(), 0U);
}

TEST(test_shm, buffer_id)
{
    constexpr std::size_t chunk_target_size = 1024;
    constexpr std::size_t chunk_count = 4;
    constexpr uint64_t test_buffer_id = 0xDEADBEEF12345678ULL;
    auto shm_name = generate_shm_name();

    ouroboros::shm_log_writer writer;
    auto writer_result = writer.configure(
        shm_name, chunk_target_size, chunk_count, test_buffer_id, false, false);
    ASSERT_TRUE(writer_result.has_value());

    EXPECT_EQ(writer.buffer_id(), test_buffer_id);

    writer.write("test entry");

    ouroboros::shm_log_reader reader;
    auto reader_result = reader.configure(shm_name);
    ASSERT_TRUE(reader_result.has_value());
    EXPECT_EQ(reader.buffer_id(), test_buffer_id);
}

TEST(test_shm, reader_configure_before_writer)
{
    auto shm_name = generate_shm_name();

    ouroboros::shm_log_reader reader;
    auto result = reader.configure(shm_name);
    EXPECT_FALSE(result.has_value())
        << "Reader should fail to configure before writer creates shm";
}

TEST(test_shm, writer_reader_basic)
{
    constexpr std::size_t chunk_target_size = 1024;
    constexpr std::size_t chunk_count = 4;
    auto shm_name = generate_shm_name();

    // Create writer
    ouroboros::shm_log_writer writer;
    auto writer_result =
        writer.configure(shm_name, chunk_target_size, chunk_count);
    ASSERT_TRUE(writer_result.has_value())
        << "Writer configuration failed: " << writer_result.error().message();

    // Create reader
    ouroboros::shm_log_reader reader;
    auto reader_result = reader.configure(shm_name);
    ASSERT_TRUE(reader_result.has_value())
        << "Reader configuration failed: " << reader_result.error().message();

    EXPECT_EQ(reader.chunk_count(), chunk_count);
    EXPECT_EQ(reader.shm_name(), shm_name);
    EXPECT_GT(reader.buffer_size(), 0U);
}

TEST(test_shm, write_single_entry)
{
    constexpr std::size_t chunk_target_size = 1024;
    constexpr std::size_t chunk_count = 4;
    auto shm_name = generate_shm_name();

    ouroboros::shm_log_writer writer;
    auto writer_result =
        writer.configure(shm_name, chunk_target_size, chunk_count);
    ASSERT_TRUE(writer_result.has_value())
        << "Writer configuration failed: " << writer_result.error().message();

    std::string test_entry = "Hello, World!";
    writer.write(test_entry);

    ouroboros::shm_log_reader reader;
    auto reader_result = reader.configure(shm_name);
    ASSERT_TRUE(reader_result.has_value())
        << "Reader configuration failed: " << reader_result.error().message();

    auto entry_result = reader.read_next_entry();
    ASSERT_TRUE(entry_result.has_value());
    EXPECT_EQ(entry_result->data, test_entry);
    EXPECT_TRUE(entry_result->is_valid());

    // Should be no more entries
    auto no_more = reader.read_next_entry();
    EXPECT_FALSE(no_more.has_value());
}

TEST(test_shm, write_multiple_entries)
{
    constexpr std::size_t chunk_target_size = 1024;
    constexpr std::size_t chunk_count = 4;
    auto shm_name = generate_shm_name();

    ouroboros::shm_log_writer writer;
    auto writer_result =
        writer.configure(shm_name, chunk_target_size, chunk_count);
    ASSERT_TRUE(writer_result.has_value());

    std::vector<std::string> test_entries = {"First entry", "Second entry",
                                             "Third entry", "Fourth entry",
                                             "Fifth entry"};

    for (const auto& entry : test_entries)
    {
        writer.write(entry);
    }

    ouroboros::shm_log_reader reader;
    auto reader_result = reader.configure(shm_name);
    ASSERT_TRUE(reader_result.has_value());

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

TEST(test_shm, writer_finish_reader_unlinks_shm)
{
    constexpr std::size_t chunk_target_size = 1024;
    constexpr std::size_t chunk_count = 4;
    auto shm_name = generate_shm_name();

    ouroboros::shm_log_writer writer;
    auto writer_result = writer.configure(shm_name, chunk_target_size,
                                          chunk_count, 0, false, false);
    ASSERT_TRUE(writer_result.has_value());

    writer.write("Entry 1");
    writer.write("Entry 2");
    writer.finish();

    ouroboros::shm_log_reader reader;
    auto reader_result = reader.configure(shm_name);
    ASSERT_TRUE(reader_result.has_value());

    auto entry1 = reader.read_next_entry();
    ASSERT_TRUE(entry1.has_value());
    EXPECT_EQ(entry1->data, "Entry 1");

    auto entry2 = reader.read_next_entry();
    ASSERT_TRUE(entry2.has_value());
    EXPECT_EQ(entry2->data, "Entry 2");

    // After finish entry, reader returns writer_finished and unlinks shm
    auto finish_result = reader.read_next_entry();
    ASSERT_FALSE(finish_result.has_value());
    EXPECT_EQ(finish_result.error(),
              ouroboros::make_error_code(ouroboros::error::writer_finished));

    // Subsequent reads keep returning writer_finished
    auto subsequent = reader.read_next_entry();
    ASSERT_FALSE(subsequent.has_value());
    EXPECT_EQ(subsequent.error(),
              ouroboros::make_error_code(ouroboros::error::writer_finished));

    // Release the writer's handle on the shared memory.
    // On POSIX, the reader's unlink_shm() already removed the name.
    // On Windows, unlink_shm() is a no-op — the named mapping persists until
    // all handles are closed. Resetting the writer closes its handle, allowing
    // the kernel to destroy the mapping object.
    writer = ouroboros::shm_log_writer{};

    // Shared memory should have been unlinked - new reader cannot attach
    ouroboros::shm_log_reader reader2;
    auto attach_result = reader2.configure(shm_name);
    EXPECT_FALSE(attach_result.has_value());
}

TEST(test_shm, reader_empty_buffer_handling)
{
    constexpr std::size_t chunk_target_size = 1024;
    constexpr std::size_t chunk_count = 4;
    auto shm_name = generate_shm_name();

    ouroboros::shm_log_writer writer;
    auto writer_result =
        writer.configure(shm_name, chunk_target_size, chunk_count);
    ASSERT_TRUE(writer_result.has_value());

    ouroboros::shm_log_reader reader;
    auto reader_result = reader.configure(shm_name);
    ASSERT_TRUE(reader_result.has_value());

    // Try to read from empty buffer - should fail
    auto entry_result = reader.read_next_entry();
    ASSERT_FALSE(entry_result.has_value());
    EXPECT_EQ(entry_result.error(),
              ouroboros::make_error_code(ouroboros::error::no_data_available));
}

TEST(test_shm, multiple_readers)
{
    constexpr std::size_t chunk_target_size = 1024;
    constexpr std::size_t chunk_count = 4;
    auto shm_name = generate_shm_name();

    ouroboros::shm_log_writer writer;
    auto writer_result =
        writer.configure(shm_name, chunk_target_size, chunk_count);
    ASSERT_TRUE(writer_result.has_value());

    std::vector<std::string> test_entries = {"One", "Two", "Three"};

    for (const auto& entry : test_entries)
    {
        writer.write(entry);
    }

    // Create multiple readers
    ouroboros::shm_log_reader reader1;
    auto result1 = reader1.configure(shm_name);
    ASSERT_TRUE(result1.has_value());

    ouroboros::shm_log_reader reader2;
    auto result2 = reader2.configure(shm_name);
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

TEST(test_shm, interleaved_operations)
{
    constexpr std::size_t chunk_target_size = 1024;
    constexpr std::size_t chunk_count = 4;
    auto shm_name = generate_shm_name();

    ouroboros::shm_log_writer writer;
    auto writer_result =
        writer.configure(shm_name, chunk_target_size, chunk_count);
    ASSERT_TRUE(writer_result.has_value());

    ouroboros::shm_log_reader reader;
    auto reader_result = reader.configure(shm_name);
    ASSERT_TRUE(reader_result.has_value());

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

TEST(test_shm, wrap_behavior)
{
    constexpr std::size_t chunk_target_size = 64; // Small chunk size
    constexpr std::size_t chunk_count = 2;
    auto shm_name = generate_shm_name();

    ouroboros::shm_log_writer writer;
    auto writer_result =
        writer.configure(shm_name, chunk_target_size, chunk_count);
    ASSERT_TRUE(writer_result.has_value());

    // Write enough entries to cause a wrap
    for (int i = 0; i < 20; ++i)
    {
        std::string entry = "Entry " + std::to_string(i);
        writer.write(entry);
    }

    // Reader should handle wrap correctly
    ouroboros::shm_log_reader reader;
    auto reader_result = reader.configure(shm_name);
    ASSERT_TRUE(reader_result.has_value());

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

TEST(test_shm, reader_is_ready)
{
    constexpr std::size_t chunk_target_size = 1024;
    constexpr std::size_t chunk_count = 4;
    auto shm_name = generate_shm_name();

    // Reader should not be ready before writer creates shm
    ouroboros::shm_log_reader reader;
    EXPECT_FALSE(reader.is_ready());

    // Create writer
    ouroboros::shm_log_writer writer;
    auto writer_result =
        writer.configure(shm_name, chunk_target_size, chunk_count);
    ASSERT_TRUE(writer_result.has_value());

    // Reader should still not be ready until configured
    EXPECT_FALSE(reader.is_ready());

    // Configure reader
    auto reader_result = reader.configure(shm_name);
    ASSERT_TRUE(reader_result.has_value());

    // Now reader should be ready
    EXPECT_TRUE(reader.is_ready());
}

TEST(test_shm, move_semantics)
{
    constexpr std::size_t chunk_target_size = 1024;
    constexpr std::size_t chunk_count = 4;
    auto shm_name = generate_shm_name();

    // Test writer move

    ouroboros::shm_log_writer writer1;
    auto result1 = writer1.configure(shm_name, chunk_target_size, chunk_count);
    ASSERT_TRUE(result1.has_value())
        << "Writer configuration failed: " << result1.error().message();

    writer1.write("Test entry");

    ouroboros::shm_log_writer writer2 = std::move(writer1);
    writer2.write("Another entry");

    // writer1 should be in a moved-from state
    // writer2 should work
    EXPECT_EQ(writer2.shm_name(), shm_name);

    // Test reader move
    {
        ouroboros::shm_log_reader reader1;
        auto result1 = reader1.configure(shm_name);
        ASSERT_TRUE(result1.has_value());

        auto read1 = reader1.read_next();
        ASSERT_TRUE(read1.has_value());
        EXPECT_EQ(read1.value(), "Test entry");

        ouroboros::shm_log_reader reader2 = std::move(reader1);
        EXPECT_EQ(reader2.shm_name(), shm_name);

        // Should be able to read entries
        auto read2 = reader2.read_next();
        ASSERT_TRUE(read2.has_value());
        EXPECT_EQ(read2.value(), "Another entry");
    }
}
