// Copyright (c) 2023 Steinwurf ApS
// All Rights Reserved
//
// THIS IS UNPUBLISHED PROPRIETARY SOURCE CODE OF STEINWURF
// The copyright notice above does not evidence any
// actual or intended publication of such source code.

#include <ouroboros/shm_log_reader.hpp>
#include <ouroboros/shm_log_writer.hpp>

#include <ouroboros/error_code.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <gtest/gtest.h>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

namespace
{

// Helper to generate unique shared memory names for tests
auto generate_shm_name() -> std::string
{
    static std::atomic<uint32_t> counter{0};
    auto c = counter.fetch_add(1, std::memory_order_relaxed);
    auto pid = static_cast<uint32_t>(::getpid());

    // "/ouroboros_" (10) + pid (up to 10) + "_" (1) + counter (up to 10) = <= 31-ish
    return "/ouroboros_" + std::to_string(pid) + "_" + std::to_string(c);
}
}

TEST(test_shm_log, writer_configure)
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
}

TEST(test_shm_log, reader_configure_before_writer)
{
    auto shm_name = generate_shm_name();

    ouroboros::shm_log_reader reader;
    auto result = reader.configure(shm_name);
    EXPECT_FALSE(result.has_value())
        << "Reader should fail to configure before writer creates shm";
}

TEST(test_shm_log, writer_reader_basic)
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

TEST(test_shm_log, writer_write_single_entry)
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

TEST(test_shm_log, writer_write_multiple_entries)
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

TEST(test_shm_log, reader_empty_buffer_handling)
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
    EXPECT_EQ(entry_result.error(), ouroboros::make_error_code(ouroboros::error::no_data_available));
}

TEST(test_shm_log, multiple_readers)
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

TEST(test_shm_log, reader_writer_interleaved_operations)
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
    EXPECT_EQ(entry4.error(), ouroboros::make_error_code(ouroboros::error::no_data_available));
}

TEST(test_shm_log, wrap_behavior)
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

TEST(test_shm_log, single_writer_single_reader_threaded)
{
    constexpr std::size_t chunk_target_size = 1024;
    constexpr std::size_t chunk_count = 4;
    auto shm_name = generate_shm_name();

    ouroboros::shm_log_writer writer;
    auto writer_result =
        writer.configure(shm_name, chunk_target_size, chunk_count);
    ASSERT_TRUE(writer_result.has_value());

    // Synchronization
    std::atomic<bool> writer_running{true};
    std::atomic<int> entries_written{0};
    std::atomic<int> entries_read{0};
    std::vector<std::string> written_entries;
    std::vector<std::string> read_entries;
    std::mutex written_mutex;
    std::mutex read_mutex;

    // Reader thread
    std::thread reader_thread(
        [&]()
        {
            ouroboros::shm_log_reader reader;

            // Retry configuration until buffer is ready
            auto reader_result = reader.configure(shm_name);
            while (!reader_result.has_value() && writer_running.load())
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
                reader_result = reader.configure(shm_name);
            }
            ASSERT_TRUE(reader_result.has_value());

            int consecutive_failures = 0;
            constexpr int max_consecutive_failures = 1000;

            while (writer_running.load() ||
                   consecutive_failures < max_consecutive_failures)
            {
                auto entry_result = reader.read_next();
                if (entry_result.has_value())
                {
                    consecutive_failures = 0;
                    {
                        std::lock_guard<std::mutex> lock(read_mutex);
                        read_entries.push_back(entry_result.value());
                        entries_read.fetch_add(1);
                    }
                }
                else
                {
                    consecutive_failures++;
                    std::this_thread::sleep_for(std::chrono::microseconds(10));
                }
            }
        });

    // Writer runs in main thread
    constexpr int num_entries = 100;
    for (int i = 0; i < num_entries; ++i)
    {
        std::string entry = "Entry " + std::to_string(i);
        writer.write(entry);
        {
            std::lock_guard<std::mutex> lock(written_mutex);
            written_entries.push_back(entry);
        }
        entries_written.fetch_add(1);
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    writer_running.store(false);
    reader_thread.join();

    // Verify results
    EXPECT_EQ(entries_written.load(), num_entries);
    EXPECT_GT(entries_read.load(), 0);
    EXPECT_LE(entries_read.load(), num_entries);

    // Verify all read entries were actually written
    {
        std::lock_guard<std::mutex> lock_read(read_mutex);
        std::lock_guard<std::mutex> lock_written(written_mutex);
        for (const auto& read_entry : read_entries)
        {
            EXPECT_NE(std::find(written_entries.begin(), written_entries.end(),
                                read_entry),
                      written_entries.end())
                << "Read entry not found in written entries: " << read_entry;
        }
    }
}

TEST(test_shm_log, single_writer_multiple_readers_threaded)
{
    constexpr std::size_t chunk_target_size = 1024;
    constexpr std::size_t chunk_count = 4;
    auto shm_name = generate_shm_name();

    ouroboros::shm_log_writer writer;
    auto writer_result =
        writer.configure(shm_name, chunk_target_size, chunk_count);
    ASSERT_TRUE(writer_result.has_value());

    // Test parameters
    constexpr int num_reader_threads = 5;
    constexpr int num_entries = 50;

    // Synchronization
    std::atomic<bool> writer_running{true};
    std::atomic<int> entries_written{0};
    std::atomic<int> total_reads{0};
    std::mutex read_entries_mutex;
    std::vector<std::string> read_entries;
    std::set<std::string> unique_read_entries;

    // Reader threads
    std::vector<std::thread> reader_threads;
    for (int t = 0; t < num_reader_threads; ++t)
    {
        reader_threads.emplace_back(
            [&, t]()
            {
                ouroboros::shm_log_reader reader;

                // Retry configuration until buffer is ready
                auto reader_result = reader.configure(shm_name);
                while (!reader_result.has_value() && writer_running.load())
                {
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                    reader_result = reader.configure(shm_name);
                }
                ASSERT_TRUE(reader_result.has_value());

                int consecutive_failures = 0;
                constexpr int max_consecutive_failures = 1000;

                while (writer_running.load() ||
                       consecutive_failures < max_consecutive_failures)
                {
                    auto entry_result = reader.read_next();
                    if (entry_result.has_value())
                    {
                        consecutive_failures = 0;
                        {
                            std::lock_guard<std::mutex> lock(
                                read_entries_mutex);
                            total_reads.fetch_add(1);
                            read_entries.push_back(entry_result.value());
                            unique_read_entries.insert(entry_result.value());
                        }
                    }
                    else
                    {
                        consecutive_failures++;
                        std::this_thread::sleep_for(
                            std::chrono::microseconds(10));
                    }
                }
            });
    }

    // Writer runs in main thread
    for (int i = 0; i < num_entries; ++i)
    {
        std::string entry = "Entry " + std::to_string(i);
        writer.write(entry);
        entries_written.fetch_add(1);
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    writer_running.store(false);

    // Give readers time to finish
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Wait for all reader threads
    for (auto& thread : reader_threads)
    {
        thread.join();
    }

    // Verify results
    auto writes = entries_written.load();
    auto reads = total_reads.load();

    EXPECT_EQ(writes, num_entries);
    EXPECT_GT(reads, 0);

    // With multiple readers, we should have read at least as many entries as
    // written (each entry can be read by multiple readers)
    EXPECT_GE(reads, writes);

    // All unique entries read should match what was written
    {
        std::lock_guard<std::mutex> lock(read_entries_mutex);
        EXPECT_EQ(unique_read_entries.size(), static_cast<std::size_t>(writes))
            << "Unique entries read should match entries written";
    }
}

TEST(test_shm_log, multi_threaded_with_wraps)
{
    // Use a small buffer to force multiple wraps
    constexpr std::size_t chunk_target_size = 512;
    constexpr std::size_t chunk_count = 4;
    auto shm_name = generate_shm_name();

    ouroboros::shm_log_writer writer;
    auto writer_result =
        writer.configure(shm_name, chunk_target_size, chunk_count);
    ASSERT_TRUE(writer_result.has_value());

    // Test parameters
    constexpr int num_reader_threads = 3;
    constexpr std::chrono::seconds test_duration(2);
    constexpr int entries_per_batch = 5;

    // Synchronization
    std::atomic<bool> writer_running{true};
    std::atomic<std::uint64_t> entries_written{0};
    std::atomic<std::uint64_t> total_reads{0};
    std::atomic<std::uint64_t> valid_reads{0};
    std::mutex read_entries_mutex;
    std::vector<std::string> read_entries;
    std::set<std::string> unique_read_entries;

    // Reader threads - continuously read entries
    std::vector<std::thread> reader_threads;
    for (int t = 0; t < num_reader_threads; ++t)
    {
        reader_threads.emplace_back(
            [&, t]()
            {
                ouroboros::shm_log_reader reader;

                // Retry configuration until buffer is ready
                auto reader_result = reader.configure(shm_name);
                while (!reader_result.has_value() && writer_running.load())
                {
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                    reader_result = reader.configure(shm_name);
                }
                ASSERT_TRUE(reader_result.has_value());

                int consecutive_failures = 0;
                constexpr int max_consecutive_failures = 1000;

                while (writer_running.load() ||
                       consecutive_failures < max_consecutive_failures)
                {
                    auto entry_result = reader.read_next();
                    if (entry_result.has_value())
                    {
                        consecutive_failures = 0;
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
            // Generate unique entry
            std::string entry = "ENTRY_" + std::to_string(entry_counter) + "_" +
                                std::to_string(std::chrono::steady_clock::now()
                                                   .time_since_epoch()
                                                   .count()) +
                                "_";

            // Pad to target size with unique data
            std::size_t target_size = 100;
            while (entry.size() < target_size)
            {
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

    // Get unique entries count (thread-safe, all readers are joined)
    std::size_t unique_count = 0;
    {
        std::lock_guard<std::mutex> lock(read_entries_mutex);
        unique_count = unique_read_entries.size();
    }

    // We should have written many entries
    EXPECT_GT(writes, 0U) << "Writer should have written some entries";

    // We should have read many entries (can be more than writes due to multiple
    // readers)
    EXPECT_GT(reads, 0U) << "Readers should have read some entries";

    // Most reads should be valid
    EXPECT_GT(valid, 0U) << "Should have at least some valid reads";

    // Unique entries read should be less than or equal to entries written
    // (some may be overwritten due to wraps)
    EXPECT_LE(unique_count, static_cast<std::size_t>(writes))
        << "Unique entries read should not exceed entries written";
}

TEST(test_shm_log, concurrent_readers_different_starting_points)
{
    constexpr std::size_t chunk_target_size = 512;
    constexpr std::size_t chunk_count = 4;
    auto shm_name = generate_shm_name();

    ouroboros::shm_log_writer writer;
    auto writer_result =
        writer.configure(shm_name, chunk_target_size, chunk_count);
    ASSERT_TRUE(writer_result.has_value());

    // Write some initial entries

    int entries_written = 0;
    for (; entries_written < 10; ++entries_written)
    {
        writer.write("Initial " + std::to_string(entries_written));
    }

    // Synchronization
    std::atomic<bool> writer_running{true};
    std::atomic<int> total_reads{0};
    std::mutex read_entries_mutex;
    std::set<std::string> unique_read_entries;

    // Create readers that start at different times
    std::vector<std::thread> reader_threads;
    for (int t = 0; t < 12; ++t)
    {
        reader_threads.emplace_back(
            [&, t]()
            {
                // Delay each reader by different amounts
                std::this_thread::sleep_for(std::chrono::milliseconds(t * 50));

                ouroboros::shm_log_reader reader;
                auto reader_result = reader.configure(shm_name);
                ASSERT_TRUE(reader_result.has_value());

                int consecutive_failures = 0;
                constexpr int max_consecutive_failures = 500;

                while (writer_running.load() ||
                       consecutive_failures < max_consecutive_failures)
                {
                    auto entry_result = reader.read_next();
                    if (entry_result.has_value())
                    {
                        consecutive_failures = 0;
                        {
                            std::lock_guard<std::mutex> lock(
                                read_entries_mutex);
                            total_reads.fetch_add(1);
                            unique_read_entries.insert(entry_result.value());
                        }
                    }
                    else
                    {
                        consecutive_failures++;
                        std::this_thread::sleep_for(
                            std::chrono::microseconds(10));
                    }
                }
            });
    }

    // Writer continues writing
    for (; entries_written < 1000; ++entries_written)
    {
        writer.write("Entry " + std::to_string(entries_written));
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    writer_running.store(false);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Wait for all reader threads
    for (auto& thread : reader_threads)
    {
        thread.join();
    }

    // Verify results
    EXPECT_GT(total_reads.load(), 0);
    {
        std::lock_guard<std::mutex> lock(read_entries_mutex);
        EXPECT_LE(unique_read_entries.size(), entries_written);
    }
}

TEST(test_shm_log, reader_is_ready)
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

TEST(test_shm_log, move_semantics)
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
