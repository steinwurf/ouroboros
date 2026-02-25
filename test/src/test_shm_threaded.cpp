// Copyright (c) 2026 Steinwurf ApS
// SPDX-License-Identifier: MIT

#include <ouroboros/detail/buffer_format.hpp>
#include <ouroboros/reader.hpp>
#include <ouroboros/shm_file.hpp>
#include <ouroboros/writer.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <gtest/gtest.h>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <tl/expected.hpp>
#include <vector>

#include "test_helpers.hpp"

using test_helpers::generate_shm_name;

namespace
{
using rw_shm_file = ouroboros::shm_file<ouroboros::shm_access::read_write>;
using ro_shm_file = ouroboros::shm_file<ouroboros::shm_access::read_only>;

auto configure_writer(rw_shm_file& shm_file, ouroboros::writer& writer,
                      const std::string& shm_name,
                      std::size_t chunk_target_size, std::size_t chunk_count)
    -> tl::expected<void, ouroboros::configure_error>
{
    const std::size_t required_size =
        ouroboros::detail::buffer_format::compute_buffer_size(chunk_target_size,
                                                              chunk_count);
    auto shm_result = shm_file.open_or_create(shm_name, required_size, true);
    if (!shm_result.has_value())
    {
        return tl::make_unexpected(
            ouroboros::configure_error{shm_result.error()});
    }

    return writer.configure(
        std::span<uint8_t>(shm_file.data(), shm_file.size()), chunk_target_size,
        chunk_count);
}

auto configure_reader(ro_shm_file& shm_file, ouroboros::reader& reader,
                      const std::string& shm_name)
    -> tl::expected<void, std::error_code>
{
    auto shm_result = shm_file.open(shm_name);
    if (!shm_result.has_value())
    {
        return tl::make_unexpected(shm_result.error());
    }
    return reader.configure(
        std::span<const uint8_t>(shm_file.data(), shm_file.size()));
}
} // namespace

TEST(test_shm_threaded, single_writer_single_reader)
{
    constexpr std::size_t chunk_target_size = 1024;
    constexpr std::size_t chunk_count = 4;
    auto shm_name = generate_shm_name();

    rw_shm_file writer_shm;
    ouroboros::writer writer;
    auto writer_result = configure_writer(writer_shm, writer, shm_name,
                                          chunk_target_size, chunk_count);
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
            ro_shm_file reader_shm;
            ouroboros::reader reader;

            // Retry configuration until buffer is ready
            auto reader_result = configure_reader(reader_shm, reader, shm_name);
            while (!reader_result.has_value() && writer_running.load())
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
                reader_result = configure_reader(reader_shm, reader, shm_name);
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

TEST(test_shm_threaded, single_writer_multiple_readers)
{
    constexpr std::size_t chunk_target_size = 1024;
    constexpr std::size_t chunk_count = 4;
    auto shm_name = generate_shm_name();

    rw_shm_file writer_shm;
    ouroboros::writer writer;
    auto writer_result = configure_writer(writer_shm, writer, shm_name,
                                          chunk_target_size, chunk_count);
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
                ro_shm_file reader_shm;
                ouroboros::reader reader;

                // Retry configuration until buffer is ready
                auto reader_result =
                    configure_reader(reader_shm, reader, shm_name);
                while (!reader_result.has_value() && writer_running.load())
                {
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                    reader_result =
                        configure_reader(reader_shm, reader, shm_name);
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

TEST(test_shm_threaded, multi_threaded_with_wraps)
{
    // Use a small buffer to force multiple wraps
    constexpr std::size_t chunk_target_size = 512;
    constexpr std::size_t chunk_count = 4;
    auto shm_name = generate_shm_name();

    rw_shm_file writer_shm;
    ouroboros::writer writer;
    auto writer_result = configure_writer(writer_shm, writer, shm_name,
                                          chunk_target_size, chunk_count);
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
                ro_shm_file reader_shm;
                ouroboros::reader reader;

                // Retry configuration until buffer is ready
                auto reader_result =
                    configure_reader(reader_shm, reader, shm_name);
                while (!reader_result.has_value() && writer_running.load())
                {
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                    reader_result =
                        configure_reader(reader_shm, reader, shm_name);
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

TEST(test_shm_threaded, concurrent_readers_different_starting_points)
{
    constexpr std::size_t chunk_target_size = 512;
    constexpr std::size_t chunk_count = 4;
    auto shm_name = generate_shm_name();

    rw_shm_file writer_shm;
    ouroboros::writer writer;
    auto writer_result = configure_writer(writer_shm, writer, shm_name,
                                          chunk_target_size, chunk_count);
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

                ro_shm_file reader_shm;
                ouroboros::reader reader;
                auto reader_result =
                    configure_reader(reader_shm, reader, shm_name);
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

TEST(test_shm_threaded,
     multiple_readers_different_speeds_and_start_times_with_wraps)
{
    // Use small buffer and chunk sizes to force multiple wraps
    constexpr std::size_t chunk_target_size = 128; // Small chunk size
    constexpr std::size_t chunk_count = 4;         // Small number of chunks
    auto shm_name = generate_shm_name();

    rw_shm_file writer_shm;
    ouroboros::writer writer;
    auto writer_result = configure_writer(writer_shm, writer, shm_name,
                                          chunk_target_size, chunk_count);
    ASSERT_TRUE(writer_result.has_value())
        << "Writer configuration failed: " << writer_result.error().message();

    // Test parameters
    constexpr int num_reader_threads = 6;
    constexpr std::chrono::seconds test_duration(
        5); // Run long enough for wraps
    constexpr std::size_t entry_size =
        20; // Small entries so multiple fit per chunk

    // Synchronization
    std::atomic<bool> writer_running{true};
    std::atomic<std::uint64_t> entries_written{0};
    std::mutex read_stats_mutex;

    struct ReaderStats
    {
        std::uint64_t entries_read{0};
        std::set<std::string> unique_entries;
    };

    std::vector<ReaderStats> reader_stats(num_reader_threads);

    // Reader threads with different speeds and start times
    std::vector<std::thread> reader_threads;
    for (int t = 0; t < num_reader_threads; ++t)
    {
        reader_threads.emplace_back(
            [&, t]()
            {
                // Different start delays: first 2 start immediately, others
                // start later
                int start_delay_ms = (t < 2) ? 0 : (t - 1) * 100;
                std::this_thread::sleep_for(
                    std::chrono::milliseconds(start_delay_ms));

                ro_shm_file reader_shm;
                ouroboros::reader reader;

                // Retry configuration until buffer is ready
                auto reader_result =
                    configure_reader(reader_shm, reader, shm_name);
                while (!reader_result.has_value() && writer_running.load())
                {
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                    reader_result =
                        configure_reader(reader_shm, reader, shm_name);
                }
                ASSERT_TRUE(reader_result.has_value())
                    << "Reader " << t << " configuration failed";

                // Different read speeds: first 2 read fast (10us delay),
                // middle 2 read medium (1ms delay), last 2 read slow (10ms
                // delay)
                int read_delay_us;
                if (t < 2)
                {
                    read_delay_us = 10; // Fast readers
                }
                else if (t < 4)
                {
                    read_delay_us = 1000; // Medium speed readers
                }
                else
                {
                    read_delay_us = 10000; // Slow readers
                }

                int consecutive_failures = 0;
                constexpr int max_consecutive_failures = 2000;

                while (writer_running.load() ||
                       consecutive_failures < max_consecutive_failures)
                {
                    auto entry_result = reader.read_next();
                    if (entry_result.has_value())
                    {
                        consecutive_failures = 0;
                        {
                            std::lock_guard<std::mutex> lock(read_stats_mutex);
                            reader_stats[t].entries_read++;
                            reader_stats[t].unique_entries.insert(
                                entry_result.value());
                        }
                    }
                    else
                    {
                        consecutive_failures++;
                    }
                    // Apply read delay based on reader speed
                    std::this_thread::sleep_for(
                        std::chrono::microseconds(read_delay_us));
                }
            });
    }

    // Writer runs in main thread - continuously writes entries
    int entry_counter = 0;
    auto start_time = std::chrono::steady_clock::now();

    while (writer_running.load())
    {
        // Generate unique entry with counter
        std::string entry = "ENTRY_" + std::to_string(entry_counter);
        // Pad to target size
        while (entry.size() < entry_size)
        {
            entry += '_' + std::to_string(entry_counter * 1000 + entry.size());
        }

        writer.write(entry);
        entry_counter++;
        entries_written.fetch_add(1, std::memory_order_relaxed);

        // Check if we should stop
        auto elapsed = std::chrono::steady_clock::now() - start_time;
        if (elapsed >= test_duration)
        {
            writer_running.store(false);
            break;
        }

        // Writer writes at a steady rate (faster than slow readers)
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    // Give readers time to finish reading remaining entries
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    // Wait for all reader threads
    for (auto& thread : reader_threads)
    {
        thread.join();
    }

    // Verify test results
    auto writes = entries_written.load();

    EXPECT_GT(writes, 0U) << "Writer should have written some entries";

    // Verify that fast readers (first 2) read more entries than slow readers
    // (last 2)
    {
        std::lock_guard<std::mutex> lock(read_stats_mutex);
        std::uint64_t fast_readers_total = 0;
        std::uint64_t slow_readers_total = 0;

        for (int t = 0; t < num_reader_threads; ++t)
        {
            if (t < 2)
            {
                fast_readers_total += reader_stats[t].entries_read;
            }
            else if (t >= 4)
            {
                slow_readers_total += reader_stats[t].entries_read;
            }
        }

        EXPECT_GT(fast_readers_total, 0U)
            << "Fast readers should have read some entries";
        EXPECT_GT(slow_readers_total, 0U)
            << "Slow readers should have read some entries";

        // Fast readers should have read more entries
        EXPECT_GT(fast_readers_total, slow_readers_total)
            << "Fast readers should read more entries than slow readers";

        // Verify that early-starting readers (first 2) read more unique entries
        // than late-starting readers
        std::size_t early_unique = 0;
        std::size_t late_unique = 0;

        for (int t = 0; t < num_reader_threads; ++t)
        {
            if (t < 2)
            {
                early_unique += reader_stats[t].unique_entries.size();
            }
            else if (t >= 4)
            {
                late_unique += reader_stats[t].unique_entries.size();
            }
        }

        EXPECT_GT(early_unique, 0U)
            << "Early readers should have read some unique entries";
        EXPECT_GT(late_unique, 0U)
            << "Late readers should have read some unique entries";

        // Early fast readers should have read more unique entries
        EXPECT_GE(early_unique, late_unique)
            << "Early readers should read at least as many unique entries as "
               "late readers";

        // Verify that we had enough writes to cause wraps
        // With small buffer, we should have wrapped multiple times
        EXPECT_GT(writes, 100U)
            << "Should have written enough entries to cause multiple wraps";
    }
}

TEST(test_shm_threaded, maximum_throughput)
{
    // Use medium buffer size to allow high throughput
    constexpr std::size_t chunk_target_size = 512;
    constexpr std::size_t chunk_count = 8;
    auto shm_name = generate_shm_name();

    rw_shm_file writer_shm;
    ouroboros::writer writer;
    auto writer_result = configure_writer(writer_shm, writer, shm_name,
                                          chunk_target_size, chunk_count);
    ASSERT_TRUE(writer_result.has_value())
        << "Writer configuration failed: " << writer_result.error().message();

    // Test parameters
    constexpr std::chrono::seconds test_duration(2);
    constexpr std::size_t entry_size = 50; // Medium-sized entries

    // Synchronization
    std::atomic<bool> writer_running{true};
    std::atomic<std::uint64_t> entries_written{0};
    std::atomic<std::uint64_t> entries_read{0};
    std::mutex read_entries_mutex;
    std::set<std::string> unique_entries_read;

    // Reader thread - reads as fast as possible (no delays)
    std::thread reader_thread(
        [&]()
        {
            ro_shm_file reader_shm;
            ouroboros::reader reader;

            // Retry configuration until buffer is ready
            auto reader_result = configure_reader(reader_shm, reader, shm_name);
            while (!reader_result.has_value() && writer_running.load())
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
                reader_result = configure_reader(reader_shm, reader, shm_name);
            }
            ASSERT_TRUE(reader_result.has_value())
                << "Reader configuration failed";

            int consecutive_failures = 0;
            constexpr int max_consecutive_failures = 1000;

            // Read as fast as possible - no delays between reads
            while (writer_running.load() ||
                   consecutive_failures < max_consecutive_failures)
            {
                auto entry_result = reader.read_next();
                if (entry_result.has_value())
                {
                    consecutive_failures = 0;
                    entries_read.fetch_add(1, std::memory_order_relaxed);
                    {
                        std::lock_guard<std::mutex> lock(read_entries_mutex);
                        unique_entries_read.insert(entry_result.value());
                    }
                }
                else
                {
                    consecutive_failures++;
                    // Minimal delay only when no data available to avoid
                    // busy-waiting
                    if (consecutive_failures < 10)
                    {
                        std::this_thread::yield();
                    }
                    else
                    {
                        std::this_thread::sleep_for(
                            std::chrono::microseconds(1));
                    }
                }
            }
        });

    // Writer runs in main thread - writes as fast as possible (no delays)
    int entry_counter = 0;
    auto start_time = std::chrono::steady_clock::now();

    while (writer_running.load())
    {
        // Generate unique entry with counter
        std::string entry = "ENTRY_" + std::to_string(entry_counter);
        // Pad to target size
        while (entry.size() < entry_size)
        {
            entry += '_' + std::to_string(entry_counter * 1000 + entry.size());
        }

        writer.write(entry);
        entry_counter++;
        entries_written.fetch_add(1, std::memory_order_relaxed);

        // Check if we should stop
        auto elapsed = std::chrono::steady_clock::now() - start_time;
        if (elapsed >= test_duration)
        {
            writer_running.store(false);
            break;
        }

        // No delay - write as fast as possible
    }

    // Give reader time to finish reading remaining entries
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Wait for reader thread
    reader_thread.join();

    // Verify test results
    auto writes = entries_written.load();
    auto reads = entries_read.load();

    EXPECT_GT(writes, 0U) << "Writer should have written some entries";
    EXPECT_GT(reads, 0U)
        << "Reader should have read at least some entries despite high "
           "throughput";

    // Verify that unique entries were read
    {
        std::lock_guard<std::mutex> lock(read_entries_mutex);
        EXPECT_GT(unique_entries_read.size(), 0U)
            << "Should have read at least some unique entries";
        EXPECT_LE(unique_entries_read.size(), static_cast<std::size_t>(writes))
            << "Should not read more unique entries than were written";
    }

    // With maximum throughput, reader may not keep up, but should read
    // something
    EXPECT_GT(reads, 0U) << "Reader should have read at least some entries";
}
