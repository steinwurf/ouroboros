// Copyright (c) 2026 Steinwurf ApS
// SPDX-License-Identifier: MIT

#include <ouroboros/reader.hpp>
#include <ouroboros/writer.hpp>

#include <atomic>
#include <chrono>
#include <gtest/gtest.h>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "test_helpers.hpp"

using test_helpers::create_aligned_buffer;

TEST(test_reader_writer_threaded, multi_threaded_with_wraps)
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
