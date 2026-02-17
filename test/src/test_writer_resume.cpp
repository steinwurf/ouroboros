// Copyright (c) 2026 Steinwurf ApS
// SPDX-License-Identifier: MIT

#include <ouroboros/reader.hpp>
#include <ouroboros/writer.hpp>

#include <ouroboros/error_code.hpp>

#include <cstring>
#include <functional>
#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "test_helpers.hpp"

using test_helpers::create_aligned_buffer;

TEST(test_writer_resume, succeeds_with_matching_params)
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

TEST(test_writer_resume, reinitializes_on_version_mismatch)
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

TEST(test_writer_resume, fails_with_chunk_count_mismatch)
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
    EXPECT_EQ(result2.error(), ouroboros::error::resume_chunk_count_mismatch);
}

// Note: writer_resume_fails_with_buffer_size_mismatch test removed
// The buffer size mismatch error is unreachable because the initial VERIFY
// in configure() checks buffer.size() >= expected_buffer_size before the
// resume logic runs. The resume_buffer_size_mismatch error code exists
// for completeness but can't be triggered in practice.

TEST(test_writer_resume, fails_with_buffer_id_mismatch)
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
    EXPECT_EQ(result2.error(), ouroboros::error::resume_buffer_id_mismatch);
}

TEST(test_writer_resume, force_init_reinitializes_with_different_id)
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

    // Second writer force init with different buffer_id
    // This reinitializes the buffer, losing old entries
    {
        ouroboros::writer writer2;
        auto result2 = writer2.configure(buffer_span, chunk_target_size,
                                         chunk_count, buffer_id_2,
                                         true); // force_init = true
        ASSERT_TRUE(result2.has_value()) << result2.error().message();

        // Buffer ID should be updated
        EXPECT_EQ(writer2.buffer_id(), buffer_id_2);

        // Should start fresh (force_init reinitializes)
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

TEST(test_writer_resume, after_wrap)
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

TEST(test_writer_resume, fails_after_finish)
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

    // Second writer tries to resume - should fail because writer finished
    {
        ouroboros::writer writer2;
        auto result = writer2.configure(buffer_span, chunk_target_size,
                                        chunk_count, buffer_id);
        ASSERT_FALSE(result.has_value());
        EXPECT_EQ(result.error(), ouroboros::error::resume_writer_finished);
    }

    // With force_init, the buffer is reinitialized
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

TEST(test_writer_resume, fresh_buffer)
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

TEST(test_writer_resume, force_init_with_chunk_count_mismatch)
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

    // Second writer force init with different chunk_count
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
// Parameterized Resume Tests - Efficiently test all failure/recovery cases
// ============================================================================

struct ResumeTestCase
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

    friend void PrintTo(const ResumeTestCase& tc, std::ostream* os)
    {
        *os << tc.name;
    }
};

class WriterResumeTest : public ::testing::TestWithParam<ResumeTestCase>
{
protected:
    static constexpr std::size_t kChunkTargetSize = 1024;
    static constexpr std::size_t kChunkCount = 4;
    static constexpr uint64_t kBufferId = 42;

    void SetUp() override
    {
        buffer_size_ = ouroboros::detail::buffer_format::compute_buffer_size(
            kChunkTargetSize, kChunkCount);
        buffer_ = create_aligned_buffer(buffer_size_);
        buffer_span_ = std::span<uint8_t>(buffer_);
    }

    std::size_t buffer_size_;
    std::vector<uint8_t> buffer_;
    std::span<uint8_t> buffer_span_;
};

TEST_P(WriterResumeTest, resume_fails_then_force_succeeds)
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

    // Resume should fail with expected error
    {
        ouroboros::writer writer2;
        auto result = writer2.configure(
            buffer_span_, test_case.second_chunk_target_size,
            test_case.second_chunk_count, test_case.second_buffer_id, false);
        ASSERT_FALSE(result.has_value())
            << "Resume should fail for: " << test_case.name;
        EXPECT_EQ(result.error(), test_case.expected_error)
            << "Wrong error for: " << test_case.name;
    }

    // Force init should succeed
    {
        ouroboros::writer writer3;
        auto result = writer3.configure(
            buffer_span_, test_case.second_chunk_target_size,
            test_case.second_chunk_count, test_case.second_buffer_id, true);
        ASSERT_TRUE(result.has_value())
            << "Force init should succeed for: " << test_case.name
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
    resume_cases, WriterResumeTest,
    ::testing::Values(
        ResumeTestCase{
            "chunk_count_mismatch",
            ouroboros::error::resume_chunk_count_mismatch,
            nullptr, // No buffer modification needed
            1024,    // same chunk_target_size
            3,       // different chunk_count
            42       // same buffer_id
        },
        ResumeTestCase{
            "buffer_id_mismatch", ouroboros::error::resume_buffer_id_mismatch,
            nullptr, // No buffer modification needed
            1024,    // same chunk_target_size
            4,       // same chunk_count
            999      // different buffer_id
        },
        ResumeTestCase{
            "writer_finished", ouroboros::error::resume_writer_finished,
            [](std::span<uint8_t> buffer, std::size_t chunk_target_size,
               std::size_t chunk_count, uint64_t buffer_id)
            {
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
    [](const ::testing::TestParamInfo<ResumeTestCase>& info)
    { return info.param.name; });
