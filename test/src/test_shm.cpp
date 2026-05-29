// Copyright (c) 2026 Steinwurf ApS
// SPDX-License-Identifier: MIT

#include <ouroboros/detail/buffer_format.hpp>
#include <ouroboros/error_code.hpp>
#include <ouroboros/reader.hpp>
#include <ouroboros/shm_file.hpp>
#include <ouroboros/writer.hpp>

#include <gtest/gtest.h>
#include <tl/expected.hpp>

#include <string>
#include <vector>

#include "test_helpers.hpp"

using test_helpers::generate_shm_name;

namespace
{
using rw_shm_file = ouroboros::shm_file<ouroboros::shm_access::read_write>;
using ro_shm_file = ouroboros::shm_file<ouroboros::shm_access::read_only>;

auto configure_writer(rw_shm_file& shm_file, ouroboros::writer& writer,
                      const std::string& shm_name,
                      std::size_t chunk_target_size, std::size_t chunk_count,
                      uint64_t buffer_id = 0, bool force_init = false,
                      bool unlink_on_close = true)
    -> tl::expected<void, ouroboros::configure_error>
{
    const std::size_t required_size =
        ouroboros::detail::buffer_format::compute_buffer_size(chunk_target_size,
                                                              chunk_count);
    auto shm_result =
        shm_file.open_or_create(shm_name, required_size, unlink_on_close);
    if (!shm_result.has_value())
    {
        return tl::make_unexpected(
            ouroboros::configure_error{shm_result.error()});
    }

    return writer.configure(
        std::span<uint8_t>(shm_file.data(), shm_file.size()), chunk_target_size,
        chunk_count, buffer_id, force_init);
}

auto configure_reader(ro_shm_file& shm_file, ouroboros::reader& reader,
                      const std::string& shm_name,
                      ouroboros::reader::read_strategy strategy =
                          ouroboros::reader::read_strategy::auto_detect)
    -> tl::expected<void, std::error_code>
{
    auto shm_result = shm_file.open(shm_name);
    if (!shm_result.has_value())
    {
        return tl::make_unexpected(shm_result.error());
    }

    return reader.configure(
        std::span<const uint8_t>(shm_file.data(), shm_file.size()), strategy);
}
} // namespace

TEST(test_shm, writer_configure)
{
    constexpr std::size_t chunk_target_size = 1024;
    constexpr std::size_t chunk_count = 4;
    auto shm_name = generate_shm_name();

    rw_shm_file writer_shm;
    ouroboros::writer writer;
    auto result = configure_writer(writer_shm, writer, shm_name,
                                   chunk_target_size, chunk_count);
    ASSERT_TRUE(result.has_value())
        << "Writer configuration failed: " << result.error().message();

    EXPECT_EQ(writer.chunk_target_size(), chunk_target_size);
    EXPECT_EQ(writer.chunk_count(), chunk_count);
    EXPECT_GT(writer.max_entry_size(), 0U);
    EXPECT_EQ(writer_shm.name(), shm_name);
    EXPECT_GT(writer_shm.size(), 0U);
    EXPECT_EQ(writer.buffer_id(), 0U);
}

TEST(test_shm, buffer_id)
{
    constexpr std::size_t chunk_target_size = 1024;
    constexpr std::size_t chunk_count = 4;
    constexpr uint64_t test_buffer_id = 0xDEADBEEF12345678ULL;
    auto shm_name = generate_shm_name();

    rw_shm_file writer_shm;
    ouroboros::writer writer;
    auto writer_result =
        configure_writer(writer_shm, writer, shm_name, chunk_target_size,
                         chunk_count, test_buffer_id, false, false);
    ASSERT_TRUE(writer_result.has_value());

    EXPECT_EQ(writer.buffer_id(), test_buffer_id);
    writer.write("test entry");

    ro_shm_file reader_shm;
    ouroboros::reader reader;
    auto reader_result = configure_reader(reader_shm, reader, shm_name);
    ASSERT_TRUE(reader_result.has_value());
    EXPECT_EQ(reader.buffer_id(), test_buffer_id);
}

TEST(test_shm, reader_configure_before_writer)
{
    auto shm_name = generate_shm_name();

    ro_shm_file reader_shm;
    ouroboros::reader reader;
    auto result = configure_reader(reader_shm, reader, shm_name);
    EXPECT_FALSE(result.has_value())
        << "Reader should fail to configure before writer creates shm";
}

TEST(test_shm, writer_reader_basic)
{
    constexpr std::size_t chunk_target_size = 1024;
    constexpr std::size_t chunk_count = 4;
    auto shm_name = generate_shm_name();

    rw_shm_file writer_shm;
    ouroboros::writer writer;
    auto writer_result = configure_writer(writer_shm, writer, shm_name,
                                          chunk_target_size, chunk_count);
    ASSERT_TRUE(writer_result.has_value())
        << "Writer configuration failed: " << writer_result.error().message();

    ro_shm_file reader_shm;
    ouroboros::reader reader;
    auto reader_result = configure_reader(reader_shm, reader, shm_name);
    ASSERT_TRUE(reader_result.has_value())
        << "Reader configuration failed: " << reader_result.error().message();

    EXPECT_EQ(reader.chunk_count(), chunk_count);
    EXPECT_EQ(reader_shm.name(), shm_name);
    EXPECT_GT(reader_shm.size(), 0U);
}

TEST(test_shm, write_single_entry)
{
    constexpr std::size_t chunk_target_size = 1024;
    constexpr std::size_t chunk_count = 4;
    auto shm_name = generate_shm_name();

    rw_shm_file writer_shm;
    ouroboros::writer writer;
    auto writer_result = configure_writer(writer_shm, writer, shm_name,
                                          chunk_target_size, chunk_count);
    ASSERT_TRUE(writer_result.has_value())
        << "Writer configuration failed: " << writer_result.error().message();

    std::string test_entry = "Hello, World!";
    writer.write(test_entry);

    ro_shm_file reader_shm;
    ouroboros::reader reader;
    auto reader_result = configure_reader(reader_shm, reader, shm_name);
    ASSERT_TRUE(reader_result.has_value())
        << "Reader configuration failed: " << reader_result.error().message();

    auto entry_result = reader.read_next_entry();
    ASSERT_TRUE(entry_result.has_value());
    EXPECT_EQ(entry_result->data, test_entry);
    EXPECT_TRUE(entry_result->is_valid());

    auto no_more = reader.read_next_entry();
    EXPECT_FALSE(no_more.has_value());
}

TEST(test_shm, write_multiple_entries)
{
    constexpr std::size_t chunk_target_size = 1024;
    constexpr std::size_t chunk_count = 4;
    auto shm_name = generate_shm_name();

    rw_shm_file writer_shm;
    ouroboros::writer writer;
    auto writer_result = configure_writer(writer_shm, writer, shm_name,
                                          chunk_target_size, chunk_count);
    ASSERT_TRUE(writer_result.has_value());

    std::vector<std::string> test_entries = {"First entry", "Second entry",
                                             "Third entry", "Fourth entry",
                                             "Fifth entry"};

    for (const auto& entry : test_entries)
    {
        writer.write(entry);
    }

    ro_shm_file reader_shm;
    ouroboros::reader reader;
    auto reader_result = configure_reader(reader_shm, reader, shm_name);
    ASSERT_TRUE(reader_result.has_value());

    for (const auto& expected_entry : test_entries)
    {
        auto entry_result = reader.read_next_entry();
        ASSERT_TRUE(entry_result.has_value());
        EXPECT_EQ(entry_result->data, expected_entry);
        EXPECT_TRUE(entry_result->is_valid());
    }

    auto no_more = reader.read_next_entry();
    EXPECT_FALSE(no_more.has_value());
}

TEST(test_shm, writer_finish_reader_reports_finished)
{
    constexpr std::size_t chunk_target_size = 1024;
    constexpr std::size_t chunk_count = 4;
    auto shm_name = generate_shm_name();

    rw_shm_file writer_shm;
    ouroboros::writer writer;
    auto writer_result =
        configure_writer(writer_shm, writer, shm_name, chunk_target_size,
                         chunk_count, 0, false, false);
    ASSERT_TRUE(writer_result.has_value());

    writer.write("Entry 1");
    writer.write("Entry 2");
    writer.finish();

    ro_shm_file reader_shm;
    ouroboros::reader reader;
    auto reader_result = configure_reader(reader_shm, reader, shm_name);
    ASSERT_TRUE(reader_result.has_value());

    auto entry1 = reader.read_next_entry();
    ASSERT_TRUE(entry1.has_value());
    EXPECT_EQ(entry1->data, "Entry 1");

    auto entry2 = reader.read_next_entry();
    ASSERT_TRUE(entry2.has_value());
    EXPECT_EQ(entry2->data, "Entry 2");

    auto finish_result = reader.read_next_entry();
    ASSERT_FALSE(finish_result.has_value());
    EXPECT_EQ(finish_result.error(),
              ouroboros::make_error_code(ouroboros::error::writer_finished));

    auto subsequent = reader.read_next_entry();
    ASSERT_FALSE(subsequent.has_value());
    EXPECT_EQ(subsequent.error(),
              ouroboros::make_error_code(ouroboros::error::writer_finished));

    writer_shm.unlink();
    writer_shm = rw_shm_file{};
    reader_shm = ro_shm_file{};

    ro_shm_file reader2_shm;
    ouroboros::reader reader2;
    auto attach_result = configure_reader(reader2_shm, reader2, shm_name);
    EXPECT_FALSE(attach_result.has_value());
}

TEST(test_shm, reader_empty_buffer_handling)
{
    constexpr std::size_t chunk_target_size = 1024;
    constexpr std::size_t chunk_count = 4;
    auto shm_name = generate_shm_name();

    rw_shm_file writer_shm;
    ouroboros::writer writer;
    auto writer_result = configure_writer(writer_shm, writer, shm_name,
                                          chunk_target_size, chunk_count);
    ASSERT_TRUE(writer_result.has_value());

    ro_shm_file reader_shm;
    ouroboros::reader reader;
    auto reader_result = configure_reader(reader_shm, reader, shm_name);
    ASSERT_TRUE(reader_result.has_value());

    auto entry_result = reader.read_next_entry();
    ASSERT_FALSE(entry_result.has_value());
    EXPECT_EQ(entry_result.error(),
              ouroboros::make_error_code(
                  ouroboros::error::no_data_entry_uncommitted));
}

TEST(test_shm, multiple_readers)
{
    constexpr std::size_t chunk_target_size = 1024;
    constexpr std::size_t chunk_count = 4;
    auto shm_name = generate_shm_name();

    rw_shm_file writer_shm;
    ouroboros::writer writer;
    auto writer_result = configure_writer(writer_shm, writer, shm_name,
                                          chunk_target_size, chunk_count);
    ASSERT_TRUE(writer_result.has_value());

    std::vector<std::string> test_entries = {"One", "Two", "Three"};

    for (const auto& entry : test_entries)
    {
        writer.write(entry);
    }

    ro_shm_file reader1_shm;
    ouroboros::reader reader1;
    auto result1 = configure_reader(reader1_shm, reader1, shm_name);
    ASSERT_TRUE(result1.has_value());

    ro_shm_file reader2_shm;
    ouroboros::reader reader2;
    auto result2 = configure_reader(reader2_shm, reader2, shm_name);
    ASSERT_TRUE(result2.has_value());

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

    rw_shm_file writer_shm;
    ouroboros::writer writer;
    auto writer_result = configure_writer(writer_shm, writer, shm_name,
                                          chunk_target_size, chunk_count);
    ASSERT_TRUE(writer_result.has_value());

    ro_shm_file reader_shm;
    ouroboros::reader reader;
    auto reader_result = configure_reader(reader_shm, reader, shm_name);
    ASSERT_TRUE(reader_result.has_value());

    writer.write("Entry 1");

    auto entry1 = reader.read_next_entry();
    ASSERT_TRUE(entry1.has_value());
    EXPECT_EQ(entry1->data, "Entry 1");

    writer.write("Entry 2");

    auto entry2 = reader.read_next_entry();
    ASSERT_TRUE(entry2.has_value());
    EXPECT_EQ(entry2->data, "Entry 2");

    EXPECT_TRUE(entry1->is_valid());

    writer.write("Entry 3");

    auto entry3 = reader.read_next_entry();
    ASSERT_TRUE(entry3.has_value());
    EXPECT_EQ(entry3->data, "Entry 3");

    EXPECT_TRUE(entry1->is_valid());
    EXPECT_TRUE(entry2->is_valid());
    EXPECT_TRUE(entry3->is_valid());

    auto entry4 = reader.read_next_entry();
    ASSERT_FALSE(entry4.has_value());
    EXPECT_EQ(entry4.error(), ouroboros::make_error_code(
                                  ouroboros::error::no_data_entry_uncommitted));
}

TEST(test_shm, wrap_behavior)
{
    constexpr std::size_t chunk_target_size = 64;
    constexpr std::size_t chunk_count = 2;
    auto shm_name = generate_shm_name();

    rw_shm_file writer_shm;
    ouroboros::writer writer;
    auto writer_result = configure_writer(writer_shm, writer, shm_name,
                                          chunk_target_size, chunk_count);
    ASSERT_TRUE(writer_result.has_value());

    for (int i = 0; i < 20; ++i)
    {
        std::string entry = "Entry " + std::to_string(i);
        writer.write(entry);
    }

    ro_shm_file reader_shm;
    ouroboros::reader reader;
    auto reader_result = configure_reader(reader_shm, reader, shm_name);
    ASSERT_TRUE(reader_result.has_value());

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
    EXPECT_LT(read_count, 20);
}

TEST(test_shm, reader_is_ready)
{
    constexpr std::size_t chunk_target_size = 1024;
    constexpr std::size_t chunk_count = 4;
    auto shm_name = generate_shm_name();

    ro_shm_file reader_shm;
    EXPECT_FALSE(reader_shm.is_mapped());

    rw_shm_file writer_shm;
    ouroboros::writer writer;
    auto writer_result = configure_writer(writer_shm, writer, shm_name,
                                          chunk_target_size, chunk_count);
    ASSERT_TRUE(writer_result.has_value());

    EXPECT_FALSE(reader_shm.is_mapped());

    ouroboros::reader reader;
    auto reader_result = configure_reader(reader_shm, reader, shm_name);
    ASSERT_TRUE(reader_result.has_value());

    EXPECT_TRUE(ouroboros::reader::is_ready(
        std::span<const uint8_t>(reader_shm.data(), reader_shm.size())));
}

TEST(test_shm, move_semantics)
{
    constexpr std::size_t chunk_target_size = 1024;
    constexpr std::size_t chunk_count = 4;
    auto shm_name = generate_shm_name();

    rw_shm_file writer1_shm;
    ouroboros::writer writer1;
    auto result1 = configure_writer(writer1_shm, writer1, shm_name,
                                    chunk_target_size, chunk_count);
    ASSERT_TRUE(result1.has_value())
        << "Writer configuration failed: " << result1.error().message();

    writer1.write("Test entry");

    rw_shm_file writer2_shm = std::move(writer1_shm);
    ouroboros::writer writer2 = std::move(writer1);
    writer2.write("Another entry");

    EXPECT_EQ(writer2_shm.name(), shm_name);

    {
        ro_shm_file reader1_shm;
        ouroboros::reader reader1;
        auto result_reader1 = configure_reader(reader1_shm, reader1, shm_name);
        ASSERT_TRUE(result_reader1.has_value());

        auto read1 = reader1.read_next();
        ASSERT_TRUE(read1.has_value());
        EXPECT_EQ(read1.value(), "Test entry");

        ro_shm_file reader2_shm = std::move(reader1_shm);
        ouroboros::reader reader2 = std::move(reader1);
        EXPECT_EQ(reader2_shm.name(), shm_name);

        auto read2 = reader2.read_next();
        ASSERT_TRUE(read2.has_value());
        EXPECT_EQ(read2.value(), "Another entry");
    }
}
