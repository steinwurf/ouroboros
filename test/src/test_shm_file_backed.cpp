// Copyright (c) 2026 Steinwurf ApS
// SPDX-License-Identifier: MIT

#include <ouroboros/detail/buffer_format.hpp>
#include <ouroboros/error_code.hpp>
#include <ouroboros/reader.hpp>
#include <ouroboros/shm_file.hpp>
#include <ouroboros/writer.hpp>

#include <gtest/gtest.h>

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <string>

#include <platform/config.hpp>

#ifdef PLATFORM_WINDOWS
#include <process.h>
#else
#include <unistd.h>
#endif

namespace
{
using rw_file_shm =
    ouroboros::shm_file<ouroboros::shm_access::read_write,
                        ouroboros::shm_backing::file>;
using ro_file_shm =
    ouroboros::shm_file<ouroboros::shm_access::read_only,
                        ouroboros::shm_backing::file>;

auto unique_file_path() -> std::filesystem::path
{
    static std::atomic<uint32_t> counter{0};
    const auto id = counter.fetch_add(1, std::memory_order_relaxed);
#ifdef PLATFORM_WINDOWS
    const auto pid = static_cast<uint32_t>(::_getpid());
#else
    const auto pid = static_cast<uint32_t>(::getpid());
#endif
    return std::filesystem::temp_directory_path() /
           ("ouroboros_file_" + std::to_string(pid) + "_" +
            std::to_string(id));
}
} // namespace

TEST(test_shm_file_backed, writer_and_reader)
{
    constexpr std::size_t chunk_target_size = 1024;
    constexpr std::size_t chunk_count = 4;
    const auto path = unique_file_path();
    const std::string path_string = path.string();
    const std::size_t required_size =
        ouroboros::detail::buffer_format::compute_buffer_size(chunk_target_size,
                                                              chunk_count);

    rw_file_shm writer_shm;
    ASSERT_TRUE(
        writer_shm.open_or_create(path_string, required_size, false).has_value());
    EXPECT_TRUE(std::filesystem::exists(path));
    EXPECT_EQ(std::filesystem::file_size(path), required_size);

    ouroboros::writer writer;
    auto writer_result = writer.configure(
        std::span<uint8_t>(writer_shm.data(), writer_shm.size()),
        chunk_target_size, chunk_count);
    ASSERT_TRUE(writer_result.has_value()) << writer_result.error().message();
    writer.write("file backed");

    ro_file_shm reader_shm;
    ASSERT_TRUE(reader_shm.open(path_string).has_value());
    EXPECT_EQ(reader_shm.size(), required_size);

    ouroboros::reader reader;
    auto reader_result = reader.configure(
        std::span<const uint8_t>(reader_shm.data(), reader_shm.size()));
    ASSERT_TRUE(reader_result.has_value());

    auto entry = reader.read_next();
    ASSERT_TRUE(entry.has_value());
    EXPECT_EQ(entry.value(), "file backed");

    writer_shm.unlink();
    EXPECT_FALSE(std::filesystem::exists(path));
}

TEST(test_shm_file_backed, unlink_on_close)
{
    const auto path = unique_file_path();
    const std::string path_string = path.string();

    {
        rw_file_shm writer_shm;
        ASSERT_TRUE(writer_shm.open_or_create(path_string, 4096, true).has_value());
        EXPECT_TRUE(std::filesystem::exists(path));
    }

    EXPECT_FALSE(std::filesystem::exists(path));
}

TEST(test_shm_file_backed, reopen_existing_size)
{
    const auto path = unique_file_path();
    const std::string path_string = path.string();

    {
        rw_file_shm writer_shm;
        ASSERT_TRUE(
            writer_shm.open_or_create(path_string, 4096, false).has_value());
    }

    rw_file_shm again;
    ASSERT_TRUE(again.open_or_create(path_string, 4096, true).has_value());

    rw_file_shm mismatch;
    auto mismatch_result = mismatch.open_or_create(path_string, 8192, false);
    ASSERT_FALSE(mismatch_result.has_value());
    EXPECT_EQ(mismatch_result.error(),
              ouroboros::error::shared_memory_size_mismatch);

    again.unlink();
    EXPECT_FALSE(std::filesystem::exists(path));
}

TEST(test_shm_file_backed, missing_file)
{
    ro_file_shm reader_shm;
    auto result = reader_shm.open(unique_file_path().string());
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), ouroboros::error::shared_memory_not_found);
}
