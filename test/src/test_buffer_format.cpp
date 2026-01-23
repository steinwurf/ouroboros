// Copyright (c) 2023 Steinwurf ApS
// All Rights Reserved
//
// THIS IS UNPUBLISHED PROPRIETARY SOURCE CODE OF STEINWURF
// The copyright notice above does not evidence any
// actual or intended publication of such source code.

#include <gtest/gtest.h>

#include <ouroboros/detail/buffer_format.hpp>

TEST(test_buffer_format, align_up)
{
    using namespace ouroboros::detail::buffer_format;

    EXPECT_EQ(align_up(0, 4), 0U);
    EXPECT_EQ(align_up(1, 4), 4U);
    EXPECT_EQ(align_up(2, 4), 4U);
    EXPECT_EQ(align_up(3, 4), 4U);
    EXPECT_EQ(align_up(4, 4), 4U);
    EXPECT_EQ(align_up(5, 4), 8U);
    EXPECT_EQ(align_up(6, 4), 8U);
    EXPECT_EQ(align_up(7, 4), 8U);
    EXPECT_EQ(align_up(8, 4), 8U);

    EXPECT_EQ(align_up(0, 8), 0U);
    EXPECT_EQ(align_up(1, 8), 8U);
    EXPECT_EQ(align_up(7, 8), 8U);
    EXPECT_EQ(align_up(8, 8), 8U);
    EXPECT_EQ(align_up(9, 8), 16U);
    EXPECT_EQ(align_up(15, 8), 16U);
    EXPECT_EQ(align_up(16, 8), 16U);
}

TEST(test_buffer_format, magic_value)
{
    // Verify the magic value represents "OUROBLOG"
    // O=0x4F, U=0x55, R=0x52, O=0x4F, B=0x42, L=0x4C, O=0x4F, G=0x47
    EXPECT_EQ(ouroboros::detail::buffer_format::magic, 0x4F55524F424C4F47ULL);
}

TEST(test_buffer_format, commit_flag)
{
    using namespace ouroboros::detail::buffer_format;

    uint32_t value = 0x12345678;
    uint32_t committed_value = set_commit(value);
    EXPECT_TRUE(is_committed(committed_value));
    EXPECT_EQ(clear_commit(committed_value), value);

    uint64_t value64 = 0x1234567890ABCDEE;
    uint64_t committed_value64 = set_commit(value64);
    EXPECT_TRUE(is_committed(committed_value64));
    EXPECT_EQ(clear_commit(committed_value64), value64);
}

TEST(test_buffer_format, commit_flag_min)
{
    using namespace ouroboros::detail::buffer_format;
    uint32_t value_min = 0; // Min value without commit flag
    uint32_t committed_value_min = set_commit(value_min);
    EXPECT_TRUE(is_committed(committed_value_min));
    EXPECT_EQ(clear_commit(committed_value_min), value_min);

    uint64_t value64_min = 0; // Min value without commit
    uint64_t committed_value64_min = set_commit(value64_min);
}

TEST(test_buffer_format, commit_flag_max)
{
    using namespace ouroboros::detail::buffer_format;
    uint32_t value_max = clear_commit(std::numeric_limits<uint32_t>::max());
    EXPECT_FALSE(is_committed(value_max));
    uint32_t committed_value_max = set_commit(value_max);
    EXPECT_TRUE(is_committed(committed_value_max));
    EXPECT_EQ(clear_commit(committed_value_max), value_max);

    uint64_t value64_max = clear_commit(std::numeric_limits<uint64_t>::max());
    EXPECT_FALSE(is_committed(value64_max));
    uint64_t committed_value64_max = set_commit(value64_max);
    EXPECT_TRUE(is_committed(committed_value64_max));
    EXPECT_EQ(clear_commit(committed_value64_max), value64_max);
}

TEST(test_buffer_format, commit_flag_double_set)
{
    using namespace ouroboros::detail::buffer_format;
    EXPECT_DEATH(
        { set_commit(set_commit<uint32_t>(0x12345678)); },
        "Assertion failed at buffer_format.hpp");
    EXPECT_DEATH(
        { set_commit(set_commit<uint64_t>(0x1234567890ABCDEF)); },
        "Assertion failed at buffer_format.hpp");
}
